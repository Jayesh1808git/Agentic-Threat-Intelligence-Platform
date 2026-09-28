import logging
from typing import Any
from pydantic import BaseModel, Field

from app.agents.state import CyberRAGState
from app.schemas.agent_outputs import RiskAssessment, RiskAssessmentResult
from app.services.llm import llm_service

logger = logging.getLogger("risk_assessment_agent")


SYSTEM_PROMPT = """
You are the Risk Assessment Agent in an AI-agent-driven CyberRAG vulnerability assessment workflow.
Your task is to conduct an organization-specific security risk assessment for validated vulnerability findings.

Do NOT confuse retrieval relevance score with security risk!
- Retrieval score answers: "How relevant is this document to my query?"
- Risk assessment answers: "How dangerous is this vulnerability to this specific organization/project context?"

Consider the following risk factors holistically:
1. CVSS score & CVSS vector (Base severity, exploitability, impact)
2. EPSS probability (Exploit Prediction Scoring System likelihood of exploitation in the wild)
3. CISA KEV status (Is the vulnerability listed in CISA's Known Exploited Vulnerabilities catalog?)
4. Exploit availability (Is proof-of-concept or active exploit code available?)
5. Asset criticality (Critical, High, Medium, Low)
6. Business impact & exposure context

Do NOT rely on a single simplistic rule like "if cvss > 8: risk = critical".
Reason through the combination of factors. For example:
- A CVSS 7.5 vulnerability that is actively exploited (CISA KEV=True, High EPSS) on a Critical asset is CRITICAL risk.
- A CVSS 9.8 vulnerability with low EPSS, no active exploit, on an isolated non-critical asset might be HIGH or MEDIUM risk.

Assign:
- risk_score: A normalized float score from 0.0 to 100.0
- risk_level: "critical", "high", "medium", "low", or "minimal"
- rationale: A clear, multi-sentence reasoning explaining how the score and level were determined from the observed factors.

Return structured output matching the RiskAssessmentResult schema.
"""


def risk_assessment_agent(state: CyberRAGState) -> dict[str, Any]:
    """
    Agent 6: Risk Assessment Agent

    Receives validated findings and uses AI reasoning over technical severity and
    organizational asset context to evaluate business risk.
    """
    validated_findings = state.get("validated_findings", [])
    assets = state.get("assets", [])
    errors = list(state.get("errors", []))

    if not validated_findings:
        return {
            "risk_assessments": [],
            "errors": errors,
        }

    risk_assessments: list[dict[str, Any]] = []

    for finding in validated_findings:
        # Assess only validated and affected findings
        if finding.get("status") != "validated" or finding.get("affected") is not True:
            continue

        vulnerability_id = finding.get("vulnerability_id") or finding.get("vulnerability")
        asset_data = finding.get("asset", {})
        if not isinstance(asset_data, dict):
            asset_data = {}

        asset_name = asset_data.get("name", "Unknown asset")
        installed_version = asset_data.get("version")
        asset_criticality = asset_data.get("criticality")
        business_impact = asset_data.get("business_impact")

        # Find matching asset context if specified in state
        for a in assets:
            if isinstance(a, dict) and str(a.get("name", "")).lower() == str(asset_name).lower():
                asset_criticality = asset_criticality or a.get("criticality")
                business_impact = business_impact or a.get("business_impact")
                break

        cvss = finding.get("cvss")
        cvss_vector = finding.get("cvss_vector")
        epss = finding.get("epss")
        kev = finding.get("kev")
        exploit_available = finding.get("exploit_available")

        # 1. AI Reasoning for Risk Assessment
        if llm_service.is_configured():
            try:
                prompt = _build_risk_prompt(
                    vulnerability_id=vulnerability_id,
                    asset_name=asset_name,
                    installed_version=installed_version,
                    asset_criticality=asset_criticality,
                    business_impact=business_impact,
                    cvss=cvss,
                    cvss_vector=cvss_vector,
                    epss=epss,
                    kev=kev,
                    exploit_available=exploit_available,
                    reason=finding.get("reason", ""),
                )
                res: RiskAssessmentResult = llm_service.invoke_structured(
                    prompt=prompt,
                    response_model=RiskAssessmentResult,
                    system_prompt=SYSTEM_PROMPT,
                    agent_name="risk_assessment",
                )
                if res.risk_assessments:
                    risk_assessment_dict = res.risk_assessments[0].model_dump()
                    risk_assessments.append(risk_assessment_dict)
                    continue
            except Exception as exc:
                logger.warning("LLM risk assessment reasoning failed for %s: %s. Using heuristic formula fallback.", vulnerability_id, exc)
                errors.append(f"LLM risk assessment warning for {vulnerability_id}: {exc}")

        # Deterministic Heuristic Fallback if LLM unavailable
        risk_score, risk_level, rationale = _heuristic_risk_score(
            cvss=cvss,
            epss=epss,
            kev=kev,
            exploit_available=exploit_available,
            criticality=asset_criticality,
            business_impact=business_impact,
        )

        risk_assessments.append(
            RiskAssessment(
                vulnerability_id=str(vulnerability_id),
                asset_id=asset_data.get("id"),
                asset={
                    "name": asset_name,
                    "version": installed_version,
                    "criticality": asset_criticality,
                    "business_impact": business_impact,
                },
                risk_score=risk_score,
                risk_level=risk_level,
                risk_factors={
                    "cvss": cvss,
                    "epss": epss,
                    "kev": kev,
                    "exploit_available": exploit_available,
                    "asset_criticality": asset_criticality,
                    "business_impact": business_impact,
                },
                rationale=rationale,
            ).model_dump()
        )

    return {
        "risk_assessments": risk_assessments,
        "errors": errors,
    }


def _build_risk_prompt(
    vulnerability_id: Any,
    asset_name: str,
    installed_version: str | None,
    asset_criticality: str | None,
    business_impact: str | None,
    cvss: float | None,
    cvss_vector: str | None,
    epss: float | None,
    kev: bool | None,
    exploit_available: bool | None,
    reason: str,
) -> str:
    return (
        f"Perform an organizational security risk assessment for:\n\n"
        f"Vulnerability ID: {vulnerability_id}\n"
        f"Asset: {asset_name} (Version: {installed_version or 'Unspecified'})\n"
        f"Asset Criticality: {asset_criticality or 'Unspecified'}\n"
        f"Business Impact: {business_impact or 'Unspecified'}\n"
        f"Technical Risk Factors:\n"
        f"- CVSS Base Score: {cvss if cvss is not None else 'N/A'}\n"
        f"- CVSS Vector: {cvss_vector or 'N/A'}\n"
        f"- EPSS Probability: {epss if epss is not None else 'N/A'}\n"
        f"- CISA KEV (Known Exploited): {kev if kev is not None else 'False'}\n"
        f"- Exploit Available: {exploit_available if exploit_available is not None else 'False'}\n"
        f"Validation Context: {reason}\n"
    )


def _heuristic_risk_score(
    cvss: float | None,
    epss: float | None,
    kev: bool | None,
    exploit_available: bool | None,
    criticality: str | None,
    business_impact: str | None,
) -> tuple[float, str, str]:
    norm_cvss = (cvss * 10.0) if cvss is not None else 50.0
    norm_epss = (epss * 100.0) if epss is not None else 10.0
    norm_kev = 100.0 if kev is True else 0.0
    norm_exploit = 100.0 if exploit_available is True else 0.0

    crit_map = {"critical": 100.0, "high": 75.0, "medium": 50.0, "low": 25.0}
    norm_crit = crit_map.get(str(criticality).lower(), 50.0)
    norm_impact = crit_map.get(str(business_impact).lower(), 50.0)

    score = (
        norm_cvss * 0.40 +
        norm_epss * 0.20 +
        norm_kev * 0.15 +
        norm_exploit * 0.10 +
        norm_crit * 0.10 +
        norm_impact * 0.05
    )
    score = round(max(0.0, min(score, 100.0)), 2)

    if score >= 80.0:
        level = "critical"
    elif score >= 60.0:
        level = "high"
    elif score >= 40.0:
        level = "medium"
    elif score >= 20.0:
        level = "low"
    else:
        level = "minimal"

    rationale = f"Heuristic risk score ({score}) calculated from CVSS ({cvss}), EPSS ({epss}), CISA KEV ({kev}), exploit availability ({exploit_available}), and asset criticality ({criticality})."
    return score, level, rationale