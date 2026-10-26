import json
import logging
from typing import Any

from app.agents.state import CyberRAGState
from app.agents.recommendation import (
    _build_fallback_recommendation,
    _find_verified_patched_version,
)
from app.core.config import settings
from app.schemas.agent_outputs import (
    RiskAssessment,
    RiskRecommendationResult,
)
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

Risk score and level are calculated deterministically and supplied with each finding.
Explain how those fixed values relate to the observed risk factors. Do not recalculate them.
Write clear rationale and practical remediation guidance grounded in the supplied evidence.

Return one result per finding_key, with a concise rationale and recommendation fields:
action, description, and mitigation. Do not return risk scores or target versions.
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
            "recommendations": [],
            "errors": errors,
        }

    risk_assessments: list[dict[str, Any]] = []
    recommendations: list[dict[str, Any]] = []
    batch_items: list[dict[str, Any]] = []
    risk_by_id: dict[str, dict[str, Any]] = {}
    web_evidence = state.get("web_evidence", [])

    for index, finding in enumerate(validated_findings):
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
        for asset in assets:
            if isinstance(asset, dict) and str(asset.get("name", "")).lower() == str(asset_name).lower():
                asset_criticality = asset_criticality or asset.get("criticality")
                business_impact = business_impact or asset.get("business_impact")
                break

        cvss = finding.get("cvss")
        epss = finding.get("epss")
        kev = finding.get("kev")
        exploit_available = finding.get("exploit_available")
        risk_score, risk_level, fallback_rationale = _heuristic_risk_score(
            cvss=cvss,
            epss=epss,
            kev=kev,
            exploit_available=exploit_available,
            criticality=asset_criticality,
            business_impact=business_impact,
        )
        finding_key = f"finding_{index}"
        risk_by_id[finding_key] = {
            "finding": finding,
            "asset_data": asset_data,
            "asset_name": asset_name,
            "installed_version": installed_version,
            "asset_criticality": asset_criticality,
            "business_impact": business_impact,
            "cvss": cvss,
            "epss": epss,
            "kev": kev,
            "exploit_available": exploit_available,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "fallback_rationale": fallback_rationale,
            "vulnerability_id": vulnerability_id,
        }
        batch_items.append({
            "finding_key": finding_key,
            "vulnerability_id": vulnerability_id,
            "asset": asset_name,
            "version": installed_version,
            "cvss": cvss,
            "epss": epss,
            "kev": kev,
            "exploit_available": exploit_available,
            "criticality": asset_criticality,
            "business_impact": business_impact,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "validation_context": finding.get("reason", ""),
            "verified_patch": _find_verified_patched_version(
                finding.get("patched_versions", []),
                finding.get("evidence", []),
                web_evidence,
                vulnerability_id,
            ),
        })

    llm_items: dict[str, Any] = {}
    if batch_items and llm_service.is_configured():
        try:
            result: RiskRecommendationResult = llm_service.invoke_structured(
                prompt=(
                    "For each item, use its provided risk_score and risk_level as fixed "
                    "values. Write a concise risk rationale and an evidence-based remediation "
                    "recommendation. Only use verified_patch as target-version evidence. "
                    "Return all items keyed by finding_key.\n"
                    f"{json.dumps(batch_items, separators=(',', ':'))}"
                ),
                response_model=RiskRecommendationResult,
                system_prompt=SYSTEM_PROMPT,
                model=settings.LIGHTWEIGHT_LLM_MODEL,
                agent_name="risk_and_recommendation",
            )
            llm_items = {item.finding_key: item for item in result.results}
        except Exception as exc:
            logger.warning("Batched LLM risk/recommendation generation failed: %s. Using deterministic fallbacks.", exc)
            errors.append(f"LLM risk and recommendation warning: {exc}")

    for finding_key, item in risk_by_id.items():
        llm_item = llm_items.get(finding_key)
        rationale = (
            llm_item.rationale.strip()
            if llm_item and llm_item.rationale.strip()
            else item["fallback_rationale"]
        )
        risk_assessment = RiskAssessment(
            vulnerability_id=str(item["vulnerability_id"]),
            asset_id=item["asset_data"].get("id"),
            asset={
                "name": item["asset_name"],
                "version": item["installed_version"],
                "criticality": item["asset_criticality"],
                "business_impact": item["business_impact"],
            },
            risk_score=item["risk_score"],
            risk_level=item["risk_level"],
            risk_factors={
                "cvss": item["cvss"],
                "epss": item["epss"],
                "kev": item["kev"],
                "exploit_available": item["exploit_available"],
                "asset_criticality": item["asset_criticality"],
                "business_impact": item["business_impact"],
            },
            rationale=rationale,
        ).model_dump()
        risk_assessments.append(risk_assessment)

        finding = item["finding"]
        evidence_items = finding.get("evidence", [])
        verified_patch = _find_verified_patched_version(
            finding.get("patched_versions", []),
            evidence_items,
            web_evidence,
            item["vulnerability_id"],
        )
        fallback_recommendation = _build_fallback_recommendation(
            vulnerability_id=item["vulnerability_id"],
            asset_name=item["asset_name"],
            installed_version=item["installed_version"],
            verified_patch=verified_patch,
            matching_risk={
                "risk_level": item["risk_level"],
                "risk_score": item["risk_score"],
            },
            evidence=evidence_items,
        ).model_dump()
        if llm_item:
            recommendation_fields = llm_item.recommendation
            fallback_fields = fallback_recommendation["recommendation"]
            action = recommendation_fields.get("action")
            if action not in {"upgrade", "patch", "mitigation", "investigate"}:
                action = fallback_fields["action"]
            fallback_fields.update({
                "action": action,
                "description": recommendation_fields.get("description") or fallback_fields["description"],
                "mitigation": recommendation_fields.get("mitigation") or fallback_fields["mitigation"],
                "target_version": verified_patch,
                "priority": fallback_fields["priority"],
            })
        recommendations.append(fallback_recommendation)

    return {
        "risk_assessments": risk_assessments,
        "recommendations": recommendations,
        "errors": errors,
    }


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