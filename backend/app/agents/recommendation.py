import logging
from typing import Any
from pydantic import BaseModel, Field

from app.agents.state import CyberRAGState
from app.schemas.agent_outputs import Recommendation, RecommendationResult
from app.services.llm import llm_service

logger = logging.getLogger("recommendation_agent")


SYSTEM_PROMPT = """
You are the Recommendation Agent in an AI-agent-driven CyberRAG vulnerability assessment workflow.
Your task is to generate evidence-based remediation recommendations for validated vulnerability findings.

Requirements:
1. Determine appropriate remediation action:
   - "upgrade": If a verified patched/fixed version exists in the evidence (e.g., "Upgrade Spring Boot from 3.2.5 to 3.2.8 or later").
   - "patch": Apply official vendor security patch.
   - "mitigation": Apply documented configuration changes, temporary workarounds, or firewall/WAF rules.
   - "investigate": If no verified fixed version or official mitigation guidance exists in the evidence.

2. CRITICAL CONSTRAINT:
   Do NOT invent, fabricate, or hallucinate a target version or patched version if it is NOT present in the database or retrieved evidence!
   If the evidence states "fixed in 3.2.8", recommend upgrading to 3.2.8 or later.
   If no patched version is documented, set target_version to null and state clearly in description that no official fixed version is confirmed in current evidence.

3. Assign priority based on risk level:
   - "urgent": Critical risk
   - "high": High risk
   - "medium": Medium risk
   - "low": Low risk

4. Provide clear, actionable remediation instructions and mitigations.

Return structured output matching the RecommendationResult schema.
"""


def recommendation_agent(state: CyberRAGState) -> dict[str, Any]:
    """
    Agent 7: Recommendation Agent

    Consumes validated findings, risk assessments, and retrieved evidence to build
    evidence-based remediation recommendations.
    """
    validated_findings = state.get("validated_findings", [])
    risk_assessments = state.get("risk_assessments", [])
    web_evidence = state.get("web_evidence", [])
    errors = list(state.get("errors", []))

    if not validated_findings:
        return {
            "recommendations": [],
            "errors": errors,
        }

    recommendations: list[dict[str, Any]] = []

    for finding in validated_findings:
        if finding.get("status") != "validated" or finding.get("affected") is not True:
            continue

        vulnerability_id = finding.get("vulnerability_id") or finding.get("vulnerability")

        # Find matching risk assessment
        matching_risk = None
        for risk in risk_assessments:
            if risk.get("vulnerability_id") == vulnerability_id:
                matching_risk = risk
                break

        if not matching_risk:
            matching_risk = {
                "risk_level": "medium",
                "risk_score": 50.0,
            }

        # Extract verified patched versions from finding or evidence
        patched_versions = finding.get("patched_versions", [])
        evidence_items = finding.get("evidence", [])

        # Recover patched version from web evidence if not in DB
        verified_patch = _find_verified_patched_version(patched_versions, evidence_items, web_evidence, vulnerability_id)

        asset_info = finding.get("asset", {})
        asset_name = asset_info.get("name", "Affected asset")
        installed_version = asset_info.get("version")

        # 1. AI Reasoning for Recommendation
        if llm_service.is_configured():
            try:
                prompt = _build_recommendation_prompt(
                    vulnerability_id=vulnerability_id,
                    asset_name=asset_name,
                    installed_version=installed_version,
                    verified_patch=verified_patch,
                    risk_level=matching_risk.get("risk_level"),
                    risk_score=matching_risk.get("risk_score"),
                    evidence=evidence_items,
                    web_evidence=web_evidence,
                )
                res: RecommendationResult = llm_service.invoke_structured(
                    prompt=prompt,
                    response_model=RecommendationResult,
                    system_prompt=SYSTEM_PROMPT,
                    agent_name="recommendation",
                )
                if res.recommendations:
                    rec_dict = res.recommendations[0].model_dump()
                    # Ensure no hallucinated patch if not verified
                    if not verified_patch:
                        rec_dict["recommendation"]["target_version"] = None
                    recommendations.append(rec_dict)
                    continue
            except Exception as exc:
                logger.warning("LLM recommendation generation failed for %s: %s. Using heuristic fallback.", vulnerability_id, exc)
                errors.append(f"LLM recommendation warning for {vulnerability_id}: {exc}")

        # Deterministic Fallback if LLM unavailable
        rec_item = _build_fallback_recommendation(
            vulnerability_id=vulnerability_id,
            asset_name=asset_name,
            installed_version=installed_version,
            verified_patch=verified_patch,
            matching_risk=matching_risk,
            evidence=evidence_items,
        )
        recommendations.append(rec_item.model_dump())

    return {
        "recommendations": recommendations,
        "errors": errors,
    }


def _find_verified_patched_version(
    patched_versions: list[Any],
    evidence_items: list[dict[str, Any]],
    web_evidence: list[dict[str, Any]],
    vulnerability_id: Any,
) -> str | None:
    if isinstance(patched_versions, list) and patched_versions:
        valid = [str(v).strip() for v in patched_versions if v and str(v).strip()]
        if valid:
            return ", ".join(valid)
    elif isinstance(patched_versions, str) and patched_versions.strip():
        return patched_versions.strip()

    # Search web evidence for patch version string
    for item in web_evidence + evidence_items:
        if not isinstance(item, dict):
            continue
        rel = item.get("relevant_information")
        if isinstance(rel, dict):
            versions = rel.get("versions_found", [])
            if isinstance(versions, list) and versions:
                return str(versions[0]).strip()

    return None


def _build_recommendation_prompt(
    vulnerability_id: Any,
    asset_name: str,
    installed_version: str | None,
    verified_patch: str | None,
    risk_level: str | None,
    risk_score: float | None,
    evidence: list[dict[str, Any]],
    web_evidence: list[dict[str, Any]],
) -> str:
    return (
        f"Generate remediation recommendation:\n\n"
        f"Vulnerability ID: {vulnerability_id}\n"
        f"Asset: {asset_name} (Installed Version: {installed_version or 'Unspecified'})\n"
        f"Verified Patched/Fixed Version in Evidence: {verified_patch or 'NONE CONFIRMED'}\n"
        f"Assessed Risk Level: {risk_level} (Score: {risk_score})\n"
        f"Evidence Summary Count: {len(evidence) + len(web_evidence)}\n"
    )


def _build_fallback_recommendation(
    vulnerability_id: Any,
    asset_name: str,
    installed_version: str | None,
    verified_patch: str | None,
    matching_risk: dict[str, Any],
    evidence: list[dict[str, Any]],
) -> Recommendation:
    risk_level = matching_risk.get("risk_level", "medium")
    priority_map = {"critical": "urgent", "high": "high", "medium": "medium", "low": "low"}
    priority = priority_map.get(str(risk_level).lower(), "medium")

    if verified_patch:
        action = "upgrade"
        description = f"Upgrade {asset_name} from version {installed_version or 'current'} to fixed version {verified_patch} or later."
        mitigation = f"Apply official vendor patch updating to version {verified_patch}."
    else:
        action = "investigate"
        description = f"No official fixed version is confirmed in database evidence for {vulnerability_id}. Obtain confirmed vendor remediation guidance."
        mitigation = "Monitor vendor advisories and restrict network access or disable affected features as a temporary safeguard."

    refs = [item.get("url") for item in evidence if item.get("url")]

    return Recommendation(
        vulnerability_id=str(vulnerability_id),
        asset=f"{asset_name} {installed_version}" if installed_version else asset_name,
        recommendation={
            "action": action,
            "target_version": verified_patch,
            "priority": priority,
            "description": description,
            "mitigation": mitigation,
        },
        risk={
            "risk_score": matching_risk.get("risk_score", 50.0),
            "risk_level": risk_level,
        },
        references=list(set(filter(None, refs))),
        evidence_used={"patched_versions": verified_patch, "evidence_count": len(evidence)},
    )