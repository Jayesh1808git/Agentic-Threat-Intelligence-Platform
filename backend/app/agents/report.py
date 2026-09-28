import logging
from datetime import datetime
from typing import Any
from pydantic import BaseModel, Field

from app.agents.state import CyberRAGState
from app.schemas.agent_outputs import AssessmentReport
from app.services.llm import llm_service

logger = logging.getLogger("report_agent")


SYSTEM_PROMPT = """
You are the Report Generation Agent in an AI-agent-driven CyberRAG vulnerability assessment workflow.
Your task is to synthesize the structured findings, risk assessments, and remediation recommendations into a professional Security Assessment Report.

Do NOT rediscover or search for new vulnerabilities!
Use ONLY the validated findings, risk assessments, recommendations, and evidence already provided in the state.

Categorize all findings clearly into:
1. Confirmed Vulnerabilities (status = 'validated', affected = true)
2. Potential Vulnerabilities (status = 'needs_review', requires further verification)
3. Not Applicable (status = 'not_affected', installed version safe or product mismatch)
4. Insufficient Evidence (findings missing critical advisory data)

Structure the output matching the AssessmentReport schema.
Generate a comprehensive, beautifully formatted Markdown report containing:
- Executive Summary
- Affected Assets
- Confirmed Vulnerabilities & Technical Rationale
- Risk Analysis Summary
- Remediation Guidance & Action Plan
- Authoritative References
"""


def report_agent(state: CyberRAGState) -> dict[str, Any]:
    """
    Agent 8: Report Generation Agent

    Synthesizes validated findings, risk scores, recommendations, and evidence into a
    structured report and Markdown document.
    """
    project_input = state.get("project_input", {})
    assets = state.get("assets", [])
    validated_findings = state.get("validated_findings", [])
    risk_assessments = state.get("risk_assessments", [])
    recommendations = state.get("recommendations", [])
    retrieval_mode = state.get("retrieval_mode", "HYBRID")
    errors = list(state.get("errors", []))

    project_name = project_input.get("name") or project_input.get("project_name") or "CyberRAG Security Assessment"

    # Categorize findings
    confirmed = [f for f in validated_findings if f.get("status") == "validated" and f.get("affected") is True]
    potential = [f for f in validated_findings if f.get("status") == "needs_review"]
    not_applicable = [f for f in validated_findings if f.get("status") == "not_affected" or f.get("affected") is False]

    # 1. AI Reasoning for Executive Summary & Markdown Report
    markdown_report = ""
    executive_summary = ""

    if llm_service.is_configured():
        try:
            prompt = _build_report_prompt(
                project_name=project_name,
                assets=assets,
                confirmed=confirmed,
                potential=potential,
                not_applicable=not_applicable,
                risk_assessments=risk_assessments,
                recommendations=recommendations,
                retrieval_mode=retrieval_mode,
            )
            report_res: AssessmentReport = llm_service.invoke_structured(
                prompt=prompt,
                response_model=AssessmentReport,
                system_prompt=SYSTEM_PROMPT,
                agent_name="report",
            )
            executive_summary = report_res.executive_summary
            markdown_report = report_res.markdown or _generate_fallback_markdown(
                project_name=project_name,
                executive_summary=executive_summary,
                assets=assets,
                confirmed=confirmed,
                potential=potential,
                not_applicable=not_applicable,
                risk_assessments=risk_assessments,
                recommendations=recommendations,
                retrieval_mode=retrieval_mode,
                errors=errors,
            )
        except Exception as exc:
            logger.warning("LLM report generation failed: %s. Using deterministic markdown generator.", exc)
            errors.append(f"LLM report generation warning: {exc}")
            executive_summary = f"CyberRAG vulnerability assessment for {project_name}. Evaluated {len(assets)} technology assets and found {len(confirmed)} confirmed vulnerabilities."
            markdown_report = _generate_fallback_markdown(
                project_name=project_name,
                executive_summary=executive_summary,
                assets=assets,
                confirmed=confirmed,
                potential=potential,
                not_applicable=not_applicable,
                risk_assessments=risk_assessments,
                recommendations=recommendations,
                retrieval_mode=retrieval_mode,
                errors=errors,
            )
    else:
        executive_summary = f"CyberRAG vulnerability assessment for {project_name}. Evaluated {len(assets)} technology assets and found {len(confirmed)} confirmed vulnerabilities."
        markdown_report = _generate_fallback_markdown(
            project_name=project_name,
            executive_summary=executive_summary,
            assets=assets,
            confirmed=confirmed,
            potential=potential,
            not_applicable=not_applicable,
            risk_assessments=risk_assessments,
            recommendations=recommendations,
            retrieval_mode=retrieval_mode,
            errors=errors,
        )

    report_data = {
        "title": f"CyberRAG Vulnerability Assessment Report - {project_name}",
        "project_name": project_name,
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "executive_summary": executive_summary,
        "retrieval_mode": retrieval_mode,
        "affected_assets": assets,
        "confirmed_vulnerabilities": confirmed,
        "potential_vulnerabilities": potential,
        "not_applicable": not_applicable,
        "risk_assessments": risk_assessments,
        "recommendations": recommendations,
        "markdown": markdown_report,
    }

    return {
        "report": report_data,
        "errors": errors,
    }


def _clean_finding_summary(finding: dict[str, Any]) -> dict[str, Any]:
    return {
        "vulnerability_id": finding.get("vulnerability") or finding.get("vulnerability_id"),
        "asset": finding.get("asset"),
        "status": finding.get("status"),
        "affected": finding.get("affected"),
        "reason": finding.get("reason"),
        "affected_versions": finding.get("affected_versions", []),
        "patched_versions": finding.get("patched_versions", []),
        "cvss": finding.get("cvss"),
        "epss": finding.get("epss"),
        "kev": finding.get("kev"),
    }


def _build_report_prompt(
    project_name: str,
    assets: list[dict[str, Any]],
    confirmed: list[dict[str, Any]],
    potential: list[dict[str, Any]],
    not_applicable: list[dict[str, Any]],
    risk_assessments: list[dict[str, Any]],
    recommendations: list[dict[str, Any]],
    retrieval_mode: str,
) -> str:
    clean_confirmed = [_clean_finding_summary(f) for f in confirmed]
    clean_potential = [_clean_finding_summary(f) for f in potential]
    clean_not_app = [_clean_finding_summary(f) for f in not_applicable]

    clean_risks = [
        {
            "vulnerability_id": r.get("vulnerability_id"),
            "risk_score": r.get("risk_score"),
            "risk_level": r.get("risk_level"),
            "rationale": r.get("rationale"),
        }
        for r in risk_assessments
    ]

    clean_recs = [
        {
            "vulnerability_id": r.get("vulnerability_id"),
            "asset": r.get("asset"),
            "recommendation": r.get("recommendation"),
        }
        for r in recommendations
    ]

    return (
        f"Generate complete CyberRAG Security Assessment Report:\n\n"
        f"Project Name: {project_name}\n"
        f"Retrieval Mode: {retrieval_mode}\n"
        f"Assets Evaluated ({len(assets)}): {assets}\n"
        f"Confirmed Vulnerabilities ({len(clean_confirmed)}): {clean_confirmed}\n"
        f"Potential Vulnerabilities ({len(clean_potential)}): {clean_potential}\n"
        f"Not Applicable Findings ({len(clean_not_app)}): {clean_not_app}\n"
        f"Risk Assessments: {clean_risks}\n"
        f"Remediation Recommendations: {clean_recs}\n"
    )


def _generate_fallback_markdown(
    project_name: str,
    executive_summary: str,
    assets: list[dict[str, Any]],
    confirmed: list[dict[str, Any]],
    potential: list[dict[str, Any]],
    not_applicable: list[dict[str, Any]],
    risk_assessments: list[dict[str, Any]],
    recommendations: list[dict[str, Any]],
    retrieval_mode: str,
    errors: list[str],
) -> str:
    lines = [
        f"# CyberRAG Vulnerability Assessment Report",
        "",
        f"**Project:** {project_name}",
        f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"**Retrieval Subsystem Mode:** `{retrieval_mode}`",
        "",
        "## 1. Executive Summary",
        "",
        executive_summary,
        "",
        "### Assessment Statistics",
        f"- **Assets Evaluated:** {len(assets)}",
        f"- **Confirmed Vulnerabilities:** {len(confirmed)}",
        f"- **Potential / Needs Review:** {len(potential)}",
        f"- **Not Applicable:** {len(not_applicable)}",
        "",
        "## 2. Technology Assets Evaluated",
        "",
    ]

    if assets:
        lines.append("| Technology | Vendor | Product | Type | Installed Version | Criticality |")
        lines.append("|------------|--------|---------|------|-------------------|-------------|")
        for a in assets:
            lines.append(
                f"| {a.get('name', 'N/A')} | {a.get('vendor', 'N/A')} | {a.get('product', 'N/A')} | "
                f"{a.get('type', 'N/A')} | {a.get('version', 'Unspecified')} | {a.get('criticality', 'N/A')} |"
            )
        lines.append("")
    else:
        lines.append("No technology assets extracted.\n")

    lines.append("## 3. Confirmed Vulnerabilities")
    lines.append("")

    if confirmed:
        for idx, item in enumerate(confirmed, start=1):
            v_id = item.get("vulnerability") or item.get("vulnerability_id")
            asset_info = item.get("asset", {})
            asset_str = f"{asset_info.get('name')} {asset_info.get('version')}" if isinstance(asset_info, dict) else str(asset_info)

            # Match risk
            r_info = next((r for r in risk_assessments if r.get("vulnerability_id") == v_id), {})
            rec_info = next((rec for rec in recommendations if rec.get("vulnerability_id") == v_id), {})

            lines.extend([
                f"### Finding {idx}: {v_id}",
                f"- **Affected Asset:** {asset_str}",
                f"- **Validation Status:** Verified Applicable ({item.get('confidence', 0.0)*100:.0f}% confidence)",
                f"- **Risk Level:** **{str(r_info.get('risk_level', 'medium')).upper()}** (Score: {r_info.get('risk_score', 'N/A')}/100)",
                f"- **CVSS Base Score:** {item.get('cvss', 'N/A')}",
                f"- **CISA KEV Status:** {'Yes' if item.get('kev') else 'No'}",
                f"- **EPSS Probability:** {item.get('epss', 'N/A')}",
                f"- **Affected Versions:** {', '.join(map(str, item.get('affected_versions', []))) or 'All below fixed'}",
                f"- **Patched Versions:** {', '.join(map(str, item.get('patched_versions', []))) or 'Not confirmed'}",
                "",
                f"**Validation Reasoning:** {item.get('reason')}",
                "",
            ])

            if r_info.get("rationale"):
                lines.extend([f"**Risk Rationale:** {r_info.get('rationale')}", ""])

            rec_dict = rec_info.get("recommendation", {})
            if rec_dict:
                lines.extend([
                    "**Remediation Recommendation:**",
                    f"- Action: `{rec_dict.get('action')}`",
                    f"- Priority: `{rec_dict.get('priority')}`",
                    f"- Description: {rec_dict.get('description')}",
                    f"- Mitigation: {rec_dict.get('mitigation')}",
                    "",
                ])
    else:
        lines.append("No confirmed vulnerabilities detected for the project assets.\n")

    lines.append("## 4. Potential Vulnerabilities & Not Applicable Findings")
    lines.append("")

    if potential:
        lines.append("### Findings Requiring Further Evidence")
        for item in potential:
            v_id = item.get("vulnerability") or item.get("vulnerability_id")
            lines.append(f"- **{v_id}**: {item.get('reason')}")
        lines.append("")

    if not_applicable:
        lines.append("### Findings Determined Not Applicable")
        for item in not_applicable:
            v_id = item.get("vulnerability") or item.get("vulnerability_id")
            lines.append(f"- **{v_id}**: {item.get('reason')}")
        lines.append("")

    if errors:
        lines.extend([
            "## 5. Execution Warnings & Errors",
            "",
        ])
        for err in errors:
            lines.append(f"- {err}")
        lines.append("")

    return "\n".join(lines)