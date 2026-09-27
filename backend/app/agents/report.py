from datetime import datetime
from typing import Any

from app.agents.state import CyberRAGState


# =========================================================
# Risk formatting
# =========================================================

def _format_risk(
    risk: dict[str, Any],
) -> str:
    score = risk.get(
        "risk_score",
        "N/A",
    )

    level = risk.get(
        "risk_level",
        "unknown",
    )

    return f"{str(level).upper()} (score: {score})"


# =========================================================
# Normalize list values
# =========================================================

def _as_list(
    value: Any,
) -> list[Any]:

    if value is None:
        return []

    if isinstance(value, list):
        return value

    return [value]


# =========================================================
# Collect retrieval sources
# =========================================================

def _collect_retrieval_sources(
    evidence: list[Any],
) -> list[str]:
    """
    Extract retrieval sources from evidence.

    Examples:
        lexical
        semantic
        web
    """

    sources: list[str] = []

    for item in evidence:

        if not isinstance(item, dict):
            continue

        retrieval_sources = item.get(
            "retrieval_sources",
            [],
        )

        if isinstance(
            retrieval_sources,
            str,
        ):
            retrieval_sources = [
                retrieval_sources
            ]

        if isinstance(
            retrieval_sources,
            list,
        ):

            for source in retrieval_sources:

                if (
                    source
                    and source not in sources
                ):
                    sources.append(
                        str(source)
                    )

        # Also support a single retrieval_source
        retrieval_source = item.get(
            "retrieval_source"
        )

        if (
            retrieval_source
            and retrieval_source not in sources
        ):
            sources.append(
                str(retrieval_source)
            )

    return sources


# =========================================================
# Collect references
# =========================================================

def _collect_references(
    finding: dict[str, Any],
    evidence: list[Any],
) -> list[str]:

    references: list[str] = []

    # References directly attached to finding
    finding_references = finding.get(
        "references",
        [],
    )

    for reference in _as_list(
        finding_references
    ):

        if (
            reference
            and str(reference) not in references
        ):
            references.append(
                str(reference)
            )

    # References from evidence
    for item in evidence:

        if not isinstance(item, dict):
            continue

        url = item.get(
            "url"
        )

        if (
            url
            and str(url) not in references
        ):
            references.append(
                str(url)
            )

        item_references = item.get(
            "references",
            [],
        )

        for reference in _as_list(
            item_references
        ):

            if (
                reference
                and str(reference) not in references
            ):
                references.append(
                    str(reference)
                )

    return references


# =========================================================
# Format one evidence item
# =========================================================

def _format_evidence_item(
    evidence_item: dict[str, Any],
) -> list[str]:
    """
    Convert a rich evidence record into readable
    report lines.

    This function supports both internal retrieval
    evidence and external web evidence.
    """

    lines: list[str] = []

    evidence_type = evidence_item.get(
        "type",
        "unknown",
    )

    source_type = evidence_item.get(
        "source_type"
    )

    source = evidence_item.get(
        "source"
    )

    # -----------------------------------------------------
    # Determine display source
    # -----------------------------------------------------

    display_source = (
        source_type
        or source
        or evidence_item.get(
            "retrieval_source"
        )
        or evidence_type
        or "unknown"
    )

    title = evidence_item.get(
        "title"
    )

    vulnerability_id = (
        evidence_item.get(
            "vulnerability_id"
        )
        or evidence_item.get(
            "cve"
        )
    )

    description = evidence_item.get(
        "description"
    )

    vendor = evidence_item.get(
        "vendor"
    )

    product = evidence_item.get(
        "product"
    )

    cvss = evidence_item.get(
        "cvss"
    )

    epss = evidence_item.get(
        "epss"
    )

    kev = evidence_item.get(
        "kev"
    )

    exploit_available = evidence_item.get(
        "exploit_available"
    )

    semantic_score = evidence_item.get(
        "semantic_score"
    )

    lexical_score = evidence_item.get(
        "lexical_score"
    )

    retrieval_sources = evidence_item.get(
        "retrieval_sources",
        [],
    )

    url = evidence_item.get(
        "url"
    )

    # -----------------------------------------------------
    # Header
    # -----------------------------------------------------

    header_parts = [
        f"[{evidence_type}]",
        str(display_source),
    ]

    if vulnerability_id:
        header_parts.append(
            f"({vulnerability_id})"
        )

    lines.append(
        "- " + " ".join(header_parts)
    )

    # -----------------------------------------------------
    # Title
    # -----------------------------------------------------

    if title:
        lines.append(
            f"  - Title: {title}"
        )

    # -----------------------------------------------------
    # Vendor / product
    # -----------------------------------------------------

    if vendor:
        lines.append(
            f"  - Vendor: {vendor}"
        )

    if product:
        lines.append(
            f"  - Product: {product}"
        )

    # -----------------------------------------------------
    # Description
    # -----------------------------------------------------

    if description:

        clean_description = str(
            description
        ).replace(
            "\n",
            " ",
        )

        lines.append(
            f"  - Description: {clean_description}"
        )

    # -----------------------------------------------------
    # Vulnerability intelligence
    # -----------------------------------------------------

    if cvss is not None:
        lines.append(
            f"  - CVSS: {cvss}"
        )

    if epss is not None:
        lines.append(
            f"  - EPSS: {epss}"
        )

    if kev is not None:
        lines.append(
            f"  - CISA KEV: {kev}"
        )

    if exploit_available is not None:
        lines.append(
            f"  - Exploit available: "
            f"{exploit_available}"
        )

    # -----------------------------------------------------
    # Retrieval scores
    # -----------------------------------------------------

    if semantic_score is not None:
        lines.append(
            f"  - Semantic score: "
            f"{semantic_score}"
        )

    if lexical_score is not None:
        lines.append(
            f"  - Lexical score: "
            f"{lexical_score}"
        )

    # -----------------------------------------------------
    # Retrieval sources
    # -----------------------------------------------------

    if isinstance(
        retrieval_sources,
        str,
    ):
        retrieval_sources = [
            retrieval_sources
        ]

    if retrieval_sources:

        lines.append(
            "  - Retrieval sources: "
            + ", ".join(
                map(
                    str,
                    retrieval_sources,
                )
            )
        )

    # -----------------------------------------------------
    # URL
    # -----------------------------------------------------

    if url:
        lines.append(
            f"  - URL: {url}"
        )

    return lines


# =========================================================
# Build one finding
# =========================================================

def _build_finding_section(
    finding: dict[str, Any],
    risk: dict[str, Any] | None,
    recommendation: dict[str, Any] | None,
) -> dict[str, Any]:

    vulnerability_id = (
        finding.get(
            "vulnerability_id"
        )
        or finding.get(
            "vulnerability"
        )
        or "Unknown"
    )

    asset = finding.get(
        "asset",
        {},
    )

    if not isinstance(
        asset,
        dict,
    ):
        asset = {}

    asset_name = asset.get(
        "name",
        "Unknown asset",
    )

    installed_version = asset.get(
        "version",
        "Unknown version",
    )

    status = finding.get(
        "status",
        "unknown",
    )

    affected = finding.get(
        "affected"
    )

    evidence = finding.get(
        "evidence",
        [],
    )

    if not isinstance(
        evidence,
        list,
    ):
        evidence = []

    # -----------------------------------------------------
    # Derive sources from actual evidence
    # -----------------------------------------------------

    sources = _collect_retrieval_sources(
        evidence
    )

    # Keep any explicitly supplied sources too
    explicit_sources = finding.get(
        "sources",
        [],
    )

    if isinstance(
        explicit_sources,
        list,
    ):

        for source in explicit_sources:

            if (
                source
                and source not in sources
            ):
                sources.append(
                    str(source)
                )

    discrepancies = finding.get(
        "discrepancies",
        [],
    )

    if not isinstance(
        discrepancies,
        list,
    ):
        discrepancies = []

    references = _collect_references(
        finding,
        evidence,
    )

    section = {
        "vulnerability_id": vulnerability_id,

        "asset": (
            f"{asset_name} {installed_version}"
        ),

        "status": status,

        "affected": affected,

        "reason": finding.get(
            "reason"
        ),

        "affected_versions": finding.get(
            "affected_versions",
            [],
        ),

        "patched_versions": finding.get(
            "patched_versions",
            [],
        ),

        "risk": None,

        "recommendation": None,

        "evidence": evidence,

        "sources": sources,

        "references": references,

        "discrepancies": discrepancies,
    }

    # -----------------------------------------------------
    # Risk
    # -----------------------------------------------------

    if risk:

        section["risk"] = {
            "score": risk.get(
                "risk_score"
            ),

            "level": risk.get(
                "risk_level"
            ),

            "factors": risk.get(
                "risk_factors",
                {},
            ),

            "rationale": risk.get(
                "rationale"
            ),

            "normalized_factors": risk.get(
                "normalized_factors",
                {},
            ),

            "scoring_formula": risk.get(
                "scoring_formula"
            ),
        }

    # -----------------------------------------------------
    # Recommendation
    # -----------------------------------------------------

    if recommendation:

        section["recommendation"] = (
            recommendation.get(
                "recommendation",
                {},
            )
        )

        section[
            "recommendation_evidence"
        ] = recommendation.get(
            "evidence_used",
            {},
        )

    return section


# =========================================================
# Markdown report
# =========================================================

def _build_markdown_report(
    project_input: dict[str, Any],
    findings: list[dict[str, Any]],
    errors: list[str],
) -> str:

    project_name = (
        project_input.get(
            "name"
        )
        or project_input.get(
            "project_name"
        )
        or "CyberRAG Vulnerability Assessment"
    )

    lines = [
        "# CyberRAG Vulnerability Assessment Report",
        "",
        f"**Project:** {project_name}",
        f"**Generated:** "
        f"{datetime.now().isoformat(timespec='seconds')}",
        "",
        "## Executive Summary",
        "",
        f"Validated findings: **{len(findings)}**",
        "",
    ]

    if not findings:

        lines.extend(
            [
                "No validated vulnerability findings "
                "are available for reporting.",
                "",
            ]
        )

    # =====================================================
    # Findings
    # =====================================================

    for index, item in enumerate(
        findings,
        start=1,
    ):

        vulnerability_id = item.get(
            "vulnerability_id",
            "Unknown",
        )

        asset = item.get(
            "asset",
            "Unknown asset",
        )

        lines.extend(
            [
                f"## Finding {index}: "
                f"{vulnerability_id}",
                "",
                f"**Asset:** {asset}",
                f"**Status:** "
                f"{item.get('status', 'unknown')}",
                f"**Affected:** "
                f"{item.get('affected', 'unknown')}",
                "",
            ]
        )

        # -------------------------------------------------
        # Validation
        # -------------------------------------------------

        reason = item.get(
            "reason"
        )

        if reason:

            lines.extend(
                [
                    "### Validation",
                    "",
                    str(reason),
                    "",
                ]
            )

        # -------------------------------------------------
        # Affected versions
        # -------------------------------------------------

        affected_versions = item.get(
            "affected_versions",
            [],
        )

        if affected_versions:

            lines.extend(
                [
                    "**Affected versions:** "
                    + ", ".join(
                        map(
                            str,
                            affected_versions,
                        )
                    ),
                    "",
                ]
            )

        # -------------------------------------------------
        # Patched versions
        # -------------------------------------------------

        patched_versions = item.get(
            "patched_versions",
            [],
        )

        if patched_versions:

            lines.extend(
                [
                    "**Patched versions:** "
                    + ", ".join(
                        map(
                            str,
                            patched_versions,
                        )
                    ),
                    "",
                ]
            )

        else:

            lines.extend(
                [
                    "**Patched versions:** "
                    "Not confirmed by available evidence.",
                    "",
                ]
            )

        # -------------------------------------------------
        # Risk
        # -------------------------------------------------

        risk = item.get(
            "risk"
        )

        if risk:

            lines.extend(
                [
                    "### Risk Assessment",
                    "",
                    f"**Risk level:** "
                    f"{str(risk.get('level', 'unknown')).upper()}",
                    f"**Risk score:** "
                    f"{risk.get('score', 'N/A')}",
                    "",
                ]
            )

            rationale = risk.get(
                "rationale"
            )

            if rationale:

                lines.extend(
                    [
                        f"**Rationale:** "
                        f"{rationale}",
                        "",
                    ]
                )

            factors = risk.get(
                "factors",
                {},
            )

            if factors:

                lines.extend(
                    [
                        "**Risk factors:**",
                        "",
                    ]
                )

                for key, value in factors.items():

                    lines.append(
                        f"- {key}: {value}"
                    )

                lines.append("")

        # -------------------------------------------------
        # Recommendation
        # -------------------------------------------------

        recommendation = item.get(
            "recommendation"
        )

        if recommendation:

            lines.extend(
                [
                    "### Recommendation",
                    "",
                    f"**Action:** "
                    f"{recommendation.get('action', 'N/A')}",
                    f"**Priority:** "
                    f"{recommendation.get('priority', 'N/A')}",
                    "",
                ]
            )

            target_version = recommendation.get(
                "target_version"
            )

            if target_version:

                lines.extend(
                    [
                        f"**Target version:** "
                        f"{target_version}",
                        "",
                    ]
                )

            description = recommendation.get(
                "description"
            )

            if description:

                lines.extend(
                    [
                        str(description),
                        "",
                    ]
                )

            mitigation = recommendation.get(
                "mitigation"
            )

            if mitigation:

                lines.extend(
                    [
                        f"**Mitigation:** "
                        f"{mitigation}",
                        "",
                    ]
                )

        # -------------------------------------------------
        # Evidence
        # -------------------------------------------------

        evidence = item.get(
            "evidence",
            [],
        )

        if evidence:

            lines.extend(
                [
                    "### Evidence",
                    "",
                ]
            )

            for evidence_item in evidence:

                if not isinstance(
                    evidence_item,
                    dict,
                ):
                    continue

                lines.extend(
                    _format_evidence_item(
                        evidence_item
                    )
                )

            lines.append("")

        # -------------------------------------------------
        # Retrieval sources
        # -------------------------------------------------

        sources = item.get(
            "sources",
            [],
        )

        if sources:

            lines.extend(
                [
                    "### Retrieval Sources",
                    "",
                ]
            )

            for source in sources:

                lines.append(
                    f"- {source}"
                )

            lines.append("")

        # -------------------------------------------------
        # References
        # -------------------------------------------------

        references = item.get(
            "references",
            [],
        )

        if references:

            lines.extend(
                [
                    "### References",
                    "",
                ]
            )

            for reference in references:

                lines.append(
                    f"- {reference}"
                )

            lines.append("")

        # -------------------------------------------------
        # Discrepancies
        # -------------------------------------------------

        discrepancies = item.get(
            "discrepancies",
            [],
        )

        if discrepancies:

            lines.extend(
                [
                    "### Evidence Limitations / Discrepancies",
                    "",
                ]
            )

            for discrepancy in discrepancies:

                lines.append(
                    f"- {discrepancy}"
                )

            lines.append("")

    # =====================================================
    # Pipeline errors
    # =====================================================

    if errors:

        lines.extend(
            [
                "## Pipeline Errors / Limitations",
                "",
            ]
        )

        for error in errors:

            lines.append(
                f"- {error}"
            )

        lines.append("")

    # =====================================================
    # Scope
    # =====================================================

    lines.extend(
        [
            "## Report Scope",
            "",
            "This report summarizes findings produced "
            "by the CyberRAG analysis pipeline.",
            "It does not independently rediscover "
            "vulnerabilities or replace the evidence "
            "and validation performed by the preceding agents.",
            "",
        ]
    )

    return "\n".join(lines)


# =========================================================
# Report Agent
# =========================================================

def report_agent(
    state: CyberRAGState,
) -> dict[str, Any]:

    project_input = state.get(
        "project_input",
        {},
    )

    if not isinstance(
        project_input,
        dict,
    ):
        project_input = {}

    validated_findings = state.get(
        "validated_findings",
        [],
    )

    if not isinstance(
        validated_findings,
        list,
    ):
        validated_findings = []

    risk_assessments = state.get(
        "risk_assessments",
        [],
    )

    if not isinstance(
        risk_assessments,
        list,
    ):
        risk_assessments = []

    recommendations = state.get(
        "recommendations",
        [],
    )

    if not isinstance(
        recommendations,
        list,
    ):
        recommendations = []

    errors = list(
        state.get(
            "errors",
            [],
        )
    )

    report_findings: list[
        dict[str, Any]
    ] = []

    # =====================================================
    # Combine agents' outputs
    # =====================================================

    for finding in validated_findings:

        if not isinstance(
            finding,
            dict,
        ):
            continue

        vulnerability_id = (
            finding.get(
                "vulnerability_id"
            )
            or finding.get(
                "vulnerability"
            )
        )

        # -------------------------------------------------
        # Match risk
        # -------------------------------------------------

        matching_risk = None

        for risk in risk_assessments:

            if not isinstance(
                risk,
                dict,
            ):
                continue

            if (
                risk.get(
                    "vulnerability_id"
                )
                == vulnerability_id
            ):

                matching_risk = risk
                break

        # -------------------------------------------------
        # Match recommendation
        # -------------------------------------------------

        matching_recommendation = None

        for recommendation in recommendations:

            if not isinstance(
                recommendation,
                dict,
            ):
                continue

            if (
                recommendation.get(
                    "vulnerability_id"
                )
                == vulnerability_id
            ):

                matching_recommendation = (
                    recommendation
                )

                break

        # -------------------------------------------------
        # Build report finding
        # -------------------------------------------------

        report_findings.append(
            _build_finding_section(
                finding,
                matching_risk,
                matching_recommendation,
            )
        )

    # =====================================================
    # Markdown
    # =====================================================

    markdown_report = _build_markdown_report(
        project_input=project_input,
        findings=report_findings,
        errors=errors,
    )

    # =====================================================
    # Final report object
    # =====================================================

    report = {
        "title": (
            "CyberRAG Vulnerability "
            "Assessment Report"
        ),

        "generated_at": datetime.now().isoformat(
            timespec="seconds"
        ),

        "summary": {
            "validated_findings": len(
                report_findings
            ),
            "errors": len(
                errors
            ),
        },

        "findings": report_findings,

        "markdown": markdown_report,
    }

    # =====================================================
    # Citations
    # =====================================================

    citations: list[str] = []

    for finding in report_findings:

        for reference in finding.get(
            "references",
            [],
        ):

            if (
                reference
                and reference not in citations
            ):
                citations.append(
                    reference
                )

    return {
        "report": report,
        "citations": citations,
        "errors": errors,
    }