from typing import Any

from app.agents.state import CyberRAGState


# =========================================================
# CyberRAG Risk Assessment
# =========================================================
#
# The architecture defines these risk factors:
#
#   CVSS
#   EPSS
#   CISA KEV
#   Exploit availability
#   Asset criticality
#   Business impact
#
# The architecture does NOT define a fixed scoring formula.
#
# Therefore, this implementation explicitly documents the
# formula used here.
#
# Risk Score = weighted sum of six normalized factors:
#
#   CVSS                 40%
#   EPSS                 20%
#   KEV                  15%
#   Exploit availability 10%
#   Asset criticality    10%
#   Business impact       5%
#
# Total = 100%
#
# This formula is an implementation choice, not a formula
# prescribed by the architecture document.
# =========================================================


# ---------------------------------------------------------
# Risk weights
# ---------------------------------------------------------

CVSS_WEIGHT = 0.40
EPSS_WEIGHT = 0.20
KEV_WEIGHT = 0.15
EXPLOIT_WEIGHT = 0.10
CRITICALITY_WEIGHT = 0.10
BUSINESS_IMPACT_WEIGHT = 0.05


# ---------------------------------------------------------
# Normalization helpers
# ---------------------------------------------------------


def _normalize_cvss(value: Any) -> float:
    """
    Normalize CVSS 0-10 to 0-100.
    """

    if value is None:
        return 0.0

    try:
        score = float(value)
    except (TypeError, ValueError):
        return 0.0

    score = max(0.0, min(score, 10.0))

    return score * 10.0


def _normalize_epss(value: Any) -> float:
    """
    Normalize EPSS probability 0-1 to 0-100.
    """

    if value is None:
        return 0.0

    try:
        score = float(value)
    except (TypeError, ValueError):
        return 0.0

    score = max(0.0, min(score, 1.0))

    return score * 100.0


def _normalize_boolean(value: Any) -> float:
    """
    Convert boolean threat signals into 0 or 100.
    """

    if value is True:
        return 100.0

    if value is False:
        return 0.0

    return 0.0


def _normalize_criticality(value: Any) -> float:
    """
    Convert asset criticality into a 0-100 score.
    """

    if value is None:
        return 0.0

    criticality = str(value).strip().lower()

    mapping = {
        "critical": 100.0,
        "high": 75.0,
        "medium": 50.0,
        "low": 25.0,
        "informational": 0.0,
        "info": 0.0,
    }

    return mapping.get(criticality, 0.0)


def _normalize_business_impact(value: Any) -> float:
    """
    Convert business impact into a 0-100 score.

    The architecture identifies business impact as a factor
    but does not prescribe its exact representation.
    """

    if value is None:
        return 0.0

    if isinstance(value, (int, float)):
        score = float(value)

        # Allow either 0-10 or 0-100 representation.
        if score <= 10:
            score *= 10.0

        return max(0.0, min(score, 100.0))

    impact = str(value).strip().lower()

    mapping = {
        "critical": 100.0,
        "high": 75.0,
        "medium": 50.0,
        "low": 25.0,
        "minimal": 10.0,
        "none": 0.0,
    }

    return mapping.get(impact, 0.0)


# ---------------------------------------------------------
# Risk level
# ---------------------------------------------------------


def _risk_level(score: float) -> str:
    """
    Human-readable interpretation of the calculated score.

    These bands are implementation conventions and are not
    defined by the architecture document.
    """

    if score >= 80:
        return "critical"

    if score >= 60:
        return "high"

    if score >= 40:
        return "medium"

    if score >= 20:
        return "low"

    return "minimal"


# ---------------------------------------------------------
# Extract vulnerability intelligence
# ---------------------------------------------------------


def _extract_vulnerability_factors(
    finding: dict[str, Any],
) -> dict[str, Any]:
    """
    Extract CVSS, EPSS, KEV and exploit information from
    the validated finding and its evidence.

    Validation output may contain the evidence from:
    PostgreSQL/Qdrant and Web Search.
    """

    cvss = None
    epss = None
    kev = None
    exploit_available = None

    # -----------------------------------------------------
    # Direct fields, if available
    # -----------------------------------------------------

    if finding.get("cvss") is not None:
        cvss = finding.get("cvss")

    if finding.get("epss") is not None:
        epss = finding.get("epss")

    if finding.get("kev") is not None:
        kev = finding.get("kev")

    if finding.get("exploit_available") is not None:
        exploit_available = finding.get(
            "exploit_available"
        )

    # -----------------------------------------------------
    # Inspect evidence
    # -----------------------------------------------------

    evidence_items = finding.get(
        "evidence",
        [],
    )

    if not isinstance(evidence_items, list):
        evidence_items = []

    for evidence in evidence_items:

        if not isinstance(evidence, dict):
            continue

        # Internal evidence
        if evidence.get("cvss") is not None:
            cvss = evidence.get("cvss")

        if evidence.get("epss") is not None:
            epss = evidence.get("epss")

        if evidence.get("kev") is not None:
            kev = evidence.get("kev")

        if evidence.get("exploit_available") is not None:
            exploit_available = evidence.get(
                "exploit_available"
            )

        # Some evidence can contain a nested
        # vulnerability record.
        vulnerability_data = evidence.get(
            "vulnerability"
        )

        if isinstance(vulnerability_data, dict):

            if vulnerability_data.get("cvss") is not None:
                cvss = vulnerability_data.get("cvss")

            if vulnerability_data.get("epss") is not None:
                epss = vulnerability_data.get("epss")

            if vulnerability_data.get("kev") is not None:
                kev = vulnerability_data.get("kev")

            if (
                vulnerability_data.get(
                    "exploit_available"
                )
                is not None
            ):
                exploit_available = vulnerability_data.get(
                    "exploit_available"
                )

    return {
        "cvss": cvss,
        "epss": epss,
        "kev": kev,
        "exploit_available": exploit_available,
    }


# ---------------------------------------------------------
# Risk Assessment Agent
# ---------------------------------------------------------


def risk_assessment_agent(
    state: CyberRAGState,
) -> dict[str, Any]:
    """
    Agent 6: Risk Assessment Agent.

    Input:
        Validated findings
        Organization assets
        Vulnerability intelligence
        Asset criticality
        Business impact

    Output:
        Risk assessments

    This agent does NOT:
        - search for new vulnerabilities
        - perform vulnerability matching
        - change validated vulnerability facts
        - generate remediation recommendations
    """

    validated_findings = state.get(
        "validated_findings",
        [],
    )

    assets = state.get(
        "assets",
        [],
    )

    errors = list(
        state.get(
            "errors",
            [],
        )
    )

    risk_assessments: list[dict[str, Any]] = []

    for finding in validated_findings:

        # -------------------------------------------------
        # Only assess validated findings
        # -------------------------------------------------

        if finding.get("status") != "validated":
            continue

        if finding.get("affected") is not True:
            continue

        vulnerability_id = (
            finding.get("vulnerability_id")
            or finding.get("vulnerability")
        )

        asset_data = finding.get(
            "asset",
            {},
        )

        if not isinstance(asset_data, dict):
            asset_data = {}

        asset_id = asset_data.get(
            "id"
        )

        asset_name = asset_data.get(
            "name"
        )

        installed_version = asset_data.get(
            "version"
        )

        # -------------------------------------------------
        # Locate matching organization asset
        # -------------------------------------------------

        organization_asset = None

        for asset in assets:

            if not isinstance(asset, dict):
                continue

            if asset_id and asset.get("id") == asset_id:
                organization_asset = asset
                break

            if (
                asset_name
                and str(
                    asset.get("name", "")
                ).lower()
                == str(asset_name).lower()
            ):
                organization_asset = asset
                break

        if organization_asset:

            asset_id = (
                asset_id
                or organization_asset.get("id")
            )

            installed_version = (
                installed_version
                or organization_asset.get(
                    "version"
                )
            )

            asset_criticality = (
                organization_asset.get(
                    "criticality"
                )
            )

            business_impact = (
                organization_asset.get(
                    "business_impact"
                )
            )

        else:

            asset_criticality = asset_data.get(
                "criticality"
            )

            business_impact = asset_data.get(
                "business_impact"
            )

        # -------------------------------------------------
        # Extract vulnerability factors
        # -------------------------------------------------

        vulnerability_factors = (
            _extract_vulnerability_factors(
                finding
            )
        )

        cvss = vulnerability_factors["cvss"]
        epss = vulnerability_factors["epss"]
        kev = vulnerability_factors["kev"]
        exploit_available = vulnerability_factors[
            "exploit_available"
        ]

        # -------------------------------------------------
        # Normalize factors
        # -------------------------------------------------

        normalized_cvss = _normalize_cvss(
            cvss
        )

        normalized_epss = _normalize_epss(
            epss
        )

        normalized_kev = _normalize_boolean(
            kev
        )

        normalized_exploit = _normalize_boolean(
            exploit_available
        )

        normalized_criticality = (
            _normalize_criticality(
                asset_criticality
            )
        )

        normalized_business_impact = (
            _normalize_business_impact(
                business_impact
            )
        )

        # -------------------------------------------------
        # Calculate weighted risk score
        # -------------------------------------------------

        risk_score = (
            normalized_cvss
            * CVSS_WEIGHT
            + normalized_epss
            * EPSS_WEIGHT
            + normalized_kev
            * KEV_WEIGHT
            + normalized_exploit
            * EXPLOIT_WEIGHT
            + normalized_criticality
            * CRITICALITY_WEIGHT
            + normalized_business_impact
            * BUSINESS_IMPACT_WEIGHT
        )

        risk_score = round(
            max(
                0.0,
                min(
                    risk_score,
                    100.0,
                ),
            ),
            2,
        )

        risk_level = _risk_level(
            risk_score
        )

        # -------------------------------------------------
        # Build rationale
        # -------------------------------------------------

        rationale_parts = []

        if cvss is not None:
            rationale_parts.append(
                f"CVSS={cvss}"
            )

        if epss is not None:
            rationale_parts.append(
                f"EPSS={epss}"
            )

        if kev is True:
            rationale_parts.append(
                "CISA KEV=true"
            )

        if exploit_available is True:
            rationale_parts.append(
                "exploit_available=true"
            )

        if asset_criticality:
            rationale_parts.append(
                f"asset_criticality={asset_criticality}"
            )

        if business_impact:
            rationale_parts.append(
                f"business_impact={business_impact}"
            )

        rationale = (
            "Organizational risk was calculated from "
            "the validated vulnerability using "
            "CVSS, EPSS, CISA KEV, exploit availability, "
            "asset criticality, and business impact. "
        )

        if rationale_parts:
            rationale += (
                "Observed factors: "
                + ", ".join(rationale_parts)
                + "."
            )

        else:
            rationale += (
                "Some risk factors were unavailable "
                "and were therefore not assigned "
                "additional weight."
            )

        # -------------------------------------------------
        # Output
        # -------------------------------------------------

        risk_assessments.append(
            {
                "vulnerability_id": vulnerability_id,
                "asset_id": asset_id,
                "asset": {
                    "name": asset_name,
                    "version": installed_version,
                    "criticality": asset_criticality,
                    "business_impact": business_impact,
                },
                "risk_score": risk_score,
                "risk_level": risk_level,
                "risk_factors": {
                    "cvss": cvss,
                    "epss": epss,
                    "kev": kev,
                    "exploit_available": (
                        exploit_available
                    ),
                    "asset_criticality": (
                        asset_criticality
                    ),
                    "business_impact": (
                        business_impact
                    ),
                },
                "normalized_factors": {
                    "cvss": normalized_cvss,
                    "epss": normalized_epss,
                    "kev": normalized_kev,
                    "exploit_available": (
                        normalized_exploit
                    ),
                    "asset_criticality": (
                        normalized_criticality
                    ),
                    "business_impact": (
                        normalized_business_impact
                    ),
                },
                "scoring_formula": {
                    "cvss_weight": CVSS_WEIGHT,
                    "epss_weight": EPSS_WEIGHT,
                    "kev_weight": KEV_WEIGHT,
                    "exploit_weight": EXPLOIT_WEIGHT,
                    "asset_criticality_weight": (
                        CRITICALITY_WEIGHT
                    ),
                    "business_impact_weight": (
                        BUSINESS_IMPACT_WEIGHT
                    ),
                },
                "rationale": rationale,
            }
        )

    return {
        "risk_assessments": risk_assessments,
        "errors": errors,
    }