from typing import Any

from app.agents.state import CyberRAGState


# =========================================================
# Helper: Find documented fixed version
# =========================================================

def _find_fixed_version(
    finding: dict[str, Any],
) -> str | None:
    """
    Extract a documented patched/fixed version.

    Never invent a target version.
    """

    patched_versions = finding.get(
        "patched_versions",
        [],
    )

    if isinstance(patched_versions, str):
        value = patched_versions.strip()

        if value:
            return value

        return None

    if isinstance(patched_versions, list):

        valid_versions = [
            str(version).strip()
            for version in patched_versions
            if version
        ]

        if valid_versions:
            return ", ".join(valid_versions)

    return None


# =========================================================
# Helper: Collect remediation-related evidence
# =========================================================

def _collect_remediation_evidence(
    finding: dict[str, Any],
) -> list[dict[str, Any]]:
    """
    Collect external evidence that may contain remediation,
    patch, mitigation, or vendor guidance.

    This function DOES NOT decide that the vulnerability is
    fixed. It only collects evidence supplied by previous
    agents.
    """

    evidence = finding.get(
        "evidence",
        [],
    )

    if not isinstance(evidence, list):
        return []

    remediation_evidence: list[dict[str, Any]] = []

    allowed_source_types = {
        "vendor_advisory",
        "patch_information",
        "security_advisory",
        "mitigation",
        "github_advisory",
        "nvd",
        "cisa_kev",
    }

    for item in evidence:

        if not isinstance(item, dict):
            continue

        source_type = item.get(
            "source_type"
        )

        if source_type in allowed_source_types:
            remediation_evidence.append(item)

    return remediation_evidence


# =========================================================
# Helper: Merge Web Evidence into Finding Evidence
# =========================================================

def _merge_web_evidence_into_finding(
    finding: dict[str, Any],
    web_evidence: list[dict[str, Any]],
) -> dict[str, Any]:
    """
    Merge matching web evidence into the finding.

    Only evidence belonging to the same vulnerability is added.
    """

    finding_copy = dict(finding)

    existing_evidence = list(
        finding_copy.get(
            "evidence",
            [],
        )
        or []
    )

    vulnerability_id = (
        finding.get("vulnerability_id")
        or finding.get("vulnerability")
    )

    cve = finding.get("cve")

    existing_keys = set()

    for item in existing_evidence:

        if not isinstance(item, dict):
            continue

        key = (
            item.get("source_type"),
            item.get("url"),
            item.get("cve"),
        )

        existing_keys.add(key)

    for item in web_evidence:

        if not isinstance(item, dict):
            continue

        same_vulnerability = False

        item_vulnerability_id = item.get(
            "vulnerability_id"
        )

        item_cve = item.get("cve")

        if (
            vulnerability_id
            and item_vulnerability_id
            and item_vulnerability_id == vulnerability_id
        ):
            same_vulnerability = True

        if (
            cve
            and item_cve
            and item_cve == cve
        ):
            same_vulnerability = True

        if not same_vulnerability:
            continue

        key = (
            item.get("source_type"),
            item.get("url"),
            item.get("cve"),
        )

        if key in existing_keys:
            continue

        existing_evidence.append(item)
        existing_keys.add(key)

    finding_copy["evidence"] = existing_evidence

    # -----------------------------------------------------
    # Recover patched versions from web evidence when
    # previous agents have not already supplied them.
    # -----------------------------------------------------

    patched_versions = list(
        finding_copy.get(
            "patched_versions",
            [],
        )
        or []
    )

    if isinstance(
        finding_copy.get("patched_versions"),
        str,
    ):
        patched_versions = [
            finding_copy["patched_versions"]
        ]

    for item in existing_evidence:

        if not isinstance(item, dict):
            continue

        source_type = item.get(
            "source_type"
        )

        if source_type not in {
            "patch_information",
            "vendor_advisory",
            "security_advisory",
            "github_advisory",
        }:
            continue

        relevant_information = item.get(
            "relevant_information"
        )

        if not isinstance(
            relevant_information,
            dict,
        ):
            continue

        versions_found = relevant_information.get(
            "versions_found",
            [],
        )

        if not isinstance(
            versions_found,
            list,
        ):
            continue

        for version in versions_found:

            if not version:
                continue

            version_string = str(version).strip()

            if (
                version_string
                and version_string not in patched_versions
            ):
                patched_versions.append(
                    version_string
                )

    finding_copy["patched_versions"] = patched_versions

    return finding_copy


# =========================================================
# Helper: Collect references
# =========================================================

def _collect_references(
    finding: dict[str, Any],
    remediation_evidence: list[dict[str, Any]],
) -> list[str]:
    """
    Collect URLs/references already supplied by evidence.
    """

    references: list[str] = []

    finding_references = finding.get(
        "references",
        [],
    )

    if isinstance(
        finding_references,
        list,
    ):

        for reference in finding_references:

            if (
                reference
                and reference not in references
            ):
                references.append(
                    str(reference)
                )

    for item in finding.get(
        "evidence",
        [],
    ):

        if not isinstance(item, dict):
            continue

        url = item.get("url")

        if (
            url
            and url not in references
        ):
            references.append(
                str(url)
            )

        item_references = item.get(
            "references",
            [],
        )

        if isinstance(
            item_references,
            list,
        ):

            for reference in item_references:

                if (
                    reference
                    and reference not in references
                ):
                    references.append(
                        str(reference)
                    )

    return references


# =========================================================
# Helper: Build evidence summary
# =========================================================

def _build_evidence_summary(
    finding: dict[str, Any],
    remediation_evidence: list[dict[str, Any]],
) -> dict[str, Any]:
    """
    Preserve what evidence was actually used.
    """

    source_types: list[str] = []

    for item in remediation_evidence:

        source_type = item.get(
            "source_type"
        )

        if (
            source_type
            and source_type not in source_types
        ):
            source_types.append(
                source_type
            )

    return {
        "patched_versions": finding.get(
            "patched_versions",
            [],
        ),
        "remediation_evidence_count": len(
            remediation_evidence
        ),
        "remediation_sources": source_types,
    }


# =========================================================
# Build recommendation
# =========================================================

def _build_recommendation(
    finding: dict[str, Any],
    risk: dict[str, Any],
) -> dict[str, Any]:
    """
    Build an evidence-based remediation recommendation.

    The agent must not invent a target version or mitigation.
    """

    vulnerability_id = (
        finding.get("vulnerability_id")
        or finding.get("vulnerability")
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
        "name"
    )

    installed_version = asset.get(
        "version"
    )

    patched_version = _find_fixed_version(
        finding
    )

    risk_level = risk.get(
        "risk_level",
        "unknown",
    )

    risk_score = risk.get(
        "risk_score"
    )

    remediation_evidence = (
        _collect_remediation_evidence(
            finding
        )
    )

    references = _collect_references(
        finding,
        remediation_evidence,
    )

    # -----------------------------------------------------
    # Determine recommendation
    # -----------------------------------------------------

    if patched_version:

        action = "upgrade"

        recommendation_text = (
            f"Upgrade {asset_name or 'the affected asset'} "
            f"from installed version "
            f"{installed_version or 'the current version'} "
            f"to the documented patched/fixed version: "
            f"{patched_version}."
        )

        mitigation = (
            "Apply the documented vendor security update "
            "or other evidence-supported fixed version."
        )

    elif remediation_evidence:

        action = "apply_vendor_guidance"

        recommendation_text = (
            "Review and apply the remediation or mitigation "
            "guidance documented in the available security "
            "advisory evidence."
        )

        mitigation = (
            "Follow only the remediation or mitigation "
            "guidance explicitly documented by the cited "
            "security sources. Do not infer an unverified "
            "target version."
        )

    else:

        action = "investigate"

        recommendation_text = (
            "Obtain confirmed vendor remediation or "
            "mitigation guidance before selecting a "
            "specific remediation action."
        )

        mitigation = (
            "Do not invent a target version or mitigation. "
            "Further verification is required."
        )

    # -----------------------------------------------------
    # Priority
    # -----------------------------------------------------

    if risk_level == "critical":
        priority = "urgent"

    elif risk_level == "high":
        priority = "high"

    elif risk_level == "medium":
        priority = "medium"

    elif risk_level == "low":
        priority = "low"

    else:
        priority = "review"

    return {
        "vulnerability_id": vulnerability_id,

        "asset": (
            f"{asset_name} {installed_version}"
            if asset_name and installed_version
            else asset_name
        ),

        "recommendation": {
            "action": action,
            "target_version": patched_version,
            "priority": priority,
            "description": recommendation_text,
            "mitigation": mitigation,
        },

        "risk": {
            "risk_score": risk_score,
            "risk_level": risk_level,
        },

        "references": references,

        "evidence_used": _build_evidence_summary(
            finding,
            remediation_evidence,
        ),
    }


# =========================================================
# Recommendation Agent
# =========================================================

def recommendation_agent(
    state: CyberRAGState,
) -> dict[str, Any]:
    """
    Agent 7: Recommendation Agent.

    Converts validated and risk-assessed findings into
    evidence-supported remediation recommendations.

    This agent does NOT:
        - discover vulnerabilities
        - change vulnerability facts
        - perform validation
        - calculate risk
        - invent patched versions
        - invent mitigation guidance
    """

    validated_findings = state.get(
        "validated_findings",
        [],
    )

    risk_assessments = state.get(
        "risk_assessments",
        [],
    )

    web_evidence = state.get(
        "web_evidence",
        [],
    )

    errors = list(
        state.get(
            "errors",
            [],
        )
    )

    recommendations: list[dict[str, Any]] = []

    # -----------------------------------------------------
    # Match validated finding with risk assessment
    # -----------------------------------------------------

    for finding in validated_findings:

        if finding.get("status") != "validated":
            continue

        vulnerability_id = (
            finding.get("vulnerability_id")
            or finding.get("vulnerability")
        )

        matching_risk = None

        for risk in risk_assessments:

            if (
                risk.get("vulnerability_id")
                == vulnerability_id
            ):
                matching_risk = risk
                break

        # -------------------------------------------------
        # Missing risk assessment
        # -------------------------------------------------

        if matching_risk is None:

            errors.append(
                "No risk assessment found for "
                f"{vulnerability_id}."
            )

            continue

        # -------------------------------------------------
        # Merge latest Web Search evidence
        # -------------------------------------------------

        finding_with_web_evidence = (
            _merge_web_evidence_into_finding(
                finding,
                web_evidence,
            )
        )

        # -------------------------------------------------
        # Build recommendation
        # -------------------------------------------------

        try:

            recommendation = _build_recommendation(
                finding_with_web_evidence,
                matching_risk,
            )

            recommendations.append(
                recommendation
            )

        except Exception as exc:

            errors.append(
                "Recommendation generation failed "
                f"for {vulnerability_id}: {exc}"
            )

    return {
        "recommendations": recommendations,
        "errors": errors,
    }