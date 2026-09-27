from typing import Any

from packaging.specifiers import SpecifierSet
from packaging.version import InvalidVersion, Version

from app.agents.state import CyberRAGState


# =========================================================
# Version helpers
# =========================================================

def _parse_version(value: Any) -> Version | None:
    """Safely convert a version string into packaging Version."""

    if value is None:
        return None

    value = str(value).strip()

    if not value:
        return None

    try:
        return Version(value)
    except InvalidVersion:
        return None


def _version_in_range(
    installed_version: Any,
    affected_ranges: Any,
) -> bool | None:
    """
    Determine whether installed version falls inside
    the vulnerability affected version range.
    """

    installed = _parse_version(installed_version)

    if installed is None:
        return None

    if not affected_ranges:
        return None

    if isinstance(affected_ranges, str):
        affected_ranges = [affected_ranges]

    if not isinstance(affected_ranges, list):
        return None

    for raw_range in affected_ranges:

        if raw_range is None:
            continue

        range_text = str(raw_range).strip()

        if not range_text:
            continue

        # Python packaging specifiers
        try:
            if any(
                operator in range_text
                for operator in ["<", ">", "=", "!", "~"]
            ):
                try:
                    specifier = SpecifierSet(range_text)

                    if installed in specifier:
                        return True

                    continue
                except Exception:
                    pass

        except Exception:
            pass

        # Human-readable range
        # Example: 2.0 - 2.14.1
        if " - " in range_text:

            parts = range_text.split(" - ", 1)

            if len(parts) == 2:

                lower = _parse_version(parts[0])
                upper = _parse_version(parts[1])

                if lower and upper:

                    if lower <= installed <= upper:
                        return True

                    continue

        # Exact version
        exact = _parse_version(range_text)

        if exact is not None:

            if installed == exact:
                return True

    return False


def _version_is_patched(
    installed_version: Any,
    patched_versions: Any,
) -> bool | None:
    """
    Determine whether installed version is at or above
    a known patched version.
    """

    installed = _parse_version(installed_version)

    if installed is None:
        return None

    if not patched_versions:
        return None

    if isinstance(patched_versions, str):
        patched_versions = [patched_versions]

    if not isinstance(patched_versions, list):
        return None

    parsed_patches: list[Version] = []

    for value in patched_versions:

        parsed = _parse_version(value)

        if parsed:
            parsed_patches.append(parsed)

    if not parsed_patches:
        return None

    earliest_patch = min(parsed_patches)

    return installed >= earliest_patch


# =========================================================
# Deduplication / merge helpers
# =========================================================

def _merge_unique_values(*values: Any) -> list[Any]:
    """
    Merge list/scalar values while preserving order
    and removing duplicates.
    """

    result: list[Any] = []

    for value in values:

        if value is None:
            continue

        if isinstance(value, (list, tuple, set)):
            items = value
        else:
            items = [value]

        for item in items:

            if item is None:
                continue

            if item not in result:
                result.append(item)

    return result


def _best_numeric_value(*values: Any) -> Any:
    """
    Return the strongest/largest numeric value available.

    Used for retrieval scores where multiple retrieval
    records exist for the same vulnerability.
    """

    numeric_values: list[float] = []

    original_values: list[Any] = []

    for value in values:

        if value is None:
            continue

        original_values.append(value)

        try:
            numeric_values.append(float(value))
        except (TypeError, ValueError):
            continue

    if numeric_values:
        return max(numeric_values)

    if original_values:
        return original_values[0]

    return None


def _merge_internal_evidence(
    related_internal: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """
    Deduplicate internal PostgreSQL/Qdrant evidence.

    Multiple lexical/semantic retrieval records for the
    same vulnerability are merged into ONE evidence record.

    Important:
    - lexical_score is preserved
    - semantic_score is preserved
    - retrieval_sources are unioned
    - CVSS/EPSS/KEV/exploit information is preserved
    - affected/patched versions are merged
    - references are merged
    """

    merged: dict[str, dict[str, Any]] = {}

    for item in related_internal:

        cve = str(item.get("cve") or "").strip()
        vulnerability_id = str(
            item.get("vulnerability_id") or ""
        ).strip()

        # Prefer CVE as primary identity.
        if cve:
            key = f"cve:{cve}"
        elif vulnerability_id:
            key = f"id:{vulnerability_id}"
        else:
            # Unknown identity should not accidentally merge
            # unrelated evidence.
            key = f"unknown:{id(item)}"

        if key not in merged:

            merged[key] = dict(item)

            merged[key]["affected_versions"] = (
                _merge_unique_values(
                    item.get("affected_versions", [])
                )
            )

            merged[key]["patched_versions"] = (
                _merge_unique_values(
                    item.get("patched_versions", [])
                )
            )

            merged[key]["references"] = (
                _merge_unique_values(
                    item.get("references", [])
                )
            )

            merged[key]["retrieval_sources"] = (
                _merge_unique_values(
                    item.get("retrieval_sources", [])
                )
            )

            merged[key]["lexical_score"] = item.get(
                "lexical_score"
            )

            merged[key]["semantic_score"] = item.get(
                "semantic_score"
            )

            continue

        existing = merged[key]

        # -------------------------------------------------
        # Fill missing scalar information
        # -------------------------------------------------

        scalar_fields = [
            "vulnerability_id",
            "cve",
            "title",
            "description",
            "vendor",
            "product",
            "cvss",
            "cvss_vector",
            "epss",
            "kev",
            "exploit_available",
        ]

        for field in scalar_fields:

            if existing.get(field) is None:
                if item.get(field) is not None:
                    existing[field] = item.get(field)

        # -------------------------------------------------
        # Merge version information
        # -------------------------------------------------

        existing["affected_versions"] = _merge_unique_values(
            existing.get("affected_versions", []),
            item.get("affected_versions", []),
        )

        existing["patched_versions"] = _merge_unique_values(
            existing.get("patched_versions", []),
            item.get("patched_versions", []),
        )

        # -------------------------------------------------
        # Merge references
        # -------------------------------------------------

        existing["references"] = _merge_unique_values(
            existing.get("references", []),
            item.get("references", []),
        )

        # -------------------------------------------------
        # Merge retrieval sources
        # -------------------------------------------------

        existing["retrieval_sources"] = _merge_unique_values(
            existing.get("retrieval_sources", []),
            item.get("retrieval_sources", []),
        )

        # -------------------------------------------------
        # Preserve BEST lexical score
        # -------------------------------------------------

        existing["lexical_score"] = _best_numeric_value(
            existing.get("lexical_score"),
            item.get("lexical_score"),
        )

        # -------------------------------------------------
        # Preserve BEST semantic score
        # -------------------------------------------------

        existing["semantic_score"] = _best_numeric_value(
            existing.get("semantic_score"),
            item.get("semantic_score"),
        )

    return list(merged.values())


def _merge_web_evidence(
    related_web: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """
    Deduplicate external evidence.

    Stable identity:
        source_type + URL + CVE

    This keeps different sources separate while removing
    exact duplicates.
    """

    merged: dict[str, dict[str, Any]] = {}

    for item in related_web:

        source_type = str(
            item.get("source_type") or ""
        ).strip()

        url = str(
            item.get("url") or ""
        ).strip()

        cve = str(
            item.get("cve")
            or item.get("vulnerability_id")
            or ""
        ).strip()

        key = "|".join(
            [
                source_type,
                url,
                cve,
            ]
        )

        if not key.strip("|"):

            key = f"unknown:{id(item)}"

        if key not in merged:

            merged[key] = dict(item)
            continue

        existing = merged[key]

        # Fill missing fields.
        for field in [
            "source_type",
            "source",
            "url",
            "cve",
            "vulnerability_id",
            "cvss",
            "epss",
            "kev",
            "exploit_available",
            "published_at",
            "relevant_information",
        ]:

            if existing.get(field) is None:

                if item.get(field) is not None:
                    existing[field] = item.get(field)

    return list(merged.values())


# =========================================================
# Identity validation
# =========================================================

def _validate_identity(
    candidate: dict[str, Any],
    evidence: list[dict[str, Any]],
) -> bool:

    candidate_cve = candidate.get("cve")
    candidate_id = candidate.get("vulnerability_id")

    if not candidate_cve and not candidate_id:
        return False

    for item in evidence:

        if candidate_cve and item.get("cve") == candidate_cve:
            return True

        if (
            candidate_id
            and item.get("vulnerability_id") == candidate_id
        ):
            return True

    return False


# =========================================================
# Product validation
# =========================================================

def _validate_product(
    candidate: dict[str, Any],
    evidence: list[dict[str, Any]],
) -> bool:

    candidate_vendor = candidate.get("vendor")
    candidate_product = candidate.get("product")

    for item in evidence:

        vendor_matches = True
        product_matches = True

        if candidate_vendor:

            evidence_vendor = item.get("vendor")

            if evidence_vendor:

                vendor_matches = (
                    str(candidate_vendor).lower()
                    == str(evidence_vendor).lower()
                )

        if candidate_product:

            evidence_product = item.get("product")

            if evidence_product:

                product_matches = (
                    str(candidate_product).lower()
                    == str(evidence_product).lower()
                )

        if vendor_matches and product_matches:
            return True

    return False


# =========================================================
# Source corroboration
# =========================================================

def _collect_sources(
    internal_evidence: list[dict[str, Any]],
    web_evidence: list[dict[str, Any]],
) -> list[str]:

    sources: list[str] = []

    for item in internal_evidence:

        for source in item.get(
            "retrieval_sources",
            [],
        ):

            if source not in sources:
                sources.append(source)

    for item in web_evidence:

        source_type = item.get("source_type")

        if source_type and source_type not in sources:
            sources.append(source_type)

    return sources


# =========================================================
# Vulnerability intelligence extraction
# =========================================================

def _extract_vulnerability_intelligence(
    candidate: dict[str, Any],
    internal_evidence: list[dict[str, Any]],
    web_evidence: list[dict[str, Any]],
) -> dict[str, Any]:
    """
    Preserve vulnerability intelligence from PostgreSQL/Qdrant
    and external web evidence.

    This data is required by the Risk Assessment Agent.
    """

    result = {
        "cvss": candidate.get("cvss"),
        "cvss_vector": candidate.get("cvss_vector"),
        "epss": candidate.get("epss"),
        "kev": candidate.get("kev"),
        "exploit_available": candidate.get(
            "exploit_available"
        ),
    }

    # Internal evidence is authoritative when available.
    for item in internal_evidence:

        if item.get("cvss") is not None:
            result["cvss"] = item.get("cvss")

        if item.get("cvss_vector") is not None:
            result["cvss_vector"] = item.get(
                "cvss_vector"
            )

        if item.get("epss") is not None:
            result["epss"] = item.get("epss")

        if item.get("kev") is not None:
            result["kev"] = item.get("kev")

        if item.get("exploit_available") is not None:
            result["exploit_available"] = item.get(
                "exploit_available"
            )

    # Web evidence can supplement missing values.
    for item in web_evidence:

        if (
            result["cvss"] is None
            and item.get("cvss") is not None
        ):
            result["cvss"] = item.get("cvss")

        if (
            result["epss"] is None
            and item.get("epss") is not None
        ):
            result["epss"] = item.get("epss")

        if (
            result["kev"] is None
            and item.get("kev") is not None
        ):
            result["kev"] = item.get("kev")

        if (
            result["exploit_available"] is None
            and item.get("exploit_available") is not None
        ):
            result["exploit_available"] = item.get(
                "exploit_available"
            )

    return result


# =========================================================
# Validation Agent
# =========================================================

def validation_agent(
    state: CyberRAGState,
) -> dict[str, Any]:
    """
    Agent 5: Validation Agent.

    Determines whether candidate vulnerabilities are
    sufficiently supported and applicable.

    Validation checks:

    1. Identity
    2. Product
    3. Installed version
    4. Patch information
    5. Source corroboration

    This agent does NOT calculate organizational risk.
    """

    candidates = state.get(
        "candidate_vulnerabilities",
        [],
    )

    assets = state.get(
        "assets",
        [],
    )

    internal_evidence = state.get(
        "internal_evidence",
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

    validated_findings: list[dict[str, Any]] = []

    for candidate in candidates:

        cve = candidate.get("cve")

        vulnerability_id = candidate.get(
            "vulnerability_id"
        )

        # -------------------------------------------------
        # Find related internal evidence
        # -------------------------------------------------

        related_internal_raw = [
            item
            for item in internal_evidence
            if (
                item.get("cve") == cve
                or item.get("vulnerability_id")
                == vulnerability_id
            )
        ]

        # IMPORTANT:
        # Merge duplicate lexical/semantic retrieval
        # records before doing validation.
        related_internal = _merge_internal_evidence(
            related_internal_raw
        )

        # -------------------------------------------------
        # Find related web evidence
        # -------------------------------------------------

        related_web_raw = [
            item
            for item in web_evidence
            if (
                item.get("cve") == cve
                or item.get("vulnerability_id")
                == vulnerability_id
            )
        ]

        related_web = _merge_web_evidence(
            related_web_raw
        )

        # -------------------------------------------------
        # Find asset
        # -------------------------------------------------

        candidate_asset = candidate.get(
            "asset",
            {},
        )

        if not isinstance(candidate_asset, dict):
            candidate_asset = {}

        asset_name = (
            candidate_asset.get("name")
            or candidate.get("product")
        )

        installed_version = (
            candidate.get("asset_version")
            or candidate_asset.get("version")
        )

        # If asset was not embedded in candidate,
        # find it in state.
        if not installed_version and asset_name:

            for asset in assets:

                if (
                    str(asset.get("name", "")).lower()
                    == str(asset_name).lower()
                ):

                    installed_version = asset.get(
                        "version"
                    )

                    break

        # -------------------------------------------------
        # Use merged internal evidence
        # -------------------------------------------------

        evidence = (
            related_internal[0]
            if related_internal
            else candidate
        )

        affected_versions = evidence.get(
            "affected_versions"
        )

        patched_versions = evidence.get(
            "patched_versions"
        )

        # -------------------------------------------------
        # Validation checks
        # -------------------------------------------------

        identity_valid = _validate_identity(
            candidate,
            related_internal,
        )

        if not identity_valid and related_web:
            identity_valid = True

        product_valid = _validate_product(
            candidate,
            related_internal,
        )

        if not product_valid and related_web:
            product_valid = True

        version_affected = _version_in_range(
            installed_version,
            affected_versions,
        )

        patch_status = _version_is_patched(
            installed_version,
            patched_versions,
        )

        corroborating_sources = _collect_sources(
            related_internal,
            related_web,
        )

        source_corroborated = (
            len(corroborating_sources) > 0
        )

        # -------------------------------------------------
        # Discrepancies
        # -------------------------------------------------

        discrepancies: list[str] = []

        if not identity_valid:

            discrepancies.append(
                "Vulnerability identity could not "
                "be corroborated."
            )

        if not product_valid:

            discrepancies.append(
                "Vendor/product could not be "
                "corroborated."
            )

        if version_affected is None:

            discrepancies.append(
                "Installed version or affected "
                "version range is unavailable."
            )

        if patch_status is None:

            discrepancies.append(
                "Patched/fixed version information "
                "is unavailable."
            )

        if not source_corroborated:

            discrepancies.append(
                "No supporting evidence source "
                "was identified."
            )

        # -------------------------------------------------
        # Final validation determination
        # -------------------------------------------------

        if (
            identity_valid
            and product_valid
            and version_affected is True
            and source_corroborated
        ):

            status = "validated"
            affected = True

            reason = (
                "The candidate vulnerability is supported "
                "by the available evidence and the "
                "installed version falls within the "
                "identified affected range."
            )

        elif (
            identity_valid
            and product_valid
            and version_affected is False
        ):

            status = "not_affected"
            affected = False

            reason = (
                "The installed version does not fall "
                "within the identified affected range."
            )

        else:

            status = "needs_review"
            affected = None

            reason = (
                "The available evidence is insufficient "
                "to establish applicability conclusively."
            )

        # -------------------------------------------------
        # Extract vulnerability intelligence
        # -------------------------------------------------

        vulnerability_intelligence = (
            _extract_vulnerability_intelligence(
                candidate,
                related_internal,
                related_web,
            )
        )

        # -------------------------------------------------
        # Preserve evidence
        # -------------------------------------------------

        evidence_items: list[dict[str, Any]] = []

        # Each vulnerability now produces ONE merged
        # internal evidence item.
        for item in related_internal:

            evidence_items.append(
                {
                    "type": "internal",

                    "vulnerability_id": item.get(
                        "vulnerability_id"
                    ),

                    "cve": item.get("cve"),

                    "title": item.get("title"),

                    "description": item.get(
                        "description"
                    ),

                    "vendor": item.get("vendor"),

                    "product": item.get("product"),

                    "affected_versions": item.get(
                        "affected_versions",
                        [],
                    ),

                    "patched_versions": item.get(
                        "patched_versions",
                        [],
                    ),

                    # Risk intelligence
                    "cvss": item.get("cvss"),

                    "cvss_vector": item.get(
                        "cvss_vector"
                    ),

                    "epss": item.get("epss"),

                    "kev": item.get("kev"),

                    "exploit_available": item.get(
                        "exploit_available"
                    ),

                    "references": item.get(
                        "references",
                        [],
                    ),

                    # IMPORTANT:
                    # Both retrieval scores are preserved.
                    "semantic_score": item.get(
                        "semantic_score"
                    ),

                    "lexical_score": item.get(
                        "lexical_score"
                    ),

                    # IMPORTANT:
                    # Example:
                    # ["lexical", "semantic"]
                    "retrieval_sources": item.get(
                        "retrieval_sources",
                        [],
                    ),
                }
            )

        # Web evidence stays separate.
        for item in related_web:

            evidence_items.append(
                {
                    "type": "external",

                    "source_type": item.get(
                        "source_type"
                    ),

                    "source": item.get("source"),

                    "url": item.get("url"),

                    "cve": item.get("cve"),

                    "vulnerability_id": item.get(
                        "vulnerability_id"
                    ),

                    "cvss": item.get("cvss"),

                    "epss": item.get("epss"),

                    "kev": item.get("kev"),

                    "exploit_available": item.get(
                        "exploit_available"
                    ),

                    "published_at": item.get(
                        "published_at"
                    ),

                    "relevant_information": item.get(
                        "relevant_information"
                    ),
                }
            )

        # -------------------------------------------------
        # Final validated finding
        # -------------------------------------------------

        validated_findings.append(
            {
                "asset": {
                    "name": asset_name,

                    "version": installed_version,

                    "vendor": candidate.get(
                        "vendor"
                    ),

                    "product": candidate.get(
                        "product"
                    ),

                    # Optional organizational
                    # risk attributes.
                    "criticality": candidate_asset.get(
                        "criticality"
                    ),

                    "business_impact": candidate_asset.get(
                        "business_impact"
                    ),
                },

                "vulnerability": (
                    cve
                    or vulnerability_id
                ),

                "vulnerability_id": vulnerability_id,

                "status": status,

                "affected": affected,

                "reason": reason,

                "validation_checks": {
                    "identity": identity_valid,

                    "product": product_valid,

                    "version": version_affected,

                    "patch": patch_status,

                    "source_corroboration": (
                        source_corroborated
                    ),
                },

                "affected_versions": (
                    affected_versions or []
                ),

                "patched_versions": (
                    patched_versions or []
                ),

                # Risk Agent reads these directly.
                "cvss": vulnerability_intelligence[
                    "cvss"
                ],

                "cvss_vector": vulnerability_intelligence[
                    "cvss_vector"
                ],

                "epss": vulnerability_intelligence[
                    "epss"
                ],

                "kev": vulnerability_intelligence[
                    "kev"
                ],

                "exploit_available": (
                    vulnerability_intelligence[
                        "exploit_available"
                    ]
                ),

                "evidence": evidence_items,

                "sources": corroborating_sources,

                "discrepancies": discrepancies,
            }
        )

    return {
        "validated_findings": validated_findings,
        "errors": errors,
    }