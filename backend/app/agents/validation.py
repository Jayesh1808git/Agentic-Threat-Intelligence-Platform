import json
import logging
from typing import Any
from packaging.specifiers import SpecifierSet
from packaging.version import InvalidVersion, Version
from pydantic import BaseModel, Field

from app.core.config import settings
from app.agents.state import CyberRAGState
from app.schemas.agent_outputs import ValidatedFinding, ValidationResult
from app.services.llm import llm_service

logger = logging.getLogger("validation_agent")


SYSTEM_PROMPT = """
You are the Validation Agent in an AI-agent-driven CyberRAG vulnerability assessment workflow.
Your task is to determine: "Is this candidate vulnerability actually applicable to this organization's asset?"

You must evaluate and reason over:
- Project Asset (name, vendor, product, version)
- Candidate Vulnerability details
- Affected version ranges
- Patched/fixed versions
- Internal Evidence (PostgreSQL + Qdrant)
- Web Evidence (external advisories)

Evaluate the following explicit factors:
1. identity_match (boolean): Do the vulnerability/CVE IDs in candidate and evidence match?
2. product_match (boolean): Does the vendor/product in the advisory match the project asset?
   CRITICAL: Web evidence must NEVER automatically override an identity or product mismatch! If the product names are completely different technologies (e.g. Django vs Spring), product_match MUST be false.
3. version_match (boolean or null): Does the project's installed version fall inside the affected version range and below patched versions?
4. evidence_quality: Assessment of evidence reliability and corroboration across sources.
5. evidence_conflicts: List any conflicting claims between internal DB and external web advisories.
6. final_applicability (boolean or null): Is the vulnerability confirmed applicable (true), confirmed not affected (false), or uncertain/insufficient (null)?
7. confidence (float 0.0 to 1.0): Confidence score in your applicability decision.
8. reason: Detailed explanation justifying the validation determination.

Return structured output matching the ValidationResult schema.
"""


def validation_agent(state: CyberRAGState) -> dict[str, Any]:
    """
    Agent 5: Validation Agent

    Determines whether candidate vulnerabilities are genuinely applicable to project assets
    by combining deterministic version checks with AI agent batched reasoning.
    """
    candidates = state.get("candidate_vulnerabilities", [])
    assets = state.get("assets", [])
    internal_evidence = state.get("internal_evidence", [])
    web_evidence = state.get("web_evidence", [])
    errors = list(state.get("errors", []))

    if not candidates:
        return {
            "validated_findings": [],
            "errors": errors,
        }

    max_candidates = getattr(settings, "MAX_VALIDATION_CANDIDATES", 10)
    batch_size = getattr(settings, "MAX_VALIDATION_BATCH_SIZE", 10)
    candidates_to_process = candidates[:max_candidates]

    logger.info(
        "validation_mode=batched candidate_count=%d validation_candidate_count=%d",
        len(candidates),
        len(candidates_to_process),
    )

    # Pre-process candidate items and deterministic checks
    prepared_items = []
    for candidate in candidates_to_process:
        cve = candidate.get("cve")
        vulnerability_id = candidate.get("vulnerability_id") or candidate.get("cve") or "Unknown"

        # Evidence lookup
        related_internal = [
            item for item in internal_evidence
            if (item.get("cve") and item.get("cve") == cve) or
               (item.get("vulnerability_id") and item.get("vulnerability_id") == vulnerability_id)
        ]
        merged_internal = _merge_internal_evidence(related_internal)

        related_web = [
            item for item in web_evidence
            if (item.get("cve") and item.get("cve") == cve) or
               (item.get("vulnerability_id") and item.get("vulnerability_id") == vulnerability_id)
        ]
        merged_web = _merge_web_evidence(related_web)

        candidate_asset = candidate.get("asset", {})
        if not isinstance(candidate_asset, dict):
            candidate_asset = {}

        asset_name = candidate_asset.get("name") or candidate.get("product") or "Unknown"
        installed_version = candidate.get("asset_version") or candidate_asset.get("version")

        if not installed_version and asset_name:
            for a in assets:
                if isinstance(a, dict) and str(a.get("name", "")).lower() == str(asset_name).lower():
                    installed_version = a.get("version")
                    break

        evidence_base = merged_internal[0] if merged_internal else candidate
        affected_versions = evidence_base.get("affected_versions", [])
        patched_versions = evidence_base.get("patched_versions", [])

        # Deterministic version and product checks
        version_affected = _version_in_range(installed_version, affected_versions)
        patch_status = _version_is_patched(installed_version, patched_versions)
        identity_valid = _validate_identity(candidate, merged_internal)
        product_valid = _validate_product(candidate, merged_internal)

        prepared_items.append({
            "candidate": candidate,
            "vulnerability_id": vulnerability_id,
            "cve": cve,
            "asset": candidate_asset,
            "asset_name": asset_name,
            "installed_version": installed_version,
            "affected_versions": affected_versions,
            "patched_versions": patched_versions,
            "version_affected": version_affected,
            "patch_status": patch_status,
            "identity_valid": identity_valid,
            "product_valid": product_valid,
            "merged_internal": merged_internal,
            "merged_web": merged_web,
        })

    # AI Batched Reasoning
    llm_results = {}
    if llm_service.is_configured() and prepared_items:
        try:
            compact_candidates = [
                {
                    "vulnerability_id": item["vulnerability_id"],
                    "asset_name": item["asset_name"],
                    "installed_version": item["installed_version"],
                    "product": item["candidate"].get("product"),
                    "affected_versions": item["affected_versions"],
                    "patched_versions": item["patched_versions"],
                    "description": str(item["candidate"].get("description", ""))[:250],
                }
                for item in prepared_items[:batch_size]
            ]
            prompt = f"Validate applicability for candidates:\n{json.dumps(compact_candidates, indent=2)}"
            
            from app.schemas.agent_outputs import BatchValidationResult
            res: BatchValidationResult = llm_service.invoke_structured(
                prompt=prompt,
                response_model=BatchValidationResult,
                system_prompt=SYSTEM_PROMPT,
                agent_name="validation",
            )
            for res_item in res.results:
                if res_item.vulnerability_id:
                    llm_results[res_item.vulnerability_id] = res_item
        except Exception as exc:
            logger.warning("LLM batched validation failed: %s. Using deterministic fallback.", exc)
            errors.append(f"LLM validation warning: {exc}")

    validated_findings: list[dict[str, Any]] = []

    for item in prepared_items:
        v_id = item["vulnerability_id"]
        candidate = item["candidate"]
        asset_name = item["asset_name"]
        installed_version = item["installed_version"]
        affected_versions = item["affected_versions"]
        patched_versions = item["patched_versions"]
        identity_valid = item["identity_valid"]
        product_valid = item["product_valid"]
        version_affected = item["version_affected"]
        patch_status = item["patch_status"]
        merged_internal = item["merged_internal"]
        merged_web = item["merged_web"]

        llm_match = llm_results.get(v_id)

        if llm_match:
            applicable = llm_match.applicable
            confidence = llm_match.confidence
            reason = llm_match.reason or "Validated via AI batched reasoning."
            if applicable and identity_valid and product_valid:
                status = "validated"
                affected = True
            elif not applicable or not product_valid or not identity_valid:
                status = "not_affected"
                affected = False
            else:
                status = "needs_review"
                affected = None
        else:
            # Deterministic Fallback if LLM unavailable or omitted candidate
            if identity_valid and product_valid and version_affected is True and not patch_status:
                status = "validated"
                affected = True
                reason = f"The project uses {asset_name} {installed_version} which falls within the affected version range ({affected_versions}) and is not patched."
                confidence = 0.95
            elif identity_valid and product_valid and (version_affected is False or patch_status is True):
                status = "not_affected"
                affected = False
                reason = f"The installed version ({installed_version}) does not fall within affected ranges or is already patched (fixed in {patched_versions})."
                confidence = 0.90
            elif not product_valid or not identity_valid:
                status = "not_affected"
                affected = False
                reason = f"Product/vendor mismatch: Asset '{asset_name}' does not match vulnerability target '{candidate.get('product')}'."
                confidence = 0.95
            else:
                status = "needs_review"
                affected = None
                reason = "Available evidence is insufficient or version range requires manual review."
                confidence = 0.50

        # Construct final ValidatedFinding dictionary, preserving ALL trusted DB facts
        finding_dict = {
            "asset": item["asset"] or {"name": asset_name, "version": installed_version},
            "vulnerability": v_id,
            "vulnerability_id": v_id,
            "cve": item["cve"],
            "status": status,
            "affected": affected,
            "confidence": confidence,
            "identity_match": identity_valid,
            "product_match": product_valid,
            "version_match": version_affected,
            "patch_status": patch_status,
            "source_corroborated": bool(merged_internal or merged_web),
            "reason": reason,
            "affected_versions": affected_versions,
            "patched_versions": patched_versions,
            "cvss": candidate.get("cvss") if candidate.get("cvss") is not None else (merged_internal[0].get("cvss") if merged_internal else None),
            "cvss_vector": candidate.get("cvss_vector") if candidate.get("cvss_vector") is not None else (merged_internal[0].get("cvss_vector") if merged_internal else None),
            "epss": candidate.get("epss") if candidate.get("epss") is not None else (merged_internal[0].get("epss") if merged_internal else None),
            "kev": candidate.get("kev") if candidate.get("kev") is not None else (merged_internal[0].get("kev") if merged_internal else False),
            "exploit_available": candidate.get("exploit_available") if candidate.get("exploit_available") is not None else (merged_internal[0].get("exploit_available") if merged_internal else False),
            "evidence": _build_evidence_items(merged_internal, merged_web),
        }
        validated_findings.append(finding_dict)

    return {
        "validated_findings": validated_findings,
        "errors": errors,
    }


def _build_validation_prompt(
    candidate: dict[str, Any],
    asset_name: str,
    installed_version: str | None,
    affected_versions: list[str],
    patched_versions: list[str],
    identity_valid: bool,
    product_valid: bool,
    version_affected: bool | None,
    patch_status: bool | None,
    internal_evidence: list[dict[str, Any]],
    web_evidence: list[dict[str, Any]],
) -> str:
    return (
        f"Validate vulnerability applicability:\n\n"
        f"Target Asset: {asset_name} (Installed Version: {installed_version or 'Not specified'})\n"
        f"Vulnerability: {candidate.get('cve') or candidate.get('vulnerability_id')}\n"
        f"Candidate Vendor/Product: {candidate.get('vendor')} / {candidate.get('product')}\n"
        f"Vulnerability Description: {candidate.get('description', '')[:400]}\n"
        f"Affected Versions in DB: {affected_versions}\n"
        f"Patched Versions in DB: {patched_versions}\n"
        f"Deterministic Identity Match: {identity_valid}\n"
        f"Deterministic Product Match: {product_valid}\n"
        f"Deterministic Version Match (in range): {version_affected}\n"
        f"Deterministic Patch Status (is patched): {patch_status}\n\n"
        f"Internal Evidence Count: {len(internal_evidence)}\n"
        f"Web Evidence Count: {len(web_evidence)}\n"
    )


def _build_evidence_items(internal: list[dict[str, Any]], web: list[dict[str, Any]]) -> list[dict[str, Any]]:
    items = []
    for item in internal:
        items.append({
            "type": "internal",
            "vulnerability_id": item.get("vulnerability_id"),
            "cve": item.get("cve"),
            "title": item.get("title"),
            "vendor": item.get("vendor"),
            "product": item.get("product"),
            "affected_versions": item.get("affected_versions", []),
            "patched_versions": item.get("patched_versions", []),
            "cvss": item.get("cvss"),
            "epss": item.get("epss"),
            "kev": item.get("kev"),
            "exploit_available": item.get("exploit_available"),
            "semantic_score": item.get("semantic_score"),
            "lexical_score": item.get("lexical_score"),
            "retrieval_sources": item.get("retrieval_sources", []),
        })
    for item in web:
        items.append({
            "type": "external",
            "source_type": item.get("source_type"),
            "source": item.get("source"),
            "url": item.get("url"),
            "cve": item.get("cve"),
            "vulnerability_id": item.get("vulnerability_id"),
            "reason_relevant": item.get("reason_relevant"),
        })
    return items


# Version comparison helpers
def _parse_version(value: Any) -> Version | None:
    if value is None:
        return None
    val_str = str(value).strip()
    if not val_str:
        return None
    try:
        return Version(val_str)
    except InvalidVersion:
        return None


def _version_in_range(installed_version: Any, affected_ranges: Any) -> bool | None:
    installed = _parse_version(installed_version)
    if installed is None or not affected_ranges:
        return None

    if isinstance(affected_ranges, str):
        affected_ranges = [affected_ranges]

    if not isinstance(affected_ranges, list):
        return None

    for raw_range in affected_ranges:
        if not raw_range:
            continue
        range_text = str(raw_range).strip()
        try:
            if any(op in range_text for op in ["<", ">", "=", "!", "~"]):
                try:
                    spec = SpecifierSet(range_text)
                    if installed in spec:
                        return True
                    continue
                except Exception:
                    pass
        except Exception:
            pass

        if " - " in range_text:
            parts = range_text.split(" - ", 1)
            if len(parts) == 2:
                lower = _parse_version(parts[0])
                upper = _parse_version(parts[1])
                if lower and upper:
                    if lower <= installed <= upper:
                        return True
                    continue

        exact = _parse_version(range_text)
        if exact is not None and installed == exact:
            return True

    return False


def _version_is_patched(installed_version: Any, patched_versions: Any) -> bool | None:
    installed = _parse_version(installed_version)
    if installed is None or not patched_versions:
        return None

    if isinstance(patched_versions, str):
        patched_versions = [patched_versions]

    if not isinstance(patched_versions, list):
        return None

    parsed_patches = [_parse_version(v) for v in patched_versions if _parse_version(v) is not None]
    if not parsed_patches:
        return None

    earliest_patch = min(parsed_patches)
    return installed >= earliest_patch


def _validate_identity(candidate: dict[str, Any], evidence: list[dict[str, Any]]) -> bool:
    candidate_cve = candidate.get("cve")
    candidate_id = candidate.get("vulnerability_id")

    if not candidate_cve and not candidate_id:
        return False

    for item in evidence:
        if candidate_cve and item.get("cve") == candidate_cve:
            return True
        if candidate_id and item.get("vulnerability_id") == candidate_id:
            return True

    return bool(candidate_cve or candidate_id)


def _validate_product(candidate: dict[str, Any], evidence: list[dict[str, Any]]) -> bool:
    candidate_vendor = candidate.get("vendor")
    candidate_product = candidate.get("product")
    asset = candidate.get("asset", {})
    asset_name = asset.get("name") if isinstance(asset, dict) else candidate_product

    # Asset name vs Candidate product check
    if asset_name and candidate_product:
        c_prod = str(candidate_product).lower()
        a_name = str(asset_name).lower()
        if c_prod not in a_name and a_name not in c_prod:
            return False

    if not evidence:
        return True

    for item in evidence:
        v_match = True
        p_match = True

        if candidate_vendor and item.get("vendor"):
            ev_vendor = str(item.get("vendor")).lower()
            cand_vendor = str(candidate_vendor).lower()
            v_match = cand_vendor in ev_vendor or ev_vendor in cand_vendor

        if candidate_product and item.get("product"):
            ev_prod = str(item.get("product")).lower()
            cand_prod = str(candidate_product).lower()
            p_match = cand_prod in ev_prod or ev_prod in cand_prod or (asset_name and str(asset_name).lower() in ev_prod)

        if v_match and p_match:
            return True

    return False


def _merge_internal_evidence(related: list[dict[str, Any]]) -> list[dict[str, Any]]:
    merged: dict[str, dict[str, Any]] = {}
    for item in related:
        key = item.get("cve") or item.get("vulnerability_id") or str(id(item))
        if key not in merged:
            merged[key] = dict(item)
        else:
            for field in ["affected_versions", "patched_versions", "references", "retrieval_sources"]:
                existing = merged[key].get(field, [])
                new_items = item.get(field, [])
                merged[key][field] = list(set(existing + new_items))
    return list(merged.values())


def _merge_web_evidence(related: list[dict[str, Any]]) -> list[dict[str, Any]]:
    merged: dict[str, dict[str, Any]] = {}
    for item in related:
        key = f"{item.get('source_type')}|{item.get('url')}|{item.get('cve')}"
        if key not in merged:
            merged[key] = dict(item)
    return list(merged.values())