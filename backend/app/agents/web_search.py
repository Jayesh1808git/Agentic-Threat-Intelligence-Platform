from typing import Any
import re

import requests

from app.agents.state import CyberRAGState


REQUEST_TIMEOUT = 10


# =========================================================
# Evidence Sufficiency Decision
# =========================================================

def evidence_is_sufficient(
    candidate: dict[str, Any],
    internal_evidence: list[dict[str, Any]],
) -> bool:
    """
    Decide whether internal evidence is sufficient.

    Web search is required when important information is
    missing or uncertain.

    This function does NOT decide vulnerability applicability.
    """

    cve = candidate.get("cve")
    vulnerability_id = candidate.get("vulnerability_id")

    related = [
        item
        for item in internal_evidence
        if (
            item.get("cve") == cve
            or item.get("vulnerability_id") == vulnerability_id
        )
    ]

    if not related:
        return False

    for evidence in related:

        has_identity = bool(
            evidence.get("cve")
            or evidence.get("vulnerability_id")
        )

        has_product = bool(evidence.get("product"))
        has_description = bool(evidence.get("description"))

        if not (
            has_identity
            and has_product
            and has_description
        ):
            return False

        # Missing fixed/patch information is an evidence gap.
        if not evidence.get("patched_versions"):
            return False

        # Missing exploit information is also an evidence gap.
        if evidence.get("exploit_available") is None:
            return False

    return True


# =========================================================
# External HTTP helpers
# =========================================================

def _fetch_json(url: str) -> dict[str, Any] | list[Any] | None:
    """
    Fetch public JSON vulnerability intelligence.

    Only public vulnerability intelligence is requested.
    No private organization information is sent.
    """

    try:
        response = requests.get(
            url,
            timeout=REQUEST_TIMEOUT,
            headers={
                "User-Agent": "CyberRAG/1.0",
                "Accept": "application/json",
            },
        )

        response.raise_for_status()

        data = response.json()

        if isinstance(data, (dict, list)):
            return data

        return None

    except (
        requests.RequestException,
        ValueError,
    ):
        return None


def _fetch_text(url: str) -> str | None:
    """
    Fetch public advisory/reference content.

    Some Adobe HelpX pages return only a dynamic page shell
    to normal HTTP clients. For Adobe security bulletins,
    the official Adobe security URL is also tried.

    Only public security information is requested.
    """

    urls_to_try = [url]

    # Adobe HelpX security pages may expose only the page shell.
    # Try the official Adobe security bulletin URL as fallback.
    if "helpx.adobe.com" in url and "/security/products/" in url:
        adobe_path = url.split("/security/products/", 1)[1]

        fallback_url = (
            "https://www.adobe.com/trust/security/products/"
            + adobe_path
        )

        if fallback_url not in urls_to_try:
            urls_to_try.append(fallback_url)

    headers_list = [
        {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/154.0.0.0 Safari/537.36"
            ),
            "Accept": (
                "text/html,application/xhtml+xml,"
                "application/xml;q=0.9,*/*;q=0.8"
            ),
            "Accept-Language": "en-US,en;q=0.9",
        },
        {
            "User-Agent": "CyberRAG/1.0",
            "Accept": (
                "text/html,text/plain,"
                "application/xhtml+xml"
            ),
        },
    ]

    for target_url in urls_to_try:

        for headers in headers_list:

            try:
                response = requests.get(
                    target_url,
                    timeout=REQUEST_TIMEOUT,
                    headers=headers,
                    allow_redirects=True,
                )

                if response.status_code != 200:
                    continue

                text = response.text

                if not text:
                    continue

                lower_text = text.lower()

                # Only accept pages containing actual advisory content.
                has_security_content = any(
                    marker in lower_text
                    for marker in [
                        "affected versions",
                        "updated version",
                        "solution",
                        "cve-",
                        "vulnerability details",
                    ]
                )

                if has_security_content:
                    return text[:50000]

            except requests.RequestException:
                continue

    return None

# =========================================================
# Text Evidence Extraction
# =========================================================

def _extract_versions(text: str) -> list[str]:
    """
    Extract versions only when they are explicitly connected
    to fixed, patched, resolved, remediated, upgrade, or update
    language.

    This prevents unrelated version numbers on an advisory page
    from incorrectly being treated as patched versions.
    """

    if not text:
        return []

    patterns = [
        (
            r"(?:fixed|fixes|patched|patch|resolved|remediated"
            r"|update(?:d)?\s+to|upgrade\s+to)"
            r"[^.\n]{0,120}?"
            r"\bv?(\d+\.\d+(?:\.\d+){0,3})\b"
        ),
        (
            r"\bv?(\d+\.\d+(?:\.\d+){0,3})\b"
            r"[^.\n]{0,120}?"
            r"(?:fixed|patched|resolved|remediated)"
        ),
    ]

    versions: list[str] = []

    for pattern in patterns:

        matches = re.findall(
            pattern,
            text,
            flags=re.IGNORECASE,
        )

        for match in matches:

            if isinstance(match, tuple):
                match = match[0]

            version = str(match).lstrip("v").strip()

            if version and version not in versions:
                versions.append(version)

    return versions


def _extract_remediation_text(text: str) -> list[str]:
    """
    Extract short evidence snippets related to patches,
    upgrades, fixed versions, and mitigations.
    """

    if not text:
        return []

    keywords = [
        "fixed",
        "fix",
        "patched",
        "patch",
        "upgrade",
        "update",
        "mitigation",
        "workaround",
        "remediation",
        "security update",
        "fixed version",
        "patched version",
        "upgrade to",
        "update to",
        "affected versions",
        "unaffected versions",
    ]

    lines = re.split(r"[\r\n]+", text)

    relevant: list[str] = []

    for line in lines:

        clean = re.sub(
            r"<[^>]+>",
            " ",
            line,
        )

        clean = re.sub(
            r"\s+",
            " ",
            clean,
        ).strip()

        if not clean:
            continue

        lower = clean.lower()

        if any(keyword in lower for keyword in keywords):

            if clean not in relevant:
                relevant.append(clean[:1000])

    return relevant[:20]


def _classify_reference(
    url: str,
    text: str,
) -> str:
    """
    Classify external reference evidence.

    Classification is based only on observable URL/content
    indicators. It does not decide vulnerability applicability.
    """

    lower_url = url.lower()
    lower_text = (text or "").lower()

    if any(
        value in lower_url
        for value in [
            "advisory",
            "security",
            "security-bulletin",
            "security-update",
            "psirt",
            "cve",
        ]
    ):

        if any(
            value in lower_text
            for value in [
                "fixed version",
                "fixed in",
                "patched version",
                "patched in",
                "upgrade to",
                "update to",
            ]
        ):
            return "patch_information"

        return "security_advisory"

    if any(
        value in lower_text
        for value in [
            "fixed version",
            "fixed in",
            "patched version",
            "patched in",
            "upgrade to",
            "update to",
        ]
    ):
        return "patch_information"

    if any(
        value in lower_text
        for value in [
            "mitigation",
            "workaround",
            "temporary workaround",
        ]
    ):
        return "mitigation"

    return "vendor_advisory"


# =========================================================
# NVD External Evidence
# =========================================================

def _search_nvd(
    cve: str,
) -> dict[str, Any] | None:

    url = (
        "https://services.nvd.nist.gov/rest/json/"
        f"cves/2.0?cveId={cve}"
    )

    data = _fetch_json(url)

    if not isinstance(data, dict):
        return None

    vulnerabilities = data.get(
        "vulnerabilities",
        [],
    )

    if not vulnerabilities:
        return None

    return {
        "source_type": "nvd",
        "source": "National Vulnerability Database",
        "url": url,
        "published_at": None,
        "relevant_information": vulnerabilities,
    }


# =========================================================
# CISA KEV External Evidence
# =========================================================

def _search_cisa_kev(
    cve: str,
) -> dict[str, Any] | None:

    url = (
        "https://www.cisa.gov/sites/default/files/"
        "feeds/known_exploited_vulnerabilities.json"
    )

    data = _fetch_json(url)

    if not isinstance(data, dict):
        return None

    vulnerabilities = data.get(
        "vulnerabilities",
        [],
    )

    matches = [
        item
        for item in vulnerabilities
        if item.get("cveID") == cve
    ]

    if not matches:
        return None

    return {
        "source_type": "cisa_kev",
        "source": "CISA Known Exploited Vulnerabilities",
        "url": url,
        "published_at": None,
        "relevant_information": matches,
    }


# =========================================================
# GitHub Advisory External Evidence
# =========================================================

def _search_github_advisory(
    cve: str,
) -> dict[str, Any] | None:

    url = (
        "https://api.github.com/"
        f"advisories?cve_id={cve}"
    )

    try:
        response = requests.get(
            url,
            timeout=REQUEST_TIMEOUT,
            headers={
                "Accept": "application/vnd.github+json",
                "User-Agent": "CyberRAG/1.0",
            },
        )

        response.raise_for_status()

        data = response.json()

        if not isinstance(data, list) or not data:
            return None

        return {
            "source_type": "github_advisory",
            "source": "GitHub Advisory Database",
            "url": url,
            "published_at": None,
            "relevant_information": data,
        }

    except (
        requests.RequestException,
        ValueError,
    ):
        return None


# =========================================================
# Vendor / Existing Reference Evidence
# =========================================================

def _search_references(
    candidate: dict[str, Any],
) -> list[dict[str, Any]]:

    results: list[dict[str, Any]] = []

    references = candidate.get(
        "references",
        [],
    )

    if not isinstance(references, list):
        return results

    for reference in references[:10]:

        if not isinstance(reference, str):
            continue

        text = _fetch_text(reference)

        if not text:
            continue

        source_type = _classify_reference(
            reference,
            text,
        )

        versions = _extract_versions(text)

        remediation = _extract_remediation_text(text)

        results.append(
            {
                "source_type": source_type,
                "source": reference,
                "url": reference,
                "published_at": None,
                "relevant_information": {
                    "text_excerpt": text[:20000],
                    "versions_found": versions,
                    "remediation_evidence": remediation,
                },
            }
        )

    return results


# =========================================================
# Web Search Agent
# =========================================================

def web_search_agent(
    state: CyberRAGState,
) -> dict[str, Any]:
    """
    Agent 4: Web Search Agent.

    Purpose:
        Find fresh or missing external vulnerability intelligence.

    This agent supplies evidence only.

    It does NOT:
        - declare the organization vulnerable
        - perform final validation
        - calculate risk
        - recommend remediation
    """

    candidates = state.get(
        "candidate_vulnerabilities",
        [],
    )

    internal_evidence = state.get(
        "internal_evidence",
        [],
    )

    existing_web_evidence = list(
        state.get(
            "web_evidence",
            [],
        )
    )

    errors = list(
        state.get(
            "errors",
            [],
        )
    )

    web_evidence = existing_web_evidence

    for candidate in candidates:

        # -------------------------------------------------
        # Conditional Web Search
        # -------------------------------------------------

        if evidence_is_sufficient(
            candidate,
            internal_evidence,
        ):
            continue

        cve = candidate.get("cve")

        if not cve:
            errors.append(
                "Web search skipped because candidate "
                "has no CVE identifier."
            )
            continue

        try:

            # ---------------------------------------------
            # NVD
            # ---------------------------------------------

            nvd_result = _search_nvd(cve)

            if nvd_result:

                nvd_result["cve"] = cve

                nvd_result["vulnerability_id"] = (
                    candidate.get("vulnerability_id")
                )

                web_evidence.append(
                    nvd_result
                )

            # ---------------------------------------------
            # CISA KEV
            # ---------------------------------------------

            cisa_result = _search_cisa_kev(cve)

            if cisa_result:

                cisa_result["cve"] = cve

                cisa_result["vulnerability_id"] = (
                    candidate.get("vulnerability_id")
                )

                web_evidence.append(
                    cisa_result
                )

            # ---------------------------------------------
            # GitHub Advisory
            # ---------------------------------------------

            github_result = _search_github_advisory(cve)

            if github_result:

                github_result["cve"] = cve

                github_result["vulnerability_id"] = (
                    candidate.get("vulnerability_id")
                )

                web_evidence.append(
                    github_result
                )

            # ---------------------------------------------
            # Vendor / Patch / Mitigation References
            # ---------------------------------------------

            reference_results = _search_references(
                candidate
            )

            for result in reference_results:

                result["cve"] = cve

                result["vulnerability_id"] = (
                    candidate.get("vulnerability_id")
                )

                web_evidence.append(
                    result
                )

        except Exception as exc:

            errors.append(
                f"Web search failed for {cve}: {exc}"
            )

    # -----------------------------------------------------
    # Remove duplicate evidence
    # -----------------------------------------------------

    unique_evidence: list[dict[str, Any]] = []

    seen: set[tuple] = set()

    for evidence in web_evidence:

        identity = (
            evidence.get("source_type"),
            evidence.get("cve"),
            evidence.get("url"),
        )

        if identity in seen:
            continue

        seen.add(identity)

        unique_evidence.append(
            evidence
        )

    return {
        "web_evidence": unique_evidence,
        "errors": errors,
    }