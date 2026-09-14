import hashlib
import json


def vulnerability_content_hash(vulnerability) -> str:
    """
    Hash only fields that affect semantic search.

    Dynamic risk metadata such as EPSS and KEV is
    intentionally excluded.
    """

    payload = {
        "title": vulnerability.title or "",
        "description": vulnerability.description or "",
        "vendor": vulnerability.vendor or "",
        "product": vulnerability.product or "",
        "affected_versions": (
            vulnerability.affected_versions or []
        ),
        "patched_versions": (
            vulnerability.patched_versions or []
        ),
        "cpe_matches": (
            vulnerability.cpe_matches or []
        ),
    }

    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode("utf-8")

    return hashlib.sha256(encoded).hexdigest()