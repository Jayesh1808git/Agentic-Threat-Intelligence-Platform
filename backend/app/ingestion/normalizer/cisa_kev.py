from datetime import datetime, timezone
from app.schemas.vulnerability import VulnerabilitySchema


class CISAKEVNormalizer:

    def normalize(self, record: dict) -> VulnerabilitySchema:
        cve = record.get("cveID")
        vulnerability_id = cve or record.get("vulnerabilityName") or "CISA-KEV-RECORD"

        vendor = record.get("vendorProject")
        product = record.get("product")
        title = record.get("vulnerabilityName") or cve or "CISA Known Exploited Vulnerability"
        description = record.get("shortDescription") or title

        if record.get("requiredAction"):
            description += f"\n\nRequired Action: {record['requiredAction']}"

        date_added = None
        if record.get("dateAdded"):
            try:
                date_added = datetime.fromisoformat(
                    record["dateAdded"].replace("Z", "+00:00")
                )
                if date_added.tzinfo is None:
                    date_added = date_added.replace(tzinfo=timezone.utc)
            except (ValueError, TypeError):
                pass

        return VulnerabilitySchema(
            source="CISA",
            vulnerability_id=vulnerability_id,
            cve=cve,
            title=title,
            description=description,
            vendor=vendor,
            product=product,
            affected_versions=[],
            patched_versions=[],
            cpe_matches=[],
            cvss=None,
            cvss_vector=None,
            epss=None,
            kev=True,
            exploit_available=True,
            references=[],
            published=date_added,
            updated=date_added,
        )