from datetime import datetime, timezone
from app.schemas.vulnerability import VulnerabilitySchema


class OSVNormalizer:

    def normalize(self, record: dict) -> VulnerabilitySchema:
        aliases = record.get("aliases", [])
        cve = next((x for x in aliases if x.startswith("CVE-")), None)
        vuln_id = record.get("id") or cve or "OSV-RECORD"

        summary = record.get("summary") or ""
        details = record.get("details") or ""

        affected_versions = []
        vendor = None
        product = None

        for item in record.get("affected", []):
            package = item.get("package", {})
            pkg_name = package.get("name")
            ecosystem = package.get("ecosystem")

            if pkg_name:
                product = pkg_name
            if ecosystem:
                vendor = ecosystem

            for r in item.get("ranges", []):
                events = r.get("events", [])
                affected_versions.append(f"{ecosystem or ''}:{pkg_name or ''}:{events}")

        references = [
            ref["url"] for ref in record.get("references", []) if ref.get("url")
        ]

        published = None
        if record.get("published"):
            try:
                published = datetime.fromisoformat(
                    record["published"].replace("Z", "+00:00")
                )
                if published.tzinfo is None:
                    published = published.replace(tzinfo=timezone.utc)
            except (ValueError, TypeError):
                pass

        modified = None
        if record.get("modified"):
            try:
                modified = datetime.fromisoformat(
                    record["modified"].replace("Z", "+00:00")
                )
                if modified.tzinfo is None:
                    modified = modified.replace(tzinfo=timezone.utc)
            except (ValueError, TypeError):
                pass

        title = summary or vuln_id
        description = details or summary or title

        return VulnerabilitySchema(
            source="OSV",
            vulnerability_id=vuln_id,
            cve=cve,
            title=title,
            description=description,
            vendor=vendor,
            product=product,
            affected_versions=affected_versions,
            patched_versions=[],
            cpe_matches=[],
            cvss=None,
            cvss_vector=None,
            epss=None,
            kev=False,
            exploit_available=False,
            references=references,
            published=published,
            updated=modified,
        )
