from datetime import datetime


class OSVNormalizer:

    def normalize(self, record):

        aliases = record.get(
            "aliases",
            [],
        )

        cve = next(
            (
                x
                for x in aliases
                if x.startswith("CVE-")
            ),
            None,
        )

        vuln_id = record.get(
            "id"
        )

        summary = record.get(
            "summary"
        ) or ""

        details = record.get(
            "details"
        ) or ""

        affected = []

        for item in record.get(
            "affected",
            [],
        ):

            package = item.get(
                "package",
                {}
            )

            name = package.get(
                "name"
            )

            ecosystem = package.get(
                "ecosystem"
            )

            for r in item.get(
                "ranges",
                [],
            ):

                events = r.get(
                    "events",
                    []
                )

                affected.append(
                    (
                        f"{ecosystem}:"
                        f"{name}:"
                        f"{events}"
                    )
                )

        references = []

        for ref in record.get(
            "references",
            [],
        ):

            url = ref.get(
                "url"
            )

            if url:
                references.append(
                    url
                )

        published = None

        if record.get("published"):

            try:
                published = datetime.fromisoformat(
                    record["published"]
                    .replace(
                        "Z",
                        "+00:00"
                    )
                )
            except ValueError:
                pass

        modified = None

        if record.get("modified"):

            try:
                modified = datetime.fromisoformat(
                    record["modified"]
                    .replace(
                        "Z",
                        "+00:00"
                    )
                )
            except ValueError:
                pass

        # Lightweight object compatible with
        # VulnerabilityWriter.
        class V:
            pass

        v = V()

        v.source = "OSV"
        v.vulnerability_id = vuln_id
        v.cve = cve

        v.title = (
            summary
            or vuln_id
        )

        v.description = (
            details
            or summary
        )

        v.vendor = None
        v.product = None

        v.affected_versions = (
            affected
        )

        v.patched_versions = []

        v.cpe_matches = []

        v.cvss = None
        v.cvss_vector = None

        v.epss = None

        v.kev = False
        v.exploit_available = False

        v.references = references

        v.published = published
        v.updated = modified

        return v