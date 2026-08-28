from datetime import datetime

from app.schemas.vulnerability import (
    VulnerabilitySchema,
)


class GitHubNormalizer:

    def normalize(
        self,
        record: dict,
    ) -> VulnerabilitySchema:

        identifiers = record.get(
            "identifiers",
            []
        )

        cve = None

        aliases = []

        for identifier in identifiers:

            value = identifier.get(
                "value"
            )

            if not value:
                continue

            if identifier.get(
                "type"
            ) == "CVE":

                cve = value

            else:

                aliases.append(value)

        ghsa = record.get(
            "ghsa_id"
        )

        if ghsa and ghsa != cve:
            aliases.append(ghsa)

        vulnerabilities = record.get(
            "vulnerabilities",
            []
        )

        affected_versions = []
        patched_versions = []

        vendor = None
        product = None
        ecosystem = None
        package_name = None

        if vulnerabilities:

            vuln = vulnerabilities[0]

            package = vuln.get(
                "package",
                {}
            )

            ecosystem = package.get(
                "ecosystem"
            )

            package_name = package.get(
                "name"
            )

            product = package_name

            affected_versions.append(
                vuln.get(
                    "vulnerable_version_range",
                    ""
                )
            )

            patched = vuln.get(
                "first_patched_version"
            )

            if patched:
                patched_versions.append(
                    patched
                )

        cvss = None
        cvss_vector = None

        cvss_data = record.get(
            "cvss"
        )

        if cvss_data:

            cvss = cvss_data.get(
                "score"
            )

            cvss_vector = cvss_data.get(
                "vector_string"
            )

        return VulnerabilitySchema(

            source="GITHUB",

            vulnerability_id=(
                ghsa
                or cve
                or str(record["id"])
            ),

            cve=cve,

            aliases=list(
                set(aliases)
            ),

            title=(
                record.get(
                    "summary"
                )
                or cve
                or ghsa
                or "GitHub Advisory"
            ),

            description=(
                record.get(
                    "description"
                )
                or ""
            ),

            vendor=vendor,

            product=product,

            ecosystem=ecosystem,

            package_name=package_name,

            affected_versions=(
                affected_versions
            ),

            patched_versions=(
                patched_versions
            ),

            cvss=cvss,

            cvss_vector=cvss_vector,

            epss=self._epss(
                record
            ),

            epss_percentile=(
                self._epss_percentile(
                    record
                )
            ),

            references=(
                record.get(
                    "references",
                    []
                )
            ),

            published=self._parse_date(
                record.get(
                    "published_at"
                )
            ),

            updated=self._parse_date(
                record.get(
                    "updated_at"
                )
            ),

            source_url=(
                record.get(
                    "html_url"
                )
            ),

            raw_id=ghsa,
        )

    @staticmethod
    def _parse_date(
        value: str | None
    ):

        if not value:
            return None

        return datetime.fromisoformat(
            value.replace(
                "Z",
                "+00:00"
            )
        )

    @staticmethod
    def _epss(record):

        epss = record.get(
            "epss"
        )

        if not epss:
            return None

        value = epss.get(
            "percentage"
        )

        if value is None:
            return None

        return float(value)

    @staticmethod
    def _epss_percentile(record):

        epss = record.get(
            "epss"
        )

        if not epss:
            return None

        value = epss.get(
            "percentile"
        )

        if value is None:
            return None

        try:
            return float(value)
        except ValueError:
            return None