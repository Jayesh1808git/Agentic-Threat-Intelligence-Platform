from __future__ import annotations

from datetime import datetime
from typing import Any

from app.schemas.vulnerability import VulnerabilitySchema


class NVDNormalizer:
    """
    Converts a raw NVD CVE object into our
    unified VulnerabilitySchema.
    """

    @staticmethod
    def _get_description(cve: dict[str, Any]) -> str:
        descriptions = cve.get("descriptions", [])

        for item in descriptions:
            if item.get("lang") == "en":
                return item.get("value", "")

        return ""

    @staticmethod
    def _parse_datetime(value: str | None) -> datetime | None:
        if not value:
            return None

        try:
            return datetime.fromisoformat(
                value.replace("Z", "+00:00")
            )
        except ValueError:
            return None

    @staticmethod
    def _extract_cvss(
        cve: dict[str, Any],
    ) -> tuple[float | None, str | None]:

        metrics = cve.get("metrics", {})

        # Prefer CVSS v4
        if metrics.get("cvssMetricV40"):
            metric = metrics["cvssMetricV40"][0]
            cvss_data = metric.get("cvssData", {})

            return (
                cvss_data.get("baseScore"),
                cvss_data.get("vectorString"),
            )

        # Then CVSS v3.1
        if metrics.get("cvssMetricV31"):
            metric = metrics["cvssMetricV31"][0]
            cvss_data = metric.get("cvssData", {})

            return (
                cvss_data.get("baseScore"),
                cvss_data.get("vectorString"),
            )

        # Then CVSS v3.0
        if metrics.get("cvssMetricV30"):
            metric = metrics["cvssMetricV30"][0]
            cvss_data = metric.get("cvssData", {})

            return (
                cvss_data.get("baseScore"),
                cvss_data.get("vectorString"),
            )

        # Finally CVSS v2
        if metrics.get("cvssMetricV2"):
            metric = metrics["cvssMetricV2"][0]
            cvss_data = metric.get("cvssData", {})

            return (
                cvss_data.get("baseScore"),
                cvss_data.get("vectorString"),
            )

        return None, None

    @staticmethod
    def _extract_cpes(
        cve: dict[str, Any],
    ) -> list[dict[str, Any]]:

        results = []

        configurations = cve.get("configurations", [])

        for configuration in configurations:

            nodes = configuration.get("nodes", [])

            for node in nodes:

                for match in node.get("cpeMatch", []):

                    cpe_name = match.get("criteria")

                    if not cpe_name:
                        continue

                    results.append(
                        {
                            "cpe": cpe_name,
                            "vulnerable": match.get(
                                "vulnerable",
                                False,
                            ),
                            "version_start_including": match.get(
                                "versionStartIncluding"
                            ),
                            "version_start_excluding": match.get(
                                "versionStartExcluding"
                            ),
                            "version_end_including": match.get(
                                "versionEndIncluding"
                            ),
                            "version_end_excluding": match.get(
                                "versionEndExcluding"
                            ),
                        }
                    )

        return results

    @staticmethod
    def _extract_references(
        cve: dict[str, Any],
    ) -> list[str]:

        references = cve.get("references", [])

        return [
            reference.get("url")
            for reference in references
            if reference.get("url")
        ]

    @staticmethod
    def _extract_product_from_cpe(
        cpe: str,
    ) -> tuple[str | None, str | None, str | None]:

        parts = cpe.split(":")

        # Expected:
        # cpe:2.3:a:vendor:product:version:...

        if len(parts) < 6:
            return None, None, None

        vendor = parts[3]
        product = parts[4]
        version = parts[5]

        return vendor, product, version

    def normalize(
        self,
        cve: dict[str, Any],
    ) -> VulnerabilitySchema:

        cve_id = cve.get("id", "")

        description = self._get_description(cve)

        cvss, cvss_vector = self._extract_cvss(cve)

        cpe_entries = self._extract_cpes(cve)

        references = self._extract_references(cve)

        vendor = None
        product = None

        affected_versions = []
        patched_versions = []

        for entry in cpe_entries:

            if not entry["vulnerable"]:
                continue

            if vendor is None and product is None:

                vendor, product, version = (
                    self._extract_product_from_cpe(
                        entry["cpe"]
                    )
                )

            start_inc = entry["version_start_including"]
            start_exc = entry["version_start_excluding"]
            end_inc = entry["version_end_including"]
            end_exc = entry["version_end_excluding"]

            if start_inc:
                affected_versions.append(
                    f">={start_inc}"
                )

            if start_exc:
                affected_versions.append(
                    f">{start_exc}"
                )

            if end_inc:
                affected_versions.append(
                    f"<={end_inc}"
                )

            if end_exc:
                affected_versions.append(
                    f"<{end_exc}"
                )

        return VulnerabilitySchema(
            source="NVD",
            vulnerability_id=cve_id,
            cve=cve_id,
            title=cve_id,
            description=description,
            vendor=vendor,
            product=product,
            affected_versions=affected_versions,
            patched_versions=patched_versions,
            cpe_matches=cpe_entries,
            cvss=cvss,
            cvss_vector=cvss_vector,
            epss=None,
            kev=False,
            exploit_available=False,
            references=references,
            published=self._parse_datetime(
                cve.get("published")
            ),
            updated=self._parse_datetime(
                cve.get("lastModified")
            ),
        )