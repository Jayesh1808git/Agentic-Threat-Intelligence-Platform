from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from app.schemas.vulnerability import VulnerabilitySchema


class NVDNormalizer:
    """
    Converts an NVD 2.0 CVE record into the unified
    VulnerabilitySchema.

    Supports both:

        {"id": "CVE-..."}

    and the complete NVD API wrapper:

        {"cve": {"id": "CVE-..."}}
    """

    # ============================================================
    # RAW NVD EXTRACTION
    # ============================================================

    @staticmethod
    def _unwrap_cve(
        record: dict[str, Any],
    ) -> dict[str, Any]:

        # NVD API normally gives:
        #
        # {
        #     "cve": {
        #         "id": "...",
        #         ...
        #     }
        # }

        if isinstance(
            record.get("cve"),
            dict,
        ):
            return record["cve"]

        # Also support passing the CVE object directly.
        return record

    # ============================================================
    # DESCRIPTION
    # ============================================================

    @staticmethod
    def _get_description(
        cve: dict[str, Any],
    ) -> str:

        descriptions = cve.get(
            "descriptions",
            [],
        )

        # Prefer English.
        for item in descriptions:

            if (
                item.get("lang") == "en"
                and item.get("value")
            ):
                return item["value"]

        # Fallback to any available description.
        for item in descriptions:

            value = item.get("value")

            if value:
                return value

        return ""

    # ============================================================
    # DATETIME
    # ============================================================

    @staticmethod
    def _parse_datetime(
        value: str | None,
    ) -> datetime | None:

        if not value:
            return None

        try:

            parsed = datetime.fromisoformat(
                value.replace(
                    "Z",
                    "+00:00",
                )
            )

            # Ensure timezone-aware datetime.
            if parsed.tzinfo is None:

                parsed = parsed.replace(
                    tzinfo=timezone.utc
                )

            return parsed

        except (
            ValueError,
            TypeError,
        ):

            return None

    # ============================================================
    # CVSS
    # ============================================================

    @staticmethod
    def _extract_cvss(
        cve: dict[str, Any],
    ) -> tuple[
        float | None,
        str | None,
    ]:

        metrics = cve.get(
            "metrics",
            {},
        )

        # --------------------------------------------------------
        # CVSS 4.0
        # --------------------------------------------------------

        if metrics.get(
            "cvssMetricV40"
        ):

            metric = metrics[
                "cvssMetricV40"
            ][0]

            cvss_data = metric.get(
                "cvssData",
                {},
            )

            return (
                cvss_data.get(
                    "baseScore"
                ),
                cvss_data.get(
                    "vectorString"
                ),
            )

        # --------------------------------------------------------
        # CVSS 3.1
        # --------------------------------------------------------

        if metrics.get(
            "cvssMetricV31"
        ):

            metric = metrics[
                "cvssMetricV31"
            ][0]

            cvss_data = metric.get(
                "cvssData",
                {},
            )

            return (
                cvss_data.get(
                    "baseScore"
                ),
                cvss_data.get(
                    "vectorString"
                ),
            )

        # --------------------------------------------------------
        # CVSS 3.0
        # --------------------------------------------------------

        if metrics.get(
            "cvssMetricV30"
        ):

            metric = metrics[
                "cvssMetricV30"
            ][0]

            cvss_data = metric.get(
                "cvssData",
                {},
            )

            return (
                cvss_data.get(
                    "baseScore"
                ),
                cvss_data.get(
                    "vectorString"
                ),
            )

        # --------------------------------------------------------
        # CVSS 2.0
        # --------------------------------------------------------

        if metrics.get(
            "cvssMetricV2"
        ):

            metric = metrics[
                "cvssMetricV2"
            ][0]

            cvss_data = metric.get(
                "cvssData",
                {},
            )

            return (
                cvss_data.get(
                    "baseScore"
                ),
                cvss_data.get(
                    "vectorString"
                ),
            )

        return None, None

    # ============================================================
    # CPE EXTRACTION
    # ============================================================

    @staticmethod
    def _extract_cpes(
        cve: dict[str, Any],
    ) -> list[dict[str, Any]]:

        results = []

        configurations = cve.get(
            "configurations",
            [],
        )

        for configuration in configurations:

            nodes = configuration.get(
                "nodes",
                [],
            )

            for node in nodes:

                # NVD configurations can contain
                # nested child nodes.
                #
                # Process the current node's
                # cpeMatch entries.

                matches = node.get(
                    "cpeMatch",
                    [],
                )

                for match in matches:

                    cpe_name = match.get(
                        "criteria"
                    )

                    if not cpe_name:
                        continue

                    results.append(
                        {
                            "cpe": cpe_name,

                            "vulnerable":
                                match.get(
                                    "vulnerable",
                                    False,
                                ),

                            "version_start_including":
                                match.get(
                                    "versionStartIncluding"
                                ),

                            "version_start_excluding":
                                match.get(
                                    "versionStartExcluding"
                                ),

                            "version_end_including":
                                match.get(
                                    "versionEndIncluding"
                                ),

                            "version_end_excluding":
                                match.get(
                                    "versionEndExcluding"
                                ),
                        }
                    )

        return results

    # ============================================================
    # REFERENCES
    # ============================================================

    @staticmethod
    def _extract_references(
        cve: dict[str, Any],
    ) -> list[str]:

        references = cve.get(
            "references",
            [],
        )

        result = []

        for reference in references:

            url = reference.get(
                "url"
            )

            if url:
                result.append(url)

        # Remove duplicates while preserving order.
        return list(
            dict.fromkeys(result)
        )

    # ============================================================
    # CPE PARSING
    # ============================================================

    @staticmethod
    def _extract_product_from_cpe(
        cpe: str,
    ) -> tuple[
        str | None,
        str | None,
        str | None,
    ]:

        parts = cpe.split(":")

        # Expected CPE 2.3:
        #
        # cpe:2.3:a:vendor:product:version:...

        if len(parts) < 6:
            return (
                None,
                None,
                None,
            )

        if parts[0] != "cpe":
            return (
                None,
                None,
                None,
            )

        if parts[1] != "2.3":
            return (
                None,
                None,
                None,
            )

        vendor = parts[3]
        product = parts[4]
        version = parts[5]

        return (
            vendor,
            product,
            version,
        )

    # ============================================================
    # AFFECTED VERSION EXTRACTION
    # ============================================================

    @staticmethod
    def _extract_affected_versions(
        cpe_entries: list[
            dict[str, Any]
        ],
    ) -> list[str]:

        affected_versions = []

        for entry in cpe_entries:

            if not entry.get(
                "vulnerable",
                False,
            ):
                continue

            start_inc = entry.get(
                "version_start_including"
            )

            start_exc = entry.get(
                "version_start_excluding"
            )

            end_inc = entry.get(
                "version_end_including"
            )

            end_exc = entry.get(
                "version_end_excluding"
            )

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

        return list(
            dict.fromkeys(
                affected_versions
            )
        )

    # ============================================================
    # NORMALIZE
    # ============================================================

    def normalize(
        self,
        record: dict[str, Any],
    ) -> VulnerabilitySchema:

        # --------------------------------------------------------
        # IMPORTANT:
        # Handle both NVD wrapper and direct CVE object.
        # --------------------------------------------------------

        cve = self._unwrap_cve(
            record
        )

        # --------------------------------------------------------
        # ID
        # --------------------------------------------------------

        cve_id = (
            cve.get("id")
            or ""
        )

        # --------------------------------------------------------
        # Description
        # --------------------------------------------------------

        description = (
            self._get_description(
                cve
            )
        )

        # --------------------------------------------------------
        # CVSS
        # --------------------------------------------------------

        cvss, cvss_vector = (
            self._extract_cvss(
                cve
            )
        )

        # --------------------------------------------------------
        # CPE
        # --------------------------------------------------------

        cpe_entries = (
            self._extract_cpes(
                cve
            )
        )

        # --------------------------------------------------------
        # References
        # --------------------------------------------------------

        references = (
            self._extract_references(
                cve
            )
        )

        # --------------------------------------------------------
        # Vendor / Product
        # --------------------------------------------------------

        vendor = None
        product = None

        for entry in cpe_entries:

            if not entry.get(
                "vulnerable",
                False,
            ):
                continue

            (
                candidate_vendor,
                candidate_product,
                _,
            ) = (
                self._extract_product_from_cpe(
                    entry["cpe"]
                )
            )

            if (
                candidate_vendor
                and candidate_product
            ):

                vendor = (
                    candidate_vendor
                )

                product = (
                    candidate_product
                )

                break

        # --------------------------------------------------------
        # Affected versions
        # --------------------------------------------------------

        affected_versions = (
            self._extract_affected_versions(
                cpe_entries
            )
        )

        # --------------------------------------------------------
        # Title
        # --------------------------------------------------------

        title = (
            cve_id
            or "Unknown NVD vulnerability"
        )

        # --------------------------------------------------------
        # Fallback description
        #
        # Some very old/rejected NVD records may
        # not contain a usable description.
        # Do not throw them away.
        # --------------------------------------------------------

        if not description:

            description = title

        # --------------------------------------------------------
        # Build unified schema
        # --------------------------------------------------------

        return VulnerabilitySchema(

            source="NVD",

            vulnerability_id=(
                cve_id
            ),

            cve=(
                cve_id
                or None
            ),

            title=title,

            description=description,

            vendor=vendor,

            product=product,

            affected_versions=(
                affected_versions
            ),

            patched_versions=[],

            cpe_matches=(
                cpe_entries
            ),

            cvss=cvss,

            cvss_vector=(
                cvss_vector
            ),

            epss=None,

            kev=False,

            exploit_available=False,

            references=references,

            published=(
                self._parse_datetime(
                    cve.get(
                        "published"
                    )
                )
            ),

            updated=
                self._parse_datetime(
                    cve.get("lastModified")
                ),
        )