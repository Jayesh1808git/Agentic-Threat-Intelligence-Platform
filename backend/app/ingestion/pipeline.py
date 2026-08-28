from collections import defaultdict

from app.schemas.vulnerability import (
    VulnerabilitySchema,
)


class VulnerabilityMerger:

    def merge(
        self,
        records: list[VulnerabilitySchema],
    ) -> list[VulnerabilitySchema]:

        groups = defaultdict(list)

        for record in records:

            key = self._identity(record)

            groups[key].append(record)

        merged = []

        for records_for_id in groups.values():

            merged.append(
                self._merge_group(
                    records_for_id
                )
            )

        return merged

    def _identity(
        self,
        record: VulnerabilitySchema,
    ) -> str:

        if record.cve:

            return (
                f"cve:{record.cve.lower()}"
            )

        for alias in record.aliases:

            if alias.upper().startswith(
                "CVE-"
            ):

                return (
                    f"cve:{alias.lower()}"
                )

        if record.aliases:

            return (
                f"alias:"
                f"{sorted(record.aliases)[0].lower()}"
            )

        return (
            f"source:"
            f"{record.source.lower()}:"
            f"{record.vulnerability_id.lower()}"
        )

    def _merge_group(
        self,
        records: list[VulnerabilitySchema],
    ) -> VulnerabilitySchema:

        base = max(
            records,
            key=self._quality_score,
        )

        sources = [
            record.source
            for record in records
        ]

        aliases = set(
            base.aliases
        )

        for record in records:

            aliases.update(
                record.aliases
            )

            if (
                record.cve
                and record.cve != base.cve
            ):
                aliases.add(
                    record.cve
                )

        return base.model_copy(
            update={
                "aliases": sorted(
                    aliases
                ),

                "kev": any(
                    r.kev
                    for r in records
                ),

                "exploit_available": any(
                    r.exploit_available
                    for r in records
                ),

                "epss": self._first_not_none(
                    [
                        r.epss
                        for r in records
                    ]
                ),

                "references": sorted(
                    set(
                        ref
                        for r in records
                        for ref in r.references
                    )
                ),

                "cpe_matches": [
                    cpe
                    for r in records
                    for cpe in r.cpe_matches
                ],

                "raw_id": "|".join(
                    sources
                ),
            }
        )

    @staticmethod
    def _quality_score(
        record: VulnerabilitySchema,
    ) -> int:

        score = 0

        if record.description:
            score += 5

        if record.cve:
            score += 5

        if record.vendor:
            score += 2

        if record.product:
            score += 2

        if record.cvss is not None:
            score += 2

        if record.cpe_matches:
            score += 3

        if record.affected_versions:
            score += 2

        return score

    @staticmethod
    def _first_not_none(
        values,
    ):

        for value in values:

            if value is not None:
                return value

        return None