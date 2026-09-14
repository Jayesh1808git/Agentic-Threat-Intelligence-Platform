from __future__ import annotations

from app.core.config import settings
from app.database.postgres import SessionLocal
from app.ingestion.hash import (
    vulnerability_content_hash,
)
from app.ingestion.normalizer.nvd import (
    NVDNormalizer,
)
from app.ingestion.sources.nvd import (
    NVDSource,
)
from app.ingestion.state.checkpoint import (
    CheckpointManager,
)
from app.repositories.vulnerability import (
    VulnerabilityRepository,
)


class BulkIngestion:

    SOURCE = "NVD"
    RUN_TYPE = "historical"

    def __init__(self):

        self.source = NVDSource(
            settings.NVD_API_KEY
        )

        self.normalizer = NVDNormalizer()

    # ============================================================
    # NVD HISTORICAL INGESTION
    # ============================================================

    async def ingest_nvd(
        self,
        start_year: int = 1999,
        end_year: int = 2024,
    ):

        print()
        print("=" * 70)
        print("CYBERRAG NVD -> LOCAL POSTGRESQL")
        print("=" * 70)

        print(
            f"Start year: {start_year}"
        )

        async for start, end in (
            self.source.historical(
                start_year=start_year,
                end_year=end_year,
            )
        ):

            await self._process_window(
                start,
                end,
            )

        print()
        print("=" * 70)
        print("NVD HISTORICAL INGESTION COMPLETE")
        print("=" * 70)

    # ============================================================
    # WINDOW
    # ============================================================

    async def _process_window(
        self,
        start,
        end,
    ):

        window = (
            f"{start.date()} -> "
            f"{end.date()}"
        )

        print()
        print("=" * 70)
        print(f"NVD WINDOW: {window}")
        print("=" * 70)

        # --------------------------------------------------------
        # Check database checkpoint
        # --------------------------------------------------------

        db = SessionLocal()

        try:

            checkpoint = CheckpointManager(db)

            if checkpoint.is_window_completed(
                source=self.SOURCE,
                run_type=self.RUN_TYPE,
                window_start=start,
                window_end=end,
            ):

                print(
                    f"SKIP: window already completed: "
                    f"{window}"
                )

                return

        finally:

            db.close()

        # --------------------------------------------------------
        # Start ingestion checkpoint
        # --------------------------------------------------------

        db = SessionLocal()

        run = None

        try:

            checkpoint = CheckpointManager(db)

            run = checkpoint.start_run(
                source=self.SOURCE,
                run_type=self.RUN_TYPE,
                window_start=start,
                window_end=end,
            )

        finally:

            db.close()

        # --------------------------------------------------------
        # Fetch
        # --------------------------------------------------------

        try:

            raw_records = (
                await self.source.fetch_window(
                    start=start,
                    end=end,
                )
            )

            print()
            print(
                f"NVD fetched: "
                f"{len(raw_records)}"
            )

            # ----------------------------------------------------
            # Normalize
            # ----------------------------------------------------

            normalized = []

            normalization_failed = 0

            for raw_record in raw_records:

                try:

                    vulnerability = (
                        self.normalizer.normalize(
                            raw_record
                        )
                    )

                    if not vulnerability.vulnerability_id:

                        raise ValueError(
                            "NVD record has no "
                            "vulnerability ID."
                        )

                    if not vulnerability.title:

                        vulnerability.title = (
                            vulnerability.vulnerability_id
                        )

                    if not vulnerability.description:

                        vulnerability.description = (
                            vulnerability.title
                        )

                    normalized.append(
                        vulnerability
                    )

                except Exception as exc:

                    normalization_failed += 1

                    cve_id = (
                        raw_record
                        .get("cve", {})
                        .get("id", "UNKNOWN")
                    )

                    print(
                        "NORMALIZATION ERROR: "
                        f"{cve_id}: {exc}"
                    )

            print(
                f"Normalized: "
                f"{len(normalized)}"
            )

            print(
                f"Normalization failures: "
                f"{normalization_failed}"
            )

            if raw_records and not normalized:

                raise RuntimeError(
                    "NVD returned records, "
                    "but none could be normalized."
                )

            # ----------------------------------------------------
            # PostgreSQL
            # ----------------------------------------------------

            (
                inserted,
                updated,
                unchanged,
            ) = self._persist_records(
                normalized
            )

            # ----------------------------------------------------
            # Checkpoint ONLY after successful DB commit
            # ----------------------------------------------------

            db = SessionLocal()

            try:

                checkpoint = CheckpointManager(db)

                run = (
                    db.merge(run)
                )

                checkpoint.complete_run(
                    run=run,
                    records_fetched=len(
                        raw_records
                    ),
                    records_processed=len(
                        normalized
                    ),
                )

            finally:

                db.close()

            print()
            print(
                f"WINDOW COMPLETED: {window}"
            )

            print(
                f"Fetched:    {len(raw_records)}"
            )

            print(
                f"Normalized: {len(normalized)}"
            )

            print(
                f"Inserted:   {inserted}"
            )

            print(
                f"Updated:    {updated}"
            )

            print(
                f"Unchanged:  {unchanged}"
            )

            print(
                f"Failed normalization: "
                f"{normalization_failed}"
            )

        except Exception as exc:

            print()
            print("=" * 70)
            print(
                f"NVD WINDOW FAILED: {window}"
            )
            print("=" * 70)

            print(
                f"Error: {exc}"
            )

            # ----------------------------------------------------
            # Mark checkpoint failed
            # ----------------------------------------------------

            if run is not None:

                db = SessionLocal()

                try:

                    checkpoint = (
                        CheckpointManager(db)
                    )

                    run = db.merge(run)

                    checkpoint.fail_run(
                        run=run,
                        error_message=str(exc),
                    )

                finally:

                    db.close()

            raise

    # ============================================================
    # PERSIST
    # ============================================================

    def _persist_records(
        self,
        vulnerabilities,
    ) -> tuple[int, int, int]:

        inserted = 0
        updated = 0
        unchanged = 0

        db = SessionLocal()

        try:

            repository = (
                VulnerabilityRepository(db)
            )

            for vulnerability in vulnerabilities:

                content_hash = (
                    vulnerability_content_hash(
                        vulnerability
                    )
                )

                (
                    _record,
                    was_inserted,
                    semantic_changed,
                ) = repository.upsert(
                    vulnerability,
                    content_hash,
                )

                if was_inserted:

                    inserted += 1

                elif semantic_changed:

                    updated += 1

                else:

                    unchanged += 1

            # ----------------------------------------------------
            # Critical:
            #
            # All records in this window are committed together.
            # The checkpoint is NOT written here.
            # ----------------------------------------------------

            db.commit()

        except Exception:

            db.rollback()

            raise

        finally:

            db.close()

        return (
            inserted,
            updated,
            unchanged,
        )

    # ============================================================
    # RUN
    # ============================================================

    async def run(
        self,
        nvd: bool = True,
        start_year: int = 1999,
        end_year: int = 2024,
    ):

        if nvd:

            await self.ingest_nvd(
                start_year=start_year,
                end_year=end_year,
            )


async def run_nvd_ingestion(
    start_year: int = 1999,
    end_year: int = 2024,
):

    ingestion = BulkIngestion()

    await ingestion.run(
        nvd=True,
        start_year=start_year,
        end_year=end_year,
    )