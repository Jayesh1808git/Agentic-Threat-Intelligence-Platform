from __future__ import annotations

import logging

from app.database.postgres import SessionLocal
from app.ingestion.checkpoint import CheckpointManager
from app.ingestion.fetcher.nvd import NVDFetcher
from app.ingestion.normalizer.nvd import NVDNormalizer
from app.repositories.vulnerability import (
    VulnerabilityRepository,
)

logger = logging.getLogger(__name__)


class NVDIngestionService:

    def __init__(self):

        self.fetcher = NVDFetcher(
            page_size=2000,
        )

        self.normalizer = NVDNormalizer()

    async def ingest_window(
        self,
        window_start,
        window_end,
    ) -> dict:

        db = SessionLocal()

        checkpoint = CheckpointManager(db)

        repository = VulnerabilityRepository(db)

        run = checkpoint.start_run(
            source="NVD",
            run_type="historical",
            window_start=window_start,
            window_end=window_end,
        )

        try:

            logger.info(
                "Starting NVD ingestion: %s -> %s",
                window_start,
                window_end,
            )

            raw_records = await self.fetcher.fetch(
                pub_start=window_start,
                pub_end=window_end,
            )

            fetched = len(raw_records)

            logger.info(
                "Fetched %s NVD records",
                fetched,
            )

            normalized_records = []

            for raw_cve in raw_records:

                try:

                    normalized = (
                        self.normalizer.normalize(
                            raw_cve
                        )
                    )

                    normalized_records.append(
                        normalized
                    )

                except Exception as exc:

                    logger.exception(
                        "Failed to normalize CVE: %s",
                        raw_cve.get("id"),
                    )

            processed = repository.bulk_upsert(
                normalized_records
            )

            checkpoint.complete_run(
                run=run,
                records_fetched=fetched,
                records_processed=processed,
            )

            logger.info(
                "Completed NVD window. "
                "Fetched=%s Processed=%s",
                fetched,
                processed,
            )

            return {
                "status": "completed",
                "fetched": fetched,
                "processed": processed,
            }

        except Exception as exc:

            checkpoint.fail_run(
                run,
                str(exc),
            )

            logger.exception(
                "NVD ingestion failed."
            )

            raise

        finally:

            db.close()