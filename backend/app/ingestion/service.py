from __future__ import annotations

import logging
from datetime import datetime, timezone

from sqlalchemy import select

from app.database.postgres import SessionLocal
from app.ingestion.checkpoint import CheckpointManager
from app.ingestion.fetcher.nvd import NVDFetcher
from app.ingestion.normalizer.nvd import NVDNormalizer
from app.ingestion.normalizer.cisa_kev import CISAKEVNormalizer
from app.ingestion.normalizer.github import GitHubNormalizer
from app.ingestion.normalizer.osv import OSVNormalizer
from app.ingestion.sources.cisa import CISASource
from app.ingestion.sources.epss import EPSSSource
from app.ingestion.sources.github import GitHubAdvisorySource
from app.ingestion.sources.osv import OSVSource
from app.models.vulnerability import Vulnerability
from app.repositories.vulnerability import VulnerabilityRepository

logger = logging.getLogger(__name__)


class NVDIngestionService:

    def __init__(self):
        self.fetcher = NVDFetcher(page_size=2000)
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
            logger.info("Starting NVD ingestion: %s -> %s", window_start, window_end)
            raw_records = await self.fetcher.fetch(
                pub_start=window_start,
                pub_end=window_end,
            )

            fetched = len(raw_records)
            logger.info("Fetched %s NVD records", fetched)

            normalized_records = []
            for raw_cve in raw_records:
                try:
                    normalized = self.normalizer.normalize(raw_cve)
                    normalized_records.append(normalized)
                except Exception:
                    logger.exception("Failed to normalize CVE: %s", raw_cve.get("id"))

            processed = repository.bulk_upsert_schemas(normalized_records)
            checkpoint.complete_run(
                run=run,
                records_fetched=fetched,
                records_processed=processed[0] + processed[1],
            )

            logger.info(
                "Completed NVD window. Fetched=%s Processed=%s",
                fetched,
                processed,
            )

            return {
                "status": "completed",
                "fetched": fetched,
                "processed": processed,
            }

        except Exception as exc:
            checkpoint.fail_run(run, str(exc))
            logger.exception("NVD ingestion failed.")
            raise
        finally:
            db.close()

    
    async def ingest_incremental(
        self,
        lookback_hours: int = 6,
        overlap_minutes: int = 10,
    ) -> dict:
        
        from datetime import timedelta

        if lookback_hours < 1:
            raise ValueError("lookback_hours must be at least 1")

        if overlap_minutes < 0:
            raise ValueError("overlap_minutes cannot be negative")

        db = SessionLocal()
        checkpoint = CheckpointManager(db)
        repository = VulnerabilityRepository(db)

        run = None
        fetched = 0
        inserted = 0
        updated = 0
        unchanged = 0
        normalization_failed = 0

        try:
            # Determine the next modification-time window.
            now = datetime.now(timezone.utc)

            last_window_end = checkpoint.last_successful_window(
                source="NVD",
                run_type="incremental",
            )

            if last_window_end is None:
                start = now - timedelta(hours=lookback_hours)
            else:
                if last_window_end.tzinfo is None:
                    last_window_end = last_window_end.replace(
                        tzinfo=timezone.utc
                    )

                start = last_window_end - timedelta(
                    minutes=overlap_minutes
                )

            if start >= now:
                raise ValueError(
                    f"Invalid NVD window: {start} -> {now}"
                )

            logger.info(
                "NVD incremental window: %s -> %s",
                start.isoformat(),
                now.isoformat(),
            )

            # Persist the running checkpoint before fetching.
            run = checkpoint.start_run(
                source="NVD",
                run_type="incremental",
                window_start=start,
                window_end=now,
            )

            # Fetch records using NVD's last-modified filters.
            raw_records = await self.fetcher.fetch(
                last_mod_start=start,
                last_mod_end=now,
            )

            fetched = len(raw_records)

            logger.info(
                "NVD returned %d modified CVEs",
                fetched,
            )

            normalized_records = []

            for raw_cve in raw_records:
                try:
                    normalized = self.normalizer.normalize(raw_cve)

                    if not normalized.vulnerability_id:
                        raise ValueError(
                            "Normalized record has no vulnerability ID"
                        )

                    normalized_records.append(normalized)

                except Exception:
                    normalization_failed += 1

                    logger.exception(
                        "NVD normalization failed for record: %s",
                        raw_cve.get("id", "UNKNOWN"),
                    )

            # Never advance the checkpoint if any records failed
            # normalization. The next retry will re-fetch the window.
            if normalization_failed:
                raise RuntimeError(
                    f"{normalization_failed} of {fetched} NVD "
                    "records failed normalization; checkpoint "
                    "will not be completed."
                )

            # Persist all normalized CVEs. This repository method
            # commits the vulnerability transaction.
            inserted, updated, unchanged = (
                repository.bulk_upsert_schemas(normalized_records)
            )

            processed = inserted + updated + unchanged

            if processed != fetched:
                raise RuntimeError(
                    "NVD processing count mismatch: "
                    f"fetched={fetched}, processed={processed}"
                )

            # Only mark the window complete after successful
            # vulnerability persistence.
            checkpoint.complete_run(
                run=run,
                records_fetched=fetched,
                records_processed=processed,
            )

            logger.info(
                "NVD incremental completed: fetched=%d inserted=%d "
                "updated=%d unchanged=%d",
                fetched,
                inserted,
                updated,
                unchanged,
            )

            return {
                "status": "completed",
                "window_start": start.isoformat(),
                "window_end": now.isoformat(),
                "fetched": fetched,
                "inserted": inserted,
                "updated": updated,
                "unchanged": unchanged,
                "normalization_failed": normalization_failed,
            }

        except Exception as exc:
            logger.exception("NVD incremental ingestion failed")

            if run is not None:
                # The checkpoint manager handles its own commit
                # and rollback when marking a run failed.
                checkpoint.fail_run(
                    run,
                    str(exc),
                )

            raise

        finally:
            db.close()


class CISAIngestionService:

    def __init__(self):
        self.source = CISASource()
        self.normalizer = CISAKEVNormalizer()

    async def ingest(self) -> dict:
        db = SessionLocal()
        checkpoint = CheckpointManager(db)
        repository = VulnerabilityRepository(db)

        now = datetime.now(timezone.utc)
        run = checkpoint.start_run(
            source="CISA",
            run_type="full_sync",
            window_start=now,
            window_end=now,
        )

        try:
            logger.info("Starting CISA KEV ingestion...")
            raw_records = await self.source.fetch()
            fetched = len(raw_records)
            logger.info("Fetched %d CISA KEV records", fetched)

            normalized = [self.normalizer.normalize(r) for r in raw_records]
            enriched, inserted = repository.enrich_cisa_kev(normalized)

            checkpoint.complete_run(
                run=run,
                records_fetched=fetched,
                records_processed=enriched + inserted,
            )

            logger.info("CISA KEV ingestion complete. Enriched=%d Inserted=%d", enriched, inserted)
            return {"status": "completed", "fetched": fetched, "enriched": enriched, "inserted": inserted}
        except Exception as exc:
            checkpoint.fail_run(run, str(exc))
            logger.exception("CISA ingestion failed.")
            raise
        finally:
            db.close()


class EPSSIngestionService:

    def __init__(self):
        self.source = EPSSSource()

    
    
    async def ingest_bulk(self) -> dict:
        db = SessionLocal()
        checkpoint = CheckpointManager(db)
        repository = VulnerabilityRepository(db)

        now = datetime.now(timezone.utc)

        run = checkpoint.start_run(
            source="EPSS",
            run_type="full_sync",
            window_start=now,
            window_end=now,
        )

        try:
            logger.info("Starting EPSS bulk ingestion...")

            try:
                epss_map = await self.source.fetch_bulk_csv()
            except Exception:
                logger.exception(
                    "EPSS bulk CSV failed; falling back to FIRST API"
                )
                cves = db.scalars(
                    select(Vulnerability.cve)
                    .where(Vulnerability.cve.is_not(None))
                    .distinct()
                ).all()
                epss_map = await self.source.fetch_batch(list(cves))

            if not epss_map:
                raise RuntimeError(
                    "EPSS source returned no records"
                )

            fetched = len(epss_map)
            updated = repository.bulk_update_epss(epss_map)

            checkpoint.complete_run(
                run=run,
                records_fetched=fetched,
                records_processed=updated,
            )

            logger.info(
                "EPSS ingestion complete. Fetched=%d Updated=%d",
                fetched,
                updated,
            )

            return {
                "status": "completed",
                "fetched": fetched,
                "updated": updated,
            }

        except Exception as exc:
            checkpoint.fail_run(run, str(exc))
            logger.exception("EPSS ingestion failed.")
            raise

        finally:
            db.close()  



class GitHubIngestionService:

    def __init__(self):
        self.source = GitHubAdvisorySource()
        self.normalizer = GitHubNormalizer()

    async def ingest(self, max_pages: int = 10) -> dict:
        db = SessionLocal()
        checkpoint = CheckpointManager(db)
        repository = VulnerabilityRepository(db)

        now = datetime.now(timezone.utc)
        run = checkpoint.start_run(
            source="GITHUB",
            run_type="advisories",
            window_start=now,
            window_end=now,
        )

        try:
            logger.info("Starting GitHub Advisories ingestion (max_pages=%d)...", max_pages)
            raw_records = await self.source.fetch_all(max_pages=max_pages)
            fetched = len(raw_records)
            logger.info("Fetched %d GitHub Advisory records", fetched)

            
            normalized = []
            normalization_failed = 0

            for record in raw_records:
                try:
                    schema = self.normalizer.normalize(record)

                    if not schema.vulnerability_id:
                        raise ValueError(
                            "Normalized advisory has no vulnerability ID"
                        )

                    normalized.append(schema)

                except Exception:
                    normalization_failed += 1
                    logger.exception(
                        "Failed to normalize GitHub advisory: %s",
                        record.get("ghsa_id", "UNKNOWN"),
                    )

            if normalization_failed:
                raise RuntimeError(
                    f"{normalization_failed} of {fetched} GitHub "
                    "advisories failed normalization. "
                    "Run will not be marked completed."
                )

            unique_normalized = {}
            for schema in normalized:
                unique_normalized.setdefault(
                    (
                        schema.source.upper(),
                        schema.vulnerability_id.upper(),
                    ),
                    schema,
                )

            inserted, updated, unchanged = (
                repository.bulk_upsert_schemas(
                    list(unique_normalized.values())
                )
            )

            processed = inserted + updated + unchanged

            if processed != len(unique_normalized):
                raise RuntimeError(
                    "GitHub count mismatch after deduplication: "
                    f"unique={len(unique_normalized)}, processed={processed}"
                )

            checkpoint.complete_run(
                run=run,
                records_fetched=fetched,
                records_processed=processed,
            )

            logger.info("GitHub ingestion complete. Inserted=%d Updated=%d Unchanged=%d", inserted, updated, unchanged)
            return {
            "status": "completed",
            "fetched": fetched,
            "unique": len(unique_normalized),
            "inserted": inserted,
            "updated": updated,
            "unchanged": unchanged,
            "limited": max_pages is not None,
        }
        except Exception as exc:
            checkpoint.fail_run(run, str(exc))
            logger.exception("GitHub ingestion failed.")
            raise
        finally:
            db.close()


class OSVIngestionService:

    def __init__(self):
        self.source = OSVSource()
        self.normalizer = OSVNormalizer()

    async def ingest(self, max_records: int | None = None) -> dict:
        db = SessionLocal()
        checkpoint = CheckpointManager(db)
        repository = VulnerabilityRepository(db)

        now = datetime.now(timezone.utc)
        run = checkpoint.start_run(
            source="OSV",
            run_type="vulnerabilities",
            window_start=now,
            window_end=now,
        )

        try:
            
            logger.info("Starting OSV ingestion...")

            normalized_batch = []
            fetched = 0
            normalization_failed = 0

            async for raw in self.source.records(
                max_records=max_records
            ):
                fetched += 1

                try:
                    schema = self.normalizer.normalize(raw)

                    if not schema.vulnerability_id:
                        raise ValueError(
                            "Normalized OSV record has no vulnerability ID"
                        )

                    normalized_batch.append(schema)

                except Exception:
                    normalization_failed += 1
                    logger.exception(
                        "Failed to normalize OSV record"
                    )

            if normalization_failed:
                raise RuntimeError(
                    f"{normalization_failed} of {fetched} OSV "
                    "records failed normalization. "
                    "Run will not be marked completed."
                )

            inserted, updated, unchanged = (
                repository.bulk_upsert_schemas(normalized_batch)
            )

            processed = inserted + updated + unchanged

            if processed != fetched:
                raise RuntimeError(
                    f"OSV count mismatch: fetched={fetched}, "
                    f"processed={processed}"
                )

            checkpoint.complete_run(
                run=run,
                records_fetched=fetched,
                records_processed=processed,
            )

            logger.info(
                "OSV ingestion complete. Fetched=%d "
                "Inserted=%d Updated=%d Unchanged=%d",
                fetched,
                inserted,
                updated,
                unchanged,
            )

            return {
            "status": "completed",
            "fetched": fetched,
            "inserted": inserted,
            "updated": updated,
            "unchanged": unchanged,
            "limited": max_records is not None,
        }
        except Exception as exc:
            checkpoint.fail_run(run, str(exc))
            logger.exception("OSV ingestion failed.")
            raise
        finally:
            db.close()
