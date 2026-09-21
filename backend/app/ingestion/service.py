from __future__ import annotations

import logging
from datetime import datetime, timezone

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

    async def ingest_incremental(self, lookback_hours: int = 6) -> dict:
        from datetime import timedelta
        db = SessionLocal()
        checkpoint = CheckpointManager(db)
        repository = VulnerabilityRepository(db)

        now = datetime.now(timezone.utc)
        last_window = checkpoint.last_successful_window(source="NVD", run_type="incremental")

        if last_window:
            start = last_window - timedelta(minutes=5)
        else:
            start = now - timedelta(hours=lookback_hours)

        run = checkpoint.start_run(
            source="NVD",
            run_type="incremental",
            window_start=start,
            window_end=now,
        )

        try:
            logger.info("Starting NVD incremental ingestion: %s -> %s", start, now)
            raw_records = await self.fetcher.fetch(
                last_mod_start=start,
                last_mod_end=now,
            )
            fetched = len(raw_records)
            logger.info("Fetched %d modified NVD records", fetched)

            normalized_records = []
            for raw_cve in raw_records:
                try:
                    normalized = self.normalizer.normalize(raw_cve)
                    normalized_records.append(normalized)
                except Exception as exc:
                    logger.warning("Failed to normalize NVD CVE: %s", exc)

            inserted, updated, unchanged = repository.bulk_upsert_schemas(normalized_records)

            checkpoint.complete_run(
                run=run,
                records_fetched=fetched,
                records_processed=inserted + updated,
            )

            logger.info("NVD incremental sync complete. Fetched=%d Inserted=%d Updated=%d Unchanged=%d", fetched, inserted, updated, unchanged)
            return {
                "status": "completed",
                "fetched": fetched,
                "inserted": inserted,
                "updated": updated,
                "unchanged": unchanged,
            }
        except Exception as exc:
            checkpoint.fail_run(run, str(exc))
            logger.exception("NVD incremental sync failed.")
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
            logger.info("Starting EPSS ingestion...")
            epss_map = {}
            try:
                epss_map = await self.source.fetch_bulk_csv()
            except Exception as exc:
                logger.warning("Bulk CSV download failed (%s). Falling back to FIRST API batching for DB CVEs...", exc)
                # Fetch CVEs from DB that have no EPSS or need refresh
                from sqlalchemy import select
                from app.models.vulnerability import Vulnerability
                cve_records = db.scalars(
                    select(Vulnerability.cve).where(Vulnerability.cve.isnot(None))
                ).all()
                cves = [c for c in cve_records if c]
                logger.info("Batch fetching EPSS for %d CVEs from FIRST API...", len(cves))
                epss_map = await self.source.fetch_batch(cves)

            fetched = len(epss_map)
            updated = repository.bulk_update_epss(epss_map)

            checkpoint.complete_run(
                run=run,
                records_fetched=fetched,
                records_processed=updated,
            )

            logger.info("EPSS ingestion complete. Fetched=%d Updated=%d", fetched, updated)
            return {"status": "completed", "fetched": fetched, "updated": updated}
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
            for r in raw_records:
                try:
                    normalized.append(self.normalizer.normalize(r))
                except Exception as exc:
                    logger.warning("Failed to normalize GitHub advisory: %s", exc)

            inserted, updated, unchanged = repository.bulk_upsert_schemas(normalized)

            checkpoint.complete_run(
                run=run,
                records_fetched=fetched,
                records_processed=inserted + updated,
            )

            logger.info("GitHub ingestion complete. Inserted=%d Updated=%d Unchanged=%d", inserted, updated, unchanged)
            return {
                "status": "completed",
                "fetched": fetched,
                "inserted": inserted,
                "updated": updated,
                "unchanged": unchanged,
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

            async for raw in self.source.records(max_records=max_records):
                fetched += 1
                try:
                    schema = self.normalizer.normalize(raw)
                    normalized_batch.append(schema)
                except Exception as exc:
                    logger.warning("Failed to normalize OSV record: %s", exc)

            inserted, updated, unchanged = repository.bulk_upsert_schemas(normalized_batch)

            checkpoint.complete_run(
                run=run,
                records_fetched=fetched,
                records_processed=inserted + updated,
            )

            logger.info("OSV ingestion complete. Fetched=%d Inserted=%d Updated=%d", fetched, inserted, updated)
            return {
                "status": "completed",
                "fetched": fetched,
                "inserted": inserted,
                "updated": updated,
                "unchanged": unchanged,
            }
        except Exception as exc:
            checkpoint.fail_run(run, str(exc))
            logger.exception("OSV ingestion failed.")
            raise
        finally:
            db.close()