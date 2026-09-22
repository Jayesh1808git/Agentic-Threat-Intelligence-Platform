from __future__ import annotations

import logging
from datetime import datetime, timezone

from app.ingestion.service import (
    CISAIngestionService,
    EPSSIngestionService,
    GitHubIngestionService,
    NVDIngestionService,
    OSVIngestionService,
)

logger = logging.getLogger(__name__)


class IncrementalIngestionOrchestrator:

    def __init__(self):
        self.nvd_service = NVDIngestionService()
        self.cisa_service = CISAIngestionService()
        self.epss_service = EPSSIngestionService()
        self.github_service = GitHubIngestionService()
        self.osv_service = OSVIngestionService()

    async def run_all_incremental(
        self,
        nvd_lookback_hours: int = 6,
        nvd_overlap_minutes: int = 10,
        github_max_pages: int = 3,
        osv_max_records: int = 500,
    ) -> dict:
        start_time = datetime.now(timezone.utc)
        logger.info("Starting unified incremental threat intelligence ingestion cycle...")

        summary = {
            "start_time": start_time.isoformat(),
            "sources": {},
            "status": "completed",
        }

        # 1. NVD Incremental Sync
        try:
            logger.info("Executing NVD incremental ingestion...")
            nvd_result = await self.nvd_service.ingest_incremental(
                lookback_hours=nvd_lookback_hours,
                overlap_minutes=nvd_overlap_minutes,
            )
            summary["sources"]["NVD"] = nvd_result
        except Exception as exc:
            logger.error("NVD incremental sync failed: %s", exc)
            summary["sources"]["NVD"] = {"status": "failed", "error": str(exc)}

        # 2. CISA KEV Sync
        try:
            logger.info("Executing CISA KEV ingestion...")
            cisa_result = await self.cisa_service.ingest()
            summary["sources"]["CISA"] = cisa_result
        except Exception as exc:
            logger.error("CISA ingestion failed: %s", exc)
            summary["sources"]["CISA"] = {"status": "failed", "error": str(exc)}

        # 3. EPSS Risk Score Refresh
        try:
            logger.info("Executing EPSS risk score refresh...")
            epss_result = await self.epss_service.ingest_bulk()
            summary["sources"]["EPSS"] = epss_result
        except Exception as exc:
            logger.error("EPSS ingestion failed: %s", exc)
            summary["sources"]["EPSS"] = {"status": "failed", "error": str(exc)}

        # 4. GitHub Advisories Sync
        try:
            logger.info("Executing GitHub Advisories incremental ingestion...")
            github_result = await self.github_service.ingest(max_pages=github_max_pages)
            summary["sources"]["GITHUB"] = github_result
        except Exception as exc:
            logger.error("GitHub ingestion failed: %s", exc)
            summary["sources"]["GITHUB"] = {"status": "failed", "error": str(exc)}

        # 5. OSV Incremental Sync
        try:
            logger.info("Executing OSV incremental ingestion...")
            osv_result = await self.osv_service.ingest(max_records=osv_max_records)
            summary["sources"]["OSV"] = osv_result
        except Exception as exc:
            logger.error("OSV ingestion failed: %s", exc)
            summary["sources"]["OSV"] = {"status": "failed", "error": str(exc)}

        end_time = datetime.now(timezone.utc)

        failed_sources = [
            source
            for source, result in summary["sources"].items()
            if result.get("status") != "completed"
        ]

        summary["end_time"] = end_time.isoformat()
        summary["duration_seconds"] = round(
            (end_time - start_time).total_seconds(),
            2,
        )
        summary["failed_sources"] = failed_sources
        summary["status"] = (
            "partial"
            if failed_sources
            else "completed"
        )

        logger.info(
            "Unified incremental cycle finished: status=%s duration=%.2fs",
            summary["status"],
            summary["duration_seconds"],
        )

        return summary
