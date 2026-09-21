from __future__ import annotations

import asyncio
import logging
import signal
from datetime import datetime, timedelta, timezone

from app.core.config import settings
from app.ingestion.incremental import IncrementalIngestionOrchestrator

logger = logging.getLogger(__name__)


class ThreatIngestionScheduler:

    def __init__(
        self,
        interval_hours: int | None = None,
        run_on_startup: bool = True,
    ):
        self.interval_hours = interval_hours or getattr(settings, "THREAT_SYNC_INTERVAL_HOURS", 5)
        self.run_on_startup = run_on_startup
        self.orchestrator = IncrementalIngestionOrchestrator()
        self._running = False
        self._task: asyncio.Task | None = None

    async def start(self):
        """
        Start the automated background scheduler loop.
        """
        self._running = True
        logger.info(
            "Threat Ingestion Scheduler started. Automated sync interval: %d hours.",
            self.interval_hours,
        )

        interval_seconds = self.interval_hours * 3600

        if self.run_on_startup:
            logger.info("Executing initial startup ingestion cycle...")
            await self._run_cycle()

        while self._running:
            next_run = datetime.now(timezone.utc) + timedelta(seconds=interval_seconds)
            logger.info("Next scheduled incremental ingestion run at: %s (in %d hours)", next_run.isoformat(), self.interval_hours)

            try:
                await asyncio.sleep(interval_seconds)
            except asyncio.CancelledError:
                logger.info("Scheduler task cancelled.")
                break

            if self._running:
                await self._run_cycle()

    async def _run_cycle(self):
        try:
            logger.info("Starting scheduled incremental ingestion cycle...")
            summary = await self.orchestrator.run_all_incremental()
            logger.info("Completed scheduled sync cycle in %.2fs. NVD=%s CISA=%s EPSS=%s GITHUB=%s OSV=%s",
                        summary.get("duration_seconds", 0),
                        summary.get("sources", {}).get("NVD", {}).get("status"),
                        summary.get("sources", {}).get("CISA", {}).get("status"),
                        summary.get("sources", {}).get("EPSS", {}).get("status"),
                        summary.get("sources", {}).get("GITHUB", {}).get("status"),
                        summary.get("sources", {}).get("OSV", {}).get("status"))
        except Exception as exc:
            logger.error("Scheduled ingestion cycle failed: %s", exc)

    def stop(self):
        """
        Stop the background scheduler loop.
        """
        logger.info("Stopping Threat Ingestion Scheduler...")
        self._running = False
        if self._task and not self._task.done():
            self._task.cancel()
