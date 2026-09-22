
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta, timezone

from app.core.config import settings
from app.ingestion.incremental import IncrementalIngestionOrchestrator

logger = logging.getLogger(__name__)


class ThreatIngestionScheduler:
    
    def __init__(
        self,
        interval_minutes: int | None = None,
        run_on_startup: bool = True,
    ):
        
        configured_interval = (
            interval_minutes
            if interval_minutes is not None
            else getattr(settings, "THREAT_SYNC_INTERVAL_MINUTES", 15)
        )

        self.interval_minutes = int(configured_interval)

        if self.interval_minutes < 1:
            raise ValueError("interval_minutes must be at least 1")

        self.run_on_startup = run_on_startup
        self.orchestrator = IncrementalIngestionOrchestrator()

        self._running = False
        self._stop_event = asyncio.Event()

    async def start(self):
        """Run incremental ingestion on a repeating interval."""
        if self._running:
            logger.warning("Scheduler is already running.")
            return

        self._running = True
        self._stop_event.clear()

        logger.info(
            "Threat Ingestion Scheduler started. Interval: %d minutes.",
            self.interval_minutes,
        )

        try:
            if self.run_on_startup:
                logger.info("Executing initial startup ingestion cycle...")
                await self._run_cycle()

            interval_seconds = self.interval_minutes * 60

            while self._running:
                next_run = datetime.now(timezone.utc) + timedelta(
                    seconds=interval_seconds
                )
                logger.info(
                    "Next incremental ingestion run at: %s",
                    next_run.isoformat(),
                )

                try:
                    await asyncio.wait_for(
                        self._stop_event.wait(),
                        timeout=interval_seconds,
                    )
                    # Stop event was set.
                    break
                except asyncio.TimeoutError:
                    pass

                if self._running:
                    await self._run_cycle()

        finally:
            self._running = False
            logger.info("Threat Ingestion Scheduler stopped.")

    async def _run_cycle(self):
        try:
            logger.info("Starting scheduled incremental ingestion cycle...")
            summary = await self.orchestrator.run_all_incremental()

            sources = summary.get("sources", {})
            logger.info(
                "Completed sync cycle in %.2fs. "
                "NVD=%s CISA=%s EPSS=%s GITHUB=%s OSV=%s",
                summary.get("duration_seconds", 0),
                sources.get("NVD", {}).get("status"),
                sources.get("CISA", {}).get("status"),
                sources.get("EPSS", {}).get("status"),
                sources.get("GITHUB", {}).get("status"),
                sources.get("OSV", {}).get("status"),
            )
        except Exception:
            logger.exception("Scheduled ingestion cycle failed.")

    def stop(self):
        """Request a prompt, graceful stop of the scheduler loop."""
        logger.info("Stopping Threat Ingestion Scheduler...")
        self._running = False
        self._stop_event.set()