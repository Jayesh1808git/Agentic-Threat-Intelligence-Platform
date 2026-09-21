import argparse
import asyncio
import logging
import signal
import sys

from app.ingestion.scheduler import ThreatIngestionScheduler

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)

logger = logging.getLogger("scheduler_daemon")


async def main():
    parser = argparse.ArgumentParser(description="Threat Intelligence Automated Ingestion Daemon")
    parser.add_argument("--interval-hours", type=int, default=5, help="Ingestion interval in hours (default: 5)")
    parser.add_argument("--no-initial-run", action="store_true", help="Skip immediate initial ingestion on startup")
    parser.add_argument("--run-once", action="store_true", help="Run a single incremental cycle and exit")

    args = parser.parse_args()

    scheduler = ThreatIngestionScheduler(
        interval_hours=args.interval_hours,
        run_on_startup=not args.no_initial_run,
    )

    if args.run_once:
        logger.info("Executing single incremental ingestion cycle...")
        await scheduler._run_cycle()
        logger.info("Run-once cycle completed. Exiting daemon.")
        return

    # Setup signal handlers for graceful shutdown
    loop = asyncio.get_running_loop()

    def shutdown():
        logger.info("Received termination signal. Shutting down daemon...")
        scheduler.stop()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, shutdown)
        except NotImplementedError:
            # Signal handling on Windows selector loop fallback
            pass

    logger.info("Starting Threat Ingestion Daemon (running every %d hours)...", args.interval_hours)
    await scheduler.start()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Daemon interrupted by user. Exiting.")
        sys.exit(0)
