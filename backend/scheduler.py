
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
    parser = argparse.ArgumentParser(
        description="Threat Intelligence Automated Ingestion Daemon"
    )

    interval = parser.add_mutually_exclusive_group()
    interval.add_argument(
        "--interval-minutes",
        type=int,
        help="Ingestion interval in minutes (default: 15)",
    )


    parser.add_argument(
        "--no-initial-run",
        action="store_true",
        help="Skip immediate initial ingestion on startup",
    )
    parser.add_argument(
        "--run-once",
        action="store_true",
        help="Run one incremental cycle and exit",
    )

    args = parser.parse_args()

    scheduler_kwargs = {
        "run_on_startup": not args.no_initial_run,
    }

    scheduler_kwargs["interval_minutes"] = args.interval_minutes


    scheduler = ThreatIngestionScheduler(**scheduler_kwargs)

    if args.run_once:
        logger.info("Executing single incremental ingestion cycle...")
        await scheduler._run_cycle()
        logger.info("Run-once cycle completed.")
        return

    loop = asyncio.get_running_loop()

    def shutdown():
        logger.info("Received termination signal.")
        scheduler.stop()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, shutdown)
        except (NotImplementedError, RuntimeError):
            # Signal handler support varies by platform.
            pass

    logger.info(
        "Starting ingestion daemon: every %d minutes.",
        scheduler.interval_minutes,
    )
    await scheduler.start()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Daemon interrupted.")
        sys.exit(0)