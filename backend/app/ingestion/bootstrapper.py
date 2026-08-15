from __future__ import annotations

import argparse
import asyncio
import logging
from datetime import datetime, timedelta, timezone

from app.database.postgres import SessionLocal
from app.ingestion.checkpoint import CheckpointManager
from app.ingestion.service import NVDIngestionService


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
)

logger = logging.getLogger(__name__)


# NVD allows date ranges up to 120 days.
# We use 90 days for safety.
MAX_NVD_WINDOW_DAYS = 90


def generate_windows(
    start: datetime,
    end: datetime,
):
    """
    Generate safe NVD date windows.
    """

    current = start

    while current < end:

        window_end = min(
            current + timedelta(
                days=MAX_NVD_WINDOW_DAYS
            ),
            end,
        )

        yield current, window_end

        current = window_end


def get_completed_windows(
    source: str,
    run_type: str,
):
    """
    Retrieve all successfully completed
    ingestion windows.
    """

    db = SessionLocal()

    try:

        checkpoint = CheckpointManager(db)

        runs = checkpoint.get_completed_windows(
            source=source,
            run_type=run_type,
        )

        return {
            (
                run.window_start,
                run.window_end,
            )
            for run in runs
        }

    finally:

        db.close()


async def bootstrap(
    start_year: int,
    end_year: int,
    force: bool = False,
):

    start = datetime(
        start_year,
        1,
        1,
        tzinfo=timezone.utc,
    )

    end = datetime(
        end_year + 1,
        1,
        1,
        tzinfo=timezone.utc,
    )

    windows = list(
        generate_windows(
            start,
            end,
        )
    )

    completed_windows = set()

    if not force:

        completed_windows = get_completed_windows(
            source="NVD",
            run_type="historical",
        )

    print()
    print("=" * 70)
    print("NVD HISTORICAL BOOTSTRAP")
    print("=" * 70)

    print(
        f"Period: "
        f"{start.date()} → "
        f"{(end - timedelta(seconds=1)).date()}"
    )

    print(
        f"Total windows: {len(windows)}"
    )

    print(
        f"Completed windows: "
        f"{len(completed_windows)}"
    )

    print(
        f"Remaining windows: "
        f"{len(windows) - len(completed_windows)}"
    )

    print("=" * 70)
    print()

    service = NVDIngestionService()

    total_fetched = 0
    total_processed = 0
    skipped = 0
    failed = 0

    for index, (
        window_start,
        window_end,
    ) in enumerate(windows, start=1):

        window_key = (
            window_start,
            window_end,
        )

        # --------------------------------------------------
        # Skip completed window
        # --------------------------------------------------

        if not force and window_key in completed_windows:

            skipped += 1

            print(
                f"[{index}/{len(windows)}] "
                f"SKIPPING COMPLETED"
            )

            print(
                f"    {window_start.date()} → "
                f"{window_end.date()}"
            )

            print()

            continue

        print(
            f"[{index}/{len(windows)}] "
            f"PROCESSING"
        )

        print(
            f"    {window_start.date()} → "
            f"{window_end.date()}"
        )

        try:

            result = await service.ingest_window(
                window_start,
                window_end,
            )

            fetched = result["fetched"]
            processed = result["processed"]

            total_fetched += fetched
            total_processed += processed

            print(
                f"    Fetched:   {fetched}"
            )

            print(
                f"    Processed: {processed}"
            )

            print()

        except Exception as exc:

            failed += 1

            logger.exception(
                "Window failed: %s → %s",
                window_start,
                window_end,
            )

            print(
                f"    ERROR: {exc}"
            )

            print(
                "    Stopping bootstrap."
            )

            print(
                "    Restart the same command "
                "to resume."
            )

            break

    print("=" * 70)
    print("BOOTSTRAP SUMMARY")
    print("=" * 70)

    print(
        f"Fetched:          {total_fetched}"
    )

    print(
        f"Processed:        {total_processed}"
    )

    print(
        f"Skipped:          {skipped}"
    )

    print(
        f"Failed:           {failed}"
    )

    print("=" * 70)

    if failed:

        print(
            "Bootstrap stopped because a window failed."
        )

        print(
            "Run the same command again to resume."
        )

    else:

        print(
            "Bootstrap completed successfully."
        )


def parse_args():

    parser = argparse.ArgumentParser(
        description=(
            "Resume-aware historical NVD "
            "vulnerability ingestion."
        )
    )

    parser.add_argument(
        "--start-year",
        type=int,
        required=True,
        help="First year to ingest.",
    )

    parser.add_argument(
        "--end-year",
        type=int,
        required=True,
        help="Last year to ingest.",
    )

    parser.add_argument(
        "--force",
        action="store_true",
        help=(
            "Reprocess already completed "
            "windows."
        ),
    )

    return parser.parse_args()


if __name__ == "__main__":

    args = parse_args()

    asyncio.run(
        bootstrap(
            start_year=args.start_year,
            end_year=args.end_year,
            force=args.force,
        )
    )