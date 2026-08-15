from datetime import datetime, timezone
from pdb import run

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.ingestion import IngestionRun


class CheckpointManager:

    def __init__(self, db: Session):
        self.db = db

    def start_run(
        self,
        source: str,
        run_type: str,
        window_start: datetime,
        window_end: datetime,
    ) -> IngestionRun:

        run = IngestionRun(
            source=source,
            run_type=run_type,
            window_start=window_start,
            window_end=window_end,
            status="running",
            started_at=datetime.now(timezone.utc),
        )

        self.db.add(run)
        self.db.commit()
        self.db.refresh(run)

        return run

    def complete_run(
        self,
        run: IngestionRun,
        records_fetched: int,
        records_processed: int,
    ) -> None:

        run.status = "completed"

        run.records_fetched = records_fetched

        run.records_processed = records_processed

        run.completed_at = datetime.now(timezone.utc)

        self.db.commit()

    def fail_run(
    self,
    run: IngestionRun,
    error_message: str,
    ) -> None:

        try:
            run.status = "failed"
            run.error_message = error_message
            run.completed_at = datetime.now(timezone.utc)

            self.db.commit()

        except Exception as exc:
            # The database connection itself may be dead.
            # Do not allow checkpoint failure to hide
            # the original ingestion error.
            print(
                f"WARNING: Could not update failed "
                f"checkpoint: {exc}"
            )

            try:
                self.db.rollback()
            except Exception:
                pass
    def get_completed_windows(
        self,
        source: str,
        run_type: str,
        ) -> list[IngestionRun]:
        stmt = (
            select(IngestionRun)
            .where(
                IngestionRun.source == source,
                IngestionRun.run_type == run_type,
                IngestionRun.status == "completed",
            )
            .order_by(
                IngestionRun.window_start.asc()
            )
        )

        result = self.db.execute(stmt)

        return list(result.scalars().all())

    def last_successful_window(
        self,
        source: str,
        run_type: str,
    ) -> datetime | None:

        stmt = (
            select(IngestionRun)
            .where(
                IngestionRun.source == source,
                IngestionRun.run_type == run_type,
                IngestionRun.status == "completed",
            )
            .order_by(
                IngestionRun.window_end.desc()
            )
            .limit(1)
        )

        result = self.db.execute(stmt)

        run = result.scalar_one_or_none()

        if not run:
            return None

        return run.window_end