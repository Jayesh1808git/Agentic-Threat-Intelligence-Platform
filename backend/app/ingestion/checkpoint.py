from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.ingestion import IngestionRun


class CheckpointManager:
    """
    PostgreSQL-backed ingestion checkpoint manager.

    A window is considered complete only after the corresponding
    ingestion has successfully committed its vulnerability records.
    """

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
            records_fetched=0,
            records_processed=0,
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
            print(
                "WARNING: Could not update failed "
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
        statement = (
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

        return list(
            self.db.scalars(statement).all()
        )

    def last_successful_window(
        self,
        source: str,
        run_type: str,
    ) -> datetime | None:
        statement = (
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

        run = self.db.scalar(statement)

        if run is None:
            return None

        return run.window_end