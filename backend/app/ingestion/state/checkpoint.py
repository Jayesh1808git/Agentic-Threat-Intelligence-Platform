from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.ingestion import IngestionRun


class CheckpointManager:

    def __init__(self, db: Session):
        self.db = db

    # ============================================================
    # START
    # ============================================================

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
            records_fetched=0,
            records_processed=0,
            started_at=datetime.now(timezone.utc),
        )

        self.db.add(run)
        self.db.commit()
        self.db.refresh(run)

        return run

    # ============================================================
    # COMPLETE
    # ============================================================

    def complete_run(
        self,
        run: IngestionRun,
        records_fetched: int,
        records_processed: int,
    ) -> None:

        run.status = "completed"

        run.records_fetched = records_fetched

        run.records_processed = records_processed

        run.completed_at = datetime.now(
            timezone.utc
        )

        self.db.commit()

    # ============================================================
    # FAIL
    # ============================================================

    def fail_run(
        self,
        run: IngestionRun,
        error_message: str,
    ) -> None:

        try:

            run.status = "failed"

            run.error_message = (
                error_message[:5000]
            )

            run.completed_at = datetime.now(
                timezone.utc
            )

            self.db.commit()

        except Exception as exc:

            print(
                "WARNING: Could not update "
                f"failed checkpoint: {exc}"
            )

            try:
                self.db.rollback()
            except Exception:
                pass

    # ============================================================
    # COMPLETED WINDOWS
    # ============================================================

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
            self.db.scalars(
                statement
            ).all()
        )

    # ============================================================
    # CHECK EXACT WINDOW
    # ============================================================

    def is_window_completed(
        self,
        source: str,
        run_type: str,
        window_start: datetime,
        window_end: datetime,
    ) -> bool:

        statement = (
            select(IngestionRun.id)
            .where(
                IngestionRun.source == source,
                IngestionRun.run_type == run_type,
                IngestionRun.status == "completed",
                IngestionRun.window_start
                == window_start,
                IngestionRun.window_end
                == window_end,
            )
            .limit(1)
        )

        return (
            self.db.scalar(statement)
            is not None
        )

    # ============================================================
    # LAST SUCCESSFUL WINDOW
    # ============================================================

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