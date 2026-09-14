from sqlalchemy import text

from app.database.postgres import engine


def main():
    with engine.begin() as conn:

        result = conn.execute(
            text(
                """
                DELETE FROM ingestion_runs
                WHERE source = 'nvd'
                  AND run_type = 'historical'
                  AND status = 'completed'
                  AND window_end < '2025-01-01'
                  AND records_processed = 0
                """
            )
        )

        print(
            f"Deleted {result.rowcount} "
            f"false NVD checkpoint(s)."
        )


if __name__ == "__main__":
    main()