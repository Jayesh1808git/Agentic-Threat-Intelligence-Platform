from sqlalchemy import text
from app.database.postgres import engine

def clear_nvd_checkpoints():
    with engine.begin() as conn:
        result = conn.execute(
            text(
                """
                DELETE FROM ingestion_runs
                WHERE UPPER(source) = 'NVD'
                  AND run_type = 'historical';
                """
            )
        )
        print(f"Cleared {result.rowcount} NVD historical checkpoint(s) from database.")

if __name__ == "__main__":
    clear_nvd_checkpoints()
