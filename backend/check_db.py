from sqlalchemy import text
from app.database.postgres import engine


with engine.connect() as conn:

    # Total vulnerabilities
    total = conn.execute(
        text("SELECT COUNT(*) FROM vulnerabilities")
    ).scalar()

    print(f"TOTAL VULNERABILITIES: {total}")

    # Date coverage
    dates = conn.execute(
        text(
            """
            SELECT MIN(published), MAX(published)
            FROM vulnerabilities
            """
        )
    ).fetchone()

    print(f"MIN PUBLISHED: {dates[0]}")
    print(f"MAX PUBLISHED: {dates[1]}")

    # Ingestion runs
    print("\nINGESTION RUNS:")

    rows = conn.execute(
        text(
            """
            SELECT
                source,
                run_type,
                status,
                COUNT(*) AS runs,
                COALESCE(SUM(records_fetched), 0) AS fetched,
                COALESCE(SUM(records_processed), 0) AS processed
            FROM ingestion_runs
            GROUP BY source, run_type, status
            ORDER BY source, run_type, status
            """
        )
    ).fetchall()

    for row in rows:
        print(
            f"  source={row.source} "
            f"run_type={row.run_type} "
            f"status={row.status} "
            f"runs={row.runs} "
            f"fetched={row.fetched} "
            f"processed={row.processed}"
        )

    # Duplicate check
    duplicates = conn.execute(
        text(
            """
            SELECT COUNT(*)
            FROM (
                SELECT
                    source,
                    vulnerability_id
                FROM vulnerabilities
                GROUP BY source, vulnerability_id
                HAVING COUNT(*) > 1
            ) AS duplicate_groups
            """
        )
    ).scalar()

    print(f"\nDUPLICATE GROUPS: {duplicates}")