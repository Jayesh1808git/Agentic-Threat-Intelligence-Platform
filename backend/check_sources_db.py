from sqlalchemy import text
from app.database.postgres import engine


def check_sources_db():
    print("=" * 75)
    print("POSTGRESQL MULTI-SOURCE DATABASE BREAKDOWN")
    print("=" * 75)

    with engine.connect() as conn:
        # Total counts by source
        sources_summary = conn.execute(text(
            "SELECT source, COUNT(*) as count FROM vulnerabilities GROUP BY source ORDER BY count DESC"
        )).fetchall()

        # KEV count
        kev_count = conn.execute(text(
            "SELECT COUNT(*) FROM vulnerabilities WHERE kev = TRUE"
        )).scalar()

        # EPSS count
        epss_count = conn.execute(text(
            "SELECT COUNT(*) FROM vulnerabilities WHERE epss IS NOT NULL"
        )).scalar()

        # Total vulnerabilities
        total_count = conn.execute(text(
            "SELECT COUNT(*) FROM vulnerabilities"
        )).scalar()

        # Latest ingestion runs summary
        ingestion_runs = conn.execute(text(
            "SELECT source, run_type, status, records_fetched, records_processed, started_at, completed_at "
            "FROM ingestion_runs ORDER BY id DESC LIMIT 10"
        )).fetchall()

    print("\n[Vulnerabilities by Source]")
    print(f"{'SOURCE':<15} | {'COUNT':<15}")
    print("-" * 35)
    for row in sources_summary:
        print(f"{row[0]:<15} | {row[1]:<15,}")
    print("-" * 35)
    print(f"{'TOTAL':<15} | {total_count:<15,}")

    print("\n[Risk Metrics Coverage]")
    print(f"Known Exploited Vulnerabilities (KEV=True): {kev_count:,}")
    print(f"Vulnerabilities with EPSS Scores:           {epss_count:,} ({(epss_count / (total_count or 1)) * 100:.1f}%)")

    print("\n[Recent Ingestion Runs]")
    print(f"{'SOURCE':<10} | {'TYPE':<15} | {'STATUS':<10} | {'FETCHED':<10} | {'PROCESSED':<10}")
    print("-" * 65)
    for run in ingestion_runs:
        print(f"{run[0]:<10} | {run[1]:<15} | {run[2]:<10} | {run[3]:<10,} | {run[4]:<10,}")
    print("=" * 75)


if __name__ == "__main__":
    check_sources_db()
