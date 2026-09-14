import asyncio
from datetime import datetime, timedelta, timezone
import httpx
from sqlalchemy import text
from app.core.config import settings
from app.database.postgres import engine

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
WINDOW_DAYS = 119

def format_nvd_datetime(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")

def get_db_stats():
    with engine.connect() as conn:
        count_2025 = conn.execute(text(
            "SELECT count(*) FROM vulnerabilities WHERE published >= '2025-01-01' AND published < '2026-01-01'"
        )).scalar()
        
        count_2026 = conn.execute(text(
            "SELECT count(*) FROM vulnerabilities WHERE published >= '2026-01-01'"
        )).scalar()
        
        total_all = conn.execute(text(
            "SELECT count(*) FROM vulnerabilities"
        )).scalar()
        
        latest_published = conn.execute(text(
            "SELECT MAX(published) FROM vulnerabilities"
        )).scalar()
        
        latest_updated = conn.execute(text(
            "SELECT MAX(updated) FROM vulnerabilities"
        )).scalar()

    return {
        "db_2025": count_2025,
        "db_2026": count_2026,
        "total_all": total_all,
        "latest_published": latest_published,
        "latest_updated": latest_updated,
    }

async def fetch_nvd_window_total(client: httpx.AsyncClient, start: datetime, end: datetime, headers: dict) -> int:
    params = {
        "resultsPerPage": 1,
        "startIndex": 0,
        "pubStartDate": format_nvd_datetime(start),
        "pubEndDate": format_nvd_datetime(end),
    }
    
    for attempt in range(1, 4):
        try:
            resp = await client.get(NVD_URL, params=params, headers=headers)
            if resp.status_code == 200:
                data = resp.json()
                return data.get("totalResults", 0)
            elif resp.status_code == 429:
                await asyncio.sleep(2 * attempt)
                continue
            else:
                print(f"Error HTTP {resp.status_code} for window {start.date()} to {end.date()}")
                return 0
        except Exception as exc:
            if attempt == 3:
                print(f"Network error for window {start.date()} to {end.date()}: {exc}")
                return 0
            await asyncio.sleep(2)
    return 0

async def get_nvd_year_total(start_year: int, end_year: int, headers: dict) -> int:
    start_dt = datetime(start_year, 1, 1, tzinfo=timezone.utc)
    if end_year == 2026:
        end_dt = datetime.now(timezone.utc)
    else:
        end_dt = datetime(end_year, 12, 31, 23, 59, 59, tzinfo=timezone.utc)
        
    total_records = 0
    current = start_dt
    
    async with httpx.AsyncClient(timeout=30.0) as client:
        while current < end_dt:
            window_end = min(current + timedelta(days=WINDOW_DAYS), end_dt)
            window_total = await fetch_nvd_window_total(client, current, window_end, headers)
            total_records += window_total
            print(f"  Window {current.date()} -> {window_end.date()}: NVD total = {window_total:,}")
            current = window_end + timedelta(seconds=1)
            await asyncio.sleep(0.6) # respect rate limit
            
    return total_records

async def main():
    headers = {
        "User-Agent": "CyberRAG-Check/1.0",
        "Accept": "application/json",
    }
    if settings.NVD_API_KEY:
        headers["apiKey"] = settings.NVD_API_KEY

    print("=" * 75)
    print("CYBERRAG NVD SYNC STATUS CHECK (2025 - 2026)")
    print("=" * 75)
    
    db_stats = get_db_stats()
    
    print("\nFetching live NVD totals for 2025...")
    nvd_2025 = await get_nvd_year_total(2025, 2025, headers)
    
    print("\nFetching live NVD totals for 2026...")
    nvd_2026 = await get_nvd_year_total(2026, 2026, headers)
    
    print("\n" + "=" * 75)
    print(f"{'YEAR':<8} | {'LOCAL POSTGRES':<16} | {'NVD API (LIVE)':<16} | {'MATCH STATUS':<16}")
    print("-" * 75)
    
    diff_2025 = db_stats['db_2025'] - nvd_2025
    diff_2026 = db_stats['db_2026'] - nvd_2026
    
    status_2025 = "IN SYNC (100%)" if diff_2025 >= 0 else f"MISSING {abs(diff_2025):,}"
    status_2026 = "IN SYNC (100%)" if diff_2026 >= 0 else f"MISSING {abs(diff_2026):,}"
    
    print(f"{'2025':<8} | {db_stats['db_2025']:<16,} | {nvd_2025:<16,} | {status_2025:<16}")
    print(f"{'2026':<8} | {db_stats['db_2026']:<16,} | {nvd_2026:<16,} | {status_2026:<16}")
    print("=" * 75)
    
    print(f"\nTotal Vulnerabilities in PostgreSQL: {db_stats['total_all']:,}")
    print(f"Latest Published CVE in PostgreSQL:   {db_stats['latest_published']}")
    print(f"Latest Updated CVE in PostgreSQL:     {db_stats['latest_updated']}")
    print("=" * 75)
    
    if diff_2025 >= 0 and diff_2026 >= 0:
        print("\nCONCLUSION: Local database is FULLY UP TO DATE with NVD for 2025 and 2026!")
    else:
        print("\nCONCLUSION: Database requires sync for missing records.")

if __name__ == "__main__":
    asyncio.run(main())
