import argparse
import asyncio
import logging
import sys

from app.ingestion.service import (
    CISAIngestionService,
    EPSSIngestionService,
    GitHubIngestionService,
    OSVIngestionService,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)

logger = logging.getLogger("run_multi_source_ingest")


async def run_cisa():
    print("\n" + "=" * 70)
    print("RUNNING CISA KEV INGESTION")
    print("=" * 70)
    service = CISAIngestionService()
    result = await service.ingest()
    print(f"CISA KEV result: {result}")


async def run_epss():
    print("\n" + "=" * 70)
    print("RUNNING EPSS BULK INGESTION")
    print("=" * 70)
    service = EPSSIngestionService()
    result = await service.ingest_bulk()
    print(f"EPSS result: {result}")


async def run_github(max_pages: int = 10):
    print("\n" + "=" * 70)
    print(f"RUNNING GITHUB ADVISORIES INGESTION (max_pages={max_pages})")
    print("=" * 70)
    service = GitHubIngestionService()
    result = await service.ingest(max_pages=max_pages)
    print(f"GitHub Advisories result: {result}")


async def run_osv(max_records: int | None = None):
    print("\n" + "=" * 70)
    print(f"RUNNING OSV INGESTION (max_records={max_records})")
    print("=" * 70)
    service = OSVIngestionService()
    result = await service.ingest(max_records=max_records)
    print(f"OSV result: {result}")


async def main():
    parser = argparse.ArgumentParser(description="Multi-Source Threat Intelligence Ingestion")
    parser.add_argument("--cisa", action="store_true", help="Ingest CISA Known Exploited Vulnerabilities")
    parser.add_argument("--epss", action="store_true", help="Ingest/Update EPSS scores from Cyentia CSV")
    parser.add_argument("--github", action="store_true", help="Ingest GitHub Advisories")
    parser.add_argument("--osv", action="store_true", help="Ingest OSV vulnerabilities database")
    parser.add_argument("--all", action="store_true", help="Run all secondary sources (CISA, EPSS, GitHub, OSV)")
    parser.add_argument("--github-max-pages", type=int, default=5, help="Maximum pages for GitHub Advisories (default: 5)")
    parser.add_argument("--osv-max-records", type=int, default=1000, help="Maximum records for OSV (default: 1000, 0 for all)")

    args = parser.parse_args()

    # If no flags specified, run all
    if not (args.cisa or args.epss or args.github or args.osv or args.all):
        args.all = True

    osv_limit = None if args.osv_max_records == 0 else args.osv_max_records

    if args.cisa or args.all:
        try:
            await run_cisa()
        except Exception as exc:
            logger.error("CISA ingestion failed: %s", exc)

    if args.epss or args.all:
        try:
            await run_epss()
        except Exception as exc:
            logger.error("EPSS ingestion failed: %s", exc)

    if args.github or args.all:
        try:
            await run_github(max_pages=args.github_max_pages)
        except Exception as exc:
            logger.error("GitHub ingestion failed: %s", exc)

    if args.osv or args.all:
        try:
            await run_osv(max_records=osv_limit)
        except Exception as exc:
            logger.error("OSV ingestion failed: %s", exc)


if __name__ == "__main__":
    asyncio.run(main())
