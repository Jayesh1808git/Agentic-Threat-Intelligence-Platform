import argparse
import asyncio
import json
import logging
import sys

from app.ingestion.incremental import IncrementalIngestionOrchestrator

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)

logger = logging.getLogger("run_incremental_ingest")


async def main():
    parser = argparse.ArgumentParser(description="One-shot Incremental Threat Intelligence Ingestion")
    parser.add_argument("--nvd-hours", type=int, default=6, help="Lookback hours for modified NVD CVEs (default: 6)")
    parser.add_argument("--github-pages", type=int, default=3, help="Max pages for GitHub Advisories (default: 3)")
    parser.add_argument("--osv-records", type=int, default=500, help="Max records for OSV (default: 500)")
    parser.add_argument(
    "--nvd-overlap-minutes",
    type=int,
    default=10,
    help="Minutes to overlap the previous NVD watermark.",
)

    args = parser.parse_args()

    orchestrator = IncrementalIngestionOrchestrator()
    summary = await orchestrator.run_all_incremental(
    nvd_lookback_hours=args.nvd_hours,
    github_max_pages=args.github_pages,
    osv_max_records=args.osv_records,
    nvd_overlap_minutes=args.nvd_overlap_minutes,
)

    print("\n" + "=" * 75)
    print("INCREMENTAL INGESTION SUMMARY")
    print("=" * 75)
    print(json.dumps(summary, indent=2))
    print("=" * 75)


if __name__ == "__main__":
    asyncio.run(main())
