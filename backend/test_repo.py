import asyncio

from app.database.postgres import SessionLocal
from app.ingestion.fetcher.nvd import NVDFetcher
from app.ingestion.normalizer.nvd import NVDNormalizer
from app.repositories.vulnerability import VulnerabilityRepository


async def main():

    print("Fetching NVD data...")

    fetcher = NVDFetcher(
        page_size=20,
    )

    raw_vulnerabilities = await fetcher.fetch(
        max_records=5,
    )

    print(
        f"Fetched {len(raw_vulnerabilities)} CVEs"
    )

    normalizer = NVDNormalizer()

    normalized_vulnerabilities = []

    for raw_cve in raw_vulnerabilities:

        normalized = normalizer.normalize(
            raw_cve
        )

        normalized_vulnerabilities.append(
            normalized
        )

    print(
        f"Normalized "
        f"{len(normalized_vulnerabilities)} CVEs"
    )

    db = SessionLocal()

    try:

        repository = VulnerabilityRepository(
            db
        )

        inserted = repository.bulk_upsert(
            normalized_vulnerabilities
        )

        print(
            f"Stored {inserted} vulnerabilities "
            f"in Neon PostgreSQL"
        )

        print(
            "Total vulnerabilities in database:",
            repository.count(),
        )

    finally:

        db.close()


if __name__ == "__main__":
    asyncio.run(main())