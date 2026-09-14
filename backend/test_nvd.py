import asyncio
from datetime import datetime, timedelta, timezone

from app.core.config import Settings
from app.database.postgres import SessionLocal
from app.ingestion.hash import vulnerability_content_hash
from app.ingestion.normalizer.nvd import NVDNormalizer
from app.ingestion.sources.nvd import NVDSource
from app.repositories.vulnerability import (
    VulnerabilityRepository,
)


async def main():
    print("=" * 70)
    print("NVD → NEON TEST")
    print("=" * 70)

    end = datetime.now(timezone.utc)
    start = end - timedelta(days=1)

    print(f"Start: {start}")
    print(f"End:   {end}")

    source = NVDSource(
        Settings().NVD_API_KEY or None
    )

    normalizer = NVDNormalizer()

    fetched = 0
    inserted = 0
    updated = 0
    unchanged = 0
    failed = 0

    async for page in source.fetch_window(
        start,
        end,
    ):
        print(
            f"\nReceived page with "
            f"{len(page)} records"
        )

        fetched += len(page)

        db = SessionLocal()

        try:
            repository = VulnerabilityRepository(db)

            for raw_record in page:
                try:
                    vulnerability = (
                        normalizer.normalize(
                            raw_record
                        )
                    )

                    content_hash = (
                        vulnerability_content_hash(
                            vulnerability
                        )
                    )

                    (
                        _record,
                        was_inserted,
                        semantic_changed,
                    ) = repository.upsert(
                        vulnerability,
                        content_hash,
                    )

                    if was_inserted:
                        inserted += 1

                    elif semantic_changed:
                        updated += 1

                    else:
                        unchanged += 1

                except Exception as exc:
                    failed += 1

                    cve_id = (
                        raw_record
                        .get("cve", {})
                        .get("id", "UNKNOWN")
                    )

                    print(
                        f"ERROR {cve_id}: {exc}"
                    )

            db.commit()

        except Exception:
            db.rollback()
            raise

        finally:
            db.close()

    print()
    print("=" * 70)
    print("TEST COMPLETE")
    print("=" * 70)

    print(f"Fetched:   {fetched}")
    print(f"Inserted:  {inserted}")
    print(f"Updated:   {updated}")
    print(f"Unchanged: {unchanged}")
    print(f"Failed:    {failed}")


if __name__ == "__main__":
    asyncio.run(main())