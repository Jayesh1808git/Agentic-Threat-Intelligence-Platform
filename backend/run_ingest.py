import asyncio
from datetime import datetime, timedelta, timezone

from app.core.config import settings
from app.ingestion.sources.nvd import NVDSource


async def main():

    end = datetime.now(
        timezone.utc
    )

    start = (
        end - timedelta(days=1)
    )

    print("=" * 70)
    print("NVD STREAM TEST")
    print("=" * 70)

    print(
        f"Start: {start}"
    )

    print(
        f"End:   {end}"
    )

    source = NVDSource(
        settings.NVD_API_KEY
    )

    total = 0
    pages = 0

    async for page in source.fetch_window(
        start,
        end,
    ):

        pages += 1
        total += len(page)

        print(
            f"Received page {pages}: "
            f"{len(page)} records"
        )

    print()
    print("=" * 70)
    print("STREAM TEST COMPLETE")
    print("=" * 70)

    print(
        f"Pages:  {pages}"
    )

    print(
        f"Total:  {total}"
    )


if __name__ == "__main__":
    asyncio.run(main())