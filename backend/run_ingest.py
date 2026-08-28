import asyncio

from app.ingestion.bulk_ingestion import (
    BulkIngestion,
)


async def main():

    ingestion = BulkIngestion()

    await ingestion.run(
        nvd=True,
        osv=True,
        github=True,
        cisa=True,
        epss=True,
    )


if __name__ == "__main__":

    asyncio.run(main())