import asyncio

from app.ingestion.fetcher.nvd import NVDFetcher
from app.ingestion.normalizer.nvd import NVDNormalizer


async def main():

    fetcher = NVDFetcher(
        page_size=20,
    )

    normalizer = NVDNormalizer()

    print("Fetching 5 CVEs from NVD...")

    vulnerabilities = await fetcher.fetch(
        max_records=5,
    )

    print()
    print("Normalizing...")
    print()

    for raw_cve in vulnerabilities:

        normalized = normalizer.normalize(raw_cve)

        print("=" * 70)

        print("CVE:", normalized.cve)

        print("Description:")
        print(normalized.description[:300])

        print()

        print("Vendor:", normalized.vendor)

        print("Product:", normalized.product)

        print("Affected versions:")
        print(normalized.affected_versions)

        print()

        print("CVSS:", normalized.cvss)

        print("CVSS Vector:", normalized.cvss_vector)

        print()

        print("References:", len(normalized.references))

        print("Published:", normalized.published)

        print("Updated:", normalized.updated)


if __name__ == "__main__":
    asyncio.run(main())