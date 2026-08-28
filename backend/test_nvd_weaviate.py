import asyncio
from datetime import datetime, timezone

from app.core.config import settings
from app.ingestion.fetcher.nvd import NVDFetcher
from app.ingestion.normalizer.nvd import NVDNormalizer
from app.embeddings.service import EmbeddingService
from app.vectorstore.weaviate_client import WeaviateClient
from app.vectorstore.vulnerability_writer import (
    VulnerabilityWriter,
)


async def main():

    print("=" * 70)
    print("TEST 2: NVD → WEAVIATE")
    print("=" * 70)

    # --------------------------------------------------
    # Services
    # --------------------------------------------------

    fetcher = NVDFetcher(
        page_size=5
    )

    normalizer = NVDNormalizer()

    embeddings = EmbeddingService(
        settings.EMBEDDING_MODEL
    )

    weaviate = WeaviateClient(
        settings.WEAVIATE_URL,
        settings.WEAVIATE_API_KEY,
    )

    try:

        print("\nChecking Weaviate...")

        if not weaviate.is_ready():
            raise RuntimeError(
                "Weaviate is not ready."
            )

        print("✓ Weaviate ready")

        writer = VulnerabilityWriter(
            weaviate.client,
            settings.WEAVIATE_COLLECTION,
        )

        # --------------------------------------------------
        # Fetch only 5 CVEs
        # --------------------------------------------------

        print("\nFetching 5 CVEs from NVD...")

        raw_records = await fetcher.fetch(
            pub_start=datetime(
                2024,
                1,
                1,
                tzinfo=timezone.utc,
            ),
            pub_end=datetime(
                2024,
                1,
                2,
                tzinfo=timezone.utc,
            ),
        )

        raw_records = raw_records[:5]

        print(
            f"Fetched {len(raw_records)} CVEs"
        )

        # --------------------------------------------------
        # Normalize
        # --------------------------------------------------

        vulnerabilities = []

        for record in raw_records:

            try:

                vulnerability = (
                    normalizer.normalize(
                        record
                    )
                )

                vulnerabilities.append(
                    vulnerability
                )

            except Exception as exc:

                print(
                    f"Normalization failed: {exc}"
                )

        print(
            f"Normalized "
            f"{len(vulnerabilities)} CVEs"
        )

        # --------------------------------------------------
        # Create embedding text
        # --------------------------------------------------

        texts = [
            writer.build_embedding_text(
                vulnerability
            )
            for vulnerability
            in vulnerabilities
        ]

        print(
            "\nGenerating embeddings..."
        )

        vectors = embeddings.embed_batch(
            texts
        )

        print(
            f"Generated {len(vectors)} vectors"
        )

        # --------------------------------------------------
        # Upload
        # --------------------------------------------------

        print(
            "\nUploading to Weaviate..."
        )

        for vulnerability, vector in zip(
            vulnerabilities,
            vectors,
        ):

            object_id = writer.insert(
                vulnerability,
                vector,
            )

            print(
                f"✓ {vulnerability.cve} "
                f"→ {object_id}"
            )

        print("\n" + "=" * 70)
        print("TEST 2 PASSED")
        print("=" * 70)

    finally:

        weaviate.close()


if __name__ == "__main__":
    asyncio.run(main())