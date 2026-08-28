import asyncio

from app.embeddings.service import (
    EmbeddingService,
)

from app.ingestion.fetcher.cisa_kev import (
    CISAKEVFetcher,
)

from app.ingestion.fetcher.github import (
    GitHubAdvisoryFetcher,
)

from app.ingestion.normalizer.cisa_kev import (
    CISAKEVNormalizer,
)

from app.ingestion.normalizer.github import (
    GitHubNormalizer,
)

from app.ingestion.pipeline import (
    VulnerabilityMerger,
)

from app.ingestion.raw_storage import (
    RawStorage,
)

from app.vectorstore.qdrant import (
    QdrantVectorStore,
)

from app.core.config import settings
from app.database import qdrant


async def main():

    # =====================================
    # 1. Initialize services
    # =====================================

    raw_storage = RawStorage()

    embedding_service = (
        EmbeddingService()
    )

    qdrant = QdrantVectorStore(
        url=settings.QDRANT_URL,
        api_key=settings.QDRANT_API_KEY,
        collection_name=(
            settings.QDRANT_COLLECTION
        ),
    )

    # =====================================
    # 2. CISA KEV
    # =====================================

    print(
        "\n[1/2] Fetching CISA KEV..."
    )

    cisa_fetcher = (
        CISAKEVFetcher()
    )

    cisa_records = (
        await cisa_fetcher.fetch()
    )

    print(
        f"CISA records: "
        f"{len(cisa_records)}"
    )

    raw_storage.save(
        "cisa_kev",
        cisa_records,
    )

    cisa_normalizer = (
        CISAKEVNormalizer()
    )

    cisa_normalized = [
        cisa_normalizer.normalize(
            record
        )
        for record in cisa_records
    ]

    # =====================================
    # 3. GitHub
    # =====================================

    print(
        "\n[2/2] Fetching GitHub advisories..."
    )

    github_fetcher = (
        GitHubAdvisoryFetcher()
    )

    github_records = (
        await github_fetcher.fetch(
            max_pages=2
        )
    )

    print(
        f"GitHub records: "
        f"{len(github_records)}"
    )

    raw_storage.save(
        "github",
        github_records,
    )

    github_normalizer = (
        GitHubNormalizer()
    )

    github_normalized = [
        github_normalizer.normalize(
            record
        )
        for record in github_records
    ]

    # =====================================
    # 4. Merge / Deduplicate
    # =====================================

    print(
        "\nMerging vulnerabilities..."
    )

    all_records = (
        cisa_normalized
        + github_normalized
    )

    merger = VulnerabilityMerger()

    unified = merger.merge(
        all_records
    )

    print(
        f"Source records: "
        f"{len(all_records)}"
    )

    print(
        f"Unified records: "
        f"{len(unified)}"
    )

    # =====================================
    # 5. Generate embeddings
    # =====================================

    print(
        "\nGenerating embeddings..."
    )

    batch_size = 100

    total = len(unified)

    print(
        f"\nProcessing {total} "
        f"vulnerabilities in batches of "
        f"{batch_size}..."
    )

    for start in range(
        0,
        total,
        batch_size,
    ):        
        end = min(
            start + batch_size,
            total,
        )

        batch = unified[start:end]

        print(
            f"\n[{start + 1}-{end}/{total}]"
            f" Generating embeddings..."
        )

        embeddings = (
            embedding_service.embed(
                batch,
                batch_size=32,
            )
        )

        print(
            f"Uploading batch "
            f"{start + 1}-{end}..."
        )

        qdrant.upsert(
            embeddings,
            batch,
            max_retries=5,
        )

        print(
            f"✓ Qdrant progress: "
            f"{end}/{total}"
        )

    # =====================================
    # 7. Verify
    # =====================================

    count = qdrant.count()

    print()
    print(
        "================================"
    )

    print(
        "PIPELINE COMPLETE"
    )

    print(
        f"Unified vulnerabilities: "
        f"{len(unified)}"
    )

    print(
        f"Qdrant points: "
        f"{count}"
    )

    print(
        "================================"
    )


if __name__ == "__main__":

    asyncio.run(main())