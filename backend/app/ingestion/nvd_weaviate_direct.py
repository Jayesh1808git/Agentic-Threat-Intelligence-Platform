from __future__ import annotations

import json
from datetime import datetime

from app.core.config import settings
from app.embeddings.service import EmbeddingService
from app.ingestion.fetcher.nvd import NVDFetcher
from app.ingestion.normalizers.nvd import NVDNormalizer
from app.vectorstore.schema import (
    create_vulnerability_collection,
)
from app.vectorstore.weaviate_client import (
    WeaviateClient,
)


def serialize(value):

    if value is None:
        return []

    if isinstance(value, list):
        return value

    return []


def datetime_to_iso(value):

    if value is None:
        return None

    if isinstance(value, datetime):

        if value.tzinfo is None:
            return value.astimezone()

        return value.isoformat()

    return str(value)


def build_properties(
    vulnerability,
):

    return {

        "cve":
            vulnerability.cve or "",

        "vulnerability_id":
            vulnerability.vulnerability_id,

        "title":
            vulnerability.title or "",

        "description":
            vulnerability.description or "",

        "vendor":
            vulnerability.vendor or "",

        "product":
            vulnerability.product or "",

        "affected_versions":
            serialize(
                vulnerability.affected_versions
            ),

        "patched_versions":
            serialize(
                vulnerability.patched_versions
            ),

        "cvss":
            vulnerability.cvss,

        "cvss_vector":
            vulnerability.cvss_vector or "",

        "epss":
            vulnerability.epss,

        "kev":
            bool(vulnerability.kev),

        "exploit_available":
            bool(
                vulnerability.exploit_available
            ),

        "source":
            vulnerability.source,

        "published":
            datetime_to_iso(
                vulnerability.published
            ),

        "updated":
            datetime_to_iso(
                vulnerability.updated
            ),

        "cpe_matches":
            json.dumps(
                vulnerability.cpe_matches,
                default=str,
            ),

        "references":
            serialize(
                vulnerability.references
            ),
    }


async def ingest_nvd_window(
    start_date,
    end_date,
):

    print()
    print("=" * 70)
    print("NVD → WEAVIATE DIRECT INGESTION")
    print("=" * 70)

    # --------------------------------------------------
    # Services
    # --------------------------------------------------

    fetcher = NVDFetcher(
        page_size=500
    )

    normalizer = NVDNormalizer()

    embeddings = EmbeddingService(
        settings.EMBEDDING_MODEL
    )

    weaviate_client = WeaviateClient(
        settings.WEAVIATE_URL,
        settings.WEAVIATE_API_KEY,
    )

    try:

        if not weaviate_client.is_ready():

            raise RuntimeError(
                "Weaviate is not ready."
            )

        create_vulnerability_collection(
            weaviate_client.client,
            settings.WEAVIATE_COLLECTION,
        )

        collection = (
            weaviate_client.client
            .collections
            .get(
                settings.WEAVIATE_COLLECTION
            )
        )

        # --------------------------------------------------
        # Fetch NVD
        # --------------------------------------------------

        raw_records = await fetcher.fetch(
            pub_start=start_date,
            pub_end=end_date,
        )

        print(
            f"Fetched: {len(raw_records)}"
        )

        # --------------------------------------------------
        # Normalize
        # --------------------------------------------------

        normalized = []

        for raw in raw_records:

            try:

                vulnerability = (
                    normalizer.normalize(raw)
                )

                normalized.append(
                    vulnerability
                )

            except Exception as exc:

                print(
                    f"Normalization failed: "
                    f"{exc}"
                )

        print(
            f"Normalized: {len(normalized)}"
        )

        # --------------------------------------------------
        # Embed + upload
        # --------------------------------------------------

        embedding_batch_size = 32

        for start in range(
            0,
            len(normalized),
            embedding_batch_size,
        ):

            batch = normalized[
                start:
                start + embedding_batch_size
            ]

            texts = [
                embeddings.build_text(
                    vulnerability
                )
                for vulnerability in batch
            ]

            vectors = (
                embeddings.embed_batch(
                    texts
                )
            )

            with collection.batch.dynamic() as wb:

                for vulnerability, vector in zip(
                    batch,
                    vectors,
                ):

                    wb.add_object(
                        properties=(
                            build_properties(
                                vulnerability
                            )
                        ),
                        vector=vector,
                    )

            print(
                f"Weaviate progress: "
                f"{min(start + len(batch), len(normalized))}"
                f"/{len(normalized)}"
            )

    finally:

        weaviate_client.close()

    print()
    print(
        "NVD window successfully ingested "
        "into Weaviate."
    )