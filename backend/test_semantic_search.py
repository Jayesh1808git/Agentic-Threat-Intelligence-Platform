from app.core.config import settings
from app.embeddings.service import EmbeddingService
from app.vectorstore.weaviate_client import (
    WeaviateClient,
)


def main():

    print("=" * 70)
    print("TEST 4: SEMANTIC SEARCH")
    print("=" * 70)

    client = WeaviateClient(
        settings.WEAVIATE_URL,
        settings.WEAVIATE_API_KEY,
    )

    embeddings = EmbeddingService(
        settings.EMBEDDING_MODEL
    )

    try:

        collection = (
            client.client
            .collections
            .get(
                settings.WEAVIATE_COLLECTION
            )
        )

        query = (
            "remote code execution "
            "vulnerability in a web application"
        )

        print(
            f"\nQuery:\n{query}\n"
        )

        query_vector = embeddings.embed(
            query
        )

        response = (
            collection.query.near_vector(
                near_vector=query_vector,
                limit=5,
                return_metadata=[
                    "distance"
                ],
            )
        )

        print(
            "Semantic search results:"
        )

        for index, obj in enumerate(
            response.objects,
            start=1,
        ):

            properties = obj.properties

            print(
                f"\n{index}. "
                f"{properties.get('cve')}"
            )

            print(
                "Product:",
                properties.get(
                    "product"
                ),
            )

            print(
                "CVSS:",
                properties.get(
                    "cvss"
                ),
            )

            print(
                "Distance:",
                obj.metadata.distance,
            )

            print(
                "Description:",
                str(
                    properties.get(
                        "description"
                    )
                )[:200],
                "...",
            )

        print("\n" + "=" * 70)
        print("TEST 4 COMPLETE")
        print("=" * 70)

    finally:

        client.close()


if __name__ == "__main__":
    main()