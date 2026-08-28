from app.core.config import settings
from app.vectorstore.weaviate_client import (
    WeaviateClient,
)


def main():

    print("=" * 70)
    print("TEST 3: READ FROM WEAVIATE")
    print("=" * 70)

    client = WeaviateClient(
        settings.WEAVIATE_URL,
        settings.WEAVIATE_API_KEY,
    )

    try:

        collection = (
            client.client
            .collections
            .get(
                settings.WEAVIATE_COLLECTION
            )
        )

        response = (
            collection.query.fetch_objects(
                limit=10
            )
        )

        print(
            f"\nObjects returned: "
            f"{len(response.objects)}"
        )

        for obj in response.objects:

            properties = obj.properties

            print("\n" + "-" * 60)

            print(
                "CVE:",
                properties.get("cve")
            )

            print(
                "Vendor:",
                properties.get("vendor")
            )

            print(
                "Product:",
                properties.get("product")
            )

            print(
                "CVSS:",
                properties.get("cvss")
            )

            print(
                "Source:",
                properties.get("source")
            )

            print(
                "Description:",
                str(
                    properties.get(
                        "description"
                    )
                )[:150],
                "...",
            )

            print(
                "UUID:",
                obj.uuid
            )

            print(
                "Vector:",
                (
                    "YES"
                    if obj.vector
                    else "NO"
                )
            )

        print("\n" + "=" * 70)

        if len(response.objects) > 0:
            print("TEST 3 PASSED")
        else:
            print("TEST 3 FAILED")

        print("=" * 70)

    finally:

        client.close()


if __name__ == "__main__":
    main()