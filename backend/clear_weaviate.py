from app.core.config import settings
from app.vectorstore.weaviate_client import WeaviateClient


def main():

    print("Connecting to Weaviate...")

    client = WeaviateClient(
        settings.WEAVIATE_URL,
        settings.WEAVIATE_API_KEY,
    )

    collection = client.client.collections.get(
        settings.WEAVIATE_COLLECTION
    )

    print(
        f"Deleting all objects from: "
        f"{settings.WEAVIATE_COLLECTION}"
    )

    collection.data.delete_many(
        where={
            "path": ["source"],
            "operator": "IsNotNull",
        }
    )

    print("✓ All vulnerability records deleted.")

    client.close()


if __name__ == "__main__":
    main()