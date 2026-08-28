# reset_weaviate.py

from app.vectorstore.weaviate_client import WeaviateClient
from app.core.config import Settings


def main():
    client_wrapper = WeaviateClient()
    client = client_wrapper.client

    collection_name = Settings().WEAVIATE_COLLECTION

    print(f"Checking collection: {collection_name}")

    if client.collections.exists(collection_name):
        print(f"Deleting {collection_name}...")
        client.collections.delete(collection_name)
        print("✓ Collection deleted")
    else:
        print("Collection does not exist")

    client_wrapper.close()


if __name__ == "__main__":
    main()