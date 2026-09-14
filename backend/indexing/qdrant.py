from qdrant_client import QdrantClient
from qdrant_client.http import models

from app.core.config import settings


class QdrantVectorStore:

    def __init__(self):

        if settings.QDRANT_API_KEY:

            self.client = QdrantClient(
                url=settings.QDRANT_URL,
                api_key=settings.QDRANT_API_KEY,
            )

        else:

            self.client = QdrantClient(
                url=settings.QDRANT_URL,
            )

        self.collection_name = (
            settings.QDRANT_COLLECTION
        )

    def ensure_collection(
        self,
        vector_size: int,
    ) -> None:

        collections = (
            self.client.get_collections()
        )

        names = {
            collection.name
            for collection in collections.collections
        }

        if self.collection_name in names:
            return

        self.client.create_collection(
            collection_name=self.collection_name,
            vectors_config=models.VectorParams(
                size=vector_size,
                distance=models.Distance.COSINE,
            ),
        )

    def upsert(
        self,
        record,
        vector: list[float],
    ) -> None:

        self.ensure_collection(
            len(vector)
        )

        point = models.PointStruct(
            id=str(record.id),
            vector=vector,
            payload={
                "source": record.source,
                "vulnerability_id": (
                    record.vulnerability_id
                ),
                "cve": record.cve or "",
                "vendor": record.vendor or "",
                "product": record.product or "",
            },
        )

        self.client.upsert(
            collection_name=self.collection_name,
            points=[point],
            wait=True,
        )

    def close(self) -> None:

        close_method = getattr(
            self.client,
            "close",
            None,
        )

        if close_method:
            close_method()