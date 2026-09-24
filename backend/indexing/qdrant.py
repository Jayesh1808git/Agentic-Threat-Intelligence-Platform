from typing import Any
from qdrant_client import QdrantClient
from qdrant_client.http import models

from app.core.config import settings
from app.database.qdrant import get_qdrant_client


class QdrantVectorStore:

    def __init__(self):
        self.client: QdrantClient = get_qdrant_client()
        self.collection_name: str = settings.QDRANT_COLLECTION

    def ensure_payload_indexes(self) -> None:
        payload_fields = [
            ("vendor", models.PayloadSchemaType.KEYWORD),
            ("product", models.PayloadSchemaType.KEYWORD),
            ("source", models.PayloadSchemaType.KEYWORD),
            ("kev", models.PayloadSchemaType.BOOL),
            ("exploit_available", models.PayloadSchemaType.BOOL),
        ]
        for field_name, schema_type in payload_fields:
            try:
                self.client.create_payload_index(
                    collection_name=self.collection_name,
                    field_name=field_name,
                    field_schema=schema_type,
                    wait=False,
                )
            except Exception:
                pass

    def ensure_collection(self, vector_size: int) -> None:
        try:
            collections = self.client.get_collections()
            names = {c.name for c in collections.collections}

            if self.collection_name not in names:
                self.client.create_collection(
                    collection_name=self.collection_name,
                    vectors_config=models.VectorParams(
                        size=vector_size,
                        distance=models.Distance.COSINE,
                    ),
                )
                print(f"Created Qdrant collection '{self.collection_name}' with size {vector_size}.")

            self.ensure_payload_indexes()
        except Exception as exc:
            print(f"Error ensuring Qdrant collection: {exc}")
            raise

    def build_payload(self, record: Any) -> dict[str, Any]:
        return {
            "postgres_id": str(record.id),
            "source": record.source,
            "vulnerability_id": record.vulnerability_id,
            "cve": record.cve or "",
            "vendor": record.vendor or "",
            "product": record.product or "",
            "title": record.title or "",
            "cvss": record.cvss,
            "epss": record.epss,
            "kev": bool(record.kev),
            "exploit_available": bool(record.exploit_available),
            "content_hash": record.content_hash or "",
        }

    def upsert_batch(
        self,
        records_and_vectors: list[tuple[Any, list[float]]],
    ) -> int:
        if not records_and_vectors:
            return 0

        vector_size = len(records_and_vectors[0][1])
        self.ensure_collection(vector_size)

        points = []
        for record, vector in records_and_vectors:
            point_id = str(record.id)  # Deterministic UUID string from PostgreSQL
            payload = self.build_payload(record)
            points.append(
                models.PointStruct(
                    id=point_id,
                    vector=vector,
                    payload=payload,
                )
            )

        import time
        max_retries = 3
        for attempt in range(1, max_retries + 1):
            try:
                self.client.upsert(
                    collection_name=self.collection_name,
                    points=points,
                    wait=True,
                )
                return len(points)
            except Exception as exc:
                if attempt == max_retries:
                    raise
                print(f"Warning: Qdrant batch upsert attempt {attempt} failed ({exc}). Retrying in {attempt}s...")
                time.sleep(attempt)
        return len(points)

    def upsert(self, record: Any, vector: list[float]) -> None:
        self.upsert_batch([(record, vector)])

    def search(
        self,
        query_vector: list[float],
        limit: int = 20,
        filters: dict[str, Any] | None = None,
    ) -> list[models.ScoredPoint]:
        self.ensure_collection(len(query_vector))

        qdrant_filter = None
        if filters:
            conditions = []
            if filters.get("vendor"):
                conditions.append(
                    models.FieldCondition(
                        key="vendor",
                        match=models.MatchValue(value=filters["vendor"].lower()),
                    )
                )
            if filters.get("product"):
                conditions.append(
                    models.FieldCondition(
                        key="product",
                        match=models.MatchValue(value=filters["product"].lower()),
                    )
                )
            if filters.get("source"):
                conditions.append(
                    models.FieldCondition(
                        key="source",
                        match=models.MatchValue(value=filters["source"]),
                    )
                )
            if filters.get("kev") is not None:
                conditions.append(
                    models.FieldCondition(
                        key="kev",
                        match=models.MatchValue(value=bool(filters["kev"])),
                    )
                )
            if filters.get("exploit_available") is not None:
                conditions.append(
                    models.FieldCondition(
                        key="exploit_available",
                        match=models.MatchValue(value=bool(filters["exploit_available"])),
                    )
                )

            if conditions:
                qdrant_filter = models.Filter(must=conditions)

        # qdrant_client version query compatibility
        if hasattr(self.client, "query_points"):
            res = self.client.query_points(
                collection_name=self.collection_name,
                query=query_vector,
                query_filter=qdrant_filter,
                limit=limit,
                with_payload=True,
            )
            return res.points
        else:
            return self.client.search(
                collection_name=self.collection_name,
                query_vector=query_vector,
                query_filter=qdrant_filter,
                limit=limit,
                with_payload=True,
            )

    def count(self) -> int:
        try:
            res = self.client.get_collection(self.collection_name)
            return res.points_count or 0
        except Exception:
            return 0

    def close(self) -> None:
        close_method = getattr(self.client, "close", None)
        if close_method:
            close_method()