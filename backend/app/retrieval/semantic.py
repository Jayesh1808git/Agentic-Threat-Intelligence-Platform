import logging
from uuid import UUID
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.embeddings.service import EmbeddingService
from app.models.vulnerability import Vulnerability
from indexing.qdrant import QdrantVectorStore
from app.retrieval.schemas import RetrievalFilters

logger = logging.getLogger("semantic_retriever")


class SemanticRetriever:
    """
    Qdrant-based dense semantic similarity search with PostgreSQL hydration.
    """

    def __init__(self, db: Session):
        self.db = db
        self.embedding_service = EmbeddingService(settings.EMBEDDING_MODEL)
        self.vector_store = QdrantVectorStore()

    def search(
        self,
        query: str,
        filters: RetrievalFilters | None = None,
        limit: int = 20,
    ) -> list[tuple[Vulnerability, float]]:
        if not query or not query.strip():
            return []

        # 1. Embed query
        query_vector = self.embedding_service.embed(query)

        filter_dict = filters.model_dump(exclude_none=True) if filters else None

        # 2. Qdrant similarity search
        try:
            scored_points = self.vector_store.search(
                query_vector=query_vector,
                limit=limit * 2, # fetch extra to allow for PostgreSQL hydration & deduplication
                filters=filter_dict,
            )
        except Exception as exc:
            logger.warning("Qdrant filtered search exception: %s. Retrying without vector filter...", exc)
            try:
                scored_points = self.vector_store.search(
                    query_vector=query_vector,
                    limit=limit * 4,
                    filters=None,
                )
            except Exception as inner_exc:
                logger.error("Qdrant semantic search failed: %s", inner_exc)
                return []

        if not scored_points:
            return []

        # 3. Map point IDs / payload to PostgreSQL UUIDs
        point_scores: dict[UUID, float] = {}
        fallback_payloads: dict[tuple[str, str], float] = {}

        for point in scored_points:
            score = float(point.score)
            # Try point.id as UUID
            rec_uuid = None
            try:
                rec_uuid = UUID(str(point.id))
            except (ValueError, TypeError):
                pass

            if rec_uuid is not None:
                if rec_uuid not in point_scores:
                    point_scores[rec_uuid] = score
            else:
                payload = point.payload or {}
                src = payload.get("source")
                vuln_id = payload.get("vulnerability_id")
                if src and vuln_id:
                    fallback_payloads[(src, vuln_id)] = score

        # 4. Hydrate authoritative records from PostgreSQL
        results: list[tuple[Vulnerability, float]] = []

        if point_scores:
            stmt = select(Vulnerability).where(Vulnerability.id.in_(list(point_scores.keys())))
            records = self.db.scalars(stmt).all()
            for rec in records:
                score = point_scores.get(rec.id, 0.0)
                results.append((rec, score))

        if fallback_payloads:
            for (src, vuln_id), score in fallback_payloads.items():
                stmt = select(Vulnerability).where(
                    Vulnerability.source == src,
                    Vulnerability.vulnerability_id == vuln_id,
                )
                rec = self.db.scalar(stmt)
                if rec:
                    results.append((rec, score))

        # Sort by score descending
        results.sort(key=lambda x: x[1], reverse=True)
        return results[:limit]
