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

    Qdrant is used for semantic similarity.
    PostgreSQL remains the authoritative source for vulnerability records.

    Hydration strategy:
    1. Try PostgreSQL UUID when Qdrant point ID matches.
    2. Fall back to Qdrant payload: source + vulnerability_id.
       This handles cases where Qdrant and PostgreSQL were indexed
       from different database states and therefore have different UUIDs.
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

        # ---------------------------------------------------------
        # 1. Embed query
        # ---------------------------------------------------------
        query_vector = self.embedding_service.embed(query)

        filter_dict = (
            filters.model_dump(exclude_none=True)
            if filters
            else None
        )

        # ---------------------------------------------------------
        # 2. Qdrant semantic search
        # ---------------------------------------------------------
        try:
            scored_points = self.vector_store.search(
                query_vector=query_vector,
                limit=limit * 2,
                filters=filter_dict,
            )

        except Exception as exc:
            logger.warning(
                "Qdrant filtered search exception: %s. "
                "Retrying without vector filter...",
                exc,
            )

            try:
                scored_points = self.vector_store.search(
                    query_vector=query_vector,
                    limit=limit * 4,
                    filters=None,
                )

            except Exception as inner_exc:
                logger.error(
                    "Qdrant semantic search failed: %s",
                    inner_exc,
                )
                return []

        if not scored_points:
            return []

        # ---------------------------------------------------------
        # 3. Extract Qdrant identities
        # ---------------------------------------------------------
        point_scores: dict[UUID, float] = {}

        fallback_payloads: dict[tuple[str, str], float] = {}

        for point in scored_points:
            score = float(point.score)

            payload = point.payload or {}

            # Prefer explicit postgres_id from Qdrant payload.
            postgres_id = payload.get("postgres_id")

            rec_uuid = None

            if postgres_id:
                try:
                    rec_uuid = UUID(str(postgres_id))
                except (ValueError, TypeError):
                    rec_uuid = None

            # If payload does not contain postgres_id,
            # try the Qdrant point ID.
            if rec_uuid is None:
                try:
                    rec_uuid = UUID(str(point.id))
                except (ValueError, TypeError):
                    rec_uuid = None

            if rec_uuid is not None:
                # Keep highest semantic score for duplicate UUIDs.
                previous_score = point_scores.get(rec_uuid)

                if previous_score is None or score > previous_score:
                    point_scores[rec_uuid] = score

            # Always retain stable vulnerability identity as fallback.
            source = payload.get("source")
            vulnerability_id = payload.get("vulnerability_id")

            if source and vulnerability_id:
                key = (
                    str(source),
                    str(vulnerability_id),
                )

                previous_score = fallback_payloads.get(key)

                if previous_score is None or score > previous_score:
                    fallback_payloads[key] = score

        # ---------------------------------------------------------
        # 4. Hydrate from PostgreSQL using UUID
        # ---------------------------------------------------------
        results: list[tuple[Vulnerability, float]] = []

        hydrated_ids: set[UUID] = set()

        if point_scores:
            stmt = select(Vulnerability).where(
                Vulnerability.id.in_(list(point_scores.keys()))
            )

            records = self.db.scalars(stmt).all()

            for rec in records:
                score = point_scores.get(rec.id)

                if score is not None:
                    results.append((rec, score))
                    hydrated_ids.add(rec.id)

        # ---------------------------------------------------------
        # 5. Fallback hydration using source + vulnerability_id
        # ---------------------------------------------------------
        #
        # This is important when Qdrant was indexed from another
        # PostgreSQL database/version and UUIDs do not match.
        #
        if fallback_payloads:

            for (source, vulnerability_id), score in fallback_payloads.items():

                stmt = select(Vulnerability).where(
                    Vulnerability.source == source,
                    Vulnerability.vulnerability_id == vulnerability_id,
                )

                rec = self.db.scalar(stmt)

                if rec is None:
                    # Try CVE directly as an additional stable identity.
                    stmt = select(Vulnerability).where(
                        Vulnerability.vulnerability_id == vulnerability_id
                    )

                    rec = self.db.scalar(stmt)

                if rec is not None:

                    # Avoid adding the same PostgreSQL record twice.
                    if rec.id in hydrated_ids:
                        continue

                    results.append((rec, score))
                    hydrated_ids.add(rec.id)

        # ---------------------------------------------------------
        # 6. Sort by semantic score
        # ---------------------------------------------------------
        results.sort(
            key=lambda x: x[1],
            reverse=True,
        )

        return results[:limit]