import logging
from typing import Any
from sqlalchemy.orm import Session

from app.retrieval.schemas import (
    NormalizedVulnerabilityResult,
    RetrievalFilters,
    RetrievalResponse,
)
from app.retrieval.lexical import LexicalRetriever
from app.retrieval.semantic import SemanticRetriever
from app.retrieval.fusion import rrf_fusion

logger = logging.getLogger("retrieval_service")


class VulnerabilityRetriever:
    """
    Unified Hybrid Retrieval Subsystem.

    Combines:
    - PostgreSQL Lexical/Structured search (lexical.py)
    - Qdrant Semantic Similarity search (semantic.py)
    - Reciprocal Rank Fusion & Exact CVE override (fusion.py)

    Exposes Python interface for future LangGraph agents and HTTP API.
    """

    def __init__(self, db: Session):
        self.db = db
        self.lexical_retriever = LexicalRetriever(db)
        self.semantic_retriever = SemanticRetriever(db)

    def retrieve(
        self,
        query: str,
        vendor: str | None = None,
        product: str | None = None,
        severity: float | None = None,
        source: str | None = None,
        kev: bool | None = None,
        exploit_available: bool | None = None,
        filters: RetrievalFilters | None = None,
        limit: int = 20,
    ) -> list[NormalizedVulnerabilityResult]:
        """
        Public Python method for retrieving relevant vulnerabilities.
        """
        if not query or not query.strip():
            return []

        # Merge parameter filters with filters object
        if filters is None:
            filters = RetrievalFilters(
                vendor=vendor,
                product=product,
                severity=severity,
                source=source,
                kev=kev,
                exploit_available=exploit_available,
            )

        logger.info(
            "Retrieval started -> query='%s', filters=%s, limit=%d",
            query,
            filters.model_dump(exclude_none=True),
            limit,
        )

        # 1. Lexical retrieval from PostgreSQL
        try:
            lexical_results = self.lexical_retriever.search(
                query=query,
                filters=filters,
                limit=limit * 2,
            )
            logger.info("Lexical results count: %d", len(lexical_results))
        except Exception as exc:
            logger.error("Lexical search failed: %s", exc)
            lexical_results = []

        # 2. Semantic retrieval from Qdrant
        try:
            semantic_results = self.semantic_retriever.search(
                query=query,
                filters=filters,
                limit=limit * 2,
            )
            logger.info("Semantic results count: %d", len(semantic_results))
        except Exception as exc:
            logger.error("Semantic search failed (falling back to lexical): %s", exc)
            semantic_results = []

        # 3. Perform RRF Fusion & Exact CVE ranking
        fused_results = rrf_fusion(
            lexical_results=lexical_results,
            semantic_results=semantic_results,
            query=query,
            top_k=limit,
        )

        logger.info("Retrieval completed -> fused results count: %d", len(fused_results))
        return fused_results

    def search(
        self,
        query: str,
        vendor: str | None = None,
        product: str | None = None,
        severity: float | None = None,
        source: str | None = None,
        kev: bool | None = None,
        exploit_available: bool | None = None,
        limit: int = 20,
    ) -> list[NormalizedVulnerabilityResult]:
        """
        Alias for .retrieve(...) for intuitive agent tool consumption.
        """
        return self.retrieve(
            query=query,
            vendor=vendor,
            product=product,
            severity=severity,
            source=source,
            kev=kev,
            exploit_available=exploit_available,
            limit=limit,
        )