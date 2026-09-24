from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.database.postgres import get_db
from app.retrieval.service import VulnerabilityRetriever
from app.retrieval.schemas import (
    RetrievalRequest,
    RetrievalResponse,
    RetrievalFilters,
)

router = APIRouter()


@router.get(
    "/search",
    response_model=RetrievalResponse,
    summary="Hybrid Vulnerability Search (GET)",
    description="Retrieve vulnerabilities using hybrid lexical + semantic search with RRF fusion and filters.",
)
def search_vulnerabilities_get(
    q: str = Query(..., description="Query string, CVE ID, vendor, or product name"),
    vendor: str | None = Query(None, description="Optional vendor filter"),
    product: str | None = Query(None, description="Optional product filter"),
    severity: float | None = Query(None, description="Minimum CVSS severity threshold"),
    source: str | None = Query(None, description="Source system filter (e.g. NVD, CISA, GITHUB)"),
    kev: bool | None = Query(None, description="Filter for CISA Known Exploited Vulnerabilities"),
    exploit_available: bool | None = Query(None, description="Filter for vulnerabilities with public exploits"),
    limit: int = Query(20, ge=1, le=100, description="Maximum number of results to return"),
    db: Session = Depends(get_db),
):
    retriever = VulnerabilityRetriever(db)
    filters = RetrievalFilters(
        vendor=vendor,
        product=product,
        severity=severity,
        source=source,
        kev=kev,
        exploit_available=exploit_available,
    )
    results = retriever.retrieve(query=q, filters=filters, limit=limit)
    return RetrievalResponse(
        query=q,
        total=len(results),
        results=results,
    )


@router.post(
    "/search",
    response_model=RetrievalResponse,
    summary="Hybrid Vulnerability Search (POST)",
    description="Retrieve vulnerabilities using hybrid lexical + semantic search with JSON payload.",
)
def search_vulnerabilities_post(
    request: RetrievalRequest,
    db: Session = Depends(get_db),
):
    retriever = VulnerabilityRetriever(db)
    filters = RetrievalFilters(
        vendor=request.vendor,
        product=request.product,
        severity=request.severity,
        source=request.source,
        kev=request.kev,
        exploit_available=request.exploit_available,
    )
    results = retriever.retrieve(query=request.q, filters=filters, limit=request.limit)
    return RetrievalResponse(
        query=request.q,
        total=len(results),
        results=results,
    )