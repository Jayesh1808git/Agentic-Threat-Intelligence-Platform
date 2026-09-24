from typing import Any
from pydantic import BaseModel, Field


class NormalizedVulnerabilityResult(BaseModel):
    id: str
    vulnerability_id: str
    source: str
    cve: str | None = None
    title: str
    description: str
    vendor: str | None = None
    product: str | None = None
    affected_versions: list[str] = Field(default_factory=list)
    patched_versions: list[str] = Field(default_factory=list)
    cvss: float | None = None
    cvss_vector: str | None = None
    epss: float | None = None
    kev: bool = False
    exploit_available: bool = False
    references: list[str] = Field(default_factory=list)
    published: str | None = None
    updated: str | None = None

    semantic_score: float | None = None
    lexical_score: float | None = None
    final_score: float = 0.0

    retrieval_sources: list[str] = Field(default_factory=list)


class RetrievalFilters(BaseModel):
    vendor: str | None = None
    product: str | None = None
    severity: float | None = None
    source: str | None = None
    kev: bool | None = None
    exploit_available: bool | None = None


class RetrievalRequest(BaseModel):
    q: str = Field(..., description="Query string, CVE ID, product name, etc.")
    vendor: str | None = None
    product: str | None = None
    severity: float | None = None
    source: str | None = None
    kev: bool | None = None
    exploit_available: bool | None = None
    limit: int = Field(default=20, ge=1, le=100)


class RetrievalResponse(BaseModel):
    query: str
    total: int
    results: list[NormalizedVulnerabilityResult]
