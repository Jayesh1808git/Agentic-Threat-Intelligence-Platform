from typing import Any
from pydantic import BaseModel, Field


class TechnologyInput(BaseModel):
    name: str
    type: str | None = "technology"
    version: str | None = None
    vendor: str | None = None
    ecosystem: str | None = None
    criticality: str | None = None
    business_impact: str | None = None


class ProjectInput(BaseModel):
    name: str
    description: str | None = None
    technologies: list[TechnologyInput] = Field(default_factory=list)


class AssessmentRequest(BaseModel):
    project_input: ProjectInput


class AssessmentResponse(BaseModel):
    status: str  # "completed", "partial", "failed"
    retrieval_mode: str = "HYBRID"  # "HYBRID" or "POSTGRESQL_FALLBACK"
    project_name: str
    report: dict[str, Any]
    findings: list[dict[str, Any]]
    errors: list[Any] = Field(default_factory=list)
    llm_used: bool = False
    fallback_used: bool = False
    fallback_reason: str | None = None
    llm_call_count: int = 0
    rate_limit_count: int = 0
    retry_count: int = 0
    fallback_count: int = 0