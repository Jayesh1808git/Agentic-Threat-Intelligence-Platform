from typing import Any

from pydantic import BaseModel, Field


class TechnologyInput(BaseModel):
    name: str
    type: str
    version: str | None = None
    vendor: str | None = None
    ecosystem: str | None = None
    criticality: str | None = None
    business_impact: str | None = None


class ProjectInput(BaseModel):
    name: str
    technologies: list[TechnologyInput] = Field(..., min_length=1)


class AssessmentRequest(BaseModel):
    project_input: ProjectInput


class AssessmentResponse(BaseModel):
    status: str
    project_name: str
    report: dict[str, Any]
    findings: list[dict[str, Any]]
    errors: list[Any] = Field(default_factory=list)