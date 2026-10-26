from typing import Any
from pydantic import BaseModel, Field, field_validator


class Asset(BaseModel):
    name: str = Field(..., description="Technology or product name, e.g. Spring Boot")
    vendor: str | None = Field(default=None, description="Vendor or provider, e.g. VMware")
    product: str | None = Field(default=None, description="Product identifier or canonical name")
    type: str | None = Field(default=None, description="Component type e.g. framework, library, runtime, database, OS")
    version: str | None = Field(default=None, description="Exact installed version if present in input")
    version_constraints: str | None = Field(default=None, description="Version range or constraint if specified")
    dependency_relationship: str | None = Field(default=None, description="direct, transitive, or root")
    criticality: str | None = Field(default=None, description="Asset criticality: critical, high, medium, low")
    business_impact: str | None = Field(default=None, description="Business impact assessment: high, medium, low")


class TechnologyExtractionResult(BaseModel):
    assets: list[Asset] = Field(default_factory=list)
    summary: str | None = Field(default=None, description="Short summary of extracted technology stack")


class CandidateMatchEvaluation(BaseModel):
    vulnerability_id: str = Field(default="", description="Primary vulnerability ID or CVE")
    cve: str | None = Field(default=None)
    match_confidence: float = Field(default=0.75, ge=0.0, le=1.0)
    reason: str = Field(default="", description="Reasoning for candidate relevance")

    @field_validator("match_confidence", mode="before")
    @classmethod
    def coerce_confidence(cls, v: Any) -> float:
        """Treat null/non-numeric LLM output as the default confidence."""
        if v is None:
            return 0.75
        try:
            return float(v)
        except (TypeError, ValueError):
            return 0.75

    @field_validator("reason", mode="before")
    @classmethod
    def coerce_reason(cls, v: Any) -> str:
        """Treat null LLM output as an empty string."""
        return str(v) if v is not None else ""


class CandidateVulnerability(BaseModel):
    asset: dict | Asset = Field(default_factory=dict, description="Associated asset information")
    vulnerability_id: str = Field(default="", description="Primary vulnerability identifier or CVE")
    cve: str | None = Field(default=None, description="CVE ID if available")
    source: str = Field(default="NVD", description="Data source e.g. NVD, GHSA")
    title: str = Field(default="", description="Short title of the vulnerability")
    description: str = Field(default="", description="Detailed description")
    vendor: str | None = Field(default=None)
    product: str | None = Field(default=None)
    affected_versions: list[str] = Field(default_factory=list)
    patched_versions: list[str] = Field(default_factory=list)
    cpe_matches: list[str] = Field(default_factory=list)
    cvss: float | None = Field(default=None)
    cvss_vector: str | None = Field(default=None)
    epss: float | None = Field(default=None)
    kev: bool = Field(default=False)
    exploit_available: bool = Field(default=False)
    references: list[str] = Field(default_factory=list)
    asset_version: str | None = Field(default=None)
    match_confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    reason: str = Field(default="", description="Reasoning for candidate relevance")

    @field_validator("affected_versions", "patched_versions", "cpe_matches", "references", mode="before")
    @classmethod
    def normalize_missing_lists(cls, value: Any) -> list[str]:
        return [] if value is None else value

    @field_validator("match_confidence", mode="before")
    @classmethod
    def coerce_confidence(cls, v: Any) -> float:
        """Treat null/non-numeric LLM output as the default confidence."""
        if v is None:
            return 1.0
        try:
            return float(v)
        except (TypeError, ValueError):
            return 1.0

    @field_validator("reason", mode="before")
    @classmethod
    def coerce_reason(cls, v: Any) -> str:
        """Treat null LLM output as an empty string."""
        return str(v) if v is not None else ""


class VulnerabilityMatchResult(BaseModel):
    """LLM response schema for vulnerability matching.

    The LLM is instructed to populate ``candidate_evaluations`` only.
    ``candidate_vulnerabilities`` is kept for backward-compat but is never
    sent as part of the schema instructions to the LLM.
    """
    candidate_evaluations: list[CandidateMatchEvaluation] = Field(
        default_factory=list,
        description="One entry per candidate: its ID and a match_confidence score (0.0-1.0) with reasoning.",
    )
    # Kept for backward-compat; populated only if the LLM ignores instructions.
    candidate_vulnerabilities: list[CandidateVulnerability] = Field(default_factory=list)
    reasoning: str | None = Field(default=None)

    @classmethod
    def model_json_schema_for_llm(cls) -> dict:
        """Return a schema that only exposes candidate_evaluations to the LLM.

        This prevents the model from getting confused by the large
        CandidateVulnerability schema and returning null fields.
        """
        return {
            "type": "object",
            "required": ["candidate_evaluations"],
            "properties": {
                "candidate_evaluations": {
                    "type": "array",
                    "description": "One entry per candidate vulnerability evaluated.",
                    "items": {
                        "type": "object",
                        "required": ["vulnerability_id", "match_confidence", "reason"],
                        "properties": {
                            "vulnerability_id": {"type": "string", "description": "The vulnerability or CVE ID"},
                            "cve": {"type": "string", "description": "CVE ID if known"},
                            "match_confidence": {"type": "number", "minimum": 0.0, "maximum": 1.0, "description": "0.0=no match, 1.0=definite match"},
                            "reason": {"type": "string", "description": "Brief explanation of match confidence"},
                        },
                    },
                },
            },
        }


class RetrievalQuery(BaseModel):
    target_vulnerability: str
    asset_name: str
    query_text: str
    required_fields: list[str] = Field(default_factory=list)


class InternalEvidence(BaseModel):
    candidate_cve: str | None = None
    candidate_vulnerability_id: str | None = None
    query: str
    vulnerability_id: str
    cve: str | None = None
    title: str = ""
    description: str = ""
    vendor: str | None = None
    product: str | None = None
    affected_versions: list[str] = Field(default_factory=list)
    patched_versions: list[str] = Field(default_factory=list)
    cvss: float | None = None
    cvss_vector: str | None = None
    epss: float | None = None
    kev: bool | None = None
    exploit_available: bool | None = None
    references: list[str] = Field(default_factory=list)
    semantic_score: float | None = None
    lexical_score: float | None = None
    retrieval_sources: list[str] = Field(default_factory=list)
    retrieval_mode: str = "HYBRID"


class WebEvidence(BaseModel):
    source_type: str = Field(..., description="e.g. nvd, cisa_kev, github_advisory, vendor_advisory, patch_information")
    source: str = Field(..., description="Source name or URL")
    url: str = Field(..., description="Citable URL")
    cve: str | None = None
    vulnerability_id: str | None = None
    title: str | None = None
    published_at: str | None = None
    relevant_information: Any = None
    reason_relevant: str = Field(default="", description="Explanation of why this external evidence is relevant")


class ValidatedFinding(BaseModel):
    asset: dict = Field(..., description="Asset details")
    vulnerability: str = Field(..., description="Vulnerability or CVE ID")
    vulnerability_id: str | None = None
    cve: str | None = None
    status: str = Field(..., description="validated, not_affected, or needs_review")
    affected: bool | None = Field(default=None)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    identity_match: bool = False
    product_match: bool = False
    version_match: bool | None = None
    patch_status: bool | None = None
    source_corroborated: bool = False
    reason: str = ""
    affected_versions: list[str] = Field(default_factory=list)
    patched_versions: list[str] = Field(default_factory=list)
    cvss: float | None = None
    cvss_vector: str | None = None
    epss: float | None = None
    kev: bool | None = None
    exploit_available: bool | None = None
    evidence: list[dict] = Field(default_factory=list)
    sources: list[str] = Field(default_factory=list)
    discrepancies: list[str] = Field(default_factory=list)
    conflicts: list[str] = Field(default_factory=list)


class ValidationResult(BaseModel):
    validated_findings: list[ValidatedFinding] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)


class BatchValidationItem(BaseModel):
    vulnerability_id: str = Field(..., description="Vulnerability or CVE ID being evaluated")
    applicable: bool = Field(..., description="True if installed version falls within affected range, False otherwise")
    confidence: float = Field(default=0.9, ge=0.0, le=1.0, description="Confidence score")
    reason: str = Field(default="", description="Concise explanation of applicability decision")


class BatchValidationResult(BaseModel):
    results: list[BatchValidationItem] = Field(default_factory=list)


class RiskAssessment(BaseModel):
    vulnerability_id: str
    asset_id: str | None = None
    asset: dict = Field(default_factory=dict)
    risk_score: float = Field(..., ge=0.0, le=100.0)
    risk_level: str = Field(..., description="critical, high, medium, low, minimal")
    risk_factors: dict = Field(default_factory=dict)
    normalized_factors: dict | None = None
    scoring_formula: dict | None = None
    rationale: str = Field(..., description="AI reasoning explaining the calculated risk")


class RiskAssessmentResult(BaseModel):
    risk_assessments: list[RiskAssessment] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)


class RiskRecommendationItem(BaseModel):
    finding_key: str
    rationale: str = ""
    recommendation: dict = Field(default_factory=dict)


class RiskRecommendationResult(BaseModel):
    results: list[RiskRecommendationItem] = Field(default_factory=list)


class Recommendation(BaseModel):
    vulnerability_id: str
    asset: str
    recommendation: dict = Field(..., description="Contains action, target_version, priority, description, mitigation")
    risk: dict = Field(..., description="Contains risk_score, risk_level")
    references: list[str] = Field(default_factory=list)
    evidence_used: dict = Field(default_factory=dict)


class RecommendationResult(BaseModel):
    recommendations: list[Recommendation] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)


class AssessmentReport(BaseModel):
    title: str = "CyberRAG Vulnerability Assessment Report"
    project_name: str = ""
    generated_at: str = ""
    executive_summary: str = ""
    affected_assets: list[dict] = Field(default_factory=list)
    confirmed_vulnerabilities: list[dict] = Field(default_factory=list)
    potential_vulnerabilities: list[dict] = Field(default_factory=list)
    not_applicable: list[dict] = Field(default_factory=list)
    evidence_summary: dict = Field(default_factory=dict)
    risk_analysis: dict = Field(default_factory=dict)
    recommendations: list[dict] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    markdown: str = ""
