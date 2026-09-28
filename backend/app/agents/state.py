from typing import Any, TypedDict


class CyberRAGState(TypedDict, total=False):
    # User input
    project_input: dict[str, Any]

    # Technology Extraction
    assets: list[dict[str, Any]]

    # Vulnerability Matching
    candidate_vulnerabilities: list[dict[str, Any]]

    # Retrieval Agent Queries
    retrieval_queries: list[dict[str, Any]]

    # Internal Hybrid Retrieval Evidence
    internal_evidence: list[dict[str, Any]]

    # External Web Search Evidence
    web_evidence: list[dict[str, Any]]

    # Validation
    validated_findings: list[dict[str, Any]]

    # Risk Assessment
    risk_assessments: list[dict[str, Any]]

    # Recommendations
    recommendations: list[dict[str, Any]]

    # Final Report
    report: dict[str, Any]

    # Execution metadata
    retrieval_mode: str  # "HYBRID" or "POSTGRESQL_FALLBACK"
    errors: list[str]
    citations: list[dict[str, Any]]