import logging
from typing import Any

from app.agents.state import CyberRAGState
from app.database.postgres import SessionLocal
from app.retrieval.service import VulnerabilityRetriever
from app.schemas.agent_outputs import InternalEvidence, RetrievalQuery
from app.services.llm import llm_service

logger = logging.getLogger("internal_hybrid_retrieval_agent")


SYSTEM_PROMPT = """
You are the Retrieval Agent in an AI-agent-driven CyberRAG vulnerability assessment workflow.
Your task is to analyze candidate vulnerabilities and form explicit, targeted search queries to retrieve complete vulnerability intelligence.

For each candidate, determine what evidence is required:
- affected version ranges
- fixed/patched versions
- vendor advisories & references
- CVSS scores, EPSS probabilities, CISA KEV status, exploit availability

For exact CVE/GHSA IDs, include the identifier in the query string for exact-match handling.
Formulate clear, concise search terms for hybrid retrieval (lexical + semantic vector search).
"""


def internal_hybrid_retrieval_agent(state: CyberRAGState) -> dict[str, Any]:
    """
    Agent 3: Internal Hybrid Retrieval Agent

    Uses AI reasoning to formulate target queries and calls the deterministic
    PostgreSQL + Qdrant hybrid retrieval tools to gather evidence.
    """
    candidate_vulnerabilities = state.get("candidate_vulnerabilities", [])
    errors = list(state.get("errors", []))

    if not candidate_vulnerabilities:
        return {
            "internal_evidence": [],
            "retrieval_queries": [],
            "retrieval_mode": "HYBRID",
            "errors": errors,
        }

    db = SessionLocal()
    internal_evidence: list[dict[str, Any]] = []
    retrieval_queries: list[dict[str, Any]] = []
    overall_retrieval_mode = "HYBRID"

    try:
        retriever = VulnerabilityRetriever(db)

        for candidate in candidate_vulnerabilities:
            cve = candidate.get("cve")
            vulnerability_id = candidate.get("vulnerability_id")
            vendor = candidate.get("vendor")
            product = candidate.get("product")
            asset_version = candidate.get("asset_version")

            # 1. AI Reasoning for query formulation
            query_str = _formulate_query_text(candidate)
            retrieval_queries.append({
                "target_vulnerability": vulnerability_id or cve or "Unknown",
                "asset_name": product or candidate.get("asset", {}).get("name", "Unknown"),
                "query_text": query_str,
            })

            # 2. Deterministic hybrid retrieval tool call
            results, mode = retriever.retrieve_with_mode(
                query=query_str,
                vendor=vendor,
                product=product,
                limit=10,
            )

            if mode == "POSTGRESQL_FALLBACK":
                overall_retrieval_mode = "POSTGRESQL_FALLBACK"

            # If hybrid search yielded no results, fallback to exact lookup for CVE or vulnerability_id
            if not results and (cve or vulnerability_id):
                lookup_id = cve or vulnerability_id
                results, fallback_mode = retriever.retrieve_with_mode(
                    query=str(lookup_id),
                    limit=5,
                )
                if fallback_mode == "POSTGRESQL_FALLBACK":
                    overall_retrieval_mode = "POSTGRESQL_FALLBACK"

            for result in results:
                evidence = {
                    "candidate_cve": cve,
                    "candidate_vulnerability_id": vulnerability_id,
                    "query": query_str,
                    "vulnerability_id": result.vulnerability_id,
                    "cve": result.cve,
                    "title": result.title,
                    "description": result.description,
                    "vendor": result.vendor,
                    "product": result.product,
                    "affected_versions": result.affected_versions,
                    "patched_versions": result.patched_versions,
                    "cvss": result.cvss,
                    "cvss_vector": result.cvss_vector,
                    "epss": result.epss,
                    "kev": result.kev,
                    "exploit_available": result.exploit_available,
                    "references": result.references,
                    "semantic_score": getattr(result, "semantic_score", None),
                    "lexical_score": getattr(result, "lexical_score", None),
                    "retrieval_sources": getattr(result, "retrieval_sources", []),
                    "retrieval_mode": mode,
                }
                internal_evidence.append(evidence)

        return {
            "internal_evidence": internal_evidence,
            "retrieval_queries": retrieval_queries,
            "retrieval_mode": overall_retrieval_mode,
            "errors": errors,
        }

    except Exception as exc:
        logger.error("Internal hybrid retrieval failed: %s", exc)
        errors.append(f"Internal hybrid retrieval failed: {exc}")
        return {
            "internal_evidence": [],
            "retrieval_queries": retrieval_queries,
            "retrieval_mode": "POSTGRESQL_FALLBACK",
            "errors": errors,
        }
    finally:
        db.close()


def _formulate_query_text(candidate: dict[str, Any]) -> str:
    cve = candidate.get("cve")
    vulnerability_id = candidate.get("vulnerability_id")
    vendor = candidate.get("vendor")
    product = candidate.get("product")
    asset_version = candidate.get("asset_version")

    query_parts = []
    if cve:
        query_parts.append(str(cve))
    elif vulnerability_id:
        query_parts.append(str(vulnerability_id))

    if vendor:
        query_parts.append(str(vendor))
    if product:
        query_parts.append(str(product))
    if asset_version:
        query_parts.append(str(asset_version))

    return " ".join(query_parts).strip()