from typing import Any

from app.agents.state import CyberRAGState
from app.database.postgres import SessionLocal
from app.retrieval.service import VulnerabilityRetriever


def internal_hybrid_retrieval_agent(
    state: CyberRAGState,
) -> dict[str, Any]:
    """
    Agent 3: Internal Hybrid Retrieval

    Uses the existing CyberRAG hybrid retrieval service to retrieve
    evidence from PostgreSQL + Qdrant.

    This agent retrieves evidence only.
    It does not validate findings or calculate risk.
    """

    candidate_vulnerabilities = state.get(
        "candidate_vulnerabilities",
        [],
    )

    if not candidate_vulnerabilities:
        return {
            "internal_evidence": [],
            "errors": state.get("errors", []),
        }

    db = SessionLocal()

    try:
        retriever = VulnerabilityRetriever(db)

        internal_evidence: list[dict[str, Any]] = []

        for candidate in candidate_vulnerabilities:
            cve = candidate.get("cve")
            vulnerability_id = candidate.get("vulnerability_id")
            vendor = candidate.get("vendor")
            product = candidate.get("product")
            asset_version = candidate.get("asset_version")

            query_parts = []

            if cve:
                query_parts.append(str(cve))

            if vendor:
                query_parts.append(str(vendor))

            if product:
                query_parts.append(str(product))

            if asset_version:
                query_parts.append(str(asset_version))

            query = " ".join(query_parts).strip()

            if not query:
                continue

            results = retriever.retrieve(
                query=query,
                vendor=vendor,
                product=product,
                limit=10,
            )

            for result in results:
                evidence = {
                    "candidate_cve": cve,
                    "candidate_vulnerability_id": vulnerability_id,
                    "query": query,
                    "vulnerability_id": result.vulnerability_id,
                    "cve": result.cve,
                    "title": result.title,
                    "description": result.description,
                    "vendor": result.vendor,
                    "product": result.product,
                    "affected_versions": result.affected_versions,
                    "patched_versions": result.patched_versions,
                    "cvss": result.cvss,
                    "epss": result.epss,
                    "kev": result.kev,
                    "exploit_available": result.exploit_available,
                    "references": result.references,
                    "semantic_score": getattr(
                        result,
                        "semantic_score",
                        None,
                    ),
                    "lexical_score": getattr(
                        result,
                        "lexical_score",
                        None,
                    ),
                    "retrieval_sources": getattr(
                        result,
                        "retrieval_sources",
                        [],
                    ),
                }

                internal_evidence.append(evidence)

        return {
            "internal_evidence": internal_evidence,
            "errors": state.get("errors", []),
        }

    except Exception as exc:
        errors = list(state.get("errors", []))
        errors.append(
            f"Internal hybrid retrieval failed: {exc}"
        )

        return {
            "internal_evidence": [],
            "errors": errors,
        }

    finally:
        db.close()