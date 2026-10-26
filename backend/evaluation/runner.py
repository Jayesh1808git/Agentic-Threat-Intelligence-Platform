"""Run retrieval evaluations using CyberRAG's existing VulnerabilityRetriever."""
from __future__ import annotations

import json
import logging
import re
import time
from pathlib import Path
from typing import Any
from uuid import UUID

from evaluation.metrics import evaluate_ranking, unique_ids
from evaluation.reporting import write_reports

logger = logging.getLogger("retrieval_evaluation")
IDENTIFIER_RE = re.compile(r"\b(?:CVE-\d{4}-\d+|GHSA-[a-z0-9-]+)\b", re.IGNORECASE)
VALID_STRATEGIES = {"hybrid", "lexical", "semantic", "postgresql_fallback"}


class DatasetError(ValueError):
    pass


def load_dataset(path: str | Path, category: str | None = None) -> list[dict[str, Any]]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    cases = payload.get("cases") if isinstance(payload, dict) else None
    if not isinstance(cases, list):
        raise DatasetError("Golden dataset must be a JSON object containing a 'cases' list")
    seen: set[str] = set()
    valid: list[dict[str, Any]] = []
    for item in cases:
        if not isinstance(item, dict):
            raise DatasetError("Each dataset case must be an object")
        case_id, query = item.get("id"), item.get("query")
        if not isinstance(case_id, str) or not case_id.strip() or case_id in seen:
            raise DatasetError(f"Invalid or duplicate case id: {case_id!r}")
        seen.add(case_id)
        if not isinstance(query, str) or not query.strip():
            raise DatasetError(f"Query {case_id} must have a non-empty query")
        if "expected_relevant_ids" not in item:
            raise DatasetError(f"Query {case_id} is missing expected_relevant_ids; use [] for a verified negative or null to mark unlabelled")
        labels = item["expected_relevant_ids"]
        if labels is not None and (not isinstance(labels, list) or any(not isinstance(x, str) or not x.strip() for x in labels)):
            raise DatasetError(f"expected_relevant_ids for {case_id} must be a list of non-empty strings or null")
        if category is None or item.get("category") == category:
            valid.append(item)
    if not valid:
        raise DatasetError(f"No golden dataset cases selected{f' for category {category!r}' if category else ''}")
    return valid


def verify_ground_truth(db: Any, cases: list[dict[str, Any]]) -> None:
    """Assert labelled expected identifiers exist in PostgreSQL; no DB content is invented."""
    from sqlalchemy import func, or_, select
    from app.models.vulnerability import Vulnerability

    missing: list[str] = []
    for case in cases:
        labels = case.get("expected_relevant_ids")
        if labels is None:
            continue
        for label in labels:
            record = db.scalar(select(Vulnerability.id).where(or_(
                func.lower(Vulnerability.cve) == label.lower(),
                func.lower(Vulnerability.vulnerability_id) == label.lower(),
            )).limit(1))
            if record is None:
                missing.append(f"{case['id']}: {label}")
    if missing:
        raise DatasetError("Ground-truth identifiers not found in PostgreSQL:\n- " + "\n- ".join(missing) + "\nCorrect the labels or ingest the authoritative records; evaluation was not run.")


def _record_id(result: Any) -> str:
    """Prefer exact vulnerability identifier; fall back to a stable payload identifier."""
    value = getattr(result, "cve", None) or getattr(result, "vulnerability_id", None)
    return str(value) if value else str(getattr(result, "id", ""))


def _identifier_key(value: str) -> str:
    """Normalize recognized CVE/GHSA labels without changing arbitrary vendor IDs."""
    return value.strip().upper()


def _strategy_results(retriever: Any, query: str, strategy: str, limit: int) -> tuple[list[Any], str]:
    """Expose existing component lists with no change to production ranking defaults."""
    if strategy == "hybrid":
        return retriever.retrieve_with_mode(query=query, limit=limit)

    # Strategy methods are the same lexical and semantic components used by service.py.
    # Constructing the semantic component may load the embedding model, as in production.
    from app.retrieval.schemas import RetrievalFilters

    filters = RetrievalFilters()
    if strategy == "lexical":
        raw = retriever.lexical_retriever.search(query=query, filters=filters, limit=limit)
        records = []
        for rec, score in raw:
            # Keep a compatible result shape by passing the one component through the
            # existing fusion utility; no semantic results are supplied.
            records.append((rec, score))
        from app.retrieval.fusion import rrf_fusion
        return rrf_fusion(records, [], query=query, top_k=limit), "LEXICAL_ONLY"

    if strategy == "semantic":
        raw = retriever.semantic_retriever.search(query=query, filters=filters, limit=limit)
        from app.retrieval.fusion import rrf_fusion
        return rrf_fusion([], raw, query=query, top_k=limit), "SEMANTIC_ONLY"

    if strategy == "postgresql_fallback":
        raw = retriever.lexical_retriever.search(query=query, filters=filters, limit=limit)
        from app.retrieval.fusion import rrf_fusion
        return rrf_fusion(raw, [], query=query, top_k=limit), "POSTGRESQL_FALLBACK_FORCED"
    raise ValueError(f"Unsupported strategy {strategy!r}; choose from {sorted(VALID_STRATEGIES)}")


def _postgres_resolve(db: Any, results: list[Any]) -> tuple[bool, int, int]:
    """Check resolvability of returned PostgreSQL UUIDs; missing records are not fatal."""
    from sqlalchemy import select
    from app.models.vulnerability import Vulnerability

    uuids: list[UUID] = []
    for result in results:
        raw_id = getattr(result, "id", None)
        try:
            uuids.append(UUID(str(raw_id)))
        except (TypeError, ValueError, AttributeError):
            continue
    if not uuids:
        return True, 0, 0
    found = set(db.scalars(select(Vulnerability.id).where(Vulnerability.id.in_(uuids))).all())
    return True, len(uuids), sum(item in found for item in uuids)


def run_evaluation(
    cases: list[dict[str, Any]],
    strategies: list[str],
    top_ks: list[int],
    output_dir: str | Path,
    db: Any,
    verify_golden: bool = True,
) -> list[dict[str, Any]]:
    """Execute selected queries/strategies, recording failures rather than fabricating scores."""
    if not top_ks or any(isinstance(k, bool) or not isinstance(k, int) or k <= 0 for k in top_ks):
        raise ValueError("top_ks must contain positive integers")
    if not strategies or any(s not in VALID_STRATEGIES for s in strategies):
        raise ValueError(f"strategies must be selected from {sorted(VALID_STRATEGIES)}")
    if verify_golden:
        verify_ground_truth(db, cases)

    from app.retrieval.service import VulnerabilityRetriever
    retriever = VulnerabilityRetriever(db)
    rows: list[dict[str, Any]] = []
    max_k = max(top_ks)

    for case in cases:
        # A null label means the candidate is deliberately awaiting human review.
        # Still run retrieval for diagnostic results, but never compute relevance metrics.
        for strategy in strategies:
            started = time.perf_counter()
            record: dict[str, Any] = {
                "query_id": case["id"], "query": case["query"],
                "category": case.get("category", "uncategorized"),
                "notes": case.get("notes"), "label_source": case.get("label_source", "unspecified"),
                "expected_relevant_ids": case.get("expected_relevant_ids"),
                "strategy": strategy, "retrieval_mode": None, "retrieved_ids": [],
                "rankings": [], "metrics": {}, "latency_ms": None, "error": None,
                "has_relevant_labels": case.get("expected_relevant_ids") is not None and bool(case.get("expected_relevant_ids")),
                "known_no_relevant": case.get("expected_relevant_ids") == [],
                "is_exact_identifier": bool(IDENTIFIER_RE.search(case["query"])),
                "exact_identifier_success": None,
                "postgres_resolution_checked": False, "postgres_ids_resolved": None,
            }
            try:
                results, mode = _strategy_results(retriever, case["query"], strategy, max_k)
                elapsed_ms = (time.perf_counter() - started) * 1000
                ids_with_duplicates = [_record_id(item) for item in results]
                ids = unique_ids([item for item in ids_with_duplicates if item])
                record["retrieval_mode"] = mode
                record["retrieved_ids"] = ids
                record["latency_ms"] = round(elapsed_ms, 3)
                record["rankings"] = [
                    {"rank": rank, "id": _record_id(item), "postgres_id": getattr(item, "id", None),
                     "score": getattr(item, "final_score", None),
                     "lexical_score": getattr(item, "lexical_score", None),
                     "semantic_score": getattr(item, "semantic_score", None),
                     "retrieval_sources": getattr(item, "retrieval_sources", [])}
                    for rank, item in enumerate(results, start=1)
                ]
                expected = case.get("expected_relevant_ids")
                for k in top_ks:
                    if expected is None:
                        record["metrics"][str(k)] = {m: None for m in ("hit_rate", "recall", "precision", "mrr", "ndcg")}
                    else:
                        record["metrics"][str(k)] = evaluate_ranking(ids, expected, k)
                if record["is_exact_identifier"] and expected is not None:
                    queried = {_identifier_key(match.group(0)) for match in IDENTIFIER_RE.finditer(case["query"])}
                    returned = {_identifier_key(x) for x in ids}
                    record["exact_identifier_success"] = bool(queried.intersection(returned))
                checked, total, resolved = _postgres_resolve(db, results)
                record["postgres_resolution_checked"] = checked
                record["postgres_ids_resolved"] = (resolved == total) if total else None
                record["postgres_resolvable_result_count"] = total
                record["postgres_resolved_result_count"] = resolved
            except Exception as exc:
                record["latency_ms"] = round((time.perf_counter() - started) * 1000, 3)
                record["error"] = f"{type(exc).__name__}: {exc}"
                logger.exception("Evaluation failed for %s (%s)", case["id"], strategy)
            rows.append(record)
    write_reports(rows, top_ks, output_dir)
    return rows
