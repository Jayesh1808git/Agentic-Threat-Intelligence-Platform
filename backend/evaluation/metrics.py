"""Reusable ranking metrics for retrieval evaluation.

Conventions:
- IDs are de-duplicated by keeping the first occurrence (preserves best rank).
- Precision@K divides by K, even when fewer than K records were returned. Missing
  ranks are effectively non-relevant; this makes cutoffs comparable between systems.
- Queries with no known relevant labels (None) are unlabelled and raise ValueError.
  An explicitly empty relevant set means a known no-relevant-results query: recall,
  MRR and nDCG are undefined (None); hit rate is 0 when results exist and precision
  is 0. The aggregate evaluator excludes such cases from relevance aggregates and
  reports the count separately. This avoids rewarding systems for returning nothing.
- Relevance may be binary (set/list of IDs) or graded (mapping ID -> non-negative gain).
"""
from __future__ import annotations

import math
from collections.abc import Iterable, Mapping, Sequence
from typing import TypeAlias

RelevanceLabels: TypeAlias = Iterable[str] | Mapping[str, float] | None


def unique_ids(retrieved_ids: Iterable[str]) -> list[str]:
    """Return IDs in first-seen order, rejecting empty/non-string identifiers."""
    result: list[str] = []
    seen: set[str] = set()
    for item in retrieved_ids:
        if not isinstance(item, str) or not item.strip():
            raise ValueError("Retrieved IDs must be non-empty strings")
        if item not in seen:
            seen.add(item)
            result.append(item)
    return result


def _relevance(labels: RelevanceLabels) -> dict[str, float]:
    if labels is None:
        raise ValueError("Ground-truth labels are missing (expected_relevant_ids is required)")
    if isinstance(labels, Mapping):
        relevance: dict[str, float] = {}
        for key, value in labels.items():
            if not isinstance(key, str) or not key.strip():
                raise ValueError("Ground-truth IDs must be non-empty strings")
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise ValueError(f"Relevance for {key!r} must be numeric")
            if not math.isfinite(float(value)) or value < 0:
                raise ValueError(f"Relevance for {key!r} must be finite and >= 0")
            relevance[key] = float(value)
        return relevance
    if isinstance(labels, (str, bytes)):
        raise ValueError("Ground truth must be a collection of IDs, not a string")
    try:
        values = list(labels)
    except TypeError as exc:
        raise ValueError("Ground truth must be a collection of IDs or a relevance mapping") from exc
    relevance = {}
    for key in values:
        if not isinstance(key, str) or not key.strip():
            raise ValueError("Ground-truth IDs must be non-empty strings")
        relevance[key] = 1.0
    return relevance


def _validate_k(k: int) -> None:
    if isinstance(k, bool) or not isinstance(k, int) or k <= 0:
        raise ValueError("k must be a positive integer")


def hit_rate_at_k(retrieved_ids: Iterable[str], relevant_ids: RelevanceLabels, k: int) -> float:
    _validate_k(k)
    labels = _relevance(relevant_ids)
    retrieved = unique_ids(retrieved_ids)[:k]
    return float(any(labels.get(item, 0.0) > 0 for item in retrieved))


def recall_at_k(retrieved_ids: Iterable[str], relevant_ids: RelevanceLabels, k: int) -> float | None:
    _validate_k(k)
    labels = _relevance(relevant_ids)
    relevant = {item for item, gain in labels.items() if gain > 0}
    if not relevant:
        return None
    retrieved = unique_ids(retrieved_ids)[:k]
    return len(relevant.intersection(retrieved)) / len(relevant)


def precision_at_k(retrieved_ids: Iterable[str], relevant_ids: RelevanceLabels, k: int) -> float:
    _validate_k(k)
    labels = _relevance(relevant_ids)
    retrieved = unique_ids(retrieved_ids)[:k]
    return sum(labels.get(item, 0.0) > 0 for item in retrieved) / k


def mrr_at_k(retrieved_ids: Iterable[str], relevant_ids: RelevanceLabels, k: int) -> float | None:
    _validate_k(k)
    labels = _relevance(relevant_ids)
    if not any(gain > 0 for gain in labels.values()):
        return None
    for rank, item in enumerate(unique_ids(retrieved_ids)[:k], start=1):
        if labels.get(item, 0.0) > 0:
            return 1.0 / rank
    return 0.0


def ndcg_at_k(retrieved_ids: Iterable[str], relevant_ids: RelevanceLabels, k: int) -> float | None:
    _validate_k(k)
    labels = _relevance(relevant_ids)
    if not any(gain > 0 for gain in labels.values()):
        return None
    retrieved = unique_ids(retrieved_ids)[:k]
    dcg = sum((2 ** labels.get(item, 0.0) - 1) / math.log2(rank + 1)
              for rank, item in enumerate(retrieved, start=1))
    ideal_gains = sorted(labels.values(), reverse=True)[:k]
    idcg = sum((2 ** gain - 1) / math.log2(rank + 1)
               for rank, gain in enumerate(ideal_gains, start=1))
    return dcg / idcg if idcg > 0 else None


def evaluate_ranking(retrieved_ids: Iterable[str], relevant_ids: RelevanceLabels, k: int) -> dict[str, float | None]:
    """Return all ranking metrics with one consistent ID de-duplication policy."""
    retrieved = unique_ids(retrieved_ids)
    labels = _relevance(relevant_ids)
    return {
        "hit_rate": hit_rate_at_k(retrieved, labels, k),
        "recall": recall_at_k(retrieved, labels, k),
        "precision": precision_at_k(retrieved, labels, k),
        "mrr": mrr_at_k(retrieved, labels, k),
        "ndcg": ndcg_at_k(retrieved, labels, k),
    }
