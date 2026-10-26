import math
import pytest

from backend.evaluation.metrics import (
    hit_rate_at_k, recall_at_k, precision_at_k, mrr_at_k, ndcg_at_k,
    evaluate_ranking,
)


def test_hit_rate():
    assert hit_rate_at_k(["a", "b"], ["b"], 2) == 1.0
    assert hit_rate_at_k(["a"], ["b"], 1) == 0.0


def test_recall_multiple_relevant_and_empty_results():
    assert recall_at_k(["x", "a"], ["a", "b"], 2) == 0.5
    assert recall_at_k([], ["a", "b"], 5) == 0.0


def test_precision_divides_by_k_even_for_short_lists():
    assert precision_at_k(["a"], ["a"], 5) == 0.2
    assert precision_at_k([], ["a"], 5) == 0.0


def test_mrr():
    assert mrr_at_k(["x", "a"], ["a"], 2) == 0.5
    assert mrr_at_k(["x"], ["a"], 2) == 0.0


def test_ndcg_binary_and_graded():
    assert ndcg_at_k(["a", "b"], ["a", "b"], 2) == pytest.approx(1.0)
    # Graded gain supports ranking a gain-3 item above gain-1.
    assert ndcg_at_k(["high", "low"], {"high": 3, "low": 1}, 2) == pytest.approx(1.0)
    assert ndcg_at_k(["low", "high"], {"high": 3, "low": 1}, 2) < 1.0


def test_duplicate_results_keep_first_rank():
    assert mrr_at_k(["x", "a", "a"], ["a"], 3) == 0.5
    assert recall_at_k(["a", "a"], ["a", "b"], 5) == 0.5
    assert precision_at_k(["a", "a"], ["a"], 3) == pytest.approx(1 / 3)


def test_known_no_relevant_documents():
    assert hit_rate_at_k(["x"], [], 1) == 0.0
    assert precision_at_k(["x"], [], 1) == 0.0
    assert recall_at_k(["x"], [], 1) is None
    assert mrr_at_k(["x"], [], 1) is None
    assert ndcg_at_k(["x"], [], 1) is None


def test_missing_and_invalid_labels():
    for metric in (hit_rate_at_k, recall_at_k, precision_at_k, mrr_at_k, ndcg_at_k):
        with pytest.raises(ValueError, match="missing"):
            metric([], None, 1)
        with pytest.raises(ValueError):
            metric([], [""], 1)
        with pytest.raises(ValueError):
            metric([], ["a"], 0)


def test_ndcg_rejects_negative_or_nonfinite_grade():
    with pytest.raises(ValueError):
        ndcg_at_k([], {"a": -1}, 1)
    with pytest.raises(ValueError):
        ndcg_at_k([], {"a": math.inf}, 1)


def test_evaluate_ranking_keys():
    row = evaluate_ranking(["a"], ["a"], 1)
    assert set(row) == {"hit_rate", "recall", "precision", "mrr", "ndcg"}
    assert all(value == 1.0 for value in row.values())
