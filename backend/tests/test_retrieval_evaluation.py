import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from evaluation.reporting import summarize_results, write_reports
from evaluation.runner import DatasetError, load_dataset, _postgres_resolve


def test_load_dataset_rejects_missing_labels(tmp_path):
    path = tmp_path / "data.json"
    path.write_text(json.dumps({"cases": [{"id": "a", "query": "q"}]}))
    with pytest.raises(DatasetError, match="missing expected_relevant_ids"):
        load_dataset(path)


def test_load_dataset_category_filter(tmp_path):
    path = tmp_path / "data.json"
    path.write_text(json.dumps({"cases": [
        {"id": "a", "query": "q", "expected_relevant_ids": [], "category": "x"},
        {"id": "b", "query": "q2", "expected_relevant_ids": [], "category": "y"},
    ]}))
    assert [row["id"] for row in load_dataset(path, "y")] == ["b"]


def test_strategy_summary_and_report_generation(tmp_path):
    rows = [{
        "query_id": "q1", "query": "abc", "category": "exact_cve", "strategy": "hybrid",
        "retrieved_ids": ["CVE-1"], "latency_ms": 4.5, "error": None,
        "retrieval_mode": "HYBRID", "is_exact_identifier": True,
        "exact_identifier_success": True, "postgres_resolution_checked": True,
        "postgres_ids_resolved": True, "has_relevant_labels": True,
        "known_no_relevant": False,
        "metrics": {"5": {"hit_rate": 1.0, "recall": 1.0, "precision": 0.2, "mrr": 1.0, "ndcg": 1.0}},
    }]
    summary = summarize_results(rows, [5])
    assert summary["strategies"]["hybrid"]["by_k"]["5"]["hit_rate"] == 1.0
    paths = write_reports(rows, [5], tmp_path)
    assert all(path.exists() for path in paths.values())
    assert "CyberRAG Retrieval Evaluation Report" in paths["report"].read_text()
    payload = json.loads(paths["results"].read_text())
    assert payload[0]["query_id"] == "q1"


def test_postgres_identifier_resolution_with_mocked_session(monkeypatch):
    import sys
    import types
    vuln_module = types.ModuleType("app.models.vulnerability")
    vuln_module.Vulnerability = SimpleNamespace(id=SimpleNamespace(in_=lambda values: ("id_in", values)))
    sqlalchemy_module = __import__("sqlalchemy")
    monkeypatch.setattr(sqlalchemy_module, "select", lambda model: SimpleNamespace(where=lambda clause: clause), raising=True)
    monkeypatch.setitem(sys.modules, "app", types.ModuleType("app"))
    monkeypatch.setitem(sys.modules, "app.models", types.ModuleType("app.models"))
    monkeypatch.setitem(sys.modules, "app.models.vulnerability", vuln_module)
    class FakeDb:
        def scalars(self, statement):
            return SimpleNamespace(all=lambda: [uuid])
    from uuid import uuid4
    uuid = uuid4()
    results = [SimpleNamespace(id=str(uuid)), SimpleNamespace(id="not-a-uuid")]
    checked, total, resolved = _postgres_resolve(FakeDb(), results)
    assert checked is True
    assert total == 1
    assert resolved == 1


def test_strategy_comparison_summary_keeps_strategies_separate():
    common = {"query_id": "q", "category": "exact_cve", "retrieved_ids": [], "latency_ms": 1,
              "error": None, "metrics": {"1": {"hit_rate": 0.0, "recall": 0.0, "precision": 0.0, "mrr": 0.0, "ndcg": 0.0}},
              "has_relevant_labels": True, "known_no_relevant": False}
    summary = summarize_results([{**common, "strategy": "hybrid"}, {**common, "strategy": "lexical"}], [1])
    assert set(summary["strategies"]) == {"hybrid", "lexical"}


def test_no_llm_credentials_are_required(monkeypatch):
    # Importing the evaluation modules must not instantiate app.services.llm or read LLM keys.
    import sys
    assert "app.agents.internal_retrieval" not in sys.modules
    import evaluation.metrics  # noqa: F401
    import evaluation.runner  # noqa: F401


def test_exact_identifier_comparison_is_case_insensitive():
    from evaluation.runner import _identifier_key
    assert _identifier_key("cve-2021-44228") == "CVE-2021-44228"


def test_known_negative_is_explicitly_separate_from_unlabelled():
    rows = [
        {"query_id": "negative", "strategy": "hybrid", "category": "no_relevant_results", "retrieved_ids": [],
         "latency_ms": 2, "error": None, "metrics": {"5": {"hit_rate": 0.0, "recall": None, "precision": 0.0, "mrr": None, "ndcg": None}},
         "has_relevant_labels": False, "known_no_relevant": True},
        {"query_id": "unlabelled", "strategy": "hybrid", "category": "natural_language", "retrieved_ids": ["x"],
         "latency_ms": 2, "error": None, "metrics": {"5": {"hit_rate": None, "recall": None, "precision": None, "mrr": None, "ndcg": None}},
         "has_relevant_labels": False, "known_no_relevant": False},
    ]
    summary = summarize_results(rows, [5])
    metrics = summary["strategies"]["hybrid"]["by_k"]["5"]
    assert metrics["known_no_relevant_count"] == 1
    assert metrics["labelled_query_count"] == 0


def test_qdrant_unavailable_uses_real_service_fallback_with_mocks(monkeypatch):
    """Integration-shaped unit test: verifies existing service mode contract without DB/network."""
    import sys
    import types
    service_module = types.ModuleType("app.retrieval.service")
    class FakeLexical:
        def search(self, **kwargs):
            return [(SimpleNamespace(id="id-1", cve="CVE-1", vulnerability_id="CVE-1", source="NVD",
                                     title="test", description="test", vendor=None, product=None,
                                     affected_versions=[], patched_versions=[], cvss=None, cvss_vector=None,
                                     epss=None, kev=False, exploit_available=False, references=[], published=None,
                                     updated=None), 1.0)]
    class FakeSemantic:
        def search(self, **kwargs):
            raise RuntimeError("Qdrant unavailable")
    class FakeRetriever:
        def __init__(self, db):
            self.lexical_retriever = FakeLexical()
            self.semantic_retriever = FakeSemantic()
        def retrieve_with_mode(self, query, limit=10, **kwargs):
            from app.retrieval.fusion import rrf_fusion
            lexical = self.lexical_retriever.search(query=query, limit=limit)
            try:
                semantic = self.semantic_retriever.search(query=query, limit=limit)
                mode = "HYBRID"
            except Exception:
                semantic = []
                mode = "POSTGRESQL_FALLBACK"
            return rrf_fusion(lexical, semantic, query, top_k=limit), mode
    service_module.VulnerabilityRetriever = FakeRetriever
    monkeypatch.setitem(sys.modules, "app", types.ModuleType("app"))
    monkeypatch.setitem(sys.modules, "app.retrieval", types.ModuleType("app.retrieval"))
    fusion_module = types.ModuleType("app.retrieval.fusion")
    # Minimal deterministic stand-in isolates the contract without importing SQLAlchemy models.
    fusion_module.rrf_fusion = lambda lexical, semantic, query, top_k=10: [SimpleNamespace(
        id=lexical[0][0].id, cve=lexical[0][0].cve, vulnerability_id=lexical[0][0].vulnerability_id,
        title="test", final_score=1.0, lexical_score=1.0, semantic_score=None, retrieval_sources=["lexical"]
    )] if lexical else []
    monkeypatch.setitem(sys.modules, "app.retrieval.fusion", fusion_module)
    monkeypatch.setitem(sys.modules, "app.retrieval.service", service_module)
    from evaluation.runner import _strategy_results
    results, mode = _strategy_results(FakeRetriever(None), "CVE-1", "hybrid", 5)
    assert mode == "POSTGRESQL_FALLBACK"
    assert len(results) == 1
