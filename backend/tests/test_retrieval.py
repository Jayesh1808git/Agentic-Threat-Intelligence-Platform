import pytest
from uuid import uuid4
from unittest.mock import MagicMock, patch

from app.models.vulnerability import Vulnerability
from app.retrieval.schemas import RetrievalFilters
from app.retrieval.lexical import LexicalRetriever
from app.retrieval.fusion import rrf_fusion
from app.retrieval.service import VulnerabilityRetriever


def create_mock_vulnerability(
    cve="CVE-2021-44228",
    vulnerability_id="CVE-2021-44228",
    vendor="Apache",
    product="Log4j",
    title="Log4Shell RCE",
    description="Remote Code Execution vulnerability in Apache Log4j2.",
    cvss=9.8,
    kev=True,
    exploit_available=True,
    source="NVD",
):
    rec = Vulnerability()
    rec.id = uuid4()
    rec.source = source
    rec.vulnerability_id = vulnerability_id
    rec.cve = cve
    rec.title = title
    rec.description = description
    rec.vendor = vendor
    rec.product = product
    rec.affected_versions = ["2.0-beta9", "2.14.1"]
    rec.patched_versions = ["2.15.0"]
    rec.cvss = cvss
    rec.cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
    rec.epss = 0.95
    rec.kev = kev
    rec.exploit_available = exploit_available
    rec.references = ["https://logging.apache.org/log4j/2.x/security.html"]
    rec.content_hash = "abc123hash"
    rec.embedding_status = "indexed"
    return rec


def test_empty_query_handling():
    mock_db = MagicMock()
    retriever = VulnerabilityRetriever(mock_db)
    results = retriever.retrieve(query="")
    assert results == []

    results_whitespace = retriever.retrieve(query="   ")
    assert results_whitespace == []


def test_rrf_fusion_sorting_and_exact_match():
    v1 = create_mock_vulnerability(cve="CVE-2021-44228", title="Log4Shell")
    v2 = create_mock_vulnerability(cve="CVE-2022-22965", title="Spring4Shell", vendor="Spring", product="Framework")

    lexical_list = [(v1, 0.95), (v2, 0.50)]
    semantic_list = [(v2, 0.88), (v1, 0.82)]

    results = rrf_fusion(
        lexical_results=lexical_list,
        semantic_results=semantic_list,
        query="CVE-2021-44228",
        top_k=10,
    )

    assert len(results) == 2
    # Exact CVE match must rank 1st with score 1.0
    assert results[0].cve == "CVE-2021-44228"
    assert results[0].final_score == 1.0
    assert "lexical" in results[0].retrieval_sources
    assert "semantic" in results[0].retrieval_sources


def test_filters_schema():
    filters = RetrievalFilters(
        vendor="Apache",
        product="Log4j",
        severity=7.5,
        kev=True,
    )
    assert filters.vendor == "Apache"
    assert filters.product == "Log4j"
    assert filters.severity == 7.5
    assert filters.kev is True


def test_qdrant_unavailability_graceful_degradation():
    mock_db = MagicMock()
    v1 = create_mock_vulnerability(cve="CVE-2023-1234")
    
    with patch.object(LexicalRetriever, "search", return_value=[(v1, 0.9)]):
        with patch("app.retrieval.service.SemanticRetriever") as MockSemantic:
            instance = MockSemantic.return_value
            instance.search.side_effect = Exception("Qdrant offline connection refused")

            retriever = VulnerabilityRetriever(mock_db)
            results = retriever.retrieve(query="CVE-2023-1234")

            assert len(results) == 1
            assert results[0].cve == "CVE-2023-1234"
            assert results[0].retrieval_sources == ["lexical"]
