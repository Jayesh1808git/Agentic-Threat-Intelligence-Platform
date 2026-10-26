import pytest
from unittest.mock import MagicMock, patch
from types import SimpleNamespace
from fastapi.testclient import TestClient

from app.main import app
from app.agents.state import CyberRAGState
from app.agents.technology_extraction import technology_extraction_agent
from app.agents.vulnerability_matching import vulnerability_matching_agent
from app.agents.internal_retrieval import internal_hybrid_retrieval_agent
from app.agents.web_search import web_search_agent, evidence_is_sufficient
from app.agents.validation import validation_agent
from app.agents.risk_assessment import risk_assessment_agent
from app.agents.recommendation import recommendation_agent
from app.agents.report import report_agent
from app.graph import cyberrag_graph, evidence_decision
from app.retrieval.service import VulnerabilityRetriever
from app.retrieval.semantic import SemanticRetriever
from app.agents.validation import _version_is_patched
from run_graph import run_cyberrag

client = TestClient(app)


# Mock vulnerability helper
def create_sample_candidate(
    cve="CVE-2024-22243",
    vulnerability_id="CVE-2024-22243",
    vendor="VMware",
    product="Spring Boot",
    asset_name="Spring Boot",
    asset_version="3.2.5",
    affected_versions=None,
    patched_versions=None,
    cvss=8.1,
    kev=False,
    exploit_available=True,
):
    if affected_versions is None:
        affected_versions = ["< 3.2.8", "3.2.0 - 3.2.7"]
    if patched_versions is None:
        patched_versions = ["3.2.8"]

    return {
        "asset": {
            "name": asset_name,
            "vendor": vendor,
            "product": product,
            "version": asset_version,
            "criticality": "high",
            "business_impact": "high",
        },
        "vulnerability_id": vulnerability_id,
        "cve": cve,
        "source": "NVD",
        "title": "Spring Boot URL Parsing SSRF Vulnerability",
        "description": "Spring Boot contains an open redirect / SSRF vulnerability in version 3.2.5.",
        "vendor": vendor,
        "product": product,
        "affected_versions": affected_versions,
        "patched_versions": patched_versions,
        "cvss": cvss,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "epss": 0.45,
        "kev": kev,
        "exploit_available": exploit_available,
        "references": ["https://spring.io/security/cve-2024-22243"],
        "asset_version": asset_version,
        "match_confidence": 0.95,
        "reason": "Spring Boot 3.2.5 falls in affected range.",
    }


# Test 1: Vulnerable project (Spring Boot 3.2.5)
def test_vulnerable_project():
    state: CyberRAGState = {
        "project_input": {
            "name": "Spring Boot Vulnerable Test",
            "technologies": [
                {
                    "name": "Spring Boot",
                    "vendor": "VMware",
                    "version": "3.2.5",
                    "type": "framework",
                    "criticality": "critical",
                    "business_impact": "high",
                }
            ],
        },
        "assets": [
            {
                "name": "Spring Boot",
                "vendor": "VMware",
                "version": "3.2.5",
                "type": "framework",
                "criticality": "critical",
                "business_impact": "high",
            }
        ],
        "candidate_vulnerabilities": [
            create_sample_candidate(asset_version="3.2.5")
        ],
        "internal_evidence": [
            {
                "cve": "CVE-2024-22243",
                "vulnerability_id": "CVE-2024-22243",
                "query": "CVE-2024-22243 Spring Boot 3.2.5",
                "vendor": "VMware",
                "product": "Spring Boot",
                "description": "SSRF in Spring Boot 3.2.5",
                "affected_versions": ["< 3.2.8"],
                "patched_versions": ["3.2.8"],
                "cvss": 8.1,
                "epss": 0.45,
                "kev": False,
                "exploit_available": True,
                "references": ["https://spring.io/security/cve-2024-22243"],
                "retrieval_sources": ["lexical", "semantic"],
            }
        ],
        "web_evidence": [],
        "errors": [],
    }

    val_res = validation_agent(state)
    assert len(val_res["validated_findings"]) == 1
    finding = val_res["validated_findings"][0]
    assert finding["status"] == "validated"
    assert finding["affected"] is True

    state["validated_findings"] = val_res["validated_findings"]
    risk_res = risk_assessment_agent(state)
    assert len(risk_res["risk_assessments"]) == 1
    risk = risk_res["risk_assessments"][0]
    assert risk["risk_level"] in ["high", "critical"]

    state["risk_assessments"] = risk_res["risk_assessments"]
    rec_res = recommendation_agent(state)
    assert len(rec_res["recommendations"]) == 1
    rec = rec_res["recommendations"][0]
    assert rec["recommendation"]["target_version"] == "3.2.8"

    state["recommendations"] = rec_res["recommendations"]
    rep_res = report_agent(state)
    assert "report" in rep_res
    assert len(rep_res["report"]["confirmed_vulnerabilities"]) == 1


# Test 2: Patched project (Spring Boot 3.2.8)
def test_patched_project():
    candidate = create_sample_candidate(asset_version="3.2.8", patched_versions=["3.2.8"])
    state: CyberRAGState = {
        "assets": [{"name": "Spring Boot", "version": "3.2.8"}],
        "candidate_vulnerabilities": [candidate],
        "internal_evidence": [
            {
                "cve": "CVE-2024-22243",
                "vulnerability_id": "CVE-2024-22243",
                "vendor": "VMware",
                "product": "Spring Boot",
                "affected_versions": ["< 3.2.8"],
                "patched_versions": ["3.2.8"],
            }
        ],
        "web_evidence": [],
        "errors": [],
    }

    val_res = validation_agent(state)
    assert len(val_res["validated_findings"]) == 1
    finding = val_res["validated_findings"][0]
    assert finding["status"] == "not_affected"
    assert finding["affected"] is False


# Test 3: Unrelated technology (Django for a Spring vulnerability)
def test_unrelated_technology():
    candidate = create_sample_candidate(asset_name="Django", vendor="Django Software Foundation", product="Django")
    candidate["asset"] = {"name": "Django", "vendor": "Django Software Foundation", "version": "4.2.0"}

    state: CyberRAGState = {
        "assets": [{"name": "Django", "version": "4.2.0"}],
        "candidate_vulnerabilities": [candidate],
        "internal_evidence": [
            {
                "cve": "CVE-2024-22243",
                "vulnerability_id": "CVE-2024-22243",
                "vendor": "VMware",
                "product": "Spring Boot",
                "affected_versions": ["< 3.2.8"],
            }
        ],
        "web_evidence": [],
        "errors": [],
    }

    val_res = validation_agent(state)
    assert len(val_res["validated_findings"]) == 1
    finding = val_res["validated_findings"][0]
    assert finding["status"] == "not_affected"
    assert finding["affected"] is False


def test_multibranch_patch_versions_only_apply_to_matching_release_branch():
    assert _version_is_patched("1.5.2", ["1.4.9", "1.5.3"]) is False
    assert _version_is_patched("1.5.4", ["1.4.9", "1.5.3"]) is True
    assert _version_is_patched("1.6.1", ["1.4.9", "1.5.3"]) is None


def test_multibranch_patch_does_not_hide_affected_finding():
    candidate = create_sample_candidate(
        asset_version="1.5.2",
        affected_versions=["< 2.0"],
        patched_versions=["1.4.9", "1.5.3"],
    )
    candidate["asset"]["version"] = "1.5.2"
    candidate["asset_version"] = "1.5.2"
    candidate["affected_versions"] = ["< 2.0"]
    candidate["patched_versions"] = ["1.4.9", "1.5.3"]

    state: CyberRAGState = {
        "assets": [candidate["asset"]],
        "candidate_vulnerabilities": [candidate],
        "internal_evidence": [
            {
                "cve": candidate["cve"],
                "vulnerability_id": candidate["vulnerability_id"],
                "vendor": candidate["vendor"],
                "product": candidate["product"],
                "affected_versions": ["< 2.0"],
                "patched_versions": ["1.4.9", "1.5.3"],
            }
        ],
        "web_evidence": [],
        "errors": [],
    }

    finding = validation_agent(state)["validated_findings"][0]
    assert finding["status"] == "validated"
    assert finding["affected"] is True


def test_semantic_retriever_surfaces_qdrant_failure():
    retriever = object.__new__(SemanticRetriever)
    retriever.embedding_service = MagicMock()
    retriever.embedding_service.embed.return_value = [0.1, 0.2]
    retriever.vector_store = MagicMock()
    retriever.vector_store.search.side_effect = [
        RuntimeError("filtered query failed"),
        RuntimeError("unfiltered query failed"),
    ]

    with pytest.raises(RuntimeError, match="failed after filtered and unfiltered"):
        retriever.search(query="Spring Boot")


def test_candidate_matching_uses_larger_ordered_pool(monkeypatch):
    vulnerabilities = [
        SimpleNamespace(
            vulnerability_id=f"CVE-2024-{index:04}",
            cve=f"CVE-2024-{index:04}",
            source="NVD",
            title="Spring Boot advisory",
            description="Spring Boot vulnerability",
            vendor="VMware",
            product="Spring Boot",
            affected_versions=["< 3.2.8"],
            patched_versions=["3.2.8"],
            cpe_matches=[],
            cvss=8.0,
            cvss_vector=None,
            epss=None,
            kev=False,
            exploit_available=False,
            references=[],
            updated=None,
        )
        for index in range(12)
    ]
    session = MagicMock()
    session.execute.return_value.scalars.return_value.all.return_value = vulnerabilities
    session_context = MagicMock()
    session_context.__enter__.return_value = session
    monkeypatch.setattr(
        "app.agents.vulnerability_matching.SessionLocal",
        lambda: session_context,
    )
    monkeypatch.setattr(
        "app.agents.vulnerability_matching.llm_service.is_configured",
        lambda: False,
    )
    monkeypatch.setattr(
        "app.agents.vulnerability_matching.settings.MAX_VALIDATION_CANDIDATES",
        100,
    )

    result = vulnerability_matching_agent(
        {
            "assets": [
                {
                    "name": "Spring Boot",
                    "vendor": "VMware",
                    "version": "3.2.5",
                }
            ],
            "errors": [],
        }
    )

    query = session.execute.call_args.args[0]
    assert query._limit_clause.value == 100
    assert query._order_by_clauses
    assert len(result["candidate_vulnerabilities"]) == 12


# Test 4: Insufficient internal evidence triggers Web Search Agent
def test_insufficient_evidence_triggers_web_search():
    candidate = create_sample_candidate()
    incomplete_evidence = {
        "cve": "CVE-2024-22243",
        "vulnerability_id": "CVE-2024-22243",
        "product": "Spring Boot",
        "description": "Short desc",
        "patched_versions": [],  # Missing patched version
        "exploit_available": None,  # Missing exploit info
    }

    assert evidence_is_sufficient(candidate, [incomplete_evidence]) is False

    state: CyberRAGState = {
        "candidate_vulnerabilities": [candidate],
        "internal_evidence": [incomplete_evidence],
    }

    decision = evidence_decision(state)
    assert decision == "web_search"


# Test 5: Conflicting evidence
def test_conflicting_evidence():
    state: CyberRAGState = {
        "assets": [{"name": "Spring Boot", "version": "3.2.5"}],
        "candidate_vulnerabilities": [create_sample_candidate()],
        "internal_evidence": [
            {
                "cve": "CVE-2024-22243",
                "vulnerability_id": "CVE-2024-22243",
                "vendor": "VMware",
                "product": "Spring Boot",
                "affected_versions": ["< 3.2.8"],
                "patched_versions": ["3.2.8"],
            }
        ],
        "web_evidence": [
            {
                "source_type": "vendor_advisory",
                "source": "ThirdPartyBlog",
                "url": "https://example.com/advisory",
                "cve": "CVE-2024-22243",
                "relevant_information": {"text_excerpt": "Claiming 3.2.5 is not affected"},
            }
        ],
        "errors": [],
    }

    val_res = validation_agent(state)
    assert len(val_res["validated_findings"]) == 1


# Test 6: Qdrant failure -> PostgreSQL Fallback
def test_qdrant_failure_fallback():
    mock_db = MagicMock()
    with patch("app.retrieval.service.SemanticRetriever") as MockSemantic:
        instance = MockSemantic.return_value
        instance.search.side_effect = Exception("Qdrant connection refused")

        retriever = VulnerabilityRetriever(mock_db)
        results, mode = retriever.retrieve_with_mode(query="Spring Boot")

        assert mode == "POSTGRESQL_FALLBACK"


# Test 7: Invalid API request -> HTTP 400
def test_invalid_api_request():
    response = client.post("/v1/assessment", json={"invalid": "payload"})
    assert response.status_code == 400


# Test 8: Agent failure handling
def test_workflow_failure_error_handling(monkeypatch):
    def fake_run_cyberrag(project_input):
        raise RuntimeError("Workflow failed unexpectedly")

    monkeypatch.setattr("app.api.routes.assessment.run_cyberrag", fake_run_cyberrag)

    response = client.post(
        "/v1/assessment",
        json={
            "project_input": {
                "name": "Test Failure Project",
                "technologies": [{"name": "Spring", "type": "framework"}],
            }
        },
    )
    assert response.status_code == 500
    assert "Assessment workflow failed" in response.json()["detail"]
