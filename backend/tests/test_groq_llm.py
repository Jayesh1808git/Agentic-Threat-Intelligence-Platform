from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
import requests
from pydantic import BaseModel, Field

from app.core.config import settings
from app.services.llm import LLMService, llm_service
from app.agents.vulnerability_matching import vulnerability_matching_agent
from app.agents.validation import validation_agent
from app.agents.technology_extraction import technology_extraction_agent
from app.agents.risk_assessment import risk_assessment_agent
from app.agents.report import report_agent
from app.schemas.agent_outputs import (
    AssessmentReport,
    BatchValidationResult,
    BatchValidationItem,
    RiskRecommendationItem,
    RiskRecommendationResult,
)
from app.schemas.agent_outputs import (
    Asset,
    TechnologyExtractionResult,
    VulnerabilityMatchResult,
)


class SampleSecuritySchema(BaseModel):
    summary: str = Field(description="Summary of analysis")
    confidence: float = Field(description="Confidence score between 0.0 and 1.0")
    threat_level: str = Field(description="Threat level: low, medium, high, critical")


class FakeResponse:
    def __init__(self, status_code, text_content, json_content=None, headers=None):
        self.status_code = status_code
        self.text = text_content
        self._json = json_content or {}
        self.headers = headers or {}

    def json(self):
        return self._json


def test_groq_service_configuration():
    """Test LLM service configuration check."""
    service = LLMService()
    assert service.provider == settings.LLM_PROVIDER.lower()
    if settings.GROQ_API_KEY:
        assert service.is_configured() is True


def test_groq_llm_invoke_text():
    """Test text invocation against configured LLM service."""
    if not llm_service.is_configured():
        pytest.skip("Groq API key not configured")

    response = llm_service.invoke(
        prompt="Reply with the single word: ACKNOWLEDGED",
        json_output=False,
    )
    assert isinstance(response, str)
    assert len(response.strip()) > 0


def test_groq_llm_invoke_json():
    """Test JSON response invocation."""
    if not llm_service.is_configured():
        pytest.skip("Groq API key not configured")

    response = llm_service.invoke(
        prompt="Respond with JSON containing 'status': 'ok' and 'service': 'groq'",
        json_output=True,
    )
    assert isinstance(response, str)
    assert "status" in response or "ok" in response


def test_groq_llm_invoke_structured():
    """Test structured Pydantic model parsing via Groq API."""
    if not llm_service.is_configured():
        pytest.skip("Groq API key not configured")

    result: SampleSecuritySchema = llm_service.invoke_structured(
        prompt="Analyze a scenario with high risk vulnerability CVE-2024-12345.",
        response_model=SampleSecuritySchema,
        system_prompt="You are a security analyst.",
    )
    assert isinstance(result, SampleSecuritySchema)
    assert hasattr(result, "summary")
    assert hasattr(result, "confidence")
    assert hasattr(result, "threat_level")
    assert 0.0 <= result.confidence <= 1.0


def test_invoke_structured_uses_json_schema_override(monkeypatch):
    service = LLMService()
    captured = {}
    expected_json = (
        '{"candidate_evaluations":[{"vulnerability_id":"CVE-2024-12345",'
        '"match_confidence":0.9,"reason":"Product matches."}]}'
    )

    def fake_invoke(**kwargs):
        captured.update(kwargs)
        return expected_json

    monkeypatch.setattr(service, "invoke", fake_invoke)
    schema_override = VulnerabilityMatchResult.model_json_schema_for_llm()

    result = service.invoke_structured(
        prompt="Evaluate the candidate.",
        response_model=VulnerabilityMatchResult,
        json_schema_override=schema_override,
    )

    assert result.candidate_evaluations[0].vulnerability_id == "CVE-2024-12345"
    assert '"candidate_evaluations"' in captured["system_prompt"]
    assert '"candidate_vulnerabilities"' not in captured["system_prompt"]


def test_rate_limit_backoff_and_fallback(monkeypatch):
    """Test 429 -> exponential backoff retries -> fallback model switch."""
    call_log = []

    def fake_post(url, headers, json, timeout):
        model = json.get("model", "")
        call_log.append(model)
        if model == settings.GROQ_MODEL:
            # Primary model returns 429 Rate Limit
            return FakeResponse(429, '{"error":{"message":"Rate limit reached"}}', headers={"Retry-After": "0.1"})
        else:
            # Fallback model succeeds
            return FakeResponse(
                200,
                "",
                {"choices": [{"message": {"content": '{"summary": "Fallback ok", "confidence": 0.9, "threat_level": "medium"}'}}]},
            )

    monkeypatch.setattr(requests, "post", fake_post)

    service = LLMService()
    service.groq_api_key = "fake_key"
    service.base_delay = 0.05
    service.max_delay = 0.1
    service.cache_enabled = False

    res = service.invoke("Test rate limit backoff prompt", json_output=True)
    assert isinstance(res, str)
    # Primary model called max_retries+1 times, then fallback model called once
    assert call_log.count(settings.GROQ_MODEL) == service.max_retries + 1
    assert call_log.count(settings.GROQ_FALLBACK_MODEL) >= 1


def test_fallback_rate_limit_does_not_cycle_models(monkeypatch):
    call_log = []

    def fake_post(url, headers, json, timeout):
        call_log.append(json["model"])
        return FakeResponse(429, '{"error":{"message":"rate limit"}}', headers={"Retry-After": "30"})

    monkeypatch.setattr(requests, "post", fake_post)
    monkeypatch.setattr("app.services.llm.time.sleep", lambda delay: None)
    service = LLMService()
    service.groq_api_key = "fake_key"
    service.enabled = True
    service.min_request_interval = 0
    service.cache_enabled = False

    with pytest.raises(RuntimeError, match="rate limit"):
        service.invoke("bounded retry test", json_output=False)

    assert call_log == [settings.GROQ_MODEL, settings.GROQ_MODEL, settings.GROQ_FALLBACK_MODEL]
    assert service.metrics_snapshot()["retry_count"] == 1
    assert service.metrics_snapshot()["rate_limit_count"] == 3


def test_context_length_exceeded_compaction(monkeypatch):
    """Test 400 context_length_exceeded / 413 -> automatic prompt compaction."""
    call_log = []

    def fake_post(url, headers, json, timeout):
        messages = json.get("messages", [])
        content_len = len(messages[-1].get("content", "")) if messages else 0
        call_log.append(content_len)

        if content_len > 5000:
            return FakeResponse(400, '{"error":{"message":"Please reduce context_length_exceeded"}}')
        return FakeResponse(200, "", {"choices": [{"message": {"content": '{"status": "compacted_ok"}'}}]})

    monkeypatch.setattr(requests, "post", fake_post)

    service = LLMService()
    service.groq_api_key = "fake_key"
    service.cache_enabled = False
    service.max_input_chars = 12000

    huge_prompt = "A" * 10000
    res = service.invoke(prompt=huge_prompt, json_output=True)
    assert "compacted_ok" in res
    assert len(call_log) >= 2
    assert call_log[0] > 5000
    assert call_log[-1] <= 6000


def test_json_validation_retry_and_fallback(monkeypatch):
    """Test structured output JSON failure -> retries once -> falls back gracefully."""
    call_count = {"count": 0}

    def fake_post(url, headers, json, timeout):
        call_count["count"] += 1
        # Return non-JSON invalid string
        return FakeResponse(200, "", {"choices": [{"message": {"content": "This is invalid non-json string"}}]})

    monkeypatch.setattr(requests, "post", fake_post)

    service = LLMService()
    service.groq_api_key = "fake_key"
    service.cache_enabled = False

    with pytest.raises(RuntimeError) as exc_info:
        service.invoke_structured("Fail JSON test", SampleSecuritySchema)

    assert "JSON validation failed" in str(exc_info.value)
    assert call_count["count"] == 2  # Invoked twice (initial + 1 strict retry)


def test_candidate_limiting_and_deterministic_validation(monkeypatch):
    """Conclusive version checks should not use an LLM call."""
    llm_calls = {"count": 0}

    def fake_post(url, headers, json, timeout):
        llm_calls["count"] += 1
        batch_response = {
            "results": [
                {
                    "vulnerability_id": f"CVE-2024-100{i}",
                    "applicable": True if i % 2 == 0 else False,
                    "confidence": 0.95,
                    "reason": "Batched reasoning result"
                }
                for i in range(10)
            ]
        }
        import json as json_lib
        return FakeResponse(200, "", {"choices": [{"message": {"content": json_lib.dumps(batch_response)}}]})

    monkeypatch.setattr(requests, "post", fake_post)
    monkeypatch.setattr(llm_service, "cache_enabled", False)

    # 1. Generate 25 candidate vulnerabilities
    raw_candidates = [
        {
            "vulnerability_id": f"CVE-2024-100{i}",
            "cve": f"CVE-2024-100{i}",
            "product": "Spring Boot",
            "vendor": "VMware",
            "asset": {"name": "Spring Boot", "version": "3.2.5"},
            "asset_version": "3.2.5",
            "match_confidence": 0.8,
            "cvss": 8.5,
            "epss": 0.5,
            "kev": False,
            "exploit_available": True,
            "affected_versions": ["< 3.2.8"],
            "patched_versions": ["3.2.8"],
        }
        for i in range(25)
    ]

    state = {
        "candidate_vulnerabilities": raw_candidates,
        "assets": [{"name": "Spring Boot", "version": "3.2.5"}],
        "internal_evidence": [],
        "web_evidence": [],
        "errors": [],
    }

    val_res = validation_agent(state)
    validated_findings = val_res["validated_findings"]

    # Candidate limiting checked (max 10 validated findings returned)
    assert len(validated_findings) <= settings.MAX_VALIDATION_CANDIDATES
    assert llm_calls["count"] == 0


def test_vulnerability_matching_keeps_low_scores_and_balances_assets(monkeypatch):
    def make_vulnerability(vulnerability_id, product, affected_versions):
        return SimpleNamespace(
            vulnerability_id=vulnerability_id,
            cve=vulnerability_id,
            source="NVD",
            title=f"{product} advisory",
            description=f"Vulnerability affecting {product}",
            vendor="VMware",
            product=product,
            affected_versions=affected_versions,
            patched_versions=[],
            cpe_matches=[],
            cvss=7.0,
            cvss_vector=None,
            epss=None,
            kev=False,
            exploit_available=False,
            references=[],
            updated=None,
        )

    query_results = [
        [
            make_vulnerability("CVE-2026-41707", "spring_security", ["< 6.5.12"]),
            make_vulnerability("CVE-2025-10001", "Unrelated VMware product", ["< 1.0"]),
        ],
        [
            make_vulnerability("CVE-2025-10002", "Spring Boot", ["< 3.2.8"]),
            make_vulnerability("CVE-2025-10003", "Another unrelated product", ["< 1.0"]),
        ],
    ]
    session = MagicMock()
    session.execute.side_effect = [
        MagicMock(scalars=MagicMock(return_value=MagicMock(all=MagicMock(return_value=rows))))
        for rows in query_results
    ]
    session_context = MagicMock()
    session_context.__enter__.return_value = session
    monkeypatch.setattr(
        "app.agents.vulnerability_matching.SessionLocal",
        lambda: session_context,
    )
    monkeypatch.setattr(
        "app.agents.vulnerability_matching.settings.MAX_VALIDATION_CANDIDATES",
        4,
    )
    monkeypatch.setattr(
        "app.agents.vulnerability_matching.llm_service.is_configured",
        lambda: True,
    )
    matching_calls = []

    def fake_matching_call(**kwargs):
        matching_calls.append(kwargs)
        return SimpleNamespace(
            candidate_evaluations=[
                SimpleNamespace(
                    vulnerability_id="CVE-2026-41707",
                    cve="CVE-2026-41707",
                    match_confidence=0.1,
                    reason="Low confidence, but should still be validated.",
                ),
                SimpleNamespace(
                    vulnerability_id="CVE-2025-10002",
                    cve="CVE-2025-10002",
                    match_confidence=0.9,
                    reason="Spring Boot product match.",
                ),
            ],
            candidate_vulnerabilities=[],
        )

    monkeypatch.setattr(
        "app.agents.vulnerability_matching.llm_service.invoke_structured",
        fake_matching_call,
    )

    assets = [
        {"name": "spring_security", "vendor": "vmware", "version": "6.5.11"},
        {"name": "Spring Boot", "vendor": "VMware", "version": "3.2.5"},
    ]
    result = vulnerability_matching_agent({"assets": assets, "errors": []})

    candidates = result["candidate_vulnerabilities"]
    assert len(matching_calls) == 1
    assert "spring_security" in matching_calls[0]["prompt"]
    assert "Spring Boot" in matching_calls[0]["prompt"]
    assert {candidate["asset"]["name"] for candidate in candidates} == {
        "spring_security",
        "Spring Boot",
    }
    low_score_candidate = next(
        candidate
        for candidate in candidates
        if candidate["vulnerability_id"] == "CVE-2026-41707"
    )
    assert low_score_candidate["match_confidence"] == 0.1

    validation_result = validation_agent(
        {
            "candidate_vulnerabilities": candidates,
            "assets": assets,
            "internal_evidence": [],
            "web_evidence": [],
            "errors": [],
        }
    )
    findings = {
        finding["vulnerability_id"]: finding
        for finding in validation_result["validated_findings"]
    }
    assert findings["CVE-2026-41707"]["status"] == "validated"
    assert findings["CVE-2025-10002"]["status"] == "validated"
    assert findings["CVE-2025-10001"]["status"] == "not_affected"
    assert findings["CVE-2025-10003"]["status"] == "not_affected"
    assert "does not match" in findings["CVE-2025-10001"]["reason"]


def test_report_agent_uses_enabled_llm(monkeypatch):
    monkeypatch.setattr("app.agents.report.settings.REPORT_LLM_ENABLED", True)
    calls = []
    expected = AssessmentReport(
        executive_summary="One confirmed issue was found.",
        markdown="# Security assessment",
    )
    monkeypatch.setattr(
        "app.agents.report.llm_service.invoke_structured",
        lambda **kwargs: calls.append(kwargs) or expected,
    )

    result = report_agent(
        {
            "project_input": {"name": "Claims Access API"},
            "assets": [],
            "validated_findings": [],
            "risk_assessments": [],
            "recommendations": [],
            "errors": [],
        }
    )

    assert len(calls) == 1
    assert calls[0]["agent_name"] == "report"
    assert result["report"]["executive_summary"] == expected.executive_summary
    assert result["report"]["markdown"] == expected.markdown


def test_validation_batches_only_ambiguous_candidates(monkeypatch):
    calls = []
    expected = BatchValidationResult(results=[
        BatchValidationItem(
            vulnerability_id="CVE-2024-ambiguous",
            applicable=True,
            confidence=0.9,
            reason="Ambiguous version was assessed by the LLM.",
        )
    ])
    monkeypatch.setattr(llm_service, "is_configured", lambda: True)
    monkeypatch.setattr(
        llm_service,
        "invoke_structured",
        lambda **kwargs: calls.append(kwargs) or expected,
    )
    deterministic_candidate = {
        "vulnerability_id": "CVE-2024-deterministic",
        "product": "Spring Boot",
        "vendor": "VMware",
        "asset": {"name": "Spring Boot", "version": "3.2.5"},
        "asset_version": "3.2.5",
        "affected_versions": ["< 3.2.8"],
        "patched_versions": ["3.2.8"],
    }
    ambiguous_candidate = {
        **deterministic_candidate,
        "vulnerability_id": "CVE-2024-ambiguous",
        "asset_version": "custom-build",
    }

    result = validation_agent({
        "candidate_vulnerabilities": [deterministic_candidate, ambiguous_candidate],
        "assets": [{"name": "Spring Boot", "version": "custom-build"}],
        "internal_evidence": [],
        "web_evidence": [],
        "errors": [],
    })

    assert len(calls) == 1
    assert "CVE-2024-ambiguous" in calls[0]["prompt"]
    assert "CVE-2024-deterministic" not in calls[0]["prompt"]
    assert len(result["validated_findings"]) == 2


def test_risk_and_recommendations_use_one_llm_call_and_code_scores(monkeypatch):
    calls = []
    expected = RiskRecommendationResult(results=[
        RiskRecommendationItem(
            finding_key=f"finding_{index}",
            rationale=f"Reasoning for finding {index}.",
            recommendation={
                "action": "upgrade",
                "target_version": "invented-version",
                "description": f"Remediate finding {index}.",
                "mitigation": "Use the verified vendor patch.",
            },
        )
        for index in range(3)
    ])
    monkeypatch.setattr(llm_service, "is_configured", lambda: True)
    monkeypatch.setattr(
        llm_service,
        "invoke_structured",
        lambda **kwargs: calls.append(kwargs) or expected,
    )
    findings = [
        {
            "vulnerability_id": f"CVE-2024-{index}",
            "status": "validated",
            "affected": True,
            "asset": {"name": "Spring Boot", "version": "3.2.5"},
            "cvss": 8.0,
            "epss": 0.5,
            "kev": False,
            "exploit_available": True,
            "patched_versions": ["3.2.8"],
            "evidence": [],
        }
        for index in range(3)
    ]

    result = risk_assessment_agent({
        "validated_findings": findings,
        "assets": [],
        "web_evidence": [],
        "errors": [],
    })

    assert len(calls) == 1
    assert calls[0]["model"] == settings.LIGHTWEIGHT_LLM_MODEL
    assert len(result["risk_assessments"]) == 3
    assert len(result["recommendations"]) == 3
    assert all(item["risk_score"] == 59.5 for item in result["risk_assessments"])
    assert all(item["rationale"].startswith("Reasoning for finding") for item in result["risk_assessments"])
    assert all(item["recommendation"]["target_version"] == "3.2.8" for item in result["recommendations"])


def test_llm_response_cache_skips_repeated_provider_request(monkeypatch, tmp_path):
    calls = []

    def fake_post(url, headers, json, timeout):
        calls.append(json)
        return FakeResponse(200, "", {"choices": [{"message": {"content": '{"status":"ok"}'}}]})

    monkeypatch.setattr(requests, "post", fake_post)
    service = LLMService()
    service.groq_api_key = "fake_key"
    service.cache_enabled = True
    service.cache_dir = tmp_path
    service.min_request_interval = 0

    first = service.invoke("cache this response", system_prompt="test")
    second = service.invoke("cache this response", system_prompt="test")

    assert first == second
    assert len(calls) == 1


def test_technology_extraction_llm_success_uses_dedicated_model(monkeypatch):
    expected = TechnologyExtractionResult(assets=[Asset(name="FastAPI", version="0.115.0")])
    calls = []

    monkeypatch.setattr(llm_service, "is_configured", lambda: True)
    monkeypatch.setattr(
        llm_service,
        "invoke_structured",
        lambda **kwargs: calls.append(kwargs) or expected,
    )

    result = technology_extraction_agent({"project_input": {"description": "A proprietary internal service."}})

    assert result["assets"][0]["name"] == "FastAPI"
    assert calls[0]["model"] == settings.TECHNOLOGY_EXTRACTION_MODEL


def test_technology_extraction_429_falls_back_deterministically(monkeypatch):
    calls = []
    delays = []

    def fake_post(url, headers, json, timeout):
        calls.append(json["model"])
        return FakeResponse(429, '{"error":{"message":"rate limit"}}', headers={"Retry-After": "30"})

    service = LLMService()
    service.groq_api_key = "fake_key"
    service.enabled = True
    service.min_request_interval = 0
    monkeypatch.setattr("app.agents.technology_extraction.llm_service", service)
    monkeypatch.setattr(requests, "post", fake_post)
    monkeypatch.setattr("app.services.llm.time.sleep", delays.append)

    result = technology_extraction_agent(
        {"project_input": {"description": "A Python 3.12 service using FastAPI 0.115.0."}}
    )

    assert [asset["name"] for asset in result["assets"]] == ["FastAPI", "Python"]
    assert calls == [settings.TECHNOLOGY_EXTRACTION_MODEL] * 2
    assert len(delays) == 1
    assert 30 <= delays[0] <= 60


def test_technology_extraction_works_when_llm_disabled(monkeypatch):
    service = LLMService()
    service.enabled = False
    monkeypatch.setattr("app.agents.technology_extraction.llm_service", service)

    result = technology_extraction_agent(
        {"project_input": {"description": "A Django 5.0 app backed by PostgreSQL 16."}}
    )

    assert {asset["name"] for asset in result["assets"]} == {"Django", "PostgreSQL"}
