import pytest
import requests
from pydantic import BaseModel, Field

from app.core.config import settings
from app.services.llm import LLMService, llm_service
from app.agents.vulnerability_matching import vulnerability_matching_agent
from app.agents.validation import validation_agent
from app.agents.technology_extraction import technology_extraction_agent
from app.schemas.agent_outputs import BatchValidationResult, BatchValidationItem
from app.schemas.agent_outputs import Asset, TechnologyExtractionResult


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

    with pytest.raises(RuntimeError) as exc_info:
        service.invoke_structured("Fail JSON test", SampleSecuritySchema)

    assert "JSON validation failed" in str(exc_info.value)
    assert call_count["count"] == 2  # Invoked twice (initial + 1 strict retry)


def test_candidate_limiting_and_batched_validation(monkeypatch):
    """Test capping 100 candidates to MAX_VALIDATION_CANDIDATES and performing 1 batched LLM call."""
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
    # Exactly 1 batched LLM call executed!
    assert llm_calls["count"] == 1


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
    monkeypatch.setattr("app.agents.technology_extraction.llm_service", service)
    monkeypatch.setattr(requests, "post", fake_post)
    monkeypatch.setattr("app.services.llm.time.sleep", delays.append)

    result = technology_extraction_agent(
        {"project_input": {"description": "A Python 3.12 service using FastAPI 0.115.0."}}
    )

    assert [asset["name"] for asset in result["assets"]] == ["FastAPI", "Python"]
    assert calls == [settings.TECHNOLOGY_EXTRACTION_MODEL] * 2
    assert len(delays) == 1
    assert delays[0] <= 10


def test_technology_extraction_works_when_llm_disabled(monkeypatch):
    service = LLMService()
    service.enabled = False
    monkeypatch.setattr("app.agents.technology_extraction.llm_service", service)

    result = technology_extraction_agent(
        {"project_input": {"description": "A Django 5.0 app backed by PostgreSQL 16."}}
    )

    assert {asset["name"] for asset in result["assets"]} == {"Django", "PostgreSQL"}
