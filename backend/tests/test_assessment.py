from fastapi.testclient import TestClient

from app.main import app
from app.api.routes import assessment


client = TestClient(app)


VALID_REQUEST = {
    "project_input": {
        "name": "Test Project",
        "technologies": [
            {
                "name": "Campaign",
                "type": "application",
                "version": "7.4.2",
                "vendor": "adobe",
                "ecosystem": "enterprise",
                "criticality": "high",
                "business_impact": "high",
            }
        ],
    }
}


def test_assessment_success(monkeypatch):
    def fake_run_cyberrag(project_input):
        return {
            "report": {
                "title": "Test Report"
            },
            "validated_findings": [],
            "errors": [],
        }

    monkeypatch.setattr(
        assessment,
        "run_cyberrag",
        fake_run_cyberrag,
    )

    response = client.post(
        "/v1/assessment",
        json=VALID_REQUEST,
    )

    assert response.status_code == 200

    data = response.json()

    assert data["status"] == "completed"
    assert data["project_name"] == "Test Project"
    assert data["report"]["title"] == "Test Report"


def test_assessment_invalid_request():
    response = client.post(
        "/v1/assessment",
        json={
            "project_input": {}
        },
    )

    assert response.status_code == 400


def test_api_v1_assessment_invalid_request():
    response = client.post(
        "/api/v1/assessment",
        json={},
    )

    assert response.status_code == 400


def test_assessment_workflow_failure(monkeypatch):
    def fake_run_cyberrag(project_input):
        raise RuntimeError("Test workflow failure")

    monkeypatch.setattr(
        assessment,
        "run_cyberrag",
        fake_run_cyberrag,
    )

    response = client.post(
        "/v1/assessment",
        json=VALID_REQUEST,
    )

    assert response.status_code == 500

    data = response.json()

    assert "Assessment workflow failed" in data["detail"]


def test_assessment_returns_llm_fallback_metadata(monkeypatch):
    monkeypatch.setattr(
        assessment,
        "run_cyberrag",
        lambda project_input: {
            "report": {},
            "validated_findings": [],
            "errors": [],
            "llm_metadata": {
                "llm_used": False,
                "fallback_used": True,
                "fallback_reason": "groq_rate_limit",
                "llm_call_count": 2,
                "rate_limit_count": 2,
                "retry_count": 1,
                "fallback_count": 1,
            },
        },
    )

    response = client.post("/api/v1/assessment", json=VALID_REQUEST)

    assert response.status_code == 200
    assert response.json()["llm_used"] is False
    assert response.json()["fallback_reason"] == "groq_rate_limit"
    assert response.json()["retry_count"] == 1