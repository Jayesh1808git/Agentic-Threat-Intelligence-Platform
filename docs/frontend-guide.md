# CyberRAG Frontend Integration Guide

This guide describes the backend contract currently implemented in this repository. It is the frontend integration reference; `api.md` describes planned endpoints and is not an accurate inventory of the current API.

## Backend Connection

- Local backend base URL: `http://localhost:8000`
- Assessment endpoint: `POST /api/v1/assessment`
- Assessment compatibility alias: `POST /v1/assessment`
- Health endpoint: `GET /health/`
- Vulnerability search: `GET` or `POST /retrieval/search`
- Interactive API documentation: `GET /docs`
- Authentication: none is currently required by these routes.

The assessment request runs synchronously. Keep the form in a loading state until the response arrives; it does not return a job ID or `202 Accepted`. Avoid submitting the same assessment repeatedly while one request is in progress.

## Assessment Input

The request body must contain a `project_input` object. `name` is required; `description` and `technologies` are optional. Each technology requires a `name` and can include the fields below.

```json
{
  "project_input": {
    "name": "Payments API",
    "description": "Customer payment service",
    "technologies": [
      {
        "name": "Spring Boot",
        "type": "framework",
        "version": "3.2.5",
        "vendor": "VMware",
        "ecosystem": "Maven",
        "criticality": "high",
        "business_impact": "high"
      },
      {
        "name": "PostgreSQL",
        "type": "database",
        "version": "15.4"
      }
    ]
  }
}
```

| Field | Type | Required | Notes |
|---|---|---:|---|
| `project_input` | object | Yes | Root request field. |
| `project_input.name` | string | Yes | Project or application name. |
| `project_input.description` | string or null | No | Free-text stack/context. Keep it focused on this project. |
| `project_input.technologies` | array | No | Defaults to an empty array. Structured technologies avoid unnecessary extraction ambiguity. |
| `technologies[].name` | string | Yes | Component/product name. |
| `technologies[].type` | string or null | No | Defaults to `technology`; examples include `framework`, `library`, `database`, and `application`. |
| `technologies[].version` | string or null | No | Exact installed version, when known. Do not guess. |
| `technologies[].vendor` | string or null | No | Vendor or maintainer, when known. |
| `technologies[].ecosystem` | string or null | No | Package ecosystem, if applicable. |
| `technologies[].criticality` | string or null | No | Common values: `critical`, `high`, `medium`, `low`. |
| `technologies[].business_impact` | string or null | No | Common values: `high`, `medium`, `low`. |

For best matching, provide exact component names and versions. Unknown versions may produce `needs_review` results instead of a deterministic affected/not-affected decision.

## Submit an Assessment

```ts
const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? "http://localhost:8000";

export async function submitAssessment(projectInput: {
  name: string;
  description?: string;
  technologies?: Array<{
    name: string;
    type?: string | null;
    version?: string | null;
    vendor?: string | null;
    ecosystem?: string | null;
    criticality?: string | null;
    business_impact?: string | null;
  }>;
}) {
  const response = await fetch(`${API_BASE_URL}/api/v1/assessment`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ project_input: projectInput }),
  });

  const body = await response.json();
  if (!response.ok) {
    const detail = body?.detail;
    throw new Error(typeof detail === "string" ? detail : JSON.stringify(detail ?? body));
  }

  return body as AssessmentResponse;
}
```

Use a UI-level request/loading state and show a recoverable error if `fetch` rejects or the response is not successful. If exposing server error details to users, sanitize them first; keep the raw response in developer diagnostics only.

## Assessment Response

A successful assessment returns HTTP `200` and this top-level shape:

```json
{
  "status": "completed",
  "retrieval_mode": "HYBRID",
  "project_name": "Payments API",
  "report": {},
  "findings": [],
  "errors": [],
  "llm_used": true,
  "fallback_used": false,
  "fallback_reason": null,
  "llm_call_count": 3,
  "rate_limit_count": 0,
  "retry_count": 0,
  "fallback_count": 0
}
```

| Field | Meaning |
|---|---|
| `status` | `completed`, `partial`, or `failed`. `partial` indicates PostgreSQL retrieval fallback. A generated report can still be present when LLM fallback is used. |
| `retrieval_mode` | Usually `HYBRID`; can be `POSTGRESQL_FALLBACK` if Qdrant/hybrid retrieval is unavailable. |
| `project_name` | Name from the submitted project input. |
| `report` | Structured report described below. |
| `findings` | Validated candidate findings. It can be empty. |
| `errors` | Workflow warnings/errors; may be empty even when deterministic LLM fallback was used. |
| `llm_used` | Whether at least one LLM request succeeded during this assessment. |
| `fallback_used` | Whether the run initialized in or transitioned to fallback behavior. |
| `fallback_reason` | Optional reason, such as `llm_disabled`, `llm_not_configured`, or `groq_rate_limit`. |
| `llm_call_count` | Number of provider request attempts made, including retry/fallback attempts. |
| `rate_limit_count` | Number of HTTP 429 responses observed. |
| `retry_count` | Number of bounded retry attempts. |
| `fallback_count` | Diagnostic fallback count; it is not a vulnerability or risk count. |

These LLM fields are operational metadata. Do not use them to determine vulnerability severity or assessment status.

### Finding Shape

Each item in `findings` is a validated finding. The most useful UI fields are:

```json
{
  "asset": { "name": "Spring Boot", "version": "3.2.5" },
  "vulnerability": "CVE-2024-22243",
  "vulnerability_id": "CVE-2024-22243",
  "cve": "CVE-2024-22243",
  "status": "validated",
  "affected": true,
  "confidence": 0.95,
  "identity_match": true,
  "product_match": true,
  "version_match": true,
  "patch_status": false,
  "source_corroborated": true,
  "reason": "Installed version falls within the affected range.",
  "affected_versions": ["< 3.2.8"],
  "patched_versions": ["3.2.8"],
  "cvss": 8.1,
  "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
  "epss": 0.45,
  "kev": false,
  "exploit_available": true,
  "evidence": []
}
```

`status` is `validated`, `not_affected`, or `needs_review`; `affected` can be `true`, `false`, or `null`. Render `needs_review` distinctly from confirmed findings. Scores and evidence may be `null` or empty when the source data does not provide them.

### Report Shape

`report` is a structured object, not a Markdown string. Its main fields are:

- `title`, `project_name`, `generated_at`, `executive_summary`, `retrieval_mode`
- `affected_assets`
- `confirmed_vulnerabilities`, `potential_vulnerabilities`, `not_applicable`
- `risk_assessments`, `recommendations`
- `markdown`

Use the structured arrays for UI tables/cards. The `markdown` field is available for a report/download view; render it with a Markdown renderer that sanitizes raw HTML. `risk_assessments` and `recommendations` can be empty when no finding qualifies for remediation/risk scoring.

A risk assessment contains fields such as `vulnerability_id`, `risk_score` (0–100), `risk_level` (`critical`, `high`, `medium`, `low`, `minimal`), `risk_factors`, and `rationale`. A recommendation contains `vulnerability_id`, `asset`, a nested `recommendation` object (action, target version, priority, description, mitigation), and references/evidence metadata.

## Error Handling

| HTTP status | Meaning | Frontend handling |
|---|---|---|
| `400` | Assessment input validation or a controlled `ValueError`. Validation errors use a `detail` array; other errors may use a string. | Keep entered data and show the relevant field/form error. |
| `500` | Assessment workflow raised an unexpected exception. Body includes `detail`. | Show a generic failure message and allow retry; do not display internal exception text as trusted guidance. |
| Network error | Backend unreachable, browser CORS rejection, or connection interrupted. | Show connection/retry state; the client may not be able to distinguish these cases. |

A deterministic LLM fallback is not necessarily an HTTP error. Check `fallback_used` and `fallback_reason`; the assessment can still complete with a report.

## Health and Vulnerability Search

### Health

`GET /health/` returns:

```json
{ "status": "running", "service": "CyberRAG" }
```

This endpoint confirms the API process is responding; it does not report database/vector-store health.

### Hybrid vulnerability search

Both methods use `/retrieval/search`.

GET example:

```http
GET /retrieval/search?q=Spring%20Boot&vendor=VMware&limit=5
```

Supported query parameters: `q` (required), `vendor`, `product`, `severity` (minimum CVSS score as a number), `source`, `kev`, `exploit_available`, and `limit` (1–100; default 20).

POST example:

```json
{
  "q": "Spring Boot CVE-2024-22243",
  "vendor": "VMware",
  "product": "Spring Boot",
  "severity": 7.0,
  "kev": false,
  "limit": 5
}
```

Response shape:

```json
{
  "query": "Spring Boot",
  "total": 1,
  "results": [
    {
      "id": "...",
      "vulnerability_id": "CVE-...",
      "source": "NVD",
      "cve": "CVE-...",
      "title": "...",
      "description": "...",
      "vendor": "...",
      "product": "...",
      "affected_versions": [],
      "patched_versions": [],
      "cvss": 8.1,
      "cvss_vector": "...",
      "epss": 0.45,
      "kev": false,
      "exploit_available": false,
      "references": [],
      "published": null,
      "updated": null,
      "semantic_score": null,
      "lexical_score": null,
      "final_score": 0.8,
      "retrieval_sources": ["lexical", "semantic"]
    }
  ]
}
```

## Browser/CORS Note

The current FastAPI app does not install CORS middleware. A browser app served from a different origin (for example, `localhost:5173` calling `localhost:8000`) may be blocked even though the API is healthy. For local development, use a frontend dev-server proxy or have the backend enable the frontend origin in CORS middleware. The `CORS_ORIGINS` setting alone does not enable CORS unless middleware reads it.

## Suggested Frontend Flow

1. Collect project name, optional description, and technology rows with exact versions where known.
2. Validate required `project_input.name` and each technology `name` before submitting.
3. Submit once and show a progress/loading state while the synchronous assessment runs.
4. Present overall `status` and `retrieval_mode`, then separate confirmed, potential, and not-applicable findings.
5. Show `risk_assessments` and remediation recommendations only when returned; do not infer a risk level from retrieval scores.
6. Offer the structured report and sanitized Markdown report as separate views/download options.
