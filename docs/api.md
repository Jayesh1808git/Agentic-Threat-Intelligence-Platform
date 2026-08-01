# CyberRAG — API Reference (Planned)

Base URL: `/api/v1`
Auth: Bearer API key (per `User.api_key`) unless noted otherwise.

---

### `GET /health`
Health check for service and its dependencies.

**Response 200**
```json
{
  "status": "ok",
  "postgres": "ok",
  "qdrant": "ok",
  "neo4j": "ok",
  "last_ingestion": "2026-08-01T09:00:00Z"
}
```

---

### `GET /search`
Hybrid search (semantic + BM25 + graph) over the vulnerability knowledge base.

**Query params**
| Param | Type | Description |
|---|---|---|
| q | string, required | free-text query |
| vendor | string, optional | filter by vendor |
| product | string, optional | filter by product |
| severity | string, optional | low/medium/high/critical |
| limit | int, optional | default 20 |

**Response 200**
```json
{
  "results": [
    {
      "vuln_id": "CVE-2025-XXXXX",
      "vendor": "Apache",
      "product": "Log4j",
      "severity": "critical",
      "cvss_score": 9.8,
      "epss_score": 0.94,
      "cisa_kev": true,
      "score": 0.91
    }
  ]
}
```

---

### `GET /cve/{id}`
Retrieve full unified-schema record for a single vulnerability.

**Path params**
- `id` — CVE/GHSA/etc. identifier

**Response 200**
```json
{
  "vuln_id": "CVE-2025-XXXXX",
  "source": "NVD",
  "vendor": "Apache",
  "product": "Log4j",
  "affected_versions": ["2.0", "2.14.1"],
  "patched_versions": ["2.15.0"],
  "severity": "critical",
  "cvss_score": 9.8,
  "epss_score": 0.94,
  "cisa_kev": true,
  "exploit_available": true,
  "references": ["https://nvd.nist.gov/vuln/detail/CVE-2025-XXXXX"],
  "published_at": "2025-12-01T00:00:00Z",
  "updated_at": "2026-01-10T00:00:00Z"
}
```

**Response 404** — vulnerability not found.

---

### `POST /upload-assets`
Submit an organization's technology stack for extraction and future matching. Accepts an SBOM file, repo URL, or free-text stack description.

**Request body**
```json
{
  "organization_id": "uuid",
  "source_type": "sbom | repo_url | manual",
  "sbom_file": "base64 or multipart upload",
  "repo_url": "https://github.com/org/repo",
  "manual_stack": ["python 3.11", "fastapi 0.110", "postgresql 15"]
}
```

**Response 202**
```json
{
  "extraction_job_id": "uuid",
  "status": "processing"
}
```

---

### `POST /query`
Natural-language question answered by the multi-agent pipeline (e.g. "Are we affected by CVE-2025-XXXXX?").

**Request body**
```json
{
  "organization_id": "uuid",
  "question": "Are we affected by CVE-2025-XXXXX?"
}
```

**Response 200**
```json
{
  "answer": "Yes, 2 assets are affected: log4j 2.14.1 (payments-service), log4j 2.13.0 (auth-service).",
  "affected_assets": ["uuid1", "uuid2"],
  "confidence": 0.93,
  "citations": ["https://nvd.nist.gov/vuln/detail/CVE-2025-XXXXX"]
}
```

---

### `POST /report`
Trigger generation of a full risk/remediation report for an organization.

**Request body**
```json
{
  "organization_id": "uuid",
  "report_type": "executive | technical | full_assessment"
}
```

**Response 202**
```json
{
  "report_job_id": "uuid",
  "status": "generating"
}
```

**Once complete (via polling or webhook), returns:**
```json
{
  "report_id": "uuid",
  "risk_score": 78.4,
  "priority_ranking": [
    {"vuln_id": "CVE-2025-XXXXX", "rank": 1, "reason": "CISA KEV + critical severity + internet-facing asset"}
  ],
  "remediation_summary": "Upgrade log4j to 2.17.1 across affected services...",
  "citations": ["..."]
}
```

---

## Notes
- All endpoints are planned/future-state; none are implemented yet.
- Long-running operations (`/upload-assets`, `/report`) are async — they return a job ID that should be polled or resolved via webhook.
- Future versions may add `GET /assets/{organization_id}`, `GET /reports/{id}`, and `DELETE /assets/{id}`.