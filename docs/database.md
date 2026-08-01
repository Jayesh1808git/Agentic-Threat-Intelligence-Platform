# CyberRAG — Database Design

This document defines the core entities used across the PostgreSQL relational store, the Qdrant vector store, and the Neo4j knowledge graph. PostgreSQL holds the structured system-of-record; Qdrant holds embeddings keyed to the same IDs; Neo4j mirrors the relationships between entities.

## Entities

### ThreatFeed
Represents a configured source of threat intelligence and its ingestion state.

| Field | Type | Notes |
|---|---|---|
| id | UUID (PK) | |
| name | string | e.g. "NVD", "CISA KEV", "GitHub Security Advisories" |
| source_type | enum | nvd, mitre_cve, cisa_kev, epss, github_advisory, osv, exploitdb, opencve, vendor_bulletin |
| vendor | string, nullable | populated for vendor-specific feeds |
| url / endpoint | string | source API or feed URL |
| ingestion_mode | enum | streaming, scheduled |
| polling_interval | interval, nullable | for scheduled feeds |
| last_ingested_at | timestamp | |
| status | enum | active, paused, error |
| created_at / updated_at | timestamp | |

### Vulnerability
The unified schema representation of a vulnerability, regardless of originating feed.

| Field | Type | Notes |
|---|---|---|
| id | UUID (PK) | |
| vuln_id | string | CVE ID, GHSA ID, etc. (unique per source) |
| source_feed_id | UUID (FK → ThreatFeed) | |
| vendor | string | |
| product | string | |
| affected_versions | string[] / range | |
| patched_versions | string[] / range | |
| severity | enum | low, medium, high, critical |
| cvss_score | float | |
| cvss_vector | string, nullable | |
| epss_score | float, nullable | |
| cisa_kev | boolean | actively exploited per CISA KEV |
| exploit_available | boolean | |
| description | text | |
| references | string[] | URLs to advisories/patches |
| published_at | timestamp | |
| updated_at | timestamp | |
| embedding_id | UUID, nullable | pointer to Qdrant vector record |

### OrganizationAsset
Represents a piece of an organization's technology stack (from repo scan, SBOM, or manual input) that vulnerabilities are matched against.

| Field | Type | Notes |
|---|---|---|
| id | UUID (PK) | |
| organization_id | UUID (FK → User/Org) | |
| asset_type | enum | language, framework, library, database, cloud_service, os, dependency |
| name | string | e.g. "log4j", "PostgreSQL", "Ubuntu" |
| version | string | |
| source | enum | sbom, repo_scan, manual, uploaded_doc |
| criticality | enum | low, medium, high, critical (business impact weighting) |
| discovered_at | timestamp | |
| updated_at | timestamp | |

### ThreatReport
A generated output of the multi-agent pipeline for a given organization or query.

| Field | Type | Notes |
|---|---|---|
| id | UUID (PK) | |
| organization_id | UUID (FK → User/Org) | |
| report_type | enum | executive, technical, single_cve, full_assessment |
| related_vulnerabilities | UUID[] (FK → Vulnerability) | |
| related_assets | UUID[] (FK → OrganizationAsset) | |
| risk_score | float | aggregate organizational risk score |
| priority_ranking | jsonb | ordered list of vulnerabilities with rationale |
| remediation_summary | text | |
| citations | jsonb | evidence references used to generate the report |
| generated_by_agent_version | string | for auditability |
| created_at | timestamp | |

### User
Represents an account/organization accessing the platform.

| Field | Type | Notes |
|---|---|---|
| id | UUID (PK) | |
| organization_name | string | |
| email | string, unique | |
| password_hash | string | |
| role | enum | admin, analyst, viewer |
| api_key | string, nullable | for programmatic access |
| created_at / updated_at | timestamp | |

## Cross-Store Notes

- **PostgreSQL** is the source of truth for all entities above.
- **Qdrant** stores vector embeddings for `Vulnerability.description` (and optionally `ThreatReport` summaries) keyed by `embedding_id`, enabling semantic retrieval.
- **Neo4j** mirrors relationships such as `(Vendor)-[:PRODUCES]->(Product)`, `(Product)-[:AFFECTED_BY]->(Vulnerability)`, `(OrganizationAsset)-[:MATCHES]->(Vulnerability)`, and `(Vulnerability)-[:EXPLOITED_BY]->(ExploitReference)`, enabling multi-hop reasoning (e.g. transitive dependency exposure).