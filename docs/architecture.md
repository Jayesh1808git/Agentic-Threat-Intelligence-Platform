# CyberRAG — Architecture

## Project Objective

CyberRAG is an agentic threat intelligence and vulnerability intelligence platform. Instead of answering questions from a static document set like a conventional RAG system, it continuously ingests live vulnerability and exploit data from public and vendor sources, normalizes it into a unified schema, and uses a multi-agent AI pipeline to determine whether a given organization's technology stack is affected by newly disclosed vulnerabilities — then explains why, how severe the exposure is, and what to do about it.

The objective is to replace manual vulnerability triage (analysts reading advisories and cross-referencing them against internal asset inventories by hand) with a continuously running, explainable, evidence-cited AI system.

## Current Implementation

- **Scheduled incremental ingestion** from the configured NVD, CISA KEV, EPSS, GitHub Advisory, and OSV connectors
- **Vendor data normalization** into one unified vulnerability schema
- **Hybrid retrieval** combining PostgreSQL text search and Qdrant dense semantic search with Reciprocal Rank Fusion (RRF)
- **Multi-agent decision making** — specialized agents for extraction, matching, retrieval, validation, risk scoring, remediation, and reporting
- **Organizational vulnerability assessment** — accepts a stack description or structured technology list
- **Automated risk prioritization** using CVSS, EPSS, CISA KEV status, exploit availability, and business/asset context
- **Structured security reports** with finding evidence and remediation recommendations

BM25, Neo4j graph traversal, Kafka streaming, and repository/SBOM scanning are not part of the active request pipeline described below.

## Components

### 1. Ingestion Layer
Pulls data from all configured threat intelligence sources on a continuous or scheduled basis (Kafka streaming for production-scale deployments, cron-based polling for smaller ones).

### 2. Normalization Engine
Converts every heterogeneous advisory format into the Unified Vulnerability Schema (see `database.md`) so all downstream components operate on one consistent structure regardless of source.

### 3. Storage Layer
- **PostgreSQL** — authoritative vulnerability records
- **Qdrant (Vector DB)** — derived semantic vectors, synchronized by the embedding worker
- Neo4j settings exist, but graph retrieval is not currently wired into the active assessment or retrieval path.

### 4. Hybrid Retrieval Layer
The active retriever combines two result sets with RRF:
- PostgreSQL text matching, including exact CVE/GHSA identifiers and `ILIKE` field matching (not BM25)
- Dense embedding similarity search in Qdrant, with record details hydrated from PostgreSQL

### 5. Multi-Agent Analysis Layer (LangGraph-orchestrated)
- **Technology Extraction Agent** — parses project descriptions, repos, SBOMs, and documents to identify the org's tech stack
- **Vulnerability Matching Agent** — searches PostgreSQL for candidates by technology/vendor text
- **Internal Retrieval Agent** — retrieves candidate evidence using the PostgreSQL/Qdrant retriever
- **Web Search Agent** — conditionally gathers external evidence when internal evidence is incomplete
- **Validation Agent** — cross-checks findings across sources to reduce false positives/hallucinations
- **Risk Assessment Agent** — scores confirmed findings and creates remediation recommendations
- **Report Generation Agent** — produces cited executive and technical reports

### 6. API & Dashboard Layer
FastAPI backend exposing programmatic access (see `api.md`); Next.js (or Streamlit) frontend for interactive use.

## Data Flow

```
Threat Intelligence Sources
        │
        ▼
Scheduled Incremental Ingestion
        │
        ▼
Data Normalization → Unified Vulnerability Schema
        │
        ▼
PostgreSQL → Embedding Worker → Qdrant
        │
        ▼
PostgreSQL text + Qdrant semantic → RRF
        │
        ▼
Multi-Agent Analysis Pipeline
  (Extraction → Matching → Internal Retrieval → Conditional Web Search
   → Validation → Risk & Recommendation → Report)
        │
        ▼
Report Generation (cited, evidence-backed)
        │
        ▼
User Dashboard / REST API
```

At a request level: a user submits a stack description or structured technology list → extraction identifies components and versions → matching selects PostgreSQL candidates → internal retrieval enriches candidate evidence → web search runs when that evidence is incomplete → validation determines applicability → risk assessment calculates risk and creates recommendations → report generation returns the result through the API.

## Design Notes

### 1. How does data flow from external sources into your database?

1. **Fetch** — the incremental scheduler invokes the configured NVD, CISA KEV, EPSS, GitHub Advisory, and OSV ingestion services. NVD uses persisted checkpoints; secondary sources are refreshed by their ingestion services.
2. **Normalize** — the Normalization Engine maps each source's raw payload (JSON, CVRF/CSAF, RSS, vendor-specific formats) into the Unified Vulnerability Schema, resolving field-name and unit differences (e.g. differing severity scales) and deduplicating records that describe the same CVE across multiple feeds.
3. **Persist and index** — normalized records are upserted into PostgreSQL. The embedding worker processes pending/changed records and synchronizes derived vectors to Qdrant; it is a separate step, not one cross-store transaction.
4. **Refresh** — scheduled incremental runs update source records and the embedding worker refreshes vectors when relevant content changes. Neo4j is not currently populated or queried by this active path.

PostgreSQL is authoritative; Qdrant is a derived index that can be rebuilt.

### 2. How will the RAG system retrieve relevant vulnerabilities?

The active retrieval service combines two signals and merges results before they reach the agents:

- **PostgreSQL text search** — exact CVE/GHSA checks and SQL `ILIKE` matching over identifiers, vendor, product, title, and description.
- **Dense semantic search (Qdrant)** — embeds the query and retrieves similar vulnerability records, hydrating their details from PostgreSQL.

The two result sets are merged with Reciprocal Rank Fusion. The active retriever does not implement BM25, a separate reranker, or graph traversal.

### 3. Where does LangGraph fit into the workflow?

LangGraph is the orchestration layer for the active assessment pipeline. It defines Technology Extraction → Vulnerability Matching → Internal Retrieval → conditional Web Search → Validation → Risk Assessment → Report Generation. The risk-assessment node currently produces both risk scores and remediation recommendations.

The graph passes shared assessment state between nodes and routes to web search when internal evidence is insufficient. It does not currently loop back for retrieval, parallelize assessment nodes, or configure LangGraph checkpointing/retries.

### 4. How are organization assets matched with vulnerabilities?

1. The Technology Extraction Agent accepts a structured technology list or stack description and produces asset records.
2. The Vulnerability Matching Agent performs text-based candidate selection in PostgreSQL; it does not currently do graph-based dependency expansion.
3. The Internal Retrieval Agent retrieves evidence for each candidate using PostgreSQL text search and Qdrant semantic search.
4. The Web Search Agent supplements missing or incomplete internal evidence.
5. The Validation Agent applies identity, product, and version checks and classifies findings as validated, not affected, or requiring review.

Only matches that pass validation are carried forward into risk scoring and reporting.

### 5. What information should appear in the final AI-generated report?

Per `ThreatReport` in `database.md`, each report should include:

- **Affected assets** — which specific organizational assets (name, version, criticality) are implicated
- **Matched vulnerabilities** — CVE/GHSA ID, vendor, product, affected/patched versions, and a plain-language description of the issue
- **Severity signals** — CVSS score and vector, EPSS score, CISA KEV status, and whether a public exploit is known to be available
- **Risk score and priority ranking** — an aggregate organizational risk score per finding, with a ranked order and the rationale behind that ranking (e.g. "ranked #1: CISA KEV + high EPSS + internet-facing asset")
- **Business impact context** — informed by asset criticality, to distinguish "critical CVE on a non-critical internal tool" from "medium CVE on a customer-facing production service"
- **Remediation guidance** — specific patch/upgrade versions, mitigations or compensating controls if no patch exists yet, and relevant configuration changes
- **Citations/evidence** — direct references to the source advisories (NVD, vendor bulletin, GitHub Advisory, etc.) backing each finding, so a human analyst can independently verify every claim
- **Report metadata** — report type (executive/technical), generation timestamp, and the agent/pipeline version that produced it, for auditability

Executive reports should lead with the risk score, priority ranking, and business impact in plain language; technical reports should lead with the full vulnerability detail, matched assets, and remediation steps, with the executive summary as a shorter preface.

### 6. Update status

This document has been updated to include the Design Notes above alongside the existing Project Objective, Features, Components, and Data Flow sections.