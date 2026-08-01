# CyberRAG — Architecture

## Project Objective

CyberRAG is an agentic threat intelligence and vulnerability intelligence platform. Instead of answering questions from a static document set like a conventional RAG system, it continuously ingests live vulnerability and exploit data from public and vendor sources, normalizes it into a unified schema, and uses a multi-agent AI pipeline to determine whether a given organization's technology stack is affected by newly disclosed vulnerabilities — then explains why, how severe the exposure is, and what to do about it.

The objective is to replace manual vulnerability triage (analysts reading advisories and cross-referencing them against internal asset inventories by hand) with a continuously running, explainable, evidence-cited AI system.

## Features

- **Continuous threat intelligence ingestion** from NVD, MITRE CVE, CISA KEV, FIRST EPSS, GitHub Security Advisories, OSV.dev, ExploitDB, OpenCVE, and vendor bulletins (Microsoft, Cisco, Red Hat, Oracle, VMware, Palo Alto, etc.)
- **Vendor data normalization** into one unified vulnerability schema, decoupling downstream logic from source-specific formats
- **Hybrid Retrieval-Augmented Generation** combining dense semantic search, BM25 keyword search, and graph traversal
- **Knowledge graph reasoning** over relationships between vendors, products, versions, vulnerabilities, and exploits
- **Multi-agent decision making** — specialized agents for extraction, matching, retrieval, validation, risk scoring, remediation, and reporting
- **Organizational vulnerability assessment** — given a repo, SBOM, or stack description, determine actual exposure
- **Automated risk prioritization** using CVSS, EPSS, CISA KEV status, exploit availability, and business/asset context
- **Explainable, cited security reports** for both executive and technical audiences

## Components

### 1. Ingestion Layer
Pulls data from all configured threat intelligence sources on a continuous or scheduled basis (Kafka streaming for production-scale deployments, cron-based polling for smaller ones).

### 2. Normalization Engine
Converts every heterogeneous advisory format into the Unified Vulnerability Schema (see `database.md`) so all downstream components operate on one consistent structure regardless of source.

### 3. Storage Layer
- **PostgreSQL** — structured, transactional data (vulnerabilities, assets, users, reports)
- **Qdrant (Vector DB)** — semantic embeddings of advisory text for similarity search
- **Neo4j (Knowledge Graph)** — relationships between vendors, products, versions, CVEs, and exploit chains

### 4. Hybrid Retrieval Layer
Combines three retrieval strategies and merges/re-ranks results:
- Dense embedding similarity search (Qdrant)
- BM25 lexical/keyword search
- Graph-based relationship retrieval (Neo4j)

### 5. Multi-Agent Analysis Layer (LangGraph/LangChain-orchestrated)
- **Technology Extraction Agent** — parses project descriptions, repos, SBOMs, and documents to identify the org's tech stack
- **Vulnerability Matching Agent** — maps extracted technologies/versions to known vulnerabilities
- **Retrieval Agent** — pulls the most relevant intelligence via Hybrid RAG
- **Validation Agent** — cross-checks findings across sources to reduce false positives/hallucinations
- **Risk Assessment Agent** — scores organizational risk from CVSS, EPSS, KEV status, exploit availability, and asset criticality
- **Recommendation Agent** — generates patch/mitigation guidance
- **Report Generation Agent** — produces cited executive and technical reports

### 6. API & Dashboard Layer
FastAPI backend exposing programmatic access (see `api.md`); Next.js (or Streamlit) frontend for interactive use.

## Data Flow

```
Threat Intelligence Sources
        │
        ▼
Streaming/Scheduled Ingestion (Kafka or cron)
        │
        ▼
Data Normalization → Unified Vulnerability Schema
        │
        ▼
Storage  (PostgreSQL ─ structured data)
         (Qdrant ─ vector embeddings)
         (Neo4j ─ relationship graph)
        │
        ▼
Hybrid Retrieval (semantic + BM25 + graph)
        │
        ▼
Multi-Agent Analysis Pipeline
  (Extraction → Matching → Retrieval → Validation → Risk Scoring → Recommendation)
        │
        ▼
Report Generation (cited, evidence-backed)
        │
        ▼
User Dashboard / REST API
```

At a request level: a user submits an organizational context (repo URL, SBOM, or stack description) → the Technology Extraction Agent identifies components and versions → the Vulnerability Matching Agent and Retrieval Agent pull candidate vulnerabilities → the Validation Agent cross-verifies them against multiple sources → the Risk Assessment Agent scores and prioritizes → the Recommendation Agent drafts remediation steps → the Report Generation Agent assembles a cited report returned via API/dashboard.

## Design Notes

### 1. How does data flow from external sources into your database?

1. **Fetch** — the Ingestion Layer pulls raw advisories from each configured `ThreatFeed` (NVD, MITRE CVE, CISA KEV, EPSS, GitHub Security Advisories, OSV.dev, ExploitDB, OpenCVE, vendor bulletins), either via Kafka-fed streaming consumers (production scale) or scheduled cron polling (smaller deployments). Each source keeps its own polling interval and last-ingested checkpoint to support incremental pulls.
2. **Normalize** — the Normalization Engine maps each source's raw payload (JSON, CVRF/CSAF, RSS, vendor-specific formats) into the Unified Vulnerability Schema, resolving field-name and unit differences (e.g. differing severity scales) and deduplicating records that describe the same CVE across multiple feeds.
3. **Persist** — the normalized record is written to PostgreSQL as the system of record. In the same transaction/step, its description text is embedded and upserted into Qdrant, and its vendor/product/version relationships are upserted into Neo4j.
4. **Reconcile** — a periodic reconciliation job re-checks existing records against their sources for updates (e.g. a CVE's CVSS score changing, or it being added to CISA KEV after initial publication) and updates all three stores accordingly.

This keeps PostgreSQL, Qdrant, and Neo4j eventually consistent, with PostgreSQL as the authoritative source and the other two stores treated as derived, rebuildable indexes.

### 2. How will the RAG system retrieve relevant vulnerabilities?

Retrieval is hybrid, combining three complementary signals and merging/re-ranking the results before they reach the agents:

- **Dense semantic search (Qdrant)** — embeds the query (e.g. a CVE description, a technology name, or a natural-language question) and retrieves vulnerabilities with similar embeddings, catching semantically related matches even when wording differs.
- **BM25 lexical search** — catches exact-match signals that dense embeddings can miss, such as precise version strings, CVE IDs, or package names.
- **Graph retrieval (Neo4j)** — traverses vendor → product → vulnerability → exploit relationships to catch matches that depend on structure rather than text similarity, including transitive dependency exposure (e.g. a vulnerable library pulled in indirectly by a direct dependency).

The three result sets are merged and re-ranked (e.g. reciprocal rank fusion, then a lightweight relevance re-rank) before being passed to the Retrieval Agent, so the final candidate set balances precision (BM25/graph) with recall (dense search).

### 3. Where does LangGraph fit into the workflow?

LangGraph is the orchestration layer for the Multi-Agent Analysis pipeline. It defines the workflow as a directed graph of agent nodes — Technology Extraction → Vulnerability Matching → Retrieval → Validation → Risk Assessment → Recommendation → Report Generation — with explicit state passed between nodes (extracted technologies, candidate vulnerabilities, validated findings, risk scores, remediation steps).

Concretely, LangGraph is responsible for:
- Maintaining shared state across agent steps (so later agents can see earlier agents' outputs and reasoning)
- Conditional routing — e.g. looping back to the Retrieval Agent if the Validation Agent finds insufficient corroborating evidence, or skipping the Risk Assessment Agent for a simple single-CVE lookup
- Parallelizing independent steps where possible (e.g. running Risk Assessment across multiple matched vulnerabilities concurrently)
- Providing checkpointing/retries per node, and an audit trail of which agent produced which intermediate result, which feeds directly into the citations in the final report

LangChain is used underneath individual nodes for model calls, tool use, and retrieval integrations; LangGraph is what turns those individual capabilities into a coherent, stateful, multi-step workflow.

### 4. How are organization assets matched with vulnerabilities?

1. The Technology Extraction Agent parses the submitted input (SBOM, repository, dependency manifest, or manual stack description) and produces a list of `OrganizationAsset` records — each with a name, version, and asset type (language, framework, library, database, cloud service, OS).
2. The Vulnerability Matching Agent takes each asset and queries the unified vulnerability database for records where `vendor`/`product` matches the asset name and the asset's version falls within the vulnerability's `affected_versions` range (and outside `patched_versions`).
3. In parallel, the same asset is looked up in the Neo4j graph to catch indirect matches — e.g. a vulnerability in a transitive dependency of a directly-referenced library — which a flat version-range comparison alone would miss.
4. The Retrieval Agent supplements this with Hybrid RAG search in case an asset name doesn't exactly match a vendor/product string in the database (e.g. informal naming in an SBOM vs. the CPE-style naming used by NVD).
5. The Validation Agent cross-checks each candidate match against multiple sources (e.g. confirming a GitHub Advisory match against the corresponding NVD/OSV entry) before it's treated as confirmed, reducing false positives from naming collisions or ambiguous version ranges.

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