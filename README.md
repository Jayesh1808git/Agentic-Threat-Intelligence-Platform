# 🛡️ Agentic Threat Intelligence Platform (CyberRAG)

**AI-powered, agentic threat intelligence platform** that ingests and normalizes vulnerability data — using **LangGraph**, **FastAPI**, **PostgreSQL**, and **Qdrant** — to assess whether a submitted technology stack may be exposed to known CVEs and produce evidence-backed remediation reports.

Unlike a traditional RAG chatbot that answers questions from a static document set, CyberRAG runs as a continuously updated system: new advisories flow in, get normalized, get matched against your assets, and get prioritized — before an analyst ever has to look for them.

---

## 🚀 Why This Exists

Security teams are flooded with thousands of advisories a month from NVD, CISA KEV, GitHub Security Advisories, vendor bulletins, and more — each in a different format, arriving continuously. Manually figuring out *"does this affect us, and how bad is it?"* doesn't scale.

CyberRAG automates that entire lifecycle: **ingest → normalize → retrieve → reason → prioritize → report.**

---

## ✨ Key Features

- 🔄 **Scheduled incremental ingestion** from the configured NVD, CISA KEV, FIRST EPSS, GitHub Advisory, and OSV connectors
- 🧩 **Unified vulnerability schema** — normalizes every source into one consistent format
- 🔍 **Hybrid retrieval** — PostgreSQL text search + Qdrant dense semantic search, merged with Reciprocal Rank Fusion (RRF)
- 🤖 **Multi-agent pipeline** (LangGraph) — extraction, matching, validation, risk scoring, remediation, and reporting agents working in sequence
- 🎯 **Organizational vulnerability assessment** — submit a stack description or structured technology list to assess potential exposure
- 📊 **Automated risk prioritization** using CVSS, EPSS, CISA KEV status, exploit availability, and asset criticality
- 📄 **Evidence-backed reports** — findings include available supporting evidence and remediation guidance

---

## 🏗️ Architecture & Data Flow

```
                     Configured Threat Sources
                 (NVD, CISA KEV, EPSS, GitHub, OSV)
                            │
                            ▼
               Scheduled Incremental Ingestion
                  (Python scheduler / CLI)
                            │
                            ▼
             Data Normalization Engine
          → Unified Vulnerability Schema
                            ▼
                      PostgreSQL
                   (source of truth)
                            ▼
                 Embedding Worker
                            ▼
                         Qdrant
                   (derived vectors)
                            │
                 ┌──────────┴──────────┐
                 ▼                     ▼
          PostgreSQL text       Qdrant semantic
             search                search
                 └──────────┬──────────┘
                            ▼
                    RRF Hybrid Retrieval
                            │
                            ▼
            Multi-Agent Analysis (LangGraph)
   Extraction → Matching → Retrieval → Conditional Web Search
              → Validation → Risk & Recommendation
                            │
                            ▼
             Cited Report Generation
                            │
                            ▼
             REST API (FastAPI) / Web Dashboard
```

**In practice:** you submit a stack description or structured technology list → the **Technology Extraction Agent** identifies assets → **Vulnerability Matching** selects database candidates → **Internal Retrieval** enriches those candidates with PostgreSQL/Qdrant evidence, with external web lookups when evidence is incomplete → **Validation** determines applicability → **Risk Assessment** calculates risk and creates recommendations → **Report Generation** assembles the report for the API. The current active retrieval path does not implement BM25 or Neo4j graph traversal; those are not represented as live pipeline stages.

---

## 🧰 Tech Stack

| Layer | Technology |
|---|---|
| **Backend** | Python, FastAPI |
| **Agent Orchestration** | LangGraph, LangChain |
| **LLMs** | Llama 3 / Qwen / Gemma (or GPT-compatible APIs) |
| **Retrieval** | PostgreSQL text search + Qdrant dense embeddings + RRF |
| **Vector Database** | Qdrant |
| **Relational Database** | PostgreSQL |
| **Ingestion** | Scheduled incremental Python workers |
| **Frontend** | Next.js (preferred) or Streamlit |
| **Deployment** | Docker, deployable to Railway / AWS / Azure / GCP |

---

## 📅 Estimated Timeline (4 Weeks)

| Week | Focus |
|---|---|
| **Week 1 — Foundations & Ingestion** | Project scaffolding, Docker Compose setup (PostgreSQL, Qdrant, Neo4j), unified schema design, first ingestion connectors (NVD, MITRE, CISA KEV), normalization engine |
| **Week 2 — Storage, Retrieval & Feeds** | Remaining connectors (EPSS, GitHub Advisories, OSV.dev, ExploitDB, OpenCVE), embeddings into Qdrant, knowledge graph population in Neo4j, Hybrid Retrieval implementation, core read endpoints |
| **Week 3 — Multi-Agent Pipeline** | LangGraph orchestration, Technology Extraction / Matching / Validation / Risk Assessment / Recommendation agents, asset ingestion and query endpoints |
| **Week 4 — Reporting, Dashboard & Deployment** | Report Generation Agent with citations, report endpoints, Next.js/Streamlit dashboard, end-to-end testing, Docker deployment, final documentation |

> 📌 This is a working estimate for an MVP; see `docs/roadmap.md` for the full breakdown.

---

## 📂 Documentation

- [`docs/architecture.md`](docs/architecture.md) — objective, components, data flow, and design notes
- [`docs/database.md`](docs/database.md) — core entities and schema
- [`docs/api.md`](docs/api.md) — planned API endpoints
- [`docs/roadmap.md`](docs/roadmap.md) — full 4-week roadmap

---

## 📖 Example Questions It Can Answer

- Are we affected by this CVE?
- Which of our systems are vulnerable?
- Is a public exploit available for this vulnerability?
- Is it actively being exploited in the wild?
- What's the business impact if we don't patch?
- Which vulnerabilities should we fix first?
- Which of our technologies are currently at risk?

---

## 🎯 Project Goal

Replace manual vulnerability monitoring with a continuously updated, explainable AI system — one that doesn't just answer cybersecurity questions, but proactively identifies, prioritizes, and explains the vulnerabilities that actually matter to *your* environment.