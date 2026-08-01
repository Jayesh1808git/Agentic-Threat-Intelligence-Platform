# 🛡️ Agentic Threat Intelligence Platform (CyberRAG)

**AI-powered, agentic threat intelligence platform** that continuously ingests, normalizes, and reasons over live vulnerability data — using **Multi-Agent RAG**, **LangGraph**, **FastAPI**, **PostgreSQL**, **Qdrant**, and **Neo4j** — to automatically determine whether *your* organization's technology stack is exposed to newly disclosed CVEs, and to generate explainable, cited remediation reports.

Unlike a traditional RAG chatbot that answers questions from a static document set, CyberRAG runs as a continuously updated system: new advisories flow in, get normalized, get matched against your assets, and get prioritized — before an analyst ever has to look for them.

---

## 🚀 Why This Exists

Security teams are flooded with thousands of advisories a month from NVD, CISA KEV, GitHub Security Advisories, vendor bulletins, and more — each in a different format, arriving continuously. Manually figuring out *"does this affect us, and how bad is it?"* doesn't scale.

CyberRAG automates that entire lifecycle: **ingest → normalize → retrieve → reason → prioritize → report.**

---

## ✨ Key Features

- 🔄 **Continuous ingestion** from NVD, MITRE CVE, CISA KEV, FIRST EPSS, GitHub Security Advisories, OSV.dev, ExploitDB, OpenCVE, and vendor bulletins
- 🧩 **Unified vulnerability schema** — normalizes every source into one consistent format
- 🔍 **Hybrid RAG retrieval** — dense semantic search + BM25 + knowledge graph traversal
- 🕸️ **Knowledge graph reasoning** over vendor → product → vulnerability → exploit relationships (Neo4j)
- 🤖 **Multi-agent pipeline** (LangGraph) — extraction, matching, validation, risk scoring, remediation, and reporting agents working in sequence
- 🎯 **Organizational vulnerability detection** — point it at a repo, SBOM, or stack description and it tells you what's actually at risk
- 📊 **Automated risk prioritization** using CVSS, EPSS, CISA KEV status, exploit availability, and asset criticality
- 📄 **Explainable, cited reports** — every claim in a report traces back to a source advisory

---

## 🏗️ Architecture & Data Flow

```
                     Threat Intelligence Sources
        (NVD, CISA KEV, MITRE, EPSS, GitHub Advisories,
              OSV.dev, ExploitDB, Vendor Bulletins)
                            │
                            ▼
              Streaming / Scheduled Ingestion
                    (Kafka or Cron)
                            │
                            ▼
             Data Normalization Engine
          → Unified Vulnerability Schema
                            │
              ┌─────────────┼─────────────┐
              ▼             ▼             ▼
         PostgreSQL      Qdrant         Neo4j
       (structured)    (embeddings)  (relationships)
              │             │             │
              └─────────────┼─────────────┘
                            ▼
              Hybrid Retrieval (RAG)
        (Semantic Search + BM25 + Graph Traversal)
                            │
                            ▼
            Multi-Agent Analysis (LangGraph)
   Extraction → Matching → Retrieval → Validation
           → Risk Scoring → Recommendation
                            │
                            ▼
             Cited Report Generation
                            │
                            ▼
             REST API (FastAPI) / Web Dashboard
```

**In practice:** you submit an organization's context (a repo URL, an SBOM, or a plain-text stack description) → the **Technology Extraction Agent** identifies your languages, frameworks, and dependencies → the **Vulnerability Matching** and **Retrieval Agents** pull candidate CVEs via Hybrid RAG → the **Validation Agent** cross-checks findings across sources to cut down false positives → the **Risk Assessment Agent** scores and ranks everything → the **Recommendation Agent** drafts remediation steps → the **Report Generation Agent** assembles a fully cited report, delivered via the API or dashboard.

---

## 🧰 Tech Stack

| Layer | Technology |
|---|---|
| **Backend** | Python, FastAPI |
| **Agent Orchestration** | LangGraph, LangChain |
| **LLMs** | Llama 3 / Qwen / Gemma (or GPT-compatible APIs) |
| **Retrieval** | Hybrid Search — BM25 + Dense Embeddings |
| **Vector Database** | Qdrant |
| **Knowledge Graph** | Neo4j |
| **Relational Database** | PostgreSQL |
| **Streaming/Ingestion** | Apache Kafka (or cron-based polling for smaller deployments) |
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