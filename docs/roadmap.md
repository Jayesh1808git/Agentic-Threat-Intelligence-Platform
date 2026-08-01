# CyberRAG — 4-Week Roadmap

## Week 1 — Foundations & Ingestion
- Set up project scaffolding: FastAPI backend, Docker Compose (PostgreSQL, Qdrant, Neo4j)
- Design and migrate the Unified Vulnerability Schema into PostgreSQL
- Build ingestion connectors for NVD, MITRE CVE, and CISA KEV (start with cron-based polling)
- Build the Data Normalization Engine to map raw feed payloads to the unified schema
- Write `architecture.md`, `database.md` (done), and initial project README

## Week 2 — Storage, Retrieval & Additional Feeds
- Add ingestion connectors for FIRST EPSS, GitHub Security Advisories, OSV.dev, ExploitDB, OpenCVE
- Generate and store embeddings for vulnerability descriptions in Qdrant
- Model and populate the Neo4j knowledge graph (Vendor → Product → Vulnerability → Exploit relationships)
- Implement Hybrid Retrieval: dense search + BM25 + graph traversal with result merging/re-ranking
- Stand up `GET /health`, `GET /search`, `GET /cve/{id}` endpoints

## Week 3 — Multi-Agent Pipeline
- Implement LangGraph agent orchestration
- Build the Technology Extraction Agent (parse SBOMs, repo files, manual stack descriptions)
- Build the Vulnerability Matching Agent and Validation Agent (cross-source verification)
- Build the Risk Assessment Agent (CVSS + EPSS + KEV + exploit availability + asset criticality scoring)
- Build the Recommendation Agent (patch/mitigation guidance generation)
- Implement `POST /upload-assets` and `POST /query`

## Week 4 — Reporting, Dashboard & Deployment
- Build the Report Generation Agent with citation tracking
- Implement `POST /report` (executive + technical report generation)
- Build the Next.js (or Streamlit) dashboard: search, org asset view, report viewer
- End-to-end testing across ingestion → retrieval → multi-agent → report flow
- Finalize Docker deployment, write full documentation, and prepare demo/handoff