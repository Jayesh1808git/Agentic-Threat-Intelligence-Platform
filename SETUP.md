# CyberRAG Setup Guide & Teammate Onboarding

Welcome to the **CyberRAG Agentic Threat Intelligence & Vulnerability Platform**. This guide provides step-by-step instructions for setting up the environment, initializing the PostgreSQL database, loading the seed vulnerability data, configuring Qdrant vector search, and using the hybrid retrieval subsystem in your AI agents.

---

## 📋 Prerequisites

Before starting, ensure you have installed:
- **Python 3.11+**
- **PostgreSQL 15+** running locally (or via Docker)
- **Git**

---

## 🚀 1. Repository Setup & Virtual Environment

### Step 1: Clone the Repository
```bash
git clone https://github.com/Jayesh1808git/Agentic-Threat-Intelligence-Platform.git
cd Agentic-Threat-Intelligence-Platform
```

### Step 2: Create & Activate Virtual Environment

**On Windows (PowerShell):**
```powershell
python -m venv backend\.venv
.\backend\.venv\Scripts\Activate.ps1
```

**On Linux / macOS:**
```bash
python3 -m venv backend/.venv
source backend/.venv/bin/activate
```

### Step 3: Install Dependencies
```bash
pip install --upgrade pip
pip install -r backend/requirements.txt
```

---

## ⚙️ 2. Environment Configuration (`.env`)

Create a `.env` file inside the `backend/` directory by copying `.env.example`:

```bash
cp .env.example backend/.env
```

Open `backend/.env` and update the following configuration sections:

### A. PostgreSQL Configuration
Update with your local PostgreSQL user and password:
```env
DATABASE_MODE=local
POSTGRES_HOST=localhost
POSTGRES_PORT=5432
POSTGRES_DB=threat_intelligence
POSTGRES_USER=postgres
POSTGRES_PASSWORD=your_postgres_password
POSTGRES_URL=postgresql://postgres:your_postgres_password@localhost:5432/threat_intelligence
```

### B. Qdrant Credentials (Provided by Lead)
Paste the Qdrant Cloud URL and API Key provided by your team lead (or leave default for embedded local storage fallback):
```env
QDRANT_URL=https://<your-qdrant-cluster-url>.qdrant.io
QDRANT_API_KEY=<your-qdrant-api-key>
QDRANT_COLLECTION=vulnerabilities

EMBEDDING_MODEL=BAAI/bge-small-en-v1.5
```

---

## 🗄️ 3. Database Initialization & Seed Data Loading

### Step 1: Create PostgreSQL Database
Make sure PostgreSQL service is running, then create the `threat_intelligence` database:

**Using psql CLI:**
```sql
CREATE DATABASE threat_intelligence;
```

### Step 2: Load Seed Vulnerabilities (`vuln_seed_data.csv`)
Run the seed loader script from the `backend/` directory:

```bash
cd backend
python load_seed_data.py
```
This script will initialize all database tables and import the vulnerability seed data from `data/vuln_seed_data.csv` (or `data/vuln_seed.csv`).

---

## 🧠 4. Qdrant Vector Embedding Sync

Generate vector embeddings for all seed vulnerability records and upload them into Qdrant:

```bash
cd backend
python -m indexing.embedding_worker
```

> **Note**: To force re-indexing of all vulnerabilities from scratch, run with the `--rebuild` flag:
> ```bash
> python -m indexing.embedding_worker --rebuild
> ```

---

## 🌐 5. Running the Backend API Server

Start the FastAPI application using `uvicorn` from the `backend/` directory:

```bash
cd backend
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

Once running:
- **Interactive Swagger API Documentation**: [http://localhost:8000/docs](http://localhost:8000/docs)
- **Health Check Endpoint**: [http://localhost:8000/health](http://localhost:8000/health)
- **Hybrid Retrieval Search Endpoint**: [http://localhost:8000/retrieval/search](http://localhost:8000/retrieval/search)

---

## 🤖 6. How Teammates Should Consume the Retriever in Agents

Your agent nodes (built with **LangGraph** or custom Python agent workflows) can call the retrieval subsystem in **two ways**:

### Option A: Direct Python Service Import (Recommended for Agents)

Inside your agent node code (running within the backend context), import `VulnerabilityRetriever` directly. This executes hybrid search in-memory without HTTP network overhead:

```python
from app.database.postgres import SessionLocal
from app.retrieval.service import VulnerabilityRetriever

# 1. Initialize database session
db = SessionLocal()
retriever = VulnerabilityRetriever(db)

# 2. Run hybrid retrieval with natural language query & filters
results = retriever.retrieve(
    query="privilege escalation in Windows Kernel",
    vendor="Microsoft",
    product="Windows",
    kev=True, # CISA Known Exploited Vulnerabilities filter
    limit=10,
)

# 3. Process normalized results inside your agent node
for vuln in results:
    print(f"ID: {vuln.vulnerability_id}")
    print(f"CVE: {vuln.cve}")
    print(f"Title: {vuln.title}")
    print(f"CVSS: {vuln.cvss} | EPSS: {vuln.epss}")
    print(f"Relevance Score: {vuln.final_score}")
    print(f"Sources: {vuln.retrieval_sources}")
    print("-" * 50)

# 4. Close database session when finished
db.close()
```

### Option B: HTTP API Endpoint (For External Agents / Frontend)

#### HTTP GET Example:
```bash
curl -X GET "http://localhost:8000/retrieval/search?q=remote+code+execution&vendor=Microsoft&product=Windows&limit=5"
```

#### HTTP POST Example:
```bash
curl -X POST "http://localhost:8000/retrieval/search" \
     -H "Content-Type: application/json" \
     -d '{
           "q": "Apache Log4j remote code execution",
           "vendor": "Apache",
           "product": "Log4j",
           "limit": 5
         }'
```

#### Sample Response Structure:
```json
{
  "query": "Apache Log4j remote code execution",
  "total": 1,
  "results": [
    {
      "id": "18f50c05-b1a7-4762-b9e7-5df737877ce5",
      "vulnerability_id": "CVE-2021-44228",
      "source": "NVD",
      "cve": "CVE-2021-44228",
      "title": "Apache Log4j2 Remote Code Execution Vulnerability (Log4Shell)",
      "description": "Apache Log4j2 2.0-beta9 through 2.15.0 JNDI features...",
      "vendor": "Apache",
      "product": "Log4j",
      "affected_versions": ["2.0-beta9", "2.14.1"],
      "patched_versions": ["2.15.0"],
      "cvss": 10.0,
      "epss": 0.95,
      "kev": true,
      "exploit_available": true,
      "semantic_score": 0.92,
      "lexical_score": 1.0,
      "final_score": 1.0,
      "retrieval_sources": ["semantic", "lexical"]
    }
  ]
}
```

---

## 🧪 7. Verification & Testing

To verify that the entire retrieval layer is functioning correctly on your machine, run the test suite:

```bash
cd backend
python -m pytest tests/test_retrieval.py -v
```

Happy coding! If you run into any issues during setup, reach out to the project maintainer.
