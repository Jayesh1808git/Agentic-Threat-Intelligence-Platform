FROM python:3.11-slim

WORKDIR /app

# Install system dependencies for PostgreSQL and SSL
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy dependencies file
COPY requirements.txt .

# Install Python requirements
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt || \
    pip install --no-cache-dir httpx pydantic pydantic-settings sqlalchemy psycopg2-binary qdrant-client

# Copy application source code
COPY app/ ./app/
COPY scheduler.py .
COPY run_incremental_ingest.py .
COPY run_multi_source_ingest.py .
COPY check_sources_db.py .

ENV PYTHONPATH=/app

CMD ["python", "scheduler.py", "--interval-hours", "5"]
