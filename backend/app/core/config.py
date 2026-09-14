from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


BASE_DIR = Path(__file__).resolve().parent.parent.parent


class Settings(BaseSettings):

    # ---------------------------------------------------------
    # Application
    # ---------------------------------------------------------

    APP_NAME: str = "Agentic Threat Intelligence Platform"
    APP_ENV: str = "development"
    DEBUG: bool = True

    HOST: str = "0.0.0.0"
    PORT: int = 8000

    # ---------------------------------------------------------
    # Security
    # ---------------------------------------------------------

    SECRET_KEY: str = "change_this_to_a_random_secret_key"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60

    # ---------------------------------------------------------
    # PostgreSQL
    # ---------------------------------------------------------

    DATABASE_MODE: str = "local"

    POSTGRES_URL: str = ""

    POSTGRES_HOST: str = "localhost"
    POSTGRES_PORT: int = 5432
    POSTGRES_DB: str = "threat_intelligence"
    POSTGRES_USER: str = "postgres"
    POSTGRES_PASSWORD: str = "postgres"

    # ---------------------------------------------------------
    # Qdrant
    # ---------------------------------------------------------

    QDRANT_URL: str = "http://localhost:6333"
    QDRANT_API_KEY: str = ""
    QDRANT_COLLECTION: str = "vulnerabilities"

    # ---------------------------------------------------------
    # Neo4j
    # ---------------------------------------------------------

    NEO4J_URI: str = "neo4j://localhost:7687"
    NEO4J_USER: str = "neo4j"
    NEO4J_PASSWORD: str = ""

    # ---------------------------------------------------------
    # Embeddings
    # ---------------------------------------------------------

    EMBEDDING_MODEL: str = "BAAI/bge-small-en-v1.5"

    # ---------------------------------------------------------
    # LLM
    # ---------------------------------------------------------

    LLM_PROVIDER: str = "groq"

    GROQ_API_KEY: str = ""
    GEMINI_API_KEY: str = ""
    OPENAI_API_KEY: str = ""

    # ---------------------------------------------------------
    # Threat Intelligence Sources
    # ---------------------------------------------------------

    NVD_API_KEY: str = ""

    CISA_KEV_URL: str = (
        "https://www.cisa.gov/sites/default/files/feeds/"
        "known_exploited_vulnerabilities.json"
    )

    EPSS_API_URL: str = (
        "https://api.first.org/data/v1/epss"
    )

    GITHUB_ADVISORY_API: str = (
        "https://api.github.com/advisories"
    )

    # ---------------------------------------------------------
    # Storage
    # ---------------------------------------------------------

    DATA_DIR: str = "./data"
    RAW_DATA_DIR: str = "./data/raw"
    PROCESSED_DATA_DIR: str = "./data/processed"
    REPORT_DIR: str = "./data/reports"

    LOG_LEVEL: str = "INFO"
    LOG_FILE: str = "logs/app.log"

    # ---------------------------------------------------------
    # Application Settings
    # ---------------------------------------------------------

    CACHE_TTL: int = 3600

    CORS_ORIGINS: str = '["http://localhost:3000"]'

    MAX_UPLOAD_SIZE_MB: int = 20

    UPLOAD_FOLDER: str = "uploads"

    REPORT_TEMPLATE: str = "default"

    THREAT_SYNC_INTERVAL_HOURS: int = 6

    # ---------------------------------------------------------
    # Pydantic
    # ---------------------------------------------------------

    model_config = SettingsConfigDict(
        env_file=BASE_DIR / ".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


settings = Settings()