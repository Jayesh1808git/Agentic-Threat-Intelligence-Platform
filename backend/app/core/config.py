from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict

BASE_DIR = Path(__file__).resolve().parent.parent.parent


class Settings(BaseSettings):
    # Application
    APP_NAME: str = "Agentic Threat Intelligence Platform"
    APP_ENV: str = "development"
    DEBUG: bool = True
    HOST: str = "0.0.0.0"
    PORT: int = 8000

    # Security
    SECRET_KEY: str = "change_this_to_a_random_secret_key"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60

    # PostgreSQL
    POSTGRES_HOST: str = "localhost"
    POSTGRES_PORT: int = 5432
    POSTGRES_DB: str = "threat_intelligence"
    POSTGRES_USER: str = "postgres"
    POSTGRES_PASSWORD: str = "postgres"
    DATABASE_URL: str

    # Qdrant
    QDRANT_HOST: str = "localhost"
    QDRANT_PORT: int = 6333
    QDRANT_COLLECTION: str = "threat_documents"
    QDRANT_API_KEY: str = ""

    # Embeddings / LLM
    EMBEDDING_MODEL: str = "BAAI/bge-small-en-v1.5"
    LLM_PROVIDER: str = "groq"
    GROQ_API_KEY: str = ""
    GEMINI_API_KEY: str = ""
    OPENAI_API_KEY: str = ""

    # Threat intel sources
    NVD_API_KEY: str = ""
    CISA_KEV_URL: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    EPSS_API_URL: str = "https://api.first.org/data/v1/epss"
    GITHUB_ADVISORY_API: str = "https://api.github.com/advisories"

    # Storage / logs
    DATA_DIR: str = "./data"
    RAW_DATA_DIR: str = "./data/raw"
    PROCESSED_DATA_DIR: str = "./data/processed"
    REPORT_DIR: str = "./data/reports"
    LOG_LEVEL: str = "INFO"
    LOG_FILE: str = "logs/app.log"

    # Cache / CORS / uploads
    CACHE_TTL: int = 3600
    CORS_ORIGINS: str = '["http://localhost:3000"]'
    MAX_UPLOAD_SIZE_MB: int = 20
    UPLOAD_FOLDER: str = "uploads"

    # Reports / scheduler
    REPORT_TEMPLATE: str = "default"
    THREAT_SYNC_INTERVAL_HOURS: int = 6

    model_config = SettingsConfigDict(
        env_file=BASE_DIR / ".env",
        extra="ignore",
    )


settings = Settings()