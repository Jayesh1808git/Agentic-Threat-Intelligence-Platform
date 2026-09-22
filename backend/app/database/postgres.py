from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.config import settings
from app.models.vulnerability import Base


if not settings.POSTGRES_URL:
    raise RuntimeError(
        "POSTGRES_URL is not configured. "
        "Set it in the project .env file."
    )


engine = create_engine(
    settings.POSTGRES_URL,
    pool_pre_ping=True,
    pool_recycle=1800,

    
    pool_size=10,
    max_overflow=20,

    connect_args={
        "connect_timeout": 10,
    },
)


SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False,
    expire_on_commit=False,
)


def init_db() -> None:
    """
    Create all SQLAlchemy tables.

    For production deployments, Alembic migrations
    should eventually replace create_all().
    """

    Base.metadata.create_all(
        bind=engine
    )


def get_db():
    """
    FastAPI dependency providing a request-scoped
    PostgreSQL session.
    """

    db = SessionLocal()

    try:
        yield db

    finally:
        db.close()