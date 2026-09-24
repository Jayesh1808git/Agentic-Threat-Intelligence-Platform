import os
from pathlib import Path
from qdrant_client import QdrantClient
from app.core.config import settings

_qdrant_client: QdrantClient | None = None

def get_qdrant_client() -> QdrantClient:
    global _qdrant_client
    if _qdrant_client is not None:
        return _qdrant_client

    if settings.QDRANT_URL:
        try:
            client = QdrantClient(
                url=settings.QDRANT_URL,
                api_key=settings.QDRANT_API_KEY or None,
                timeout=5.0,
            )
            # Test connectivity
            client.get_collections()
            _qdrant_client = client
            return _qdrant_client
        except Exception as exc:
            print(f"Warning: Qdrant cloud/remote connection to {settings.QDRANT_URL} failed: {exc}")
            print("Falling back to local embedded Qdrant database...")

    # Fallback to local persistent Qdrant storage
    storage_path = Path(settings.DATA_DIR) / "qdrant_storage"
    storage_path.mkdir(parents=True, exist_ok=True)
    _qdrant_client = QdrantClient(path=str(storage_path))
    return _qdrant_client