import httpx
from app.core.config import settings


class CISAKEVFetcher:

    def __init__(
        self,
        url: str | None = None,
    ):
        self.url = url or settings.CISA_KEV_URL

    async def fetch(self) -> list[dict]:
        async with httpx.AsyncClient(
            timeout=60.0,
            headers={"User-Agent": "CyberRAG-ThreatIntel/1.0"},
        ) as client:
            response = await client.get(self.url)
            response.raise_for_status()
            data = response.json()

        return data.get("vulnerabilities", [])