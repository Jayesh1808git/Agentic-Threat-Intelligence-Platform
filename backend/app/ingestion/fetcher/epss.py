import httpx
from app.core.config import settings


class EPSSFetcher:

    def __init__(
        self,
        url: str | None = None,
    ):
        self.url = url or settings.EPSS_API_URL

    async def fetch_cve(
        self,
        cve: str,
    ) -> float | None:
        async with httpx.AsyncClient(
            timeout=30.0
        ) as client:
            response = await client.get(
                self.url,
                params={
                    "cve": cve
                },
            )
            response.raise_for_status()
            data = response.json()

        results = data.get(
            "data",
            []
        )

        if not results:
            return None

        return float(
            results[0]["epss"]
        )