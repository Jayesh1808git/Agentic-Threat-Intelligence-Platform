import asyncio
import logging
import httpx
from app.core.config import settings

logger = logging.getLogger(__name__)


class GitHubAdvisorySource:

    def __init__(
        self,
        token: str | None = None,
    ):
        self.token = token or getattr(settings, "GITHUB_TOKEN", None)

    async def fetch_all(
        self,
        max_pages: int | None = None,
    ) -> list[dict]:

        headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": "CyberRAG-ThreatIntel/1.0",
        }

        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"

        records = []

        async with httpx.AsyncClient(timeout=60.0) as client:
            page = 1

            while True:
                if max_pages and page > max_pages:
                    break

                try:
                    response = await client.get(
                        settings.GITHUB_ADVISORY_API,
                        headers=headers,
                        params={
                            "per_page": 100,
                            "page": page,
                            "type": "reviewed",
                        },
                    )

                    if response.status_code == 429:
                        logger.warning("GitHub API rate limited (429). Retrying in 10s...")
                        await asyncio.sleep(10)
                        continue

                    response.raise_for_status()
                    data = response.json()

                    if not data:
                        break

                    records.extend(data)
                    logger.info("GitHub advisories page %d fetched: %d total", page, len(records))

                    if len(data) < 100:
                        break

                    page += 1
                except Exception as exc:
                    logger.error("Error fetching GitHub advisories page %d: %s", page, exc)
                    break

        return records