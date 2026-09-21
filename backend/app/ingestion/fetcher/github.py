from typing import Any
from app.ingestion.sources.github import GitHubAdvisorySource


class GitHubAdvisoryFetcher:

    def __init__(self, token: str | None = None):
        self.source = GitHubAdvisorySource(token=token)

    async def fetch(
        self,
        max_pages: int = 10,
    ) -> list[dict[str, Any]]:
        return await self.source.fetch_all(max_pages=max_pages)