from typing import Any

import httpx


class GitHubAdvisoryFetcher:

    URL = (
        "https://api.github.com/advisories"
    )

    async def fetch(
        self,
        max_pages: int = 10,
    ) -> list[dict[str, Any]]:

        records = []

        headers = {
            "Accept": (
                "application/vnd.github+json"
            ),
            "X-GitHub-Api-Version": (
                "2026-03-10"
            ),
        }

        async with httpx.AsyncClient(
            timeout=30.0,
            headers=headers,
        ) as client:

            for page in range(
                1,
                max_pages + 1,
            ):

                params = {
                    "type": "reviewed",
                    "per_page": 100,
                    "page": page,
                    "sort": "updated",
                    "direction": "desc",
                }

                response = await client.get(
                    self.URL,
                    params=params,
                )

                response.raise_for_status()

                data = response.json()

                if not data:
                    break

                records.extend(data)

        return records