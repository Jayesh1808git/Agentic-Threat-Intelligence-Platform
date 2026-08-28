import asyncio
import httpx


class GitHubAdvisorySource:

    URL = (
        "https://api.github.com/advisories"
    )

    def __init__(
        self,
        token=None,
    ):

        self.token = token

    async def fetch_all(self):

        headers = {
            "Accept":
                "application/vnd.github+json",

            "X-GitHub-Api-Version":
                "2026-03-10",
        }

        if self.token:
            headers[
                "Authorization"
            ] = f"Bearer {self.token}"

        records = []

        async with httpx.AsyncClient(
            timeout=60
        ) as client:

            page = 1

            while True:

                response = await client.get(
                    self.URL,
                    headers=headers,
                    params={
                        "per_page": 100,
                        "page": page,
                        "type": "reviewed",
                    },
                )

                if response.status_code == 429:

                    await asyncio.sleep(
                        10
                    )

                    continue

                response.raise_for_status()

                data = response.json()

                if not data:
                    break

                records.extend(data)

                print(
                    f"GitHub advisories: "
                    f"{len(records)}"
                )

                if len(data) < 100:
                    break

                page += 1

        return records