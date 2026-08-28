import httpx


class CISAKEVFetcher:

    def __init__(
        self,
        url: str,
    ):
        self.url = url

    async def fetch(self):

        async with httpx.AsyncClient(
            timeout=60.0
        ) as client:

            response = await client.get(
                self.url
            )

            response.raise_for_status()

            data = response.json()

        return data.get(
            "vulnerabilities",
            []
        )