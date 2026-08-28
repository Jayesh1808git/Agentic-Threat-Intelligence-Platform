import httpx


class EPSSFetcher:

    def __init__(
        self,
        url: str,
    ):
        self.url = url

    async def fetch_cve(
        self,
        cve: str,
    ):

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