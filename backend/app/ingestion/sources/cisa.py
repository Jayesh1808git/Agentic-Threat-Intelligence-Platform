import httpx


class CISASource:

    def __init__(self, url):

        self.url = url

    async def fetch(self):

        async with httpx.AsyncClient(
            timeout=120
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