import httpx


class OSVFetcher:

    BASE_URL = (
        "https://api.osv.dev/v1/query"
    )

    async def query_package(
        self,
        ecosystem: str,
        package: str,
        version: str | None = None,
    ):

        payload = {
            "package": {
                "ecosystem": ecosystem,
                "name": package,
            }
        }

        if version:
            payload["version"] = version

        async with httpx.AsyncClient(
            timeout=60.0
        ) as client:

            response = await client.post(
                self.BASE_URL,
                json=payload,
            )

            response.raise_for_status()

            return response.json()