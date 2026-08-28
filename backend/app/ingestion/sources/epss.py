import httpx


class EPSSSource:

    def __init__(self, url):

        self.url = url

    async def fetch_batch(
        self,
        cves,
    ):

        if not cves:
            return {}

        result = {}

        # FIRST supports multiple CVEs in
        # the cve parameter.
        for i in range(
            0,
            len(cves),
            100,
        ):

            batch = cves[
                i:i + 100
            ]

            async with httpx.AsyncClient(
                timeout=60
            ) as client:

                response = await client.get(
                    self.url,
                    params={
                        "cve": ",".join(
                            batch
                        )
                    },
                )

                response.raise_for_status()

                data = response.json()

            for row in data.get(
                "data",
                [],
            ):

                try:

                    result[
                        row["cve"]
                    ] = float(
                        row["epss"]
                    )

                except (
                    KeyError,
                    TypeError,
                    ValueError,
                ):
                    pass

        return result