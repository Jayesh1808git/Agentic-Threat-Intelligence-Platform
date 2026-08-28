import asyncio
from datetime import datetime, timedelta, timezone

import httpx


NVD_URL = (
    "https://services.nvd.nist.gov/"
    "rest/json/cves/2.0"
)


class NVDSource:

    def __init__(
        self,
        api_key=None,
    ):

        self.api_key = api_key

    async def request(
        self,
        client,
        params,
    ):

        headers = {
            "User-Agent":
                "Agentic-Threat-Intelligence-Platform/1.0"
        }

        if self.api_key:
            headers[
                "apiKey"
            ] = self.api_key

        delay = 2

        for attempt in range(8):

            try:

                response = await client.get(
                    NVD_URL,
                    params=params,
                    headers=headers,
                )

                if response.status_code == 200:
                    return response.json()

                if response.status_code in (
                    429,
                    500,
                    502,
                    503,
                    504,
                ):

                    print(
                        f"NVD HTTP "
                        f"{response.status_code}. "
                        f"Retrying in {delay}s..."
                    )

                    await asyncio.sleep(
                        delay
                    )

                    delay = min(
                        delay * 2,
                        60,
                    )

                    continue

                response.raise_for_status()

            except (
                httpx.TimeoutException,
                httpx.NetworkError,
            ) as exc:

                print(
                    f"NVD network error: "
                    f"{exc}. "
                    f"Retrying in {delay}s..."
                )

                await asyncio.sleep(
                    delay
                )

                delay = min(
                    delay * 2,
                    60,
                )

        raise RuntimeError(
            "NVD request failed after retries"
        )

    async def fetch_window(
        self,
        start: datetime,
        end: datetime,
    ):

        records = []

        async with httpx.AsyncClient(
            timeout=120
        ) as client:

            start_index = 0

            while True:

                params = {
                    "startIndex":
                        start_index,

                    "resultsPerPage":
                        2000,

                    "pubStartDate":
                        start.strftime(
                            "%Y-%m-%dT%H:%M:%S.000Z"
                        ),

                    "pubEndDate":
                        end.strftime(
                            "%Y-%m-%dT%H:%M:%S.000Z"
                        ),
                }

                data = await self.request(
                    client,
                    params,
                )

                page = data.get(
                    "vulnerabilities",
                    [],
                )

                total = data.get(
                    "totalResults",
                    0,
                )

                records.extend(page)

                print(
                    f"NVD: "
                    f"{len(records)}/{total}"
                )

                if (
                    start_index
                    + len(page)
                    >= total
                ):
                    break

                if not page:
                    break

                start_index += len(page)

                # Don't hammer NVD.
                await asyncio.sleep(
                    0.7
                )

        return records

    async def historical(
        self,
        start_year=1999,
    ):

        start = datetime(
            start_year,
            1,
            1,
            tzinfo=timezone.utc,
        )

        end = datetime.now(
            timezone.utc
        )

        current = start

        while current < end:

            # NVD maximum date-range window is
            # 120 consecutive days.
            window_end = min(
                current
                + timedelta(days=119),
                end,
            )

            yield (
                current,
                window_end,
            )

            current = (
                window_end
                + timedelta(seconds=1)
            )