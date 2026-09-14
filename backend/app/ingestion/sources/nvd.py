from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from typing import Any, AsyncIterator

import httpx


NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

PAGE_SIZE = 2_000

# NVD allows date ranges, but keeping the historical windows
# comfortably below the maximum makes the importer more reliable.
WINDOW_DAYS = 119

MAX_RETRIES = 8
INITIAL_RETRY_DELAY = 2
MAX_RETRY_DELAY = 60


class NVDSource:
    """
    NVD API 2.0 client.

    Responsibilities:
    - Fetch NVD CVE records
    - Handle pagination
    - Retry temporary failures
    - Generate historical date windows

    This class does NOT write to PostgreSQL.
    """

    def __init__(
        self,
        api_key: str | None = None,
    ):
        self.api_key = api_key or None

    # ============================================================
    # HTTP
    # ============================================================

    def _headers(self) -> dict[str, str]:
        headers = {
            "User-Agent": (
                "CyberRAG-Agentic-Threat-Intelligence-Platform/1.0"
            ),
            "Accept": "application/json",
        }

        if self.api_key:
            headers["apiKey"] = self.api_key

        return headers

    async def request(
        self,
        client: httpx.AsyncClient,
        params: dict[str, Any],
    ) -> dict[str, Any]:

        delay = INITIAL_RETRY_DELAY

        for attempt in range(1, MAX_RETRIES + 1):

            try:
                response = await client.get(
                    NVD_URL,
                    params=params,
                    headers=self._headers(),
                )

                if response.status_code == 200:
                    return response.json()

                if response.status_code in {
                    429,
                    500,
                    502,
                    503,
                    504,
                }:

                    if attempt == MAX_RETRIES:
                        response.raise_for_status()

                    print(
                        f"NVD HTTP {response.status_code}. "
                        f"Retry {attempt}/{MAX_RETRIES} "
                        f"in {delay}s..."
                    )

                    await asyncio.sleep(delay)

                    delay = min(
                        delay * 2,
                        MAX_RETRY_DELAY,
                    )

                    continue

                response.raise_for_status()

            except (
                httpx.TimeoutException,
                httpx.NetworkError,
            ) as exc:

                if attempt == MAX_RETRIES:
                    raise

                print(
                    f"NVD network error: {exc}. "
                    f"Retry {attempt}/{MAX_RETRIES} "
                    f"in {delay}s..."
                )

                await asyncio.sleep(delay)

                delay = min(
                    delay * 2,
                    MAX_RETRY_DELAY,
                )

        raise RuntimeError(
            "NVD request failed after retries."
        )

    # ============================================================
    # FETCH ONE PAGE
    # ============================================================

    async def fetch_page(
        self,
        client: httpx.AsyncClient,
        start: datetime,
        end: datetime,
        start_index: int,
    ) -> tuple[list[dict[str, Any]], int]:

        params = {
            "startIndex": start_index,
            "resultsPerPage": PAGE_SIZE,
            "pubStartDate": self._format_datetime(start),
            "pubEndDate": self._format_datetime(end),
        }

        data = await self.request(
            client,
            params,
        )

        records = data.get(
            "vulnerabilities",
            [],
        )

        total = int(
            data.get(
                "totalResults",
                0,
            )
        )

        return records, total

    # ============================================================
    # FETCH COMPLETE WINDOW
    # ============================================================

    async def fetch_window(
        self,
        start: datetime,
        end: datetime,
    ) -> list[dict[str, Any]]:

        records: list[dict[str, Any]] = []

        async with httpx.AsyncClient(
            timeout=httpx.Timeout(
                connect=30,
                read=120,
                write=120,
                pool=30,
            )
        ) as client:

            start_index = 0
            page_number = 0
            total = None

            while True:

                page_number += 1

                page, page_total = await self.fetch_page(
                    client=client,
                    start=start,
                    end=end,
                    start_index=start_index,
                )

                if total is None:
                    total = page_total

                    print(
                        f"NVD total for window: {total}"
                    )

                if not page:
                    break

                records.extend(page)

                print(
                    f"NVD page {page_number}: "
                    f"{len(page)} records "
                    f"({len(records)}/{total})"
                )

                start_index += len(page)

                if start_index >= total:
                    break

                # Respect NVD API rate limits.
                await asyncio.sleep(0.7)

        return records

    # ============================================================
    # HISTORICAL WINDOWS
    # ============================================================

    async def historical(
    self,
    start_year: int = 1999,
    end_year: int = 2024,
):
        start = datetime(
            start_year,
            1,
            1,
            tzinfo=timezone.utc,
        )

        # Explicitly stop at 2024-12-31 23:59:59 UTC.
        # This prevents overlap with the already-ingested
        # 2025-2026 data.
        end = datetime(
            end_year,
            12,
            31,
            23,
            59,
            59,
            tzinfo=timezone.utc,
        )

        current = start

        while current <= end:

            window_end = min(
                current + timedelta(days=119),
                end,
            )

            yield current, window_end

            current = (
                window_end
                + timedelta(seconds=1)
            )

    # ============================================================
    # DATETIME FORMAT
    # ============================================================

    @staticmethod
    def _format_datetime(
        value: datetime,
    ) -> str:

        if value.tzinfo is None:
            value = value.replace(
                tzinfo=timezone.utc
            )

        value = value.astimezone(
            timezone.utc
        )

        return value.strftime(
            "%Y-%m-%dT%H:%M:%S.000Z"
        )