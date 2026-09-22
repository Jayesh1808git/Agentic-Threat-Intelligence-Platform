
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx

from app.core.config import settings

logger = logging.getLogger(__name__)


class NVDFetcher:
    """Async client for the NVD CVE API 2.0."""

    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(
        self,
        api_key: str | None = None,
        page_size: int = 100,
        timeout: float = 60.0,
        max_retries: int = 5,
    ) -> None:
        if page_size < 1:
            raise ValueError("page_size must be at least 1.")
        if max_retries < 1:
            raise ValueError("max_retries must be at least 1.")

        self.api_key = api_key or settings.NVD_API_KEY or None
        self.page_size = min(page_size, 2000)
        self.timeout = timeout
        self.max_retries = max_retries

    def _headers(self) -> dict[str, str]:
        headers = {
            "Accept": "application/json",
            "User-Agent": "Agentic-Threat-Intelligence-Platform/1.0",
        }
        if self.api_key:
            headers["apiKey"] = self.api_key
        return headers

    @staticmethod
    def _format_nvd_datetime(value: datetime) -> str:
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)

        value = value.astimezone(timezone.utc)
        return value.strftime("%Y-%m-%dT%H:%M:%S.000Z")

    async def _request(
        self,
        client: httpx.AsyncClient,
        request_params: dict[str, Any],
    ) -> dict[str, Any]:
        delay = 2.0

        for attempt in range(1, self.max_retries + 1):
            try:
                response = await client.get(
                    self.BASE_URL,
                    params=request_params,
                    headers=self._headers(),
                )

                if response.status_code == 200:
                    return response.json()

                retryable = response.status_code in {
                    429, 500, 502, 503, 504
                }

                if not retryable:
                    response.raise_for_status()

                if attempt == self.max_retries:
                    response.raise_for_status()

                retry_after = response.headers.get("Retry-After")
                wait_time = delay

                if retry_after:
                    try:
                        wait_time = max(float(retry_after), 1.0)
                    except ValueError:
                        pass

                logger.warning(
                    "Retryable NVD HTTP %s; attempt %s/%s, "
                    "waiting %.1fs",
                    response.status_code,
                    attempt,
                    self.max_retries,
                    wait_time,
                )

                await asyncio.sleep(wait_time)
                delay = min(delay * 2, 60.0)

            except (httpx.TimeoutException, httpx.NetworkError):
                if attempt == self.max_retries:
                    raise

                logger.warning(
                    "NVD network/timeout error; attempt %s/%s, "
                    "waiting %.1fs",
                    attempt,
                    self.max_retries,
                    delay,
                )
                await asyncio.sleep(delay)
                delay = min(delay * 2, 60.0)

        raise RuntimeError("NVD request failed after retries.")

    async def fetch(
        self,
        *,
        start_index: int = 0,
        max_records: int | None = None,
        last_mod_start: datetime | None = None,
        last_mod_end: datetime | None = None,
        pub_start: datetime | None = None,
        pub_end: datetime | None = None,
    ) -> list[dict[str, Any]]:
        """Fetch raw CVE objects with optional date filters."""

        if start_index < 0:
            raise ValueError("start_index cannot be negative.")

        if max_records is not None and max_records <= 0:
            return []

        if last_mod_start and last_mod_end:
            if last_mod_end <= last_mod_start:
                raise ValueError(
                    "last_mod_end must be after last_mod_start."
                )

        if pub_start and pub_end and pub_end <= pub_start:
            raise ValueError("pub_end must be after pub_start.")

        request_params: dict[str, Any] = {
            "startIndex": start_index,
            "resultsPerPage": self.page_size,
        }

        if last_mod_start:
            request_params["lastModStartDate"] = (
                self._format_nvd_datetime(last_mod_start)
            )

        if last_mod_end:
            request_params["lastModEndDate"] = (
                self._format_nvd_datetime(last_mod_end)
            )

        if pub_start:
            request_params["pubStartDate"] = (
                self._format_nvd_datetime(pub_start)
            )

        if pub_end:
            request_params["pubEndDate"] = (
                self._format_nvd_datetime(pub_end)
            )

        records: list[dict[str, Any]] = []

        async with httpx.AsyncClient(
            timeout=self.timeout,
            follow_redirects=True,
        ) as client:
            current_index = start_index

            while True:
                request_params["startIndex"] = current_index

                data = await self._request(
                    client,
                    request_params,
                )

                vulnerabilities = data.get("vulnerabilities", [])
                total_results = int(data.get("totalResults", 0))

                if not vulnerabilities:
                    break

                for item in vulnerabilities:
                    cve = item.get("cve")
                    if cve:
                        records.append(cve)

                    if (
                        max_records is not None
                        and len(records) >= max_records
                    ):
                        return records[:max_records]

                current_index += len(vulnerabilities)

                logger.info(
                    "NVD pagination: %s/%s",
                    min(current_index, total_results),
                    total_results,
                )

                if current_index >= total_results:
                    break

                if not self.api_key:
                    await asyncio.sleep(0.7)

        return records

    async def fetch_modified_window(
        self,
        start: datetime,
        end: datetime,
        max_records: int | None = None,
    ) -> list[dict[str, Any]]:
        """Fetch CVEs whose NVD modification time is in this window."""

        if start.tzinfo is None:
            start = start.replace(tzinfo=timezone.utc)

        if end.tzinfo is None:
            end = end.replace(tzinfo=timezone.utc)

        start = start.astimezone(timezone.utc)
        end = end.astimezone(timezone.utc)

        if end <= start:
            raise ValueError(
                "Incremental window end must be after its start."
            )

        return await self.fetch(
            max_records=max_records,
            last_mod_start=start,
            last_mod_end=end,
        )

    async def fetch_recent(
        self,
        hours: int = 24,
        max_records: int | None = None,
    ) -> list[dict[str, Any]]:
        """Fetch CVEs modified in the last `hours`."""

        if hours <= 0:
            raise ValueError("hours must be positive.")

        end = datetime.now(timezone.utc)
        start = end - timedelta(hours=hours)

        return await self.fetch_modified_window(
            start=start,
            end=end,
            max_records=max_records,
        )