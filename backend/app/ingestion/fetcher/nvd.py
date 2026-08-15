from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import params
import httpx

from app.core.config import settings

logger = logging.getLogger(__name__)


class NVDFetcher:
    """
    Client for the NVD CVE API 2.0.

    Responsibilities:
    - Fetch CVE records from NVD
    - Handle pagination
    - Handle rate limits and transient failures
    - Support incremental synchronization
    - Return raw NVD records

    Normalization is handled separately.
    """

    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(
        self,
        api_key: str | None = None,
        page_size: int = 100,
        timeout: float = 30.0,
        max_retries: int = 3,
    ):
        self.api_key = api_key or settings.NVD_API_KEY or None
        self.page_size = min(page_size, 2000)
        self.timeout = timeout
        self.max_retries = max_retries

    def _headers(self) -> dict[str, str]:
        """
        Build request headers.

        NVD API key is optional.
        """
        headers = {
            "Accept": "application/json",
            "User-Agent": "Agentic-Threat-Intelligence-Platform/1.0",
        }

        if self.api_key:
            headers["apiKey"] = self.api_key

        return headers

    @staticmethod
    def _format_nvd_datetime(value: datetime) -> str:
        """
        Convert datetime to NVD's expected ISO-8601 format.
        """
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)

        value = value.astimezone(timezone.utc)

        return value.strftime("%Y-%m-%dT%H:%M:%S.000Z")

    async def _request(
        self,
        client: httpx.AsyncClient,
        params: dict[str, Any],
    ) -> dict[str, Any]:

        for attempt in range(1, self.max_retries + 1):

            try:
                response = await client.get(
                    self.BASE_URL,
                    params=params,
                    headers=self._headers(),
                )

                if response.status_code == 200:
                    return response.json()

                if response.status_code == 429:
                    retry_after = response.headers.get("Retry-After")

                    if retry_after:
                        try:
                            wait_time = float(retry_after)
                        except ValueError:
                            wait_time = 10.0
                    else:
                        wait_time = min(10 * attempt, 60)

                    logger.warning(
                        "NVD rate limit reached. "
                        "Retrying in %.1f seconds...",
                        wait_time,
                    )

                    await asyncio.sleep(wait_time)
                    continue

                if response.status_code in {500, 502, 503, 504}:
                    wait_time = min(2**attempt, 30)

                    logger.warning(
                        "NVD server error %s. "
                        "Retrying in %s seconds...",
                        response.status_code,
                        wait_time,
                    )

                    await asyncio.sleep(wait_time)
                    continue

                response.raise_for_status()

            except httpx.TimeoutException as exc:

                if attempt == self.max_retries:
                    raise

                wait_time = min(2**attempt, 30)

                logger.warning(
                    "NVD request timed out. "
                    "Retrying in %s seconds...",
                    wait_time,
                )

                await asyncio.sleep(wait_time)

            except httpx.RequestError:

                if attempt == self.max_retries:
                    raise

                wait_time = min(2**attempt, 30)

                logger.warning(
                    "NVD network error. "
                    "Retrying in %s seconds...",
                    wait_time,
                )

                await asyncio.sleep(wait_time)

        raise RuntimeError("NVD request failed after all retries.")

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
        """
        Fetch CVE records from NVD.

        Parameters
        ----------
        start_index:
            Starting record index.

        max_records:
            Maximum number of records to retrieve.
            Useful during development/testing.

        last_mod_start:
            Only return CVEs modified after this time.

        last_mod_end:
            Only return CVEs modified before this time.

        Returns
        -------
        list[dict]
            Raw NVD vulnerability records.
        """

        records: list[dict[str, Any]] = []

        if max_records is not None and max_records <= 0:
            return records

        params: dict[str, Any] = {
            "startIndex": start_index,
            "resultsPerPage": self.page_size,
        }

        if last_mod_start:
            params["lastModStartDate"] = self._format_nvd_datetime(
                last_mod_start
            )

        if last_mod_end:
            params["lastModEndDate"] = self._format_nvd_datetime(
                last_mod_end
            )
        if pub_start:
            params["pubStartDate"] = self._format_nvd_datetime(
            pub_start
            )

        if pub_end:
            params["pubEndDate"] = self._format_nvd_datetime(
                pub_end
            )

        async with httpx.AsyncClient(
            timeout=self.timeout,
            follow_redirects=True,
        ) as client:

            current_index = start_index

            while True:

                params["startIndex"] = current_index

                logger.info(
                    "Fetching NVD records starting at index %s",
                    current_index,
                )

                data = await self._request(
                    client,
                    params,
                )

                vulnerabilities = data.get(
                    "vulnerabilities",
                    [],
                )

                total_results = data.get(
                    "totalResults",
                    0,
                )

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
                    "Fetched %s/%s NVD records",
                    min(current_index, total_results),
                    total_results,
                )

                if current_index >= total_results:
                    break

                # Small delay to avoid unnecessary rate limiting.
                if not self.api_key:
                    await asyncio.sleep(0.7)

        return records

    async def fetch_recent(
        self,
        hours: int = 24,
        max_records: int | None = None,
    ) -> list[dict[str, Any]]:
        """
        Fetch CVEs modified during the last `hours`.
        """

        end = datetime.now(timezone.utc)

        start = end - timedelta(hours=hours)

        return await self.fetch(
            max_records=max_records,
            last_mod_start=start,
            last_mod_end=end,
        )