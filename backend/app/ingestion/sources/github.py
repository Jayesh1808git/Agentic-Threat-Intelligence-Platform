
import asyncio
import logging

import httpx

from app.core.config import settings

logger = logging.getLogger(__name__)


class GitHubAdvisorySource:
    def __init__(self, token: str | None = None):
        self.token = token or getattr(settings, "GITHUB_TOKEN", None)

    async def fetch_all(
        self,
        max_pages: int | None = None,
    ) -> list[dict]:
        if max_pages is not None and max_pages < 1:
            raise ValueError("max_pages must be at least 1")

        headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": "CyberRAG-ThreatIntel/1.0",
        }

        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"

        records: list[dict] = []
        page = 1
        max_attempts = 5

        async with httpx.AsyncClient(
            timeout=60.0,
            follow_redirects=True,
        ) as client:

            while True:
                if max_pages is not None and page > max_pages:
                    logger.warning(
                        "GitHub fetch reached max_pages=%d; "
                        "results may be incomplete.",
                        max_pages,
                    )
                    break

                params = {
                    "per_page": 100,
                    "page": page,
                    "type": "reviewed",
                }

                for attempt in range(1, max_attempts + 1):
                    try:
                        response = await client.get(
                            settings.GITHUB_ADVISORY_API,
                            headers=headers,
                            params=params,
                        )

                        if response.status_code in (429, 403):
                            remaining = response.headers.get(
                                "X-RateLimit-Remaining"
                            )
                            retry_after = response.headers.get(
                                "Retry-After"
                            )

                            # GitHub can indicate rate limiting with 403
                            # as well as 429.
                            if response.status_code == 429 or remaining == "0":
                                delay = int(retry_after or 10)

                                if attempt == max_attempts:
                                    response.raise_for_status()

                                logger.warning(
                                    "GitHub rate limit on page %d; "
                                    "retrying in %d seconds "
                                    "(attempt %d/%d)",
                                    page,
                                    delay,
                                    attempt,
                                    max_attempts,
                                )

                                await asyncio.sleep(delay)
                                continue

                        if response.status_code in (500, 502, 503, 504):
                            if attempt == max_attempts:
                                response.raise_for_status()

                            delay = min(2 ** attempt, 30)
                            logger.warning(
                                "GitHub server error %d on page %d; "
                                "retrying in %d seconds",
                                response.status_code,
                                page,
                                delay,
                            )
                            await asyncio.sleep(delay)
                            continue

                        response.raise_for_status()
                        data = response.json()

                        if not isinstance(data, list):
                            raise RuntimeError(
                                "Unexpected GitHub API response: "
                                "expected a JSON list"
                            )

                        break

                    except (httpx.TimeoutException, httpx.NetworkError):
                        if attempt == max_attempts:
                            raise

                        delay = min(2 ** attempt, 30)
                        logger.warning(
                            "GitHub network error on page %d; "
                            "retrying in %d seconds",
                            page,
                            delay,
                        )
                        await asyncio.sleep(delay)

                else:
                    raise RuntimeError(
                        f"GitHub failed to fetch page {page}"
                    )

                if not data:
                    logger.info(
                        "GitHub returned no records on page %d",
                        page,
                    )
                    break

                records.extend(data)

                logger.info(
                    "GitHub page %d fetched; total records=%d",
                    page,
                    len(records),
                )

                if len(data) < 100:
                    break

                page += 1

        return records