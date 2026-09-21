import csv
import gzip
import io
import logging
import httpx
from app.core.config import settings

logger = logging.getLogger(__name__)

BULK_EPSS_CSV_URL = "https://epss.cyentia.com/epss-csv.gz"


class EPSSSource:

    def __init__(self, url: str | None = None):
        self.url = url or settings.EPSS_API_URL

    async def fetch_bulk_csv(self) -> dict[str, float]:
        """
        Download daily full EPSS dataset from Cyentia / FIRST (epss-csv.gz).
        Returns a dictionary mapping CVE ID to float EPSS score.
        """
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        }
        logger.info("Downloading bulk EPSS CSV from %s...", BULK_EPSS_CSV_URL)
        async with httpx.AsyncClient(timeout=300.0, headers=headers) as client:
            response = await client.get(BULK_EPSS_CSV_URL, follow_redirects=True)
            response.raise_for_status()

        result: dict[str, float] = {}
        with gzip.GzipFile(fileobj=io.BytesIO(response.content)) as gz:
            text_stream = io.TextIOWrapper(gz, encoding="utf-8")
            for line in text_stream:
                if line.startswith("#"):
                    continue
                parts = line.strip().split(",")
                if len(parts) >= 2 and parts[0].startswith("cve"):
                    continue
                if len(parts) >= 2:
                    cve_id = parts[0].strip().upper()
                    try:
                        score = float(parts[1])
                        result[cve_id] = score
                    except ValueError:
                        pass

        logger.info("Parsed %d EPSS scores from bulk CSV.", len(result))
        return result


    async def fetch_batch(self, cves: list[str]) -> dict[str, float]:
        if not cves:
            return {}

        result: dict[str, float] = {}
        batch_size = 100

        async with httpx.AsyncClient(timeout=60.0) as client:
            for i in range(0, len(cves), batch_size):
                batch = cves[i : i + batch_size]
                try:
                    response = await client.get(
                        self.url,
                        params={"cve": ",".join(batch)},
                    )
                    response.raise_for_status()
                    data = response.json()

                    for row in data.get("data", []):
                        try:
                            result[row["cve"].upper()] = float(row["epss"])
                        except (KeyError, TypeError, ValueError):
                            pass
                except Exception as exc:
                    logger.warning("EPSS batch fetch error: %s", exc)

        return result