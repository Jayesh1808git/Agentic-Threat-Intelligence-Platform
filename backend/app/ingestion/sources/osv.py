import io
import json
import logging
import zipfile
import httpx

logger = logging.getLogger(__name__)

BASE_OSV_URL = "https://storage.googleapis.com/osv-vulnerabilities"


class OSVSource:

    def __init__(self, ecosystem: str = "PyPI", url: str | None = None):
        self.ecosystem = ecosystem
        if url:
            self.url = url
        elif ecosystem and ecosystem.lower() != "all":
            self.url = f"{BASE_OSV_URL}/{ecosystem}/all.zip"
        else:
            self.url = f"{BASE_OSV_URL}/all.zip"

    async def download(self) -> bytes:
        logger.info("Downloading OSV database for '%s' from %s...", self.ecosystem, self.url)

        async with httpx.AsyncClient(timeout=300.0) as client:
            response = await client.get(self.url, follow_redirects=True)
            response.raise_for_status()

        logger.info("OSV download complete (%d bytes).", len(response.content))
        return response.content

    async def records(self, max_records: int | None = None):
        content = await self.download()

        with zipfile.ZipFile(io.BytesIO(content)) as archive:
            names = [n for n in archive.namelist() if n.endswith(".json")]
            logger.info("OSV '%s' archive contains %d JSON files.", self.ecosystem, len(names))

            count = 0
            for name in names:
                if max_records and count >= max_records:
                    break

                try:
                    raw = archive.read(name)
                    record = json.loads(raw)
                    count += 1
                    yield record
                except Exception as exc:
                    logger.warning("OSV skip %s: %s", name, exc)
