
import io
import json
import logging
import zipfile

import httpx

logger = logging.getLogger(__name__)

BASE_OSV_URL = "https://storage.googleapis.com/osv-vulnerabilities"


class OSVSource:
    def __init__(
        self,
        ecosystem: str = "PyPI",
        url: str | None = None,
    ):
        self.ecosystem = ecosystem

        if url:
            self.url = url
        elif ecosystem and ecosystem.lower() != "all":
            self.url = f"{BASE_OSV_URL}/{ecosystem}/all.zip"
        else:
            self.url = f"{BASE_OSV_URL}/all.zip"

    async def download(self) -> bytes:
        logger.info(
            "Downloading OSV database for '%s' from %s...",
            self.ecosystem,
            self.url,
        )

        async with httpx.AsyncClient(timeout=300.0) as client:
            response = await client.get(
                self.url,
                follow_redirects=True,
            )
            response.raise_for_status()

        content = response.content

        if not content:
            raise RuntimeError("OSV download returned an empty response")

        logger.info(
            "OSV download complete (%d bytes).",
            len(content),
        )

        return content

    async def records(self, max_records: int | None = None):
        if max_records is not None and max_records < 1:
            raise ValueError("max_records must be at least 1")

        content = await self.download()

        try:
            archive = zipfile.ZipFile(io.BytesIO(content))
        except zipfile.BadZipFile as exc:
            raise RuntimeError(
                "Downloaded OSV content is not a valid ZIP archive"
            ) from exc

        with archive:
            names = sorted(
                name
                for name in archive.namelist()
                if name.endswith(".json")
            )

            logger.info(
                "OSV '%s' archive contains %d JSON files.",
                self.ecosystem,
                len(names),
            )

            count = 0

            for name in names:
                if (
                    max_records is not None
                    and count >= max_records
                ):
                    logger.warning(
                        "OSV fetch reached max_records=%d; "
                        "results may be incomplete.",
                        max_records,
                    )
                    break

                try:
                    raw = archive.read(name)
                    record = json.loads(raw)

                    if not isinstance(record, dict):
                        raise ValueError(
                            "OSV JSON record is not an object"
                        )

                except Exception as exc:
                    raise RuntimeError(
                        f"Failed to read OSV record {name}"
                    ) from exc

                count += 1
                yield record