import io
import json
import zipfile

import httpx


class OSVSource:

    URL = (
        "https://storage.googleapis.com/"
        "osv-vulnerabilities/all.zip"
    )

    async def download(self):

        print(
            "Downloading OSV database..."
        )

        async with httpx.AsyncClient(
            timeout=600
        ) as client:

            response = await client.get(
                self.URL
            )

            response.raise_for_status()

        print(
            "OSV download complete."
        )

        return response.content

    async def records(self):

        content = await self.download()

        with zipfile.ZipFile(
            io.BytesIO(content)
        ) as archive:

            names = archive.namelist()

            print(
                f"OSV files: {len(names)}"
            )

            for name in names:

                if not name.endswith(
                    ".json"
                ):
                    continue

                try:

                    raw = archive.read(
                        name
                    )

                    record = json.loads(
                        raw
                    )

                    yield record

                except Exception as exc:

                    print(
                        f"OSV skip {name}: "
                        f"{exc}"
                    )