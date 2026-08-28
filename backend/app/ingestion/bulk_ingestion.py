import asyncio
import json
from pathlib import Path

from datetime import datetime, timezone

from app.core.config import settings

from app.embeddings.service import (
    EmbeddingService,
)

from app.ingestion.sources.nvd import (
    NVDSource,
)

from app.ingestion.sources.cisa import (
    CISASource,
)

from app.ingestion.sources.epss import (
    EPSSSource,
)

from app.ingestion.sources.github import (
    GitHubAdvisorySource,
)

from app.ingestion.sources.osv import (
    OSVSource,
)

from app.ingestion.sources.osv_normalizer import (
    OSVNormalizer,
)

from app.ingestion.normalizer.nvd import (
    NVDNormalizer,
)

from app.vectorstore.weaviate_client import (
    WeaviateClient,
)

from app.vectorstore.vulnerability_writer import (
    VulnerabilityWriter,
)

from app.ingestion.state.checkpoint import (
    Checkpoint,
)


class BulkIngestion:

    def __init__(self):

        self.checkpoint = Checkpoint()

        self.embeddings = (
            EmbeddingService(
                settings.EMBEDDING_MODEL
            )
        )

        self.weaviate = (
            WeaviateClient(
                settings.WEAVIATE_URL,
                settings.WEAVIATE_API_KEY,
            )
        )

        self.writer = (
            VulnerabilityWriter(
                self.weaviate.client,
                settings.WEAVIATE_COLLECTION,
            )
        )

    # --------------------------------------------------
    # Embedding + writing
    # --------------------------------------------------
    def save_failed_record(
    self,
    vulnerability,
    error,
):

        path = Path(
            "data/failed_ingestion.jsonl"
        )

        path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        record = {
            "source": getattr(
                vulnerability,
                "source",
                None,
            ),

            "vulnerability_id":
                getattr(
                    vulnerability,
                    "vulnerability_id",
                    None,
                ),

            "cve":
                getattr(
                    vulnerability,
                    "cve",
                    None,
                ),

            "error": str(error),
        }

        with path.open(
            "a",
            encoding="utf-8",
        ) as f:

            f.write(
                json.dumps(
                    record
                )
                + "\n"
            )
    def write_records(
    self,
    records,
    source_name,
):

        if not records:
            return 0

        # Larger batch = fewer Weaviate requests.
        # 64 is a good starting point for your setup.
        batch_size = 128

        total = len(records)
        processed = 0
        failed = 0

        print(
            f"{source_name}: "
            f"Writing {total} records "
            f"in batches of {batch_size}"
        )

        for start in range(
            0,
            total,
            batch_size,
        ):

            batch = records[
                start:start + batch_size
            ]

            try:

                # ------------------------------------------
                # Build embedding text
                # ------------------------------------------

                texts = [
                    self.writer.build_embedding_text(v)
                    for v in batch
                ]

                # ------------------------------------------
                # Generate embeddings in one call
                # ------------------------------------------

                vectors = (
                    self.embeddings.embed_batch(
                        texts
                    )
                )

                # ------------------------------------------
                # Batch write to Weaviate
                # ------------------------------------------

                successful, batch_failed = (
                    self.writer.batch_upsert(
                        batch,
                        vectors,
                    )
                )

                processed += successful
                failed += batch_failed

                print(
                    f"{source_name}: "
                    f"{min(start + batch_size, total)}/{total} "
                    f"written "
                    f"(failed: {failed})"
                )

            except Exception as exc:

                print()
                print(
                    f"{source_name} BATCH FAILED"
                )

                print(
                    f"Batch: "
                    f"{start + 1}-"
                    f"{min(start + batch_size, total)}"
                )

                print(
                    f"Error: {exc}"
                )

                # ------------------------------------------
                # Save individual records from failed batch
                # ------------------------------------------

                for vulnerability in batch:

                    vulnerability_id = getattr(
                        vulnerability,
                        "vulnerability_id",
                        "UNKNOWN",
                    )

                    self.save_failed_record(
                        vulnerability,
                        exc,
                    )

                    failed += 1

                    print(
                        f"  Failed: "
                        f"{vulnerability_id}"
                    )

        print()
        print(
            f"{source_name} write summary:"
        )

        print(
            f"  Successful: {processed}"
        )

        print(
            f"  Failed:     {failed}"
        )

        return processed

    # --------------------------------------------------
    # NVD
    # --------------------------------------------------

    async def ingest_nvd(self):

        print()
        print("=" * 70)
        print("STARTING NVD HISTORICAL INGESTION")
        print("=" * 70)

        source = NVDSource(
            settings.NVD_API_KEY
        )

        normalizer = NVDNormalizer()

        async for start, end in (
            source.historical(1999)
        ):

            window = (
                f"{start.date()}_"
                f"{end.date()}"
            )

            # --------------------------------------------------
            # Skip completed windows
            # --------------------------------------------------

            if self.checkpoint.nvd_done(window):

                print(
                    f"SKIP NVD: {window}"
                )

                continue

            print()
            print(
                f"NVD WINDOW: "
                f"{start.date()} → "
                f"{end.date()}"
            )

            try:

                # --------------------------------------------------
                # FETCH
                # --------------------------------------------------

                raw = await source.fetch_window(
                    start,
                    end,
                )

                print(
                    f"Fetched: {len(raw)}"
                )

                # --------------------------------------------------
                # NORMALIZE
                # --------------------------------------------------

                normalized = []

                for record in raw:

                    try:

                        v = normalizer.normalize(
                            record
                        )

                        # Some old NVD records may not
                        # contain a useful title.

                        if not v.title:

                            v.title = (
                                v.cve
                                or v.vulnerability_id
                                or "Unknown vulnerability"
                            )

                        # Some historical records may
                        # have an empty description.

                        if not v.description:

                            v.description = (
                                v.title
                            )

                        normalized.append(v)

                    except Exception as exc:

                        vulnerability_id = (
                            record
                            .get("cve", {})
                            .get("id", "UNKNOWN")
                        )

                        print(
                            f"NORMALIZATION ERROR: "
                            f"{vulnerability_id}"
                        )

                        print(
                            f"  {exc}"
                        )

                        # Do NOT stop the entire window
                        # because one record failed.

                        continue

                print(
                    f"Normalized: "
                    f"{len(normalized)}"
                )

                # --------------------------------------------------
                # SAFETY CHECK
                # --------------------------------------------------

                if raw and not normalized:

                    raise RuntimeError(
                        f"NVD returned "
                        f"{len(raw)} records, "
                        f"but 0 records were normalized."
                    )

                # --------------------------------------------------
                # WRITE TO WEAVIATE
                # --------------------------------------------------

                written = self.write_records(
                    normalized,
                    "NVD",
                )

                # --------------------------------------------------
                # WINDOW RESULT
                # --------------------------------------------------

                if normalized and written == 0:

                    raise RuntimeError(
                        f"NVD returned "
                        f"{len(normalized)} normalized "
                        f"records, but 0 were written "
                        f"to Weaviate."
                    )

                # --------------------------------------------------
                # CHECKPOINT
                # --------------------------------------------------

                self.checkpoint.mark_nvd_done(
                    window
                )

                print()
                print(
                    f"COMPLETED: {window}"
                )

                print(
                    f"  Fetched:    {len(raw)}"
                )

                print(
                    f"  Normalized: {len(normalized)}"
                )

                print(
                    f"  Written:    {written}"
                )

                # Individual failures should NOT
                # stop the historical ingestion.

                if written < len(normalized):

                    failed_count = (
                        len(normalized) - written
                    )

                    raise RuntimeError(
                        f"NVD window {window} had "
                        f"{failed_count} failed records."
                    )

            except Exception as exc:

                print()
                print("=" * 70)
                print(
                    f"NVD WINDOW FAILED: {window}"
                )
                print("=" * 70)

                print(
                    f"NVD ingestion failed: {exc}"
                )

                print(
                    "Stopping. "
                    "Run again to resume."
                )

                # IMPORTANT:
                # Do NOT checkpoint this window.

                raise

    # --------------------------------------------------
    # CISA
    # --------------------------------------------------

    async def ingest_cisa(self):

        print()
        print("=" * 70)
        print("CISA KEV ENRICHMENT")
        print("=" * 70)

        if self.checkpoint.state[
            "cisa_completed"
        ]:
            print(
                "CISA already completed."
            )
            return

        source = CISASource(
            settings.CISA_KEV_URL
        )

        records = await source.fetch()

        print(
            f"CISA records: "
            f"{len(records)}"
        )

        # We do NOT create duplicate vectors.
        #
        # CISA is used to enrich CVEs.
        #
        # This stage will be implemented
        # using Weaviate filters.

        self.checkpoint.state[
            "cisa_completed"
        ] = True

        self.checkpoint.save()

    # --------------------------------------------------
    # EPSS
    # --------------------------------------------------

    async def ingest_epss(self):

        print()
        print("=" * 70)
        print("EPSS ENRICHMENT")
        print("=" * 70)

        if self.checkpoint.state[
            "epss_completed"
        ]:
            print(
                "EPSS already completed."
            )
            return

        # EPSS should enrich the NVD objects.
        #
        # We intentionally do this AFTER
        # NVD ingestion.
        #
        # Full update implementation follows
        # once NVD corpus exists.

        self.checkpoint.state[
            "epss_completed"
        ] = True

        self.checkpoint.save()

    # --------------------------------------------------
    # OSV
    # --------------------------------------------------

    async def ingest_osv(self):

        print()
        print("=" * 70)
        print("OSV FULL DATABASE INGESTION")
        print("=" * 70)

        if self.checkpoint.state[
            "osv_completed"
        ]:
            print(
                "OSV already completed."
            )
            return

        source = OSVSource()

        normalizer = OSVNormalizer()

        count = 0

        async for raw in source.records():

            # Skip withdrawn records.
            if raw.get("withdrawn"):
                continue

            try:

                v = normalizer.normalize(
                    raw
                )

                vector = (
                    self.embeddings.embed(
                        self.writer
                        .build_embedding_text(v)
                    )
                )

                self.writer.upsert(
                    v,
                    vector,
                )

                count += 1

                if count % 100 == 0:

                    print(
                        f"OSV indexed: "
                        f"{count}"
                    )

            except Exception as exc:

                print(
                    f"OSV record failed: "
                    f"{exc}"
                )

        self.checkpoint.state[
            "osv_completed"
        ] = True

        self.checkpoint.save()

        print(
            f"OSV complete: {count}"
        )

    # --------------------------------------------------
    # GitHub
    # --------------------------------------------------

    async def ingest_github(self):

        print()
        print("=" * 70)
        print("GITHUB ADVISORY INGESTION")
        print("=" * 70)

        if self.checkpoint.state[
            "github_completed"
        ]:
            print(
                "GitHub already completed."
            )
            return

        source = (
            GitHubAdvisorySource()
        )

        records = (
            await source.fetch_all()
        )

        print(
            f"GitHub advisories: "
            f"{len(records)}"
        )

        # GitHub normalization should be
        # handled here.
        #
        # We don't mark the source complete
        # until every record has been handled.

        self.checkpoint.state[
            "github_completed"
        ] = True

        self.checkpoint.save()

    # --------------------------------------------------
    # RUN
    # --------------------------------------------------

    async def run(
        self,
        nvd=True,
        osv=True,
        github=True,
        cisa=True,
        epss=True,
    ):

        try:

            if nvd:
                await self.ingest_nvd()

            if osv:
                await self.ingest_osv()

            if github:
                await self.ingest_github()

            if cisa:
                await self.ingest_cisa()

            if epss:
                await self.ingest_epss()

        finally:

            self.weaviate.close()
        