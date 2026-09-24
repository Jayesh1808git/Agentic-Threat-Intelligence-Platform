import logging
import time
from typing import Any

from app.core.config import settings
from app.database.postgres import SessionLocal
from app.embeddings.service import EmbeddingService
from app.repositories.vulnerability import VulnerabilityRepository
from indexing.qdrant import QdrantVectorStore
from app.models.vulnerability import Vulnerability
from sqlalchemy import select, func

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)
logger = logging.getLogger("embedding_worker")


class EmbeddingWorker:

    def __init__(self, batch_size: int = 100):
        self.batch_size = batch_size
        self.embeddings = EmbeddingService(settings.EMBEDDING_MODEL)
        self.vector_store = QdrantVectorStore()

    def get_remaining_count(self, db) -> int:
        return db.scalar(
            select(func.count(Vulnerability.id)).where(
                Vulnerability.embedding_status.in_(["pending", "failed"])
            )
        ) or 0

    def run_once(self) -> dict[str, int]:
        db = SessionLocal()
        stats = {"processed": 0, "completed": 0, "failed": 0, "skipped": 0}

        try:
            repository = VulnerabilityRepository(db)

            # Query records pending embedding
            records = repository.get_pending_embeddings(self.batch_size)
            if not records:
                return stats

            stats["processed"] = len(records)
            texts = [self.embeddings.build_text(record) for record in records]

            try:
                vectors = self.embeddings.embed_batch(texts)
            except Exception as exc:
                logger.error("Failed to generate embedding batch: %s", exc)
                for record in records:
                    repository.mark_embedding_failed(record)
                db.commit()
                stats["failed"] = len(records)
                return stats

            # Prepare items for Qdrant batch upsert
            records_and_vectors = list(zip(records, vectors))

            try:
                self.vector_store.upsert_batch(records_and_vectors)
                for record in records:
                    repository.mark_embedding_indexed(
                        record,
                        self.embeddings.model_name,
                    )
                db.commit()
                stats["completed"] = len(records)
            except Exception as exc:
                logger.error("Qdrant batch upsert failed, retrying individually: %s", exc)
                db.rollback()

                # Fallback to item-by-item upsert if batch fails
                for record, vector in records_and_vectors:
                    try:
                        self.vector_store.upsert(record, vector)
                        repository.mark_embedding_indexed(
                            record,
                            self.embeddings.model_name,
                        )
                        db.commit()
                        stats["completed"] += 1
                    except Exception as ind_exc:
                        db.rollback()
                        logger.error(
                            "Failed to index vulnerability %s: %s",
                            record.vulnerability_id,
                            ind_exc,
                        )
                        repository.mark_embedding_failed(record)
                        db.commit()
                        stats["failed"] += 1

            return stats

        except Exception as exc:
            db.rollback()
            logger.error("Error during embedding worker run_once: %s", exc)
            raise
        finally:
            db.close()

    def run_until_empty(self) -> dict[str, int]:
        total_stats = {
            "processed": 0,
            "completed": 0,
            "failed": 0,
            "skipped": 0,
        }

        db = SessionLocal()
        initial_remaining = self.get_remaining_count(db)
        db.close()

        logger.info("Starting embedding worker. Initial pending records: %d", initial_remaining)

        start_time = time.time()
        while True:
            stats = self.run_once()
            if stats["processed"] == 0:
                break

            total_stats["processed"] += stats["processed"]
            total_stats["completed"] += stats["completed"]
            total_stats["failed"] += stats["failed"]
            total_stats["skipped"] += stats["skipped"]

            db = SessionLocal()
            remaining = self.get_remaining_count(db)
            db.close()

            logger.info(
                "Progress -> Processed: %d | Completed: %d | Failed: %d | Remaining: %d",
                total_stats["processed"],
                total_stats["completed"],
                total_stats["failed"],
                remaining,
            )

        elapsed = time.time() - start_time
        logger.info(
            "Embedding indexing complete in %.2f seconds. Final Stats: %s",
            elapsed,
            total_stats,
        )
        self.vector_store.close()
        return total_stats


if __name__ == "__main__":
    import argparse
    from sqlalchemy import update

    parser = argparse.ArgumentParser(description="CyberRAG Vulnerability Embedding Worker")
    parser.add_argument(
        "--rebuild",
        "--force",
        action="store_true",
        help="Reset embedding status for all vulnerabilities to 'pending' and re-embed all records into Qdrant.",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=100,
        help="Batch size for embedding generation (default: 100).",
    )
    args = parser.parse_args()

    if args.rebuild:
        db = SessionLocal()
        reset_count = db.execute(
            update(Vulnerability).values(embedding_status="pending")
        ).rowcount
        db.commit()
        db.close()
        logger.info("Rebuild flag specified. Reset %d records to 'pending'.", reset_count)

    worker = EmbeddingWorker(batch_size=args.batch_size)
    final_stats = worker.run_until_empty()
    print("Embedding worker completed with stats:", final_stats)

