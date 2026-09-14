from app.core.config import settings
from app.database.postgres import SessionLocal
from app.embeddings.service import EmbeddingService
from backend.app.repositories.vulnerability import (
    VulnerabilityRepository,
)
from app.indexing.qdrant import QdrantVectorStore


class EmbeddingWorker:

    def __init__(
        self,
        batch_size: int = 100,
    ):

        self.batch_size = batch_size

        self.embeddings = EmbeddingService(
            settings.EMBEDDING_MODEL
        )

        self.vector_store = (
            QdrantVectorStore()
        )

    def run_once(self) -> int:

        db = SessionLocal()

        try:

            repository = (
                VulnerabilityRepository(db)
            )

            records = (
                repository.get_pending_embeddings(
                    self.batch_size
                )
            )

            if not records:
                return 0

            texts = [
                self.embeddings.build_text(
                    record
                )
                for record in records
            ]

            vectors = (
                self.embeddings.embed_batch(
                    texts
                )
            )

            indexed = 0

            for record, vector in zip(
                records,
                vectors,
            ):

                try:

                    self.vector_store.upsert(
                        record,
                        vector,
                    )

                    repository.mark_embedding_indexed(
                        record,
                        self.embeddings.model_name,
                    )

                    indexed += 1

                except Exception as exc:

                    print(
                        "Qdrant indexing failed "
                        f"for {record.vulnerability_id}: "
                        f"{exc}"
                    )

                    repository.mark_embedding_failed(
                        record
                    )

            db.commit()

            return indexed

        except Exception:

            db.rollback()
            raise

        finally:

            db.close()

    def run_until_empty(self) -> int:

        total = 0

        while True:

            count = self.run_once()

            if count == 0:
                break

            total += count

            print(
                f"Indexed embeddings: "
                f"{total}"
            )

        self.vector_store.close()

        return total


if __name__ == "__main__":

    worker = EmbeddingWorker(
        batch_size=100
    )

    total = worker.run_until_empty()

    print(
        f"Embedding indexing complete: {total}"
    )