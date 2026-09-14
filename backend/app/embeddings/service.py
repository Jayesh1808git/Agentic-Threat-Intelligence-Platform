from sentence_transformers import SentenceTransformer


class EmbeddingService:

    def __init__(
        self,
        model_name: str,
    ):
        self.model_name = model_name

        print(
            f"Loading embedding model: "
            f"{model_name}"
        )

        self.model = SentenceTransformer(
            model_name
        )

    @staticmethod
    def build_text(vulnerability) -> str:

        return "\n".join([
            f"Vendor: {vulnerability.vendor or ''}",
            f"Product: {vulnerability.product or ''}",
            f"Title: {vulnerability.title or ''}",
            (
                "Description: "
                f"{vulnerability.description or ''}"
            ),
        ])

    def embed(
        self,
        text: str,
    ) -> list[float]:

        vector = self.model.encode(
            text,
            normalize_embeddings=True,
        )

        return vector.tolist()

    def embed_batch(
        self,
        texts: list[str],
    ) -> list[list[float]]:

        vectors = self.model.encode(
            texts,
            normalize_embeddings=True,
            batch_size=32,
            show_progress_bar=True,
        )

        return vectors.tolist()