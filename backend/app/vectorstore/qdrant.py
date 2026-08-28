import hashlib
import time
import uuid
from qdrant_client import QdrantClient
from qdrant_client.models import (
    Distance,
    PointStruct,
    VectorParams,
)

import httpx

class QdrantVectorStore:

    VECTOR_SIZE = 384

    def __init__(
        self,
        url: str,
        api_key: str,
        collection_name: str,
    ):

        self.collection_name = (
            collection_name
        )

        print(
            f"Connecting to Qdrant: "
            f"{url}"
        )

        self.client = QdrantClient(
            url=url,
            api_key=api_key,
        )

        self._create_collection_if_needed()

    def _create_collection_if_needed(self):

        collections = (
            self.client
            .get_collections()
            .collections
        )

        exists = any(
            collection.name
            == self.collection_name
            for collection in collections
        )

        if exists:

            print(
                f"Qdrant collection "
                f"'{self.collection_name}' "
                f"already exists."
            )

            return

        print(
            f"Creating Qdrant collection "
            f"'{self.collection_name}'..."
        )

        self.client.create_collection(
            collection_name=(
                self.collection_name
            ),

            vectors_config=VectorParams(
                size=self.VECTOR_SIZE,
                distance=Distance.COSINE,
            ),
        )

        print("Qdrant collection created.")

    def upsert(
        self,
        vectors,
        vulnerabilities,
        max_retries: int = 5,
    ):

        points = []

        for vector, vulnerability in zip(
            vectors,
            vulnerabilities,
        ):

            point_id = self._generate_id(
                vulnerability
            )

            payload = self._build_payload(
                vulnerability
            )

            points.append(
                PointStruct(
                    id=point_id,
                    vector=vector.tolist(),
                    payload=payload,
                )
            )

        if not points:
            return

        last_error = None

        for attempt in range(
            1,
            max_retries + 1,
        ):

            try:

                self.client.upsert(
                    collection_name=(
                        self.collection_name
                    ),
                    points=points,
                )

                return

            except Exception as exc:

                last_error = exc

                print(
                    f"Qdrant upload failed "
                    f"(attempt {attempt}/"
                    f"{max_retries})"
                )

                print(
                    f"Error: {exc}"
                )

                if attempt < max_retries:

                    wait = min(
                        2 ** (attempt - 1),
                        30,
                    )

                    print(
                        f"Retrying in {wait} seconds..."
                    )

                    time.sleep(wait)

        raise RuntimeError(
            "Qdrant upload failed after "
            f"{max_retries} attempts"
        ) from last_error

    @staticmethod
    def _generate_id(vulnerability) -> str:
        identity = (
            vulnerability.cve
            or (
                vulnerability.source
                + ":"
                + vulnerability.vulnerability_id
            )
        )
        return str(
            uuid.uuid5(
                uuid.NAMESPACE_URL,
                identity,
            )
        )

    @staticmethod
    def _build_payload(
        vulnerability,
    ):

        return {

            "cve": vulnerability.cve,

            "vulnerability_id": (
                vulnerability.vulnerability_id
            ),

            "source": (
                vulnerability.source
            ),

            "aliases": (
                vulnerability.aliases
            ),

            "title": (
                vulnerability.title
            ),

            "description": (
                vulnerability.description
            ),

            "vendor": (
                vulnerability.vendor
            ),

            "product": (
                vulnerability.product
            ),

            "ecosystem": (
                vulnerability.ecosystem
            ),

            "package_name": (
                vulnerability.package_name
            ),

            "affected_versions": (
                vulnerability.affected_versions
            ),

            "patched_versions": (
                vulnerability.patched_versions
            ),

            "cpe_matches": (
                vulnerability.cpe_matches
            ),

            "cvss": (
                vulnerability.cvss
            ),

            "cvss_vector": (
                vulnerability.cvss_vector
            ),

            "epss": (
                vulnerability.epss
            ),

            "epss_percentile": (
                vulnerability.epss_percentile
            ),

            "kev": (
                vulnerability.kev
            ),

            "kev_date": (
                vulnerability.kev_date.isoformat()
                if vulnerability.kev_date
                else None
            ),

            "exploit_available": (
                vulnerability.exploit_available
            ),

            "references": (
                vulnerability.references
            ),

            "published": (
                vulnerability.published.isoformat()
                if vulnerability.published
                else None
            ),

            "updated": (
                vulnerability.updated.isoformat()
                if vulnerability.updated
                else None
            ),
        }

    def count(self) -> int:

        info = self.client.get_collection(
            self.collection_name
        )

        return info.points_count