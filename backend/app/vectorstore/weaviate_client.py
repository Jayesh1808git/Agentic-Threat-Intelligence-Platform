import weaviate
from weaviate.classes.init import Auth


class WeaviateClient:

    def __init__(
        self,
        url: str,
        api_key: str,
    ):
        self.client = weaviate.connect_to_weaviate_cloud(
            cluster_url=url,
            auth_credentials=Auth.api_key(api_key),
        )

    def close(self):
        if self.client:
            self.client.close()

    def is_ready(self) -> bool:
        return self.client.is_ready()