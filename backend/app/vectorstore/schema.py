import weaviate.classes.config as wvc


def create_vulnerability_collection(
    client,
    collection_name: str,
):
    # Don't recreate an existing collection
    if client.collections.exists(collection_name):
        print(
            f"Collection '{collection_name}' already exists."
        )
        return

    client.collections.create(
        name=collection_name,

        # IMPORTANT:
        # We generate embeddings ourselves using
        # BAAI/bge-small-en-v1.5.
        vector_config=wvc.Configure.Vectors.self_provided(),

        properties=[
            wvc.Property(
                name="cve",
                data_type=wvc.DataType.TEXT,
            ),

            wvc.Property(
                name="vulnerability_id",
                data_type=wvc.DataType.TEXT,
            ),

            wvc.Property(
                name="title",
                data_type=wvc.DataType.TEXT,
            ),

            wvc.Property(
                name="description",
                data_type=wvc.DataType.TEXT,
            ),

            wvc.Property(
                name="vendor",
                data_type=wvc.DataType.TEXT,
            ),

            wvc.Property(
                name="product",
                data_type=wvc.DataType.TEXT,
            ),

            wvc.Property(
                name="affected_versions",
                data_type=wvc.DataType.TEXT_ARRAY,
            ),

            wvc.Property(
                name="patched_versions",
                data_type=wvc.DataType.TEXT_ARRAY,
            ),

            wvc.Property(
                name="cvss",
                data_type=wvc.DataType.NUMBER,
            ),

            wvc.Property(
                name="cvss_vector",
                data_type=wvc.DataType.TEXT,
            ),

            wvc.Property(
                name="epss",
                data_type=wvc.DataType.NUMBER,
            ),

            wvc.Property(
                name="kev",
                data_type=wvc.DataType.BOOL,
            ),

            wvc.Property(
                name="exploit_available",
                data_type=wvc.DataType.BOOL,
            ),

            wvc.Property(
                name="source",
                data_type=wvc.DataType.TEXT,
            ),

            wvc.Property(
                name="published",
                data_type=wvc.DataType.DATE,
            ),

            wvc.Property(
                name="updated",
                data_type=wvc.DataType.DATE,
            ),

            wvc.Property(
                name="cpe_matches",
                data_type=wvc.DataType.TEXT,
            ),

            wvc.Property(
                name="references",
                data_type=wvc.DataType.TEXT_ARRAY,
            ),
        ],
    )

    print(
        f"Created collection: {collection_name}"
    )