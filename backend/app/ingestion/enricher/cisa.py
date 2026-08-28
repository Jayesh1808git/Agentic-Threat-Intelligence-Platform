class CISAKEVEnricher:

    def __init__(
        self,
        collection,
    ):
        self.collection = collection

    def enrich(
        self,
        cve: str,
    ):

        response = (
            self.collection.query.fetch_objects(
                filters=(
                    self.collection
                    .query
                    .filter
                    .by_property("cve")
                    .equal(cve)
                ),
                limit=1,
            )
        )

        if not response.objects:
            return False

        obj = response.objects[0]

        self.collection.data.update(
            uuid=obj.uuid,
            properties={
                "kev": True,
                "exploit_available": True,
            },
        )

        return True