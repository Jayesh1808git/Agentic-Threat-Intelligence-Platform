from pydantic import BaseModel, Field


class RetrievalRequest(BaseModel):
    query: str = Field(
        min_length=1,
        description=(
            "Natural language query, CVE, vendor, "
            "or product."
        ),
    )

    top_k: int = Field(
        default=10,
        ge=1,
        le=100,
    )


class RetrievalResponse(BaseModel):
    query: str
    count: int
    results: list[dict]