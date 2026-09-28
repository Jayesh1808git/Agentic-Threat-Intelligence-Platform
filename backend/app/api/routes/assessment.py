from fastapi import APIRouter, HTTPException, status

from app.api.schemas.assessment import (
    AssessmentRequest,
    AssessmentResponse,
)
from run_graph import run_cyberrag


router = APIRouter()


@router.post(
    "",
    response_model=AssessmentResponse,
    status_code=status.HTTP_200_OK,
    summary="Run CyberRAG Vulnerability Assessment",
    description="Run the complete CyberRAG LangGraph vulnerability assessment pipeline.",
)
def create_assessment(
    request: AssessmentRequest,
):
    try:
        project_input = request.project_input.model_dump(exclude_none=True)

        result = run_cyberrag(project_input)

    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc

    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Assessment workflow failed: {exc}",
        ) from exc

    retrieval_mode = result.get("retrieval_mode", "HYBRID")
    assessment_status = "completed"
    if retrieval_mode == "POSTGRESQL_FALLBACK":
        assessment_status = "partial"
    if result.get("errors") and not result.get("report"):
        assessment_status = "failed"
    llm_metadata = result.get("llm_metadata", {})

    return AssessmentResponse(
        status=assessment_status,
        retrieval_mode=retrieval_mode,
        project_name=request.project_input.name,
        report=result.get("report", {}),
        findings=result.get("validated_findings", []),
        errors=result.get("errors", []),
        **llm_metadata,
    )
