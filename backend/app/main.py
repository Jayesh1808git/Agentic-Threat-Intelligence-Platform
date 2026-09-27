from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from app.api.router import api_router
from app.core.config import settings

app = FastAPI(
    title=settings.APP_NAME,
    version="1.0.0"
)


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(
    request: Request,
    exc: RequestValidationError,
):
    # Assessment endpoint ke validation errors ko 400 return karo
    if request.url.path == "/v1/assessment":
        return JSONResponse(
            status_code=400,
            content={
                "detail": exc.errors(),
            },
        )

    # Baaki endpoints ka normal FastAPI behavior 422 rahega
    return JSONResponse(
        status_code=422,
        content={
            "detail": exc.errors(),
        },
    )


app.include_router(api_router)