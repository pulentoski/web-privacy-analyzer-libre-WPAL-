import logging
from datetime import datetime, timezone
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

logger = logging.getLogger(__name__)


class AppError(Exception):
    def __init__(
        self,
        error_code: str,
        message: str,
        *,
        stage: str,
        status_code: int = 400,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.error_code = error_code
        self.message = message
        self.stage = stage
        self.status_code = status_code
        self.details = details or {}


def error_body(error_code: str, message: str, stage: str, details: dict[str, Any] | None = None) -> dict:
    return {
        "error_code": error_code,
        "message": message,
        "details": details or {},
        "stage": stage,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def register_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(AppError)
    async def handle_app_error(request: Request, exc: AppError) -> JSONResponse:
        return JSONResponse(
            error_body(exc.error_code, exc.message, exc.stage, exc.details), status_code=exc.status_code
        )

    @app.exception_handler(RequestValidationError)
    async def handle_validation(request: Request, exc: RequestValidationError) -> JSONResponse:
        fields = [
            {"loc": [str(p) for p in err.get("loc", ())], "type": err.get("type"), "msg": err.get("msg")}
            for err in exc.errors()
        ]
        return JSONResponse(
            error_body("REQUEST_INVALID", "La solicitud no es válida.", "request", {"fields": fields}),
            status_code=422,
        )

    @app.exception_handler(StarletteHTTPException)
    async def handle_http(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        return JSONResponse(
            error_body(f"HTTP_{exc.status_code}", str(exc.detail), "request"), status_code=exc.status_code
        )

    @app.exception_handler(Exception)
    async def handle_unexpected(request: Request, exc: Exception) -> JSONResponse:
        # El stack trace va solo al log, nunca al cliente.
        logger.error("unhandled_exception", exc_info=exc, extra={"path": request.url.path})
        return JSONResponse(
            error_body("INTERNAL_ERROR", "Error interno del servidor.", "internal"), status_code=500
        )
