from __future__ import annotations

import logging
from typing import Any

import ddtrace.auto  # noqa: F401
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, PlainTextResponse
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from app.api.messages import router as messages_router
from app.core.config import get_settings
from app.core.logging import request_id_ctx, setup_logging
from app.core.middleware import ApiKeyMiddleware, RequestContextMiddleware
from app.db.session import engine
from app.observability.metrics import metrics_response, stats
from app.observability.tracing import setup_tracing
from app.services.errors import DuplicateError, IdempotencyConflictError, NotFoundError
from app.services.validators import ValidationError

settings = get_settings()
setup_logging(settings.log_level)
setup_tracing()

app = FastAPI(title="Reliable Message API", version=settings.dd_version)

app.add_middleware(RequestContextMiddleware)
app.add_middleware(ApiKeyMiddleware)

app.include_router(messages_router)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/ready")
def readiness() -> JSONResponse:
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
        return JSONResponse(content={"status": "ready"})
    except SQLAlchemyError as exc:
        logging.getLogger(__name__).error("readiness failed", extra={"error": str(exc)})
        return JSONResponse(status_code=503, content={"status": "not_ready"})


@app.get("/metrics")
def metrics() -> PlainTextResponse:
    payload, content_type = metrics_response()
    return PlainTextResponse(content=payload.decode("utf-8"), media_type=content_type)


@app.get("/stats")
def stats_endpoint() -> dict[str, Any]:
    return {"counters": stats.counters}


@app.exception_handler(ValidationError)
async def validation_exception_handler(request: Request, exc: ValidationError) -> JSONResponse:
    return error_payload(request, 400, "invalid_request", str(exc), exc.details)


@app.exception_handler(RequestValidationError)
async def request_validation_handler(
    request: Request, exc: RequestValidationError
) -> JSONResponse:
    details = [err.get("msg", "Invalid request") for err in exc.errors()]
    return error_payload(request, 400, "invalid_request", "Request validation failed", details)

@app.exception_handler(NotFoundError)
async def not_found_exception_handler(request: Request, exc: NotFoundError) -> JSONResponse:
    return error_payload(request, 404, "not_found", str(exc))


@app.exception_handler(DuplicateError)
async def duplicate_exception_handler(request: Request, exc: DuplicateError) -> JSONResponse:
    return error_payload(request, 409, "duplicate", str(exc))


@app.exception_handler(IdempotencyConflictError)
async def idempotency_exception_handler(
    request: Request, exc: IdempotencyConflictError
) -> JSONResponse:
    return error_payload(request, 409, "idempotency_conflict", str(exc))


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    logging.getLogger(__name__).exception("unhandled error")
    return error_payload(request, 500, "internal_error", "Unexpected error")


def error_payload(
    request: Request,
    status_code: int,
    error_code: str,
    message: str,
    details: list[str] | None = None,
) -> JSONResponse:
    req_id = request_id_ctx.get()
    payload = {
        "error_code": error_code,
        "message": message,
        "details": details,
        "request_id": req_id,
    }
    return JSONResponse(status_code=status_code, content=payload)
