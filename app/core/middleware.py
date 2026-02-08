from __future__ import annotations

import time
import uuid
from typing import Callable

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

from app.core.config import get_settings
from app.core.logging import log_info, request_id_ctx
from app.observability.metrics import record_request


class RequestContextMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: ASGIApp) -> None:
        super().__init__(app)

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        req_id = request.headers.get("X-Request-Id") or str(uuid.uuid4())
        token = request_id_ctx.set(req_id)
        start = time.perf_counter()
        try:
            response = await call_next(request)
        finally:
            request_id_ctx.reset(token)
        duration_ms = (time.perf_counter() - start) * 1000.0
        response.headers["X-Request-Id"] = req_id
        record_request(request.method, request.url.path, response.status_code, duration_ms)
        log_info(
            "request",
            path=request.url.path,
            method=request.method,
            status_code=response.status_code,
            latency_ms=round(duration_ms, 2),
            client_ip=request.client.host if request.client else None,
        )
        return response


class ApiKeyMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: ASGIApp) -> None:
        super().__init__(app)

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        settings = get_settings()
        if settings.require_api_key:
            key = request.headers.get("X-API-Key")
            if not key or key != settings.api_key:
                payload = (
                    f'{{\"error_code\":\"forbidden\",\"message\":\"Invalid API key\",'
                    f'\"request_id\":\"{request_id_ctx.get()}\"}}'
                )
                return Response(status_code=403, content=payload, media_type="application/json")
        return await call_next(request)
