from __future__ import annotations

import logging
import sys
from contextvars import ContextVar
from datetime import datetime, timezone
from typing import Any

from pythonjsonlogger import jsonlogger

request_id_ctx: ContextVar[str | None] = ContextVar("request_id", default=None)


class ContextFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.request_id = request_id_ctx.get()
        record.timestamp = datetime.now(timezone.utc).isoformat()
        record.path = getattr(record, "path", None)
        record.method = getattr(record, "method", None)
        record.status_code = getattr(record, "status_code", None)
        record.latency_ms = getattr(record, "latency_ms", None)
        record.client_ip = getattr(record, "client_ip", None)
        try:
            from ddtrace import tracer  # type: ignore

            span = tracer.current_span()
            if span is not None:
                record.dd_trace_id = span.trace_id
                record.dd_span_id = span.span_id
            else:
                record.dd_trace_id = None
                record.dd_span_id = None
        except Exception:
            record.dd_trace_id = None
            record.dd_span_id = None
        return True


def setup_logging(level: str) -> None:
    logger = logging.getLogger()
    logger.setLevel(level)

    handler = logging.StreamHandler(sys.stdout)
    formatter = jsonlogger.JsonFormatter(
        "%(timestamp)s %(levelname)s %(message)s %(request_id)s %(dd_trace_id)s %(dd_span_id)s "
        "%(path)s %(method)s %(status_code)s %(latency_ms)s %(client_ip)s"
    )
    handler.setFormatter(formatter)
    handler.addFilter(ContextFilter())

    logger.handlers.clear()
    logger.addHandler(handler)


def log_info(message: str, **kwargs: Any) -> None:
    logging.getLogger(__name__).info(message, extra=kwargs)


def log_error(message: str, **kwargs: Any) -> None:
    logging.getLogger(__name__).error(message, extra=kwargs)
