from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Dict

from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest

from app.core.config import get_settings

try:
    from datadog import statsd
except Exception:  # pragma: no cover - optional dependency in some envs
    statsd = None  # type: ignore


REQUEST_COUNT = Counter(
    "http_requests_total",
    "Total HTTP requests",
    ["method", "path", "status_code"],
)
REQUEST_LATENCY = Histogram(
    "http_request_duration_seconds",
    "HTTP request latency in seconds",
    ["method", "path"],
)
MESSAGES_CREATED = Counter("messages_created_total", "Messages created")
MESSAGES_DUPLICATE = Counter("messages_duplicate_total", "Duplicate messages")
MESSAGES_INVALID = Counter("messages_invalid_total", "Invalid message requests")


@dataclass
class Stats:
    counters: Dict[str, int] = field(default_factory=dict)

    def inc(self, key: str, amount: int = 1) -> None:
        self.counters[key] = self.counters.get(key, 0) + amount


stats = Stats()


def _configure_statsd() -> bool:
    settings = get_settings()
    if settings.dd_agent_host and statsd is not None:
        statsd.host = settings.dd_agent_host
        return True
    return False


def metrics_response() -> tuple[bytes, str]:
    payload = generate_latest()
    return payload, CONTENT_TYPE_LATEST


def record_request(method: str, path: str, status_code: int, latency_ms: float) -> None:
    REQUEST_COUNT.labels(method=method, path=path, status_code=str(status_code)).inc()
    REQUEST_LATENCY.labels(method=method, path=path).observe(latency_ms / 1000.0)
    if _configure_statsd():
        statsd.increment("http.requests.by_route", tags=[f"method:{method}", f"path:{path}"])
        statsd.histogram("request.latency", latency_ms, tags=[f"path:{path}"])


def record_message_created() -> None:
    MESSAGES_CREATED.inc()
    stats.inc("messages.created")
    if _configure_statsd():
        statsd.increment("messages.created")


def record_message_duplicate() -> None:
    MESSAGES_DUPLICATE.inc()
    stats.inc("messages.duplicate")
    if _configure_statsd():
        statsd.increment("messages.duplicate")


def record_message_invalid() -> None:
    MESSAGES_INVALID.inc()
    stats.inc("messages.invalid")
    if _configure_statsd():
        statsd.increment("messages.invalid")


def now_ms() -> float:
    return time.perf_counter() * 1000.0
