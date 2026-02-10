from __future__ import annotations

import time
from dataclasses import dataclass, field
from threading import Lock

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
    counters: dict[str, int] = field(default_factory=dict)
    _lock: Lock = field(default_factory=Lock, init=False, repr=False)

    def inc(self, key: str, amount: int = 1) -> None:
        with self._lock:
            self.counters[key] = self.counters.get(key, 0) + amount

    def snapshot(self) -> dict[str, int]:
        with self._lock:
            return dict(self.counters)


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
    settings = get_settings()
    method = method.upper()
    status_code_str = str(status_code)

    if settings.metrics_enabled:
        REQUEST_COUNT.labels(method=method, path=path, status_code=status_code_str).inc()
        REQUEST_LATENCY.labels(method=method, path=path).observe(latency_ms / 1000.0)
        if _configure_statsd():
            statsd.increment(
                "http.requests.by_route",
                tags=[
                    f"method:{method}",
                    f"path:{path}",
                    f"code:{status_code_str}",
                ],
            )
            statsd.histogram("request.latency", latency_ms, tags=[f"path:{path}"])

    if settings.stats_enabled:
        stats.inc("requests.total")
        stats.inc(f"requests.by_method.{method}")
        stats.inc(f"requests.by_path.{path}")
        stats.inc(f"responses.by_status.{status_code_str}")


def record_message_created() -> None:
    settings = get_settings()
    if settings.metrics_enabled:
        MESSAGES_CREATED.inc()
        if _configure_statsd():
            statsd.increment("messages.created")
    if settings.stats_enabled:
        stats.inc("messages.created")


def record_message_duplicate() -> None:
    settings = get_settings()
    if settings.metrics_enabled:
        MESSAGES_DUPLICATE.inc()
        if _configure_statsd():
            statsd.increment("messages.duplicate")
    if settings.stats_enabled:
        stats.inc("messages.duplicate")


def record_message_invalid() -> None:
    settings = get_settings()
    if settings.metrics_enabled:
        MESSAGES_INVALID.inc()
        if _configure_statsd():
            statsd.increment("messages.invalid")
    if settings.stats_enabled:
        stats.inc("messages.invalid")


def now_ms() -> float:
    return time.perf_counter() * 1000.0
