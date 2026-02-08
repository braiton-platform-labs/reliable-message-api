from __future__ import annotations

from ddtrace import config as dd_config


def setup_tracing() -> None:
    dd_config.logs_injection = True
