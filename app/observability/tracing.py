from __future__ import annotations

from ddtrace import config as dd_config
from ddtrace import tracer

from app.core.config import get_settings


def setup_tracing() -> None:
    settings = get_settings()
    dd_config.logs_injection = True
    dd_config.fastapi["service_name"] = settings.dd_service
    dd_config.sqlalchemy["service"] = f"{settings.dd_service}-postgres"
    tracer.set_tags(
        {
            "env": settings.dd_env,
            "version": settings.dd_version,
        }
    )
