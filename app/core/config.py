from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict()

    app_name: str = "reliable-message-api"
    environment: str = "local"
    log_level: str = "INFO"

    database_url: str = Field(
        default="postgresql+psycopg2://postgres:postgres@postgres:5432/messages",
        alias="DATABASE_URL",
    )

    require_api_key: bool = Field(default=False, alias="REQUIRE_API_KEY")
    api_key: str = Field(default="", alias="API_KEY")

    dd_service: str = Field(default="reliable-message-api", alias="DD_SERVICE")
    dd_env: str = Field(default="local", alias="DD_ENV")
    dd_version: str = Field(default="0.1.0", alias="DD_VERSION")
    dd_agent_host: str | None = Field(default=None, alias="DD_AGENT_HOST")

    metrics_enabled: bool = Field(default=True, alias="METRICS_ENABLED")
    stats_enabled: bool = Field(default=True, alias="STATS_ENABLED")

    idempotency_ttl_hours: int = Field(default=24, alias="IDEMPOTENCY_TTL_HOURS")

    app_mode: Literal["api", "migrations"] = "api"


@lru_cache
def get_settings() -> Settings:
    return Settings()
