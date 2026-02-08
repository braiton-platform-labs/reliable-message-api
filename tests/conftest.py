from __future__ import annotations

import importlib
import os
from typing import Generator

import pytest
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from testcontainers.postgres import PostgresContainer


@pytest.fixture(scope="session")
def postgres_url() -> Generator[str, None, None]:
    with PostgresContainer("postgres:15") as postgres:
        yield postgres.get_connection_url()


@pytest.fixture(scope="session")
def client(postgres_url: str) -> Generator[TestClient, None, None]:
    os.environ["DATABASE_URL"] = postgres_url

    from app.core.config import get_settings

    get_settings.cache_clear()
    import app.db.session as session

    importlib.reload(session)

    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", postgres_url)
    command.upgrade(cfg, "head")

    import app.main as main

    importlib.reload(main)

    with TestClient(main.app) as test_client:
        yield test_client


@pytest.fixture(scope="session")
def app_instance(postgres_url: str):
    os.environ["DATABASE_URL"] = postgres_url

    from app.core.config import get_settings

    get_settings.cache_clear()
    import app.db.session as session

    importlib.reload(session)

    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", postgres_url)
    command.upgrade(cfg, "head")

    import app.main as main

    importlib.reload(main)
    return main.app
