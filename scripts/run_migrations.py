from __future__ import annotations

import os
import sys
import time
from datetime import datetime

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, text
from sqlalchemy.exc import SQLAlchemyError


def log(msg: str) -> None:
    print(f"[{datetime.utcnow().isoformat()}] {msg}", flush=True)


def wait_for_db(database_url: str, timeout_seconds: int) -> None:
    start = time.time()
    delay = 1.0
    while True:
        try:
            engine = create_engine(database_url, pool_pre_ping=True)
            with engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            return
        except SQLAlchemyError as exc:
            elapsed = time.time() - start
            if elapsed > timeout_seconds:
                raise RuntimeError(f"Database not ready after {timeout_seconds}s: {exc}")
            log(f"DB not ready yet, retrying in {delay:.1f}s")
            time.sleep(delay)
            delay = min(delay * 1.5, 10.0)


def main() -> int:
    database_url = os.getenv("DATABASE_URL")
    if not database_url:
        log("DATABASE_URL is required")
        return 1

    timeout_seconds = int(os.getenv("MIGRATION_WAIT_TIMEOUT", "120"))

    log("waiting for database")
    try:
        wait_for_db(database_url, timeout_seconds)
    except RuntimeError as exc:
        log(str(exc))
        return 1

    log("running alembic migrations")
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", database_url)
    command.upgrade(cfg, "head")
    log("migrations complete")
    return 0


if __name__ == "__main__":
    sys.exit(main())
