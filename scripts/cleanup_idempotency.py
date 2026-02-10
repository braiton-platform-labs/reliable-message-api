from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta

from sqlalchemy import create_engine, delete
from sqlalchemy.orm import Session

from app.db.models import IdempotencyKey


def main() -> None:
    database_url = os.getenv(
        "DATABASE_URL", "postgresql+psycopg2://postgres:postgres@postgres:5432/messages"
    )
    ttl_hours = int(os.getenv("IDEMPOTENCY_TTL_HOURS", "24"))
    cutoff = datetime.now(UTC) - timedelta(hours=ttl_hours)

    engine = create_engine(database_url)
    with Session(engine) as session:
        result = session.execute(delete(IdempotencyKey).where(IdempotencyKey.created_at < cutoff))
        session.commit()
        deleted = result.rowcount or 0
    print(f"deleted={deleted}")


if __name__ == "__main__":
    main()
