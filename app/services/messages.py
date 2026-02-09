from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.db.models import IdempotencyKey, Message
from app.services.errors import DuplicateError, IdempotencyConflictError, NotFoundError
from app.services.validators import hash_request, normalize_message, validate_message


def create_message(
    db: Session, message: str, idempotency_key: str | None
) -> tuple[dict[str, Any], int, bool]:
    validate_message(message)
    normalized = normalize_message(message)
    request_hash = hash_request(message)

    if idempotency_key:
        existing = db.get(IdempotencyKey, idempotency_key)
        if existing:
            if existing.request_hash != request_hash:
                raise IdempotencyConflictError("Idempotency-Key reused with different request")
            return existing.response_snapshot["body"], 200, True

    new_message = Message(message_raw=message, message_normalized=normalized)
    db.add(new_message)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise DuplicateError("Duplicate message")

    db.refresh(new_message)
    response = {
        "id": str(new_message.id),
        "message": new_message.message_raw,
        "created_at": new_message.created_at.isoformat(),
    }

    if idempotency_key:
        snapshot = {"status_code": 201, "body": response}
        db.add(
            IdempotencyKey(
                key=idempotency_key,
                request_hash=request_hash,
                response_snapshot=snapshot,
                message_id=new_message.id,
            )
        )
        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            existing = db.get(IdempotencyKey, idempotency_key)
            if existing and existing.request_hash == request_hash:
                return existing.response_snapshot["body"], 200, True
            if existing and existing.request_hash != request_hash:
                raise IdempotencyConflictError("Idempotency-Key reused with different request")

    return response, 201, False


def list_messages(db: Session) -> list[Message]:
    return list(db.scalars(select(Message).order_by(Message.created_at.desc())).all())


def get_message(db: Session, message_id: uuid.UUID) -> Message:
    message = db.get(Message, message_id)
    if not message:
        raise NotFoundError("Message not found")
    return message


def delete_message(db: Session, message_id: uuid.UUID) -> None:
    message = db.get(Message, message_id)
    if not message:
        raise NotFoundError("Message not found")
    db.delete(message)
    db.commit()


def reset_messages(db: Session) -> int:
    # Reset should wipe all API state. Keeping idempotency keys would allow replaying
    # responses for messages that no longer exist.
    db.execute(delete(IdempotencyKey))
    result = db.execute(delete(Message))
    db.commit()
    return result.rowcount or 0
