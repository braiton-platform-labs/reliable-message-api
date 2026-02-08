from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, Depends, Header
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from app.api.schemas import CreateMessageRequest, ErrorResponse, MessageResponse
from app.core.logging import request_id_ctx
from app.db.session import get_db
from app.observability.metrics import (
    record_message_created,
    record_message_duplicate,
    record_message_invalid,
)
from app.services import messages as message_service
from app.services.errors import DuplicateError, IdempotencyConflictError
from app.services.validators import ValidationError

router = APIRouter(prefix="/messages", tags=["messages"])


@router.post(
    "",
    response_model=MessageResponse,
    status_code=201,
    responses={400: {"model": ErrorResponse}, 409: {"model": ErrorResponse}},
)
def create_message(
    payload: CreateMessageRequest,
    db: Session = Depends(get_db),
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
) -> JSONResponse:
    try:
        body, status_code, replay = message_service.create_message(
            db, payload.message, idempotency_key
        )
        if not replay:
            record_message_created()
        return JSONResponse(status_code=status_code, content=body)
    except ValidationError as exc:
        record_message_invalid()
        return error_response(400, "invalid_request", str(exc), exc.details)
    except DuplicateError:
        record_message_duplicate()
        return error_response(409, "duplicate", "Message already exists")
    except IdempotencyConflictError as exc:
        return error_response(409, "idempotency_conflict", str(exc))


@router.get("", response_model=list[MessageResponse])
def read_messages(db: Session = Depends(get_db)) -> list[MessageResponse]:
    rows = message_service.list_messages(db)
    return [
        MessageResponse(
            id=str(row.id), message=row.message_raw, created_at=row.created_at
        )
        for row in rows
    ]


@router.get(
    "/{message_id}",
    response_model=MessageResponse,
    responses={404: {"model": ErrorResponse}},
)
def read_message(message_id: uuid.UUID, db: Session = Depends(get_db)) -> MessageResponse:
    row = message_service.get_message(db, message_id)
    return MessageResponse(id=str(row.id), message=row.message_raw, created_at=row.created_at)


@router.delete("/{message_id}", responses={404: {"model": ErrorResponse}})
def delete_message(message_id: uuid.UUID, db: Session = Depends(get_db)) -> dict[str, Any]:
    message_service.delete_message(db, message_id)
    return {"status": "deleted"}


@router.post("/reset")
def reset_messages(db: Session = Depends(get_db)) -> dict[str, Any]:
    count = message_service.reset_messages(db)
    return {"status": "ok", "deleted": count}


def error_response(
    status_code: int,
    error_code: str,
    message: str,
    details: list[str] | None = None,
) -> JSONResponse:
    req_id = request_id_ctx.get()
    payload = {
        "error_code": error_code,
        "message": message,
        "details": details,
        "request_id": req_id,
    }
    return JSONResponse(status_code=status_code, content=payload)
