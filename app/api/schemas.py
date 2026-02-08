from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class CreateMessageRequest(BaseModel):
    message: str = Field(..., min_length=1)


class MessageResponse(BaseModel):
    id: str
    message: str
    created_at: datetime


class ErrorResponse(BaseModel):
    error_code: str
    message: str
    details: list[str] | None = None
    request_id: str | None = None
    extra: dict[str, Any] | None = None
