from __future__ import annotations

import unicodedata


class ValidationError(Exception):
    def __init__(self, message: str, details: list[str] | None = None) -> None:
        super().__init__(message)
        self.details = details or []


def normalize_message(message: str) -> str:
    normalized = unicodedata.normalize("NFKC", message)
    normalized = normalized.strip().lower()
    normalized = " ".join(normalized.split())
    return normalized


def validate_message(message: str) -> None:
    details: list[str] = []
    if message is None:
        details.append("message must be provided")
    else:
        if len(message.strip()) == 0:
            details.append("message must not be empty")
        if len(message) < 5:
            details.append("message must be at least 5 characters")
        if len(message) > 200:
            details.append("message must be at most 200 characters")
        if not any(ch.isalnum() for ch in message):
            details.append("message must contain at least one alphanumeric character")

    if details:
        raise ValidationError("Invalid message", details)


def hash_request(message: str) -> str:
    import hashlib

    payload = message.encode("utf-8")
    return hashlib.sha256(payload).hexdigest()
