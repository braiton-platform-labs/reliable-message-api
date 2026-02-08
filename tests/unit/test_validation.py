from __future__ import annotations

import pytest

from app.services.validators import ValidationError, normalize_message, validate_message


def test_normalize_message() -> None:
    assert normalize_message("  Hello   WORLD ") == "hello world"
    assert normalize_message("Hello\tWORLD") == "hello world"


def test_validate_message_ok() -> None:
    validate_message("Hello123")


def test_validate_message_failures() -> None:
    with pytest.raises(ValidationError) as exc:
        validate_message("   ")
    assert "message must not be empty" in exc.value.details

    with pytest.raises(ValidationError) as exc2:
        validate_message("!!!!")
    assert "message must contain at least one alphanumeric character" in exc2.value.details

    with pytest.raises(ValidationError) as exc3:
        validate_message("abcd")
    assert "message must be at least 5 characters" in exc3.value.details
