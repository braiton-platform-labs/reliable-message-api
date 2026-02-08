from __future__ import annotations

from app.services.validators import hash_request


def test_hash_request_is_stable() -> None:
    assert hash_request("hello") == hash_request("hello")
    assert hash_request("hello") != hash_request("hello2")
