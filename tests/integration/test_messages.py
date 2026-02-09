from __future__ import annotations


def test_create_and_get_message(client) -> None:
    client.post("/messages/reset")
    response = client.post("/messages", json={"message": "Hello world"})
    assert response.status_code == 201
    payload = response.json()
    message_id = payload["id"]

    get_resp = client.get(f"/messages/{message_id}")
    assert get_resp.status_code == 200
    assert get_resp.json()["message"] == "Hello world"


def test_duplicate_message(client) -> None:
    client.post("/messages/reset")
    response = client.post("/messages", json={"message": "Duplicate me"})
    assert response.status_code == 201

    dup = client.post("/messages", json={"message": "duplicate   me"})
    assert dup.status_code == 409


def test_idempotency_key(client) -> None:
    client.post("/messages/reset")
    headers = {"Idempotency-Key": "abc-123"}
    first = client.post("/messages", json={"message": "Idempotent"}, headers=headers)
    assert first.status_code == 201

    replay = client.post("/messages", json={"message": "Idempotent"}, headers=headers)
    assert replay.status_code == 200
    assert replay.json()["id"] == first.json()["id"]


def test_delete_message(client) -> None:
    client.post("/messages/reset")
    created = client.post("/messages", json={"message": "To delete"})
    assert created.status_code == 201
    message_id = created.json()["id"]

    deleted = client.delete(f"/messages/{message_id}")
    assert deleted.status_code == 200
    assert deleted.json()["status"] == "deleted"

    missing = client.get(f"/messages/{message_id}")
    assert missing.status_code == 404


def test_reset_clears_messages_and_idempotency_keys(client) -> None:
    client.post("/messages/reset")
    headers = {"Idempotency-Key": "reset-key"}
    first = client.post("/messages", json={"message": "Resettable"}, headers=headers)
    assert first.status_code == 201

    replay = client.post("/messages", json={"message": "Resettable"}, headers=headers)
    assert replay.status_code == 200

    reset = client.post("/messages/reset")
    assert reset.status_code == 200
    assert reset.json()["status"] == "ok"

    # After reset, the same Idempotency-Key should not replay (state is wiped).
    again = client.post("/messages", json={"message": "Resettable"}, headers=headers)
    assert again.status_code == 201
