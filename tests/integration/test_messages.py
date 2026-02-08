from __future__ import annotations


def test_create_and_get_message(client) -> None:
    response = client.post("/messages", json={"message": "Hello world"})
    assert response.status_code == 201
    payload = response.json()
    message_id = payload["id"]

    get_resp = client.get(f"/messages/{message_id}")
    assert get_resp.status_code == 200
    assert get_resp.json()["message"] == "Hello world"


def test_duplicate_message(client) -> None:
    response = client.post("/messages", json={"message": "Duplicate me"})
    assert response.status_code == 201

    dup = client.post("/messages", json={"message": "duplicate   me"})
    assert dup.status_code == 409


def test_idempotency_key(client) -> None:
    headers = {"Idempotency-Key": "abc-123"}
    first = client.post("/messages", json={"message": "Idempotent"}, headers=headers)
    assert first.status_code == 201

    replay = client.post("/messages", json={"message": "Idempotent"}, headers=headers)
    assert replay.status_code == 200
    assert replay.json()["id"] == first.json()["id"]
