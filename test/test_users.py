import sqlite3
from unittest.mock import MagicMock

import pytest

import app as flask_app


@pytest.fixture
def client(tmp_path, monkeypatch):
    db_path = tmp_path / "test.db"
    monkeypatch.setattr(flask_app, "DB_PATH", str(db_path))
    monkeypatch.setenv("CAPTURE_EMAIL_TOKENS", "1")
    flask_app.EMAIL_OUTBOX.clear()
    flask_app.TOKEN_CAPTURE.clear()
    flask_app.init_db()
    return flask_app.app.test_client()


def test_list_users_returns_json(client):
    response = client.get("/users")

    assert response.status_code == 200
    users = response.get_json()
    assert len(users) >= 2
    assert users[0]["username"] == "alice"
    assert set(users[0].keys()) == {"id", "username", "email", "email_verified"}


def test_list_users_error_does_not_leak_internals(client, monkeypatch):
    mock_conn = MagicMock()
    mock_conn.execute.side_effect = sqlite3.OperationalError(
        "no such table: secret_users"
    )
    monkeypatch.setattr(flask_app, "get_db", lambda: mock_conn)
    response = client.get("/users")

    assert response.status_code == 500
    body = response.get_json()
    assert body["error"] == "Unable to retrieve users"
    assert "correlation_id" in body
    assert "secret_users" not in response.get_data(as_text=True)


def test_register_user_stores_hashed_credentials(client):
    response = client.post(
        "/users",
        json={
            "username": "carol",
            "password": "securepass1",
            "email": "carol@example.com",
        },
    )

    assert response.status_code == 201
    body = response.get_json()
    assert body["username"] == "carol"
    assert body["email"] == "carol@example.com"
    assert body["email_verified"] is False
    assert "password" not in body
    assert "password_hash" not in body

    conn = sqlite3.connect(flask_app.DB_PATH)
    row = conn.execute(
        "SELECT password_hash FROM users WHERE username = ?", ("carol",)
    ).fetchone()
    conn.close()
    assert row is not None
    assert row[0].startswith("$2")
    assert row[0] != "securepass1"


def test_register_duplicate_username_returns_conflict(client):
    client.post(
        "/users",
        json={"username": "dave", "password": "securepass1", "email": "d@example.com"},
    )
    response = client.post(
        "/users",
        json={"username": "dave", "password": "anotherpass", "email": "d2@example.com"},
    )

    assert response.status_code == 409
    assert response.get_json()["error"] == "Username already exists"


def test_login_returns_user_without_password_fields(client):
    client.post(
        "/users",
        json={"username": "erin", "password": "securepass1", "email": "e@example.com"},
    )
    response = client.post(
        "/users",
        json={"username": "erin", "password": "securepass1", "action": "login"},
    )

    assert response.status_code == 200
    body = response.get_json()
    assert body["username"] == "erin"
    assert set(body.keys()) == {"id", "username", "email", "email_verified"}


def test_login_with_invalid_credentials_is_generic(client):
    client.post(
        "/users",
        json={"username": "frank", "password": "securepass1", "email": "f@example.com"},
    )
    response = client.post(
        "/users",
        json={"username": "frank", "password": "wrongpassword", "action": "login"},
    )

    assert response.status_code == 401
    assert response.get_json()["error"] == "Invalid username or password"


def _verification_token_for(email):
    for entry in reversed(flask_app.TOKEN_CAPTURE):
        if entry["kind"] == "verification" and entry["recipient"] == email:
            return entry["token"]
    raise AssertionError(f"No verification token captured for {email}")


def _reset_token_for(email):
    for entry in reversed(flask_app.TOKEN_CAPTURE):
        if entry["kind"] == "password_reset" and entry["recipient"] == email:
            return entry["token"]
    raise AssertionError(f"No reset token captured for {email}")


def test_registration_queues_verification_email(client):
    response = client.post(
        "/users",
        json={
            "username": "gina",
            "password": "securepass1",
            "email": "gina@example.com",
        },
    )

    assert response.status_code == 201
    assert any(
        e["kind"] == "verification" and e["recipient"] == "gina@example.com"
        for e in flask_app.EMAIL_OUTBOX
    )


def test_verify_email_marks_user_verified(client):
    client.post(
        "/users",
        json={
            "username": "heidi",
            "password": "securepass1",
            "email": "heidi@example.com",
        },
    )
    token = _verification_token_for("heidi@example.com")
    response = client.post(
        "/users",
        json={"action": "verify_email", "token": token},
    )

    assert response.status_code == 200
    body = response.get_json()
    assert body["email_verified"] is True


def test_resend_verification_is_generic_for_unknown_email(client):
    response = client.post(
        "/users",
        json={"action": "resend_verification", "email": "missing@example.com"},
    )

    assert response.status_code == 200
    assert "message" in response.get_json()


def test_forgot_password_does_not_enumerate_users(client):
    known = client.post(
        "/users",
        json={
            "username": "ivan",
            "password": "securepass1",
            "email": "ivan@example.com",
        },
    )
    assert known.status_code == 201

    known_response = client.post(
        "/users",
        json={"action": "forgot_password", "email": "ivan@example.com"},
    )
    unknown_response = client.post(
        "/users",
        json={"action": "forgot_password", "email": "nobody@example.com"},
    )

    assert known_response.status_code == 200
    assert unknown_response.status_code == 200
    assert known_response.get_json() == unknown_response.get_json()


def test_reset_password_with_valid_token(client):
    client.post(
        "/users",
        json={
            "username": "jane",
            "password": "securepass1",
            "email": "jane@example.com",
        },
    )
    client.post(
        "/users",
        json={"action": "forgot_password", "email": "jane@example.com"},
    )
    token = _reset_token_for("jane@example.com")

    reset_response = client.post(
        "/users",
        json={"action": "reset_password", "token": token, "password": "newsecure1"},
    )
    assert reset_response.status_code == 200

    login_old = client.post(
        "/users",
        json={"username": "jane", "password": "securepass1", "action": "login"},
    )
    login_new = client.post(
        "/users",
        json={"username": "jane", "password": "newsecure1", "action": "login"},
    )
    assert login_old.status_code == 401
    assert login_new.status_code == 200
