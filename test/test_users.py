import sqlite3
from unittest.mock import MagicMock

import pytest

import app as flask_app


@pytest.fixture
def client(tmp_path, monkeypatch):
    db_path = tmp_path / "test.db"
    monkeypatch.setattr(flask_app, "DB_PATH", str(db_path))
    flask_app.init_db()
    return flask_app.app.test_client()


def test_list_users_returns_json(client):
    response = client.get("/users")

    assert response.status_code == 200
    users = response.get_json()
    assert len(users) >= 2
    assert users[0]["username"] == "alice"
    assert set(users[0].keys()) == {"id", "username", "email"}


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
    assert set(body.keys()) == {"id", "username", "email"}


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
