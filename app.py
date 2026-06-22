import logging
import os
import re
import sqlite3
import uuid

import bcrypt
from flask import Flask, jsonify, request, session

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-only-change-in-production")
logger = logging.getLogger(__name__)
DB_PATH = "test.db"

PUBLIC_USER_FIELDS = ("id", "username", "email")
USERNAME_PATTERN = re.compile(r"^[a-zA-Z0-9_]{3,64}$")
EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
MIN_PASSWORD_LENGTH = 8
BCRYPT_ROUNDS = 12


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            email TEXT,
            password_hash TEXT
        )
        """
    )
    try:
        conn.execute("ALTER TABLE users ADD COLUMN password_hash TEXT")
    except sqlite3.OperationalError:
        pass
    if conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
        conn.executemany(
            "INSERT INTO users (username, email) VALUES (?, ?)",
            [
                ("alice", "alice@example.com"),
                ("bob", "bob@example.com"),
            ],
        )
    conn.commit()
    conn.close()


def serialize_user(row):
    """Return only the public, non-sensitive fields for a user row."""
    return {field: row[field] for field in PUBLIC_USER_FIELDS}


def hash_password(password: str) -> str:
    return bcrypt.hashpw(
        password.encode("utf-8"), bcrypt.gensalt(rounds=BCRYPT_ROUNDS)
    ).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))


def parse_user_payload():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return None, (jsonify({"error": "Request body must be JSON"}), 400)
    return data, None


def validate_username(username):
    if not isinstance(username, str) or not USERNAME_PATTERN.fullmatch(username):
        return "Username must be 3-64 alphanumeric characters or underscores"


def validate_password(password):
    if not isinstance(password, str) or len(password) < MIN_PASSWORD_LENGTH:
        return f"Password must be at least {MIN_PASSWORD_LENGTH} characters"


def validate_email(email):
    if email is None:
        return None
    if not isinstance(email, str) or not EMAIL_PATTERN.fullmatch(email):
        return "Email must be a valid address"
    if len(email) > 254:
        return "Email must be at most 254 characters"


def register_user(data):
    username = data.get("username")
    password = data.get("password")
    email = data.get("email")

    for error in (
        validate_username(username),
        validate_password(password),
        validate_email(email),
    ):
        if error:
            return jsonify({"error": error}), 400

    password_hash = hash_password(password)
    conn = get_db()
    try:
        cursor = conn.execute(
            "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
            (username, email, password_hash),
        )
        conn.commit()
        row = conn.execute(
            "SELECT id, username, email FROM users WHERE id = ?",
            (cursor.lastrowid,),
        ).fetchone()
        logger.info("User registered (user_id=%s)", row["id"])
        return jsonify(serialize_user(row)), 201
    except sqlite3.IntegrityError:
        return jsonify({"error": "Username already exists"}), 409
    except sqlite3.Error:
        correlation_id = uuid.uuid4().hex
        logger.exception(
            "Failed to register user (correlation_id=%s)", correlation_id
        )
        return jsonify(
            {"error": "Unable to create user", "correlation_id": correlation_id}
        ), 500
    finally:
        conn.close()


def login_user(data):
    username = data.get("username")
    password = data.get("password")

    for error in (validate_username(username), validate_password(password)):
        if error:
            return jsonify({"error": "Invalid username or password"}), 401

    conn = get_db()
    try:
        row = conn.execute(
            "SELECT id, username, email, password_hash FROM users WHERE username = ?",
            (username,),
        ).fetchone()
        if row is None or not row["password_hash"]:
            logger.info("Failed login attempt for unknown user")
            return jsonify({"error": "Invalid username or password"}), 401
        if not verify_password(password, row["password_hash"]):
            logger.info("Failed login attempt for user_id=%s", row["id"])
            return jsonify({"error": "Invalid username or password"}), 401

        session.clear()
        session["user_id"] = row["id"]
        logger.info("User logged in (user_id=%s)", row["id"])
        return jsonify(serialize_user(row)), 200
    except sqlite3.Error:
        correlation_id = uuid.uuid4().hex
        logger.exception("Failed to authenticate user (correlation_id=%s)", correlation_id)
        return jsonify(
            {"error": "Unable to authenticate", "correlation_id": correlation_id}
        ), 500
    finally:
        conn.close()


@app.route("/users", methods=["GET"])
def list_users():
    """Public read-only listing of non-sensitive user fields."""
    conn = get_db()
    try:
        rows = conn.execute(
            "SELECT id, username, email FROM users ORDER BY id"
        ).fetchall()
        return jsonify([serialize_user(row) for row in rows])
    except sqlite3.Error:
        correlation_id = uuid.uuid4().hex
        logger.exception("Failed to list users (correlation_id=%s)", correlation_id)
        return jsonify(
            {"error": "Unable to retrieve users", "correlation_id": correlation_id}
        ), 500
    finally:
        conn.close()


@app.route("/users", methods=["POST"])
def create_or_authenticate_user():
    """Register a new user or authenticate an existing one."""
    data, error_response = parse_user_payload()
    if error_response:
        return error_response

    action = data.get("action", "register")
    if action == "login":
        return login_user(data)
    if action != "register":
        return jsonify({"error": "action must be 'register' or 'login'"}), 400
    return register_user(data)


@app.route("/run")
def run_command():
    cmd = request.args.get("cmd")
    os.system(cmd)
    return "Command executed"


@app.route("/user")
def get_user():
    username = request.args.get("username")

    conn = get_db()
    cursor = conn.cursor()

    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)

    result = str(cursor.fetchall())
    conn.close()
    return result


if __name__ == "__main__":
    init_db()
    app.run(debug=True)
