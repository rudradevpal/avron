"""Session authentication for the admin UI.

The proxy routes are deliberately NOT protected by this. Agents authenticate to
upstream with their own bearer token; requiring a browser session there would
break every client. Only /admin and /api/admin require a session.
"""

import hashlib
import os
import secrets
import time
from datetime import datetime, timedelta, timezone
from typing import Dict, Optional

from fastapi import Cookie, HTTPException, Request

import db

COOKIE = "pii_session"

# username -> (failure count, locked-until epoch)
_failures: Dict[str, list] = {}
MAX_FAILURES = 5
LOCKOUT_SECONDS = 300


# ------------------------------------------------------------- passwords
def hash_password(password: str) -> str:
    """PBKDF2-HMAC-SHA256. No bcrypt dependency; 600k iterations."""
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 600_000)
    return f"pbkdf2${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        _, salt_hex, dk_hex = stored.split("$")
        dk = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), bytes.fromhex(salt_hex), 600_000
        )
        return secrets.compare_digest(dk.hex(), dk_hex)
    except Exception:  # noqa: BLE001
        return False


def password_problem(password: str) -> Optional[str]:
    if len(password) < 12:
        return "Password must be at least 12 characters."
    if password.lower() in ("password1234", "administrator"):
        return "Password is too common."
    return None


# -------------------------------------------------------------- sessions
def _locked(username: str) -> int:
    entry = _failures.get(username)
    if not entry:
        return 0
    remaining = int(entry[1] - time.time())
    return max(0, remaining)


def record_failure(username: str) -> None:
    entry = _failures.setdefault(username, [0, 0.0])
    entry[0] += 1
    if entry[0] >= MAX_FAILURES:
        entry[1] = time.time() + LOCKOUT_SECONDS
        entry[0] = 0


def clear_failures(username: str) -> None:
    _failures.pop(username, None)


def login(username: str, password: str) -> str:
    wait = _locked(username)
    if wait:
        raise HTTPException(429, f"Too many attempts. Try again in {wait}s.")

    row = db.db().execute(
        "SELECT * FROM users WHERE username=?", (username,)
    ).fetchone()
    if not row or not verify_password(password, row["password_hash"]):
        record_failure(username)
        raise HTTPException(401, "Invalid username or password.")

    clear_failures(username)
    token = secrets.token_urlsafe(32)
    hours = int(db.get_setting("session_hours", "12") or 12)
    expires = datetime.now(timezone.utc) + timedelta(hours=hours)
    db.db().execute(
        "INSERT INTO sessions(token,user_id,created_at,expires_at) VALUES(?,?,?,?)",
        (token, row["id"], db.now(), expires.isoformat()),
    )
    db.db().execute(
        "DELETE FROM sessions WHERE expires_at < ?",
        (datetime.now(timezone.utc).isoformat(),),
    )
    db.db().commit()
    db.audit(username, "login")
    return token


def logout(token: str) -> None:
    db.db().execute("DELETE FROM sessions WHERE token=?", (token,))
    db.db().commit()


def current_user(request: Request) -> dict:
    token = request.cookies.get(COOKIE)
    if not token:
        raise HTTPException(401, "Not authenticated")
    row = db.db().execute(
        "SELECT u.id, u.username, u.must_change, s.expires_at "
        "FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token=?",
        (token,),
    ).fetchone()
    if not row:
        raise HTTPException(401, "Session expired")
    if row["expires_at"] < datetime.now(timezone.utc).isoformat():
        db.db().execute("DELETE FROM sessions WHERE token=?", (token,))
        db.db().commit()
        raise HTTPException(401, "Session expired")
    return dict(row)


def secure_cookie() -> bool:
    return os.getenv("COOKIE_SECURE", "false").lower() == "true"
