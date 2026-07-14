"""
User store for the web app's login, persisted to data/users.json.

Deliberately mirrors backend/history.py's shape (module-level lock, _read_all /
_write_all) rather than introducing a database -- this is a single-process tool
and a flat file with a lock is sufficient and auditable.

Passwords are hashed with PBKDF2-HMAC-SHA256 from the standard library. This is
a NIST-approved KDF and, unlike bcrypt/argon2, needs no native extension -- which
keeps the Docker image buildable without a compiler toolchain. Plaintext
passwords are never stored or logged.
"""

import hashlib
import hmac
import json
import secrets
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

_USERS_FILE = Path(__file__).resolve().parent.parent / "data" / "users.json"
_lock = threading.Lock()

# OWASP's 2026 guidance for PBKDF2-HMAC-SHA256. Costs ~0.4s per hash, which is
# fine for a login endpoint (FastAPI runs sync routes in a threadpool, so this
# never blocks the event loop).
_ITERATIONS = 600_000
_SALT_BYTES = 16


def _hash_password(password: str, salt: bytes) -> str:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, _ITERATIONS).hex()


def _read_all() -> List[Dict[str, Any]]:
    if not _USERS_FILE.exists():
        return []
    with _USERS_FILE.open("r") as f:
        return json.load(f)


def _write_all(records: List[Dict[str, Any]]) -> None:
    _USERS_FILE.parent.mkdir(parents=True, exist_ok=True)
    with _USERS_FILE.open("w") as f:
        json.dump(records, f, indent=2)


def user_count() -> int:
    with _lock:
        return len(_read_all())


def list_users() -> List[str]:
    with _lock:
        return [u["username"] for u in _read_all()]


def create_user(username: str, password: str) -> None:
    """Raises ValueError if the username is taken or the input is unusable."""
    username = username.strip()
    if not username:
        raise ValueError("Username is required.")
    if len(password) < 8:
        raise ValueError("Password must be at least 8 characters.")

    with _lock:
        users = _read_all()
        if any(u["username"].lower() == username.lower() for u in users):
            raise ValueError("That username is already taken.")

        salt = secrets.token_bytes(_SALT_BYTES)
        users.append({
            "username": username,
            "salt": salt.hex(),
            "hash": _hash_password(password, salt),
            "iterations": _ITERATIONS,
            "created_at": datetime.now(timezone.utc).isoformat(),
        })
        _write_all(users)


def verify_user(username: str, password: str) -> Optional[str]:
    """Returns the stored username on success, None on any failure."""
    with _lock:
        users = _read_all()

    record = next((u for u in users if u["username"].lower() == username.strip().lower()), None)
    if record is None:
        # Hash anyway so a missing user and a wrong password take the same time --
        # otherwise response timing reveals which usernames exist.
        _hash_password(password, secrets.token_bytes(_SALT_BYTES))
        return None

    candidate = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        bytes.fromhex(record["salt"]),
        record.get("iterations", _ITERATIONS),
    ).hex()

    if hmac.compare_digest(candidate, record["hash"]):
        return record["username"]
    return None
