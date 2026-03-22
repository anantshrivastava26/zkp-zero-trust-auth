"""
Public Key Registry
===================
Stores ONLY: username  +  public key (y).
No passwords, no secrets, no hashes — that is the ZKP guarantee.
Backed by a local JSON file for simplicity; swap for PostgreSQL/Redis in production.
"""

import json
import os
from pathlib import Path

DB_FILE = Path(__file__).parent / "users.json"


def _load() -> dict:
    if not DB_FILE.exists():
        return {}
    with open(DB_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def _save(data: dict) -> None:
    with open(DB_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def user_exists(username: str) -> bool:
    return username in _load()


def save_user(username: str, public_key: int) -> bool:
    """Register a new user. Returns False if username already taken."""
    users = _load()
    if username in users:
        return False
    users[username] = {"public_key": public_key}
    _save(users)
    return True


def get_user(username: str) -> dict | None:
    """Return the user record or None."""
    return _load().get(username)
