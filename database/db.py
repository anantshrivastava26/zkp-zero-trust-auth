"""
Public Key Registry
===================
Stores ONLY: username  +  public key (y)  +  risk metadata.
No passwords, no secrets, no hashes — that is the ZKP guarantee.
Backed by a local JSON file for simplicity; swap for PostgreSQL/Redis in production.

Risk fields stored per user:
  failed_attempts  – consecutive ZKP verification failures (reset on success)
  last_failed_ip   – IP address of the most recent failed attempt
  last_failed_ts   – Unix timestamp of the most recent failure
  lockout_until    – Unix timestamp after which the account is unlocked (None = not locked)
  lockout_count    – how many lockout tiers have been applied (drives exponential backoff)

Lockout tiers (seconds):
  tier 1 → 30 s
  tier 2 → 300 s  (5 min)
  tier 3 → permanent (lockout_until = inf sentinel 9999999999)
"""

import json
import time
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
    users[username] = {
        "public_key": public_key,
        "failed_attempts": 0,
        "last_failed_ip": None,
        "last_failed_ts": None,
        "lockout_until": None,
        "lockout_count": 0,
    }
    _save(users)
    return True


def get_user(username: str) -> dict | None:
    """Return the user record or None."""
    return _load().get(username)


# Lockout durations per tier (seconds). Tier 3+ → permanent sentinel.
_LOCKOUT_TIERS = [30, 300, 9_999_999_999]


def record_failed_attempt(username: str, ip: str) -> int:
    """
    Increment the consecutive failed-attempt counter for a user.
    Records the IP and timestamp of the failure.
    Applies exponential lockout after every 3 consecutive failures:
      tier 1 (failures 3)  → 30 s lockout
      tier 2 (failures 6)  → 5 min lockout
      tier 3 (failures 9+) → permanent lockout
    Returns the new failed_attempts count.
    """
    users = _load()
    if username not in users:
        return 0

    now = time.time()
    u = users[username]
    u["failed_attempts"] = u.get("failed_attempts", 0) + 1
    u["last_failed_ip"]  = ip
    u["last_failed_ts"]  = now

    # Apply lockout tier every 3 failures
    fails = u["failed_attempts"]
    if fails % 3 == 0:
        tier        = min(fails // 3 - 1, len(_LOCKOUT_TIERS) - 1)
        duration    = _LOCKOUT_TIERS[tier]
        u["lockout_until"] = now + duration
        u["lockout_count"] = u.get("lockout_count", 0) + 1

    users[username] = u
    _save(users)
    return u["failed_attempts"]


def get_lockout(username: str) -> tuple[bool, float]:
    """
    Returns (is_locked: bool, locked_until: float).
    Auto-clears expired lockouts so the record stays clean.
    """
    users = _load()
    u = users.get(username)
    if not u:
        return False, 0.0

    lockout_until = u.get("lockout_until") or 0
    if lockout_until and time.time() < lockout_until:
        return True, lockout_until

    # Expired — clear it
    if u.get("lockout_until"):
        u["lockout_until"]  = None
        u["failed_attempts"] = 0       # reset counter after lockout expires
        users[username] = u
        _save(users)

    return False, 0.0


def reset_failed_attempts(username: str) -> None:
    """Reset all failure and lockout state after a successful authentication."""
    users = _load()
    if username not in users:
        return
    users[username]["failed_attempts"] = 0
    users[username]["last_failed_ip"]  = None
    users[username]["last_failed_ts"]  = None
    users[username]["lockout_until"]   = None
    users[username]["lockout_count"]   = 0
    _save(users)
