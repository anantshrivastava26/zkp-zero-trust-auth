"""
Dynamic IP Rate Limiter
=======================
Tracks per-IP failure counts in memory and auto-blocks IPs that exceed
thresholds. Blocks expire after a configurable TTL — no manual intervention
needed and no file I/O.

State resets on server restart (by design for a prototype; swap the dict
for a Redis TTL key in production).

Thresholds:
  IP_WARN_THRESHOLD   – failures before risk score rises
  IP_BLOCK_THRESHOLD  – failures before the IP is hard-blocked
  IP_BLOCK_TTL        – seconds an IP stays blocked before auto-unblocking
  IP_WINDOW           – sliding window (seconds) over which failures are counted
"""

import time
import threading
from collections import defaultdict

# ── Configuration ──────────────────────────────────────────────────────────
IP_WARN_THRESHOLD  = 5     # failures in window before risk score rises
IP_BLOCK_THRESHOLD = 10    # failures in window before IP is hard-blocked
IP_BLOCK_TTL       = 900   # seconds an IP stays blocked (15 minutes)
IP_WINDOW          = 300   # sliding window in seconds (5 minutes)

# ── Internal State ─────────────────────────────────────────────────────────
# { ip: [timestamp, timestamp, ...] }  — raw failure timestamps
_failure_log: dict[str, list[float]] = defaultdict(list)

# { ip: unblock_at_timestamp }  — IPs currently hard-blocked
_blocked_until: dict[str, float] = {}

_lock = threading.Lock()


# ── Helpers ────────────────────────────────────────────────────────────────
def _prune(ip: str, now: float) -> None:
    """Drop failure timestamps outside the sliding window."""
    _failure_log[ip] = [t for t in _failure_log[ip] if now - t < IP_WINDOW]


def _recent_failures(ip: str) -> int:
    """Return the number of failures for ip within the current window."""
    now = time.time()
    _prune(ip, now)
    return len(_failure_log[ip])


# ── Public API ─────────────────────────────────────────────────────────────
def record_ip_failure(ip: str) -> None:
    """
    Record one failure for this IP.
    If the sliding-window count now exceeds IP_BLOCK_THRESHOLD,
    the IP is hard-blocked for IP_BLOCK_TTL seconds.
    """
    with _lock:
        now = time.time()
        _failure_log[ip].append(now)
        _prune(ip, now)
        if len(_failure_log[ip]) >= IP_BLOCK_THRESHOLD:
            _blocked_until[ip] = now + IP_BLOCK_TTL


def is_ip_blocked(ip: str) -> tuple[bool, float]:
    """
    Returns (blocked: bool, unblock_at: float).
    Auto-clears expired blocks.
    """
    with _lock:
        unblock_at = _blocked_until.get(ip, 0)
        if unblock_at and time.time() < unblock_at:
            return True, unblock_at
        # expired — clean up
        _blocked_until.pop(ip, None)
        return False, 0.0


def ip_risk_score(ip: str) -> tuple[int, str | None]:
    """
    Returns (score_increment, reason | None).
    +0  — under warn threshold
    +1  — between warn and block threshold (elevated)
    (blocked IPs never reach this — they are rejected before risk scoring)
    """
    with _lock:
        count = _recent_failures(ip)

    if count >= IP_WARN_THRESHOLD:
        return 1, f"IP {ip!r} has {count} failures in the last {IP_WINDOW}s"
    return 0, None


def reset_ip(ip: str) -> None:
    """
    Clear all failure history and any block for this IP.
    Called after a successful authentication.
    """
    with _lock:
        _failure_log.pop(ip, None)
        _blocked_until.pop(ip, None)
