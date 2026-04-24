"""
Zero Trust Policy Engine
========================
Applies context-aware access rules AFTER ZKP authentication succeeds.
Zero Trust principle: "Never trust, always verify."

Rules enforced:
  1. Time-based access  – only during allowed hours
  2. IP blocklist       – deny known bad actors
  3. Risk score         – deny if computed risk exceeds threshold

Risk score contributors (additive):
  +1  off-hours access
  +2  IP mismatch  – current request IP differs from the IP that last failed
  +2  repeated failures (3–4 consecutive failed /verify attempts)
  +4  high failure count (5+ consecutive failed /verify attempts)
  Score is capped; any value > MAX_RISK_SCORE blocks the request.
"""

import time
from datetime import datetime
from database.db import get_user
from policy.rate_limiter import ip_risk_score

# ── Policy Configuration ───────────────────────────────────────────────────
ALLOWED_HOURS    = (0, 23)        # 24-hour window; narrow in production (e.g. 8, 20)
BLOCKED_IPS: set[str] = set()    # Manually populated blocklist
MAX_RISK_SCORE   = 3             # Requests scoring above this are denied

# Failure thresholds that drive the risk score
FAIL_WARN_THRESHOLD = 3          # ≥ this many failures → +2 risk
FAIL_BLOCK_THRESHOLD = 5         # ≥ this many failures → +4 risk (overrides warn)

# How long (seconds) a failure record stays relevant for IP-mismatch checks
FAIL_RECENCY_WINDOW = 300        # 5 minutes


# ── Rule 1: Time ───────────────────────────────────────────────────────────
def _check_time() -> bool:
    hour = datetime.now().hour
    return ALLOWED_HOURS[0] <= hour <= ALLOWED_HOURS[1]


# ── Rule 2: IP blocklist ───────────────────────────────────────────────────
def _check_ip(ip: str) -> bool:
    return ip not in BLOCKED_IPS


# ── Rule 3: Risk Score ─────────────────────────────────────────────────────
def _compute_risk(username: str, ip: str) -> tuple[int, list[str]]:
    """
    Heuristic risk score built from per-user failure history.

    Scoring:
      +1  off-hours access
      +2  IP used now differs from the IP that last triggered a failure
          (possible credential hand-off or session-hijack attempt)
      +2  3–4 consecutive failed /verify attempts for this user
      +4  5+ consecutive failed /verify attempts for this user

    Returns (score, [list of reasons]) for audit logging.
    """
    score   = 0
    reasons = []

    # Signal 1: off-hours
    if not _check_time():
        score += 1
        reasons.append("off-hours access")

    # Pull per-user failure metadata from the registry
    user = get_user(username)
    if user:
        failed   = user.get("failed_attempts", 0)
        last_ip  = user.get("last_failed_ip")
        last_ts  = user.get("last_failed_ts")

        # Signal 2: IP mismatch within recency window
        if (
            last_ip is not None
            and last_ip != ip
            and last_ts is not None
            and (time.time() - last_ts) < FAIL_RECENCY_WINDOW
        ):
            score += 2
            reasons.append(
                f"IP mismatch: current={ip!r}, last failure from={last_ip!r}"
            )

        # Signal 3: repeated failures
        if failed >= FAIL_BLOCK_THRESHOLD:
            score += 4
            reasons.append(f"high consecutive failure count ({failed})")
        elif failed >= FAIL_WARN_THRESHOLD:
            score += 2
            reasons.append(f"elevated consecutive failure count ({failed})")

    # Signal 4: IP-level failure rate across all accounts
    ip_score, ip_reason = ip_risk_score(ip)
    if ip_score:
        score += ip_score
        reasons.append(ip_reason)

    return score, reasons


# ── Public API ─────────────────────────────────────────────────────────────
def evaluate_policy(username: str, ip: str) -> tuple[bool, str]:
    """
    Evaluate all Zero Trust rules.

    Returns
    -------
    (allowed: bool, reason: str)
    """
    if not _check_time():
        start, end = ALLOWED_HOURS
        return False, (
            f"Access denied: outside allowed hours "
            f"({start:02d}:00 – {end:02d}:59)"
        )

    if not _check_ip(ip):
        return False, f"Access denied: IP address {ip!r} is blocked"

    risk, reasons = _compute_risk(username, ip)
    if risk > MAX_RISK_SCORE:
        detail = "; ".join(reasons) if reasons else "risk threshold exceeded"
        return False, (
            f"Access denied: risk score {risk} exceeds threshold "
            f"{MAX_RISK_SCORE} ({detail})"
        )

    return True, "All Zero Trust policy checks passed"
