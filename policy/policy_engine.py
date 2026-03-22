"""
Zero Trust Policy Engine
========================
Applies context-aware access rules AFTER ZKP authentication succeeds.
Zero Trust principle: "Never trust, always verify."

Rules enforced:
  1. Time-based access  – only during allowed hours
  2. IP blocklist       – deny known bad actors
  3. Risk score         – deny if computed risk is too high
"""

from datetime import datetime

# ── Policy Configuration ───────────────────────────────────────────────────
ALLOWED_HOURS = (0, 23)          # 24-hour window: 0 = midnight, 23 = 11 PM
                                  # Narrow this in production (e.g. 8, 20)
BLOCKED_IPS: set[str] = set()    # Add IPs to block, e.g. {"192.168.1.99"}
MAX_RISK_SCORE = 2               # 0 = low risk, higher = riskier


# ── Rule 1: Time ───────────────────────────────────────────────────────────
def _check_time() -> bool:
    hour = datetime.now().hour
    return ALLOWED_HOURS[0] <= hour <= ALLOWED_HOURS[1]


# ── Rule 2: IP ─────────────────────────────────────────────────────────────
def _check_ip(ip: str) -> bool:
    return ip not in BLOCKED_IPS


# ── Rule 3: Risk Score ─────────────────────────────────────────────────────
def _compute_risk(username: str, ip: str) -> int:
    """
    Heuristic risk score.  Extend with:
      - failed login counter per user
      - geo-location anomaly detection
      - device fingerprinting
    """
    score = 0
    if not _check_time():
        score += 1                # off-hours access is slightly riskier
    # future checks would increment score further
    return score


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
        return False, f"Access denied: outside allowed hours ({start:02d}:00 – {end:02d}:59)"

    if not _check_ip(ip):
        return False, f"Access denied: IP address {ip!r} is blocked"

    risk = _compute_risk(username, ip)
    if risk > MAX_RISK_SCORE:
        return False, f"Access denied: risk score {risk} exceeds threshold {MAX_RISK_SCORE}"

    return True, "All Zero Trust policy checks passed"
