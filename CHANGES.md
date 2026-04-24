# Security Changes — Zero Trust Policy Layer

This document describes the security additions made to the policy and
authentication pipeline in three phases.

---

## Phase 1 — Per-user failure tracking (`database/db.py`)

**Problem:** The policy engine had no memory of past failures. An attacker
could try wrong proofs indefinitely with no consequences.

**What was added:**

Three new fields are stored per user in `users.json`:

| Field | Type | Purpose |
|---|---|---|
| `failed_attempts` | int | Consecutive ZKP failures since last successful login |
| `last_failed_ip` | str \| null | IP of the most recent failure |
| `last_failed_ts` | float \| null | Unix timestamp of the most recent failure |

Two new functions:

- `record_failed_attempt(username, ip)` — increments the counter and records
  the IP and timestamp. Called in `app.py` immediately after a failed
  `/verify`.
- `reset_failed_attempts(username)` — zeroes everything out. Called on
  successful authentication.

---

## Phase 2 — Risk scoring in the policy engine (`policy/policy_engine.py`)

**Problem:** The `_compute_risk` function was a stub that only checked the
clock. It never looked at actual user behaviour.

**What was added:**

`_compute_risk` now produces an additive integer score from four real signals:

| Signal | Score | Condition |
|---|---|---|
| Off-hours access | +1 | Request outside `ALLOWED_HOURS` |
| IP mismatch | +2 | Current IP differs from `last_failed_ip` within 5 min |
| Elevated failures | +2 | 3–4 consecutive failures for this user |
| High failures | +4 | 5+ consecutive failures for this user |
| IP rate elevated | +1 | This IP has 5+ failures across any account in 5 min |

`MAX_RISK_SCORE = 3` — requests scoring above this are denied with a
human-readable reason string returned to the caller.

The IP rate signal feeds from the new rate limiter (Phase 3).

---

## Phase 3 — Dynamic IP rate limiter + account lockout

### 3a — IP rate limiter (`policy/rate_limiter.py`) — new file

**Problem:** An attacker can rotate IPs to stay under the per-user failure
threshold. Each new IP looks clean to the system.

**How it works:**

- An in-memory sliding-window counter tracks failures per IP across **all
  accounts**, not just one.
- The window is **5 minutes** (`IP_WINDOW = 300`).
- At **5 failures** in the window, the IP's risk score rises (+1).
- At **10 failures** in the window, the IP is **hard-blocked for 15 minutes**
  (`IP_BLOCK_TTL = 900`). Blocked IPs are rejected at the start of `/verify`
  before any ZKP work is done, returning HTTP 429.
- Blocks auto-expire — no manual intervention needed.
- On a successful login, the IP's failure history is cleared (`reset_ip`).

State is in-memory: resets on server restart. For persistence across restarts,
replace the dicts with Redis TTL keys.

### 3b — Account lockout (`database/db.py`)

**Problem:** Rotating IPs still leaves the per-account failure counter
climbing. There was no mechanism to slow down or halt attempts against a
specific account.

**How it works:**

Two new fields per user:

| Field | Type | Purpose |
|---|---|---|
| `lockout_until` | float \| null | Unix timestamp until which the account is locked |
| `lockout_count` | int | Number of lockout tiers applied so far |

Lockout is triggered inside `record_failed_attempt` every 3 consecutive
failures, using an exponential backoff:

| Failures | Tier | Lockout duration |
|---|---|---|
| 3 | 1 | 30 seconds |
| 6 | 2 | 5 minutes |
| 9+ | 3 | Permanent (requires admin reset) |

`get_lockout(username)` returns `(is_locked, locked_until)` and
automatically clears expired lockouts, resetting the failure counter so the
user gets a fresh window after serving their time.

On successful authentication, `reset_failed_attempts` now also clears
`lockout_until` and `lockout_count`.

---

## Request flow after all changes

```
POST /verify
  │
  ├─ Gate 1: is_ip_blocked(ip)?
  │     YES → HTTP 429, "try again in Xs"
  │
  ├─ Gate 2: get_lockout(username)?
  │     YES (timed)     → HTTP 429, "account locked, try again in Xs"
  │     YES (permanent) → HTTP 403, "contact administrator"
  │
  ├─ ZKP verify_proof(...)
  │     FAIL → record_failed_attempt(username, ip)   [may trigger lockout]
  │          → record_ip_failure(ip)                 [may trigger IP block]
  │          → HTTP 403
  │
  ├─ evaluate_policy(username, ip)
  │     FAIL → HTTP 403 with reason string
  │
  └─ SUCCESS
        → reset_failed_attempts(username)
        → reset_ip(ip)
        → session["authenticated"] = True
        → HTTP 200
```

---

## Files changed

| File | Change |
|---|---|
| `database/db.py` | Added `failed_attempts`, `last_failed_ip`, `last_failed_ts`, `lockout_until`, `lockout_count` fields; added `record_failed_attempt`, `reset_failed_attempts`, `get_lockout` functions |
| `database/users.json` | Backfilled all existing users with new fields |
| `policy/policy_engine.py` | `_compute_risk` now scores four real signals; imports `ip_risk_score` from rate limiter |
| `policy/rate_limiter.py` | **New file** — in-memory sliding-window IP rate limiter with TTL-based auto-blocking |
| `app.py` | `/verify` route now checks IP block and account lockout before ZKP; calls `record_ip_failure` and `record_failed_attempt` on failure; calls `reset_ip` and `reset_failed_attempts` on success |
