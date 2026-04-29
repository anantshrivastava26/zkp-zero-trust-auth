"""
app.py – Authentication Module + API Layer + Access Control
===========================================================
Routes
------
  GET  /            → index page (register / login UI)
  POST /register    → register new user, return generated key-pair
  POST /login       → run ZKP proof steps, store proof in session
  POST /verify      → verify ZKP proof + Zero Trust policy → grant/deny
  GET  /dashboard   → protected cloud resource (requires auth)
  GET  /logout      → clear session
"""

import secrets
import time as _time

from flask import (
    Flask, request, jsonify, session,
    render_template, redirect, url_for
)

from config import SECRET_KEY
from zkp.schnorr import (
    generate_keys,
    verify_proof,
    fiat_shamir_challenge,
)
from database.db import (
    save_user, get_user, user_exists,
    record_failed_attempt, reset_failed_attempts,
    get_lockout,
)
from policy.policy_engine import evaluate_policy
from policy.rate_limiter import (
    record_ip_failure, is_ip_blocked, reset_ip,
)

app = Flask(__name__)
app.secret_key = SECRET_KEY


# ── Helpers ────────────────────────────────────────────────────────────────
def _bad(msg: str, code: int = 400):
    return jsonify({"success": False, "message": msg}), code


# ── 1. Index ───────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return render_template("index.html")


# ── 2. Register ────────────────────────────────────────────────────────────
@app.route("/register", methods=["POST"])
def register():
    """
    Registration Flow
    -----------------
    1. Receive username from client.
    2. Generate ZKP key-pair (x = private, y = public).
    3. Save only y (public key) to the database.
    4. Return x to the user — displayed ONCE; user must store it.
    """
    data = request.get_json(force=True)
    username = (data.get("username") or "").strip()

    if not username:
        return _bad("Username is required.")
    if user_exists(username):
        return _bad("Username already registered.", 409)

    x, y = generate_keys()
    save_user(username, y)

    return jsonify({
        "success": True,
        "message": "Registration successful!",
        "private_key": x,
        "public_key": y,
        "warning": (
            "⚠ Store your private key securely. "
            "It will NOT be shown again and is never stored on the server."
        ),
    })


# ── 3. Login (identity lookup only) ───────────────────────────────────────
@app.route("/login", methods=["POST"])
def login():
    """
    Login Step 1 – checks user exists, sets username in session.
    The Schnorr proof is generated entirely client-side; the private key
    is never transmitted to the server.
    """
    data = request.get_json(force=True)
    username = (data.get("username") or "").strip()

    if not username:
        return _bad("Username is required.")
    if not user_exists(username):
        return _bad("User not found.", 404)

    nonce = secrets.token_hex(16)
    session["username"] = username
    session["nonce"] = nonce
    return jsonify({"success": True, "message": "User found. Submit ZKP proof to /verify.", "nonce": nonce})


# ── 4. Verify (Access Control) ─────────────────────────────────────────────
@app.route("/verify", methods=["POST"])
def verify():
    """
    Verification + Zero Trust Policy Gate
    --------------------------------------
    Accepts the client-generated Schnorr proof {t, c, s} in the request body.
    Private key never reaches the server.

    Access Control logic:
      IF  ZKP valid  AND  Policy valid  →  grant access
      ELSE                              →  deny access
    """
    username = session.get("username")
    if not username:
        return _bad("No active session. Please login first.", 401)

    data = request.get_json(force=True) or {}
    try:
        t         = int(data["t"])
        c         = int(data["c"])
        s         = int(data["s"])
        timestamp = int(data["timestamp"])
    except (KeyError, ValueError, TypeError):
        return _bad("Request must include integer fields t, c, s, and timestamp.")

    # ── Fiat-Shamir challenge validation ───────────────────────────────────
    nonce = session.pop("nonce", None)
    if nonce is None:
        return _bad("No nonce in session. Please login again.", 401)

    if abs(_time.time() - timestamp) > 60:
        return _bad("Proof timestamp expired or too far in the future.", 401)

    if c != fiat_shamir_challenge(t, nonce, timestamp):
        return _bad("Challenge mismatch. Proof rejected.", 403)

    # Retrieve public key from Public Key Registry
    user = get_user(username)
    if not user:
        session.clear()
        return _bad("User not found.", 404)

    ip = request.headers.get("X-Forwarded-For", request.remote_addr)

    # ── Gate 1: Dynamic IP block ───────────────────────────────────────────
    blocked, unblock_at = is_ip_blocked(ip)
    if blocked:
        wait = int(unblock_at - _time.time())
        return _bad(
            f"Too many failed attempts from this IP. "
            f"Try again in {wait}s.", 429
        )

    # ── Gate 2: Account lockout ────────────────────────────────────────────
    locked, locked_until = get_lockout(username)
    if locked:
        wait = int(locked_until - _time.time())
        if locked_until >= 9_999_999_990:
            return _bad(
                "Account permanently locked due to repeated failures. "
                "Contact an administrator.", 403
            )
        return _bad(
            f"Account temporarily locked. Try again in {wait}s.", 429
        )

    # ── ZKP Verification ───────────────────────────────────────────────────
    if not verify_proof(user["public_key"], t, c, s):
        record_failed_attempt(username, ip)   # increments counter + maybe locks account
        record_ip_failure(ip)                 # increments IP failure window
        session.clear()
        return _bad("ZKP verification failed. Access denied.", 403)

    # ── Zero Trust Policy Check ────────────────────────────────────────────
    policy_ok, policy_msg = evaluate_policy(username, ip)
    if not policy_ok:
        session.clear()
        return _bad(policy_msg, 403)

    # ── Access Granted ─────────────────────────────────────────────────────
    reset_failed_attempts(username)           # clear account failure + lockout state
    reset_ip(ip)                              # clear IP failure window
    session["authenticated"] = True
    return jsonify({
        "success":  True,
        "message":  "Authentication successful! Access granted.",
        "redirect": "/dashboard",
    })


# ── 5. Re-auth Nonce ──────────────────────────────────────────────────────
@app.route("/reauth-nonce", methods=["GET"])
def reauth_nonce():
    """Issue a fresh single-use nonce for a continuous-auth cycle."""
    if not session.get("authenticated"):
        return _bad("Not authenticated.", 401)
    nonce = secrets.token_hex(16)
    session["reauth_nonce"] = nonce
    return jsonify({"nonce": nonce})


# ── 6. Re-auth (Continuous Authentication) ────────────────────────────────
@app.route("/reauth", methods=["POST"])
def reauth():
    """
    Continuous re-authentication endpoint.
    Client submits a fresh Schnorr proof every interval; server verifies it
    against the session-bound nonce and current policy. Failure terminates
    the session immediately.
    """
    if not session.get("authenticated"):
        return _bad("Not authenticated.", 401)

    username = session.get("username")
    if not username:
        return _bad("No session username.", 401)

    data = request.get_json(force=True) or {}
    try:
        t         = int(data["t"])
        c         = int(data["c"])
        s         = int(data["s"])
        timestamp = int(data["timestamp"])
    except (KeyError, ValueError, TypeError):
        return _bad("Request must include integer fields t, c, s, and timestamp.")

    nonce = session.pop("reauth_nonce", None)
    if nonce is None:
        return _bad("No reauth nonce. Call /reauth-nonce first.", 400)

    if abs(_time.time() - timestamp) > 60:
        session.clear()
        return _bad("Proof timestamp expired.", 401)

    if c != fiat_shamir_challenge(t, nonce, timestamp):
        session.clear()
        return _bad("Reauth challenge mismatch. Session terminated.", 403)

    user = get_user(username)
    if not user:
        session.clear()
        return _bad("User not found.", 404)

    ip = request.headers.get("X-Forwarded-For", request.remote_addr)

    if not verify_proof(user["public_key"], t, c, s):
        record_failed_attempt(username, ip)
        record_ip_failure(ip)
        session.clear()
        return _bad("Reauth ZKP verification failed. Session terminated.", 403)

    policy_ok, policy_msg = evaluate_policy(username, ip)
    if not policy_ok:
        session.clear()
        return _bad(policy_msg, 403)

    reset_failed_attempts(username)
    reset_ip(ip)
    session["last_reauth"] = int(_time.time())
    return jsonify({"success": True, "message": "Re-authentication successful."})


# ── 7. Dashboard (Protected Cloud Resource) ────────────────────────────────
@app.route("/dashboard")
def dashboard():
    if not session.get("authenticated"):
        return redirect(url_for("index"))
    return render_template("dashboard.html", username=session.get("username"))


# ── 8. Logout ─────────────────────────────────────────────────────────────
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


# ── Entry Point ────────────────────────────────────────────────────────────
if __name__ == "__main__":
    app.run(debug=True)
