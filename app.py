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

from flask import (
    Flask, request, jsonify, session,
    render_template, redirect, url_for
)

from config import SECRET_KEY
from zkp.schnorr import (
    generate_keys,
    generate_commitment,
    generate_challenge,
    generate_response,
    verify_proof,
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


# ── 3. Login (ZKP proof generation) ───────────────────────────────────────
@app.route("/login", methods=["POST"])
def login():
    """
    Login Flow  (ZKP Steps 1-3 – runs on the prover side)
    ------------------------------------------------------
    1. Receive username + private_key from client.
    2. Generate commitment t = G^r mod P.
    3. Generate challenge c.
    4. Compute response s = (r - c·x) mod (P-1).
    5. Store {t, c, s, username} in the server-side session.
    6. Return proof data to client so it can pass it to /verify.
    """
    data = request.get_json(force=True)
    username = (data.get("username") or "").strip()
    raw_key  = data.get("private_key")

    if not username or raw_key is None:
        return _bad("Username and private_key are required.")
    if not user_exists(username):
        return _bad("User not found.", 404)

    try:
        x = int(raw_key)
    except (ValueError, TypeError):
        return _bad("private_key must be an integer.")

    # ZKP steps
    r, t = generate_commitment(x)
    c    = generate_challenge()
    s    = generate_response(x, r, c)

    # Session Manager – stores temporary proof data
    session["username"] = username
    session["t"] = t
    session["c"] = c
    session["s"] = s

    return jsonify({
        "success": True,
        "message": "ZKP proof generated. Call /verify to complete login.",
        "commitment": t,
        "challenge":  c,
        "response":   s,
    })


# ── 4. Verify (Access Control) ─────────────────────────────────────────────
@app.route("/verify", methods=["POST"])
def verify():
    """
    Verification + Zero Trust Policy Gate
    --------------------------------------
    Access Control logic:
      IF  ZKP valid  AND  Policy valid  →  grant access
      ELSE                              →  deny access
    """
    # Retrieve proof from Session Manager
    username = session.get("username")
    t = session.get("t")
    c = session.get("c")
    s = session.get("s")

    if not all([username, t is not None, c is not None, s is not None]):
        return _bad("No active session. Please login first.", 401)

    # Retrieve public key from Public Key Registry
    user = get_user(username)
    if not user:
        session.clear()
        return _bad("User not found.", 404)

    ip = request.headers.get("X-Forwarded-For", request.remote_addr)

    # ── Gate 1: Dynamic IP block ───────────────────────────────────────────
    blocked, unblock_at = is_ip_blocked(ip)
    if blocked:
        import time as _time
        wait = int(unblock_at - _time.time())
        return _bad(
            f"Too many failed attempts from this IP. "
            f"Try again in {wait}s.", 429
        )

    # ── Gate 2: Account lockout ────────────────────────────────────────────
    locked, locked_until = get_lockout(username)
    if locked:
        import time as _time
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


# ── 5. Dashboard (Protected Cloud Resource) ────────────────────────────────
@app.route("/dashboard")
def dashboard():
    if not session.get("authenticated"):
        return redirect(url_for("index"))
    return render_template("dashboard.html", username=session.get("username"))


# ── 6. Logout ─────────────────────────────────────────────────────────────
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


# ── Entry Point ────────────────────────────────────────────────────────────
if __name__ == "__main__":
    app.run(debug=True)
