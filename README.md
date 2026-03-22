# 🔐 ZKP Zero Trust Authentication System

A password-free authentication system built with **Zero-Knowledge Proofs (Schnorr Protocol)** and a **Zero Trust policy engine**, implemented in Python (Flask).

> "Prove who you are — without revealing your secret."

---

## 📌 Overview

Traditional login systems store passwords (or hashes) on the server — making them a target for data breaches. This project eliminates that risk entirely.

- The server **never sees or stores** your private key / password
- Identity is proven using **cryptographic math** (Schnorr Protocol)
- Access is further gated by a **Zero Trust policy engine** (time, IP, risk score)

---

## 🏗️ Architecture — 11 Components

| # | Component | File | Role |
|---|-----------|------|------|
| 1 | User (Prover) | — | Person trying to access the system |
| 2 | **ZKP Engine** ⭐ | `zkp/schnorr.py` | Core Schnorr protocol implementation |
| 3 | Authentication Module | `app.py` | Handles register / login / verify flow |
| 4 | Session Manager | Flask `session` | Stores temporary proof data (t, c, s) |
| 5 | Public Key Registry | `database/db.py` | Stores only username + public key |
| 6 | Zero Trust Policy Engine | `policy/policy_engine.py` | Time, IP, and risk-based access rules |
| 7 | Access Control Module | `/verify` route in `app.py` | Final grant/deny decision |
| 8 | Cloud Resource | `templates/dashboard.html` | Protected dashboard |
| 9 | API / Communication Layer | Flask routes | Connects frontend ↔ backend |
| 10 | Frontend UI | `templates/index.html` | Register and login interface |
| 11 | Configuration Module | `config.py` | ZKP parameters (P, G) and secret key |

---

## 📁 Project Structure

```
warp/
├── app.py                     # Flask app — all routes
├── config.py                  # ZKP parameters & Flask secret key
├── requirements.txt
│
├── zkp/
│   └── schnorr.py             # ZKP Engine (core innovation)
│
├── database/
│   ├── db.py                  # Public key registry
│   └── users.json             # Created at runtime
│
├── policy/
│   └── policy_engine.py       # Zero Trust policy rules
│
└── templates/
    ├── index.html             # Register / Login UI
    └── dashboard.html         # Protected cloud resource
```

---

## ⚙️ How It Works

### 1. Registration
```
Client                          Server
  │─── POST /register ────────► │
  │    { username }             │  generates x (private), y = G^x mod P (public)
  │                             │  saves only y to database
  │◄── { private_key: x } ─────│
  │
  ▼
User must store x securely — it is NEVER stored on the server.
```

### 2. Login (ZKP Proof Generation)
```
Client sends: username + private_key (x)

Server computes:
  r  = random integer
  t  = G^r mod P          (commitment)
  c  = random integer      (challenge)
  s  = (r - c·x) mod P-1  (response)

Stores { t, c, s } in session.
```

### 3. Verification + Zero Trust Gate
```
Server verifies:   G^s · y^c ≡ t  (mod P)  ← ZKP check
Policy engine checks:  time window, IP blocklist, risk score

If BOTH pass → Access Granted → redirect to /dashboard
If EITHER fails → Access Denied, session cleared
```

---

## 🔢 Schnorr Protocol (Math)

| Step | Who | Operation |
|------|-----|-----------|
| Key Generation | Prover | `x` = private key; `y = G^x mod P` = public key |
| Commitment | Prover | pick random `r`; send `t = G^r mod P` |
| Challenge | Verifier | send random `c` |
| Response | Prover | compute `s = (r − c·x) mod (P−1)` |
| Verify | Verifier | check `G^s · y^c ≡ t (mod P)` |

**Why it works:**
```
G^s · y^c = G^(r−cx) · (G^x)^c = G^(r−cx+cx) = G^r = t  ✓
```

**Security:** An attacker who doesn't know `x` cannot forge a valid `s` without solving the Discrete Logarithm Problem (computationally infeasible for large P).

---

## 🛡️ Zero Trust Policy Rules

Defined in `policy/policy_engine.py`:

| Rule | Default | Description |
|------|---------|-------------|
| Time window | `00:00 – 23:59` | Restrict to business hours in production |
| IP blocklist | empty | Add blocked IPs to `BLOCKED_IPS` set |
| Risk score | max = 2 | Increases for off-hours access; extensible |

---

## 🚀 Getting Started

### Prerequisites
- Python 3.10+

### Install & Run
```bash
pip install -r requirements.txt
python app.py
```

Open your browser at: **http://127.0.0.1:5000**

### Usage
1. **Register** — enter a username; copy and save your private key (shown once)
2. **Login** — enter username + private key; ZKP proof is generated automatically
3. **Verify** — server validates the proof and checks Zero Trust policy
4. **Dashboard** — access granted to the protected cloud resource

---

## 🔒 Security Properties

| Property | Status |
|----------|--------|
| No password stored on server | ✅ |
| No secret transmitted over network | ✅ |
| Replay attack resistance (random r per login) | ✅ |
| Zero Trust policy enforcement | ✅ |
| Secure session management | ✅ |

### ⚠️ Production Notes
- Replace the 31-bit prime `P` with a **2048-bit safe prime** (e.g. RFC 3526 Group 14)
- Load `SECRET_KEY` from an environment variable or vault — do not regenerate on each restart
- Use HTTPS (TLS) in deployment
- Move the database to PostgreSQL / Redis
- Store the private key in a hardware token or OS keystore — never in a text field

---

## 📚 Tech Stack

- **Backend:** Python 3, Flask
- **Cryptography:** Schnorr Identification Protocol (custom implementation)
- **Storage:** JSON flat file (public keys only)
- **Frontend:** Vanilla HTML / CSS / JavaScript

---

## 👨‍💻 Author
Anant Shrivastava
Minor Project — Zero Trust Authentication using Zero-Knowledge Proofs
