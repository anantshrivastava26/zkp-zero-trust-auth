"""
ZKP Engine – Schnorr Identification Protocol
=============================================
Math recap
----------
Setup  : prime P, generator G (of the multiplicative group mod P)
KeyGen : secret x  ∈ [2, P-2]
         public y  = G^x  mod P

Commitment : prover picks random r, sends  t = G^r  mod P
Challenge  : verifier sends random          c
Response   : prover computes               s = (r - c·x)  mod (P-1)
Verify     : G^s · y^c  ≡  t  (mod P)

Proof:  G^s · y^c = G^(r-cx) · G^(xc) = G^r = t  ✓
"""

import random
from config import P, G


# ── 1. Key Generation ──────────────────────────────────────────────────────
def generate_keys() -> tuple[int, int]:
    """Return (private_key x, public_key y) where y = G^x mod P."""
    x = random.randint(2, P - 2)   # secret key – never stored on server
    y = pow(G, x, P)               # public key – stored in DB
    return x, y


# ── 2. Commitment ──────────────────────────────────────────────────────────
def generate_commitment(x: int) -> tuple[int, int]:
    """
    Prover picks a fresh random r and computes commitment t = G^r mod P.
    Returns (r, t).  r must be kept secret until the proof is complete.
    """
    r = random.randint(2, P - 2)
    t = pow(G, r, P)
    return r, t


# ── 3. Challenge ───────────────────────────────────────────────────────────
def generate_challenge() -> int:
    """Verifier generates a random challenge c."""
    return random.randint(1, P - 2)


# ── 4. Response ────────────────────────────────────────────────────────────
def generate_response(x: int, r: int, c: int) -> int:
    """
    Prover computes the response s = (r - c·x) mod (P-1).
    Python % always returns a non-negative result for a positive modulus.
    """
    return (r - c * x) % (P - 1)


# ── 5. Verification ────────────────────────────────────────────────────────
def verify_proof(y: int, t: int, c: int, s: int) -> bool:
    """
    Verifier checks whether G^s · y^c ≡ t (mod P).
    Returns True only if the proof is valid.
    """
    lhs = (pow(G, s, P) * pow(y, c, P)) % P
    return lhs == t
