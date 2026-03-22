import secrets

# ─────────────────────────────────────────────
#  ZKP PARAMETERS  (Schnorr Protocol)
# ─────────────────────────────────────────────
# P : large prime modulus
#   2^31 - 1 is a Mersenne prime — fine for demo.
#   Use a 2048-bit safe prime in production.
P = 2_147_483_647          # 2^31 - 1  (Mersenne prime)

# G : generator of the multiplicative group mod P
G = 7

# ─────────────────────────────────────────────
#  FLASK SESSION SECRET
# ─────────────────────────────────────────────
SECRET_KEY = secrets.token_hex(32)
