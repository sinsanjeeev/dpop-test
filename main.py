"""
FastAPI Resource Server — DPoP Token Validation
================================================
Endpoint : GET /api/account
Port     : 8080

Validates:
  1. Authorization: DPoP <access_token>  — signature via Keycloak JWKS
  2. DPoP: <proof>                       — ES256 proof tied to method + URL + key
  3. cnf.jkt in access_token matches the public key inside the DPoP proof

Run:
    pip install fastapi uvicorn python-jose[cryptography] httpx
    uvicorn main:app --port 8080 --reload
"""

import hashlib
import base64
import json
import time
import httpx

from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from jose import jwt, jwk, JWTError
from jose.utils import base64url_decode

# ── CONFIG ────────────────────────────────────────────────────────────────────
KEYCLOAK_ISSUER   = "http://localhost:7000/realms/dpop-test"
JWKS_URI          = f"{KEYCLOAK_ISSUER}/protocol/openid-connect/certs"
AUDIENCE          = "account"           # must match `aud` in your token
RESOURCE_BASE_URL = "http://localhost:8080"   # this server's public base URL
DPOP_MAX_AGE_SEC  = 60                  # reject proofs older than 60 seconds

# ── APP ───────────────────────────────────────────────────────────────────────
app = FastAPI(title="DPoP Resource Server", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5005"],   # your HTML origin
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── JWKS CACHE ────────────────────────────────────────────────────────────────
_jwks_cache: dict = {}
_jwks_fetched_at: float = 0
JWKS_TTL = 300  # re-fetch every 5 min


async def get_jwks() -> dict:
    global _jwks_cache, _jwks_fetched_at
    if time.time() - _jwks_fetched_at > JWKS_TTL:
        async with httpx.AsyncClient() as client:
            resp = await client.get(JWKS_URI)
            resp.raise_for_status()
            _jwks_cache = {k["kid"]: k for k in resp.json()["keys"]}
            _jwks_fetched_at = time.time()
    return _jwks_cache


# ── HELPERS ───────────────────────────────────────────────────────────────────

def b64url_decode_bytes(s: str) -> bytes:
    """Decode base64url string (no padding needed)."""
    return base64url_decode(s.encode())


def b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def jwk_thumbprint(jwk_dict: dict) -> str:
    """
    RFC 7638 JWK thumbprint — SHA-256 over canonical JSON of
    required members only (for EC: crv, kty, x, y).
    """
    required = {k: jwk_dict[k] for k in sorted(["crv", "kty", "x", "y"])}
    canonical = json.dumps(required, separators=(",", ":"), sort_keys=True)
    digest = hashlib.sha256(canonical.encode()).digest()
    return b64url_encode(digest)


def decode_jwt_unverified(token: str) -> tuple[dict, dict]:
    """Split and base64-decode a JWT without verification."""
    parts = token.split(".")
    if len(parts) != 3:
        raise HTTPException(400, "Malformed JWT")
    header  = json.loads(b64url_decode_bytes(parts[0]))
    payload = json.loads(b64url_decode_bytes(parts[1]))
    return header, payload


# ── STEP 1 — Verify Access Token via Keycloak JWKS ───────────────────────────

async def verify_access_token(token: str) -> dict:
    jwks = await get_jwks()
    header, _ = decode_jwt_unverified(token)
    kid = header.get("kid")

    if not kid or kid not in jwks:
        raise HTTPException(401, f"Unknown kid '{kid}' — key not in JWKS")

    key_obj = jwk.construct(jwks[kid])

    try:
        claims = jwt.decode(
            token,
            key_obj,
            algorithms=["RS256", "ES256"],
            audience=AUDIENCE,
            issuer=KEYCLOAK_ISSUER,
            options={"verify_exp": True},
        )
    except JWTError as e:
        raise HTTPException(401, f"Access token invalid: {e}")

    # Must be a DPoP-bound token
    if claims.get("token_type", "").lower() not in ("", "bearer"):
        pass  # token_type field not always present; check typ header instead

    header_typ = header.get("typ", "").lower()
    # Keycloak marks DPoP tokens with typ=at+JWT and includes cnf.jkt
    if "cnf" not in claims:
        raise HTTPException(401, "Token missing 'cnf' claim — not DPoP bound")

    return claims


# ── STEP 2 — Verify DPoP Proof ────────────────────────────────────────────────

def verify_dpop_proof(proof: str, method: str, url: str, cnf_jkt: str):
    """
    Validates the DPoP proof JWT:
      - typ == dpop+jwt
      - alg == ES256
      - htm matches request method
      - htu matches request URL
      - iat is recent
      - Signature valid against embedded JWK
      - JWK thumbprint matches cnf.jkt from access token
    """
    header, payload = decode_jwt_unverified(proof)

    # ── Header checks
    if header.get("typ", "").lower() != "dpop+jwt":
        raise HTTPException(401, "DPoP proof typ must be 'dpop+jwt'")

    if header.get("alg") not in ("ES256", "RS256"):
        raise HTTPException(401, f"Unsupported DPoP alg: {header.get('alg')}")

    embedded_jwk = header.get("jwk")
    if not embedded_jwk:
        raise HTTPException(401, "DPoP proof missing embedded JWK in header")

    # ── Payload checks
    if payload.get("htm", "").upper() != method.upper():
        raise HTTPException(
            401,
            f"DPoP htm mismatch: expected {method}, got {payload.get('htm')}"
        )

    # Normalize URLs for comparison (strip trailing slash)
    proof_htu = payload.get("htu", "").rstrip("/")
    expected_htu = url.rstrip("/")
    if proof_htu != expected_htu:
        raise HTTPException(
            401,
            f"DPoP htu mismatch: expected {expected_htu}, got {proof_htu}"
        )

    iat = payload.get("iat", 0)
    now = time.time()
    if not (now - DPOP_MAX_AGE_SEC <= iat <= now + 5):
        raise HTTPException(401, f"DPoP proof expired or future-dated (iat={iat})")

    if not payload.get("jti"):
        raise HTTPException(401, "DPoP proof missing jti")

    # ── Verify proof signature using embedded public key
    try:
        key_obj = jwk.construct(embedded_jwk)
        jwt.decode(
            proof,
            key_obj,
            algorithms=["ES256", "RS256"],
            options={
                "verify_exp": False,
                "verify_aud": False,
                "verify_iss": False,
            },
        )
    except JWTError as e:
        raise HTTPException(401, f"DPoP proof signature invalid: {e}")

    # ── Verify JWK thumbprint matches cnf.jkt in access token
    computed_jkt = jwk_thumbprint(embedded_jwk)
    if computed_jkt != cnf_jkt:
        raise HTTPException(
            401,
            f"DPoP key mismatch: cnf.jkt={cnf_jkt}, proof key thumbprint={computed_jkt}"
        )


# ── COMBINED DEPENDENCY ───────────────────────────────────────────────────────

async def require_dpop(request: Request) -> dict:
    """
    FastAPI dependency — validates both the access token and DPoP proof.
    Returns the access token claims on success.
    """
    # ── Extract Authorization header
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("DPoP "):
        raise HTTPException(
            401,
            "Authorization header must use DPoP scheme",
            headers={"WWW-Authenticate": 'DPoP realm="dpop-resource"'},
        )
    access_token = auth_header[len("DPoP "):]

    # ── Extract DPoP proof header
    dpop_proof = request.headers.get("DPoP")
    if not dpop_proof:
        raise HTTPException(401, "Missing DPoP proof header")

    # ── Step 1: Verify access token
    claims = await verify_access_token(access_token)

    # ── Step 2: Verify DPoP proof
    cnf_jkt = claims["cnf"]["jkt"]
    full_url = f"{RESOURCE_BASE_URL}{request.url.path}"

    verify_dpop_proof(
        proof=dpop_proof,
        method=request.method,
        url=full_url,
        cnf_jkt=cnf_jkt,
    )

    return claims


# ── ROUTES ────────────────────────────────────────────────────────────────────

@app.get("/api/account")
async def get_account(claims: dict = Depends(require_dpop)):
    """
    Protected endpoint — returns account info from the validated token claims.
    Only reachable with a valid DPoP-bound access token.
    """
    return {
        "message": "Hello! DPoP token verified ✅",
        "account": {
            "sub":      claims.get("sub"),
            "username": claims.get("preferred_username"),
            "email":    claims.get("email"),
            "name":     claims.get("name"),
            "roles":    claims.get("realm_access", {}).get("roles", []),
            "client":   claims.get("azp"),
            "session":  claims.get("sid"),
            "issued_at": claims.get("iat"),
            "expires_at": claims.get("exp"),
        },
        "dpop": {
            "bound": True,
            "jkt": claims["cnf"]["jkt"],
        },
    }


@app.get("/health")
async def health():
    """Public health check — no auth required."""
    return {"status": "ok", "server": "DPoP Resource Server"}


# ── STARTUP LOG ───────────────────────────────────────────────────────────────

@app.on_event("startup")
async def startup():
    print("\n" + "═" * 55)
    print("  DPoP Resource Server")
    print("═" * 55)
    print(f"  Listening : http://localhost:8080")
    print(f"  Endpoint  : GET /api/account")
    print(f"  JWKS      : {JWKS_URI}")
    print(f"  Audience  : {AUDIENCE}")
    print(f"  CORS      : http://localhost:5005")
    print("═" * 55 + "\n")