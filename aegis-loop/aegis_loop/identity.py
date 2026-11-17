from __future__ import annotations

import base64
import time
from dataclasses import dataclass
from typing import Any

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

ALLOWED_ROLES = frozenset({"employee", "finance_admin", "viewer"})
IDENTITY_AUDIENCE = "aegis"
MAX_IDENTITY_LIFETIME = 300
CLOCK_SKEW_SECONDS = 30


@dataclass(frozen=True)
class IdentityResult:
    status: str
    user_id: str | None = None
    role: str | None = None
    jti: str | None = None
    expires_at: int | None = None


def decode_public_key(encoded: str) -> Ed25519PublicKey:
    padded = encoded + "=" * (-len(encoded) % 4)
    raw = base64.b64decode(
        padded.encode("ascii"),
        altchars=b"-_",
        validate=True,
    )
    if len(raw) != 32:
        raise ValueError("Ed25519 public keys must be 32 bytes")
    return Ed25519PublicKey.from_public_bytes(raw)


def verify_identity(
    token: str | None,
    *,
    app_id: str,
    active_keys: dict[str, str],
    now: int | None = None,
) -> IdentityResult:
    if not token:
        return IdentityResult("missing_identity")
    if len(token) > 4096:
        return IdentityResult("invalid_claims")
    current_time = int(time.time()) if now is None else now
    try:
        header = jwt.get_unverified_header(token)
    except jwt.PyJWTError:
        return IdentityResult("invalid_claims")
    if header.get("alg") != "EdDSA":
        return IdentityResult("bad_signature")
    kid = header.get("kid")
    if not isinstance(kid, str) or not kid:
        return IdentityResult("invalid_claims")
    encoded_key = active_keys.get(kid)
    if encoded_key is None:
        return IdentityResult("unknown_kid")
    try:
        key = decode_public_key(encoded_key)
        claims: dict[str, Any] = jwt.decode(
            token,
            key=key,
            algorithms=["EdDSA"],
            options={
                "verify_aud": False,
                "verify_exp": False,
                "verify_iat": False,
                "verify_nbf": False,
            },
        )
    except (jwt.PyJWTError, ValueError, UnicodeError):
        return IdentityResult("bad_signature")

    if any(
        name not in claims
        for name in ("iss", "sub", "role", "aud", "iat", "exp", "jti")
    ):
        return IdentityResult("invalid_claims")
    issuer = claims.get("iss")
    if issuer != app_id:
        return IdentityResult("wrong_issuer")
    issued_at = claims.get("iat")
    expires_at = claims.get("exp")
    if (
        not isinstance(issued_at, (int, float))
        or isinstance(issued_at, bool)
        or not isinstance(expires_at, (int, float))
        or isinstance(expires_at, bool)
    ):
        return IdentityResult("invalid_claims")
    if expires_at <= issued_at or expires_at - issued_at > MAX_IDENTITY_LIFETIME:
        return IdentityResult("invalid_claims")
    if issued_at > current_time + CLOCK_SKEW_SECONDS:
        return IdentityResult("invalid_claims")
    if expires_at < current_time - CLOCK_SKEW_SECONDS:
        return IdentityResult("expired")
    if claims.get("aud") != IDENTITY_AUDIENCE:
        return IdentityResult("invalid_claims")
    user_id = claims.get("sub")
    role = claims.get("role")
    jti = claims.get("jti")
    if (
        not isinstance(user_id, str)
        or not user_id
        or len(user_id) > 200
        or not isinstance(role, str)
        or role not in ALLOWED_ROLES
        or not isinstance(jti, str)
        or not jti
        or len(jti) > 200
    ):
        return IdentityResult("invalid_claims")
    return IdentityResult(
        "valid",
        user_id=user_id,
        role=role,
        jti=jti,
        expires_at=int(expires_at),
    )
