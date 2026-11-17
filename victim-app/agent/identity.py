from __future__ import annotations

import hmac
import os
import time
from dataclasses import dataclass
from pathlib import Path
from uuid import uuid4

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


@dataclass(frozen=True)
class AuthenticatedUser:
    user_id: str
    role: str


def seeded_users() -> dict[str, tuple[str, str]]:
    return {
        "alice": (os.environ.get("VICTIM_ALICE_PASSWORD", ""), "finance_admin"),
        "bob": (os.environ.get("VICTIM_BOB_PASSWORD", ""), "viewer"),
    }


def authenticate_user(username: str, password: str) -> AuthenticatedUser | None:
    # This local login is a stand-in for a real identity provider.
    users = seeded_users()
    expected_password, role = users.get(username.casefold(), ("", ""))
    if not expected_password or not hmac.compare_digest(
        expected_password.encode("utf-8"),
        password.encode("utf-8"),
    ):
        return None
    return AuthenticatedUser(user_id=username.casefold(), role=role)


def _private_key() -> Ed25519PrivateKey:
    key_path = os.environ.get("VICTIM_IDENTITY_PRIVATE_KEY", "")
    if not key_path:
        raise RuntimeError("VICTIM_IDENTITY_PRIVATE_KEY is not configured")
    key_bytes = Path(key_path).expanduser().read_bytes()
    key = serialization.load_pem_private_key(key_bytes, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise TypeError("Victim identity key must be an Ed25519 private key")
    return key


def mint_identity_token(user: AuthenticatedUser) -> str:
    issuer = os.environ.get("AEGIS_APP_ID", "")
    kid = os.environ.get("AEGIS_IDENTITY_KID", "")
    if not issuer or not kid:
        raise RuntimeError("AEGIS_APP_ID and AEGIS_IDENTITY_KID must be configured")
    now = int(time.time())
    return jwt.encode(
        {
            "iss": issuer,
            "sub": user.user_id,
            "role": user.role,
            "aud": "aegis",
            "iat": now,
            "exp": now + 120,
            "jti": uuid4().hex,
        },
        _private_key(),
        algorithm="EdDSA",
        headers={"kid": kid},
    )
