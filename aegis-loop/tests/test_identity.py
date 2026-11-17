import base64

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aegis_loop.identity import verify_identity


def _key_record(
    private_key: Ed25519PrivateKey | None = None,
) -> tuple[Ed25519PrivateKey, dict[str, str]]:
    key = private_key or Ed25519PrivateKey.generate()
    public_key = key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    encoded = base64.urlsafe_b64encode(public_key).decode("ascii").rstrip("=")
    return key, {"lab-key": encoded}


def _token(
    private_key: Ed25519PrivateKey,
    claims: dict[str, object] | None = None,
    *,
    kid: str = "lab-key",
) -> str:
    return jwt.encode(
        claims
        or {
            "iss": "app-1",
            "sub": "alice",
            "role": "finance_admin",
            "aud": "aegis",
            "iat": 1000,
            "exp": 1120,
            "jti": "one-use",
        },
        private_key,
        algorithm="EdDSA",
        headers={"kid": kid},
    )


@pytest.mark.parametrize(
    ("token", "keys", "expected"),
    [
        (None, {}, "missing_identity"),
    ],
)
def test_missing_identity_is_reason_coded(
    token: str | None,
    keys: dict[str, str],
    expected: str,
) -> None:
    assert verify_identity(token, app_id="app-1", active_keys=keys, now=1000).status == expected


def test_valid_ed25519_identity_is_accepted() -> None:
    private_key, keys = _key_record()

    identity = verify_identity(
        _token(private_key),
        app_id="app-1",
        active_keys=keys,
        now=1000,
    )

    assert identity.status == "valid"
    assert identity.user_id == "alice"
    assert identity.role == "finance_admin"
    assert identity.jti == "one-use"
    assert identity.expires_at == 1120


def test_invalid_signature_is_denied() -> None:
    registered_key, keys = _key_record()
    other_key, _ = _key_record()

    identity = verify_identity(
        _token(other_key),
        app_id="app-1",
        active_keys=keys,
        now=1000,
    )

    assert identity.status == "bad_signature"
    assert registered_key != other_key


def test_unregistered_kid_is_denied() -> None:
    private_key, keys = _key_record()

    identity = verify_identity(
        _token(private_key, kid="unknown-key"),
        app_id="app-1",
        active_keys=keys,
        now=1000,
    )

    assert identity.status == "unknown_kid"


def test_expired_identity_is_denied() -> None:
    private_key, keys = _key_record()
    token = _token(
        private_key,
        {
            "iss": "app-1",
            "sub": "alice",
            "role": "finance_admin",
            "aud": "aegis",
            "iat": 900,
            "exp": 960,
            "jti": "expired",
        },
    )

    assert (
        verify_identity(token, app_id="app-1", active_keys=keys, now=1000).status
        == "expired"
    )


def test_wrong_issuer_and_invalid_claims_are_distinguished() -> None:
    private_key, keys = _key_record()
    wrong_issuer = _token(
        private_key,
        {
            "iss": "other-app",
            "sub": "alice",
            "role": "employee",
            "aud": "aegis",
            "iat": 1000,
            "exp": 1120,
            "jti": "wrong-issuer",
        },
    )
    missing_claim = _token(
        private_key,
        {
            "iss": "app-1",
            "sub": "alice",
            "role": "employee",
            "aud": "aegis",
            "iat": 1000,
            "exp": 1400,
            "jti": "too-long",
        },
    )

    assert (
        verify_identity(
            wrong_issuer,
            app_id="app-1",
            active_keys=keys,
            now=1000,
        ).status
        == "wrong_issuer"
    )
    assert (
        verify_identity(
            missing_claim,
            app_id="app-1",
            active_keys=keys,
            now=1000,
        ).status
        == "invalid_claims"
    )


def test_none_and_hs256_algorithms_are_rejected() -> None:
    private_key, keys = _key_record()
    claims = {
        "iss": "app-1",
        "sub": "alice",
        "role": "employee",
        "aud": "aegis",
        "iat": 1000,
        "exp": 1120,
        "jti": "downgrade",
    }
    no_signature = jwt.encode(
        claims,
        key=None,
        algorithm="none",
        headers={"kid": "lab-key"},
    )
    hmac_token = jwt.encode(
        claims,
        key="not-an-ed25519-key-that-is-at-least-thirty-two-bytes",
        algorithm="HS256",
        headers={"kid": "lab-key"},
    )

    assert (
        verify_identity(
            no_signature,
            app_id="app-1",
            active_keys=keys,
            now=1000,
        ).status
        == "bad_signature"
    )
    assert (
        verify_identity(
            hmac_token,
            app_id="app-1",
            active_keys=keys,
            now=1000,
        ).status
        == "bad_signature"
    )
    assert private_key is not None
