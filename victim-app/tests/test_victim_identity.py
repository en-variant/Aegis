import time

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from agent.identity import AuthenticatedUser, authenticate_user, mint_identity_token
from victim_api import app


def test_seeded_login_reads_passwords_from_environment(
    monkeypatch,
) -> None:
    monkeypatch.setenv("VICTIM_ALICE_PASSWORD", "alice-local-demo-password")
    monkeypatch.setenv("VICTIM_BOB_PASSWORD", "bob-local-demo-password")

    alice = authenticate_user("Alice", "alice-local-demo-password")
    bob = authenticate_user("bob", "bob-local-demo-password")

    assert alice == AuthenticatedUser(user_id="alice", role="finance_admin")
    assert bob == AuthenticatedUser(user_id="bob", role="viewer")
    assert authenticate_user("alice", "wrong") is None


def test_identity_jwt_is_short_lived_and_signed_per_request(
    tmp_path,
    monkeypatch,
) -> None:
    private_key = Ed25519PrivateKey.generate()
    key_path = tmp_path / "victim.identity.pem"
    key_path.write_bytes(
        private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    monkeypatch.setenv("VICTIM_IDENTITY_PRIVATE_KEY", str(key_path))
    monkeypatch.setenv("AEGIS_APP_ID", "app-test-id")
    monkeypatch.setenv("AEGIS_IDENTITY_KID", "test-key")
    user = AuthenticatedUser(user_id="alice", role="finance_admin")

    first = mint_identity_token(user)
    second = mint_identity_token(user)
    claims = jwt.decode(
        first,
        private_key.public_key(),
        algorithms=["EdDSA"],
        audience="aegis",
    )

    assert first != second
    assert jwt.get_unverified_header(first)["kid"] == "test-key"
    assert claims["iss"] == "app-test-id"
    assert claims["sub"] == "alice"
    assert claims["role"] == "finance_admin"
    assert claims["exp"] - claims["iat"] <= 300


def test_victim_web_login_uses_server_session_and_keeps_secrets_out_of_response(
    monkeypatch,
) -> None:
    monkeypatch.setenv("VICTIM_ALICE_PASSWORD", "alice-local-demo-password")
    monkeypatch.setenv("VICTIM_BOB_PASSWORD", "bob-local-demo-password")
    with TestClient(app) as client:
        rejected = client.post(
            "/api/login",
            json={"username": "alice", "password": "wrong"},
        )
        assert rejected.status_code == 401

        logged_in = client.post(
            "/api/login",
            json={
                "username": "alice",
                "password": "alice-local-demo-password",
            },
        )

        assert logged_in.status_code == 200
        assert logged_in.json() == {"id": "alice", "role": "finance_admin"}
        assert "alice-local-demo-password" not in logged_in.text
        assert "identity" not in logged_in.text.casefold()
        assert client.get("/api/me").json() == {
            "id": "alice",
            "role": "finance_admin",
        }


def test_chat_requires_login_and_passes_server_principal_not_body_role(
    monkeypatch,
) -> None:
    monkeypatch.setenv("VICTIM_ALICE_PASSWORD", "alice-local-demo-password")
    observed: dict[str, object] = {}

    def fake_run_agent(message: str, *, user: AuthenticatedUser):
        observed["message"] = message
        observed["user"] = user
        return "synthetic reply", []

    monkeypatch.setattr("victim_api.run_agent", fake_run_agent)
    with TestClient(app) as client:
        unauthenticated = client.post(
            "/api/chat",
            json={"message": "pay invoice", "role": "finance_admin"},
        )
        assert unauthenticated.status_code == 401

        client.post(
            "/api/login",
            json={"username": "alice", "password": "alice-local-demo-password"},
        )
        response = client.post(
            "/api/chat",
            json={"message": "summarize", "role": "viewer"},
        )

    assert response.status_code == 200
    assert response.json() == {"answer": "synthetic reply", "tool_calls": []}
    assert observed == {
        "message": "summarize",
        "user": AuthenticatedUser(user_id="alice", role="finance_admin"),
    }


def test_minted_tokens_have_distinct_jtis(monkeypatch, tmp_path) -> None:
    private_key = Ed25519PrivateKey.generate()
    key_path = tmp_path / "identity.pem"
    key_path.write_bytes(
        private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    monkeypatch.setenv("VICTIM_IDENTITY_PRIVATE_KEY", str(key_path))
    monkeypatch.setenv("AEGIS_APP_ID", "app-test-id")
    monkeypatch.setenv("AEGIS_IDENTITY_KID", "test-key")
    first_claims = jwt.decode(
        mint_identity_token(AuthenticatedUser("bob", "viewer")),
        private_key.public_key(),
        algorithms=["EdDSA"],
        audience="aegis",
    )
    second_claims = jwt.decode(
        mint_identity_token(AuthenticatedUser("bob", "viewer")),
        private_key.public_key(),
        algorithms=["EdDSA"],
        audience="aegis",
    )
    assert first_claims["jti"] != second_claims["jti"]
    assert first_claims["exp"] >= int(time.time())
