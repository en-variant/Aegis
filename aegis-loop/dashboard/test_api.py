import base64
import secrets
import time
from uuid import uuid4

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from dashboard.api import app


def _register_user(client: TestClient) -> None:
    response = client.post(
        "/api/auth/register",
        json={
            "email": f"person-{secrets.token_hex(6)}@example.test",
            "password": "correct horse battery",
        },
    )
    assert response.status_code == 200


def _identity_headers(
    client: TestClient,
    application: dict[str, str],
) -> dict[str, str]:
    registered_app = application["application"]
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    kid = f"stream-{uuid4().hex[:12]}"
    encoded_public_key = base64.urlsafe_b64encode(public_key).decode().rstrip("=")
    response = client.post(
        f"/api/apps/{registered_app['id']}/identity-keys",
        json={"kid": kid, "public_key": encoded_public_key},
    )
    assert response.status_code == 200
    now = int(time.time())
    token = jwt.encode(
        {
            "iss": registered_app["id"],
            "sub": "stream-test-user",
            "role": "employee",
            "aud": "aegis",
            "iat": now,
            "exp": now + 120,
            "jti": uuid4().hex,
        },
        private_key,
        algorithm="EdDSA",
        headers={"kid": kid},
    )
    return {
        "Authorization": f"Bearer {application['integration_token']}",
        "X-Aegis-Identity": token,
    }


def test_health_checks_postgres_and_legacy_global_api_is_removed() -> None:
    with TestClient(app) as client:
        health = client.get("/api/health")
        assert health.status_code == 200
        assert health.json() == {"status": "ok", "database": "connected"}
        assert client.get("/api/events").status_code == 404
        assert client.post("/api/demo/attack").status_code in {404, 405}


def test_browser_post_rejects_untrusted_origin() -> None:
    with TestClient(app) as client:
        response = client.post(
            "/api/auth/logout",
            headers={"Origin": "https://untrusted.example"},
        )
    assert response.status_code == 403


def test_authenticated_app_websocket_streams_its_tool_events() -> None:
    with TestClient(app) as owner, TestClient(app) as integration_client:
        _register_user(owner)
        application = owner.post(
            "/api/apps", json={"name": "Synthetic finance"}
        ).json()
        app_id = application["application"]["id"]

        with owner.websocket_connect(f"/api/live?app_id={app_id}") as websocket:
            response = integration_client.post(
                "/api/integration/authorize",
                headers=_identity_headers(owner, application),
                json={
                    "tool": "read_inbox",
                    "role": "employee",
                    "arguments": {},
                },
            )
            assert response.status_code == 200
            message = websocket.receive_json()

        assert message["type"] == "tool_event"
        assert message["app_id"] == app_id
        assert message["event"]["allowed"] is True


def test_websocket_rejects_another_users_application() -> None:
    with TestClient(app) as owner, TestClient(app) as other:
        _register_user(owner)
        app_id = owner.post(
            "/api/apps", json={"name": "Private finance app"}
        ).json()["application"]["id"]
        _register_user(other)

        with pytest.raises(WebSocketDisconnect) as error, other.websocket_connect(
            f"/api/live?app_id={app_id}"
        ):
            pytest.fail("A user connected to another user's application")
        assert error.value.code == 1008
