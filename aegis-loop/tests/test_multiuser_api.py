import base64
import json
import secrets
import time
from pathlib import Path
from typing import Any
from uuid import uuid4

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from aegis_loop import database
from dashboard.api import app


def _register_user(client: TestClient) -> str:
    email = f"person-{secrets.token_hex(6)}@example.test"
    response = client.post(
        "/api/auth/register",
        json={"email": email, "password": "correct horse battery"},
    )
    assert response.status_code == 200
    assert response.json()["email"] == email
    return email


def _register_app(client: TestClient, name: str = "Synthetic finance") -> dict:
    response = client.post("/api/apps", json={"name": name})
    assert response.status_code == 200
    application = response.json()
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    kid = f"test-{uuid4().hex[:12]}"
    public_key_text = base64.urlsafe_b64encode(public_key).decode().rstrip("=")
    registered = client.post(
        f"/api/apps/{application['application']['id']}/identity-keys",
        json={"kid": kid, "public_key": public_key_text},
    )
    assert registered.status_code == 200
    application["_identity_private_key"] = private_key
    application["_identity_kid"] = kid
    return application


def _identity_token(
    application: dict[str, Any],
    *,
    role: str = "employee",
    issuer: str | None = None,
    expires_in: int = 120,
    token_id: str | None = None,
    private_key: Ed25519PrivateKey | None = None,
    kid: str | None = None,
) -> str:
    now = int(time.time())
    claims = {
        "iss": issuer or application["application"]["id"],
        "sub": "test-user-1",
        "role": role,
        "aud": "aegis",
        "iat": now,
        "exp": now + expires_in,
        "jti": token_id or uuid4().hex,
    }
    return jwt.encode(
        claims,
        private_key or application["_identity_private_key"],
        algorithm="EdDSA",
        headers={"kid": kid or application["_identity_kid"]},
    )


def _identity_headers(
    application: dict[str, Any],
    *,
    role: str = "employee",
    issuer: str | None = None,
    expires_in: int = 120,
    token_id: str | None = None,
) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {application['integration_token']}",
        "X-Aegis-Identity": _identity_token(
            application,
            role=role,
            issuer=issuer,
            expires_in=expires_in,
            token_id=token_id,
        ),
    }


def test_login_and_registered_app_are_owner_scoped() -> None:
    with TestClient(app) as owner_client, TestClient(app) as other_client:
        owner_email = _register_user(owner_client)
        application = _register_app(owner_client)
        app_id = application["application"]["id"]

        assert application["integration_token"]
        assert application["warning"].endswith("shown once.")
        assert owner_client.get("/api/apps").json()[0]["id"] == app_id

        _register_user(other_client)
        assert other_client.get(f"/api/apps/{app_id}/events").status_code == 404
        assert other_client.get("/api/apps").json() == []

        logout = owner_client.post("/api/auth/logout")
        assert logout.status_code == 200
        assert owner_client.get("/api/apps").status_code == 401
        login = owner_client.post(
            "/api/auth/login",
            json={"email": owner_email, "password": "correct horse battery"},
        )
        assert login.status_code == 200
        assert owner_client.get("/api/apps").status_code == 200


def test_application_name_cannot_be_only_whitespace() -> None:
    with TestClient(app) as client:
        _register_user(client)

        response = client.post("/api/apps", json={"name": "   "})

        assert response.status_code == 422


def test_app_tokens_are_stored_as_peppered_hmac_digests(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with TestClient(app) as client:
        _register_user(client)
        application = _register_app(client)
        app_id = application["application"]["id"]
        token = application["integration_token"]
        with database.connection() as conn:
            row = conn.execute(
                "SELECT token_hash FROM aegis_apps WHERE id = %s",
                (app_id,),
            ).fetchone()

        assert row is not None
        assert row["token_hash"] == database.hash_app_token(token)
        assert row["token_hash"] != token
        monkeypatch.delenv("AEGIS_TOKEN_PEPPER")
        unauthorized = client.get(
            "/api/integration/context",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert unauthorized.status_code == 503
        assert token not in unauthorized.text


def test_blocked_action_creates_incident_and_red_verified_blue_proposal() -> None:
    with TestClient(app) as client:
        _register_user(client)
        application = _register_app(client)
        app_id = application["application"]["id"]

        authorization = client.post(
            "/api/integration/authorize",
            headers=_identity_headers(application),
            json={
                "tool": "send_email",
                "role": "employee",
                "arguments": {
                    "to": "reviewer@outside.test",
                    "subject": "Compliance",
                    "body": "Sensitive data stays out of stored events.",
                    "metadata": {
                        "password": "nested-password",
                        "access_token": "nested-token",
                        "safe_label": "keep-this-label",
                    },
                },
            },
        )
        assert authorization.status_code == 200
        result = authorization.json()
        assert result["allowed"] is False
        assert result["incident"]["status"] == "contained"
        assert result["patch_proposal"]["status"] == "pending"
        verification = result["patch_proposal"]["patch"]["red_verification"]
        assert verification["summary"] == {
            "attacks_blocked": 12,
            "attacks_total": 12,
            "benign_passed": 3,
            "benign_total": 3,
            "passed": True,
        }
        assert verification["adaptive"]["summary"] == {
            "attacks_passed": 4,
            "attacks_total": 4,
            "benign_passed": 1,
            "benign_total": 1,
            "passed": True,
        }
        assert verification["adaptive"]["counterfactual"]["effect"] == "already_blocked"
        assert [step["step"] for step in result["blue_analysis"]] == [
            "Observe",
            "Map to policy",
            "Propose",
            "Human review",
        ]

        history = client.get(f"/api/apps/{app_id}/events").json()
        incidents = client.get(f"/api/apps/{app_id}/incidents").json()
        assert len(history) == 1
        assert len(incidents) == 1
        assert history[0]["arguments"]["subject"] == "[REDACTED]"
        assert history[0]["arguments"]["body"] == "[REDACTED]"
        assert history[0]["arguments"]["metadata"] == {
            "password": "[REDACTED]",
            "access_token": "[REDACTED]",
            "safe_label": "keep-this-label",
        }
        assert "Sensitive data stays out" not in str(history)
        assert "nested-password" not in str(history)
        assert "nested-token" not in str(history)

        proposal_id = result["patch_proposal"]["id"]
        approved = client.post(
            f"/api/apps/{app_id}/patches/{proposal_id}/decision",
            json={"approved": True},
        )
        assert approved.status_code == 200
        assert approved.json()["status"] == "approved"

        denied_again = client.post(
            "/api/integration/authorize",
            headers=_identity_headers(application),
            json={
                "tool": "send_email",
                "role": "employee",
                "arguments": {
                    "to": "reviewer@outside.test",
                    "subject": "Follow-up",
                    "body": "No private content",
                },
            },
        )
        assert denied_again.json()["allowed"] is False
        assert "blocked by active policy" in denied_again.json()["reason"]
        assert len(client.get(f"/api/apps/{app_id}/events").json()) == 2
        assert len(client.get(f"/api/apps/{app_id}/runs").json()) >= 1


def test_rejected_proposal_does_not_change_active_policy() -> None:
    with TestClient(app) as client:
        _register_user(client)
        application = _register_app(client)
        app_id = application["application"]["id"]
        owner_id = client.get("/api/auth/me").json()["id"]
        initial_policy = database.get_owned_app(owner_id, app_id)["active_policy"]
        response = client.post(
            "/api/integration/authorize",
            headers=_identity_headers(application),
            json={
                "tool": "send_email",
                "role": "employee",
                "arguments": {
                    "to": "reviewer@outside.test",
                    "subject": "Compliance",
                    "body": "Synthetic test data",
                },
            },
        )
        proposal_id = response.json()["patch_proposal"]["id"]

        rejected = client.post(
            f"/api/apps/{app_id}/patches/{proposal_id}/decision",
            json={"approved": False},
        )

        assert rejected.status_code == 200
        assert rejected.json()["status"] == "rejected"
        assert database.get_owned_app(owner_id, app_id)["active_policy"] == initial_policy
        assert client.post(
            f"/api/apps/{app_id}/patches/{proposal_id}/decision",
            json={"approved": True},
        ).status_code == 404


def test_red_rejects_blue_candidate_that_blocks_valid_vendor() -> None:
    with TestClient(app) as client:
        _register_user(client)
        application = _register_app(client)
        app_id = application["application"]["id"]

        response = client.post(
            "/api/integration/authorize",
            headers=_identity_headers(application),
            json={
                "tool": "pay_invoice",
                "role": "employee",
                "arguments": {
                    "vendor": "Acme Supplies",
                    "amount": 400,
                    "invoice_id": "4471",
                },
            },
        )

        assert response.status_code == 200
        result = response.json()
        assert result["allowed"] is False
        assert result["patch_proposal"] is None
        assert result["red_verification"]["summary"]["passed"] is False
        failing_probe = next(
            item
            for item in result["red_verification"]["adaptive"]["results"]
            if item["id"] == "adaptive-vendor-same-vendor-admin-control"
        )
        assert failing_probe["passed"] is False
        assert failing_probe["baseline_decision"] == "allowed"
        run = client.get(f"/api/apps/{app_id}/runs").json()[0]
        assert run["status"] == "failed"
        assert any(
            item["id"] == "adaptive-vendor-same-vendor-admin-control"
            for item in run["summary"]["adaptive_results"]
        )


def test_registered_policy_red_suite_has_twelve_attacks_and_three_benign_checks() -> None:
    with TestClient(app) as client:
        _register_user(client)
        application = _register_app(client)
        app_id = application["application"]["id"]

        response = client.post(f"/api/apps/{app_id}/red/verify")

        assert response.status_code == 200
        assert response.json()["summary"] == {
            "attacks_blocked": 12,
            "attacks_total": 12,
            "benign_passed": 3,
            "benign_total": 3,
            "passed": True,
        }
        assert len(response.json()["results"]) == 15
        assert client.get(f"/api/apps/{app_id}/events").json() == []
        assert len(client.get(f"/api/apps/{app_id}/runs").json()) == 1


def test_integration_requires_valid_application_token() -> None:
    with TestClient(app) as client:
        response = client.post(
            "/api/integration/authorize",
            headers={"Authorization": "Bearer not-a-real-token"},
            json={
                "tool": "send_email",
                "role": "employee",
                "arguments": {"to": "x", "subject": "x", "body": "x"},
            },
        )
        assert response.status_code == 401


def test_authorization_uses_verified_role_and_records_mismatch() -> None:
    with TestClient(app) as client:
        _register_user(client)
        application = _register_app(client)
        app_id = application["application"]["id"]

        response = client.post(
            "/api/integration/authorize",
            headers=_identity_headers(application, role="viewer"),
            json={
                "tool": "pay_invoice",
                "role": "finance_admin",
                "arguments": {
                    "vendor": "Acme Supplies",
                    "amount": 25,
                    "invoice_id": "TEST-ROLE-MISMATCH",
                },
            },
        )

        assert response.status_code == 200
        assert response.json()["allowed"] is False
        assert response.json()["reason"] == "payment requires finance_admin"
        assert response.json()["verified_role"] == "viewer"
        assert response.json()["role_mismatch"] is True
        event = client.get(
            f"/api/apps/{app_id}/events"
        ).json()[0]
        assert event["verified_user_id"] == "test-user-1"
        assert event["role"] == "viewer"
        assert event["identity_status"] == "valid"
        assert event["role_mismatch"] is True


def test_non_string_body_role_is_ignored_and_flagged() -> None:
    with TestClient(app) as client:
        _register_user(client)
        application = _register_app(client)
        app_id = application["application"]["id"]

        response = client.post(
            "/api/integration/authorize",
            headers=_identity_headers(application, role="employee"),
            json={
                "tool": "read_inbox",
                "role": {"role": "finance_admin"},
                "arguments": {},
            },
        )

        assert response.status_code == 200
        assert response.json()["allowed"] is True
        assert response.json()["verified_role"] == "employee"
        assert response.json()["role_mismatch"] is True
        event = client.get(f"/api/apps/{app_id}/events").json()[0]
        assert event["role"] == "employee"
        assert event["role_mismatch"] is True


def test_missing_identity_is_denied_and_recorded_without_role_fallback() -> None:
    with TestClient(app) as client:
        _register_user(client)
        application = _register_app(client)
        app_id = application["application"]["id"]
        response = client.post(
            "/api/integration/authorize",
            headers={"Authorization": f"Bearer {application['integration_token']}"},
            json={
                "tool": "pay_invoice",
                "role": "finance_admin",
                "arguments": {
                    "vendor": "Acme Supplies",
                    "amount": 25,
                    "invoice_id": "TEST-MISSING-IDENTITY",
                },
            },
        )

        assert response.status_code == 200
        assert response.json()["allowed"] is False
        assert response.json()["reason"] == "missing_identity"
        assert response.json()["reason_code"] == "missing_identity"
        assert response.json()["identity_status"] == "missing_identity"
        event = client.get(f"/api/apps/{app_id}/events").json()[0]
        assert event["role"] == ""
        assert event["verified_user_id"] is None
        assert event["identity_status"] == "missing_identity"


def test_replayed_identity_is_denied_after_first_use() -> None:
    with TestClient(app) as client:
        _register_user(client)
        application = _register_app(client)
        token = _identity_token(application)
        headers = {
            "Authorization": f"Bearer {application['integration_token']}",
            "X-Aegis-Identity": token,
        }
        request = {
            "tool": "read_inbox",
            "role": "employee",
            "arguments": {},
        }

        first = client.post(
            "/api/integration/authorize",
            headers=headers,
            json=request,
        )
        replay = client.post(
            "/api/integration/authorize",
            headers=headers,
            json=request,
        )

        assert first.json()["allowed"] is True
        assert replay.json()["allowed"] is False
        assert replay.json()["reason"] == "replayed"


def test_two_active_identity_keys_work_during_rotation() -> None:
    with TestClient(app) as client:
        _register_user(client)
        application = _register_app(client)
        second_private_key = Ed25519PrivateKey.generate()
        second_public_key = second_private_key.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        second_kid = f"test-{uuid4().hex[:12]}"
        encoded_key = base64.urlsafe_b64encode(second_public_key).decode().rstrip("=")
        registered = client.post(
            f"/api/apps/{application['application']['id']}/identity-keys",
            json={"kid": second_kid, "public_key": encoded_key},
        )
        assert registered.status_code == 200

        old_key_result = client.post(
            "/api/integration/authorize",
            headers=_identity_headers(application),
            json={"tool": "read_inbox", "arguments": {}},
        )
        new_key_token = _identity_token(
            application,
            private_key=second_private_key,
            kid=second_kid,
        )
        new_key_result = client.post(
            "/api/integration/authorize",
            headers={
                "Authorization": f"Bearer {application['integration_token']}",
                "X-Aegis-Identity": new_key_token,
            },
            json={"tool": "read_inbox", "arguments": {}},
        )

        assert old_key_result.json()["allowed"] is True
        assert new_key_result.json()["allowed"] is True
        deactivated = client.post(
            f"/api/apps/{application['application']['id']}/identity-keys/"
            f"{application['_identity_kid']}/deactivate"
        )
        assert deactivated.status_code == 200
        old_key_rejected = client.post(
            "/api/integration/authorize",
            headers=_identity_headers(application),
            json={"tool": "read_inbox", "arguments": {}},
        )
        assert old_key_rejected.json()["reason"] == "unknown_kid"

        with database.connection() as conn:
            audit_rows = conn.execute(
                """
                SELECT actor_id, action, created_at
                FROM aegis_security_audit
                WHERE app_id = %s
                ORDER BY created_at
                """,
                (application["application"]["id"],),
            ).fetchall()
        assert [row["action"] for row in audit_rows] == [
            "identity_key_added",
            "identity_key_added",
            "identity_key_deactivated",
        ]
        assert all(row["actor_id"] and row["created_at"] for row in audit_rows)


@pytest.mark.parametrize(
    "reason",
    ["bad_signature", "unknown_kid", "expired", "wrong_issuer", "invalid_claims"],
)
def test_identity_failures_are_returned_as_distinct_reasons(reason: str) -> None:
    with TestClient(app) as client:
        _register_user(client)
        application = _register_app(client)
        app_id = application["application"]["id"]
        private_key = application["_identity_private_key"]
        kid = application["_identity_kid"]
        now = int(time.time())
        claims = {
            "iss": app_id,
            "sub": "test-user-1",
            "role": "employee",
            "aud": "aegis",
            "iat": now,
            "exp": now + 120,
            "jti": uuid4().hex,
        }
        signer = private_key
        token_kid = kid
        if reason == "bad_signature":
            signer = Ed25519PrivateKey.generate()
        elif reason == "unknown_kid":
            signer = Ed25519PrivateKey.generate()
            token_kid = "unregistered-kid"
        elif reason == "expired":
            claims["iat"] = now - 600
            claims["exp"] = now - 480
        elif reason == "wrong_issuer":
            claims["iss"] = "different-app"
        elif reason == "invalid_claims":
            claims["role"] = "owner"
        identity_token = jwt.encode(
            claims,
            signer,
            algorithm="EdDSA",
            headers={"kid": token_kid},
        )

        response = client.post(
            "/api/integration/authorize",
            headers={
                "Authorization": f"Bearer {application['integration_token']}",
                "X-Aegis-Identity": identity_token,
            },
            json={"tool": "read_inbox", "arguments": {}},
        )

        assert response.status_code == 200
        assert response.json()["allowed"] is False
        assert response.json()["reason"] == reason
        assert response.json()["reason_code"] == reason
        assert response.json()["identity_status"] == reason
        event = client.get(f"/api/apps/{app_id}/events").json()[0]
        assert event["identity_status"] == reason


def test_changing_signed_role_without_resigning_is_denied() -> None:
    with TestClient(app) as client:
        _register_user(client)
        application = _register_app(client)
        valid_token = _identity_token(application, role="viewer")
        header_part, payload_part, signature_part = valid_token.split(".")
        padded_payload = payload_part + "=" * (-len(payload_part) % 4)
        claims = json.loads(base64.urlsafe_b64decode(padded_payload))
        claims["role"] = "finance_admin"
        changed_payload = (
            base64.urlsafe_b64encode(
                json.dumps(claims, separators=(",", ":")).encode()
            )
            .decode()
            .rstrip("=")
        )
        forged_token = f"{header_part}.{changed_payload}.{signature_part}"

        response = client.post(
            "/api/integration/authorize",
            headers={
                "Authorization": f"Bearer {application['integration_token']}",
                "X-Aegis-Identity": forged_token,
            },
            json={
                "tool": "pay_invoice",
                "role": "finance_admin",
                "arguments": {
                    "vendor": "Acme Supplies",
                    "amount": 25,
                    "invoice_id": "FORGED-ROLE",
                },
            },
        )

        assert response.json()["allowed"] is False
        assert response.json()["reason"] == "bad_signature"


def test_app_token_rotation_revocation_and_security_audit() -> None:
    with TestClient(app) as client:
        _register_user(client)
        application = _register_app(client)
        app_id = application["application"]["id"]
        old_token = application["integration_token"]
        old_identity = _identity_token(application)

        rotated = client.post(f"/api/apps/{app_id}/token/rotate")

        assert rotated.status_code == 200
        new_token = rotated.json()["integration_token"]
        assert new_token != old_token
        assert rotated.json()["application"]["token_prefix"] == new_token[:12]
        assert rotated.json()["application"]["token_revoked"] is False
        old_request = client.post(
            "/api/integration/authorize",
            headers={
                "Authorization": f"Bearer {old_token}",
                "X-Aegis-Identity": old_identity,
            },
            json={"tool": "read_inbox", "arguments": {}},
        )
        new_request = client.post(
            "/api/integration/authorize",
            headers={
                "Authorization": f"Bearer {new_token}",
                "X-Aegis-Identity": _identity_token(application),
            },
            json={"tool": "read_inbox", "arguments": {}},
        )
        assert old_request.status_code == 401
        assert new_request.json()["allowed"] is True
        assert client.get("/api/apps").json()[0]["token_last_used_at"] is not None

        revoked = client.post(f"/api/apps/{app_id}/token/revoke")
        assert revoked.json()["status"] == "revoked"
        rejected_after_revoke = client.post(
            "/api/integration/authorize",
            headers={
                "Authorization": f"Bearer {new_token}",
                "X-Aegis-Identity": _identity_token(application),
            },
            json={"tool": "read_inbox", "arguments": {}},
        )
        assert rejected_after_revoke.status_code == 401

        with database.connection() as conn:
            audit_rows = conn.execute(
                """
                SELECT actor_label, action, details::text AS details, created_at
                FROM aegis_security_audit
                WHERE app_id = %s
                ORDER BY created_at
                """,
                (app_id,),
            ).fetchall()
        assert [row["action"] for row in audit_rows] == [
            "identity_key_added",
            "app_token_rotated",
            "app_token_revoked",
        ]
        assert all(row["actor_label"] for row in audit_rows)
        assert all(row["created_at"] is not None for row in audit_rows)
        audit_text = str(audit_rows)
        assert old_token not in audit_text
        assert new_token not in audit_text


def test_existing_app_token_is_invalidated_by_migration() -> None:
    with TestClient(app) as client:
        _register_user(client)
        application = _register_app(client)
        app_id = application["application"]["id"]
        legacy_token = application["integration_token"]
        with database.connection() as conn:
            conn.execute(
                "DELETE FROM aegis_schema_migrations WHERE version = %s",
                ("2026-identity-token-lifecycle",),
            )
            conn.execute(
                """
                UPDATE aegis_apps SET token_prefix = NULL, token_revoked = false,
                    token_hash = %s WHERE id = %s
                """,
                (legacy_token, app_id),
            )

        database.initialize()

        response = client.post(
            "/api/integration/authorize",
            headers={
                "Authorization": f"Bearer {legacy_token}",
                "X-Aegis-Identity": _identity_token(application),
            },
            json={"tool": "read_inbox", "arguments": {}},
        )
        assert response.status_code == 401
        owner_id = client.get("/api/auth/me").json()["id"]
        assert database.get_owned_app(owner_id, app_id)["token_revoked"] is True


def test_app_and_identity_tokens_never_appear_in_events_or_audit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    log_path = tmp_path / "events.jsonl"
    monkeypatch.setenv("AEGIS_EVENTS", str(log_path))
    with TestClient(app) as client:
        _register_user(client)
        application = _register_app(client)
        app_token = application["integration_token"]
        identity_token = _identity_token(application)
        response = client.post(
            "/api/integration/authorize",
            headers={
                "Authorization": f"Bearer {app_token}",
                "X-Aegis-Identity": identity_token,
            },
            json={"tool": "read_inbox", "arguments": {}},
        )

        assert response.json()["allowed"] is True
        contents = log_path.read_text(encoding="utf-8")
        assert app_token not in contents
        assert identity_token not in contents


def test_event_api_returns_owner_scoped_append_only_events(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AEGIS_EVENTS", str(tmp_path / "events.jsonl"))
    with TestClient(app) as owner, TestClient(app) as other:
        _register_user(owner)
        application = _register_app(owner)
        app_id = application["application"]["id"]
        response = owner.post(
            "/api/integration/authorize",
            headers=_identity_headers(application),
            json={
                "tool": "read_inbox",
                "role": "employee",
                "arguments": {},
            },
        )
        assert response.status_code == 200
        _register_user(other)

        owner_events = owner.get("/events").json()
        assert [event["type"] for event in owner_events] == [
            "tool_call",
            "decision",
        ]
        assert all(event["data"]["app_id"] == app_id for event in owner_events)
        assert owner.get(
            f"/events?since_seq={owner_events[0]['seq']}"
        ).json() == owner_events[1:]
        assert other.get("/events").json() == []
        with owner.stream("GET", "/events/stream?since_seq=0") as stream:
            chunks = iter(stream.iter_bytes())
            assert b": connected" in next(chunks)
            assert b"tool_call" in next(chunks)
