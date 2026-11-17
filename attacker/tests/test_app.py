from typing import Any, Self

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

import app as attacker_app

client = TestClient(attacker_app.app)


class FakeResponse:
    def __init__(self, allowed: bool, reason: str = "synthetic test result"):
        self.status_code = 200
        self._allowed = allowed
        self._reason = reason

    def json(self) -> dict[str, Any]:
        return {
            "allowed": self._allowed,
            "reason": self._reason,
            "reason_code": self._reason,
            "incident": {"event_id": "test-incident"} if not self._allowed else None,
            "patch_proposal": {"status": "pending"} if not self._allowed else None,
        }


class FakeContextResponse(FakeResponse):
    def json(self) -> dict[str, Any]:
        return {"app_id": "test-app-id"}


class FakeClient:
    def __init__(self):
        self.calls: list[tuple[str, dict[str, Any], dict[str, str]]] = []

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def get(self, url: str, *, headers: dict[str, str]) -> FakeContextResponse:
        assert url == "http://127.0.0.1:8000/api/integration/context"
        assert headers.get("Authorization", "").startswith("Bearer ")
        return FakeContextResponse(allowed=True)

    def post(
        self,
        url: str,
        *,
        headers: dict[str, str],
        json: dict[str, Any],
    ) -> FakeResponse:
        self.calls.append((url, json, headers))
        position = len(self.calls)
        if position <= 5:
            return FakeResponse(
                allowed=position == 5,
                reason="synthetic policy result",
            )
        if position == 6:
            return FakeResponse(allowed=True, reason="allowed")
        reasons = (
            "missing_identity",
            "bad_signature",
            "unknown_kid",
            "expired",
            "replayed",
            "wrong_issuer",
        )
        return FakeResponse(allowed=False, reason=reasons[position - 7])


def test_suite_uses_fixed_local_authorization_cases_and_does_not_return_token(
    monkeypatch,
) -> None:
    fake_client = FakeClient()
    signer = Ed25519PrivateKey.generate()

    def fake_httpx_client(**kwargs: Any) -> FakeClient:
        assert kwargs == {"timeout": 20, "trust_env": False}
        return fake_client

    monkeypatch.setattr(attacker_app.httpx, "Client", fake_httpx_client)
    monkeypatch.setattr(
        attacker_app,
        "_load_test_signer",
        lambda: (signer, "registered-test-kid"),
    )
    token = "synthetic-test-token-never-return-this"

    response = client.post(
        "/api/run",
        json={"aegis_url": "http://127.0.0.1:8000", "app_token": token},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 11
    assert data["passed_count"] == 11
    assert data["passed"] is True
    assert all(result["passed"] for result in data["results"])
    assert all(
        result["side_effect"] == "authorization only; no victim tool was executed"
        for result in data["results"]
    )
    assert token not in response.text
    assert all(
        url == "http://127.0.0.1:8000/api/integration/authorize"
        and headers.get("Authorization") == f"Bearer {token}"
        for url, _, headers in fake_client.calls
    )
    assert len(fake_client.calls) == 12
    assert fake_client.calls[2][1]["arguments"]["to"] == "aegis-test@outside.invalid"
    assert fake_client.calls[2][1]["tool"] == "send_email"
    assert all("role" not in body for _, body, _ in fake_client.calls[:5])
    assert all(
        headers.get("X-Aegis-Identity")
        for _, _, headers in fake_client.calls[:6]
    )
    assert "X-Aegis-Identity" not in fake_client.calls[6][2]
    assert [result["reason"] for result in data["results"][5:]] == [
        "missing_identity",
        "bad_signature",
        "unknown_kid",
        "expired",
        "replayed",
        "wrong_issuer",
    ]


def test_remote_aegis_targets_are_rejected_before_any_request() -> None:
    response = client.post(
        "/api/run",
        json={
            "aegis_url": "https://example.com",
            "app_token": "synthetic-test-token-never-used",
        },
    )

    assert response.status_code == 422
    assert "Only the local Aegis service" in response.text


def test_non_local_browser_origin_is_rejected() -> None:
    response = client.get("/", headers={"Origin": "https://example.com"})

    assert response.status_code == 403
