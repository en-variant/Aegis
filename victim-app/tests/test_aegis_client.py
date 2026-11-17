import httpx
import pytest
from aegis_client import authorize_tool
from agent.identity import AuthenticatedUser

USER = AuthenticatedUser(user_id="alice", role="finance_admin")


@pytest.fixture(autouse=True)
def stub_identity_signing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "aegis_client.mint_identity_token",
        lambda _user: "test.signed.jwt",
    )


def test_unconfigured_client_keeps_standalone_victim_behavior(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("AEGIS_URL", raising=False)
    monkeypatch.delenv("AEGIS_APP_TOKEN", raising=False)

    assert (
        authorize_tool(
            tool="read_inbox",
            user=USER,
            arguments={},
            sensitive_context=False,
        )
        is None
    )


def test_partial_configuration_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AEGIS_URL", "http://127.0.0.1:8000")
    monkeypatch.delenv("AEGIS_APP_TOKEN", raising=False)

    with pytest.raises(RuntimeError, match="Set both AEGIS_URL"):
        authorize_tool(
            tool="read_inbox",
            user=USER,
            arguments={},
            sensitive_context=False,
        )


def test_denied_decision_is_returned_without_changing_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AEGIS_URL", "http://127.0.0.1:8000/")
    monkeypatch.setenv("AEGIS_APP_TOKEN", "test-token")
    decision = {"allowed": False, "reason": "blocked by active policy"}
    monkeypatch.setattr(
        "aegis_client.httpx.post",
        lambda *args, **kwargs: httpx.Response(
            200,
            json=decision,
            request=httpx.Request("POST", args[0]),
        ),
    )

    assert (
        authorize_tool(
            tool="send_email",
            user=USER,
            arguments={"to": "external@example.test"},
            sensitive_context=True,
        )
        == decision
    )


def test_invalid_app_token_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AEGIS_URL", "http://127.0.0.1:8000")
    monkeypatch.setenv("AEGIS_APP_TOKEN", "invalid-token")
    monkeypatch.setattr(
        "aegis_client.httpx.post",
        lambda *args, **kwargs: httpx.Response(
            401,
            request=httpx.Request("POST", args[0]),
        ),
    )

    with pytest.raises(RuntimeError, match="rejected the victim application"):
        authorize_tool(
            tool="read_inbox",
            user=USER,
            arguments={},
            sensitive_context=False,
        )


def test_unavailable_aegis_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AEGIS_URL", "http://127.0.0.1:8000")
    monkeypatch.setenv("AEGIS_APP_TOKEN", "test-token")

    def offline(*args: object, **kwargs: object) -> httpx.Response:
        raise httpx.ConnectError("offline")

    monkeypatch.setattr("aegis_client.httpx.post", offline)

    with pytest.raises(RuntimeError, match="tool action was not run"):
        authorize_tool(
            tool="read_inbox",
            user=USER,
            arguments={},
            sensitive_context=False,
        )


def test_successful_request_sends_app_token_and_sensitive_context(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AEGIS_URL", "http://127.0.0.1:8000/")
    monkeypatch.setenv("AEGIS_APP_TOKEN", "test-token")
    observed: dict[str, object] = {}

    def allow(url: str, **kwargs: object) -> httpx.Response:
        observed["url"] = url
        observed.update(kwargs)
        return httpx.Response(
            200,
            json={"allowed": True, "reason": "allow"},
            request=httpx.Request("POST", url),
        )

    monkeypatch.setattr("aegis_client.httpx.post", allow)

    result = authorize_tool(
        tool="send_email",
        user=USER,
        arguments={"to": "billing@acme.example"},
        sensitive_context=True,
    )

    assert result == {"allowed": True, "reason": "allow"}
    assert observed["url"] == "http://127.0.0.1:8000/api/integration/authorize"
    assert observed["headers"]["Authorization"] == "Bearer test-token"
    assert observed["headers"]["X-Aegis-Identity"] == "test.signed.jwt"
    assert "role" not in observed["json"]
    assert observed["json"]["sensitive_context"] is True
    assert observed["trust_env"] is False


def test_malformed_decision_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AEGIS_URL", "http://127.0.0.1:8000")
    monkeypatch.setenv("AEGIS_APP_TOKEN", "test-token")
    monkeypatch.setattr(
        "aegis_client.httpx.post",
        lambda *args, **kwargs: httpx.Response(
            200,
            json={"allowed": "yes", "reason": "allow"},
            request=httpx.Request("POST", args[0]),
        ),
    )

    with pytest.raises(RuntimeError, match="invalid authorization decision"):
        authorize_tool(
            tool="read_inbox",
            user=USER,
            arguments={},
            sensitive_context=False,
        )
