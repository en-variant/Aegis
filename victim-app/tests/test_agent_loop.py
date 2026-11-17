import json
from typing import Any, Self

import pytest

from agent import loop
from agent.identity import AuthenticatedUser


class _FakeResponse:
    def raise_for_status(self) -> None:
        return None

    def json(self) -> dict[str, Any]:
        return {
            "message": {
                "role": "assistant",
                "content": "Synthetic answer",
            }
        }


class _FakeClient:
    def __init__(self) -> None:
        self.payload: dict[str, Any] | None = None

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def post(self, _url: str, *, json: dict[str, Any]) -> _FakeResponse:
        self.payload = {**json, "messages": list(json["messages"])}
        return _FakeResponse()


def test_agent_sends_system_prompt_with_first_model_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_client = _FakeClient()
    monkeypatch.setattr(loop.httpx, "Client", lambda **_kwargs: fake_client)
    monkeypatch.setattr(loop, "tool_specs", list)

    answer, calls = loop.run_agent(
        "Summarize invoice 4471",
        user=AuthenticatedUser(user_id="bob", role="viewer"),
    )

    assert answer == "Synthetic answer"
    assert calls == []
    assert fake_client.payload is not None
    assert fake_client.payload["messages"] == [
        {"role": "system", "content": loop.SYSTEM_PROMPT},
        {"role": "user", "content": "Summarize invoice 4471"},
    ]


def test_llm_tool_schemas_have_no_identity_or_role_fields() -> None:
    serialized = json.dumps(loop.tool_specs()).casefold()

    assert '"role"' not in serialized
    assert '"identity"' not in serialized
    assert "private key" not in serialized
    assert "jwt" not in serialized
