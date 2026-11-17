import asyncio
from pathlib import Path

import pytest

from aegis_loop import database, event_log
from dashboard.api import list_events, stream_events


def _append_tool_event(app_id: str) -> None:
    event_log.append_event(
        actor="victim",
        event_type="tool_call",
        data={
            "app_id": app_id,
            "tool": "read_inbox",
            "args": {},
            "kind": "source",
            "channel": None,
        },
    )


def test_rest_event_listing_filters_by_owner_apps(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AEGIS_EVENTS", str(tmp_path / "events.jsonl"))
    monkeypatch.setattr(event_log, "_sequence", None)
    monkeypatch.setattr(event_log, "_sequence_path", None)
    monkeypatch.setattr(
        database,
        "list_apps",
        lambda owner_id: [{"id": "owned-app"}] if owner_id == "owner-1" else [],
    )
    _append_tool_event("owned-app")
    _append_tool_event("other-app")

    events = list_events({"id": "owner-1"}, since_seq=0, limit=500)

    assert len(events) == 1
    assert events[0]["data"]["app_id"] == "owned-app"


def test_sse_stream_sends_connection_and_owner_visible_events(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AEGIS_EVENTS", str(tmp_path / "events.jsonl"))
    monkeypatch.setattr(event_log, "_sequence", None)
    monkeypatch.setattr(event_log, "_sequence_path", None)
    monkeypatch.setattr(
        database,
        "list_apps",
        lambda _owner_id: [{"id": "owned-app"}],
    )
    _append_tool_event("owned-app")
    _append_tool_event("other-app")
    response = asyncio.run(stream_events({"id": "owner-1"}, since_seq=0))

    async def read_first_visible_event() -> list[str]:
        chunks: list[str] = []
        iterator = response.body_iterator.__aiter__()
        try:
            chunks.append(await iterator.__anext__())
            chunks.append(await iterator.__anext__())
        finally:
            await response.body_iterator.aclose()
        return chunks

    chunks = asyncio.run(read_first_visible_event())
    assert ": connected\n\n" in chunks[0]
    assert '"app_id": "owned-app"' in chunks[1]
    assert "other-app" not in chunks[1]
