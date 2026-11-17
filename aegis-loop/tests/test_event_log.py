import json
from pathlib import Path

import pytest

from aegis_loop import event_log
from aegis_loop.event_contract import EventEnvelope


def _reset_sequence() -> None:
    event_log._sequence = None
    event_log._sequence_path = None


def test_event_log_appends_typed_events_with_increasing_sequence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "events.jsonl"
    monkeypatch.setenv("AEGIS_EVENTS", str(path))
    _reset_sequence()

    first = event_log.append_event(
        actor="victim",
        event_type="tool_call",
        data={
            "app_id": "app-1",
            "tool": "read_inbox",
            "args": {},
            "kind": "source",
            "channel": None,
        },
    )
    second = event_log.append_event(
        actor="guard",
        event_type="decision",
        data={
            "app_id": "app-1",
            "tool": "read_inbox",
            "verdict": "allow",
            "rule_id": None,
            "explain": "No matching policy rule.",
        },
    )

    assert first.seq == 1
    assert second.seq == 2
    lines = path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    assert [json.loads(line)["seq"] for line in lines] == [1, 2]
    assert event_log.read_events(since_seq=1)[0].type == "decision"


def test_event_sequence_resumes_from_last_persisted_line(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "events.jsonl"
    monkeypatch.setenv("AEGIS_EVENTS", str(path))
    _reset_sequence()
    event_log.append_event(
        actor="system",
        event_type="run_started",
        data={"kind": "demo", "params": {}},
    )

    _reset_sequence()
    resumed = event_log.append_event(
        actor="system",
        event_type="run_finished",
        data={"kind": "demo", "status": "ok", "summary": {}},
    )

    assert resumed.seq == 2


def test_events_path_must_be_absolute(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AEGIS_EVENTS", "runs/events.jsonl")

    with pytest.raises(ValueError, match="absolute path"):
        event_log.events_path()


def test_malformed_existing_event_log_fails_explicitly(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "events.jsonl"
    path.write_text("{not-json}\n", encoding="utf-8")
    monkeypatch.setenv("AEGIS_EVENTS", str(path))
    _reset_sequence()

    with pytest.raises(RuntimeError, match="malformed Aegis event log"):
        event_log.append_event(
            actor="system",
            event_type="run_started",
            data={"kind": "demo", "params": {}},
        )


def test_event_contract_rejects_missing_type_specific_data() -> None:
    with pytest.raises(ValueError, match="missing required data fields"):
        EventEnvelope(
            seq=1,
            ts="2026-11-20T10:14:03.120Z",
            actor="victim",
            type="tool_call",
            run_id="r-0001",
            data={"tool": "read_inbox"},
        )
