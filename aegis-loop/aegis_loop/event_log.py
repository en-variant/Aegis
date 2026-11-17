import os
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from aegis_loop.config import ROOT
from aegis_loop.event_contract import EventActor, EventEnvelope, EventType

DEFAULT_EVENTS_PATH = ROOT / "runs" / "events.jsonl"
_lock = threading.Lock()
_sequence: int | None = None
_sequence_path: Path | None = None


def events_path() -> Path:
    configured = os.environ.get("AEGIS_EVENTS")
    path = Path(configured) if configured else DEFAULT_EVENTS_PATH
    if not path.is_absolute():
        raise ValueError("AEGIS_EVENTS must be an absolute path")
    return path


def _last_sequence(path: Path) -> int:
    if not path.exists():
        return 0
    last_line = ""
    with path.open(encoding="utf-8") as source:
        for line in source:
            if line.strip():
                last_line = line
    if not last_line:
        return 0
    try:
        return EventEnvelope.model_validate_json(last_line).seq
    except ValueError as exc:
        raise RuntimeError(f"Cannot resume malformed Aegis event log: {path}") from exc


def append_event(
    *,
    actor: EventActor,
    event_type: EventType,
    data: dict[str, Any],
    run_id: str = "live",
    session_id: str | None = None,
    path: str | None = None,
) -> EventEnvelope:
    global _sequence, _sequence_path
    log_path = events_path()
    with _lock:
        if _sequence is None or _sequence_path != log_path:
            _sequence = _last_sequence(log_path)
            _sequence_path = log_path
        event = EventEnvelope(
            seq=_sequence + 1,
            ts=datetime.now(UTC).isoformat(timespec="milliseconds").replace(
                "+00:00", "Z"
            ),
            actor=actor,
            type=event_type,
            run_id=run_id,
            session_id=session_id,
            path=path,
            data=data,
        )
        serialized = event.model_dump_json()
        log_path.parent.mkdir(parents=True, exist_ok=True)
        with log_path.open("a", encoding="utf-8") as output:
            output.write(serialized + "\n")
            output.flush()
        _sequence = event.seq
    return event


def read_events(*, since_seq: int = 0, limit: int = 500) -> list[EventEnvelope]:
    if since_seq < 0:
        raise ValueError("since_seq cannot be negative")
    if limit < 1:
        raise ValueError("limit must be positive")
    path = events_path()
    if not path.exists():
        return []
    events: list[EventEnvelope] = []
    with path.open(encoding="utf-8") as source:
        for line in source:
            if not line.strip():
                continue
            event = EventEnvelope.model_validate_json(line)
            if event.seq > since_seq:
                events.append(event)
                if len(events) >= limit:
                    break
    return events


def archive_events() -> Path | None:
    """Archive, rather than truncate, the event stream for an explicit reset."""
    global _sequence, _sequence_path
    with _lock:
        path = events_path()
        if not path.exists() or path.stat().st_size == 0:
            _sequence = 0
            _sequence_path = path
            return None
        archive_dir = path.parent / "archive"
        archive_dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
        archive_path = archive_dir / f"events-{stamp}.jsonl"
        path.replace(archive_path)
        _sequence = 0
        _sequence_path = path
        return archive_path


def owner_visible(event: EventEnvelope, app_ids: set[str]) -> bool:
    event_app_id = event.data.get("app_id")
    return event_app_id is not None and str(event_app_id) in app_ids


def event_json(event: EventEnvelope) -> dict[str, Any]:
    return event.model_dump(mode="json")
