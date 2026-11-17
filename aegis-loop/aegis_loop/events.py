import json
import queue
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from aegis_loop.config import DATA_DIR

_subscribers: set[queue.Queue[dict[str, Any]]] = set()
_subscribers_lock = threading.Lock()
_file_lock = threading.Lock()


def _append_jsonl(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with _file_lock, path.open("a", encoding="utf-8") as output:
        output.write(json.dumps(value, sort_keys=True) + "\n")


def log_tool_event(
    *,
    role: str,
    tool_name: str,
    arguments: dict[str, Any],
    result: str,
    allowed: bool,
    reason: str,
    redacted_arguments: dict[str, Any] | None = None,
    redacted_result: str | None = None,
) -> dict[str, Any]:
    event = {
        "event_id": uuid4().hex,
        "timestamp": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "role": role,
        "tool": tool_name,
        "arguments": redacted_arguments if redacted_arguments is not None else arguments,
        "result": redacted_result if redacted_result is not None else result,
        "allowed": allowed,
        "reason": reason,
    }
    _append_jsonl(DATA_DIR / "event_log.jsonl", event)
    incident = record_incident(event)
    publish_event({"type": "tool_event", "event": event, "incident": incident})
    return event


def record_incident(event: dict[str, Any]) -> dict[str, Any] | None:
    if event["allowed"]:
        return None
    incident = {
        "event_id": event["event_id"],
        "timestamp": event["timestamp"],
        "severity": (
            "high"
            if event["tool"] in {"pay_invoice", "send_email", "post_chat"}
            else "medium"
        ),
        "tool": event["tool"],
        "role": event["role"],
        "reason": event["reason"],
        "status": "contained",
        "action": "tool call denied before execution",
    }
    _append_jsonl(DATA_DIR / "incidents.jsonl", incident)
    return incident


def publish_event(message: dict[str, Any]) -> None:
    with _subscribers_lock:
        subscribers = tuple(_subscribers)
    for subscriber in subscribers:
        try:
            subscriber.put_nowait(message)
        except queue.Full:
            try:
                subscriber.get_nowait()
            except queue.Empty:
                pass
            event = message.get("event", {})
            subscriber.put_nowait(
                {"type": "resync_required", "event_id": event.get("event_id")}
            )


def subscribe(maxsize: int = 100) -> queue.Queue[dict[str, Any]]:
    subscriber: queue.Queue[dict[str, Any]] = queue.Queue(maxsize=maxsize)
    with _subscribers_lock:
        _subscribers.add(subscriber)
    return subscriber


def unsubscribe(subscriber: queue.Queue[dict[str, Any]]) -> None:
    with _subscribers_lock:
        _subscribers.discard(subscriber)


def _read_jsonl(name: str) -> list[dict[str, Any]]:
    path = DATA_DIR / name
    if not path.exists():
        return []
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def read_event_log() -> list[dict[str, Any]]:
    return _read_jsonl("event_log.jsonl")


def read_incidents() -> list[dict[str, Any]]:
    return _read_jsonl("incidents.jsonl")


def reset_events() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    for name in ("event_log.jsonl", "incidents.jsonl"):
        (DATA_DIR / name).write_text("", encoding="utf-8")
