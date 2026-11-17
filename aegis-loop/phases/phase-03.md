# Phase 3 — Event log and guard hook

## Audit outcome

**Pass for the local adapter and registered-app HTTP integration.**

**Supplied-spec conformance: partial.** The typed append-only JSONL event
foundation and authenticated owner-scoped REST/SSE endpoints are now present,
but this phase does not yet have the spec's shared victim `guarded_call`,
complete session/context provenance model, approval flow, or full event
coverage. See [`../SPEC.md`](../SPEC.md).

## What belongs to this phase

- [`../aegis_loop/runtime.py`](../aegis_loop/runtime.py) wraps the victim's
  generic tool-call seam without making the victim import Aegis.
- [`../aegis_loop/events.py`](../aegis_loop/events.py) owns the local event
  stream; [`../aegis_loop/database.py`](../aegis_loop/database.py) persists
  registered-app events and incidents in PostgreSQL.
- [`../dashboard/applications_api.py`](../dashboard/applications_api.py)
  receives the victim's HTTP tool authorization request and records the
  sanitized decision before the victim executes the tool.
- [`../aegis_loop/event_contract.py`](../aegis_loop/event_contract.py) validates
  the versioned envelope and required fields for declared event types;
  [`../aegis_loop/event_log.py`](../aegis_loop/event_log.py) appends JSONL
  records and recovers the sequence after process restart.
- [`../dashboard/api.py`](../dashboard/api.py) exposes authenticated
  owner-filtered `GET /events` and `GET /events/stream` (SSE) endpoints.
- The victim-side seam is in
  [`../../victim-app/agent/loop.py`](../../victim-app/agent/loop.py).

## Verification

The test suites check that denied actions create persistent incidents,
subscribers receive local events, the HTTP client fails closed, app data stays
owner-scoped, and secret-like argument content is redacted before persistence.
The victim remains free of Aegis policy and event-storage code.

The separate-process smoke test confirmed the victim's email tool was denied
before execution, while its sanitized event and contained incident appeared in
the registered app's PostgreSQL-backed history.
Focused tests also cover event sequence continuation, malformed-log errors,
required event data, owner filtering, SSE event delivery, and Red sandbox
refusal.

## Limits

The legacy local adapter patches a Python module function in-process and
shares the victim's mutable fake data. The separate-process HTTP connector is
also a local demonstration protocol; it is not a production deployment
monitor. PostgreSQL remains the registered-app source of truth; the React UI
does not yet use the JSONL stream for replay or as its only data source.
