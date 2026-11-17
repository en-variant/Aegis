# Phase 7 — Live detection and containment

## Audit outcome

**Pass for local detection plus the owner-scoped PostgreSQL HTTP service.**

**Supplied-spec conformance: partial.** Live policy denials become persisted
contained incidents, but detector coverage, session quarantine/release, the
specified incident report, and patch/verify lifecycle are not implemented. See
[`../SPEC.md`](../SPEC.md).

## What belongs to this phase

- [`../dashboard/applications_api.py`](../dashboard/applications_api.py)
  authenticates a registered victim app, evaluates its active policy, persists
  sanitized tool events, and records denied calls as contained incidents.
- [`../aegis_loop/database.py`](../aegis_loop/database.py) stores app-scoped
  history, Red runs, probe results, and proposals in PostgreSQL.
- [`../dashboard/api.py`](../dashboard/api.py) scopes the `/api/live` WebSocket
  to a signed-in user and an application they own.
- The same API provides authenticated owner-scoped REST and SSE reads from the
  append-only JSONL audit stream; the existing UI still uses its PostgreSQL
  history and WebSocket path.

## Verification

Dashboard API tests exercise app-scoped tool events, the authenticated WebSocket,
and cross-user rejection. PostgreSQL integration tests verify durable history,
ownership isolation, and sanitized event contents.
The live service health endpoint reports
`{"status":"ok","database":"connected"}`. The separate-process smoke test
confirmed a denied victim action was persisted as an event and contained
incident and remained available in app history.

## Limits

PostgreSQL history persists across proof and Red runs and is scoped by owner and
app. The local JSONL stream remains for the legacy local runtime. This is still
a demo service, not a production deployment. Avoid running Aegis and victim
test suites concurrently: local adapter tests share and reset synthetic target
data.
