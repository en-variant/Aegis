# Phase 9 — Dashboard

## Audit outcome

**Build and app-scoped dashboard/API tests pass.**

**Supplied-spec conformance: partial.** Account-scoped history, incident and
proposal UI, and owner-approved policy activation exceed a basic single-user
demo, but the spec's event-only reducer/replay, exact coverage layout, and
golden-state acceptance are not present. See [`../SPEC.md`](../SPEC.md).

## What belongs to this phase

- [`../web/`](../web/) contains the React dashboard frontend.
- [`../dashboard/`](../dashboard/) contains account and app APIs, the HTTP
  victim integration endpoint, and the authenticated app-scoped WebSocket.
- [`../dashboard/api.py`](../dashboard/api.py) also provides owner-filtered
  JSONL event REST/SSE endpoints; they are not yet the dashboard's source of
  truth.

## Verification

The production dashboard build passes with `npm run build`; the current Aegis
API and persistence suite passes **46 tests**. The UI supports
registration/sign-in, app selection, persistent app history, Red result
inspection, attack-specific Red variants, a Blue play-by-play, and human
approval or rejection of verified policy proposals. The UI distinguishes the
dashboard WebSocket from an actual victim tool call and documents the
poisoned-invoice command.
The local dashboard is running at `http://127.0.0.1:8000` against the local
PostgreSQL database, and its health endpoint confirms the database connection.

## Limits

This is a local demo UI. User sessions and app ownership are enforced by the
server, but TLS, MFA, rate limiting, and deployment-grade token management are
not provided.
