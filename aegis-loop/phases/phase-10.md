# Phase 10 — Hardening and pitch

## Audit outcome

**Local-demo guardrails pass; the system is not production-ready.**

## What belongs to this phase

- [`../dashboard/api.py`](../dashboard/api.py) binds the server to loopback
  through the documented entry point, constrains hosts/origins/CORS, and
  authenticates app-scoped dashboard WebSocket sessions.
- [`../aegis_loop/auth.py`](../aegis_loop/auth.py) stores password hashes and
  hashed expiring session tokens; app tokens are stored as hashes.
- [`../aegis_loop/database.py`](../aegis_loop/database.py) persists users,
  applications, decisions, incidents, Red runs, and proposals in PostgreSQL.
- [`../aegis_loop/runtime.py`](../aegis_loop/runtime.py) rejects non-loopback
  model URLs.
- [`../../victim-app/aegis_client.py`](../../victim-app/aegis_client.py)
  calls the Aegis authorization API with ambient proxy settings disabled and
  fails closed when configured Aegis is unavailable.
- [`../README.md`](../README.md) describes the local setup and scope.

## Verification

The app-token, owner-isolation, authorization, proposal approval, fail-closed
HTTP client, and browser-origin behavior are covered by tests. Aegis can serve
the separate-process victim connector without importing the adjacent victim
folder; the local adapter checks its presence only when invoked.
Current verification: **46 Aegis tests passed**, **27 victim tests passed**,
Ruff passed in both repositories, and the dashboard production build passed.
A live separate-process check verified that Aegis denied an outbound action
before fake-tool execution and durably recorded its event, incident, Red run,
and pending proposal.

## Remaining risks and exclusions

The service has basic account/app ownership and PostgreSQL persistence, but no
TLS setup, MFA, rate limiting, token rotation/revocation UI, or external
identity provider. The victim supplies its role claim; the app token does not
authenticate an end user. Red is a deterministic policy suite, not a proof of
security. Binding to loopback and passing these checks are not production
deployment controls. Do not expose the dashboard or connect it to real tools,
credentials, user data, or company data.
