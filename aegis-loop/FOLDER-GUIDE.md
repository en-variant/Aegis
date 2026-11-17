# Folder and code ownership

This repository is the Aegis Loop security product. The adjacent
[`../victim-app/`](../victim-app/) is a separate Git repository and contains
only the intentionally vulnerable fake finance assistant.

## Aegis Loop folders

| Path | What belongs here |
|---|---|
| [`aegis_loop/`](./aegis_loop/) | Core Aegis security package: local target adapter, registered-app policy checks, Red/Blue logic, authentication helpers, PostgreSQL persistence, local events, and configuration. |
| [`dashboard/`](./dashboard/) | FastAPI authentication, owner-scoped app/history/proposal APIs, HTTP integration endpoint, authenticated app-scoped WebSocket, and API tests. |
| [`web/`](./web/) | React, Tailwind, and Three.js local dashboard frontend. |
| [`tests/`](./tests/) | Aegis policy, Red, proof-loop, multi-user PostgreSQL API, runtime-boundary, and test-selection checks. |
| [`proofs/`](./proofs/) | Sanitized proof-loop reports showing Red blocks and benign regressions. |
| [`data/`](./data/) | Runtime-only event and incident logs; ignored by Git and owned by Aegis. |
| [`phases/`](./phases/) | Phase 1–10 audit records with implementation links, test results, and remaining limitations. |
| [`PHASE-LOG.md`](./PHASE-LOG.md) | Phase-by-phase completion notes and links to the implementation folders. |

## Aegis source entry points

- [`aegis_loop/runtime.py`](./aegis_loop/runtime.py) loads the sibling target
  and wraps its generic `call_tool` seam. It is the only integration adapter.
- [`aegis_loop/policy.py`](./aegis_loop/policy.py) enforces authorization,
  approved vendors, valid payment values, outbound recipient restrictions, and
  sensitive-data egress checks.
- [`aegis_loop/events.py`](./aegis_loop/events.py) records sanitized tool
  events, contained incidents, and local live subscriber messages. Multi-user
  application history is persisted by [`aegis_loop/database.py`](./aegis_loop/database.py).
- [`aegis_loop/auth.py`](./aegis_loop/auth.py) handles password hashing and
  database-backed browser sessions.
- [`aegis_loop/blue_agent.py`](./aegis_loop/blue_agent.py) creates supported
  policy proposals; [`aegis_loop/red_agent.py`](./aegis_loop/red_agent.py)
  checks candidates with fixed attack and benign cases.
- [`red_agent.py`](./red_agent.py) runs fixed local probes and the optional
  poisoned-invoice model probe.
- [`proof_loop.py`](./proof_loop.py) executes attacks plus benign checks and
  writes evidence.
- [`dashboard/api.py`](./dashboard/api.py) serves the account/app APIs,
  PostgreSQL health check, authenticated app-scoped WebSocket, and built
  frontend. [`dashboard/applications_api.py`](./dashboard/applications_api.py)
  owns application registration, history, HTTP tool authorization, Red
  verification, and human patch decisions.
- [`dashboard/workspace.py`](./dashboard/workspace.py) confines editing to the
  explicit Aegis source allowlist and implements preview/approval/apply.
- [`dashboard/validation.py`](./dashboard/validation.py) runs only the fixed
  pytest/Ruff selector and reloads Aegis policy after a successful check.
- [`run_changed_tests.py`](./run_changed_tests.py) maps changed Aegis files to
  targeted checks and builds the frontend when needed.

## Victim app ownership

The target's [`../victim-app/agent/`](../victim-app/agent/) owns its model loop
and vulnerable finance prompt. [`../victim-app/tools/`](../victim-app/tools/)
owns the seven fake finance tools. [`../victim-app/data/`](../victim-app/data/)
and [`../victim-app/pristine/`](../victim-app/pristine/) hold synthetic target
data. [`../victim-app/tests/`](../victim-app/tests/) holds target-side benign
and standalone tool tests.

There must be no Aegis policy, event logger, Red Agent, proof runner, dashboard,
or editor implementation under `victim-app/`. The target remains testable
without Aegis; local demonstrations use the runtime adapter, while a separately
running target uses [`../victim-app/aegis_client.py`](../victim-app/aegis_client.py)
to call Aegis over HTTP. The target connector is transport-only and contains no
policy rules.
