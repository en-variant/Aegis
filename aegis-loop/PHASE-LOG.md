# Phase completion log

This log separates the security product from the test target. Phase 1 setup and
notes remain in this repository. The fake application for Phase 2 is in the
separate [`../victim-app/`](../victim-app/) repository. This audit covers
Phases 1–10 only; Phases 11–15 below retain their previously recorded status
and were not re-audited. Individual Phase 1–10 evidence is in
[`phases/`](./phases/). The supplied Complete Build Specification audit is in
[`SPEC.md`](./SPEC.md); it marks every Phase 1–10 as partial where its
acceptance criteria are not fully met.

| Phase | Status | What was built / verified | Code and evidence |
|---|---|---|---|
| 1 — Setup, learning, threat model | Local setup and tool-use verified; personal submission tasks pending | Python/Git/Node and local model were available; the tool call returned 42. Event rules, personal exercises, and submission confirmation remain user-owned. | [`phases/phase-01.md`](./phases/phase-01.md), [`hello_tool.py`](./hello_tool.py), [`PHASE-1-NOTES.md`](./PHASE-1-NOTES.md) |
| 2 — Victim app | 27 tests pass; intentional weaknesses retained | Seven synthetic tools, model-backed benign tasks, and a poisoned-invoice fixture. Live separate-process run confirmed fake admin reads and outbound emails were blocked before fake sinks. | [`phases/phase-02.md`](./phases/phase-02.md), [`../victim-app/agent/`](../victim-app/agent/), [`../victim-app/aegis_client.py`](../victim-app/aegis_client.py), [`../victim-app/tests/`](../victim-app/tests/) |
| 3 — Event log and guard hook | Partial against supplied spec | In addition to PostgreSQL, typed append-only JSONL events, sequence recovery, required-field validation, and owner-scoped REST/SSE endpoints are implemented; the shared victim guard/session/approval contract remains incomplete. | [`phases/phase-03.md`](./phases/phase-03.md), [`aegis_loop/event_contract.py`](./aegis_loop/event_contract.py), [`aegis_loop/event_log.py`](./aegis_loop/event_log.py), [`dashboard/api.py`](./dashboard/api.py) |
| 4 — Blue v1 | Audited; proposal requires owner approval | Dashboard exposes Blue's denial, rule mapping, candidate change, and approval gate. Red counterfactual identifies when the active policy already blocked the action. | [`phases/phase-04.md`](./phases/phase-04.md), [`aegis_loop/policy.py`](./aegis_loop/policy.py), [`aegis_loop/blue_agent.py`](./aegis_loop/blue_agent.py) |
| 5 — Red v1 | Fixed baseline plus incident-derived checks pass | Each candidate runs 12 baseline attacks and 3 benign controls plus selector mutations/replay and affected-path benign controls derived from the incident and Blue rule. | [`phases/phase-05.md`](./phases/phase-05.md), [`aegis_loop/red_agent.py`](./aegis_loop/red_agent.py), [`tests/test_red_agent.py`](./tests/test_red_agent.py) |
| 6 — Proof loop | Deterministic proof checks pass; history retained | Local proof reports are sanitized and do not clear prior events; registered-app Red runs and probes persist in PostgreSQL. | [`phases/phase-06.md`](./phases/phase-06.md), [`proof_loop.py`](./proof_loop.py), [`aegis_loop/database.py`](./aegis_loop/database.py) |
| 7 — Live detect and contain | Partial against supplied spec | Denied HTTP authorization is saved as a contained incident; REST/SSE JSONL reads and the existing owner-selected app WebSocket are available. Quarantine, detector suite, and incident repair/report lifecycle remain absent. | [`phases/phase-07.md`](./phases/phase-07.md), [`dashboard/applications_api.py`](./dashboard/applications_api.py), [`dashboard/api.py`](./dashboard/api.py) |
| 8 — Test changed code | Audited; deletion handling fixed | Changed Aegis files select focused checks; deleted Python files now skip Ruff and select the full suite. | [`phases/phase-08.md`](./phases/phase-08.md), [`run_changed_tests.py`](./run_changed_tests.py), [`tests/test_change_selection.py`](./tests/test_change_selection.py) |
| 9 — Dashboard | Partial against supplied spec | Multi-user UI supports account login, app selection, durable history, Red outcomes, and pending Blue decisions. JSONL REST/SSE exists, but the UI is not event-only and lacks specified replay/coverage-grid acceptance. | [`phases/phase-09.md`](./phases/phase-09.md), [`web/`](./web/), [`dashboard/`](./dashboard/) |
| 10 — Hardening and pitch | Local-demo safeguards pass; not production-ready | 46 Aegis tests, 27 victim tests, Ruff in both repos, frontend build, and a live poisoned-invoice run pass; production deployment controls remain absent. | [`phases/phase-10.md`](./phases/phase-10.md), [`dashboard/api.py`](./dashboard/api.py), [`aegis_loop/auth.py`](./aegis_loop/auth.py), [`aegis_loop/database.py`](./aegis_loop/database.py) |
| 11 — Workspace editor | Done | Read/write source access is limited to the Aegis security files allowlist. | [`dashboard/workspace.py`](./dashboard/workspace.py) |
| 12 — Review gate | Done | Unified diff preview, explicit human approval, stale-hash checks, and atomic apply. | [`dashboard/workspace.py`](./dashboard/workspace.py), [`dashboard/test_workspace.py`](./dashboard/test_workspace.py) |
| 13 — Targeted validation | Done | Browser can invoke only the fixed changed-file pytest/Ruff runner; no arbitrary commands. Successful tests reload policy. | [`dashboard/validation.py`](./dashboard/validation.py), [`run_changed_tests.py`](./run_changed_tests.py) |
| 14 — Live demo loop | Done | Local Ollama reads a poisoned fake invoice; Aegis intercepts the target tool call and records the result. | [`red_agent.py`](./red_agent.py), [`aegis_loop/runtime.py`](./aegis_loop/runtime.py), [`dashboard/api.py`](./dashboard/api.py) |
| 15 — Demo polish | Done | End-to-end attack/fix/validate/re-attack/proof workflow and setup guidance. | [`README.md`](./README.md), [`web/src/App.tsx`](./web/src/App.tsx), [`web/src/style.css`](./web/src/style.css) |

## Current architecture rule

Security rules and security evidence belong in `aegis-loop/`. The fake target's
agent, tools, data, and benign task suite belong in `victim-app/`. Tests and
docs should preserve that ownership boundary as the code evolves.

The current multi-user integration uses PostgreSQL for durable users,
registered applications, event and incident history, Red runs, probe results,
and Blue proposals. The victim is a separate process and calls
[`/api/integration/authorize`](./dashboard/applications_api.py) using its
registered app token. Aegis's local adapter remains available for local demos
and still requires the sibling victim directory only when that adapter is
invoked. Blue policy templates are deterministic. Red uses a fixed baseline
plus bounded deterministic attack-derived mutations; it is not an LLM-driven
attacker, an exhaustive test suite, or a model-driven victim test.

The Phase 1 Gandalf observations and official Round 1 submission confirmation
remain user-owned and are not represented as completed by code changes here.

## Audit verification record

Earlier Phase 1–10 validation passed **46 Aegis tests** (one existing
Starlette/httpx deprecation warning), **27 victim tests**, Ruff in both
repositories, and the dashboard production build. A live separate-process
poisoned-invoice run made six tool calls; fake admin reads and outbound emails
were blocked before fake side effects, and events, incidents, Red variants,
and pending proposals were visible in app-scoped PostgreSQL history. The
dashboard health endpoint reports a connected database.

Aegis and victim tests share the same mutable synthetic target directory and
must be run sequentially, not concurrently.

The latest specification-audit validation passed **45 Aegis tests** when
excluding `dashboard/test_api.py` and `tests/test_multiuser_api.py`, which
require `DATABASE_URL`; 15 focused event/sandbox tests passed, the changed-test
selection suite passed (8 tests), and full Aegis Ruff passed. The current local
`.env` contains no database URL, so PostgreSQL-backed API tests could not be
rerun in this environment. The new REST/SSE filtering and delivery logic was
tested directly without a database. See each linked phase record for
scope and remaining limits.
