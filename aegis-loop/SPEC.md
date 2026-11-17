# Aegis Loop specification audit

This file records the supplied Complete Build Specification as the acceptance
baseline for Phases 1–10. It is an audit and implementation tracker, not a claim
that every requirement is complete. The original requirements remain the
authority where this summary is abbreviated. Implementation choices that
diverge from them are recorded in [`DECISIONS.md`](./DECISIONS.md).

## Phase status

Status is based on implemented behavior, not on whether a similarly named
component exists. “Partial” means useful functionality exists but the stated
acceptance behavior is not complete.

| Phase | Spec outcome | Current evidence and remaining work |
|---|---|---|
| 1 — Setup, learning, threat model, Round 1 | Partial | Local setup, tool-use exercise, threat notes, and submission draft exist. Official submission confirmation and personal learning exercises cannot be established from code. The required provider/API-key and cache workflow is not implemented; this project uses local Ollama. |
| 2 — Victim app | Partial | Separate synthetic finance target, seven tools, fake data, and benign tasks exist. Its fixtures and task checks are not an exact match for every item and acceptance condition in Section 6. |
| 3 — Event log and guard hook | Partial | Added typed event envelopes, required per-event data-field validation, append-only JSONL persistence with sequence recovery, and owner-scoped REST/SSE access for registered-app tool/decision events. The victim does not route every call through the spec's shared `guarded_call`; full session/context taint tracking, approvals, fingerprints, detector hooks, and complete event coverage are absent. |
| 4 — Blue v1 | Partial | Deterministic Blue templates create candidate app policies, Red/benign checks gate them, and explicit owner approval activates a candidate. The policy representation is not the specified YAML `Rule` model; policy synthesis, five gates, generalization, history, and automatic policy version files are absent. |
| 5 — Red v1 | Partial | Red refuses to run unless `AEGIS_SANDBOX=1` and victim data is inside the workspace. It has fixed synthetic probes plus incident-derived deterministic variants and benign controls. Surface-map generation, the specified strategy/attack catalogs, seeded/holdout separation, 3-of-3 judging, and complete data-reset isolation are absent. |
| 6 — Proof loop | Partial | Reports and registered-app Red runs persist; an approved candidate is checked before activation. The required per-path, up-to-three-round synthesis/re-attack controller and path-level hardened/needs-human proof are absent. |
| 7 — Live detect and contain | Partial | Registered-app denials are persisted as contained incidents and streamed to the owner-selected app. There is no session quarantine TTL/store, detector suite, incident investigation/report workflow, or patch-and-verify incident lifecycle. |
| 8 — Test only what changed | Partial | Aegis source changes select focused tests and deleted Python files fall back to the full suite. Specified victim Git-diff analysis, imports/classification, affected attack-path scoping, and hook-driven scoped runs are absent. |
| 9 — Dashboard | Partial | A multi-user React dashboard provides owner-scoped app history, Red outcomes, Blue analysis, and approval. The append-only event API now supports REST and SSE, but the UI is still primarily backed by PostgreSQL/WebSocket history; event-only reducers, replay, the exact coverage grid, and golden-state acceptance are absent. |
| 10 — Hardening and pitch | Partial | Local-demo safeguards, ownership checks, input redaction, sandbox checks, and regression suites exist. Deterministic LLM caching, full H1–H10 enforcement, the specified score reports, and all Phase 10 acceptance scenarios remain incomplete. |

Phases 11–15 have useful workspace-editor and demo functionality recorded in
[`PHASE-LOG.md`](./PHASE-LOG.md). Those extensions are not a substitute for
meeting the remaining Phase 1–10 requirements.

## Current acceptance boundaries

- Red is constrained to the local synthetic victim and refuses to start
  without the explicit sandbox flag. The workspace check is against the victim
  data directory and workspace root; it is not a network-target allowlist
  implementation.
- Judge outcomes in the implemented Red checks come from deterministic code.
- Human approval is required before an app-specific Blue candidate is applied.
- Existing history is not deleted by proof/Red runs. The JSONL event stream is
  append-only during normal operation; its archive helper is intended only for
  explicit reset workflows.
- The React console escapes untrusted content as text through normal React
  rendering. The complete event-log replay path has not yet been implemented.
- This project is a local synthetic demonstration. Do not connect real tools,
  credentials, accounts, or data.

## Event stream implementation

`aegis_loop/event_contract.py` validates the envelope and required data fields
for each declared event type. `aegis_loop/event_log.py` appends one JSON object
per line, flushes each append, recovers the sequence from the last persisted
line, and rejects a relative `AEGIS_EVENTS` value. The authenticated
`GET /events` and `GET /events/stream` endpoints expose only events whose
`app_id` belongs to the signed-in user.

For multi-user isolation, registered-app events include an `app_id` in
`data`; this is an additive field beyond the single-user event example in the
spec. The registered-app system still uses a legacy policy dictionary rather
than spec `Rule` objects. Accordingly, its `policy_proposed` events report an
empty `rules` list and carry the actual change separately as
`legacy_policy_change`; `policy_applied.rule_ids` is empty rather than
mislabeling dictionary keys as rule IDs.
