# Phase 6 — Proof loop

## Audit outcome

**Pass for deterministic fixed probes and smoke checks.**

## What belongs to this phase

[`../proof_loop.py`](../proof_loop.py) executes fixed Red probes and three
direct benign tool checks, then writes a sanitized JSON proof under
[`../proofs/`](../proofs/).
The multi-user app workflow stores its 12-attack/3-benign Red runs and results
in PostgreSQL; running those checks does not clear earlier app history.

## Verification

The current Aegis suite passed **46 tests**, including the proof-loop and
PostgreSQL-backed multi-user tests. The proof-loop test verifies all three
attacks are blocked, all three benign checks pass, six new events are captured,
prior event history is retained, and the canary is absent from the report.
The separate-process smoke test verified its persisted Red run includes 12
blocked attack probes and 3 passed benign controls.

## Limits

The proof loop's three benign checks are not the victim's full 10-task
model-backed suite. That separate suite was run three times for Phase 2. The
proof is evidence for these named checks only, and cleanup behavior on an
unexpected exception is not guaranteed. The registered-app Red verifier
tests policy directly, not the victim model or every possible attack.
