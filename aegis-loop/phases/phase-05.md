# Phase 5 — Red probes

## Audit outcome

**Fixed probes and the live demonstration pass for the current target.**

## What belongs to this phase

[`../aegis_loop/red_agent.py`](../aegis_loop/red_agent.py) checks registered
app policy candidates with 12 baseline synthetic attacks, 3 benign controls,
and deterministic variants derived from each contained tool action and
proposed policy selector.
[`../red_agent.py`](../red_agent.py) retains the legacy local authorization
probes and optional model-backed poisoned-invoice probe for the adjacent
synthetic [`victim-app`](../../victim-app/).

## Verification

The registered-app verifier persists each fixed and incident-derived result.
Adaptive cases replay the triggering action, mutate its policy selector, and
include a benign control. The verifier compares the exact replay under active
and candidate policy, so the dashboard can distinguish a new block from a
defense-in-depth rule for an action already blocked by the active policy. A
proposal is offered only when all baseline and adaptive checks pass.
The local model probe was also verified previously: it attempted an outbound
email, Aegis denied it, and `canary_in_fake_sinks_or_answer` was `false`.
The separate-process smoke test independently confirmed a candidate passed
all 12 attack probes and all 3 benign controls before it was presented.

## Limits

The baseline cases are fixed; adaptive cases are bounded deterministic
mutations, not an LLM, exhaustive fuzzing, or a statistical claim about attack
resistance. These checks test policy behavior directly, not the victim model's
prompt-injection resistance.
The live result is model-dependent; a model that resists the prompt may report
`resisted` rather than exercise the containment path.
