# Phase 2 — Synthetic victim finance assistant

## Audit outcome

**Target checks pass; deliberate weaknesses remain by design.** The app is a
separate test target, not part of Aegis Loop's security implementation.

## What belongs to this phase

The target agent, seven fake tools, synthetic data, reset script, and benign
tasks live in [`../../victim-app/`](../../victim-app/). See its
[`README.md`](../../victim-app/README.md), [`agent/`](../../victim-app/agent/),
[`tools/`](../../victim-app/tools/), [`data/`](../../victim-app/data/), and
[`tests/`](../../victim-app/tests/). The optional HTTP transport client is
[`aegis_client.py`](../../victim-app/aegis_client.py); it contains no Aegis
policy and makes no service call when both integration variables are unset.
The synthetic prompt-injection fixture is
[`poisoned_invoice.txt`](../../victim-app/data/files/poisoned_invoice.txt).

## Verification

- Full victim suite: **27 passed**; Ruff passes.
- Model-backed benign tasks: **10/10 passed in each of three consecutive
  runs** (30 task executions).
- Dataset checks confirm 12 inbox messages, six fake files, and 10 benign
  tasks.
- Tool argument type checks reject malformed strings, objects, booleans, and
  non-finite numeric values before invoking a tool.
- A regression test confirms the deliberately untrusted currency tool
  description remains alterable in the standalone target (W3).
- The live Aegis invoice probe reproduced a follow-up email attempt and Aegis
  blocked it; the fake canary was absent from sinks and the answer.
- HTTP-client tests cover standalone mode, incomplete configuration, denied
  decisions, invalid app tokens, service outages, malformed decisions, and
  successful authorization requests.
- Separate-process smoke test registered an app in Aegis, invoked the victim's
  real HTTP authorization client before the fake `send_email` tool, and
  verified that a denied call did not modify the fake outbox.
- The poisoned-invoice walkthrough is runnable via `python -m agent.loop`
  from the victim directory after setting the registered app's Aegis
  environment variables; a local model can resist or vary the requested
  follow-up tool calls.
- Live local-model run against the separate Aegis process made six tool calls;
  both fake admin-record requests and both fake outbound-email attempts were
  denied, and the fake outbox remained unchanged.

## Audit finding fixed

The shared-budget file contained a contact sentence that the vulnerable
system prompt treated as a follow-up instruction, causing an unrequested
email instead of a summary. The line was removed from both runtime and
pristine fixtures. Summary-task tests now explicitly forbid payment, email,
and chat side effects.

## Intentional target weaknesses

The standalone victim is expected to expose W1 (follow-up instructions),
W2 (unapproved vendor payment), W3 (data-sourced tool description), and W4
(unrestricted record access). These are demonstrations for the external Aegis
layer, not target security controls. Do not connect this app to real accounts,
data, or services.
