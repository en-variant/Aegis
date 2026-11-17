# Phase 1 — Setup, learning, threat model, Round 1

## Audit outcome

**Partially verified.** Local development prerequisites and the model tool-use
feasibility check work. Personal learning exercises and event-submission tasks
cannot be completed or confirmed by repository tests.

## What belongs to this phase

- [`../hello_tool.py`](../hello_tool.py) checks that the configured local model
  calls `add` and returns a final answer containing `42`.
- [`../PHASE-1-NOTES.md`](../PHASE-1-NOTES.md) records the threat model,
  security concepts, prior-art comparison, and local-model choice.
- [`../ROUND-1-DRAFT.md`](../ROUND-1-DRAFT.md) is a draft, not proof of
  submission.

## Verification

On 2026-11-08, the environment reported Python 3.14.3, Git 2.53.0, Node
22.23.1, and npm 10.9.8. The local Ollama endpoint was reachable. Running
`python hello_tool.py` invoked the tool and produced an answer containing 42.
The client disables environment proxy discovery so this local feasibility
request is not redirected through an ambient HTTP proxy.

## Remaining work and limits

- The project uses a local Ollama model rather than an Anthropic API key. No
  paid key is required for the verified local flow.
- The `.env` file and any credentials were not inspected. Keep it ignored and
  do not include it in reports or commits.
- The official event rules, account ownership, personal Gandalf exercise, and
  submission confirmation are not established by code. Confirm the rules and
  submit the entry yourself.

## Checklist

- [x] Local tool-call feasibility check
- [x] Threat model and prior-art notes exist
- [ ] Personal learning exercises recorded
- [ ] Official submission requirements confirmed and entry submitted
