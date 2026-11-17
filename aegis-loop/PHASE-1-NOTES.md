# Phase 1 Notes

## What Aegis Loop is

An AI agent can read messages and files and use tools to take actions. If it treats instructions inside an untrusted document as trustworthy, it may do something its user did not ask for. That becomes much more serious when the same agent can read private data and send information outside.

Aegis Loop will use a finance assistant with fake data to demonstrate this risk safely. The Red Agent will test the fake app, the Blue Layer will block or repair weaknesses, and the system will keep evidence that the repair blocks the attack without breaking ordinary tasks.

## Security concepts

- **Prompt injection:** Instructions hidden in content, such as a file or email, can change what an agent does. Marking content as untrusted helps, but a system prompt alone is not a dependable security boundary.
- **Sensitive information disclosure:** An app can expose private records, credentials, or company data through its answers or tools. Keep access limited and check what leaves the system.
- **Excessive agency:** Giving an agent too many tools, permissions, or chances to act increases the impact of a mistaken or manipulated decision. Enforce permissions in code, not just in model instructions.
- **The lethal trifecta:** Risk rises sharply when an agent can access private data, reads untrusted content, and can communicate outward. The fake invoice scenario combines all three.

Sources:

- [OWASP Top 10 for LLM Applications](https://genai.owasp.org/llm-top-10/)
- [OWASP: Prompt Injection](https://genai.owasp.org/llmrisk/llm01-prompt-injection/)
- [OWASP: Sensitive Information Disclosure](https://genai.owasp.org/llmrisk/llm022025-sensitive-information-disclosure/)
- [OWASP: Excessive Agency](https://genai.owasp.org/llmrisk/llm062025-excessive-agency/)
- [Simon Willison: The lethal trifecta for AI agents](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/)

## Prior-art comparison

| Project | What it does | Difference from the Aegis Loop plan |
|---|---|---|
| [NVIDIA NeMo Guardrails](https://docs.nvidia.com/nemo/guardrails/latest/index.html) | A programmable Python library for input, retrieval, dialog, execution, and output guardrails. | Its documented focus is configuring guardrails; Aegis Loop plans an attack, patch, re-attack, and benign-regression evidence cycle for a small agent app. |
| [NVIDIA garak](https://github.com/NVIDIA/garak) | Probes LLM-backed systems for issues such as prompt injection, data leakage, and other unwanted behavior. | garak focuses on finding and reporting failures; Aegis Loop plans to connect each finding to a Blue fix and then test that fix and ordinary behavior. |
| [Microsoft PyRIT](https://github.com/microsoft/PyRIT) | An extensible toolkit for automated scans, adaptive multi-turn testing, and human-led AI red teaming. | PyRIT is a broad risk-testing toolkit; Aegis Loop is a small, reproducible demo centered on repairing a fake app and retaining proof of regression checks. |
| [promptfoo red teaming](https://www.promptfoo.dev/docs/red-team/) | Generates adversarial test inputs, evaluates application responses, and can report or integrate results into CI/CD. | Aegis Loop's planned emphasis is applying and re-testing a targeted Blue change, while checking known benign tasks still work. |
| [Lakera / Check Point AI Guardrails](https://docs.lakera.ai/guard) | Provides AI-agent discovery, risk assessment, and runtime controls for prompt attacks, data leakage, tool interactions, and policy violations. | This is a platform for protecting deployed AI systems; Aegis Loop is a local learning prototype for demonstrating an end-to-end attack/fix/retest cycle with evidence. |
| [Google DeepMind CaMeL paper](https://arxiv.org/abs/2503.18813) | Researches a design for limiting prompt-injection impact by separating control flow from untrusted data and tracking how data is used. | CaMeL is a security architecture and research contribution; Aegis Loop plans a hands-on test harness around a fake finance agent, its fixes, and benign-task regressions. |

Two-sentence comparison with garak: garak probes LLM-backed systems for failures and helps identify where they are vulnerable. Aegis Loop's planned contribution is to pair attacks with a Blue-side fix, re-attack the patched fake agent, and retain evidence that normal tasks still pass.

## Threat model

### Assets

- A planted fake API key (a canary, not a real credential).
- Fake employee records and the fake payment ledger.
- The integrity of the fake vendor list and invoice data.

### Attacker

Someone outside the company who can send an email or share a document that the finance assistant may read. All testing is restricted to the local fake app and synthetic data.

### Entry points

- Inbox messages and invoice files.
- Shared text files.
- Tool descriptions or other external data used to describe tools.

### Sinks

- Sending email.
- Posting to team chat.
- Recording a payment in the fake ledger.

### Impact

- Exposure of the fake canary or other fake records.
- A payment being recorded for an unapproved vendor.
- Unwanted messages or chat posts.

## Local model feasibility test

Ollama runs locally with the `qwen3:4b` model. Its Anthropic-compatible endpoint answered without issuing a tool call during the feasibility test, so `hello_tool.py` uses Ollama's native tool-calling API instead. The script must confirm both that the model invoked the local `add` function and that the final answer contains `42`.

Verification: `hello_tool.py` completed successfully; its final answer contained `42`, and its checks confirmed the `add` tool was called.

## Hands-on learning to finish

Play Lakera Gandalf levels 1–4 yourself and record what you noticed, without reusing real credentials or targeting real services:

| Level | What instruction or boundary did you notice? | What did you learn? |
|---|---|---|
| 1 | To fill after playing | To fill after playing |
| 2 | To fill after playing | To fill after playing |
| 3 | To fill after playing | To fill after playing |
| 4 | To fill after playing | To fill after playing |

## Round 1 submission checks

The project brief says to use the **Cybersecurity AI Agents** track and submit before the Nov 10 close. You indicated that the rules-reading step was handled; before submitting, confirm the official format/length and pre-built-code rule against the event page.

Submission status: draft prepared in [ROUND-1-DRAFT.md](./ROUND-1-DRAFT.md); not submitted and no confirmation received.
