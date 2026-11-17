# Phase 4 — Blue policy

## Audit outcome

**Pass for the documented synthetic finance rules.**

## What belongs to this phase

[`../aegis_loop/policy.py`](../aegis_loop/policy.py) contains local and
registered-app policy checks for admin records, payments, vendors, outbound
recipients, and sensitive egress. Registered apps have separate active policy
JSON; [`../aegis_loop/blue_agent.py`](../aegis_loop/blue_agent.py) proposes
only supported template changes for owner approval.

## Verification

Tests cover denied employee/admin access, unapproved payments, invalid
arguments, blocked egress, sanitized logs, and per-application policy
evaluation. A proposal remains pending until explicitly approved; approval and
proposal status change with the active policy in one database transaction.

The separate-process smoke test produced a pending proposal after a denied
synthetic email attempt. The active policy remains unchanged until an owner
approves the proposal.
Blue's current supported templates are deterministic. The dashboard now
shows the denial, matched policy field, proposed change, and human-approval
gate rather than implying Blue is an LLM.

## Limits

This is a small rule set for the fake finance tools. Its record IDs, recipient
allowlist, and sensitive-context flag are target-specific; it is not a general
data provenance or information-flow system. The app token identifies the
registered application, not the end user or correctness of the victim's
asserted role.
