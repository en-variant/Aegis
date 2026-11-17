# Implementation decisions

This file records choices made where the current product and the supplied
specification differ. These choices preserve working behavior; they do not
reclassify a spec requirement as complete.

## PostgreSQL plus an append-only event stream

**Decision:** Keep PostgreSQL as the source of truth for user accounts,
registered applications, owner-scoped history, incidents, Red runs, and
approval proposals. Add an append-only JSONL event stream as an audit/replay
foundation rather than replacing PostgreSQL.

**Reason:** The existing service is a multi-user, multi-app product. Owner
isolation and durable relational records are already implemented and tested;
replacing them with shared JSON files would remove those guarantees and break
the current dashboard. The JSONL stream is additive and uses `app_id` to keep
the event REST/SSE APIs owner-scoped.

**Spec gap:** The specification explicitly requires JSON/JSONL files only and
one event log as the console's data source. That requirement is not met by this
decision. Event replay and an event-only console still need implementation.

## Local Ollama, deterministic Blue/Red

**Decision:** Retain the current local Ollama-backed victim demo and
deterministic policy-template Blue/Red checks. Do not add a remote model
provider or make the policy judge depend on a model.

**Reason:** The repository's working demonstration is local, uses fake data,
and does not require external model credentials. Deterministic checks preserve
reproducible, code-based attack judgments.

**Spec gap:** The spec calls for an Anthropic-backed `llm()` function, model
cache, offline cache-miss behavior, and model-driven synthesis/attacker
workflows. These are not implemented. The victim's local model use is not
equivalent to the specified cache and provider behavior.

## Existing owner-approved app policy

**Decision:** Keep the existing app-specific policy dictionary and explicit
owner approval flow. Do not claim that dictionary fields are typed spec `Rule`
IDs.

**Reason:** This is the active policy format used by the registered-app HTTP
integration and dashboard. Replacing it in a broad audit change would risk
breaking an already working policy lifecycle.

**Event representation:** Current candidate events use `rules: []` and store
the actual legacy dictionary change separately. Applied events use
`rule_ids: []` and identify the changed legacy fields separately. This avoids
inventing rule IDs.

**Spec gap:** YAML active/history/retired policy loading, the full `Rule`
schema, generalization, and the five specified validation gates remain
unimplemented.

## Preserve the additional dashboard and editor

**Decision:** Preserve account-scoped applications, incident history, the
interactive Red/Blue display, and the restricted Aegis workspace editor
features already in the repository.

**Reason:** These are useful extensions to the requested console and code
review workflow. They do not authorize testing real targets or bypassing the
synthetic-only boundary.

**Spec gap:** Existing editor capabilities do not satisfy every Part C
acceptance criterion and do not replace the required Phase 1–10 event,
scoping, incident, or proof-loop work.

## Event ownership field

**Decision:** Add `app_id` to registered-app event `data` so the global
append-only stream can be safely filtered for authenticated owners.

**Reason:** The stream is shared by a multi-user service, unlike the
single-instance log described by the spec. The API returns only events for
applications owned by the authenticated account.

**Constraint:** Do not put credentials or unredacted secret values in event
data. Registered-app tool arguments use the existing sanitizer before the
event is written.
