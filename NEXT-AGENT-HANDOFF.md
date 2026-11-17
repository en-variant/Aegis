# Aegis Loop — Continuation Handoff

**Last verified:** 2026-11-10  
**Workspace:** `/home/en_variant/Desktop/2025/Aegis`  
**Purpose:** Give the next coding agent a factual snapshot of the project, the
trust-foundation work, validation, and safe next steps.

## Start here

This workspace contains three components:

1. **Aegis** (`aegis-loop/`): a local authorization service and owner
   dashboard backed by PostgreSQL.
2. **Victim** (`victim-app/`): a separate synthetic finance assistant using a
   local Ollama model and fake tools/data.
3. **Attacker** (`attacker/`): a separate local dashboard that submits fixed
   authorization-only test cases to Aegis.

The current work implements the requested trust foundation: signed end-user
identity, replay protection, app-token rotation/revocation, and identity
forgery probes. It does **not** connect to real email, payment providers,
accounts, company data, or an external identity provider. The Victim's demo
login and finance data remain synthetic.

Useful documentation:

- [Aegis README](./aegis-loop/README.md)
- [Victim README](./victim-app/README.md)
- [Attacker README](./attacker/README.md)
- Aegis API and trust logic: `aegis-loop/dashboard/applications_api.py`,
  `aegis-loop/aegis_loop/identity.py`, and `aegis-loop/aegis_loop/database.py`
- Victim backend and signing: `victim-app/victim_api.py`,
  `victim-app/agent/identity.py`, and `victim-app/aegis_client.py`
- Attacker probes: `attacker/app.py`

## Current trust and authorization flow

1. An Aegis owner registers an app and receives its app token once. Aegis
   stores a peppered HMAC-SHA-256 digest and a short display prefix.
2. The owner generates an Ed25519 keypair. Aegis stores one or more active
   public keys indexed by `kid`; the private key stays in the Victim/Attacker
   backend environment.
3. A user signs in to the local Victim web UI as seeded `alice`
   (`finance_admin`) or `bob` (`viewer`). Passwords are read from
   `VICTIM_ALICE_PASSWORD` / `VICTIM_BOB_PASSWORD`. The backend keeps the
   authenticated principal in a server-side in-memory session. This is a
   stand-in for an identity provider, not production authentication.
4. The Victim backend—not the model—mints a short-lived EdDSA identity JWT for
   each tool authorization request. Claims include `iss`, `sub`, `role`,
   `aud="aegis"`, `iat`, `exp`, and `jti`; the JWT header includes `kid`.
   Lifetime is capped at 300 seconds, with 30 seconds of clock skew.
5. The Victim sends the app token and identity in the `X-Aegis-Identity`
   header to `/api/integration/authorize`. It does not send a role in the
   authorization request body. Aegis pins verification to EdDSA, checks the
   registered active key, issuer, audience, times, claims, and allowed role,
   then consumes the JTI in PostgreSQL.
6. Only the verified role reaches policy. A body-supplied role is ignored; if
   present and different (including a non-string value), `role_mismatch` is
   recorded. Identity failures are denied and recorded with distinct reason
   codes: `missing_identity`, `bad_signature`, `expired`, `replayed`,
   `wrong_issuer`, `unknown_kid`, or `invalid_claims`.
7. The Victim runs its local fake tool only after Aegis returns a valid allow
   decision. If Aegis or identity configuration is unavailable, the
   integration fails closed.
8. Supported policy denials can create a Blue proposal. Blue is deterministic
   policy-template logic; Red checks 12 baseline attack cases, 3 benign
   controls, and incident-derived variants. A proposal remains pending for
   human review. This is not a general-purpose attack detector or a proof that
   all attacks are blocked.

## Implemented trust-foundation changes

### Aegis

- Ed25519 public-key registration, listing, deactivation, and audit records.
- `scripts/gen_identity_key.py` creates a private key with mode `0600`, avoids
  overwriting an existing key, and prints `kid` plus a base64url public key.
- Pinned EdDSA JWT verification; no `none`, HS*, or other algorithms accepted.
- PostgreSQL JTI replay protection and reason-coded identity denials.
- Verified user, role, identity status, and role mismatch stored with tool
  events. Policy uses the verified role only.
- HMAC-SHA-256 app-token digests with `AEGIS_TOKEN_PEPPER`; constant-time
  digest comparison; token prefix/created/last-used/revoked metadata.
- Owner-scoped rotate/revoke endpoints and dashboard confirmation controls.
  Rotation invalidates the old token immediately.
- Migration `2026-identity-token-lifecycle` invalidates legacy app tokens that
  were stored in plaintext. They must be reissued/rotated.
- Aegis dashboard shows app ID, token state/metadata, public-key management,
  user identity and role mismatch on tool events.

### Victim

- Local web login, logout, session-backed `/api/me`, and `/api/chat`.
- Server-side fixed role mapping for `alice` and `bob`; environment-seeded
  passwords. Login comment identifies the fake login as an identity-provider
  stand-in.
- Fresh short-lived JWT per tool call. Signing key and identity never enter the
  model request or its tool schema.
- Standalone CLI uses `--username` and password prompt instead of a role
  command-line option.
- Synthetic data/tools only. Fake payments mutate the local fake ledger; fake
  email/chat write local files.

### Attacker

- Retains five fixed policy-control probes and adds six identity probes:
  missing token, tampered role/bad signature, unregistered key, expired token,
  replay, and wrong app issuer.
- Policy probes send valid signed identities; the replay test first checks a
  valid authorization precondition.
- Results show the observed identity denial reason. Probes only request Aegis
  decisions; they do not execute Victim tools, send mail, or move money.
- Its backend reads a configured local key path; key material is not exposed
  to browser JavaScript.

## Setup notes

Follow the READMEs for current details. Important configuration:

- Aegis requires `DATABASE_URL` and a stable `AEGIS_TOKEN_PEPPER` with at
  least 32 bytes. Keep the pepper secret and reuse it across restarts. Changing
  or losing it makes existing app-token digests unusable.
- Generate a local identity key from `aegis-loop/`:

  ```bash
  python scripts/gen_identity_key.py
  ```

- Register its printed `kid` and public key for the app in Aegis. Configure
  the Victim backend with `AEGIS_URL`, `AEGIS_APP_ID`, `AEGIS_APP_TOKEN`,
  `AEGIS_IDENTITY_KID`, `VICTIM_IDENTITY_PRIVATE_KEY`,
  `VICTIM_ALICE_PASSWORD`, and `VICTIM_BOB_PASSWORD`; then run
  `python -m victim_api` from `victim-app/` (port 8002).
- For Attacker identity probes, configure
  `AEGIS_TEST_IDENTITY_PRIVATE_KEY` and `AEGIS_TEST_IDENTITY_KID` in the
  Attacker server environment. Start it on loopback port 8001.
- Keep all local services bound to loopback. Never reuse real credentials or
  signing keys. Rotate any app token that may have been pasted into a prior
  conversation or otherwise exposed.

The legacy app-token migration runs when Aegis initializes its DB. Restarting
against the real configured database is a state-changing operation: confirm
the target DB and inform the owner before doing it. Do not clear the database;
it was previously emptied at the user's explicit request and tests for this
work used a separate disposable PostgreSQL container.

## Verification completed

Latest successful checks for this work:

- Aegis full test suite against a disposable PostgreSQL instance:
  **79 passed**. Coverage includes identity reasons, altered signature,
  algorithm downgrade rejection, body-role mismatch (including non-string
  role), replay, overlapping/deactivated keys, token rotation/revocation,
  migration invalidation, and audit/log secret checks.
- Victim focused suite: **24 passed** (`test_aegis_client.py`,
  `test_agent_loop.py`, `test_tools.py`, `test_victim_identity.py`).
- Attacker suite: **3 passed**.
- Ruff checks passed on the modified Aegis, Victim, and Attacker Python files.
- Aegis frontend `npm run build` passed (`tsc -b` and Vite production build).
- Identity-key generator was exercised; its output file permissions were
  verified as `0600`, then the test file was removed.
- A disposable PostgreSQL container used for tests was stopped and removed.

There is an existing Pylance diagnostic in
`aegis-loop/aegis_loop/database.py` around the PostgreSQL `connection()`
context-manager annotation / `row_factory` typing. It was not addressed as
part of this change; Ruff and runtime tests pass.

The local `/api/health` check did not respond on ports 8000, 8001, or 8002
when this handoff was written. Do not assume the services are running. The
previously available Aegis database container may be running, but the
application endpoints need to be started and checked explicitly.

## Repository and change-management state

- The workspace root is **not** a Git repository.
- `aegis-loop/` and `victim-app/` are separate Git repositories. Both have
  numerous pre-existing dirty and untracked files from earlier phases as well
  as this work. Review each repository's status before staging anything.
- `attacker/` is not a Git repository. The user previously chose to leave
  Attacker changes uncommitted and not create a workspace-level repository.
- No commit was created. Do not stage broadly (`git add .`) or commit these
  repositories without first isolating task-owned changes and getting the
  user's approval if there is ambiguity.
- Build output under `aegis-loop/web/dist/` is ignored. No temporary database
  or test signing key should remain.

## Recommended next steps

1. Read this handoff and all three component READMEs before editing.
2. Ask the user before changing any behavior outside the specified trust
   foundation. Avoid real provider integrations; those were explicitly
   non-goals for this step.
3. If continuing this step, test the actual end-to-end startup only after
   confirming `DATABASE_URL` points to the intended development database and
   providing a stable `AEGIS_TOKEN_PEPPER`. Do not migrate or modify the
   user's DB without that confirmation.
4. Run Aegis, Victim, and Attacker on loopback, test key registration and
   signed tool calls, then run all 11 Attacker probes and inspect Aegis event
   history. The tests validate API behavior, but a full local model/Ollama
   presentation flow was not verified in the final test pass.
5. Inspect older phase documentation (including `SPEC.md`, `PHASE-LOG.md`,
   and `DECISIONS.md`) for project history and previously recorded gaps before
   making project-wide claims.
6. Do not commit unless the user asks, and never include unrelated dirty work
   or credentials.

## Known scope and gaps

- Finance records, payment ledger, email, and chat are fake/local only.
- Victim demo login uses in-memory sessions and is not production identity
  management.
- Blue is deterministic, and Red uses fixed plus incident-derived policy
  checks; neither is an LLM-based autonomous security agent.
- Existing internal Aegis Red suite tests policy decisions directly. The
  separate Attacker suite now sends valid identities for policy cases and
  tests identity rejection cases through the authorization API.
- No production deployment security (TLS, MFA, rate limiting, robust session
  storage, real IdP integration) is provided.
- No root Git repository or clean, isolated set of changes exists.
