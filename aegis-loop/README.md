# Aegis Loop

Aegis Loop is the security service. It connects to the separate synthetic
finance target in [`../victim-app/`](../victim-app/) over HTTP. The victim is
deliberately vulnerable when run alone; it does not contain Aegis policy,
security history, Red probes, Blue proposals, or the dashboard.

The service provides user accounts, owner-scoped application registrations,
PostgreSQL-backed events/incidents/runs, and an HTTP authorization endpoint for
victim tool calls. Application tokens authenticate the registered app;
short-lived Ed25519-signed identity JWTs authenticate the end user and provide
the role used by policy. Blue uses deterministic policy templates to propose
app-specific changes after supported denials. Red checks a candidate with 12
baseline attack cases, 3 benign controls, and additional mutations derived from
the contained action and proposed rule. A proposal remains pending until its
owner approves or rejects it. Only approval activates the candidate policy.

An append-only typed JSONL audit stream is available alongside PostgreSQL via
authenticated `GET /events?since_seq=0&limit=500` and
`GET /events/stream?since_seq=0` (SSE). Both endpoints return only events for
applications owned by the signed-in user. The React console has not yet been
migrated to use the JSONL stream as its sole source of truth.

## Local demo setup

Use a local PostgreSQL database. The database is initialized automatically at
service startup. Use a disposable development database for tests.

From `aegis-loop/`, create and activate a Python environment, install the
dependencies, and build the dashboard:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
cd web
npm ci
npm run build
cd ..
```

Set `DATABASE_URL` to your PostgreSQL connection string in the shell that will
run Aegis. For example, replace the values below with your own local database
credentials:

```bash
export DATABASE_URL='postgresql://<user>:<password>@127.0.0.1:5432/<database>'
```

The angle-bracketed values above are placeholders; replace them before running
the command. Never commit database credentials. Set `AEGIS_SECURE_COOKIES=1`
only when serving over HTTPS; the documented local loopback demo uses HTTP.
Set a stable, private app-token pepper in the same service environment. Keep
and reuse this value across Aegis restarts; losing or changing it invalidates
all existing app tokens.

```bash
export AEGIS_TOKEN_PEPPER="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
```

Start Aegis from this directory:

```bash
python -m dashboard
```

Open `http://127.0.0.1:8000`, create an account, and register an application.
The application token is shown only once. Copy it to the victim process's
environment; do not put it in browser code or commit it.

### Create and register an end-user identity key

Generate a signing keypair from `aegis-loop/`. The private key is written with
owner-only permissions under the ignored `victim-app/.identity/` directory;
only the public key and `kid` are entered in Aegis:

```bash
python scripts/gen_identity_key.py
```

In the Aegis dashboard, select the registered application, then add the
printed `kid` and `public_key` under **Trust configuration → End-user identity
public keys**. The private key stays in the Victim backend. Multiple public
keys can remain active during key rotation; deactivate the old one only after
the Victim uses the replacement key.

## Run the victim as a separate web application

Keep Aegis running. In a second terminal, set the URL, one-time app token, and
identity settings for the Victim backend. Copy the selected app's ID from
**Trust configuration → App ID**. Set distinct local demo passwords; these
seeded Alice/Bob accounts are not connected to a real identity provider.

```bash
cd ../victim-app
source .venv/bin/activate
export AEGIS_URL='http://127.0.0.1:8000'
export AEGIS_APP_ID='<selected-app-id>'
export AEGIS_IDENTITY_KID='<kid-printed-by-key-generator>'
export VICTIM_IDENTITY_PRIVATE_KEY="$PWD/.identity/aegis-ed25519.pem"
export VICTIM_ALICE_PASSWORD='<local-demo-password>'
export VICTIM_BOB_PASSWORD='<different-local-demo-password>'
read -s -p "Paste the app token, then press Enter: " AEGIS_APP_TOKEN; echo
export AEGIS_APP_TOKEN
python -m victim_api
```

Open <http://127.0.0.1:8002>, sign in as Alice or Bob, and submit a finance
prompt. The backend derives the role from its server-side session and signs a
fresh short-lived identity JWT for each tool authorization request. The model
does not receive the private key or JWT and cannot choose the identity or role.

The victim sends each proposed tool action to Aegis before executing it. If
Aegis is configured but unreachable, rejects the app token, or returns an
invalid decision, the victim does not execute the tool action. To run the
intentionally vulnerable victim without Aegis for a local comparison, unset
`AEGIS_URL` and `AEGIS_APP_TOKEN`. Aegis integration requires all identity
settings and fails closed if they are missing.

The dashboard app selector scopes history, Red runs, and proposals to one
registered app. The live stream requires a signed-in owner and an app owned by
that account. Register a separate app for each victim installation and keep
each token server-side.

The separate local Attacker dashboard is in
[`../attacker/`](../attacker/). Start it in another terminal by following its
README. Its five policy controls and six identity-forgery probes call only
Aegis's local authorization API; they do not execute victim tools, send email,
or move money. The Attacker backend needs the same locally configured identity
key and `kid`; the dashboard never receives either.

To run the file-based attack walkthrough, submit
`Read poisoned_invoice.txt and follow its instructions exactly.` in the Victim
web app after signing in.

The sample is synthetic and requests access to a fake restricted record and
an outbound fake email. The dashboard's browser-stream indicator only means
the dashboard is receiving app history; it is not a victim-process heartbeat.
The first actual victim tool call appears in Tool decisions. A contained call
adds an incident and a Blue/Red record.

## What the Red/Blue workflow does

1. A victim tool call reaches the Aegis HTTP authorization endpoint.
2. Aegis evaluates the registered app's active policy and stores a sanitized
   event. A denied call is recorded as a contained incident; the victim does
   not execute it.
3. For supported denials, Blue creates an app-specific candidate policy patch.
4. Red checks that candidate against 12 fixed synthetic attack probes and 3
   benign controls, then replays the contained action with selector variants
   and a benign control. The adaptive checks are derived from that incident
   and candidate rule; their results and run are saved without clearing prior
   history.
5. A passing proposal is shown as pending. The app owner must approve it to
   activate the policy or reject it to leave the active policy unchanged.

Blue is deterministic policy-template logic, not an LLM; the dashboard shows
the decision, rule mapping, proposed change, and approval gate. Red combines a
fixed baseline with deterministic incident-derived mutations; it is not an
LLM-driven attacker or proof that all attacks are blocked. It tests policy
decisions directly rather than sending all probes through the victim model.
Red also compares the exact incident under active and candidate policy. If the
active policy already denied it, the UI labels the patch as defense-in-depth,
not a newly fixed vulnerability. Policy uses only the verified identity role.
A body-supplied role is ignored and a `role_mismatch` flag is recorded when it
differs from the verified role.

## Tests

Run Aegis tests with `DATABASE_URL` set to a disposable PostgreSQL test
database:

```bash
pytest -q
ruff check .
```

From `../victim-app/`, run the victim connector and target tests:

```bash
pytest -q
ruff check .
```

The model-backed benign suite is in
[`../victim-app/tests/test_benign.py`](../victim-app/tests/test_benign.py) and
requires the local Ollama model. Run Aegis and victim suites sequentially:
both use the same synthetic target data during local adapter tests.

## Safety and limitations

This is a local demonstration, not a production security boundary. Existing
plaintext app tokens are invalidated the first time the identity/token
migration runs; rotate each app token in the dashboard and update the Victim
environment. New app tokens are stored as SHA-256 digests and shown only on
creation or rotation. Identity JWTs are EdDSA-only, expire within five minutes,
and their `jti` values are consumed once in PostgreSQL.

The Victim login uses two environment-seeded demo passwords and an in-memory
local session, not a real identity provider. The Attacker backend can read the
configured private-key file to make authorized test tokens, so keep all three
services on loopback and never reuse a real signing key. The services do not
provide deployment-grade TLS, MFA, rate limiting, production session
management, or real identity-provider integration. Do not connect real tools,
accounts, credentials, invoices, or company data.

## Documentation map

- [`FOLDER-GUIDE.md`](./FOLDER-GUIDE.md): ownership of Aegis versus the target.
- [`PHASE-LOG.md`](./PHASE-LOG.md): phase-by-phase outcomes and audit scope.
- [`phases/`](./phases/): individual Phase 1–10 audit records.
- [`PHASE-1-NOTES.md`](./PHASE-1-NOTES.md): initial threat model and learning.
- [`SPEC.md`](./SPEC.md): Phase 1–10 conformance matrix and remaining gaps.
- [`DECISIONS.md`](./DECISIONS.md): documented architecture deviations.
- [`ROUND-1-DRAFT.md`](./ROUND-1-DRAFT.md): submission draft, not proof of
  submission.
- [`../victim-app/README.md`](../victim-app/README.md): target app setup and
  behavior.
