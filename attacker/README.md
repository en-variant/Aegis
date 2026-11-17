# Aegis Attacker Lab

The Attacker Lab is a separate, local dashboard for exercising five synthetic
policy probes and six identity-forgery probes against Aegis. It uses Aegis's
integration API rather than importing or calling code inside the Victim app.

## Safety and scope

- The dashboard only accepts the Aegis service at `http://127.0.0.1:8000` or `http://localhost:8000`.
- The probe catalog is fixed in `app.py`; browser input cannot provide arbitrary tools, arguments, or target URLs.
- Requests ask Aegis to authorize an action. They do not execute the victim's payment, email, or other tools.
- Probe data is synthetic. The test email uses the reserved `.invalid` domain.
- Policy probes use short-lived, valid test identities. Identity probes deliberately omit, alter, replay, or misuse identity claims and keys.
- The app integration token is held only for the current browser request, is not persisted, and is cleared from the form after the run. Do not paste a production or real-provider credential here.
- Denied actions may create incidents in Aegis. All probes only request authorization decisions; they never execute Victim tools, send email, or move money.

This is a local lab integration, not a production security boundary. The
Attacker backend reads the configured private signing key so it can produce
both valid preconditions and deliberately forged tokens. Keep it on loopback,
use only the local demo key, and do not expose the dashboard to a network.

## Configure identity probes

First generate an Ed25519 keypair using
`../aegis-loop/scripts/gen_identity_key.py`, register its printed `kid` and
public key for the application in Aegis, and configure the Victim with the
private key. For the Attacker backend, set the same local private key path and
registered `kid` before starting the service:

```bash
export AEGIS_TEST_IDENTITY_PRIVATE_KEY='../victim-app/.identity/aegis-ed25519.pem'
export AEGIS_TEST_IDENTITY_KID='<registered-kid>'
```

The app's integration token is entered in the dashboard when running a suite.
The Attacker backend reads the app ID from Aegis using that token. Identity
probes report the actual denial reason: `missing_identity`, `bad_signature`,
`unknown_kid`, `expired`, `replayed`, and `wrong_issuer`. The replay probe first
checks that its valid test identity is accepted, then reuses that same token
and expects the second decision to be denied.

## Start the dashboard

Start Aegis first on `127.0.0.1:8000`, then open a second terminal:

```bash
cd attacker
../aegis-loop/.venv/bin/python -m uvicorn app:app --host 127.0.0.1 --port 8001
```

Open <http://127.0.0.1:8001>, enter the local app integration token, and select
**Run authorization suite**. The result cards show expected/actual decisions
and the precise identity-denial reason. These probes are authorization-only;
they do not call the Victim app.

If you maintain a separate Python environment, install `attacker/requirements.txt` there before starting the service. Run the focused tests from the `attacker` directory:

```bash
../aegis-loop/.venv/bin/python -m pytest -q
```

The suite is intentionally limited to authorization checks. Realistic end-to-end testing of email/payment providers should be added only through provider test credentials and dedicated sandbox/sink services, with live mode disabled by default.
