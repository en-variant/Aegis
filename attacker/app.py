from __future__ import annotations

import base64
import json
import os
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit
from uuid import uuid4

import httpx
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator
from starlette.middleware.trustedhost import TrustedHostMiddleware

ROOT = Path(__file__).resolve().parent
INTEGRATION_PATH = "/api/integration/authorize"


class RunRequest(BaseModel):
    aegis_url: str = Field(min_length=1, max_length=256)
    app_token: str = Field(min_length=20, max_length=512, repr=False)

    @field_validator("aegis_url")
    @classmethod
    def validate_local_aegis_url(cls, value: str) -> str:
        parsed = urlsplit(value)
        if (
            parsed.scheme != "http"
            or parsed.hostname not in {"127.0.0.1", "localhost"}
            or parsed.port != 8000
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError(
                "Only the local Aegis service at http://127.0.0.1:8000 "
                "or http://localhost:8000 is supported"
            )
        return f"http://{parsed.hostname}:8000"


CASES: tuple[dict[str, Any], ...] = (
    {
        "id": "employee-payment",
        "label": "Employee attempts a payment",
        "description": "A non-admin role attempts a synthetic payment.",
        "expected_allowed": False,
        "request": {
            "tool": "pay_invoice",
            "role": "employee",
            "arguments": {
                "vendor": "Acme Supplies",
                "amount": 25,
                "invoice_id": "ATTACK-EMPLOYEE-1",
            },
        },
    },
    {
        "id": "admin-unapproved-vendor",
        "label": "Admin uses an unapproved vendor",
        "description": "An admin role attempts a payment to a fake vendor.",
        "expected_allowed": False,
        "request": {
            "tool": "pay_invoice",
            "role": "finance_admin",
            "arguments": {
                "vendor": "Synthetic Unapproved Vendor",
                "amount": 25,
                "invoice_id": "ATTACK-VENDOR-1",
            },
        },
    },
    {
        "id": "unknown-email-recipient",
        "label": "Email to an unapproved address",
        "description": "A synthetic outbound message targets a reserved fake domain.",
        "expected_allowed": False,
        "request": {
            "tool": "send_email",
            "role": "employee",
            "arguments": {
                "to": "aegis-test@outside.invalid",
                "subject": "Synthetic Aegis test",
                "body": "This authorization probe must not send an email.",
            },
        },
    },
    {
        "id": "sensitive-egress",
        "label": "Sensitive context sent externally",
        "description": "A benign fake message is checked with sensitive context enabled.",
        "expected_allowed": False,
        "request": {
            "tool": "send_email",
            "role": "employee",
            "sensitive_context": True,
            "arguments": {
                "to": "billing@acme.example",
                "subject": "Synthetic sensitive-context test",
                "body": "Placeholder only; contains no real or fake credential.",
            },
        },
    },
    {
        "id": "approved-payment-control",
        "label": "Approved vendor control",
        "description": "An approved-vendor authorization control should be allowed.",
        "expected_allowed": True,
        "request": {
            "tool": "pay_invoice",
            "role": "finance_admin",
            "arguments": {
                "vendor": "Acme Supplies",
                "amount": 25,
                "invoice_id": "CONTROL-APPROVED-1",
            },
        },
    },
)

IDENTITY_CASES: tuple[dict[str, str], ...] = (
    {
        "id": "missing-identity",
        "label": "No identity token",
        "description": "A valid app token without a user identity must be denied.",
    },
    {
        "id": "tampered-role",
        "label": "Role claim changed without re-signing",
        "description": "A modified role claim with the old signature must be denied.",
    },
    {
        "id": "unregistered-key",
        "label": "Identity signed by an unregistered key",
        "description": "A valid EdDSA signature from an unknown kid must be denied.",
    },
    {
        "id": "expired-identity",
        "label": "Expired identity token",
        "description": "A correctly signed but expired identity token must be denied.",
    },
    {
        "id": "replayed-identity",
        "label": "Replayed identity token",
        "description": "A token allowed once must be rejected when reused.",
    },
    {
        "id": "wrong-app-issuer",
        "label": "Identity token for a different app",
        "description": "A signed token with a different app issuer must be denied.",
    },
)


def _load_test_signer() -> tuple[Ed25519PrivateKey, str]:
    path = os.environ.get("AEGIS_TEST_IDENTITY_PRIVATE_KEY", "")
    kid = os.environ.get("AEGIS_TEST_IDENTITY_KID", "")
    if not path or not kid:
        raise HTTPException(
            status_code=503,
            detail=(
                "Configure AEGIS_TEST_IDENTITY_PRIVATE_KEY and "
                "AEGIS_TEST_IDENTITY_KID for identity-forgery probes."
            ),
        )
    try:
        key = serialization.load_pem_private_key(
            Path(path).expanduser().read_bytes(),
            password=None,
        )
    except (OSError, ValueError):
        raise HTTPException(
            status_code=503,
            detail="The configured Attacker identity key could not be loaded.",
        ) from None
    if not isinstance(key, Ed25519PrivateKey):
        raise HTTPException(
            status_code=503,
            detail="The configured Attacker identity key must be Ed25519.",
        )
    return key, kid


def _identity_token(
    key: Ed25519PrivateKey,
    kid: str,
    *,
    issuer: str,
    role: str = "employee",
    issued_at: int | None = None,
    expires_at: int | None = None,
) -> str:
    now = int(time.time())
    return jwt.encode(
        {
            "iss": issuer,
            "sub": "attacker-lab-test-user",
            "role": role,
            "aud": "aegis",
            "iat": now if issued_at is None else issued_at,
            "exp": now + 120 if expires_at is None else expires_at,
            "jti": uuid4().hex,
        },
        key,
        algorithm="EdDSA",
        headers={"kid": kid},
    )


def _tamper_role(token: str, role: str) -> str:
    header, payload, signature = token.split(".")
    padded = payload + "=" * (-len(payload) % 4)
    claims = json.loads(base64.urlsafe_b64decode(padded))
    claims["role"] = role
    changed_payload = (
        base64.urlsafe_b64encode(
            json.dumps(claims, separators=(",", ":")).encode("utf-8")
        )
        .decode("ascii")
        .rstrip("=")
    )
    return f"{header}.{changed_payload}.{signature}"


app = FastAPI(title="Aegis Attacker Lab", version="0.1.0")
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=["127.0.0.1", "localhost", "testserver"],
)
app.mount("/assets", StaticFiles(directory=ROOT / "web"), name="attacker-assets")


@app.middleware("http")
async def require_local_browser_origin(request: Request, call_next):
    origin = request.headers.get("origin")
    if origin is not None and origin not in {
        "http://127.0.0.1:8001",
        "http://localhost:8001",
    }:
        return JSONResponse(
            status_code=403,
            content={"detail": "Only the local attacker UI is allowed"},
        )
    return await call_next(request)


@app.get("/")
def attacker_dashboard() -> FileResponse:
    return FileResponse(ROOT / "web" / "index.html")


@app.get("/api/cases")
def list_cases() -> list[dict[str, str]]:
    standard_cases = [
        {
            "id": str(case["id"]),
            "label": str(case["label"]),
            "description": str(case["description"]),
        }
        for case in CASES
    ]
    return standard_cases + list(IDENTITY_CASES)


@app.post("/api/run")
def run_authorization_suite(run: RunRequest) -> dict[str, Any]:
    results: list[dict[str, Any]] = []
    endpoint = f"{run.aegis_url}{INTEGRATION_PATH}"
    headers = {"Authorization": f"Bearer {run.app_token}"}

    try:
        with httpx.Client(timeout=20, trust_env=False) as client:
            context_response = client.get(
                f"{run.aegis_url}/api/integration/context",
                headers=headers,
            )
            if context_response.status_code == 401:
                raise HTTPException(
                    status_code=401,
                    detail="Aegis rejected the app token. Check that it belongs to the selected app.",
                )
            if context_response.status_code != 200:
                raise HTTPException(
                    status_code=502,
                    detail="Aegis could not provide the selected app context.",
                )
            app_id = context_response.json().get("app_id")
            if not isinstance(app_id, str) or not app_id:
                raise HTTPException(
                    status_code=502,
                    detail="Aegis returned an invalid app context.",
                )
            registered_key, registered_kid = _load_test_signer()

            for case in CASES:
                request_body = dict(case["request"])
                identity_role = request_body.pop("role", "employee")
                identity = _identity_token(
                    registered_key,
                    registered_kid,
                    issuer=app_id,
                    role=identity_role,
                )
                case_headers = {
                    **headers,
                    "X-Aegis-Identity": identity,
                }
                response = client.post(
                    endpoint,
                    headers=case_headers,
                    json=request_body,
                )
                if response.status_code == 401:
                    raise HTTPException(
                        status_code=401,
                        detail="Aegis rejected the app token. Check that it belongs to the selected app.",
                    )
                if response.status_code != 200:
                    raise HTTPException(
                        status_code=502,
                        detail=f"Aegis returned HTTP {response.status_code} for case {case['id']}.",
                    )
                body = response.json()
                if not isinstance(body, dict) or not isinstance(body.get("allowed"), bool):
                    raise HTTPException(
                        status_code=502,
                        detail=f"Aegis returned an invalid authorization result for case {case['id']}.",
                    )
                allowed = body["allowed"]
                proposal = body.get("patch_proposal")
                incident = body.get("incident")
                results.append(
                    {
                        "id": case["id"],
                        "label": case["label"],
                        "description": case["description"],
                        "expected_allowed": case["expected_allowed"],
                        "allowed": allowed,
                        "passed": allowed is case["expected_allowed"],
                        "reason": body.get("reason", ""),
                        "incident_id": (
                            incident.get("event_id")
                            if isinstance(incident, dict)
                            else None
                        ),
                        "proposal_status": (
                            proposal.get("status")
                            if isinstance(proposal, dict)
                            else None
                        ),
                        "side_effect": "authorization only; no victim tool was executed",
                    }
                )

            def probe(
                probe_id: str,
                *,
                identity: str | None,
                expected_reason: str,
                label: str,
                description: str,
                request_body: dict[str, Any] | None = None,
            ) -> dict[str, Any]:
                probe_headers = dict(headers)
                if identity is not None:
                    probe_headers["X-Aegis-Identity"] = identity
                response = client.post(
                    endpoint,
                    headers=probe_headers,
                    json=request_body
                    or {"tool": "read_inbox", "arguments": {}},
                )
                if response.status_code != 200:
                    raise HTTPException(
                        status_code=502,
                        detail=f"Aegis returned HTTP {response.status_code} for identity case {probe_id}.",
                    )
                body = response.json()
                reason = body.get("reason_code", body.get("reason"))
                if type(body.get("allowed")) is not bool:
                    raise HTTPException(
                        status_code=502,
                        detail=f"Aegis returned an invalid identity result for case {probe_id}.",
                    )
                return {
                    "id": probe_id,
                    "label": label,
                    "description": description,
                    "expected_allowed": False,
                    "allowed": body["allowed"],
                    "passed": body["allowed"] is False
                    and reason == expected_reason,
                    "reason": reason,
                    "expected_reason": expected_reason,
                    "side_effect": "authorization only; no victim tool was executed",
                }

            identity_request = {"tool": "read_inbox", "arguments": {}}
            tampered = _tamper_role(
                _identity_token(
                    registered_key,
                    registered_kid,
                    issuer=app_id,
                    role="viewer",
                ),
                "finance_admin",
            )
            unregistered_key = Ed25519PrivateKey.generate()
            expired_at = int(time.time()) - 480
            expired = _identity_token(
                registered_key,
                registered_kid,
                issuer=app_id,
                issued_at=expired_at - 120,
                expires_at=expired_at,
            )
            replay_token = _identity_token(
                registered_key,
                registered_kid,
                issuer=app_id,
            )
            first_replay_use = client.post(
                endpoint,
                headers={**headers, "X-Aegis-Identity": replay_token},
                json=identity_request,
            )
            if first_replay_use.status_code != 200:
                raise HTTPException(
                    status_code=502,
                    detail="Aegis failed the valid identity precondition for replay testing.",
                )
            first_replay_body = first_replay_use.json()
            if first_replay_body.get("allowed") is not True:
                raise HTTPException(
                    status_code=409,
                    detail=(
                        "The valid identity replay precondition was denied. "
                        "Confirm the configured public key and test user are valid."
                    ),
                )

            identity_results = [
                probe(
                    "missing-identity",
                    identity=None,
                    expected_reason="missing_identity",
                    label=IDENTITY_CASES[0]["label"],
                    description=IDENTITY_CASES[0]["description"],
                ),
                probe(
                    "tampered-role",
                    identity=tampered,
                    expected_reason="bad_signature",
                    label=IDENTITY_CASES[1]["label"],
                    description=IDENTITY_CASES[1]["description"],
                    request_body={
                        "tool": "pay_invoice",
                        "arguments": {
                            "vendor": "Acme Supplies",
                            "amount": 25,
                            "invoice_id": "FORGED-ROLE",
                        },
                    },
                ),
                probe(
                    "unregistered-key",
                    identity=_identity_token(
                        unregistered_key,
                        "attacker-unregistered",
                        issuer=app_id,
                    ),
                    expected_reason="unknown_kid",
                    label=IDENTITY_CASES[2]["label"],
                    description=IDENTITY_CASES[2]["description"],
                ),
                probe(
                    "expired-identity",
                    identity=expired,
                    expected_reason="expired",
                    label=IDENTITY_CASES[3]["label"],
                    description=IDENTITY_CASES[3]["description"],
                ),
                probe(
                    "replayed-identity",
                    identity=replay_token,
                    expected_reason="replayed",
                    label=IDENTITY_CASES[4]["label"],
                    description=(
                        f"{IDENTITY_CASES[4]['description']} "
                        f"Initial allowed: {first_replay_body['allowed']}."
                    ),
                ),
                probe(
                    "wrong-app-issuer",
                    identity=_identity_token(
                        registered_key,
                        registered_kid,
                        issuer="different-app",
                    ),
                    expected_reason="wrong_issuer",
                    label=IDENTITY_CASES[5]["label"],
                    description=IDENTITY_CASES[5]["description"],
                ),
            ]
            results.extend(identity_results)
    except HTTPException:
        raise
    except httpx.RequestError:
        raise HTTPException(
            status_code=502,
            detail=(
                "Could not reach the local Aegis service at the configured address. "
                "Confirm Aegis is running on port 8000."
            ),
        ) from None
    except ValueError:
        raise HTTPException(
            status_code=502,
            detail="Aegis returned a response that was not valid JSON.",
        ) from None

    return {
        "run_id": str(uuid4()),
        "target": "local Aegis authorization API",
        "execution_mode": "authorization-only sandbox",
        "passed": all(result["passed"] for result in results),
        "total": len(results),
        "passed_count": sum(result["passed"] for result in results),
        "results": results,
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("app:app", host="127.0.0.1", port=8001, reload=False)
