import secrets
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, Header, HTTPException, Query
from psycopg.errors import UniqueViolation
from pydantic import BaseModel, Field, field_validator

from aegis_loop import blue_agent, database, event_log, events, policy, red_agent
from aegis_loop.auth import current_user
from aegis_loop.identity import IdentityResult, decode_public_key, verify_identity

router = APIRouter(tags=["applications"])
integration_router = APIRouter(prefix="/api/integration", tags=["victim integration"])
CurrentUser = Annotated[dict[str, Any], Depends(current_user)]


def _app_token_hash(token: str) -> str:
    try:
        return database.hash_app_token(token)
    except UnicodeEncodeError:
        raise HTTPException(status_code=401, detail="Application token is invalid") from None
    except RuntimeError:
        raise HTTPException(
            status_code=503,
            detail="Aegis app-token pepper is not configured correctly",
        ) from None


class ApplicationRequest(BaseModel):
    name: str = Field(min_length=1, max_length=80)

    @field_validator("name")
    @classmethod
    def normalize_name(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("Application name cannot be blank")
        return normalized


class ToolAuthorizationRequest(BaseModel):
    tool: str = Field(min_length=1, max_length=80)
    role: Any = None
    arguments: dict[str, Any]
    sensitive_context: bool = False


class IdentityKeyRequest(BaseModel):
    kid: str = Field(min_length=1, max_length=80, pattern=r"^[A-Za-z0-9._-]+$")
    public_key: str = Field(min_length=40, max_length=64)

    @field_validator("public_key")
    @classmethod
    def validate_public_key(cls, value: str) -> str:
        try:
            decode_public_key(value)
        except (ValueError, UnicodeError) as exc:
            raise ValueError("public_key must be a base64url Ed25519 public key") from exc
        return value


class ProposalDecisionRequest(BaseModel):
    approved: bool


def _owner_app(app_id: UUID, user: dict[str, Any]) -> dict[str, Any]:
    app = database.get_owned_app(str(user["id"]), str(app_id))
    if app is None:
        raise HTTPException(status_code=404, detail="Application not found")
    return app


def _app_token(authorization: str | None) -> dict[str, Any]:
    scheme, _, token = (authorization or "").partition(" ")
    if scheme.casefold() != "bearer" or not token:
        raise HTTPException(status_code=401, detail="Application token required")
    token_hash = _app_token_hash(token)
    app = database.authenticate_app(token[:12], token_hash)
    if app is None:
        raise HTTPException(status_code=401, detail="Application token is invalid")
    return app


@integration_router.get("/context")
def integration_context(
    authorization: str | None = Header(default=None),
) -> dict[str, str]:
    app = _app_token(authorization)
    return {"app_id": str(app["id"])}


@router.post("/api/apps")
def register_application(
    request: ApplicationRequest,
    user: CurrentUser,
) -> dict[str, Any]:
    token = secrets.token_urlsafe(32)
    app = database.create_app(
        str(user["id"]),
        request.name.strip(),
        _app_token_hash(token),
        token[:12],
    )
    return {
        "application": app,
        "integration_token": token,
        "warning": "Copy this token to the victim app environment now; it is shown once.",
    }


@router.get("/api/apps")
def applications(
    user: CurrentUser,
) -> list[dict[str, Any]]:
    return database.list_apps(str(user["id"]))


@router.post("/api/apps/{app_id}/token/rotate")
def rotate_application_token(
    app_id: UUID,
    user: CurrentUser,
) -> dict[str, Any]:
    _owner_app(app_id, user)
    token = secrets.token_urlsafe(32)
    app = database.rotate_app_token(
        str(user["id"]),
        str(app_id),
        _app_token_hash(token),
        token[:12],
    )
    if app is None:
        raise HTTPException(status_code=404, detail="Application not found")
    database.record_security_audit(
        app_id=str(app_id),
        actor_id=str(user["id"]),
        actor_label=str(user["email"]),
        action="app_token_rotated",
        details={"token_prefix": app["token_prefix"]},
    )
    return {
        "application": app,
        "integration_token": token,
        "warning": "Copy this token now; the previous token stopped working immediately.",
    }


@router.post("/api/apps/{app_id}/token/revoke")
def revoke_application_token(
    app_id: UUID,
    user: CurrentUser,
) -> dict[str, str]:
    current_app = _owner_app(app_id, user)
    app = database.revoke_app_token(str(user["id"]), str(app_id))
    database.record_security_audit(
        app_id=str(app_id),
        actor_id=str(user["id"]),
        actor_label=str(user["email"]),
        action="app_token_revoked",
        details={"token_prefix": current_app["token_prefix"]},
    )
    return {"status": "revoked" if app else "already_revoked"}


@router.get("/api/apps/{app_id}/identity-keys")
def identity_keys(app_id: UUID, user: CurrentUser) -> list[dict[str, Any]]:
    _owner_app(app_id, user)
    return database.list_identity_keys(str(app_id))


@router.post("/api/apps/{app_id}/identity-keys")
def register_identity_key(
    app_id: UUID,
    request: IdentityKeyRequest,
    user: CurrentUser,
) -> dict[str, Any]:
    _owner_app(app_id, user)
    try:
        key = database.add_identity_key(
            str(app_id),
            request.kid,
            request.public_key,
            str(user["id"]),
        )
    except UniqueViolation as exc:
        raise HTTPException(status_code=409, detail="Key ID is already registered") from exc
    database.record_security_audit(
        app_id=str(app_id),
        actor_id=str(user["id"]),
        actor_label=str(user["email"]),
        action="identity_key_added",
        details={"kid": request.kid},
    )
    return key


@router.post("/api/apps/{app_id}/identity-keys/{kid}/deactivate")
def deactivate_identity_key(
    app_id: UUID,
    kid: str,
    user: CurrentUser,
) -> dict[str, str]:
    _owner_app(app_id, user)
    if not database.deactivate_identity_key(str(app_id), kid):
        raise HTTPException(status_code=404, detail="Active identity key not found")
    database.record_security_audit(
        app_id=str(app_id),
        actor_id=str(user["id"]),
        actor_label=str(user["email"]),
        action="identity_key_deactivated",
        details={"kid": kid},
    )
    return {"status": "deactivated", "kid": kid}


@router.get("/api/apps/{app_id}/events")
def application_events(
    app_id: UUID,
    user: CurrentUser,
    limit: int = Query(default=100, ge=1, le=500),
) -> list[dict[str, Any]]:
    _owner_app(app_id, user)
    return database.list_events(str(user["id"]), str(app_id), limit)


@router.get("/api/apps/{app_id}/incidents")
def application_incidents(
    app_id: UUID,
    user: CurrentUser,
    limit: int = Query(default=100, ge=1, le=500),
) -> list[dict[str, Any]]:
    _owner_app(app_id, user)
    return database.list_incidents(str(user["id"]), str(app_id), limit)


@router.get("/api/apps/{app_id}/runs")
def application_runs(
    app_id: UUID,
    user: CurrentUser,
) -> list[dict[str, Any]]:
    _owner_app(app_id, user)
    return database.list_runs(str(user["id"]), str(app_id))


@router.get("/api/apps/{app_id}/patches")
def application_patches(
    app_id: UUID,
    user: CurrentUser,
) -> list[dict[str, Any]]:
    _owner_app(app_id, user)
    return database.list_proposals(str(user["id"]), str(app_id))


@router.post("/api/apps/{app_id}/red/verify")
def verify_active_policy(
    app_id: UUID,
    user: CurrentUser,
) -> dict[str, Any]:
    app = _owner_app(app_id, user)
    owner_id = str(user["id"])
    app_id_text = str(app_id)
    run_id = database.create_run(owner_id, app_id_text, "red_policy_verification")
    report = red_agent.verify_policy(app["active_policy"])
    for result in report["results"]:
        database.append_probe_result(
            owner_id=owner_id,
            app_id=app_id_text,
            run_id=run_id,
            probe_id=result["id"],
            category=result["category"],
            passed=result["passed"],
            detail=result["reason"],
        )
    database.complete_run(
        run_id,
        "passed" if report["summary"]["passed"] else "failed",
        report["summary"],
    )
    return {"run_id": run_id, **report}


@router.post("/api/apps/{app_id}/patches/{proposal_id}/decision")
def decide_patch(
    app_id: UUID,
    proposal_id: UUID,
    decision: ProposalDecisionRequest,
    user: CurrentUser,
) -> dict[str, str]:
    owner_id = str(user["id"])
    app_id_text = str(app_id)
    _owner_app(app_id, user)
    proposal = database.get_owned_proposal(
        owner_id,
        app_id_text,
        str(proposal_id),
    )
    if proposal is None or proposal["status"] != "pending":
        raise HTTPException(status_code=404, detail="Pending patch not found")
    verification = proposal["patch"].get("red_verification", {})
    if decision.approved:
        if not verification.get("summary", {}).get("passed"):
            raise HTTPException(
                status_code=409,
                detail="Patch cannot be approved until all Red and benign checks pass",
            )
        policy_version = database.approve_proposal(
            str(proposal_id), owner_id, app_id_text
        )
        event_log.append_event(
            actor="blue",
            event_type="policy_applied",
            run_id=str(proposal_id),
            data={
                "app_id": app_id_text,
                "policy_id": str(proposal_id),
                "rule_ids": [],
                "legacy_policy_fields": list(proposal["patch"].get("change", {})),
                "version": policy_version,
            },
        )
        status = "approved"
    else:
        status = "rejected"
        database.decide_proposal(str(proposal_id), owner_id, app_id_text, status)
    return {"status": status}


@integration_router.post("/authorize")
def authorize_tool_action(
    request: ToolAuthorizationRequest,
    authorization: str | None = Header(default=None),
    identity_token: str | None = Header(default=None, alias="X-Aegis-Identity"),
) -> dict[str, Any]:
    app = _app_token(authorization)
    app_id = str(app["id"])
    owner_id = str(app["owner_id"])
    identity = verify_identity(
        identity_token,
        app_id=app_id,
        active_keys=database.active_identity_keys(app_id),
    )
    if identity.status == "valid":
        if identity.jti is None or identity.expires_at is None:
            identity = IdentityResult("invalid_claims")
        elif not database.consume_identity_jti(
            app_id, identity.jti, identity.expires_at
        ):
            identity = IdentityResult("replayed")
    safe_arguments = policy.sanitize_registered_arguments(request.arguments)
    if identity.status != "valid":
        decision = {"allowed": False, "reason": identity.status}
        event = database.append_event(
            owner_id=owner_id,
            app_id=app_id,
            tool=request.tool,
            role="",
            allowed=False,
            reason=identity.status,
            arguments=safe_arguments,
            identity_status=identity.status,
            role_mismatch=False,
        )
        event_id = str(event["id"])
        public_event = {
            **event,
            "id": event_id,
            "app_id": app_id,
            "run_id": None,
            "arguments": safe_arguments,
            "created_at": event["created_at"].isoformat(),
        }
        event_log.append_event(
            actor="victim",
            event_type="tool_call",
            run_id="live",
            data={
                "app_id": app_id,
                "tool": request.tool,
                "args": safe_arguments,
                "kind": (
                    "sink"
                    if request.tool in {"send_email", "post_chat", "pay_invoice"}
                    else "source"
                ),
                "channel": (
                    "payment"
                    if request.tool == "pay_invoice"
                    else "outbound"
                    if request.tool in {"send_email", "post_chat"}
                    else None
                ),
                "verified_user_id": None,
                "verified_role": None,
                "identity_status": identity.status,
                "role_mismatch": False,
            },
        )
        incident = {
            "event_id": event_id,
            "app_id": app_id,
            "tool": request.tool,
            "role": "",
            "reason": identity.status,
            "severity": event["incident_severity"],
            "status": "contained",
            "action": "tool call denied before execution",
            "timestamp": public_event["created_at"],
        }
        event_log.append_event(
            actor="guard",
            event_type="decision",
            run_id="live",
            data={
                "app_id": app_id,
                "tool": request.tool,
                "verdict": "deny",
                "rule_id": f"identity_{identity.status}",
                "explain": identity.status,
                "verified_user_id": None,
                "verified_role": None,
                "identity_status": identity.status,
                "role_mismatch": False,
            },
        )
        events.publish_event(
            {
                "type": "tool_event",
                "owner_id": owner_id,
                "app_id": app_id,
                "event": public_event,
                "incident": incident,
            }
        )
        return {
            "event_id": event_id,
            "allowed": False,
            "reason": identity.status,
            "reason_code": identity.status,
            "identity_status": identity.status,
            "role_mismatch": False,
            "incident": incident,
            "blue_analysis": None,
            "red_verification": None,
            "patch_proposal": None,
        }

    verified_role = identity.role
    if verified_role is None or identity.user_id is None:
        raise RuntimeError("Validated identity is missing required claims")
    role_mismatch = (
        "role" in request.model_fields_set and request.role != verified_role
    )
    decision = policy.authorize_registered_tool(
        request.tool,
        request.arguments,
        verified_role,
        app["active_policy"],
        request.sensitive_context,
    )
    tool_kinds = {
        "read_inbox": ("source", None),
        "read_file": ("source", None),
        "get_record": ("source", None),
        "currency_lookup": ("source", None),
        "send_email": ("sink", "outbound"),
        "post_chat": ("sink", "outbound"),
        "pay_invoice": ("sink", "payment"),
    }
    kind, channel = tool_kinds.get(request.tool, ("sink", None))
    live_run_id = "live"
    event_log.append_event(
        actor="victim",
        event_type="tool_call",
        run_id=live_run_id,
        data={
            "app_id": app_id,
            "tool": request.tool,
            "args": safe_arguments,
            "kind": kind,
            "channel": channel,
            "verified_user_id": identity.user_id,
            "verified_role": verified_role,
            "identity_status": identity.status,
            "role_mismatch": role_mismatch,
        },
    )
    event_log.append_event(
        actor="guard",
        event_type="decision",
        run_id=live_run_id,
        data={
            "app_id": app_id,
            "tool": request.tool,
            "verdict": "allow" if decision["allowed"] else "deny",
            "rule_id": None,
            "explain": decision["reason"],
            "verified_user_id": identity.user_id,
            "verified_role": verified_role,
            "identity_status": identity.status,
            "role_mismatch": role_mismatch,
        },
    )
    event = database.append_event(
        owner_id=owner_id,
        app_id=app_id,
        tool=request.tool,
        role=verified_role,
        allowed=decision["allowed"],
        reason=decision["reason"],
        arguments=safe_arguments,
        verified_user_id=identity.user_id,
        identity_status=identity.status,
        role_mismatch=role_mismatch,
    )
    event_id = str(event["id"])
    proposal = None
    blue_analysis = None
    red_report = None
    if not decision["allowed"]:
        event_log.append_event(
            actor="incident",
            event_type="incident_detected",
            run_id=live_run_id,
            data={
                "app_id": app_id,
                "incident_id": event_id,
                "detector": "policy_denial",
                "severity": event["incident_severity"],
                "entry_hint": decision["reason"],
            },
        )
        run_id = database.create_run(owner_id, app_id, "blue_patch_verification")
        attack_context = {
            "tool": request.tool,
            "arguments": request.arguments,
            "role": verified_role,
            "sensitive_context": request.sensitive_context,
        }
        patch = blue_agent.propose_policy_patch(
            tool=request.tool,
            arguments=request.arguments,
            reason=decision["reason"],
            app_policy=app["active_policy"],
            sensitive_context=request.sensitive_context,
        )
        if patch is not None:
            blue_analysis = patch["analysis"]
            event_log.append_event(
                actor="blue",
                event_type="policy_proposed",
                run_id=run_id,
                data={
                    "app_id": app_id,
                    "policy_id": run_id,
                    "rules": [],
                    "origin_attack_id": event_id,
                    "template": "deterministic_policy_template",
                    "legacy_policy_change": patch["change"],
                },
            )
            red_report = red_agent.verify_policy(patch["candidate_policy"])
            adaptive_report = red_agent.verify_adaptive_policy(
                active_policy=app["active_policy"],
                candidate_policy=patch["candidate_policy"],
                incident=attack_context,
                policy_change=patch["change"],
            )
            red_report["adaptive"] = adaptive_report
            red_report["summary"]["passed"] = (
                red_report["summary"]["passed"]
                and adaptive_report["summary"]["passed"]
            )
            for result in red_report["results"]:
                database.append_probe_result(
                    owner_id=owner_id,
                    app_id=app_id,
                    run_id=run_id,
                    probe_id=result["id"],
                    category=result["category"],
                    passed=result["passed"],
                    detail=result["reason"],
                )
            for result in adaptive_report["results"]:
                database.append_probe_result(
                    owner_id=owner_id,
                    app_id=app_id,
                    run_id=run_id,
                    probe_id=result["id"],
                    category=f"adaptive_{result['category']}",
                    passed=result["passed"],
                    detail=result["reason"],
                )
                if result["category"] == "attack":
                    event_log.append_event(
                        actor="red",
                        event_type="attack_attempt",
                        run_id=run_id,
                        data={
                            "app_id": app_id,
                            "attack_id": result["id"],
                            "strategy": "incident_replay_and_mutation",
                            "goal": request.tool,
                            "class": "adaptive_policy_probe",
                            "run_index": 1,
                            "note": "attack-specific verification",
                        },
                    )
                    event_log.append_event(
                        actor="red",
                        event_type="attack_result",
                        run_id=run_id,
                        data={
                            "app_id": app_id,
                            "attack_id": result["id"],
                            "strategy": "incident_replay_and_mutation",
                            "goal": request.tool,
                            "result": "blocked" if result["passed"] else "exploited",
                            "successes": 0 if result["passed"] else 1,
                            "runs": 1,
                            "evidence": result["reason"],
                            "session_ids": [],
                        },
                    )
            gates = [
                {
                    "gate": "baseline_attack_probes",
                    "ok": red_report["summary"]["attacks_blocked"]
                    == red_report["summary"]["attacks_total"],
                    "reason": (
                        f"{red_report['summary']['attacks_blocked']}/"
                        f"{red_report['summary']['attacks_total']} blocked"
                    ),
                },
                {
                    "gate": "baseline_benign_controls",
                    "ok": red_report["summary"]["benign_passed"]
                    == red_report["summary"]["benign_total"],
                    "reason": (
                        f"{red_report['summary']['benign_passed']}/"
                        f"{red_report['summary']['benign_total']} allowed"
                    ),
                },
                {
                    "gate": "incident_derived_red_checks",
                    "ok": adaptive_report["summary"]["passed"],
                    "reason": (
                        f"{adaptive_report['summary']['attacks_passed']}/"
                        f"{adaptive_report['summary']['attacks_total']} attacks and "
                        f"{adaptive_report['summary']['benign_passed']}/"
                        f"{adaptive_report['summary']['benign_total']} benign controls"
                    ),
                },
            ]
            event_log.append_event(
                actor="blue",
                event_type="policy_validated",
                run_id=run_id,
                data={"app_id": app_id, "policy_id": run_id, "gates": gates},
            )
            status = "passed" if red_report["summary"]["passed"] else "failed"
            patch["red_verification"] = red_report
            database.complete_run(
                run_id,
                status,
                {
                    **red_report["summary"],
                    "adaptive": adaptive_report["summary"],
                    "adaptive_results": adaptive_report["results"],
                    "counterfactual": adaptive_report["counterfactual"],
                    "blue_analysis": blue_analysis,
                },
            )
            if red_report["summary"]["passed"]:
                proposal = database.create_patch_proposal(
                    owner_id=owner_id,
                    app_id=app_id,
                    incident_id=event_id,
                    run_id=run_id,
                    finding=patch["finding"],
                    patch=patch,
                )
        else:
            blue_analysis = [
                {
                    "step": "Observe",
                    "detail": f"Aegis denied {request.tool}: {decision['reason']}.",
                },
                {
                    "step": "Map to policy",
                    "detail": "Blue checked its supported app-policy templates.",
                },
                {
                    "step": "No candidate",
                    "detail": (
                        "No supported new rule was available; the matching rule may "
                        "already exist or this action has no supported template."
                    ),
                },
            ]
            database.complete_run(
                run_id,
                "no_supported_patch",
                {
                    "passed": False,
                    "reason": "No supported Blue rule template",
                    "blue_analysis": blue_analysis,
                },
            )

    public_event = {
        **event,
        "id": event_id,
        "app_id": app_id,
        "run_id": None,
        "arguments": safe_arguments,
        "created_at": event["created_at"].isoformat(),
    }
    incident = None
    if not decision["allowed"]:
        incident = {
            "event_id": event_id,
            "app_id": app_id,
            "tool": request.tool,
            "role": verified_role,
            "reason": decision["reason"],
            "severity": event["incident_severity"],
            "status": "contained",
            "action": "tool call denied before execution",
            "timestamp": public_event["created_at"],
        }
    events.publish_event(
        {
            "type": "tool_event",
            "owner_id": owner_id,
            "app_id": app_id,
            "event": public_event,
            "incident": incident,
        }
    )
    return {
        "event_id": event_id,
        "allowed": decision["allowed"],
        "reason": decision["reason"],
        "reason_code": "allow" if decision["allowed"] else "policy_denied",
        "identity_status": identity.status,
        "verified_user_id": identity.user_id,
        "verified_role": verified_role,
        "role_mismatch": role_mismatch,
        "incident": incident,
        "blue_analysis": blue_analysis,
        "red_verification": red_report,
        "patch_proposal": proposal,
    }
