from copy import deepcopy
from typing import Any


def propose_policy_patch(
    *,
    tool: str,
    arguments: dict[str, Any],
    reason: str,
    app_policy: dict[str, Any],
    sensitive_context: bool = False,
) -> dict[str, Any] | None:
    candidate = deepcopy(app_policy)
    if sensitive_context and tool in {"send_email", "post_chat"}:
        if candidate.get("block_sensitive_egress") is not True:
            candidate["block_sensitive_egress"] = True
            change = {"block_sensitive_egress": True}
            finding = "Block outbound actions after sensitive data was read."
        elif tool == "send_email" and isinstance(arguments.get("to"), str):
            recipient = arguments["to"].strip().casefold()
            blocked = {
                str(value).strip().casefold()
                for value in candidate.get("blocked_recipients", [])
            }
            if recipient in blocked:
                return None
            candidate.setdefault("blocked_recipients", []).append(recipient)
            change = {"blocked_recipients": candidate["blocked_recipients"]}
            finding = f"Add explicit deny rule for attempted email recipient ({reason})."
        else:
            return None
    elif tool == "send_email" and isinstance(arguments.get("to"), str):
        recipient = arguments["to"].strip().casefold()
        blocked = {
            str(value).strip().casefold()
            for value in candidate.get("blocked_recipients", [])
        }
        if recipient in blocked:
            return None
        candidate.setdefault("blocked_recipients", []).append(recipient)
        change = {"blocked_recipients": candidate["blocked_recipients"]}
        finding = f"Add explicit deny rule for attempted email recipient ({reason})."
    elif tool == "pay_invoice" and isinstance(arguments.get("vendor"), str):
        vendor = arguments["vendor"].strip()
        blocked = {
            str(value).casefold()
            for value in candidate.get("blocked_vendors", [])
        }
        if vendor.casefold() in blocked:
            return None
        candidate.setdefault("blocked_vendors", []).append(vendor)
        change = {"blocked_vendors": candidate["blocked_vendors"]}
        finding = f"Add explicit deny rule for attempted payment vendor ({reason})."
    elif tool == "get_record" and isinstance(arguments.get("record_id"), str):
        record_id = arguments["record_id"].strip()
        restricted = {
            str(value).casefold()
            for value in candidate.get("admin_only_records", [])
        }
        if record_id.casefold() in restricted:
            return None
        candidate.setdefault("admin_only_records", []).append(record_id)
        change = {"admin_only_records": candidate["admin_only_records"]}
        finding = f"Restrict the attempted record to finance_admin ({reason})."
    else:
        return None

    rule_name = next(iter(change))
    return {
        "schema_version": 1,
        "change": change,
        "candidate_policy": candidate,
        "approval_required": True,
        "finding": finding,
        "analysis": [
            {
                "step": "Observe",
                "detail": f"Aegis denied {tool}: {reason}.",
            },
            {
                "step": "Map to policy",
                "detail": f"The denial maps to the app policy field '{rule_name}'.",
            },
            {
                "step": "Propose",
                "detail": f"Candidate change: {finding}",
            },
            {
                "step": "Human review",
                "detail": "The candidate is not active unless its owner approves it.",
            },
        ],
    }
