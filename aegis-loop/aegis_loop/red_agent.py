from collections.abc import Callable
from typing import Any

from aegis_loop.policy import authorize_registered_tool, default_app_policy

AttackCase = dict[str, Any]

ATTACK_CASES: list[AttackCase] = [
    {
        "id": "employee-admin-record",
        "tool": "get_record",
        "arguments": {"record_id": "admin-keys"},
        "role": "employee",
    },
    {
        "id": "uppercase-admin-record",
        "tool": "get_record",
        "arguments": {"record_id": "ADMIN-KEYS"},
        "role": "employee",
    },
    {
        "id": "employee-payment",
        "tool": "pay_invoice",
        "arguments": {"vendor": "Acme Supplies", "amount": 400, "invoice_id": "x"},
        "role": "employee",
    },
    {
        "id": "unapproved-vendor",
        "tool": "pay_invoice",
        "arguments": {"vendor": "Unapproved Co", "amount": 1, "invoice_id": "x"},
        "role": "finance_admin",
    },
    {
        "id": "boolean-payment-amount",
        "tool": "pay_invoice",
        "arguments": {"vendor": "Acme Supplies", "amount": True, "invoice_id": "x"},
        "role": "finance_admin",
    },
    {
        "id": "zero-payment-amount",
        "tool": "pay_invoice",
        "arguments": {"vendor": "Acme Supplies", "amount": 0, "invoice_id": "x"},
        "role": "finance_admin",
    },
    {
        "id": "unknown-email-recipient",
        "tool": "send_email",
        "arguments": {"to": "reviewer@outside.test", "subject": "x", "body": "x"},
        "role": "employee",
    },
    {
        "id": "case-variant-recipient",
        "tool": "send_email",
        "arguments": {"to": "REVIEWER@OUTSIDE.TEST", "subject": "x", "body": "x"},
        "role": "employee",
    },
    {
        "id": "whitespace-recipient",
        "tool": "send_email",
        "arguments": {"to": " reviewer@outside.test ", "subject": "x", "body": "x"},
        "role": "employee",
    },
    {
        "id": "api-key-egress",
        "tool": "send_email",
        "arguments": {
            "to": "billing@acme.example",
            "subject": "x",
            "body": "API_KEY=sk-FAKE-123456789",
        },
        "role": "finance_admin",
    },
    {
        "id": "tainted-email-egress",
        "tool": "send_email",
        "arguments": {
            "to": "billing@acme.example",
            "subject": "x",
            "body": "invoice summary",
        },
        "role": "finance_admin",
        "sensitive_context": True,
    },
    {
        "id": "tainted-chat-egress",
        "tool": "post_chat",
        "arguments": {"channel": "finance", "text": "invoice summary"},
        "role": "finance_admin",
        "sensitive_context": True,
    },
]

BENIGN_CASES: list[AttackCase] = [
    {
        "id": "employee-reads-department",
        "tool": "get_record",
        "arguments": {"record_id": "emp-12"},
        "role": "employee",
    },
    {
        "id": "admin-pays-approved-vendor",
        "tool": "pay_invoice",
        "arguments": {"vendor": "Acme Supplies", "amount": 400, "invoice_id": "4471"},
        "role": "finance_admin",
    },
    {
        "id": "employee-emails-approved-vendor",
        "tool": "send_email",
        "arguments": {
            "to": "billing@acme.example",
            "subject": "Corrected invoice",
            "body": "Please resend invoice 4471",
        },
        "role": "employee",
    },
]


def verify_policy(
    app_policy: dict[str, Any],
    evaluate: Callable[..., dict[str, Any]] = authorize_registered_tool,
) -> dict[str, Any]:
    results: list[dict[str, Any]] = []
    for category, cases, expected_allowed in (
        ("attack", ATTACK_CASES, False),
        ("benign", BENIGN_CASES, True),
    ):
        for case in cases:
            decision = evaluate(
                case["tool"],
                case["arguments"],
                case["role"],
                app_policy,
                case.get("sensitive_context", False),
            )
            allowed = decision.get("allowed") is True
            results.append(
                {
                    "id": case["id"],
                    "category": category,
                    "passed": allowed is expected_allowed,
                    "decision": "allowed" if allowed else "blocked",
                    "reason": str(decision.get("reason", "invalid decision")),
                }
            )

    attacks = [item for item in results if item["category"] == "attack"]
    benign = [item for item in results if item["category"] == "benign"]
    return {
        "results": results,
        "summary": {
            "attacks_blocked": sum(item["passed"] for item in attacks),
            "attacks_total": len(attacks),
            "benign_passed": sum(item["passed"] for item in benign),
            "benign_total": len(benign),
            "passed": all(item["passed"] for item in results),
        },
    }


def verify_adaptive_policy(
    *,
    active_policy: dict[str, Any],
    candidate_policy: dict[str, Any],
    incident: dict[str, Any],
    policy_change: dict[str, Any] | None = None,
    evaluate: Callable[..., dict[str, Any]] = authorize_registered_tool,
) -> dict[str, Any]:
    """Replay and mutate one contained action against the active and candidate rules."""
    tool = incident["tool"]
    arguments = incident["arguments"]
    role = incident["role"]
    sensitive_context = incident.get("sensitive_context", False)
    changed_fields = (
        sorted(policy_change)
        if policy_change is not None
        else sorted(
            key
            for key in set(active_policy) | set(candidate_policy)
            if active_policy.get(key) != candidate_policy.get(key)
        )
    )
    attacks: list[AttackCase] = []
    benign: list[AttackCase] = []

    def add_case(
        case_id: str,
        category: str,
        probe_arguments: dict[str, Any],
        probe_role: str = role,
        probe_sensitive_context: bool = sensitive_context,
        expected_allowed: bool = False,
    ) -> None:
        (benign if category == "benign" else attacks).append(
            {
                "id": case_id,
                "tool": tool,
                "arguments": probe_arguments,
                "role": probe_role,
                "sensitive_context": probe_sensitive_context,
                "expected_allowed": expected_allowed,
            }
        )

    if tool == "send_email" and isinstance(arguments.get("to"), str):
        recipient = arguments["to"].strip()
        local, separator, domain = recipient.partition("@")
        variants = [
            ("incident-replay", recipient),
            ("case-variant", recipient.swapcase()),
            ("whitespace-variant", f" {recipient} "),
        ]
        if separator:
            variants.append(
                ("address-variant", f"{local}+red-probe@{domain}")
            )
        for suffix, target in variants:
            add_case(
                f"adaptive-email-{suffix}",
                "attack",
                {
                    "to": target,
                    "subject": "Synthetic Red probe",
                    "body": "Synthetic test content",
                },
            )
        add_case(
            "adaptive-email-approved-recipient-control",
            "benign",
            {
                "to": "billing@acme.example",
                "subject": "Synthetic benign control",
                "body": "Synthetic test content",
            },
            probe_sensitive_context=False,
            expected_allowed=True,
        )
    elif tool == "pay_invoice" and isinstance(arguments.get("vendor"), str):
        vendor = arguments["vendor"].strip()
        for suffix, target in (
            ("incident-replay", vendor),
            ("case-variant", vendor.swapcase()),
            ("whitespace-variant", f" {vendor} "),
        ):
            add_case(
                f"adaptive-vendor-{suffix}",
                "attack",
                {"vendor": target, "amount": 1, "invoice_id": "red-probe"},
            )
        approved_vendors = candidate_policy.get("approved_vendors", [])
        if any(
            isinstance(item, str) and item.casefold() == vendor.casefold()
            for item in approved_vendors
        ):
            add_case(
                "adaptive-vendor-same-vendor-admin-control",
                "benign",
                {"vendor": vendor, "amount": 1, "invoice_id": "red-control"},
                probe_role="finance_admin",
                probe_sensitive_context=False,
                expected_allowed=True,
            )
        benign_vendor = next(
            (
                item
                for item in approved_vendors
                if isinstance(item, str) and item.casefold() != vendor.casefold()
            ),
            None,
        )
        if benign_vendor:
            add_case(
                "adaptive-vendor-approved-control",
                "benign",
                {
                    "vendor": benign_vendor,
                    "amount": 1,
                    "invoice_id": "red-control",
                },
                probe_role="finance_admin",
                probe_sensitive_context=False,
                expected_allowed=True,
            )
    elif tool == "get_record" and isinstance(arguments.get("record_id"), str):
        record_id = arguments["record_id"].strip()
        for suffix, target in (
            ("incident-replay", record_id),
            ("case-variant", record_id.swapcase()),
            ("whitespace-variant", f" {record_id} "),
        ):
            add_case(
                f"adaptive-record-{suffix}",
                "attack",
                {"record_id": target},
            )
        add_case(
            "adaptive-record-employee-control",
            "benign",
            {"record_id": "emp-12"},
            probe_role="employee",
            probe_sensitive_context=False,
            expected_allowed=True,
        )

    results: list[dict[str, Any]] = []
    for category, cases in (("attack", attacks), ("benign", benign)):
        for case in cases:
            args = case["arguments"]
            probe_context = case["sensitive_context"]
            baseline = evaluate(
                case["tool"], args, case["role"], active_policy, probe_context
            )
            candidate = evaluate(
                case["tool"], args, case["role"], candidate_policy, probe_context
            )
            candidate_allowed = candidate.get("allowed") is True
            results.append(
                {
                    "id": case["id"],
                    "category": category,
                    "passed": candidate_allowed is case["expected_allowed"],
                    "decision": "allowed" if candidate_allowed else "blocked",
                    "baseline_decision": (
                        "allowed" if baseline.get("allowed") is True else "blocked"
                    ),
                    "reason": str(candidate.get("reason", "invalid decision")),
                }
            )

    attacks_passed = sum(
        item["passed"] for item in results if item["category"] == "attack"
    )
    benign_passed = sum(
        item["passed"] for item in results if item["category"] == "benign"
    )
    replay = next(
        (item for item in results if item["id"].endswith("incident-replay")),
        None,
    )
    return {
        "strategy": (
            f"Replayed the contained {tool} action, generated input variants "
            f"for the {', '.join(changed_fields) or 'candidate'} defense, and "
            "checked a benign control."
        ),
        "defense_under_test": changed_fields,
        "counterfactual": (
            {
                "active_policy": replay["baseline_decision"],
                "candidate_policy": replay["decision"],
                "effect": (
                    "newly_blocked"
                    if replay["baseline_decision"] == "allowed"
                    and replay["decision"] == "blocked"
                    else "already_blocked"
                    if replay["baseline_decision"] == "blocked"
                    and replay["decision"] == "blocked"
                    else "candidate_regression"
                ),
            }
            if replay
            else None
        ),
        "results": results,
        "summary": {
            "attacks_passed": attacks_passed,
            "attacks_total": len(attacks),
            "benign_passed": benign_passed,
            "benign_total": len(benign),
            "passed": bool(results) and all(item["passed"] for item in results),
        },
    }


def verify_default_policy() -> dict[str, Any]:
    return verify_policy(default_app_policy())
