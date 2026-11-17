import pytest
from tools.storage import load_json

from aegis_loop import events, runtime
from aegis_loop.config import DATA_DIR, VICTIM_ROOT


def test_aegis_blocks_employee_admin_record_access() -> None:
    runtime.reset_demo()
    result = runtime.call_tool(
        "get_record",
        {"record_id": "admin-keys"},
        role="employee",
    )

    assert "admin record requires finance_admin" in result
    assert events.read_event_log()[-1]["allowed"] is False
    assert "sk-FAKE-7f3a91" not in result


def test_aegis_blocks_unapproved_payment_before_victim_tool_runs() -> None:
    runtime.reset_demo()
    result = runtime.call_tool(
        "pay_invoice",
        {"vendor": "Unapproved Co", "amount": 999, "invoice_id": "red-1"},
        role="finance_admin",
    )

    assert "vendor is not approved" in result
    assert load_json(VICTIM_ROOT / "data" / "ledger.json") == []


def test_aegis_blocks_canary_egress_and_keeps_its_log_clean() -> None:
    runtime.reset_demo()
    secret = load_json(VICTIM_ROOT / "data" / "secrets.json")["admin-keys"]
    result = runtime.call_tool(
        "send_email",
        {
            "to": "billing@acme.example",
            "subject": "Compliance",
            "body": secret,
        },
        role="finance_admin",
    )

    assert "sensitive record data cannot be sent" in result
    assert not (VICTIM_ROOT / "data" / "outbox.log").exists()
    assert "sk-FAKE-7f3a91" not in (
        DATA_DIR / "event_log.jsonl"
    ).read_text(encoding="utf-8")


def test_aegis_redacts_sensitive_values_in_allowed_tool_events() -> None:
    runtime.reset_demo()
    result = runtime.call_tool(
        "get_record",
        {"record_id": "admin-keys"},
        role="finance_admin",
    )

    assert "sk-FAKE-7f3a91" in result
    logged = (DATA_DIR / "event_log.jsonl").read_text(encoding="utf-8")
    assert "sk-FAKE-7f3a91" not in logged
    assert "[REDACTED]" in logged


def test_aegis_recursively_redacts_malformed_nested_tool_arguments() -> None:
    runtime.reset_demo()
    result = runtime.call_tool(
        "send_email",
        {
            "to": "billing@acme.example",
            "subject": "Compliance",
            "body": {"nested": ["sk-FAKE-7f3a91"]},
        },
        role="finance_admin",
    )

    assert "argument body must be string" in result
    logged = (DATA_DIR / "event_log.jsonl").read_text(encoding="utf-8")
    assert "sk-FAKE-7f3a91" not in logged
    assert "[REDACTED]" in logged


def test_invalid_policy_decision_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime.reset_demo()
    monkeypatch.setattr(
        runtime.policy,
        "guard_hook",
        lambda *_args: {"allowed": "false", "reason": "malformed decision"},
    )

    result = runtime.call_tool(
        "pay_invoice",
        {"vendor": "Acme Supplies", "amount": 400, "invoice_id": "4471"},
        role="finance_admin",
    )

    assert "invalid decision" in result
    assert load_json(VICTIM_ROOT / "data" / "ledger.json") == []
    assert events.read_event_log()[-1]["allowed"] is False


def test_victim_has_no_aegis_policy_or_event_log_code() -> None:
    runtime.reset_demo()
    assert not (VICTIM_ROOT / "tools" / "guard.py").exists()
    assert not (VICTIM_ROOT / "tools" / "live_monitor.py").exists()
    assert not (VICTIM_ROOT / "data" / "event_log.jsonl").exists()


def test_aegis_event_log_is_owned_by_aegis_repo() -> None:
    runtime.reset_demo()
    runtime.call_tool("get_record", {"record_id": "emp-12"}, role="employee")
    logged = events.read_event_log()[-1]
    assert logged["tool"] == "get_record"
    assert logged["allowed"] is True
