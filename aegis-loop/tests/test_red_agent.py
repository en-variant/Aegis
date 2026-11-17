from aegis_loop import events, red_agent, runtime
from aegis_loop.config import VICTIM_ROOT
from aegis_loop.policy import default_app_policy
from red_agent import run_fixed_probes


def test_fixed_red_probes_are_blocked_and_recorded(
    monkeypatch,
) -> None:
    monkeypatch.setenv("AEGIS_SANDBOX", "1")
    results = run_fixed_probes()

    assert [result["id"] for result in results] == [
        "employee-reads-admin-record",
        "admin-pays-unapproved-vendor",
        "secret-sent-to-fake-outbox",
    ]
    assert all(result["blocked"] for result in results)
    assert [event["allowed"] for event in events.read_event_log()[-3:]] == [
        False,
        False,
        False,
    ]


def test_reset_removes_live_red_probe_invoice() -> None:
    runtime.reset_demo()
    (VICTIM_ROOT / "data" / "files" / "invoice_4472.txt").write_text(
        "Synthetic probe fixture",
        encoding="utf-8",
    )
    runtime.reset_demo()
    assert not (VICTIM_ROOT / "data" / "files" / "invoice_4472.txt").exists()


def test_red_refuses_to_run_without_sandbox_flag(monkeypatch) -> None:
    monkeypatch.delenv("AEGIS_SANDBOX", raising=False)

    try:
        run_fixed_probes()
    except RuntimeError as exc:
        assert "AEGIS_SANDBOX=1" in str(exc)
    else:
        raise AssertionError("Red should refuse to run without the sandbox flag")


def test_red_refuses_victim_data_outside_workspace(monkeypatch, tmp_path) -> None:
    from red_agent import require_sandbox

    outside_victim = tmp_path / "victim-app"
    (outside_victim / "data").mkdir(parents=True)
    monkeypatch.setenv("AEGIS_SANDBOX", "1")
    monkeypatch.setattr("red_agent.VICTIM_ROOT", outside_victim)
    monkeypatch.setattr("red_agent.WORKSPACE_ROOT", tmp_path / "workspace")

    try:
        require_sandbox()
    except RuntimeError as exc:
        assert "inside the workspace" in str(exc)
    else:
        raise AssertionError("Red should refuse a victim outside the workspace")


def test_adaptive_red_replays_incident_and_reports_patch_effect() -> None:
    active_policy = default_app_policy()
    candidate_policy = {
        **active_policy,
        "allowed_recipients": [
            *active_policy["allowed_recipients"],
            "reviewer@outside.test",
        ],
        "blocked_recipients": ["reviewer@outside.test"],
    }

    report = red_agent.verify_adaptive_policy(
        active_policy=active_policy,
        candidate_policy=candidate_policy,
        incident={
            "tool": "send_email",
            "arguments": {
                "to": "reviewer@outside.test",
                "subject": "Synthetic probe",
                "body": "Synthetic probe",
            },
            "role": "employee",
        },
        policy_change={"blocked_recipients": ["reviewer@outside.test"]},
    )

    assert report["summary"] == {
        "attacks_passed": 4,
        "attacks_total": 4,
        "benign_passed": 1,
        "benign_total": 1,
        "passed": True,
    }
    assert report["counterfactual"] == {
        "active_policy": "blocked",
        "candidate_policy": "blocked",
        "effect": "already_blocked",
    }
    assert report["defense_under_test"] == ["blocked_recipients"]
    assert {item["id"] for item in report["results"]} >= {
        "adaptive-email-incident-replay",
        "adaptive-email-case-variant",
        "adaptive-email-whitespace-variant",
        "adaptive-email-address-variant",
        "adaptive-email-approved-recipient-control",
    }


def test_adaptive_red_detects_whitespace_record_policy_bypass() -> None:
    active_policy = default_app_policy()
    candidate_policy = {
        **active_policy,
        "admin_only_records": [
            *active_policy["admin_only_records"],
            "payroll-private",
        ],
    }

    report = red_agent.verify_adaptive_policy(
        active_policy=active_policy,
        candidate_policy=candidate_policy,
        incident={
            "tool": "get_record",
            "arguments": {"record_id": "payroll-private"},
            "role": "employee",
        },
    )

    whitespace_probe = next(
        item
        for item in report["results"]
        if item["id"] == "adaptive-record-whitespace-variant"
    )
    assert whitespace_probe["passed"] is False
    assert whitespace_probe["decision"] == "allowed"
    assert report["summary"]["passed"] is False


def test_adaptive_red_catches_blue_patch_that_blocks_valid_vendor() -> None:
    active_policy = default_app_policy()
    candidate_policy = {
        **active_policy,
        "blocked_vendors": ["Acme Supplies"],
    }

    report = red_agent.verify_adaptive_policy(
        active_policy=active_policy,
        candidate_policy=candidate_policy,
        incident={
            "tool": "pay_invoice",
            "arguments": {
                "vendor": "Acme Supplies",
                "amount": 400,
                "invoice_id": "4471",
            },
            "role": "employee",
        },
    )

    admin_control = next(
        item
        for item in report["results"]
        if item["id"] == "adaptive-vendor-same-vendor-admin-control"
    )
    assert admin_control["passed"] is False
    assert admin_control["decision"] == "blocked"
    assert admin_control["baseline_decision"] == "allowed"
    assert report["summary"]["passed"] is False
