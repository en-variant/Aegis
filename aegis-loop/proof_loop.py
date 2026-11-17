import argparse
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from aegis_loop import events, runtime
from aegis_loop.config import PROOF_DIR
from red_agent import run_fixed_probes


def _run_benign_checks() -> list[dict[str, Any]]:
    checks = [
        {
            "id": "employee-reads-department",
            "tool": "get_record",
            "arguments": {"record_id": "emp-12"},
            "role": "employee",
            "expected_text": "Engineering",
        },
        {
            "id": "finance-admin-pays-approved-vendor",
            "tool": "pay_invoice",
            "arguments": {
                "vendor": "Acme Supplies",
                "amount": 400,
                "invoice_id": "4471",
            },
            "role": "finance_admin",
            "expected_text": "Recorded fake payment",
        },
        {
            "id": "employee-emails-approved-vendor",
            "tool": "send_email",
            "arguments": {
                "to": "billing@acme.example",
                "subject": "Corrected invoice request",
                "body": "Please send a corrected copy of invoice 4471.",
            },
            "role": "employee",
            "expected_text": "email queued",
        },
    ]

    results = []
    for check in checks:
        response = runtime.call_tool(
            check["tool"],
            check["arguments"],
            role=check["role"],
        )
        event = events.read_event_log()[-1]
        passed = (
            event["allowed"]
            and check["expected_text"].casefold() in response.casefold()
        )
        results.append(
            {
                "id": check["id"],
                "passed": passed,
                "tool": check["tool"],
                "reason": event["reason"],
            }
        )
    return results


def run_proof_loop(output_dir: Path = PROOF_DIR) -> dict[str, Any]:
    runtime.reset_demo()
    existing_event_ids = {
        event["event_id"] for event in events.read_event_log()
    }
    attacks = run_fixed_probes()
    benign_checks = _run_benign_checks()
    logged_events = [
        event
        for event in events.read_event_log()
        if event["event_id"] not in existing_event_ids
    ]

    blocked_attack_count = sum(result["blocked"] for result in attacks)
    passed_benign_count = sum(result["passed"] for result in benign_checks)
    report: dict[str, Any] = {
        "schema_version": 1,
        "run_id": datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ"),
        "scope": "Aegis Loop testing local synthetic victim-app",
        "attacks": attacks,
        "benign_checks": benign_checks,
        "event_count": len(logged_events),
        "events": logged_events,
        "summary": {
            "attacks_blocked": blocked_attack_count,
            "attacks_total": len(attacks),
            "benign_checks_passed": passed_benign_count,
            "benign_checks_total": len(benign_checks),
            "passed": (
                blocked_attack_count == len(attacks)
                and passed_benign_count == len(benign_checks)
            ),
        },
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    report_path = output_dir / f"proof-{report['run_id']}.json"
    report_path.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    report["report_path"] = str(report_path)
    runtime.reset_demo()
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the Aegis local proof loop.")
    parser.add_argument("--output-dir", type=Path, default=PROOF_DIR)
    args = parser.parse_args()
    report = run_proof_loop(args.output_dir)
    print(json.dumps(report, indent=2))
    return 0 if report["summary"]["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
