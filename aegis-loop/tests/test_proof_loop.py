import json
from pathlib import Path

from aegis_loop.config import DATA_DIR, VICTIM_ROOT
from proof_loop import run_proof_loop


def test_proof_loop_saves_attack_and_benign_evidence_without_canary(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setenv("AEGIS_SANDBOX", "1")
    report = run_proof_loop(tmp_path)
    saved_report = Path(report["report_path"])
    saved_text = saved_report.read_text(encoding="utf-8")
    parsed = json.loads(saved_text)

    assert parsed["summary"] == {
        "attacks_blocked": 3,
        "attacks_total": 3,
        "benign_checks_passed": 3,
        "benign_checks_total": 3,
        "passed": True,
    }
    assert report["event_count"] == 6
    assert [event["allowed"] for event in parsed["events"]] == [
        False,
        False,
        False,
        True,
        True,
        True,
    ]
    assert "sk-FAKE-7f3a91" not in saved_text
    saved_events = (DATA_DIR / "event_log.jsonl").read_text(encoding="utf-8")
    assert saved_events
    assert not (VICTIM_ROOT / "data" / "files" / "invoice_4472.txt").exists()
