import subprocess
import sys
from types import SimpleNamespace

import pytest

from dashboard import validation


def test_validation_runs_only_the_fixed_changed_test_runner(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: dict[str, object] = {}

    def fake_run(command, **kwargs):
        observed["command"] = command
        observed["kwargs"] = kwargs
        return SimpleNamespace(returncode=0, stdout="tests passed", stderr="")

    monkeypatch.setattr(validation.subprocess, "run", fake_run)
    monkeypatch.setattr(validation, "_activate_guard", lambda: None)
    result = validation.run_validation()

    assert observed["command"] == [
        sys.executable,
        str(validation.RUNNER),
    ]
    assert observed["kwargs"]["cwd"] == validation.ROOT
    assert observed["kwargs"]["timeout"] == validation.VALIDATION_TIMEOUT_SECONDS
    assert observed["kwargs"]["capture_output"] is True
    assert result == {
        "passed": True,
        "return_code": 0,
        "active_policy_reloaded": True,
        "output": "tests passed",
    }


def test_validation_reports_failures_without_hiding_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        validation.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(
            returncode=1,
            stdout="ruff failed",
            stderr="",
        ),
    )

    result = validation.run_validation()

    assert result["passed"] is False
    assert result["return_code"] == 1
    assert result["active_policy_reloaded"] is False
    assert "ruff failed" in result["output"]


def test_validation_timeout_is_explicit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def timeout(*_args, **_kwargs):
        raise subprocess.TimeoutExpired("pytest", validation.VALIDATION_TIMEOUT_SECONDS)

    monkeypatch.setattr(validation.subprocess, "run", timeout)
    with pytest.raises(TimeoutError, match="time limit"):
        validation.run_validation()


def test_activation_reloads_live_agent_and_guard_functions() -> None:
    from aegis_loop import runtime

    validation._activate_guard()

    assert runtime.target_loop.call_tool is runtime.call_tool
