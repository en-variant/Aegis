from pathlib import Path
from typing import Any

import pytest
import yaml
from agent.identity import AuthenticatedUser
from agent.loop import run_agent
from reset import reset_data

ROOT = Path(__file__).resolve().parents[1]
BENIGN_TASKS: list[dict[str, Any]] = yaml.safe_load(
    (ROOT / "benign_tasks.yaml").read_text(encoding="utf-8")
)


@pytest.mark.parametrize("task", BENIGN_TASKS, ids=lambda task: task["id"])
def test_benign_task(task: dict[str, Any]) -> None:
    reset_data()
    answer, calls = run_agent(
        task["prompt"],
        user=AuthenticatedUser(user_id="synthetic-user", role=task["role"]),
    )
    check = task["check"]

    if "tool" in check:
        matching_calls = [call for call in calls if call["tool"] == check["tool"]]
        assert matching_calls, f"Expected {check['tool']} for {answer!r}; calls: {calls!r}"
        for key, value in check.get("args", {}).items():
            assert any(call["args"].get(key) == value for call in matching_calls), (
                f"Expected {check['tool']} argument {key}={value!r} in {matching_calls!r}"
            )
        for key, value in check.get("args_contains", {}).items():
            assert any(
                value.casefold() in str(call["args"].get(key, "")).casefold()
                for call in matching_calls
            ), f"Expected {check['tool']} argument {key} to contain {value!r}"
    if "no_tool" in check:
        assert check["no_tool"] not in [call["tool"] for call in calls], (
            f"Did not expect {check['no_tool']} call; got {calls!r}"
        )
    for tool_name in check.get("forbidden_tools", []):
        assert tool_name not in [call["tool"] for call in calls], (
            f"Did not expect {tool_name} call; got {calls!r}"
        )
    for expected in check.get("output_contains", []):
        assert expected.casefold() in answer.casefold(), (
            f"Expected {expected!r} in answer {answer!r}"
        )
    if "output_contains_any" in check:
        assert any(
            expected.casefold() in answer.casefold()
            for expected in check["output_contains_any"]
        ), f"Expected a refusal in answer {answer!r}"
