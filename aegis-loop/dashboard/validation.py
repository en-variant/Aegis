import importlib
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "run_changed_tests.py"
VALIDATION_TIMEOUT_SECONDS = 180
MAX_OUTPUT_CHARS = 20_000


def _activate_guard() -> None:
    from aegis_loop import policy, runtime

    importlib.invalidate_caches()
    importlib.reload(policy)
    importlib.reload(runtime)
    runtime.install()


def run_validation() -> dict[str, Any]:
    try:
        result = subprocess.run(
            [sys.executable, str(RUNNER)],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
            timeout=VALIDATION_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as exc:
        raise TimeoutError("Targeted validation exceeded its time limit") from exc

    output = "\n".join(
        part.strip() for part in (result.stdout, result.stderr) if part.strip()
    )
    passed = result.returncode == 0
    if passed:
        try:
            _activate_guard()
        except (ImportError, SyntaxError) as exc:
            return {
                "passed": False,
                "return_code": result.returncode,
                "active_policy_reloaded": False,
                "output": f"{output}\nPolicy activation failed: {exc}".strip(),
            }

    return {
        "passed": passed,
        "return_code": result.returncode,
        "active_policy_reloaded": passed,
        "output": output[-MAX_OUTPUT_CHARS:],
    }
