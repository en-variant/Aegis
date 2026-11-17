import argparse
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SOURCE_TESTS = {
    "aegis_loop/policy.py": {
        "tests/test_policy.py",
        "tests/test_red_agent.py",
        "tests/test_proof_loop.py",
        "tests/test_multiuser_api.py",
    },
    "aegis_loop/runtime.py": {
        "tests/test_policy.py",
        "tests/test_red_agent.py",
        "tests/test_proof_loop.py",
        "tests/test_local_model_boundary.py",
    },
    "aegis_loop/events.py": {
        "tests/test_policy.py",
        "tests/test_red_agent.py",
        "tests/test_proof_loop.py",
        "dashboard/test_api.py",
    },
    "aegis_loop/auth.py": {"tests/test_multiuser_api.py", "dashboard/test_api.py"},
    "aegis_loop/blue_agent.py": {"tests/test_multiuser_api.py"},
    "aegis_loop/database.py": {"tests/test_multiuser_api.py", "dashboard/test_api.py"},
    "aegis_loop/event_contract.py": {"tests/test_event_log.py"},
    "aegis_loop/event_log.py": {"tests/test_event_log.py", "tests/test_event_api.py"},
    "aegis_loop/red_agent.py": {
        "tests/test_red_agent.py",
        "tests/test_multiuser_api.py",
    },
    "dashboard/api.py": {
        "dashboard/test_api.py",
        "tests/test_event_api.py",
        "tests/test_multiuser_api.py",
    },
    "dashboard/applications_api.py": {
        "dashboard/test_api.py",
        "tests/test_multiuser_api.py",
        "tests/test_event_api.py",
        "tests/test_event_log.py",
    },
    "dashboard/auth_api.py": {"dashboard/test_api.py", "tests/test_multiuser_api.py"},
    "dashboard/test_api.py": {"dashboard/test_api.py"},
    "dashboard/workspace.py": {"dashboard/test_api.py", "dashboard/test_workspace.py"},
    "dashboard/test_workspace.py": {"dashboard/test_workspace.py"},
    "dashboard/validation.py": {"dashboard/test_validation.py"},
    "dashboard/test_validation.py": {"dashboard/test_validation.py"},
    "red_agent.py": {"tests/test_red_agent.py", "tests/test_proof_loop.py"},
    "tests/test_local_model_boundary.py": {"tests/test_local_model_boundary.py"},
    "tests/test_multiuser_api.py": {"tests/test_multiuser_api.py"},
    "tests/test_policy.py": {"tests/test_policy.py"},
    "proof_loop.py": {"tests/test_proof_loop.py"},
    "run_changed_tests.py": {"tests/test_change_selection.py"},
}


def _all_test_paths() -> set[str]:
    return {
        path.relative_to(ROOT).as_posix()
        for path in ROOT.rglob("test_*.py")
        if not {".git", ".venv", "node_modules", "__pycache__"}.intersection(path.parts)
    }


def select_tests(
    changed_paths: set[str], deleted_paths: set[str] | None = None
) -> set[str]:
    if deleted_paths:
        return _all_test_paths()

    selected: set[str] = set()
    has_unmapped_python = False
    for path in changed_paths:
        if path.startswith(("tests/", "dashboard/")) and path.endswith(".py"):
            if Path(path).name.startswith("test_"):
                selected.add(path)
            elif path in SOURCE_TESTS:
                selected.update(SOURCE_TESTS[path])
            else:
                has_unmapped_python = True
        elif path in SOURCE_TESTS:
            selected.update(SOURCE_TESTS[path])
        elif path.endswith(".py"):
            has_unmapped_python = True

    if has_unmapped_python:
        return _all_test_paths()
    return selected


def frontend_changed(changed_paths: set[str]) -> bool:
    return any(path.startswith("web/") for path in changed_paths)


def _git_paths(*args: str) -> set[str]:
    completed = subprocess.run(
        ["git", *args],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    return {line for line in completed.stdout.splitlines() if line}


def collect_changed_paths(base_ref: str) -> set[str]:
    paths = _git_paths("diff", "--name-only", base_ref)
    paths.update(_git_paths("diff", "--cached", "--name-only"))
    paths.update(_git_paths("ls-files", "--others", "--exclude-standard"))
    return paths


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run focused Aegis pytest and Ruff checks for changed files."
    )
    parser.add_argument(
        "--base-ref",
        default="HEAD",
        help="Git ref to compare against; defaults to HEAD for working-tree changes",
    )
    args = parser.parse_args()

    changed = collect_changed_paths(args.base_ref)
    deleted_python = {
        path
        for path in changed
        if path.endswith(".py") and not (ROOT / path).is_file()
    }
    tests = sorted(select_tests(changed, deleted_python))
    python_files = sorted(
        path
        for path in changed
        if path.endswith(".py") and (ROOT / path).is_file()
    )
    run_frontend_build = frontend_changed(changed)
    if not tests and not python_files and not run_frontend_build:
        print("No changed code files require validation.")
        return 0

    ruff = Path(sys.executable).with_name("ruff")
    if sys.platform == "win32":
        ruff = ruff.with_suffix(".exe")
    if python_files:
        subprocess.run([str(ruff), "check", *python_files], cwd=ROOT, check=True)
    if tests:
        subprocess.run(
            [sys.executable, "-m", "pytest", *tests],
            cwd=ROOT,
            check=True,
        )
    else:
        print("No mapped tests for the changed Python files.")
    if run_frontend_build:
        subprocess.run(["npm", "run", "build"], cwd=ROOT / "web", check=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
