from run_changed_tests import frontend_changed, select_tests


def test_selects_test_files_that_changed() -> None:
    assert select_tests({"tests/test_policy.py"}) == {"tests/test_policy.py"}


def test_selects_tests_for_guard_changes() -> None:
    assert select_tests({"aegis_loop/policy.py"}) == {
        "tests/test_policy.py",
        "tests/test_red_agent.py",
        "tests/test_proof_loop.py",
        "tests/test_multiuser_api.py",
    }


def test_selects_event_tests_for_event_log_changes() -> None:
    assert select_tests({"aegis_loop/event_log.py"}) == {
        "tests/test_event_api.py",
        "tests/test_event_log.py",
    }


def test_selects_api_tests_for_dashboard_changes() -> None:
    assert select_tests({"dashboard/api.py"}) == {
        "dashboard/test_api.py",
        "tests/test_event_api.py",
        "tests/test_multiuser_api.py",
    }


def test_selects_registered_app_tests_for_database_changes() -> None:
    assert select_tests({"aegis_loop/database.py"}) == {
        "dashboard/test_api.py",
        "tests/test_multiuser_api.py",
    }


def test_frontend_changes_request_frontend_build() -> None:
    assert frontend_changed({"web/src/App.tsx"}) is True
    assert frontend_changed({"README.md"}) is False


def test_unmapped_python_change_runs_full_suite() -> None:
    selected = select_tests({"new_module.py"})

    assert selected == {
        "tests/test_change_selection.py",
        "tests/test_policy.py",
        "tests/test_proof_loop.py",
        "tests/test_red_agent.py",
        "tests/test_local_model_boundary.py",
        "tests/test_event_api.py",
        "tests/test_event_log.py",
        "dashboard/test_api.py",
        "tests/test_multiuser_api.py",
        "dashboard/test_validation.py",
        "dashboard/test_workspace.py",
        "tests/test_identity.py",
    }


def test_deleted_python_file_runs_full_suite() -> None:
    assert select_tests({"aegis_loop/retired.py"}, {"aegis_loop/retired.py"}) == {
        "tests/test_change_selection.py",
        "tests/test_policy.py",
        "tests/test_proof_loop.py",
        "tests/test_red_agent.py",
        "tests/test_local_model_boundary.py",
        "tests/test_event_api.py",
        "tests/test_event_log.py",
        "dashboard/test_api.py",
        "tests/test_multiuser_api.py",
        "dashboard/test_validation.py",
        "dashboard/test_workspace.py",
        "tests/test_identity.py",
    }
