# Phase 8 — Test changed code

## Audit outcome

**Pass after fixing deleted-file handling.**

## What belongs to this phase

[`../run_changed_tests.py`](../run_changed_tests.py) maps changed Aegis Python
files to focused tests, falls back to the full Aegis suite for unmapped or
deleted Python files, runs Ruff on changed files that still exist, and builds
the frontend for web changes.

## Audit finding fixed

Previously, a deleted Python path could be sent to Ruff as if it still existed.
The runner now excludes deleted paths from Ruff and selects the full test suite
when a Python file was removed. A regression test covers this selection.

## Verification and limits

The change-selection regression tests are included in the **46 passing Aegis
tests**, and Ruff passes for the complete Aegis repository. Selection is based
on Git changes and the explicit source-to-test map; it is a focused feedback
tool, not a substitute for periodic full-suite runs.
