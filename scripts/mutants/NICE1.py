"""NICE1 (#620): the suite in low priority on a workstation, never in CI (tests/unit/conftest.py,
`pytest_configure`). M4480–M4481, measured by tests/unit/test_suite_priority.py on a fake
`os.nice` (an unprivileged process's: capped at 19, never lowered)."""
CONFTEST = "tests/unit/conftest.py"
_TESTS = "tests/unit/test_suite_priority.py"

MUTANTS = [
    ("M4480", "a CI run lowered in priority too: the CI guard skipped (NICE1)", CONFTEST,
     "    if os.environ.get(\"CI\") or not hasattr(os, \"nice\"):\n",
     "    if not hasattr(os, \"nice\"):\n"),
    ("M4481", "the rise no longer idempotent: a worker that inherits 10 adds 10 more (NICE1)", CONFTEST,
     "        current = os.nice(0)\n"
     "        if current < NICENESS:\n"
     "            os.nice(NICENESS - current)\n",
     "        os.nice(NICENESS)\n"),
]

TESTS = {
    "M4480": f"{_TESTS}::test_a_ci_run_keeps_the_priority_it_was_given",
    "M4481": f"{_TESTS}::test_a_run_already_at_ten_or_lower_in_priority_keeps_it",
}
