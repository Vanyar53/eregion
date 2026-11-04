"""CI5b (#512): a faster CI — macOS off the pull requests, 200 invariant sequences there, a run
replaced on a pull request cancelled, never on main. M3587–M3589, measured by
tests/unit/test_workflows.py."""
CI = ".github/workflows/ci.yml"
_WORKFLOWS = "tests/unit/test_workflows.py"

MUTANTS = [
    ("M3587", "the macOS job back on every pull request, never acquired by a runner (CI5)", CI,
     "    if: ${{ github.event_name == 'push' || github.event_name == 'schedule' }}\n    runs-on: macos-latest\n",
     "    runs-on: macos-latest\n"),
    ("M3588", "500 invariant sequences on each push of a pull request (CI5)", CI,
     "${{ github.event_name == 'pull_request' && '200' || '500' }}", '"500"'),
    ("M3589", "a run of main cancelled by the next push (CI5)", CI,
     "  cancel-in-progress: ${{ github.event_name == 'pull_request' }}\n", "  cancel-in-progress: true\n"),
]
TESTS = {
    "M3587": f"{_WORKFLOWS}::test_macos_runs_on_a_push_to_main_and_at_night_never_on_a_pull_request",
    "M3588": f"{_WORKFLOWS}::test_a_push_replays_the_failures_the_night_kept_on_both_machines",
    "M3589": f"{_WORKFLOWS}::test_a_new_push_on_a_pull_request_cancels_the_run_it_replaces_never_on_main",
}
