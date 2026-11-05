"""CI7 (#554): Orodruin's Terraform tests (WC1 watch_writers, IDI1 graph_read) run in the CI and in the
release gate, after the module's retried init (M4025, M4026).
"""
_WF = "tests/unit/test_workflows.py::"
_ORO = ("          terraform -chdir=infra/orodruin validate -no-color\n"
        "          terraform -chdir=infra/orodruin test -no-color\n")
_VALIDATE = "          terraform -chdir=infra/orodruin validate -no-color\n"

MUTANTS = [
    ("M4025", "Orodruin's Terraform tests out of the CI again: only validated, its contracts unrun (CI7, the "
              "defect back)", ".github/workflows/ci.yml", _ORO, _VALIDATE),
    ("M4026", "the release gate without Orodruin's Terraform tests: ci.yml's no longer word for word (CI7)",
     ".github/workflows/release-gate.yml", _ORO, _VALIDATE),
]
TESTS = {
    "M4025": f"{_WF}test_the_terraform_tests_run_on_each_push_and_pull_request",
    "M4026": f"{_WF}test_the_gate_runs_ci_s_macos_job_and_its_terraform_tests_word_for_word",
}
