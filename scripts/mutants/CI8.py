"""CI8 (#566): the CI's downloads retried, never a test — retry.sh exits with its last failure's code
after three attempts (M4015, M4016); a mutation step retried, a provider's download left unretried,
ChromaDB's model fetched by the tests again, each seen by tests/unit/test_workflows.py (M4017–M4019).
"""
RETRY = "scripts/retry.sh"
_WF = "tests/unit/test_workflows.py::"

MUTANTS = [
    ("M4015", "retry.sh exits 1 after its third failure: the last failure's code lost (CI8)", RETRY,
     "    echo \"::error::retry.sh: $said failed $attempts times; exit $code, the last failure's\"\n"
     "    exit \"$code\"\n",
     "    echo \"::error::retry.sh: $said failed $attempts times; exit $code, the last failure's\"\n"
     "    exit 1\n"),
    ("M4016", "retry.sh gives up after two attempts: one wait, no third try (CI8)", RETRY,
     "waits=(10 30)                    # between the attempts: three in all\n",
     "waits=(10)                       # between the attempts: three in all\n"),
    ("M4017", "the Monday's mutation retried: a mutant caught at one attempt in three passes unseen (CI8)",
     ".github/workflows/mutants.yml",
     '          python scripts/mutation_check.py --examples "$EXAMPLES"',
     '          bash scripts/retry.sh python scripts/mutation_check.py --examples "$EXAMPLES"'),
    ("M4018", "Celebrimbor's providers downloaded unretried again: one 504 and the job is red (CI8, the "
              "defect back)", ".github/workflows/ci.yml",
     "        run: bash scripts/retry.sh terraform -chdir=infra/terraform init ",
     "        run: terraform -chdir=infra/terraform init "),
    ("M4019", "Glorfindel's tests alone fetch ChromaDB's model themselves, unretried: its step gone (CI8)",
     ".github/workflows/components.yml",
     "      - name: ChromaDB's embedding model (fetched when the cache misses, retried)\n"
     "        if: matrix.component == 'glorfindel'\n"
     "        run: bash scripts/retry.sh python scripts/chroma_model.py\n", ""),
]
TESTS = {
    "M4015": f"{_WF}test_ci8_three_failures_exit_with_the_last_failures_code",
    "M4016": f"{_WF}test_ci8_a_download_that_fails_twice_passes_at_its_third_attempt "
             f"{_WF}test_ci8_three_failures_exit_with_the_last_failures_code",
    "M4017": f"{_WF}test_ci8_no_test_mutation_nor_invariants_is_ever_retried",
    "M4018": f"{_WF}test_ci8_every_download_is_retried",
    "M4019": f"{_WF}test_ci8_the_steps_retried_are_these_and_only_these",
}
