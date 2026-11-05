"""CI8 (#566): the CI's downloads retried, never a test — retry.sh exits with its last failure's code
after three attempts (M4015, M4016); a mutation step retried, a provider's download left unretried,
ChromaDB's model fetched by the tests again, each seen by tests/unit/test_workflows.py (M4017–M4019).
After its review: a signal is a stop even when the command catches it and exits 1 (M4027, M4028);
apt-get update fails on a transient error instead of a W: and 0 (M4029).
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
_SIG = f"{_WF}test_ci8_a_signal_is_a_stop_even_when_the_command_catches_it_and_exits_1"
MUTANTS += [
    ("M4027", "SIGINT caught by pip or Terraform, exit 1: retry.sh tries a cancelled job's command again "
              "(CI8, review)", RETRY,
     "trap 'echo \"::error::retry.sh: stopped by SIGINT: never run again\"; exit 130' INT\n", ""),
    ("M4028", "SIGTERM caught by the command, exit 1: retry.sh tries again past the job's bound (CI8, review)",
     RETRY, "trap 'echo \"::error::retry.sh: stopped by SIGTERM: never run again\"; exit 143' TERM\n", ""),
    ("M4029", "apt-get update says a transient error as a W: and exits 0: never retried, the install fails "
              "three times (CI8, review)", ".github/workflows/ci.yml",
     "          bash scripts/retry.sh sudo apt-get update -qq -o APT::Update::Error-Mode=any\n",
     "          bash scripts/retry.sh sudo apt-get update -qq\n"),
]
TESTS = {
    "M4027": f"{_SIG}[SIGINT-130]",
    "M4028": f"{_SIG}[SIGTERM-143]",
    "M4029": f"{_WF}test_ci8_every_download_is_retried",
    "M4015": f"{_WF}test_ci8_three_failures_exit_with_the_last_failures_code",
    "M4016": f"{_WF}test_ci8_a_download_that_fails_twice_passes_at_its_third_attempt "
             f"{_WF}test_ci8_three_failures_exit_with_the_last_failures_code",
    "M4017": f"{_WF}test_ci8_no_test_mutation_nor_invariants_is_ever_retried",
    "M4018": f"{_WF}test_ci8_every_download_is_retried",
    "M4019": f"{_WF}test_ci8_the_steps_retried_are_these_and_only_these",
}
