"""CI10b (#581): the CI in its place, on the workflows' side — mutant_anchors.py at each merge
(M4190), the suite in four processes from the dev lock (M4191, M4192), Components in one job on a
pull request, each component its own steps whatever the one before said (M4193, M4194); the gate
without the machine's unmutated runs in its shards (M4195), its tests in two jobs each test in one
and both in its total's needs (M4196, M4197; macOS out of them: M3605, retargeted), and release-draft
green on a run still going for macOS alone (M4199); the Monday on the machines' mutants alone, its total too (M4198). Each seen
by tests/unit/test_workflows.py or tests/unit/test_release.py.
"""
CI = ".github/workflows/ci.yml"
COMPONENTS = ".github/workflows/components.yml"
GATE = ".github/workflows/release-gate.yml"
MONDAY = ".github/workflows/mutants.yml"
_WF = "tests/unit/test_workflows.py::"
_REL = "tests/unit/test_release.py::"
_IF = "        if: ${{ !cancelled() && steps.model.outcome == 'success' }}\n"
_IF_INSTALL = "        if: ${{ !cancelled() && steps.install.outcome == 'success' }}\n"

MUTANTS = [
    ("M4190", "mutant_anchors.py no longer in ci.yml: a mutant made stale by another merge seen at the next "
              "gate only (CI10b, L16)", CI,
     "      - name: Mutants anchored to this tree\n        run: python scripts/mutant_anchors.py\n", ""),
    ("M4191", "ci.yml's tests in one process again: a pull request green in 14 min, not 7 (CI10b, L8)", CI,
     "        run: python -m pytest tests/ -q -n 4 --dist load -o faulthandler_timeout=480",
     "        run: python -m pytest tests/ -q -o faulthandler_timeout=480"),
    ("M4192", "pytest-xdist out of the dev extra: the lock no longer follows what pyproject declares, `-n 4` "
              "gone at the next make lock (CI10b, L8)", "pyproject.toml",
     '    "pytest-xdist>=3.6",     # the suite in 4 processes in the CI (CI10b, #581: `-n 4 --dist load`)\n', ""),
    ("M4193", "Gothmog's tests no longer run alone on a pull request: its imports checked, its tests never "
              "(CI10b, L11)", COMPONENTS,
     "      - name: gothmog — its tests pass alone (0 Azure call, 0 LLM call)\n" + _IF_INSTALL
     + "        run: python scripts/component_check.py gothmog\n", ""),
    ("M4194", "Glorfindel's tests skipped when core's failed: one red hides every component after it "
              "(CI10b, L11)", COMPONENTS,
     "      - name: glorfindel — its tests pass alone (0 Azure call, 0 LLM call)\n" + _IF,
     "      - name: glorfindel — its tests pass alone (0 Azure call, 0 LLM call)\n"),
    ("M4195", "the gate's shards run the machine unmutated again: 7.8 h of runner redoing what its invariant "
              "jobs prove at 2 000 (CI10b, L3)", GATE,
     "          python scripts/mutation_check.py --examples 500 --rounds 2 --jobs 4 --skip-machine-baseline\n",
     "          python scripts/mutation_check.py --examples 500 --rounds 2 --jobs 4\n"),
    ("M4196", "the gate's every other test runs Azure's machine again: 22 min more on the job the split "
              "shortened (CI10b, L6)", GATE,
     " --dist load --ignore=tests/unit/test_invariants.py -o faulthandler_timeout=2400",
     " --dist load -o faulthandler_timeout=2400"),
    ("M4197", "the gate's total green without Azure's machine: the split job left out of its needs, its red "
              "never blocks (CI10b, L6)", GATE,
     "    needs: [invariants-azure, invariants-rest, mutants,", "    needs: [invariants-rest, mutants,"),
    ("M4198", "the Monday's total judges every mutant of the tree after measuring the machines' alone: red "
              "every Monday, « never measured » (CI10b, L13)", MONDAY,
     "python3 scripts/mutation_check.py --total mutants-results --machines --shards 14",
     "python3 scripts/mutation_check.py --total mutants-results --shards 14"),
    ("M4199", "release-draft refuses a gate whose run still goes for macOS alone: the total's minutes won "
              "lost again (CI10b, L7)", "scripts/release.py",
     '    if r.get("status") != "completed" and not green:\n',
     '    if r.get("status") != "completed":\n'),
]
# After the review (05/11): a component that reads no model never waits for its download (M4235); the
# pull request's job pins its actions as the gate does (M4236); a run still going whose jobs cannot be
# read says why, never « en cours » (M4237).
MUTANTS += [
    ("M4235", "core's tests wait for ChromaDB's model again: a model that fails to download skips a "
              "component that never reads it (CI10b, review)", COMPONENTS,
     "      - name: core — its tests pass alone (0 Azure call, 0 LLM call)\n" + _IF_INSTALL,
     "      - name: core — its tests pass alone (0 Azure call, 0 LLM call)\n" + _IF),
    ("M4236", "the pull request's components job takes setup-python by its tag: a tag moved runs another "
              "commit (CI10b, review)", COMPONENTS,
     "      # Pinned by commit, the release gate's own (no action added): the matrix above keeps its tags.\n"
     "      - uses: actions/setup-python@ece7cb06caefa5fff74198d8649806c4678c61a1   # v6.3.0\n",
     "      # Pinned by commit, the release gate's own (no action added): the matrix above keeps its tags.\n"
     "      - uses: actions/setup-python@v6\n"),
    ("M4237", "a run still going whose jobs cannot be read said « en cours »: the error that refuses it "
              "hidden (CI10b, review)", "scripts/release.py",
     "        return False, said if said.startswith(UNREAD) else (",
     "        return False, ("),
]
_SHARDS = "tests/unit/test_mutation_shards.py::test_a_shard_leaves_the_machines_only_to_a_gate_that_runs_them"
_AZURE = ("      - name: Azure's invariant machine, 2 000 sequences\n        env:\n"
          "          GLORFINDEL_INVARIANT_EXAMPLES: \"2000\"\n")
_MONDAY_RUN = ('          SHARD: ${{ matrix.shard }}\n        run: >-\n'
               '          python scripts/mutation_check.py --examples "$EXAMPLES" --rounds "$ROUNDS" --jobs 4 --machines\n')
# After CI10a's merge (06/11): every option a workflow gives the harness is one its parser knows by its
# whole name (M4238, M4264); L3's test held tight — the flag sought in every job's whole text, both
# invariant jobs in the total's needs, 500 sequences at least, no machine taken out (M4239, M4260–M4263).
MUTANTS += [
    ("M4238", "the gate's shards pass an option the harness never had: the run fails on GitHub alone "
              "(CI10b, after CI10a)", GATE,
     "          python scripts/mutation_check.py --examples 500 --rounds 2 --jobs 4 --skip-machine-baseline\n",
     "          python scripts/mutation_check.py --examples 500 --rounds 2 --jobs 4 --skip-machines-baseline\n"),
    ("M4264", "the Monday passes an abbreviation (`--machine`): argparse takes it, the name never checked "
              "(CI10b, after CI10a)", MONDAY,
     ' --jobs 4 --machines\n          --shard "$SHARD/14"', ' --jobs 4 --machine\n          --shard "$SHARD/14"'),
    ("M4239", "the gate's total no longer waits for every other test: the shards skip a base no job of "
              "the total proves (CI10b, review of CI10a)", GATE,
     "    needs: [invariants-azure, invariants-rest, mutants,", "    needs: [invariants-azure, mutants,"),
    ("M4260", "Azure's machine at 200 sequences in the gate: the base the shards skip proved at a PR's "
              "budget (CI10b, review of CI10a)", GATE,
     _AZURE, _AZURE.replace('"2000"', '"200"')),
    ("M4261", "Azure's machine deselected in its own job: no job of the gate runs it, the shards skip it "
              "(CI10b, review of CI10a)", GATE,
     "        run: python -m pytest tests/unit/test_invariants.py -q -o faulthandler_timeout=2400\n",
     "        run: python -m pytest tests/unit/test_invariants.py -q --deselect "
     "tests/unit/test_invariants.py::test_isolation_invariants -o faulthandler_timeout=2400\n"),
    ("M4262", "the gate's every other test ignores the AWS machine too: no job runs it, the shards skip "
              "it (CI10b, review of CI10a)", GATE,
     "--ignore=tests/unit/test_invariants.py -o faulthandler_timeout=2400",
     "--ignore=tests/unit/test_invariants.py --ignore=tests/unit/test_invariants_aws.py "
     "-o faulthandler_timeout=2400"),
    ("M4263", "the Monday skips the machines' base through its environment, out of the `run` the test "
              "read (CI10b, review of CI10a)", MONDAY,
     _MONDAY_RUN,
     '          SHARD: ${{ matrix.shard }}\n          BASE: "--skip-machine-baseline"\n        run: >-\n'
     '          python scripts/mutation_check.py --examples "$EXAMPLES" --rounds "$ROUNDS" --jobs 4 --machines $BASE\n'),
]
TESTS = {
    "M4238": f"{_WF}test_ci10b_every_option_a_workflow_gives_the_harness_is_one_its_parser_knows",
    "M4264": f"{_WF}test_ci10b_every_option_a_workflow_gives_the_harness_is_one_its_parser_knows",
    **{m: _SHARDS for m in ("M4239", "M4260", "M4261", "M4262", "M4263")},
    "M4235": f"{_WF}test_ci10b_a_component_that_reads_no_model_never_waits_for_its_download",
    "M4236": f"{_WF}test_ci10b_the_pull_request_s_components_job_pins_its_actions_as_the_gate_does",
    "M4237": f"{_REL}test_a_run_still_going_whose_jobs_cannot_be_read_says_why",
    "M4190": f"{_WF}test_ci10b_every_mutant_is_anchored_on_each_pull_request_and_each_push",
    "M4191": f"{_WF}test_ci10b_the_suite_runs_in_four_processes_from_the_dev_lock",
    "M4192": f"{_WF}test_ci10b_the_suite_runs_in_four_processes_from_the_dev_lock",
    "M4193": f"{_WF}test_ci10b_components_run_in_one_job_on_a_pull_request_each_component_still_alone",
    "M4194": f"{_WF}test_ci10b_a_component_that_reads_no_model_never_waits_for_its_download",
    "M4195": f"{_WF}test_the_gate_runs_the_whole_mutation_in_shards_control_set_included",
    "M4196": f"{_WF}test_the_gate_runs_every_test_with_2000_invariant_sequences_on_linux",
    "M4197": f"{_WF}test_the_last_job_waits_for_every_job_that_blocks_never_macos",
    "M4198": f"{_WF}test_the_monday_measure_runs_in_the_gate_s_shards_and_their_total",
    "M4199": f"{_REL}test_a_run_still_going_for_macos_alone_is_green_once_every_job_that_blocks_is",
}
