"""CI6 (#514): the release gate — `make release-draft` refuses until it is green on a commit of
origin/main's tree, the version's pull request says it, the shards' total refuses a shard measured
at another budget (M3590–M3596, M3599, M3600–M3602); the workflow's last job counts a cancelled or
skipped job that blocks as red, every job measures the pull request's head, macOS informs and never
blocks (M3597–M3598, M3603–M3605).
"""
RELEASE = "scripts/release.py"
HARNESS = "scripts/mutation_check.py"
_REL = "tests/unit/test_release.py::"
_SH = "tests/unit/test_mutation_shards.py"

MUTANTS = [
    ("M3599", "the shards' total takes a shard measured at a lower budget (CI6)", HARNESS,
     '        if (doc.get("examples"), doc.get("rounds")) != (examples, rounds):\n', "        if False:\n"),
    ("M3590", "the draft made whatever the gate says: no gate, red, running (CI6)", RELEASE,
     "    if not green:\n        refused.append(gate_said or ",
     "    if False:\n        refused.append(gate_said or "),
    ("M3591", "the gate looked for on main's commit, not its tree: a squash-merge never passes (CI6)", RELEASE,
     '    same = [r for r in runs if _obj(r.get("head_commit")).get("tree_id") == tree]\n',
     '    same = [r for r in runs if _obj(r.get("head_commit")).get("id") == sha]\n'),
    ("M3592", "the version's pull request says nothing of the gate: merged before it is green (CI6)", RELEASE,
     '            f"{GATE_SAID}\\n\\n"\n', '            ""\n'),
    ("M3593", "a cancelled or skipped gate taken for green (CI6)", RELEASE,
     '    if r.get("conclusion") != "success":\n',
     '    if r.get("conclusion") not in ("success", "cancelled", "skipped"):\n'),
    ("M3594", "the gate's oldest run on the tree decides: a red after a green never seen (CI6)", RELEASE,
     "    runs = sorted((r for r in listed if isinstance(r, dict) and _gate_run(r)), reverse=True,\n",
     "    runs = sorted((r for r in listed if isinstance(r, dict) and _gate_run(r)), reverse=False,\n"),
    ("M3595", "any run of the workflow taken for the gate: another pull request's, its jobs skipped (CI6)", RELEASE,
     '    return r.get("event") == "pull_request" and str(r.get("head_branch") or "").startswith("chore/release-")\n',
     "    return True\n"),
    ("M3596", "a fork's run taken for the gate (CI6)", RELEASE,
     "    if not head or head != repo:\n        return False\n", "    if False:\n        return False\n"),
    ("M3600", "the gate's runs ordered by their creation: a run re-run red after a green dispatch unseen "
              "(CI6, review)", RELEASE,
     '(str(r.get("run_started_at") or r.get("created_at") or ""),', '(str(r.get("created_at") or ""),'),
    ("M3601", "a chore/release-… pull request into another branch taken for the gate: its base's workflow ran "
              "(CI6, review)", RELEASE,
     '    if not bases or any(b != "main" for b in bases):\n', "    if False:\n"),
    ("M3602", "a gate that says nothing lets the draft past (CI6, review)", RELEASE,
     "    if not green:\n        refused.append(gate_said or ",
     "    if gate_said and not green:\n        refused.append(gate_said or "),
]
TESTS = {
    "M3599": f"{_SH}",
    "M3590": f"{_REL}test_without_a_gate_the_draft_is_refused_and_says_how_to_run_it",
    "M3591": f"{_REL}test_the_gate_green_on_the_pr_head_passes_a_squash_merge_of_the_same_tree",
    "M3592": f"{_REL}test_the_version_s_pull_request_says_the_gate_runs_on_it_and_must_be_green",
    "M3593": f"{_REL}test_a_gate_that_is_not_green_refuses_with_its_state_and_its_link",
    "M3594": f"{_REL}test_the_last_run_on_the_tree_decides",
    "M3595": f"{_REL}test_a_run_that_is_not_the_gate_never_passes",
    "M3596": f"{_REL}test_a_run_that_is_not_the_gate_never_passes",
    "M3600": f"{_REL}test_a_run_re_run_after_a_green_one_decides",
    "M3601": f"{_REL}test_a_pull_request_into_another_branch_never_passes",
    "M3602": f"{_REL}test_a_gate_said_nothing_still_refuses",
}

# The workflow's own (.github/workflows/release-gate.yml).
GATE = ".github/workflows/release-gate.yml"
_WF = "tests/unit/test_workflows.py::"
MUTANTS += [
    ("M3597", "the gate's last job green with a skipped job (CI6)", GATE,
     'all(job.get("result") == "success" for job in blocking.values())',
     'all(job.get("result") in ("success", "skipped") for job in blocking.values())'),
    ("M3598", "the gate measures GitHub's merge commit, not the pull request's head: another tree (CI6)", GATE,
     "      # scripts/release.py compares that tree with origin/main's.\n"
     "      - uses: actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09   # v5.1.0\n"
     "        with:\n          ref: ${{ github.event.pull_request.head.sha || github.sha }}\n",
     "      # scripts/release.py compares that tree with origin/main's.\n"
     "      - uses: actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09   # v5.1.0\n"
     "        with:\n"),
    ("M3603", "macOS red fails the gate's run: a runner GitHub never gives holds a release back (CI6, H1c)",
     GATE, "    timeout-minutes: 25\n    continue-on-error: true\n", "    timeout-minutes: 25\n"),
    ("M3604", "Terraform taken for informative beside macOS: its red never blocks (CI6, H1c)", GATE,
     "          INFORMATIVE: macos\n", "          INFORMATIVE: macos terraform\n"),
    ("M3605", "the gate's last job asks macOS to be green again (CI6, H1c)", GATE,
     "blocking = {k: v for k, v in needs.items() if k not in informative}", "blocking = dict(needs)"),
]
TESTS.update({
    "M3597": f"{_WF}test_the_last_job_is_green_only_when_every_job_that_blocks_is",
    "M3598": f"{_WF}test_every_job_of_the_gate_measures_the_pull_request_s_head_exactly",
    "M3603": f"{_WF}test_macos_informs_and_never_blocks",
    "M3604": f"{_WF}test_the_last_job_waits_for_every_other_one",
    "M3605": f"{_WF}test_the_last_job_is_green_only_when_every_job_that_blocks_is",
})
