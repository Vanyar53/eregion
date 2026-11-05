"""REL3 (#569): release-draft judges the gate by its jobs, never by its run's conclusion — a job
that informs (macOS) red, cancelled or absent never holds the draft (M4035); a job that blocks not
green refuses, its total green or not (M4036); the total « release gate » absent refuses (M4037),
not green refuses (M4038); of a job re-run, its last attempt stands (M4039), never its id alone
(M4120); two jobs of one name in one attempt refuse (M4121); an answer without `total_count`
refuses (M4122).
"""
RELEASE = "scripts/release.py"
_REL = "tests/unit/test_release.py::"

MUTANTS = [
    ("M4035", "a job that informs read as one that blocks: macOS cancelled for want of a runner holds the "
              "draft back again (REL3, the defect back)", RELEASE,
     "if name not in informative and name != GATE_JOB\n", "if name != GATE_JOB\n"),
    ("M4036", "only the total read: a shard red beside a total green passes (REL3)", RELEASE,
     "    if red:\n", "    if False:\n"),
    ("M4037", "the total absent read as green: a run without « release gate » passes (REL3)", RELEASE,
     "    total_job = last.get(GATE_JOB)\n",
     '    total_job = last.get(GATE_JOB, {"status": "completed", "conclusion": "success"})\n'),
    ("M4038", "the total's conclusion unread: a total red, every job it holds green, passes (REL3)", RELEASE,
     '    if total_job.get("conclusion") != "success":\n', "    if False:\n"),
    ("M4039", "of a job re-run, its first attempt kept: the later one never stands (REL3)", RELEASE,
     "        if name not in last or _attempt(job) >= _attempt(last[name]):\n",
     "        if name not in last:\n"),
    ("M4120", "of a job re-run, its id alone compared: an attempt 2 under smaller ids never stands (REL3, review)",
     RELEASE,
     "    return (a if isinstance(a, int) and not isinstance(a, bool) else 0,\n",
     "    return (0,\n"),
    ("M4121", "two jobs of one name in one attempt: the later id taken, a red beside a green unseen (REL3, review)",
     RELEASE,
     "        if name in last and _attempt(job)[0] == _attempt(last[name])[0]:\n", "        if False:\n"),
    ("M4122", "an answer without total_count read as whole: a page that may not hold them all (REL3, review)",
     RELEASE,
     "    if not isinstance(total, int) or isinstance(total, bool):\n", "    if False:\n"),
]
TESTS = {
    "M4035": f"{_REL}test_a_job_that_informs_red_cancelled_or_absent_never_holds_the_draft",
    "M4036": f"{_REL}test_a_job_that_blocks_not_green_refuses_its_total_green_or_not",
    "M4037": f"{_REL}test_the_total_absent_refuses",
    "M4038": f"{_REL}test_the_total_not_green_refuses_every_other_job_green",
    "M4039": f"{_REL}test_a_job_re_run_its_last_attempt_stands",
    "M4120": f"{_REL}test_a_job_re_run_its_last_attempt_stands",
    "M4121": f"{_REL}test_two_jobs_of_one_name_in_one_attempt_refuse",
    "M4122": f"{_REL}test_jobs_that_cannot_be_read_refuse",
}
