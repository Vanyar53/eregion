"""CI6c (#541): the version's pull request's gate counts after its merge — its base read by every
pull request of its head, closed ones too, GitHub having emptied the run's `pull_requests` (M3770,
M3782); this repository's head and main only, every pull request of the head, the run's commit one
of their heads, what the run names (M3771, M3774, M3775, M3783, M3784); an ambiguous run, one
into main beside another elsewhere, refuses (M3785); a base changed after the run refuses (M3776); a read that fails, an answer that does not read, a full page, a commit or a
branch GitHub would not give refuses and says it (M3772, M3773, M3777–M3780); one read per head
(M3781).
"""
RELEASE = "scripts/release.py"
_REL = "tests/unit/test_release.py::"

MUTANTS = [
    ("M3770", "the base read by the run's own pull_requests again: a merged version PR's gate never counts "
              "(CI6c, the defect back)", RELEASE,
     "    if not ours:\n", '    if not r.get("pull_requests"):\n'),
    ("M3771", "a pull request into main of another repository taken for the gate (CI6c)", RELEASE,
     '    bases = [_obj(pr.get("base")).get("ref") if _obj(_obj(pr.get("base")).get("repo")).get("full_name") == repo\n'
     "             else None for pr in prs]\n",
     '    bases = [_obj(pr.get("base")).get("ref") for pr in prs]\n'),
    ("M3772", "a read that fails taken for a run that is not the gate: an older one decides, the error "
              "unsaid (CI6c)", RELEASE,
     "            if into is None:\n                return False, why\n",
     "            if into is None:\n                continue\n"),
    ("M3773", "an unreadable answer taken for an empty one: the run passed over, never refused (CI6c)", RELEASE,
     "        items = None\n", "        items = []\n"),
    ("M3774", "a fork's pull request from a branch of the same name taken for the head's (CI6c)", RELEASE,
     '    if any(_obj(pr.get("head")).get("ref") != branch or _obj(_obj(pr.get("head")).get("repo")).get("full_name") != repo\n'
     "           for pr in prs):\n",
     '    if any(_obj(pr.get("head")).get("ref") != branch for pr in prs):\n'),
    ("M3775", "only the pull requests whose head is the run's commit read for their base: one closed into "
              "another branch from an older commit unseen (CI6c, review)", RELEASE,
     "             else None for pr in prs]\n", "             else None for pr in ours]\n"),
    ("M3776", "a base changed after the run never seen: its run ran another branch's workflow (CI6c, review)",
     RELEASE, "        if changed:\n", "        if False:\n"),
    ("M3777", "a pull request's events that do not read taken for none: a base change unseen (CI6c, review)",
     RELEASE,
     "        if events is None:\n            return None, f\"l'historique",
     "        if events is None:\n            continue\n        if False:\n            return None, f\"l'historique"),
    ("M3778", "a full page read as the whole: what is past it never seen (CI6c, review)", RELEASE,
     "    if len(items) >= PAGE:\n", "    if False:\n"),
    ("M3779", "a run's commit GitHub would not give compared as it is: never said unreadable (CI6c, review)",
     RELEASE,
     "    if not SHA.fullmatch(sha):\n"
     "        return None, f\"la PR de la porte de release ne se lit pas, {_where(r)} : son commit est illisible\"\n",
     ""),
    ("M3780", "a run's branch GitHub would not give put into a path: its query read (CI6c, review)", RELEASE,
     "    if not isinstance(branch, str) or not VERSION_BRANCH.fullmatch(branch):\n",
     "    if not isinstance(branch, str):\n"),
    ("M3781", "a head's pulls read again for each of its runs (CI6c, review)", RELEASE,
     '    if ("head", branch) not in read:\n', "    if True:\n"),
    ("M3782", "the head's open pull requests only (GitHub's default): one closed unmerged unseen (CI6c, review)",
     RELEASE,
     '"repos/{owner}/{repo}/pulls?head={owner}:" + branch + "&state=all&per_page=100"',
     '"repos/{owner}/{repo}/pulls?head={owner}:" + branch + "&per_page=100"'),
    ("M3783", "the base the run still names unread: an open pull request into another branch counts (CI6c)",
     RELEASE,
     '    bases += [_obj(_obj(pr).get("base")).get("ref") for pr in (r.get("pull_requests") or [])]\n', ""),
    ("M3784", "the run's commit tied to no pull request of its head: any head's list will do (CI6c, review)",
     RELEASE,
     '    ours = [pr for pr in prs if _obj(pr.get("head")).get("sha") == sha]\n', "    ours = prs\n"),
    ("M3785", "an ambiguous run passed over: one pull request of its head into main, another elsewhere, and an "
              "older green run decides (CI6c, second review)", RELEASE,
     '        if "main" in bases:\n', "        if False:\n"),
]
TESTS = {
    "M3770": f"{_REL}test_the_version_s_pr_merged_its_run_naming_no_pr_still_counts",
    "M3771": f"{_REL}test_only_this_repository_s_version_pr_into_its_main_counts",
    "M3772": f"{_REL}test_a_read_that_fails_refuses_and_says_it",
    "M3773": f"{_REL}test_an_answer_that_is_not_a_list_refuses",
    "M3774": f"{_REL}test_an_answer_with_another_head_s_pr_refuses",
    "M3775": f"{_REL}test_a_pr_closed_unmerged_into_another_branch_from_the_same_head_refuses",
    "M3776": f"{_REL}test_a_base_changed_after_the_run_refuses",
    "M3777": f"{_REL}test_a_read_that_fails_refuses_and_says_it",
    "M3778": f"{_REL}test_a_full_page_refuses_it_may_not_hold_them_all",
    "M3779": f"{_REL}test_a_commit_or_a_branch_github_would_not_give_is_never_read",
    "M3780": f"{_REL}test_a_commit_or_a_branch_github_would_not_give_is_never_read",
    "M3781": f"{_REL}test_one_head_s_pulls_are_read_once",
    "M3782": f"{_REL}test_a_pr_closed_unmerged_into_another_branch_from_the_same_head_refuses",
    "M3783": f"{_REL}test_the_run_and_its_head_s_pulls_must_both_say_main",
    "M3784": f"{_REL}test_only_this_repository_s_version_pr_into_its_main_counts",
    "M3785": f"{_REL}test_an_ambiguous_run_is_never_passed_over_for_an_older_green_one",
}
