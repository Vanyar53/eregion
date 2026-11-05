"""CI6c (#541): the version's pull request's gate counts after its merge — its base read by its
commit's pull requests, GitHub having emptied the run's `pull_requests` (M3770); this repository's
head and main only (M3771, M3774); a read that fails, or an answer that does not read, refuses and
says it (M3772, M3773).
"""
RELEASE = "scripts/release.py"
_REL = "tests/unit/test_release.py::"

MUTANTS = [
    ("M3770", "the base read by the run's own pull_requests again: a merged version PR's gate never counts "
              "(CI6c, the defect back)", RELEASE,
     "    if not ours:\n", '    if not r.get("pull_requests"):\n'),
    ("M3771", "a pull request into main of another repository taken for the gate (CI6c)", RELEASE,
     '    bases = [_obj(pr.get("base")).get("ref") if _obj(_obj(pr.get("base")).get("repo")).get("full_name") == repo\n'
     "             else None for pr in ours]\n",
     '    bases = [_obj(pr.get("base")).get("ref") for pr in ours]\n'),
    ("M3772", "a pulls' read that fails taken for a run that is not the gate: an older one decides, the "
              "error unsaid (CI6c)", RELEASE,
     "            if into is None:\n                return False, why\n",
     "            if into is None:\n                continue\n"),
    ("M3773", "an unreadable pulls' answer taken for an empty one: refused for the wrong reason (CI6c)", RELEASE,
     "        prs = None\n", "        prs = []\n"),
    ("M3774", "a fork's pull request from a branch of the same name taken for the version's (CI6c)", RELEASE,
     '    ours = [pr for pr in prs if _obj(pr.get("head")).get("ref") == branch\n'
     '            and _obj(_obj(pr.get("head")).get("repo")).get("full_name") == repo]\n',
     '    ours = [pr for pr in prs if _obj(pr.get("head")).get("ref") == branch]\n'),
]
TESTS = {
    "M3770": f"{_REL}test_the_version_s_pr_merged_its_run_naming_no_pr_still_counts",
    "M3771": f"{_REL}test_only_this_repository_s_version_pr_into_its_main_counts",
    "M3772": f"{_REL}test_a_pulls_read_that_fails_refuses_and_says_it",
    "M3773": f"{_REL}test_a_pulls_answer_that_is_not_a_list_of_prs_refuses",
    "M3774": f"{_REL}test_only_this_repository_s_version_pr_into_its_main_counts",
}
