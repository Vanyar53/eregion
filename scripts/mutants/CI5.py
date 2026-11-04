"""CI5 (#512): no conflict between pull requests — the CHANGELOG's fragments (changes/<lot>.md,
assembled by scripts/release.py prepare) and each lot's mutants in a file of its own (this one,
loaded by scripts/mutation_check.py). M3580–M3586.

The form of a lot's file, as scripts/mutation_check.py loads it: MUTANTS, TESTS (its own ids),
optionally TESTS_ALSO and CONTROL; its paths as plain strings.
"""
RELEASE = "scripts/release.py"
ANCHORS = "scripts/mutant_anchors.py"
HARNESS = "scripts/mutation_check.py"
_ASSEMBLED = ("tests/unit/test_release.py::"
              "test_fragments_are_assembled_under_the_version_in_the_order_of_sections_then_removed")

MUTANTS = [
    ("M3580", "the fragments assembled but left in changes/: the next release assembles them again (CI5)",
     RELEASE,
     "        if removed:   # in the version's commit: a fragment is never assembled twice\n"
     '            run(["git", "rm", "-q", "--", *removed], root)\n',
     ""),
    ("M3581", "the sections of the version out of their order (CI5)", RELEASE,
     'KINDS = ("Security", "Added", "Changed", "Fixed")',
     'KINDS = ("Added", "Changed", "Fixed", "Security")'),
    ("M3582", "a fragment's unknown section taken (CI5)", RELEASE,
     "            if name not in KINDS:\n",
     "            if False:\n"),
    ("M3583", "what [Unreleased] still held dropped once there are fragments (CI5)", RELEASE,
     "    for name, body in old:\n        bodies[name].append(body)\n",
     ""),
    ("M3584", "a line lost by the assembly never said (CI5)", RELEASE,
     "    return sorted((want - have).elements()) + sorted((have - want).elements())",
     "    return []"),
    ("M3585", "an id two lots' files take never refused (CI5)", ANCHORS,
     "for mid, at in places(mutants, lots).items() if len(at) > 1]",
     "for mid, at in places(mutants, lots).items() if at.count(HARNESS) > 1]"),
    ("M3586", "the lots' files never loaded: their mutants never measured (CI5)", HARNESS,
     "LOTS = {p.relative_to(REPO).as_posix(): load_lot(p) for p in lot_files()}",
     "LOTS = {}"),
]
TESTS = {
    "M3580": _ASSEMBLED,
    "M3581": _ASSEMBLED,
    "M3582": "tests/unit/test_release.py::test_a_malformed_fragment_is_refused_and_nothing_is_written",
    "M3583": _ASSEMBLED,
    "M3584": "tests/unit/test_release.py::test_a_line_lost_or_added_by_the_assembly_is_said",
    "M3585": "tests/unit/test_mutant_anchors.py",
    "M3586": "tests/unit/test_mutant_anchors.py",
}
