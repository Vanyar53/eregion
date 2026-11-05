"""CI6e (#553): red as soon as a mutant survives outside the known survivors — `--min-caught` (14 of
2 850) replaced. A counted mutant that survives a round without a reason the harness reads is red,
with its id and its title; a known survivor is nothing; a known survivor caught is said, never red;
the uncounted stay uncounted; a shard leaves the verdict to its total (M3915–M3923). A reason whose
mark the harness does not read is a fault of scripts/mutant_anchors.py (M3924).

The six survivors without a reason on 05/11, each killed by a test (TESTS_ALSO below where it is not
already in its mutant's target): M1014 by test_host_deploy.py (the CD builds nothing since CI3, the
image built by hand is the one --build-only makes); M1223 and M1224 by a reader that reads the store
at half of every write; M1461 by the claim refusing on its own what the command's check let through;
M2915 and M3077 by another process holding the flock while this one writes; M3007 by the overview
saying a refused report in the console's log.
"""
HARNESS = "scripts/mutation_check.py"
ANCHORS = "scripts/mutant_anchors.py"
_SH = "tests/unit/test_mutation_shards.py::"
_MA = "tests/unit/test_mutant_anchors.py::"

_UNKNOWN = ("    unknown = [r for r in rows if r[2] not in UNCOUNTED and r[2] != \"CAUGHT\" "
            "and r[0] not in reasons]\n")

MUTANTS = [
    ("M3915", "the total green whatever survived: the known list never held (CI6e, the defect back)", HARNESS,
     "    return 1 if problems or unknown else 0\n", "    return 1 if problems else 0\n"),
    ("M3916", "the known survivors not read: a mutant that says why it survives is red (CI6e)", HARNESS,
     _UNKNOWN, "    unknown = [r for r in rows if r[2] not in UNCOUNTED and r[2] != \"CAUGHT\"]\n"),
    ("M3917", "a known survivor caught says nothing: its reason stays on the list for ever (CI6e)", HARNESS,
     "    for mid, title, _verdict, detail in no_more:\n", "    for mid, title, _verdict, detail in []:\n"),
    ("M3918", "a known survivor caught is red: a test that kills it fails the gate (CI6e)", HARNESS,
     "    return 1 if problems or unknown else 0\n", "    return 1 if problems or unknown or no_more else 0\n"),
    ("M3919", "the uncounted counted again: an EQUIVALENT, a STALE mutant red (CI6e)", HARNESS,
     _UNKNOWN, "    unknown = [r for r in rows if r[2] != \"CAUGHT\" and r[0] not in reasons]\n"),
    ("M3920", "a flaky mutant taken for caught: only one that survives every round is red (CI6e)", HARNESS,
     _UNKNOWN, _UNKNOWN.replace('r[2] != "CAUGHT"', 'r[2] == "SURVIVES"')),
    ("M3921", "any word before a colon read as a reason: « FLAKY: » makes a known survivor (CI6e)", HARNESS,
     "    return word if colon and word in KNOWN_MARKS else \"\"\n", "    return word if colon else \"\"\n"),
    ("M3922", "a run of its own (`--only`) green on an unknown survivor (CI6e)", HARNESS,
     "    return 1 if unknown and not args.json else 0\n", "    return 0\n"),
    ("M3923", "a shard red on its survivors: its result never uploaded, the total never says them (CI6e)",
     HARNESS, "    return 1 if unknown and not args.json else 0\n", "    return 1 if unknown else 0\n"),
    ("M3924", "a reason the harness cannot read passes the check before a push (CI6e)", ANCHORS,
     "        if not (colon and word in marks):\n", "        if False:\n"),
]
TESTS = {
    "M3915": f"{_SH}test_an_unknown_survivor_is_red_with_its_id_and_title",
    "M3916": f"{_SH}test_a_known_survivor_does_nothing",
    "M3917": f"{_SH}test_a_known_survivor_caught_is_said_to_take_off_the_list_never_red",
    "M3918": f"{_SH}test_a_known_survivor_caught_is_said_to_take_off_the_list_never_red",
    "M3919": f"{_SH}test_equivalent_multi_host_and_stale_are_not_counted",
    "M3920": f"{_SH}test_an_unknown_survivor_is_red_with_its_id_and_title",
    "M3921": f"{_SH}test_a_reason_the_harness_cannot_read_makes_no_known_survivor",
    "M3922": f"{_SH}test_a_run_of_its_own_is_red_on_an_unknown_survivor_a_shard_leaves_it_to_the_total",
    "M3923": f"{_SH}test_a_run_of_its_own_is_red_on_an_unknown_survivor_a_shard_leaves_it_to_the_total",
    "M3924": f"{_MA}test_a_reason_the_harness_does_not_read_is_a_fault "
             f"{_MA}test_mutant_anchors_reports_a_reason_it_cannot_read",
}
# The six survivors' killing tests, added to their mutants' targets (the others' own files hold them).
TESTS_ALSO = {
    "M1014": "tests/unit/test_host_deploy.py::test_build_only_tags_the_reference_and_never_the_running_image",
    "M2915": "tests/unit/test_locks.py::test_the_incident_registry_waits_for_another_process_s_write",
    "M3007": "tests/unit/test_indicators.py::test_the_overview_says_a_report_it_refuses_in_the_console_s_log_once",
}
