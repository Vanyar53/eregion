"""MUT3 (#599): the 17 survivors that held the 0.5.7 release gate red — there at the 0.5.6 gate too,
held since CI6e. Jonathan's decision (06/11): a FIXED-ONLY mutant is caught by the suite — its fixed
sequence of tests/unit/test_invariant_regressions.py is added to its target (TESTS_ALSO), the machine
kept; CI6e's rule unchanged for every other mutant.

- Caught by a fixed sequence: M10, M23, M24, M34, M35, M39, M40, M1961, M1963 (FIXED-ONLY), M41 (flaky).
- Caught by a unit test that already held its property: M36.
- Killed by a test of their own: M3153 (since L1O, a perimeter's `pair` reaches the narrowing only when
  its write fails again — the test the mutant named no longer went there), M3282 (`_back` has its own
  loop since L1H: `_read_both` serves `_worse` alone, whose side the test the mutant named never read),
  M1552 (the NIC was always named elsewhere — placements kept, the block's state: the kept `known_nics`
  counts once the block's state is lost too; its test's name falls in the mutant's `-k deleted_vm`) and
  M613 (the instance's lock held around every write AWS receives, the property itself).
- Rewritten in the harness: M864 called `_held_in_quarantine`, no longer imported by quarantine.py since
  SEC4b — a NameError, an isolation that failed safe, never the bug it names; with the module's own name
  (`_held_or_unreadable`), test_a_429_on_our_tag_doesnt_overwrite_a_valid_original catches it.
- M1645, taken for equivalent at first, is not (MUT3's review): a re-block clears the entry's marks
  but not the episode open in memory, and the uncovered card's mark under the same alert then reads the
  pair's next disappearance « already said ». Killed by a test of its own.
The two mutants of this lot hold M3282's and M3153's properties under another form (M4290, M4291).
"""
_RA = "glorfindel/reassert.py"
_RS = "glorfindel/reassert_said.py"
_REG = "tests/unit/test_invariant_regressions.py::"
_RE = "tests/unit/test_reassert.py::"

MUTANTS = [
    ("M4290", "a rule left out of this check read as deleted: only the card's keys compared (MUT3, M3282's "
              "other form)", _RS,
     "    return [(before[k], after[k]) for k in sorted(before.keys() & after.keys())]\n",
     "    return [(before[k], after.get(k)) for k in sorted(before.keys())]\n"),
    ("M4291", "a perimeter whose write failed again skips its narrowing: the same rules gone again after a "
              "refused card, unsaid (MUT3, M3153's other form)", _RA,
     "    if b.get(\"drift_alerted_at\") and _missing(verification) and not never_covered:\n",
     "    if b.get(\"drift_alerted_at\") and _missing(verification) and not never_covered "
     "and not (pair or {}).get(\"error\"):\n"),
]
TESTS = {
    "M4290": f"{_RE}test_a_rule_this_check_did_not_read_is_never_read_deleted",
    "M4291": f"{_RE}test_a_perimeter_whose_write_fails_again_narrows_its_baseline_before_a_refused_card",
}
TESTS_ALSO = {
    # FIXED-ONLY: the machine alone doesn't find them, their fixed sequence does (Jonathan, 06/11).
    "M10": f"{_REG}test_a_nic_whose_subnet_cant_be_read_is_neither_covered_nor_uncovered",
    "M23": f"{_REG}test_two_hosts_an_unblock_behind_the_quarantine_finds_the_block_on_x",
    "M24": f"{_REG}test_a_reset_reads_the_original_from_the_state_and_marks_what_it_left",
    "M34": f"{_REG}test_an_old_state_names_its_rules_for_the_verification_too",
    "M35": f"{_REG}test_an_interrupted_reset_is_a_release_under_way",
    "M39": f"{_REG}test_a_reset_puts_a_bare_nics_original_back_from_the_state",
    "M40": f"{_REG}test_a_block_on_a_deleted_nsg_is_gone_not_unreadable",
    "M1961": f"{_REG}test_a_block_under_its_second_name_is_found_without_its_state",
    "M1963": f"{_REG}test_a_release_after_a_lost_state_and_a_cut_isolation_says_what_it_keeps",
    # Flaky (the machine found it one round in two): its fixed sequence is there already.
    "M41": f"{_REG}test_a_reset_sweeps_the_original_it_puts_back",
    # The unit test that holds its property, outside its target.
    "M36": "tests/unit/test_glorfindel.py::test_an_old_state_file_is_moved_before_it_is_rewritten",
    # Their tests of their own.
    "M3153": f"{_RE}test_a_perimeter_whose_write_fails_again_narrows_its_baseline_before_a_refused_card",
    "M3282": f"{_RE}test_a_rule_this_check_did_not_read_is_never_read_deleted",
    # Not equivalent (MUT3's review): a re-block clears the entry's marks, not the episode open in
    # memory — the uncovered card's mark then silences the pair's next disappearance.
    "M1645": f"{_RE}test_a_reblock_then_an_uncovered_card_never_silences_the_pairs_next_disappearance",
    # The AWS machine's races never showed the instance's lock gone: its property, held directly.
    "M613": "tests/unit/test_aws_adapter.py::test_every_write_of_an_operation_holds_the_instances_lock",
}
