### Fixed
- **A reset Azure refuses is no longer read as keeping a rule unsaid** (I3K, #602; `docs/design/preuves.md`).
  The invariant machine, during MUT3's review, failed on `main` unmutated: after the role was taken away
  (every write refused), `reset --from-azure` said `swept_partial` and named each rule by its delete error,
  but the oracle asked « gardée » of the isolation deny that held back a turned allow for the VM's own other
  NIC (one NIC's old address given to the other). Nothing kept that rule: the reset lifts the VM, the turned
  rule with it, as the code reads the VM's NICs as its own. The oracle now asks of such a rule its name in
  `failed`, by its error (a whole name, never the start of another), and « gardée » only of a rule kept
  for another VM's flows. A refused delete said done, in `deleted`, is caught: no other invariant read
  `deleted`. Not the case of the identifier: the canonical id fails the same. The reset itself is
  unchanged.
  - Tests: `tests/unit/test_invariant_regressions.py` (`test_a_reset_refused_by_azure_names_the_rule_it_leaves`,
    red on `main` 3f6ae335), `tests/unit/test_invariants.py` (`_held_for_itself`, `_kept_said`); mutants
    M4413 (the refused delete said without its rule) and M4414 (the refused delete said done; survives the
    first version of the oracle) (`scripts/mutants/I3K.py`).
