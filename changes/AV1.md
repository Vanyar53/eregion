### Fixed
- **`annatar validate` says a failure by its exit code** (AV1, #524 ; `docs/operations.md`). It
  exited 0 even on an invalid scenario, so a script or a CI that trusted it (`make
  annatar-validate`) took the scenario for good. One invalid scenario now exits 1 with its cause;
  `--all` (and `validate` with no argument) exits 1 as soon as one is invalid, its causes under
  each and the invalid ones listed at the end; all valid: 0. An empty file, a YAML list or a
  `target` that is no mapping is a scenario said invalid, never a `TypeError` that stopped `--all`
  before the scenarios after it; a cause is printed as written, never read as markup.
  - Tests: `tests/unit/test_annatar_cli.py`. Mutants M3650–M3654 (`scripts/mutants/AV1.py`).
