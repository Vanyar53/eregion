### Changed
- **The CI in its place, on the workflows' side** (CI10b, #581; the CI9 study, taken whole by Jonathan
  on 05/11; `docs/operations.md`, « La CI au bon endroit » and « La porte de release »).
  - `ci.yml` runs `scripts/mutant_anchors.py` on each pull request and each push to `main`: a mutant
    made stale by another merge is seen at the merge, no longer at the next release gate (L16).
  - The suite runs in four processes (`pytest -n 4 --dist load`), on both Pythons, at the same budgets
    (200 sequences on a pull request, 500 on a push): pytest-xdist joins the dev extra and the dev lock
    (`make lock`; the images' locks unchanged). Measured on a shared workstation at 200 sequences: 8 223
    tests passing both ways, 152 to 183 s in 4 processes against 483 s in one (L8).
  - Components runs in one job on a pull request: each component's own two checks, the others absent,
    each run whatever the one before said, then the compose profiles; core, Annatar and Gothmog wait for
    the install alone, Glorfindel for ChromaDB's model too; its actions pinned by commit, the release
    gate's own. On a push to `main`, a job each as before. No required check changes name (L11).
  - The release gate: ten shards of mutants instead of fourteen (L5), no unmutated run of an invariant
    machine in a shard (`--skip-machine-baseline`, CI10a's harness; L3), its tests in two jobs side by
    side — Azure's machine alone, every other test in four processes — each test in exactly one (L6);
    its total no longer waits for macOS, which says itself (L7). `release-draft` takes a gate's run
    still going for a job that informs alone as green once its total and every job that blocks are; a
    run still going whose jobs cannot be read is refused with its error, never « en cours ».
  - The Monday measure keeps only the mutants whose target runs an invariant machine (`--machines`) and
    the control set, at 1 000 sequences, their total judging those alone (`--total --machines`, L13):
    the only verdicts a budget moves; the gate still measures every mutant at each release.
  - Unchanged: the night at 10 000 sequences, both Pythons, 200 sequences on a pull request, the gate's
    budget (500, two rounds).
  - Tests: `tests/unit/test_workflows.py`, `tests/unit/test_release.py`; mutants M4190–M4199 and
    M4235–M4237 (`scripts/mutants/CI10b.py`); M1441, M3597, M3604 and M3605 retargeted to the new workflows.
