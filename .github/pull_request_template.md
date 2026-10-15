## Lot

<!-- ID and title, e.g. "O1 — Orodruin on a dedicated VM", or the bug this fixes. -->

## What changes

<!-- A few lines: the behavior before and after, and why. -->

## Done when

<!-- Each "done when" criterion of the lot: met or not met, with the evidence (test name, file:line). -->

- [ ] 

## Checks

- [ ] `pytest` green and `ruff check .` clean
- [ ] Mutants required by the lot are present and caught
- [ ] Tests never call Azure or an LLM (`dry_run=True`, throwaway `HOME`)
- [ ] README, the doc concerned (`docs/`) and CHANGELOG updated if behavior changed; CLAUDE.md only if a rule or a convention changed
- [ ] No real infrastructure identifier (local hooks on: `git config core.hooksPath .githooks`)

## Model and review

<!-- Work done with Claude Code only: which model did it ("Opus 5.5", or "Opus 5.5 + fallback"),
     and for a fallback, the Opus 5.5 review verdict. See docs/elrond.md. -->
