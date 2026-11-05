### Changed
- **Orodruin's Terraform tests run in the CI** (CI7, #554; `docs/operations.md`, « Les providers de
  Terraform, verrouillés »). `terraform -chdir=infra/orodruin test -no-color` after its `validate`,
  in « Terraform validate — Orodruin » of `ci.yml` and of the release gate, after the module's
  retried `init` (CI8): the watch channel's writers (WC1, `watch_writers.tftest.hcl`) and Microsoft
  Graph's reads (IDI1, `graph_read.tftest.hcl`), planned against mock providers, no identifier. The
  test itself is never retried. `TF_AWAITING_STEP` is empty.
  - Tests: `tests/unit/test_workflows.py` (each module's `test` run, after its `init`).
