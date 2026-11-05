### Changed
- **Orodruin's Terraform tests run in the CI** (CI7, #554; `docs/operations.md`, « Les providers de
  Terraform, verrouillés »). `terraform -chdir=infra/orodruin test -no-color` after its `validate`,
  in `ci.yml` and in the release gate, after the module's retried `init` (CI8): the watch channel's
  writers (WC1, `watch_writers.tftest.hcl`) and Microsoft Graph's reads (IDI1,
  `graph_read.tftest.hcl`), planned against mock providers, no identifier. The test itself is never
  retried. The step « Terraform validate — Orodruin » is now « Terraform test — Orodruin (mock
  providers) », as the other modules' (a step, not a check: no required check changes).
  `TF_AWAITING_STEP` is empty.
  - Tests: `tests/unit/test_workflows.py` (each module's `test` run, after its `init`).
