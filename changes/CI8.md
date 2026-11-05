### Changed
- **The CI's downloads are retried, never a test** (CI8, #566; `docs/operations.md`, « Ce que la CI
  retente »). A repository loop, `bash scripts/retry.sh <command>`, no third-party action: three
  attempts, 10 then 30 s apart, each said (a failure as a `::warning::` of the run), the last
  failure's exit code after the third; a command stopped by SIGINT or SIGTERM is never run again.
  It wraps only the download of each network step: the locks' `pip install` (`ci.yml`, the release
  gate, `mutants.yml`, `components.yml`, `invariants.yml`, `pip-audit.yml`), Terraform from
  HashiCorp's apt repository (its key's fingerprint check outside the loop), each module's
  `terraform init` in a step of its own before its `test` or `validate`, ChromaDB's embedding model
  fetched in a step of its own before the tests (`scripts/chroma_model.py`), and publish.yml's
  pinned `syft` and `cosign`. Never a test, the mutation, the invariants nor a check: a flaky test is
  never masked. Actions (`setup-python`, `docker/build-push-action`) are not wrapped.
  - Tests: `tests/unit/test_workflows.py` (the steps retried, listed; none that measures; every
    known download retried; retry.sh against a fake command and a fake `sleep`).
