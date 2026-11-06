### Added
- **A read-only identity for the Claude session « Banc », off by default** (BRO1, #614;
  `docs/operations.md`, « L'identité de lecture du banc (BRO1) »). The session reads the bench's
  detections and reports (KQL on the bench's Log Analytics workspace) without asking the maintainer
  each time; it is never for a code lot. `infra/terraform/bench_reader.tf` (`bench_reader_enabled =
  false`) sets a single-tenant application and its service principal, with no permission asked and no
  enrolment tag, a public certificate, and one role assignment: Log Analytics Reader, scoped to the
  bench's workspace alone. The private key is drawn on the operator's machine (`make
  celebrimbor-reader-key`, 30 days by default, 90 at most) and never enters the Terraform state. A
  certificate file holding anything but one `CERTIFICATE` block stops the plan, and the plan's
  diagnostic never shows that file (a sensitive value). The credential's end is the certificate's,
  set explicitly (`end_date`, read from the `reader.end` file the key generation writes; the plan
  refuses an end more than 91 days away): left out, the API would pick one, « typically around 2
  years ». The canonical instance only; no new provider, the lock file unchanged. `make
  celebrimbor-reader-plan`, `celebrimbor-reader-up [YES=1]` and `celebrimbor-reader-profile`
  (targeted, the instance checked before any call); the `bench_reader` output holds identifiers only.
  - `scripts/bench_reader.py`: `keygen`, `profile`, `status`, `login`, `query`, `verify` (one query
    read, one write refused), `logout`. It runs `az` in the reader's own `AZURE_CONFIG_DIR`, without the
    caller's `AZURE_*` or `ARM_*` variables, against the profile's workspace only. Files others can
    read are refused. Every command but `status` refuses inside a code session (`EREGION_AGENT_SESSION`,
    a lot's worktree); the session's commands also want `EREGION_BANC_SESSION=1` and `AZURE_CONFIG_DIR`
    set to the reader's own, so that a bare `az` in the session never reads the maintainer's sign-in;
    `login`, `query` and `verify` refuse a session that inherited a credential from the shell that
    launched it (`ARM_*`, `AZURE_*`, `GH_*`, `GITHUB_*`, `*SECRET*`, `*TOKEN*`, and a non-empty
    `GIT_ASKPASS`, `SSH_ASKPASS` or `VSCODE_GIT_*`, through which a VS Code terminal's git would get
    the maintainer's GitHub sign-in; names said, never values). `status` says a posed end already past.
  - The Banc session's own settings, documented for the maintainer to write (`AZURE_CONFIG_DIR`, an
    empty `GH_CONFIG_DIR`, a `GIT_CONFIG_GLOBAL` without a credential helper, `GIT_TERMINAL_PROMPT=0`,
    empty `GIT_ASKPASS` and `SSH_ASKPASS`),
    and a launch from a fresh terminal where `.envrc` was never sourced, its environment's names
    checked first: otherwise, a session launched outside the repository holds the maintainer's
    credentials.
  - The rule in `docs/sessions.md`; a new boundary in `docs/design/modele-de-menace.md` (8).
  - Tests: `tests/unit/test_bench_reader.py`, `infra/terraform/tests/bench_reader.tftest.hcl`
    (`terraform test`, mock providers); mutants M4420–M4424, M4495–M4499 and M4507 (`scripts/mutants/BRO1.py`).
