### Security
- **oauthlib 4.0.0 → 4.0.1 in the locks, nothing else moved** (DEP2, #590; `docs/operations.md`,
  « Verrou des dépendances »). The public advisory GHSA-3jp2-3mrg-2vxc (high, oauthlib 3.3.0 to
  4.0.1 excluded): the device code flow's token endpoint did not validate `device_code`, a server
  side defect. oauthlib comes through chromadb → kubernetes → requests-oauthlib; no code of Eregion
  imports it, and requests-oauthlib stays at 2.0.0. Only `requirements/dev.txt` and
  `requirements/glorfindel.txt` change: oauthlib's line, its two hashes, and their header;
  `annatar.txt` and `audit.txt` are byte for byte the same. The lock of the image changes, so H0's
  CD waits for the harness's attestation, replayed on this lock.
  - `make lock UPGRADE_PACKAGE=<name>[,<name>]` raises those packages alone, to their newest
    release before `UPGRADE_DATE` (the day by default), only in the locks that pin them; a name no
    lock pins is refused before uv runs. Each lock keeps the date it admits a package at in its
    header (`--exclude-newer-package`), and `make lock` passes it again while it postdates
    `LOCK_DATE`: without it, the next `make lock` at the same date took oauthlib back to 4.0.0,
    silently (`scripts/lock_flags.py`).
  - Tests: `tests/unit/test_dependency_lock.py`.
