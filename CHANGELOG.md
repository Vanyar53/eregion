# Changelog

Notable changes to Eregion. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and versions follow [Semantic Versioning](https://semver.org/) — before 1.0, signals, schemas and interfaces may still change. Milestones and lots: [`ROADMAP.md`](ROADMAP.md) (French).

## [Unreleased] — toward 0.3, "the full loop runs"

### Changed
- Direction set for 1.0 (eighth pass): SOC functions for the cloud workloads of teams without a SOC, proven by attack and by failure. Three-agent loop — Annatar attacks, Gothmog breaks, Glorfindel detects and responds — with Orodruin as the disposable runner and Celebrimbor as the bench builder. Production rule: never a fault or a destructive action on a real workload. README, ROADMAP, `docs/architecture.md` (shared vocabulary, the three zones), session files for Orodruin and Gothmog, reserved folders `gothmog/` and `infra/orodruin/`.

### Fixed
- **The account-creation rule (T1136.001) fires on real creations only** (seventh review, P1). It matched every line mentioning useradd: failures (« already exists »), the « new group » line of the same creation, package-manager system accounts. On 14 days of the bench it matched only Azure agents' own accounts. It now keeps « new user: name=… » lines, except a system account without a login shell and the known agent accounts without a shell — a system UID with a shell, or an agent's name with a shell, stays. Validated on the real KQL engine (9 cases; 0 line on 14 days instead of 6); same output columns.
- **The card's NSG group no longer contradicts the readiness gate** (seventh review, P2): « NSG precedence » failed (✗) as soon as an allow came before a Glorfindel deny, while the gate knows the quarantine NSG neutralises it for an isolation and makes it a reserve for a block. The audit now judges it with the gate's own rule (`readiness.isolation_by_quarantine`): ok when the isolation goes through the quarantine, a reserve (⚠) otherwise — never a failure, as in the gate.
- **The War Room's root dot no longer reports a breakdown for a fleet posture** (seventh review, P3): a VM without a usable backup turned it red, « A module is in error ». It is now orange and says how many VMs lack a backup; red stays for a module that actually fails (a rule's poll, the audit itself).
- **The audit read a 0-s cadence right after a boot** and claimed the ransomware rule's fine mode: the agent's first upload sends several samples under one timestamp (measured on the bench). The cadence is now the smallest gap between seconds that each carry one sample; until there is one, the audit says it can't tell yet. Measured: 10 s on the bench, the real cadence.

### Added
- **The War Room card shows what detection can see of a VM** (P4): a fourth readiness group, *Detection*, next to NSG, Backup and Compute. The audit reads the disk write counter and its cadence, whether the VM sends Syslog, and the state of each rule that covers it — sees data, blind (its table gets nothing from the VM), in error (its last poll failed), or reading rows from elsewhere (storage). A VM the rules can't see no longer looks normal. Queries checked read-only on 14 days of the bench's Log Analytics.
- **DX1 — a light `CLAUDE.md`** (143 KB → 16 KB): every session and subagent loads it, so it keeps only the concept, the safety rules, the conventions and the sessions, with an index into `docs/`. The detail moved verbatim to `docs/glorfindel.md`, `docs/azure.md`, `docs/fichiers-cles.md`, `docs/operations.md` and `docs/historique.md`, and the priorities to the ROADMAP; each `CLAUDE_<ROLE>.md` points to its docs. `scripts/check_paragraphs.py` checks nothing was lost; `tests/unit/test_docs_budget.py` keeps it under 25 KB with a resolving index (mutants M48, M49). Convention: update the doc concerned; `CLAUDE.md` only when a rule or a convention changes.
- **elrond: roadmap lots dispatched to Claude Code subagents** (`.claude/skills/elrond/`, `.claude/agents/`, `docs/elrond.md`).
  - The main session keeps only the plan index and dispatches one Opus 5.5 subagent per lot, each in its own worktree.
  - `palantir.py` journals safeguard stops and model fallbacks: which model answered, at which step, and the files written meanwhile.
  - Work done on a fallback model is reviewed by Opus 5.5 before it counts as done.
  - A fallback episode that ran a shell command says its list of written files is incomplete (`files_complete: false`, with its commands): the reviewer then reads the whole diff. Measured on a real session, where Bash writes were missing from the list.
  - Optional user-level hooks: `scripts/elrond-hooks.sh`. Pull request template: `.github/pull_request_template.md`.
- **E1 — one experiment schema for a technique and a fault** (`schemas/experiment.schema.json`, versioned v1): same shape for both — `kind` absent means `technique`, `engine` absent means `local-script`, so the five existing scenarios validate unchanged; a fault names its engine, reference and steady state; a technique on another engine than local-script (Stratus, Atomic) is run by its `engine_ref`, without steps. The catalog schema (`schemas/technique_catalog.schema.json`) now holds faults, in their own `faults` list — a fault has no ATT&CK id, and neither technique loader picks it up. (Reviewed with Opus 5.5 after being written on a fallback model: both points fixed then.) `eregion_core/experiment.py` validates both; `tests/unit/test_experiment_schema.py` runs in CI (the catalog is validated there).
- **O0 — one target guard for every injector** (`eregion_core/inscription.py`): the bench's perimeter (its resource groups, and the subscription the scope names — named before, never checked), enrollment by the tags `eregion-target=<bench id>` and `eregion-zone` on the target and its resource group, and the production rule — in `production`, only a technique declared non-destructive; a fault, never. Anything unknown is refused. Replaces `annatar/safety/guard.py` and the perimeter of `annatar/campaign/scope.py`; Celebrimbor tags its resources (`infra/terraform/locals.tf`). The old `annatar-test=true` tag still enrolls a target on the bench during the migration. Six mutants (M42–M47), all caught.

### Planned for 0.3
- O1 — Orodruin on a dedicated VM: limited identity and egress, contract checked at startup, kill switch.
- R1 — first adapter to a public attack library (Stratus Red Team).
- G0 — Gothmog v0 on Azure Chaos Studio.
- B1, B2, IA0 — a second cloud model in the harness, injection through logs and memory, a campaign report whose every claim cites its run.

## [0.2.0] — not yet tagged

First release to be tagged; earlier work is in the git history.

### Glorfindel — detection and response
- Continuous rule-based detection (RulePoller, one query per rule, rows routed to VMs), assets discovered from their own telemetry (Log Analytics Heartbeat).
- Decision by an LLM (provider-agnostic via LiteLLM) over the enriched signal, a RAG memory of past cycles (ChromaDB) and validated few-shot examples, framed by deterministic guards: executable action, confidence gate, uncharacterized-signal guardrail, attribution, release precondition, autonomy mode, readiness lock. Any model failure escalates; it never acts.
- Autonomy per asset: `human_only` (default) and `non_disruptive`, with a readiness check before a VM leaves `human_only`; observe-only mode on read-only credentials.
- Verified response on Azure: just-in-time isolation by a quarantine NSG (the customer's NSG set aside and restored, compatible with Terraform — measured), Azure DNS and IMDS denied, open sessions cut, every NIC covered, NSG precedence checked, IP blocks in both directions, reassertion every minute, snapshot and restore through Recovery Services Vault with Run Command neutralized before a restore.
- Purple loop: detection rules authored by the LLM, grounded on a technique catalog and the real table schema — reactively on a missed attack, proactively with `propose-rules`; every rule is a proposal a human approves.
- War Room web UI, Discord bot, terminal dashboard; observation kit (`glorfindel verdict`, `glorfindel report`).

### Annatar — attacks
- Scenarios validated in real runs on Azure: T1486, T1041, T1110.001, T1548.003, T1136.001, and T1110 with T1548 in parallel.
- Generative campaigns: a kill chain composed from the shared technique catalog, optionally LLM-planned, within a scope and a budget.

### Proof
- Hermetic unit tests (no Azure call, no LLM call), property-based invariants on an in-memory Azure whose world moves, a mutation check with a control set, cross-process lock tests, a daily azurerm canary, the Celebrimbor bench (Terraform).
