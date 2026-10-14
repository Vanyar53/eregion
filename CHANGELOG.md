# Changelog

Notable changes to Eregion. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and versions follow [Semantic Versioning](https://semver.org/) — before 1.0, signals, schemas and interfaces may still change. Milestones and lots: [`ROADMAP.md`](ROADMAP.md) (French).

## [Unreleased] — toward 0.3, "the full loop runs"

### Changed
- Direction set for 1.0 (eighth pass): SOC functions for the cloud workloads of teams without a SOC, proven by attack and by failure. Three-agent loop — Annatar attacks, Gothmog breaks, Glorfindel detects and responds — with Orodruin as the disposable runner and Celebrimbor as the bench builder. Production rule: never a fault or a destructive action on a real workload. README, ROADMAP, `docs/architecture.md` (shared vocabulary, the three zones), session files for Orodruin and Gothmog, reserved folders `gothmog/` and `infra/orodruin/`.

### Added
- **O0 — one target guard for every injector** (`eregion_core/inscription.py`): the bench's perimeter (its resource groups, and the subscription the scope names — named before, never checked), enrollment by the tags `eregion-target=<bench id>` and `eregion-zone` on the target and its resource group, and the production rule — in `production`, only a technique declared non-destructive; a fault, never. Anything unknown is refused. Replaces `annatar/safety/guard.py` and the perimeter of `annatar/campaign/scope.py`; Celebrimbor tags its resources (`infra/terraform/locals.tf`). The old `annatar-test=true` tag still enrolls a target on the bench during the migration. Six mutants (M42–M47), all caught.

### Planned for 0.3
- E1 — one experiment schema for a technique and a fault.
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
