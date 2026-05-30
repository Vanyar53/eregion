# Eregion — Automated Incident Response

Eregion is an open-source automated incident response platform for cloud infrastructure. Two AI agents form a closed loop:

- **Annatar** (red) simulates real attacks on your Azure infrastructure using MITRE ATT&CK scenarios
- **Glorfindel** (blue) detects signals continuously, responds autonomously, verifies containment, and learns from every cycle

> Autonomous SOC for teams that don't have one.

## How it works

```
┌─────────────────────────────── Red ────────────────────────────────┐
│  Annatar attacks → attack_started signal → Glorfindel detects       │
│                                          (via detection_rules.yaml) │
└─────────────────────────────────────────────────────────────────────┘
          │ detection                        │ detection_timeout
          ▼                                  ▼
  Glorfindel decides → action         LLM proposes improved rule
  → verified → stored (ChromaDB)      → human approves → rules updated
```

**Response loop** — on a detection, Glorfindel reasons about the signal (raw indicators, past cycles from ChromaDB, current incident context) and chooses the minimum effective response. Actions are verified via Azure API. Every cycle is stored in ChromaDB — no fine-tuning required.

**Detection loop** — `detection_rules.yaml` defines continuous polling rules (KQL, PromQL, SPL…). VMs are auto-discovered via LAW Heartbeat — no `resource_id` to maintain. Glorfindel polls independently of any attack simulation.

**Purple team loop** — if detection fails, Glorfindel's LLM proposes an improved query. `glorfindel approve-rule <id>` applies it. The rules get better with each missed detection.

**Posture loop** — after each discovery cycle, Glorfindel checks that it can actually defend each VM: backup linked and recent, NSG accessible. Missing capabilities are escalated immediately with the exact `az` command to fix them — before an incident, not during.

**Autonomy boundary** — destructive actions (restore, delete) always require human approval. The graph enforces this regardless of LLM output. Reversible actions (isolate, block, snapshot) run autonomously and are verified via Azure API.

Signals from different resources run in parallel threads; signals from the same resource are serialized with shared incident context.

## Validated TTPs (Azure, real runs)

| TTP | Scenario | Detection source | Detection time | Action | RTO |
|-----|----------|-----------------|----------------|--------|-----|
| T1486 | Ransomware VM | Perf disk write anomaly | ~71s | `restore_from_backup` (escalate) | 21m23s |
| T1041 | Data exfiltration | StorageBlobLogs (PutBlob, RFC-1918) | ~30s | `isolate_vm` (internal IP) | — |
| T1110.001 | SSH brute force | Syslog DCR (auth facility) | ~89s | `block_suspicious_ip` (Tor IP) | — |
| T1548.003 | Sudo privilege escalation | Syslog DCR (auth facility) | ~40s | `isolate_vm` (OS-level compromise) | — |

Glorfindel chose the right action on all four by reasoning from raw signal indicators — not from a TTP→action table.

## Getting started

### 1. Deploy the test infrastructure

> **Skip this step if you already have Azure VMs, a Log Analytics Workspace, and NSGs.**
> The Terraform provisions a dedicated sandbox for running Annatar attack simulations safely.
> Glorfindel works on any existing Azure infrastructure — the test infra is not a prerequisite.

Everything is provisioned by Terraform — Log Analytics Workspace, VM, NSG, Backup vault, Data Collection Rule, StorageBlobLogs diagnostic settings, and Managed Identity role assignment.

```bash
cd infra/terraform/
cp infra/terraform/terraform.tfvars.example infra/terraform/terraform.tfvars
# edit terraform.tfvars — set your SSH public key and notification email
terraform init
terraform apply
# → full test infrastructure in one command (~5 min)
```

**What gets deployed** (all in one resource group, tagged `annatar-test: true`):

| Resource | SKU | Purpose |
|---|---|---|
| Linux VM | Standard_D2as_v6 (2 vCPU, 8 GB) | Attack target |
| Managed disk | Standard LRS 32 GB | Test data volume |
| Log Analytics Workspace | PerGB2018 | Detection source |
| Data Collection Rule | — | Perf + Syslog → LAW |
| Recovery Services Vault | Standard LRS | VM backup for restore |
| Storage account | Standard LRS | Exfiltration target (T1041) |
| NSG | — | Isolation + IP block |
| Public IP | Standard Static | SSH access |

**Cost of the test sandbox** (West Europe, pay-as-you-go — only if you deploy the Terraform):

| Item | Monthly cost |
|---|---|
| VM compute (~6h/day, auto-shutdown at 23:00 UTC) | ~$10–15 |
| Disks + Public IP (always billed) | ~$7 |
| Azure Backup (daily, 7-day retention) | ~$5–10 |
| Log Analytics (<1 GB/month for test runs) | <$3 |
| Storage account | <$1 |
| **Total sandbox** | **~$25–35/month** |

**Cost of running Glorfindel on existing infrastructure**: LLM API only (Anthropic default) — ~$0.05–0.10 per run (<$2/month for regular testing). Free with a local Ollama model.

> The VM auto-shuts down at 23:00 UTC daily. Start it before each run: `az vm start -g annatar -n vm-annatar-victim`. Compute is only billed when running.

### 2. Install Eregion

**Option A — local (dev)**

```bash
git clone https://github.com/Vanyar53/eregion && cd eregion
make install          # creates .venv + installs all dependencies

cp .envrc.example .envrc
# edit .envrc — fill in ANTHROPIC_API_KEY and Azure credentials
# direnv allow   (or source .envrc manually)
```

Azure credentials require a Service Principal:
```bash
az ad sp create-for-rbac --name "eregion" --role Contributor \
  --scopes /subscriptions/$(az account show --query id -o tsv)
# → appId = AZURE_CLIENT_ID, password = AZURE_CLIENT_SECRET, tenant = AZURE_TENANT_ID
```

**Option B — Docker**

```bash
make build              # builds eregion-annatar + eregion-glorfindel images
make annatar-shell      # 🔴 interactive shell — alias: ar
make glorfindel-shell   # 🔵 interactive shell — alias: gf
```

**Option C — Docker Compose (watch + War Room together)**

```bash
make glorfindel-start   # start watch + war-room → http://localhost:7007
make glorfindel-logs    # tail service logs
make glorfindel-dev     # auto-reload on code change (docker compose watch)
make glorfindel-stop    # stop all services
```

State, history, and ChromaDB model cache are persisted on the host (`~/.glorfindel/`, `~/.annatar/`, `~/.cache/chroma/`).

### 3. Run your first attack/defense loop

```bash
az vm start -g annatar -n vm-annatar-victim   # VM auto-shuts down at 23:00 UTC

glorfindel watch runs/                              # terminal 1 — Glorfindel watches for signals
annatar run annatar/scenarios/azure/ransomware-vm.yaml      # terminal 2 — Annatar attacks

# Glorfindel escalates restore_from_backup within ~60s (disk encrypted — human approval required)

glorfindel pending                                  # see escalation: restore_from_backup
glorfindel restore /subscriptions/.../vm-annatar-victim --yes   # terminal 3 (~20 min)

# Glorfindel releases isolation automatically after restore completes
```

### 4. Simulate locally (no Azure required)

```bash
python scripts/simulate_annatar.py            # normal flow
python scripts/simulate_annatar.py --ids-gap  # detection_timeout flow
```

## Using Glorfindel standalone

Glorfindel doesn't require Annatar. Two standalone modes:

**Continuous detection** — configure your Log Analytics Workspace in `glorfindel-config.yaml`, then:
```bash
cp glorfindel-config.yaml.example glorfindel-config.yaml
# edit: fill in workspace_id (LAW GUID) and vault_name (RSV)
glorfindel watch runs/ --rules glorfindel/rules/azure/detection_rules.yaml
# polls rules continuously, auto-discovers VMs via Heartbeat, runs posture checks
```

`glorfindel-config.yaml` is the single source of truth for infrastructure connection details:
- `monitoring_backends` — LAW workspace IDs, Prometheus endpoints, etc.
- `action_backends` — Recovery Services Vault for restore
- `exceptions` — fnmatch patterns to opt specific VMs out of auto-discovered rules

`detection_rules.yaml` contains only detection rules (KQL queries, TTPs, backend references). VMs are discovered dynamically via LAW Heartbeat — no `resource_id` or `workspace_id` needed inline.

**Manual signal injection** — write a `detection` signal directly:
```bash
echo '{
  "signal_id": "test-001", "event": "detection", "ttp": "T1486",
  "severity": "critical", "resource_id": "/subscriptions/.../vm-name",
  "resource_type": "vm", "provider": "azure", "timestamp": "2026-01-01T00:00:00Z",
  "raw_signal": {}, "context": {"run_id": "test"}
}' >> runs/test_signals.jsonl
glorfindel respond runs/test_signals.jsonl
```

**Pre-deployment audit** — before going live, verify that Glorfindel can act:
```bash
glorfindel audit --all   # checks NSG access, backup vault, compute permissions
```
Annatar is only needed if you want to run controlled attack scenarios and measure detection time against a real attack baseline.

## Autonomy model

Glorfindel operates under strict autonomy rules. The graph enforces them regardless of what the LLM proposes.

**Autonomous** (reversible, no human approval):
`isolate_vm`, `release_isolation`, `snapshot`, `block_suspicious_ip`, `revoke_temp_access`

**Human required** (destructive or irreversible):
`restore_from_backup`, `delete_resource`, `wipe_storage`, `modify_network_rule`, `escalate_permissions`

**Proposed unknown**: Glorfindel proposes freely in snake_case, escalates automatically — human validates and the action gets codified for future runs.

> The graph is defensive by design: even if the LLM proposes a destructive action without `escalate=True`, the routing blocks it.

**How Glorfindel reasons** — it follows a validated reasoning chain from raw signal indicators, not a TTP→action lookup table. The system prompt contains production-verified examples of correct reasoning:

```
Signal: MaxWrite=147 MB/s sustained 8 min
→ Encryption likely ran. Disk data destroyed. Isolation can't recover data.
→ restore_from_backup (escalate — human confirms)

Signal: PutBlob, CallerIP=10.x.x.x (RFC-1918)
→ Internal VM uploaded data. Disk intact. Block_ip won't work on internal IP.
→ isolate_vm (reversible, severs exfil channel)

Signal: FailedAttempts=47, SourceIP=185.x.x.x (external)
→ Attacker probing, VM uncompromised. Don't disrupt the VM.
→ block_suspicious_ip (reversible, VM stays online)

Signal: sudo success, USER=root confirmed
→ OS-level access. Disk likely intact. Cut remote foothold.
→ isolate_vm (reversible, forensics later if needed)
```

This is few-shot reasoning, not a routing table. The LLM can deviate on ambiguous signals — the examples anchor the validated cases. The safety net is the graph itself: destructive actions are blocked without `escalate=true` regardless of LLM output, and `verify_action` confirms via Azure API that the action had the expected effect.

When an escalation fires, `glorfindel pending` shows **context-aware next steps generated by the LLM** — referencing the specific signal indicators, past cycle history from ChromaDB, and the resource state.

`GLORFINDEL_WEBHOOK_URL` sends two distinct notifications: escalations (`:rotating_light:` — human action required) and autonomous actions (`:robot_face:` — `isolate_vm ✓`, `block_suspicious_ip ✓`, etc.).

**Interactive Discord bot** (`glorfindel bot`): creates one thread per VM (`🔴 vm-name`) and posts escalations as structured embeds. Buttons:
- **✓ Acknowledge** — marks escalation resolved, archives thread when done
- **📋 Command** — shows the CLI command to run (ephemeral)
- **🔄 Restore** — executes `glorfindel restore` directly from Discord (for `restore_from_backup` and `low_confidence` escalations)
- **↩️ Revert** — executes `glorfindel reset` directly from Discord (for `verification_failed`) — full reset (isolation + IP blocks)

A `/pending` slash command lists open escalations. Set `DISCORD_PING_ROLE` to notify an on-call role on thread creation. When `DISCORD_BOT_TOKEN` is set, escalation webhook notifications are suppressed (bot handles them in threads).

## CLI reference

```bash
# Glorfindel
glorfindel watch runs/                          # real-time response during an Annatar run
glorfindel watch runs/ --rules glorfindel/rules/azure/detection_rules.yaml  # + continuous detection polling
glorfindel audit <resource_id>                  # remediation readiness: NSG, backup, IAM
glorfindel audit --all                          # audit all discovered VMs
glorfindel approve-rule <id>                    # apply a proposed detection rule to detection_rules.yaml
glorfindel respond runs/<run_id>_signals.jsonl  # post-run processing
# ── Remediation actions — choose the right scope ─────────────────────────────
#
# VM state after an incident:
#   isolated  = NSG deny-all rule applied (isolate_vm)
#   blocked   = NSG deny rule for a specific IP (block_suspicious_ip)
#
# Use the minimum scope:
glorfindel release <resource_id> --yes          # lift isolation only (post-restore, VM back online)
glorfindel unblock <ip> <resource_id> --yes     # remove one IP block (e.g. after T1110)
glorfindel reset <resource_id> --yes           # reset: release isolation + unblock all IPs
glorfindel restore <resource_id> --yes          # trigger Azure Backup restore (--before auto-detected)
glorfindel list                                 # all VMs with active actions (isolation + blocked IPs)
#
# War Room buttons:   ↩️ Release (isolated) | ↩️ Unblock (blocked IP) | ⟳ Reset (both)
# TUI keyboard:       x:release  u:unblock  v:reset  r:restore
glorfindel pending                              # list pending escalations
glorfindel pending --watch                      # stay running, print new escalations as they arrive
glorfindel ack <escalation_id>                  # acknowledge an escalation
glorfindel ack --all                            # acknowledge all pending escalations
glorfindel check-ttl                            # release isolations older than TTL (default 4h)
glorfindel memory-stats                         # ChromaDB cycle count
glorfindel bot                                  # start the interactive Discord bot
glorfindel dashboard                            # full-screen TUI: resources + feed + escalations
glorfindel war-room                             # web UI on http://localhost:7007 (pip install eregion[war-room])

# Annatar
annatar run annatar/scenarios/azure/ransomware-vm.yaml            # run a scenario (--dry-run available)
annatar run annatar/scenarios/azure/data-exfiltration.yaml
annatar run annatar/scenarios/azure/lateral-movement.yaml
annatar run annatar/scenarios/azure/privilege-escalation.yaml
# annatar run ... --skip-preflight                        # bypass VM state check (power + isolation)

# LLM provider — default: Anthropic Claude
ANTHROPIC_API_KEY=...               # required for default Anthropic provider
# GLORFINDEL_LLM_MODEL=anthropic/claude-sonnet-4-6  # default
# GLORFINDEL_LLM_MODEL=openai/gpt-4o               # OpenAI
# GLORFINDEL_LLM_MODEL=azure/gpt-4o                # Azure OpenAI (+ AZURE_API_KEY, AZURE_API_BASE)
# GLORFINDEL_LLM_MODEL=ollama/llama3.1             # local / air-gapped
# GLORFINDEL_LLM_BASE_URL=http://localhost:11434    # self-hosted / Ollama endpoint

# Azure
AZURE_CLIENT_ID=...
AZURE_CLIENT_SECRET=...
AZURE_TENANT_ID=...
AZURE_SUBSCRIPTION_ID=...

# Optional — webhook (one-way)
GLORFINDEL_WEBHOOK_URL=...          # Slack / Teams / Discord — escalations + autonomous actions
                                    # Discord: use https://discord.com/api/webhooks/<id>/<token>/slack

# Optional — Discord bot (interactive, bidirectional)
DISCORD_BOT_TOKEN=...               # Bot token from discord.com/developers/applications
DISCORD_CHANNEL_ID=...              # Channel ID (right-click → Copy Channel ID, Developer Mode on)
DISCORD_PING_ROLE=...               # Role ID to ping on new incident thread (optional)

GLORFINDEL_KEEP_ISOLATED=1          # forensic mode — VM stays isolated after restore
GLORFINDEL_ISOLATION_TTL_H=4        # auto-release timeout in hours (default: 4)
GLORFINDEL_INCIDENT_TTL_S=300       # incident grouping window in seconds (default: 300)
```

See [.envrc.example](.envrc.example) for a ready-to-fill template with provider examples.

## Architecture

```
glorfindel-config.yaml    → infrastructure config (workspace IDs, RSV, exceptions) — not versioned
                             monitoring_backends: LAW workspace GUID, discovery interval
                             action_backends: RSV vault name + resource group
                             exceptions: fnmatch patterns to exclude VMs from auto-discovery

glorfindel/
  agent.py             → LangGraph graph (7 nodes): load_context → [poll_detection|propose_detection_rule]
                         → decide → execute_action → verify_action → store_cycle
                         LLM reasons from raw signal indicators, not TTP→action table
  config.py            → GlorfindelConfig + load_glorfindel_config() + ExceptionConfig
  discovery.py         → AssetRegistry (thread-safe, disk-persisted) + DiscoveryService (background thread)
                         LAW Heartbeat query → replace_for_backend() evicts deleted VMs
  posture.py           → PostureChecker: backup linked, backup recent, NSG reachable — per discovered VM
                         Escalates posture_gap with exact az fix command. Dedup: pending → skip.
  actions.py           → CloudConnector ABC + AzureConnector (isolate, release, block, unblock, snapshot, verify_*, audit checks)
  detectors.py         → DetectionConnector ABC + AzureMonitorDetector
  detection_rules.py   → DetectionRule + RulePoller: continuous polling, auto-apply via discovered assets
                         load_config(path, glorfindel_cfg=None) — workspace_id from glorfindel-config.yaml
  audit.py             → AuditCheck, AuditResult, run(): NSG / backup / compute readiness checks
  proposed_rules.py    → record/pending/approve(): detection rule proposal lifecycle
  rules/azure/
    detection_rules.yaml → rules only: KQL queries, TTP tags, backend references
                           assets: [auto] + monitoring_backends: [law-annatar] per rule
                           no workspace_id, no resource_id, no asset declarations
  incidents.py         → IncidentRegistry: groups signals by resource_id within a TTL window
  memory.py            → CycleMemory: ChromaDB with confidence + past_cycles_used metadata
  cli.py               → watch, respond, restore, release, unblock, revert, list, pending, ack,
                         audit, approve-rule, check-ttl, bot, dashboard, war-room
  escalations.py       → persistent escalation log (~/.glorfindel/escalations.jsonl)
                         types: low_confidence, destructive_action, verification_failed,
                                proposed_rule, proposed_action, posture_gap
  bot.py               → Discord bot: one thread per VM, Ack/Restore/Revert buttons, /pending command
  tui.py               → Rich full-screen TUI: resources + feed + escalations, keyboard shortcuts a/r/v
  api.py               → FastAPI War Room: /api/state, /api/feed (WS), /api/config, /api/audit,
                         /api/discovered, /api/pending/rules, /api/action/*
  static/index.html    → War Room: incident cards, live feed, action buttons
                         MONITORING zone: backends + discovered VMs + posture gaps + rules (clickable)
                         Config panel: Azure credentials + LLM only

annatar/
  runner/engine.py    → setup → integrity check → attack → emit attack_started → purple-team feedback thread
  runner/parser.py    → Scenario dataclass (detection: timeout + prerequisites + hints)
  signals/schema.py   → Signal dataclass + severity_for_ttp
  signals/emitter.py  → normalized JSONL signal emitter
  scenarios/azure/
    ransomware-vm.yaml          → T1486 (detection: timeout + prerequisites + hints)
    data-exfiltration.yaml      → T1041
    lateral-movement.yaml       → T1110.001
    privilege-escalation.yaml   → T1548.003

> **Annatar never uses SSH.** Scripts are pushed to the VM via Azure Run Command (Azure VM Agent
> over the Wire Protocol — control plane only). The VM needs no SSH access and no public IP for
> Annatar to work. The only credential required is the Service Principal used for the Azure SDK.

schemas/
  scenario.schema.json → JSON Schema for IDE validation of scenario YAML files

infra/terraform/           → full test infrastructure (VM, NSG, Log Analytics, Backup, DCR)
```

## Extending Glorfindel

### Adding a detection source (Prometheus, Datadog, Splunk, Sentinel, ...)

**1. Implement `DetectionConnector` and register it in the factory:**

```python
# glorfindel/detectors.py
class PrometheusDetector(DetectionConnector):
    def __init__(self, workspace_id: str):   # workspace_id = Prometheus endpoint
        self.endpoint = workspace_id

    def poll_alert(
        self, query: str, since: float, timeout_s: float, interval_s: float = 10.0
    ) -> tuple[float, dict] | None:
        # Poll until the query returns results or timeout_s expires
        # Return (elapsed_seconds, first_result_row) or None
        ...

_DETECTORS["prometheus"] = PrometheusDetector
```

The result row is what the LLM sees to decide — include `CallerIpAddress` or `SourceIP` for internal/external IP routing to work correctly. The `RulePoller` uses `interval_s` from each rule; `poll_detection` uses a tight 10s loop for `attack_started` signals.

**2. Add the query language to `agent.py`:**

```python
# glorfindel/agent.py — _SOURCE_LANGUAGES
_SOURCE_LANGUAGES["prometheus"] = "PromQL"
```

This ensures the LLM proposes queries in the right language when `detection_missed` fires.

**3. Add a backend in `glorfindel-config.yaml` and a rule in `detection_rules.yaml`:**

```yaml
# glorfindel-config.yaml
monitoring_backends:
  - name: prometheus-local
    type: prometheus
    workspace_id: "http://prometheus:9090"
    discovery:
      enabled: false   # Prometheus discovery not yet implemented
```

```yaml
# detection_rules.yaml
- name: high-cpu-anomaly
  description: "Sustained CPU saturation — possible cryptomining or ransomware"
  ttp: T1496
  monitoring_backends: [prometheus-local]
  assets: [auto]
  interval_s: 30
  query: |
    rate(node_cpu_seconds_total{mode!="idle"}[5m]) > 0.9
```

### Adding a cloud provider (AWS, GCP, ...)

```python
class AwsConnector(CloudConnector):
    def isolate_vm(self, resource_id) -> dict: ...
    def block_suspicious_ip(self, ip, resource_id) -> dict: ...
    def release_isolation(self, resource_id) -> dict: ...
```

Adding AWS = one class. Agent logic, scenarios, and RAG memory don't change.

## Operational notes

**Before each run**, `annatar run` automatically checks that the VM is running and not isolated by Glorfindel. If either check fails, the run aborts with the exact fix command. Use `--skip-preflight` to bypass.

To check manually:
```bash
glorfindel list                            # active isolations + blocked IPs
glorfindel reset <resource_id> --yes      # release isolation + unblock all IPs
```

**NSG isolation blocks Azure Monitor Agent** (outbound deny-all). If the VM stays isolated, the next run will hit `detection_timeout` instead of `detection`. Always release before running the next scenario.

**Block IP rules persist** between runs. After a `block_suspicious_ip` action (T1110), the NSG rule stays until explicitly removed. Running `isolate_vm` on a VM with an existing block rule at priority 200 will conflict — always unblock between runs.

**Syslog detection latency**: ~40-60s nominal. Scenario timeout set to 300s for margin (DCR ingestion can vary).

**StorageBlobLogs**: near-realtime (seconds). `AzureNetworkAnalytics_CL` (Traffic Analytics) is unusable for detection — 10-60 min latency.

**Each scenario's `detection` block** contains `prerequisites` (verification queries to run before launching), `hints` (purple-team context sent to Glorfindel on `detection_missed`), `timeout` (hard stop for the feedback watcher), and optionally `time_max` (declared SLA). Detection queries and configuration live in `detection_rules.yaml` — not in the scenario.

**Before each run, run the prerequisite queries** in your monitoring system. If any returns no rows, detection will time out.

**Before deploying Glorfindel**, verify remediation readiness:
```bash
glorfindel audit --all   # NSG / backup vault / compute — surfaces IAM gaps with fix commands
```

## Tests

```bash
pip install eregion[dev]
pytest
# 184 tests — 0 Azure calls, 0 LLM calls
```

Coverage: 7 LangGraph nodes (incl. propose_detection_rule), routing rules, signal schema, safety guard, YAML parser, ChromaDB memory, CLI escalation flow, detection rules (RulePoller + auto-apply + eviction), proposed rules lifecycle, audit readiness checks, GlorfindelConfig + ExceptionConfig, AssetRegistry + DiscoveryService (replace-on-refresh, self-evicting threads), PostureChecker (dedup, re-escalation).

## License

Apache 2.0 — see [LICENSE](LICENSE).

---

*Annatar corrupts from within. Glorfindel always returns.*
