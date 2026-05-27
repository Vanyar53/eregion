# Eregion — Active Cloud Defense

Eregion is an open-core platform for active cloud defense. Two AI agents form a complete loop:

- **Annatar** (red) simulates real attacks on your Azure infrastructure using MITRE ATT&CK scenarios
- **Glorfindel** (blue) detects signals from any source, responds autonomously, verifies containment, and learns from every cycle

> "Test your infrastructure before others do it for you."

## How it works

```
Annatar attacks → JSONL signals → Glorfindel decides → action → verified → stored
```

Glorfindel uses a LangGraph graph + LLM via LiteLLM to reason about each signal and choose the minimum effective response. Actions are verified via Azure API. Every cycle is stored in ChromaDB for cross-scenario learning — no fine-tuning required.

Signals from different resources are processed in parallel; signals from the same resource are serialized with shared incident context so Glorfindel never re-isolates a VM it already contained. When an `attack_started` signal arrives, detection polling starts immediately in a dedicated thread — two simultaneous attacks on the same VM each poll their detection source in parallel, then make sequential decisions with shared incident context once detected.

## Validated TTPs (Azure, real runs)

| TTP | Scenario | Detection source | Detection time | Action | RTO |
|-----|----------|-----------------|----------------|--------|-----|
| T1486 | Ransomware VM | Perf disk write anomaly | 50s | `isolate_vm` | 21m23s |
| T1041 | Data exfiltration | StorageBlobLogs (PutBlob) | 229s | `isolate_vm` (internal IP) | — |
| T1110.001 | SSH brute force | Syslog DCR (auth facility) | 60s | `block_suspicious_ip` (Tor IP) | — |
| T1548.003 | Sudo privilege escalation | Syslog DCR (auth facility) | 40s | `isolate_vm` (OS-level compromise) | — |

Glorfindel chose the right action on all four without explicit per-TTP rules — it reasoned from signal context.

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

State, history, and ChromaDB model cache are persisted on the host (`~/.glorfindel/`, `~/.annatar/`, `~/.cache/chroma/`).

### 3. Run your first attack/defense loop

```bash
az vm start -g annatar -n vm-annatar-victim   # VM auto-shuts down at 23:00 UTC

glorfindel watch runs/                              # terminal 1 — Glorfindel watches for signals
annatar run scenarios/azure/ransomware-vm.yaml      # terminal 2 — Annatar attacks

# Glorfindel isolates the VM automatically within ~60s

glorfindel pending                                  # see escalation: restore_from_backup required
glorfindel restore /subscriptions/.../vm-annatar-victim --yes   # terminal 3

# Glorfindel releases isolation automatically after restore
```

### 4. Simulate locally (no Azure required)

```bash
python scripts/simulate_annatar.py            # normal flow
python scripts/simulate_annatar.py --ids-gap  # detection_timeout flow
```

## Using Glorfindel standalone

Glorfindel doesn't require Annatar. Any valid JSONL signal triggers the response loop.
Annatar is only needed if you want to measure `detection_s` from a real attack baseline.

```bash
# Or write a signal directly
echo '{"event": "attack_started", ...}' >> runs/test_signals.jsonl
glorfindel respond runs/test_signals.jsonl
```

## Autonomy model

Glorfindel operates under strict autonomy rules. The graph enforces them regardless of what the LLM proposes.

**Autonomous** (reversible, no human approval):
`isolate_vm`, `release_isolation`, `snapshot`, `block_suspicious_ip`, `revoke_temp_access`

**Human required** (destructive):
`restore_from_backup`, `delete_resource`, `wipe_storage`, `modify_network_rule`, `escalate_permissions`

**Proposed unknown**: Glorfindel proposes freely in snake_case, escalates automatically — human validates and the action gets codified for future runs.

> The graph is defensive by design: even if the LLM proposes a destructive action without `escalate=True`, the routing blocks it.

When an escalation fires, `glorfindel pending` shows **context-aware next steps generated by the LLM** — referencing the specific TTP, past cycle history from ChromaDB, and the resource state. Not a static template: the same LLM that detected the issue tells you what to do next.

`GLORFINDEL_WEBHOOK_URL` sends two distinct notifications: escalations (`:rotating_light:` — human action required) and autonomous actions (`:robot_face:` — `isolate_vm ✓`, `block_suspicious_ip ✓`, etc.).

## CLI reference

```bash
# Glorfindel
glorfindel watch runs/                          # real-time response during an Annatar run
glorfindel respond runs/<run_id>_signals.jsonl  # post-run processing
glorfindel restore <resource_id> --yes          # trigger Azure Backup restore (--before auto-detected)
glorfindel release <resource_id> --yes          # manually release an isolation
glorfindel unblock <ip> <resource_id> --yes     # remove a block_suspicious_ip rule
glorfindel list                                 # all VMs with active actions (isolation + blocked IPs)
glorfindel revert <resource_id> --yes           # release isolation + unblock all IPs in one command
glorfindel pending                              # list pending escalations
glorfindel pending --watch                      # stay running, print new escalations as they arrive
glorfindel ack <escalation_id>                  # acknowledge an escalation
glorfindel ack --all                            # acknowledge all pending escalations
glorfindel check-ttl                            # release isolations older than TTL (default 4h)
glorfindel memory-stats                         # ChromaDB cycle count

# Annatar
annatar run scenarios/azure/ransomware-vm.yaml            # run a scenario (--dry-run available)
annatar run scenarios/azure/data-exfiltration.yaml
annatar run scenarios/azure/lateral-movement.yaml
annatar run scenarios/azure/privilege-escalation.yaml

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

# Optional
GLORFINDEL_WEBHOOK_URL=...          # Slack/Teams — escalations + autonomous actions
GLORFINDEL_KEEP_ISOLATED=1          # forensic mode — VM stays isolated after restore
GLORFINDEL_ISOLATION_TTL_H=4        # auto-release timeout in hours (default: 4)
GLORFINDEL_INCIDENT_TTL_S=300       # incident grouping window in seconds (default: 300)
```

See [.envrc.example](.envrc.example) for a ready-to-fill template with provider examples.

## Architecture

```
glorfindel/
  agent.py        → LangGraph graph (6 nodes): load_context → poll_detection → decide
                    → execute_action → verify_action → store_cycle
  actions.py      → CloudConnector ABC + AzureConnector (isolate, release, block, unblock, snapshot, verify_*)
  detectors.py    → DetectionConnector ABC + AzureMonitorDetector (polls every 10s)
  incidents.py    → IncidentRegistry: groups signals by resource_id within a TTL window (~/.glorfindel/incidents.jsonl)
  memory.py       → CycleMemory: ChromaDB with confidence + past_cycles_used metadata
  cli.py          → watch (threaded, per-resource queues), respond, restore, release, unblock, pending, ack, check-ttl
  escalations.py  → persistent escalation log (~/.glorfindel/escalations.jsonl)

annatar/
  runner/engine.py    → setup → integrity check → attack → emit attack_started
  signals/emitter.py  → normalized JSONL signal emitter

scenarios/azure/
  ransomware-vm.yaml          → T1486
  data-exfiltration.yaml      → T1041
  lateral-movement.yaml       → T1110.001
  privilege-escalation.yaml   → T1548.003

schemas/
  scenario.schema.json → JSON Schema for IDE validation of scenario YAML files

infra/terraform/           → full test infrastructure (VM, NSG, Log Analytics, Backup, DCR)
```

## Extending Glorfindel

### Adding a detection source (Prometheus, Datadog, Splunk, Sentinel, ...)

Implement `DetectionConnector` and register it in the factory:

```python
class PrometheusDetector(DetectionConnector):
    def poll_alert(self) -> tuple[float, dict] | None:
        # Query Prometheus
        # Return (detection_s, result_row) or None
        ...

# detectors.py — factory
def detector_for(source: str) -> DetectionConnector:
    if source == "prometheus":
        return PrometheusDetector(...)
```

`poll_alert()` is called every 10s by the `poll_detection` node. The result row is what the LLM
sees to decide — include `CallerIpAddress` or `SourceIP` for internal/external IP routing to work correctly.

### Adding a cloud provider (AWS, GCP, ...)

```python
class AwsConnector(CloudConnector):
    def isolate_vm(self, resource_id) -> dict: ...
    def block_suspicious_ip(self, ip, resource_id) -> dict: ...
    def release_isolation(self, resource_id) -> dict: ...
```

Adding AWS = one class. Agent logic, scenarios, and RAG memory don't change.

## Operational notes

**Before each run**, verify no stale isolation or block rules are active:
```bash
az network nsg rule list -g <rg> --nsg-name <nsg> -o table
# If glorfindel-isolation-* rules are present:
glorfindel release <resource_id> --yes
# If glorfindel-block-* rules are present (left over from a T1110 run):
glorfindel unblock <ip> <resource_id> --yes
```

**NSG isolation blocks Azure Monitor Agent** (outbound deny-all). If the VM stays isolated, the next run will hit `detection_timeout` instead of `detection`. Always release before running the next scenario.

**Block IP rules persist** between runs. After a `block_suspicious_ip` action (T1110), the NSG rule stays until explicitly removed. Running `isolate_vm` on a VM with an existing block rule at priority 200 will conflict — always unblock between runs.

**Syslog detection latency**: ~40-60s nominal. Scenario timeout set to 300s for margin (DCR ingestion can vary).

**StorageBlobLogs**: near-realtime (seconds). `AzureNetworkAnalytics_CL` (Traffic Analytics) is unusable for detection — 10-60 min latency.

**Each scenario declares its prerequisites** in a `prerequisites:` block with KQL verification queries. Run those queries in Log Analytics before launching — if any returns no rows, the detection will time out.

## Tests

```bash
pip install eregion[dev]
pytest
# 88 tests — 0 Azure calls, 0 LLM calls
```

Coverage: 6 LangGraph nodes, routing rules, signal schema, safety guard, YAML parser, ChromaDB memory, CLI escalation flow, T1548 privilege escalation detection.

## License

Apache 2.0 — see [LICENSE](LICENSE).

---

*Annatar corrupts from within. Glorfindel always returns.*
