# Eregion — Active Cloud Defense

Eregion is an open-core platform for active cloud defense. Two AI agents form a complete loop:

- **Annatar** (red) simulates real attacks on your cloud infrastructure
- **Glorfindel** (blue) detects, responds autonomously, and verifies containment

> "Test your infrastructure before others do it for you."

## How it works

```
Annatar attacks → JSONL signals → Glorfindel decides → action → verified
```

Glorfindel uses a LangGraph graph + Claude API to reason about each signal and choose the minimum effective response. Actions are verified via Azure API. Every cycle is stored in ChromaDB for cross-scenario learning.

## Validated TTPs (Azure)

| TTP | Scenario | Detection | Response | RTO |
|-----|----------|-----------|----------|-----|
| T1486 | Ransomware VM | 50s (Perf disk write) | `isolate_vm` | 21m23s |
| T1041 | Data exfiltration | 229s (StorageBlobLogs) | `isolate_vm` (internal IP) | — |
| T1110.001 | SSH brute force | 60s (Syslog DCR) | `block_suspicious_ip` | — |

## Autonomy model

Glorfindel operates under strict autonomy rules:

- **Autonomous** (reversible): `isolate_vm`, `release_isolation`, `snapshot`, `block_suspicious_ip`, `revoke_temp_access`
- **Human required** (destructive): `restore_from_backup`, `delete_resource`, `wipe_storage`
- **Proposed unknown**: Glorfindel proposes freely, escalates automatically — human validates and codifies

The graph is defensive by design: even if the LLM proposes a destructive action without `escalate=True`, the routing blocks it.

## Quickstart

```bash
pip install eregion

# Set up Azure credentials
export AZURE_SUBSCRIPTION_ID=...
export AZURE_RESOURCE_GROUP=...
export ANTHROPIC_API_KEY=...

# Simulate locally (no Azure required)
python scripts/simulate_annatar.py
python scripts/simulate_annatar.py --ids-gap

# Run a real scenario (tagged resources only: annatar-test=true)
az vm start -g annatar -n vm-annatar-victim
glorfindel watch runs/                              # terminal 1
annatar run scenarios/azure/ransomware-vm.yaml      # terminal 2
```

## Requirements

- Python 3.11+
- Azure subscription with tagged test resources (`annatar-test: "true"`)
- Anthropic API key
- Azure Monitor workspace (for detection)

## Architecture

```
glorfindel/
  agent.py        → LangGraph graph (6 nodes)
  actions.py      → CloudConnector ABC + AzureConnector
  detectors.py    → DetectionConnector ABC + AzureMonitorDetector
  memory.py       → ChromaDB cycle memory
  cli.py          → watch, respond, restore, release, pending, ack, check-ttl
  escalations.py  → persistent escalation log

annatar/
  runner/engine.py    → pre-check + attack + emit
  signals/emitter.py  → JSONL signal emitter

scenarios/azure/
  ransomware-vm.yaml       → T1486
  data-exfiltration.yaml   → T1041
  lateral-movement.yaml    → T1110.001
```

## Adding a new cloud provider

Implement `CloudConnector` and `DetectionConnector` ABCs:

```python
class AwsConnector(CloudConnector):
    def isolate_vm(self, resource_id) -> dict: ...
    def block_suspicious_ip(self, ip, resource_id) -> dict: ...
    # ...
```

Adding AWS = one class. The agent logic doesn't change.

## Tests

```bash
pip install eregion[dev]
pytest  # 57 tests, 0 Azure calls, 0 Claude API calls
```

## License

Apache 2.0 — see [LICENSE](LICENSE).

---

*Annatar corrupts from within. Glorfindel always returns.*
