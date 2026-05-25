# Eregion — Active Cloud Defense

Eregion is an open-core platform for active cloud defense. Two AI agents form a complete loop:

- **Annatar** (red) simulates real attacks on your cloud infrastructure
- **Glorfindel** (blue) detects signals from any source, responds autonomously, and verifies containment

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

## Using Glorfindel standalone

Glorfindel doesn't require Annatar. Any valid JSONL signal triggers the response loop.
Annatar is only needed if you want to measure `detection_s` from a real attack baseline.

```bash
# Simulate without Azure or Annatar
python scripts/simulate_annatar.py
python scripts/simulate_annatar.py --ids-gap

# Or write a signal directly
echo '{"event": "attack_started", ...}' >> runs/test_signals.jsonl
glorfindel respond runs/test_signals.jsonl
```

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

`poll_alert()` is called every 10s by the `poll_detection` node.
The result row is what the LLM sees to decide — include `CallerIpAddress`
or `SourceIP` for internal/external IP routing to work correctly.

Already have a SIEM? Implement a `SentinelDetector` or `SplunkDetector`
that queries your SIEM alerts instead of raw sources. Everything else stays the same.

### Adding a cloud provider (AWS, GCP, ...)

```python
class AwsConnector(CloudConnector):
    def isolate_vm(self, resource_id) -> dict: ...
    def block_suspicious_ip(self, ip, resource_id) -> dict: ...
    def release_isolation(self, resource_id) -> dict: ...
```

Adding AWS = one class. Agent logic, scenarios, and RAG memory don't change.

## Tests

```bash
pip install eregion[dev]
pytest  # 84 tests, 0 Azure calls, 0 Claude API calls
```

## License

Apache 2.0 — see [LICENSE](LICENSE).

---

*Annatar corrupts from within. Glorfindel always returns.*
