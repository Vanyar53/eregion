# Contributing to Eregion

Eregion is open-core (Apache 2.0). Contributions are welcome — scenarios, cloud providers, detection sources, and bug fixes.

## Development setup

```bash
git clone https://github.com/Vanyar53/eregion
cd eregion
pip install -e ".[dev]"
pytest                  # 88 tests, 0 Azure calls, 0 Claude API calls
```

## How to add a detection source

Implement `DetectionConnector` in `glorfindel/detectors.py` and register it in `detector_for()`:

```python
class PrometheusDetector(DetectionConnector):
    def poll_alert(self, query: str, since: float, timeout_s: float) -> tuple[float, dict] | None:
        # Poll your source every 10s until detection or timeout
        # Return (detection_s, result_row) or None on timeout
        ...

def detector_for(source: str, **kwargs) -> DetectionConnector:
    if source == "prometheus":
        return PrometheusDetector(...)
```

`poll_alert()` is called every 10s by the `poll_detection` node. The `result_row` dict is what the LLM sees — include `SourceIP` or `CallerIpAddress` for IP-based routing to work correctly.

## How to add a cloud provider

Implement `CloudConnector` in `glorfindel/actions.py`:

```python
class AwsConnector(CloudConnector):
    def isolate_vm(self, resource_id: str) -> dict: ...
    def release_isolation(self, resource_id: str) -> dict: ...
    def block_suspicious_ip(self, ip: str, resource_id: str) -> dict: ...
    def unblock_ip(self, ip: str, resource_id: str) -> dict: ...
    def snapshot(self, resource_id: str) -> str: ...
    def verify_isolation(self, resource_id: str) -> dict: ...
    def verify_snapshot(self, snap_id: str) -> dict: ...
    def verify_block_ip(self, ip: str, resource_id: str) -> dict: ...
    def restore_from_backup(self, resource_id: str, vault: str, before_attack_time: str | None) -> dict: ...
```

The agent, scenarios, and RAG memory don't change — only the connector.

## How to add a scenario

Create a YAML file in `scenarios/<provider>/`. The JSON Schema at `schemas/scenario.schema.json` validates it (IDE autocomplete if you use VS Code with the provided settings).

```yaml
name: my-scenario
description: What this scenario tests
mitre: T1234
version: "1.0.0"

target:
  type: azure_vm
  resource_group: my-rg
  vm_name: my-vm

prerequisites:
  detection:
    - name: my_table
      table: MyTable
      why: why this table must exist
      verify: "MyTable | limit 1"
      setup: "how to enable it"

steps:
  - name: simulate_attack
    action: run_script_on_vm
    script: scripts/vm/my_attack_sim.sh
    record: T0        # marks this step's start time as T0 for detection_s measurement

detection:
  source: azure_monitor
  workspace_id: "<your_workspace_id>"
  query: |
    MyTable
    | where TimeGenerated > ago(5m)
    | limit 1
  timeout: "300s"

recovery: null
cleanup: []
```

**Safety**: Annatar will only run against resources tagged `annatar-test: "true"`. The safety guard in `annatar/safety/guard.py` blocks execution otherwise.

## How to add an autonomous action

1. Implement `connector.my_action(resource_id)` and `connector.verify_my_action(resource_id)` in `AzureConnector`
2. Add `"my_action"` to `AUTONOMOUS_ACTIONS` in `glorfindel/actions.py`
3. Wire it in `execute_action` and `verify_action` in `glorfindel/agent.py`
4. Add a test in `tests/unit/test_agent_nodes.py`

Actions not in `AUTONOMOUS_ACTIONS` are automatically escalated to the human — so Glorfindel can propose your new action before it's implemented.

## Tests

```bash
pytest                          # all tests
pytest tests/unit/test_agent_nodes.py -v    # LangGraph nodes only
pytest -k "isolate"             # filter by name
```

No Azure credentials or Anthropic API key needed. All cloud calls and LLM calls are mocked.

## Commit convention

Every commit that changes behavior: update `README.md` and `CLAUDE.md`.

```
feat: short description
fix: short description
test: short description
docs: short description
refactor: short description
```
