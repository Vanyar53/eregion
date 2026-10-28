# Contributing to Eregion

Eregion is open-core (Apache 2.0). Contributions are welcome — adapters first, then scenarios and bug fixes.

## Where to start: the adapters

Eregion has three agents:
- **Glorfindel**, the defender: the product, always present;
- **Annatar**, the attacker;
- **Gothmog**, the fault injector.

They meet only through the shared core (`eregion_core/`). The usage profiles are combinations of the three, with Glorfindel in each ([`docs/profils/`](docs/profils/README.md)).

What reaches the outside world sits behind an **adapter**: a cloud, a telemetry source, or a public attack or fault library. An adapter is the best first contribution. It is small, it has one interface, and you can develop and test it without the rest:

| You bring | The adapter | Its interface | Its example |
|---|---|---|---|
| a cloud provider (AWS, GCP…) | `glorfindel/providers/<name>/` | `CloudConnector` + its `CAPABILITIES` | `glorfindel/providers/azure/`, `glorfindel/providers/aws/` |
| a detection source (Prometheus, Sentinel…) | `glorfindel/providers/<name>/` | `DetectionConnector` | `glorfindel/providers/azure/monitor.py` |
| a public attack library | `annatar/engines/<name>.py` | `engine` + `engine_ref` of the experiment schema; prepare, inject, revert, clean | `annatar/engines/atomic.py` (Atomic Red Team) |
| a fault engine | `gothmog/engines/<name>.py` | the same, `kind: fault` | `gothmog/engines/chaos_studio.py` |

**Two rules hold every adapter in place:**
- **A provider's SDK** (azure, boto3, google-cloud) is imported only in its adapter. `tests/unit/test_provider_boundary.py` enforces it, and CI runs it as its own step.
- **No component imports another.** Glorfindel reaches Annatar or Gothmog, and they reach Glorfindel, only through the listed bridges, each with its reason (`scripts/component_check.py`, `BRIDGES` and `CROSSINGS`). What they share lives in `eregion_core/`, such as the signal contract, `eregion_core/signals.py`. `tests/unit/test_components.py` refuses any other crossing.

**What an injector adapter does not do.** It never checks its own target, its host or the watch. The runner does that before it calls the adapter:
- the inscription (`eregion_core/inscription.py`);
- Orodruin's contract (`eregion_core/orodruin.py`);
- the live Glorfindel watch (`eregion_core/watch_gate.py`);
- the exercise window (`eregion_core/exercise.py`).

An injector adapter wraps a public library at a pinned version. Eregion has no offensive logic of its own.

**Develop it alone.** Each component is tested with the others absent from the interpreter. An injector also runs without Glorfindel's dependencies (LangGraph, ChromaDB, the bot, the console). CI does the same ([`components.yml`](.github/workflows/components.yml)):

```bash
python scripts/component_check.py annatar --imports   # every module imports with the others absent
python scripts/component_check.py annatar             # its tests, the others absent
make components-check                                 # all four: core, glorfindel, annatar, gothmog
```

A new test file goes into its component's list in `scripts/component_check.py`, or into `TOGETHER` if it crosses components on purpose. `test_components.py` fails until it has a home.

## Development setup

```bash
git clone https://github.com/Vanyar53/eregion
cd eregion
pip install --require-hashes -r requirements/dev.txt   # the lock: what CI and the image run
pip install --no-deps --no-build-isolation -e .
pytest                  # 0 Azure calls, 0 Claude API calls
```

(`make install` does the same in `.venv/`.) A new dependency goes into `pyproject.toml`, then
`make lock` (needs [uv](https://docs.astral.sh/uv/)) updates `requirements/*.txt` in the same PR —
`tests/unit/test_dependency_lock.py` fails until it does. See `docs/operations.md`, « Verrou des
dépendances ».

## Local safety hooks (recommended)

This is a **public** repo. To stop real infrastructure identifiers (vault / resource-group / host names, subscription IDs, NDA codenames) from ever being committed, enable the local commit hooks:

```bash
git config core.hooksPath .githooks
```

Then list the terms to block in `.git/infra-denylist.txt` — one per line. This file lives under `.git/` and is **never committed**:

```
# .git/infra-denylist.txt
my-real-vault-name
my-real-resource-group
00000000-0000-0000-0000-000000000000
```

`pre-commit` (staged content) and `commit-msg` (commit message) then refuse any commit that introduces a listed term — case-insensitive. Deliberate override: `git commit --no-verify`. Both `core.hooksPath` and the denylist are local, so re-run this after a fresh clone.

## How to add a detection source

Implement `DetectionConnector` (`glorfindel/providers/interface.py`) in its provider's adapter, `glorfindel/providers/<name>/` — the only place its SDK may be imported (Azure Monitor: `glorfindel/providers/azure/monitor.py`) — and register it in `detector_for()` (`glorfindel/detectors.py`):

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

Add an adapter under `glorfindel/providers/<name>/` — the only place its SDK may be imported (`tests/unit/test_provider_boundary.py`, run in CI) — that implements `CloudConnector` (`glorfindel/providers/interface.py`) and declares its capabilities (`CAPABILITIES`, see `glorfindel/providers/azure/capabilities.py`): the readiness check reads the rights each one needs from there.

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
    def restore_job_status(self, vault: str, vault_rg: str, job_name: str) -> str: ...
```

The agent, scenarios, and RAG memory don't change — only the connector.

## How to add a scenario

Create a YAML file in `annatar/scenarios/<provider>/`. The JSON Schema at `schemas/scenario.schema.json` validates it (IDE autocomplete if you use VS Code with the provided settings).

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

**Safety**: an injector only acts on an **enrolled** target: the resource and its resource group tagged `eregion-target=<bench id>` with an `eregion-zone` (`bench`, `twin` or `production`), inside the bench's resource groups — and in `production`, only a technique declared non-destructive, never a fault. The shared guard in `eregion_core/inscription.py` blocks execution otherwise (the old `annatar-test: "true"` tag still enrolls a target on the bench during the migration).

## How to add an autonomous action

1. Implement `connector.my_action(resource_id)` and `connector.verify_my_action(resource_id)` in `AzureConnector` (a mixin of `glorfindel/providers/azure/`)
2. Add `"my_action"` to `AUTONOMOUS_ACTIONS` in `glorfindel/response/policy.py` (imported everywhere from `glorfindel.actions`)
3. Wire it in `execute_action` and `verify_action` in `glorfindel/agent.py`
4. Add a test in `tests/unit/test_agent_nodes.py`

Actions not in `AUTONOMOUS_ACTIONS` are automatically escalated to the human — so Glorfindel can propose your new action before it's implemented.

## Tests

Patching the response code (`glorfindel/actions.py` is a façade over `glorfindel/response/` and `glorfindel/providers/azure/`): on `glorfindel.actions`, use `monkeypatch.setattr` — it reaches every module that reads the name — never `mock.patch`, which deletes the name on exit (the façade refuses, and the patched value would stay everywhere). Or `mock.patch` the module of origin (`glorfindel.response.state._ISOLATION_STATE_DIR`…), which patches that module only.

```bash
pytest                          # all tests
pytest tests/unit/test_agent_nodes.py -v    # LangGraph nodes only
pytest -k "isolate"             # filter by name
```

No Azure credentials or Anthropic API key needed. All cloud calls and LLM calls are mocked.

## Commit convention

Every commit that changes behavior: update the doc concerned (`README.md`, `docs/`, `CHANGELOG.md`). Change `CLAUDE.md` only when a rule or a convention changes — every session loads it, so it stays under 25 KB (`tests/unit/test_docs_budget.py` fails above); the details live in `docs/` (see its "Où trouver quoi" index).

```
feat: short description
fix: short description
test: short description
docs: short description
refactor: short description
```

An optional scope names the area: `feat(inscription): …`, `fix(detection): …`.

## Working with Claude Code

This repository is developed with Claude Code. There are two ways to work on it:

- **Specialised sessions**, one per component. Each has a role file (`CLAUDE_<ROLE>.md`), and they coordinate through the local `collab/` folder. See the "Sessions Claude spécialisées" section of `CLAUDE.md`.
- **elrond**, an orchestration skill shipped in `.claude/` (`/elrond init`, `/elrond run`). The main session dispatches one subagent per roadmap lot, each in its own worktree. Any work done while a fallback model answered is reviewed by Opus 5.5 before it counts as done. See [docs/elrond.md](docs/elrond.md) (in French).

Either way, the same rules hold:
- no real infrastructure identifier (enable the local hooks above);
- tests never call Azure or an LLM;
- one lot or one fix per pull request.

## Security

A vulnerability is reported privately, its details never in an issue or a pull request: [`SECURITY.md`](SECURITY.md). The boundaries and what holds them: [`docs/design/modele-de-menace.md`](docs/design/modele-de-menace.md) — a lot that moves a boundary updates its page, and writes what it leaves open as « planifié : #n », never how to use it.

Three rules the tests hold:
- **A workflow that holds a secret** (or runs on `pull_request_target` / `workflow_run`) **pins every action by commit** (`uses: owner/action@<40 hex>   # vX.Y.Z`); no `run:` takes `${{ inputs.* }}`, `${{ github.event.* }}` or `${{ github.head_ref }}` in its text — pass them through `env:` (`tests/unit/test_workflows.py`).
- **Text from outside reaching a chat** (the model's words, names from Azure, a rule's name) goes through `glorfindel/chat_text.py` (`tests/unit/test_chat_escaping.py`); the console has its own rule (`scripts/console_escaping.py`).
- **Install from the repository** (`make install`, or `pip install -e '.[console]'`), never from a package index by name (`tests/unit/test_readme.py`).
- **The release pull request** bumps `pyproject.toml`, the `CHANGELOG.md` and the README's « **Status — vX.Y.Z.** » together (`tests/unit/test_readme.py`); `docs/operations.md`, « Packaging et version ».

## Pull requests

The title follows the commit convention, and the body follows `.github/pull_request_template.md`. That template asks for:
- the lot and its "done when" criteria;
- the tests and mutants;
- the docs that were updated;
- for work done with Claude Code, which model did it, and whether fallback work was reviewed.

To avoid two people taking the same lot, announce it first, with a draft pull request or an assigned issue.
