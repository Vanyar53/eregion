"""SEC6 (#277): the workflows of .github/workflows/, read as GitHub runs them.

Two rules (docs/design/modele-de-menace.md, « La CI et le CD »):
- A workflow that holds a secret, or runs on an event a fork can trigger with the default
  branch's rights (pull_request_target, workflow_run), pins every action by commit: a tag
  can be moved, a commit cannot. The others may still name a tag, only those listed below —
  the list can shrink, never grow.
- No `run:` takes an expression an outsider or a dispatcher chooses (`inputs.*`,
  `github.event.*`, `github.head_ref`): such a value goes through `env:` and is read as a
  variable, never pasted into the script's text.
"""
import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = sorted((ROOT / ".github" / "workflows").glob("*.yml"))
FORK_EVENTS = {"pull_request_target", "workflow_run"}
PINNED = re.compile(r"^[\w.-]+/[\w./-]+@[0-9a-f]{40}$")
CHOSEN = re.compile(r"\$\{\{[^}]*\b(inputs\.|github\.event\.|github\.head_ref)")
# Secret-less workflows (contents: read) still naming a tag: to pin by commit, a lookup of each
# action's commit on GitHub — planned. Never add to this list.
TAGGED_WITHOUT_SECRETS = {
    ("ci.yml", "actions/setup-python@v6"), ("ci.yml", "actions/cache@v5"),
    ("ci.yml", "actions/cache/restore@v5"),
    ("components.yml", "actions/setup-python@v6"), ("components.yml", "actions/cache@v5"),
    ("invariants.yml", "actions/setup-python@v6"), ("invariants.yml", "actions/cache/restore@v5"),
    ("invariants.yml", "actions/cache/save@v5"),
    ("mutants.yml", "actions/setup-python@v6"),
}


def _load(path: Path) -> dict:
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    doc["on"] = doc.get("on", doc.pop(True, None))   # YAML 1.1 reads a bare `on` as true
    return doc


def _steps(doc: dict):
    for job in (doc.get("jobs") or {}).values():
        if job.get("uses"):                          # a reusable workflow
            yield {"uses": job["uses"]}
        yield from job.get("steps") or []


def _events(doc: dict) -> set[str]:
    on = doc["on"]
    return {on} if isinstance(on, str) else set(on or ())


def _holds_secrets(path: Path, doc: dict) -> bool:
    return "secrets." in path.read_text(encoding="utf-8") or bool(_events(doc) & FORK_EVENTS)


def _actions(doc: dict) -> list[str]:
    return [s["uses"] for s in _steps(doc) if s.get("uses") and not s["uses"].startswith("./")]


def test_every_workflow_is_read():
    assert {p.name for p in WORKFLOWS} >= {"ci.yml", "canary-azurerm.yml", "mutants.yml", "notify.yml"}


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def test_a_workflow_that_holds_a_secret_pins_its_actions_by_commit(path):
    doc = _load(path)
    if not _holds_secrets(path, doc):
        pytest.skip("no secret, no event a fork can trigger")
    assert [a for a in _actions(doc) if not PINNED.match(a)] == []


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def test_no_new_action_named_by_its_tag(path):
    tagged = {(path.name, a) for a in _actions(_load(path)) if not PINNED.match(a)}
    assert tagged - TAGGED_WITHOUT_SECRETS == set()


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def test_no_run_takes_a_chosen_value_in_its_text(path):
    bad = [s["run"] for s in _steps(_load(path)) if CHOSEN.search(str(s.get("run") or ""))]
    assert bad == []


@pytest.mark.parametrize("text, pinned", [
    ("actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09", True),
    ("actions/checkout@v5", False),
    ("actions/checkout@v5.1.0", False),
    ("actions/cache/restore@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09", True),
    ("actions/checkout@fbc6f399", False),           # an abbreviated commit is a ref like a tag
])
def test_what_counts_as_pinned(text, pinned):
    assert bool(PINNED.match(text)) is pinned


@pytest.mark.parametrize("run, chosen", [
    ("python x.py --n ${{ inputs.examples || '1000' }}", True),
    ("echo ${{ github.event.pull_request.title }}", True),
    ("git switch ${{ github.head_ref }}", True),
    ('python x.py --n "$EXAMPLES"', False),
    ("python scripts/component_check.py ${{ matrix.component }}", False),
])
def test_what_counts_as_a_chosen_value(run, chosen):
    assert bool(CHOSEN.search(run)) is chosen
