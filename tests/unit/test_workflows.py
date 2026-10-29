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
# What an outsider or a dispatcher chooses, as GitHub's expressions name it: by property (read
# with the strings blanked) or by index (`github['head_ref']`, `inputs['x']`), anywhere in the
# expression — `format('{0}', inputs.x)` included.
CHOSEN_NAME = re.compile(r"\binputs\s*\.|\bgithub\s*\.\s*(?:event|head_ref)\b")
CHOSEN_INDEX = re.compile(r"\binputs\s*\[|\bgithub\s*\[\s*'(?:event|head_ref)'")
HASHICORP_APT_FPR = "D55C0D1AC78A8D8126CB631CFC9CA96ACA026560"   # hashicorp.com/en/trust/security, 28/10
# Secret-less workflows (contents: read) still naming a tag: to pin by commit, a lookup of each
# action's commit on GitHub — planned. Never add to this list; remove what gets pinned.
TAGGED_WITHOUT_SECRETS = {
    ("ci.yml", "actions/setup-python@v6"), ("ci.yml", "actions/cache@v5"),
    ("ci.yml", "actions/cache/restore@v5"),
    ("components.yml", "actions/setup-python@v6"), ("components.yml", "actions/cache@v5"),
    ("invariants.yml", "actions/setup-python@v6"), ("invariants.yml", "actions/cache/restore@v5"),
    ("invariants.yml", "actions/cache/save@v5"),
    ("mutants.yml", "actions/setup-python@v6"),
}


def _expressions(text: str) -> list[tuple[str, str]]:
    """Each `${{ … }}` of a text, whole, as GitHub reads it — it ends at the first `}}` outside a
    single-quoted string ('' is a quote inside one): (as written, its strings blanked)."""
    out, i = [], 0
    while (start := text.find("${{", i)) != -1:
        j, blank, quoted = start + 3, [], False
        while j < len(text):
            c = text[j]
            if quoted:
                if c == "'" and text[j + 1:j + 2] == "'":
                    blank.append("  ")
                    j += 2
                    continue
                quoted = c != "'"
                blank.append(" " if quoted else "'")
            elif c == "'":
                quoted = True
                blank.append("'")
            elif text.startswith("}}", j):
                break
            else:
                blank.append(c)
            j += 1
        out.append((text[start + 3:j], "".join(blank)))
        i = j + 2
    return out


def _chosen(text: str) -> bool:
    return any(CHOSEN_NAME.search(blank) or CHOSEN_INDEX.search(raw) for raw, blank in _expressions(text))


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


def test_the_list_of_tags_left_holds_only_what_is_still_there():
    """An entry whose action was pinned meanwhile must go: left, it would let the tag back in."""
    tagged = {(p.name, a) for p in WORKFLOWS for a in _actions(_load(p)) if not PINNED.match(a)}
    assert TAGGED_WITHOUT_SECRETS - tagged == set()


def test_the_canary_trusts_hashicorps_key_by_its_fingerprint_only():
    """Its apt key is checked against the fingerprint HashiCorp publishes before apt trusts it,
    and only that key is exported to apt's keyring (never the older 798A… one)."""
    text = (ROOT / ".github" / "workflows" / "canary-azurerm.yml").read_text(encoding="utf-8")
    (install,) = [s for s in _steps(_load(ROOT / ".github" / "workflows" / "canary-azurerm.yml"))
                  if "apt.releases.hashicorp.com/gpg" in str(s.get("run") or "")]
    assert install["env"]["HASHICORP_APT_FPR"] == HASHICORP_APT_FPR
    run = install["run"]
    # one primary key, whose own fingerprint it is — never a subkey's fpr line, never a second key
    assert ("""'$1=="pub"{n++;p=1;next} $1=="fpr"&&p{k=$10;p=0} END{exit !(n==1&&k==f)}'""" in run
            and '-v f="$HASHICORP_APT_FPR"' in run and "exit 1" in run)
    assert "grep -qx \"fpr:" not in run
    assert run.index("exit 1") < run.index("/usr/share/keyrings/hashicorp-archive-keyring.gpg")
    assert '--export "$HASHICORP_APT_FPR"' in run
    assert "798AEC65" not in text.replace(" ", "")


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def test_no_run_takes_a_chosen_value_in_its_text(path):
    bad = [s["run"] for s in _steps(_load(path)) if _chosen(str(s.get("run") or ""))]
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
    ("python x.py --n ${{ format('{0}', inputs.examples) }}", True),     # past a } in a string
    ("python x.py --n ${{ format('{0}}}', github.event.issue.title) }}", True),
    ("echo ${{ github['head_ref'] }}", True),
    ("echo ${{ inputs['examples'] }}", True),
    ("echo ${{ github.event_name }}", False),
    ("echo ${{ 'inputs.x' }}", False),                                  # a string, not a value
    ("echo ${{ matrix.a }} ${{ inputs.b }}", True),                       # every expression read
])
def test_what_counts_as_a_chosen_value(run, chosen):
    assert _chosen(run) is chosen


@pytest.mark.parametrize("workflow,job", [("ci.yml", "test"), ("ci.yml", "test-macos"),
                                          ("invariants.yml", "invariants")])
def test_the_jobs_that_run_the_invariants_are_bounded(workflow, job):
    """A job without a bound runs six hours: a race of the invariant machine that hung its
    teardown did so on macOS (I3F); each job that runs them is bounded (U3F)."""
    bound = _load(ROOT / ".github" / "workflows" / workflow)["jobs"][job].get("timeout-minutes")
    assert isinstance(bound, int) and 0 < bound <= 180, bound
