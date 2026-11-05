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


_MACHINES = ("tests/unit/test_invariants.py", "tests/unit/test_invariants_aws.py")


def test_the_night_runs_both_machines_and_keeps_their_failures():
    """Each machine, Azure's and AWS's, runs every night at the night's budget with the
    cached database, and the database is saved: a failure is kept to be replayed. The AWS
    machine ran at the push budget only, its failures kept nowhere (AWS1, #334).

    The save comes after every machine's step, whatever their outcome (`always()`); each
    machine's step has its own bound, their sum under the job's: one that runs over fails
    its step, never cancels the job — the next machine still runs (`!cancelled()`) and the
    database is still saved (AWS1, review)."""
    job = _load(ROOT / ".github" / "workflows" / "invariants.yml")["jobs"]["invariants"]
    steps = job["steps"]
    saves = [i for i, s in enumerate(steps) if "actions/cache/save" in (s.get("uses") or "")
             and (s.get("with") or {}).get("path") == ".hypothesis-invariants"]
    assert len(saves) == 1, saves
    save = steps[saves[0]]
    assert "always()" in str(save.get("if") or ""), save
    bounds = []
    for n, machine in enumerate(_MACHINES):
        at = [i for i, s in enumerate(steps) if machine in (s.get("run") or "").split()]
        assert len(at) == 1, f"{machine} run {len(at)} times at night"
        step = steps[at[0]]
        env = step.get("env") or {}
        assert env.get("GLORFINDEL_INVARIANT_DB") == ".hypothesis-invariants", (machine, env)
        assert "10000" in str(env.get("GLORFINDEL_INVARIANT_EXAMPLES")), (machine, env)
        assert at[0] < saves[0], f"{machine} runs after the database is saved: its failures are lost"
        cond = str(step.get("if") or "")
        if n:
            assert "!cancelled()" in cond or "always()" in cond, (
                f"{machine} skipped when the machine before it failed: {cond}")
        bound = step.get("timeout-minutes")
        assert isinstance(bound, int) and bound > 0, (machine, bound)
        bounds.append(bound)
    assert sum(bounds) < job["timeout-minutes"], (bounds, job["timeout-minutes"])


def test_a_push_replays_the_failures_the_night_kept_on_both_machines():
    """ci.yml's Linux job restores the database and runs every test with it — both
    machines among them, at the push budget."""
    steps = _load(ROOT / ".github" / "workflows" / "ci.yml")["jobs"]["test"]["steps"]
    assert any("actions/cache/restore" in (s.get("uses") or "") and
               (s.get("with") or {}).get("path") == ".hypothesis-invariants" for s in steps)
    runs = [s for s in steps if "pytest tests/ " in (s.get("run") or "")]
    assert runs and all((ROOT / m).is_file() for m in _MACHINES), runs     # under tests/, run by it
    env = runs[0].get("env") or {}
    assert env.get("GLORFINDEL_INVARIANT_DB") == ".hypothesis-invariants", env
    # CI5 (#512): 500 on a push to main, 200 on a pull request.
    assert _expr(env.get("GLORFINDEL_INVARIANT_EXAMPLES"), "push") == "500", env
    assert _expr(env.get("GLORFINDEL_INVARIANT_EXAMPLES"), "pull_request") == "200", env


@pytest.mark.parametrize("job", ["test", "test-macos"])
def test_a_hang_of_the_ci_tests_says_where_it_waits(job):
    """The CI's test steps write every thread's stack when a test outlasts 8 min: a hang is
    seen where it waits, before the job's bound cancels it (U3F review)."""
    steps = _load(ROOT / ".github" / "workflows" / "ci.yml")["jobs"][job]["steps"]
    runs = [s["run"] for s in steps if "pytest tests/" in (s.get("run") or "") and "boundary" not in s["run"]]
    assert runs and all("-o faulthandler_timeout=480" in r for r in runs), runs


# Workflows whose red run is not announced in #ci, with their reason. Notify itself; Roadmap is a
# Discord job that stays green by design (N2: a Discord or GitHub error is one line in its log).
NOT_ANNOUNCED = {"notify.yml": "the announcer itself", "roadmap.yml": "green by design, Discord's own job (N2)"}


def test_every_workflow_a_push_a_pull_request_or_the_night_runs_is_announced_when_red():
    """notify.yml's workflow_run lists by name every workflow a push, a pull request or a schedule
    runs: one left out turns red unseen in #ci (CI1: Images)."""
    listed = set(_load(ROOT / ".github" / "workflows" / "notify.yml")["on"]["workflow_run"]["workflows"])
    docs = {p.name: _load(p) for p in WORKFLOWS}
    due = {doc["name"] for name, doc in docs.items()
           if _events(doc) & {"push", "pull_request", "schedule"} and name not in NOT_ANNOUNCED}
    assert due - listed == set()
    assert listed - {doc["name"] for doc in docs.values()} == set(), "a name listed that no workflow has"
    assert set(NOT_ANNOUNCED) <= set(docs)


# ── CI2, after its review (SEC7) : `issues: write`, the dependency audit's alone ──────────
# The audit's issues are read back only when their author is github-actions[bot] (CI2): any
# other workflow that may write issues writes them under that same author, and could forge a
# key that silences an advisory. So `issues: write` (or write-all) is pip-audit.yml's alone,
# at the workflow's level or a job's — and every workflow says its permissions (no default).

def _permission_sets(doc: dict) -> list:
    sets = [doc.get("permissions")]
    sets += [job.get("permissions") for job in (doc.get("jobs") or {}).values() if isinstance(job, dict)]
    return [p for p in sets if p is not None]


def _writes_issues(perms) -> bool:
    if isinstance(perms, str):
        return perms.strip() == "write-all"
    return isinstance(perms, dict) and str(perms.get("issues", "")).strip() == "write"


def test_only_the_dependency_audit_may_write_issues():
    """And, beside it, ci.yml's `macos-red` job alone (CI5): never on a pull request, nothing of the
    repository run (no checkout, no action), its text fixed — it cannot write the audit's key."""
    docs = {p.name: _load(p) for p in WORKFLOWS}
    assert all("permissions" in doc for doc in docs.values()), "a workflow without its permissions"
    writers = {name for name, doc in docs.items() if any(_writes_issues(p) for p in _permission_sets(doc))}
    assert writers == {"pip-audit.yml", "ci.yml"}
    ci = docs["ci.yml"]
    assert not _writes_issues(ci["permissions"])
    jobs = {name for name, job in ci["jobs"].items() if _writes_issues(job.get("permissions"))}
    assert jobs == {"macos-red"}
    job = ci["jobs"]["macos-red"]
    assert job["permissions"] == {"issues": "write"}
    assert [s for s in job["steps"] if s.get("uses")] == []
    text = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert "eregion-pip-audit" not in text and "--label" not in "".join(s.get("run", "") for s in job["steps"])
    for event in ("pull_request", "pull_request_target", "workflow_run", "workflow_dispatch"):
        assert _expr(job["if"], event, needs={"test-macos": "failure"}) is False, event


@pytest.mark.parametrize("perms, writes", [
    ({"contents": "read", "issues": "write"}, True), ("write-all", True), ({"issues": "read"}, False),
    ("read-all", False), ({}, False),
])
def test_what_counts_as_writing_issues(perms, writes):
    assert _writes_issues(perms) is writes


# ── CI3 (#267): publishing, minting an OIDC token, attesting — publish.yml's alone ────────────
# A token that writes packages, an OIDC token sigstore certifies, the attestation store: what
# makes an image H0 deploys (its CD trusts the signature of publish.yml on main). Only that
# workflow holds them, at a job's level, and only on a push to this repository's main.
PUBLISHING = ("packages", "id-token", "attestations")
PUBLISH = ROOT / ".github" / "workflows" / "publish.yml"
CANARY = ROOT / ".github" / "workflows" / "canary-azurerm.yml"


def _publishes(perms, rights=PUBLISHING) -> bool:
    if isinstance(perms, str):
        return perms.strip() == "write-all"
    return isinstance(perms, dict) and any(str(perms.get(p, "")).strip() == "write" for p in rights)


def test_only_the_publishing_workflow_may_write_packages_or_attest_and_the_canary_alone_mints_beside_it():
    """`id-token: write` has a second holder since P-04: the canary's job, whose token Entra ID
    exchanges for its principal (never for a signature H0 trusts: the CD checks the workflow)."""
    docs = {p.name: _load(p) for p in WORKFLOWS}
    writers = {name for name, doc in docs.items()
               if any(_publishes(p, ("packages", "attestations")) for p in _permission_sets(doc))}
    assert writers == {"publish.yml"}
    minters = {name for name, doc in docs.items() if any(_publishes(p, ("id-token",)) for p in _permission_sets(doc))}
    assert minters == {"publish.yml", CANARY.name}
    doc = docs["publish.yml"]
    assert doc["permissions"] == {"contents": "read"}               # the workflow's level: nothing more
    (job,) = doc["jobs"].values()
    assert job["permissions"] == {"contents": "read", "packages": "write", "id-token": "write",
                                  "attestations": "write"}


def test_the_publishing_workflow_runs_only_on_a_push_to_this_repositorys_main():
    """Never a pull request (a fork's included), never a workflow_run or a dispatch: the job is
    guarded by its repository, its ref and its event."""
    doc = _load(PUBLISH)
    assert doc["on"] == {"push": {"branches": ["main"]}}
    (job,) = doc["jobs"].values()
    guard = job["if"].replace(" ", "")
    for part in ("github.repository=='grootcyber/eregion'", "github.ref=='refs/heads/main'",
                 "github.event_name=='push'"):
        assert part in guard
    assert "||" not in guard


def test_the_publishing_workflow_proves_its_image_before_it_pushes_and_verifies_it_as_h0_does():
    steps = _load(PUBLISH)["jobs"]["publish"]["steps"]
    names = [s.get("name") or s["uses"].split("@")[0] for s in steps]
    build = next(s for s in steps if str(s.get("uses", "")).startswith("docker/build-push-action"))
    assert build["with"]["push"] is False and build["with"]["load"] is True
    assert build["with"]["provenance"] is False and "cache-to" not in build["with"]   # main's cache: images.yml's
    order = [names.index(n) for n in ("In the image (nothing started, no network, no secret)", "Push",
                                      "actions/attest-build-provenance", "actions/attest-sbom", "Sign (keyless)",
                                      "Verified as H0 verifies it")]
    assert order == sorted(order)
    runs = {s.get("name"): s.get("run", "") for s in steps}
    assert runs["In the image (nothing started, no network, no secret)"].startswith("python3 scripts/image_check.py")
    assert "published_image.py install-cosign" in runs["cosign"]          # the pinned cosign, as on H0
    assert runs["Verified as H0 verifies it"].startswith("python3 scripts/published_image.py verify")
    attest = next(s for s in steps if str(s.get("uses", "")).startswith("actions/attest-build-provenance"))
    assert attest["with"]["push-to-registry"] is True and attest["with"]["subject-digest"] == \
        "${{ steps.push.outputs.digest }}"
    assert "UID=${{ steps.meta.outputs.uid }}" in build["with"]["build-args"]


def test_the_publishing_workflow_is_the_identity_h0_trusts():
    """The path the CD asks cosign for is this file (published_image.WORKFLOW), on main."""
    text = (ROOT / "scripts" / "published_image.py").read_text(encoding="utf-8")
    assert 'WORKFLOW = ".github/workflows/publish.yml"' in text and 'BRANCH_REF = "refs/heads/main"' in text
    assert 'TRIGGER = "push"' in text and PUBLISH.exists()


@pytest.mark.parametrize("perms, publishes", [
    ({"packages": "write"}, True), ({"id-token": "write"}, True), ({"attestations": "write"}, True),
    ("write-all", True), ({"packages": "read"}, False), ({"contents": "write"}, False), ("read-all", False),
])
def test_what_counts_as_publishing(perms, publishes):
    assert _publishes(perms) is publishes


# ── P04: the azurerm canary without a long-lived secret (OIDC), at least privilege ────────────
# The canary held a client secret, and its principal could create a resource group in the
# subscription. Now: a short-lived OIDC token, this job's alone, exchanged for a principal that
# is Contributor on one group, rg-eregion-canary, which the canary never creates nor deletes.
# Read from the files; the steps' scripts and run.sh run against fake `curl`, `az` and
# `terraform` — no Azure, no network.
JIT = ROOT / "infra" / "canary" / "jit-terraform"
CANARY_SECRETS = {"ARM_CLIENT_ID": "CANARY_AZURE_CLIENT_ID", "ARM_TENANT_ID": "CANARY_AZURE_TENANT_ID",
                  "ARM_SUBSCRIPTION_ID": "CANARY_AZURE_SUBSCRIPTION_ID"}


def _canary_job() -> dict:
    (job,) = _load(CANARY)["jobs"].values()
    return job


def _canary_step(job: dict, needle: str) -> dict:
    (step,) = [s for s in job["steps"] if needle in str(s.get("run") or "")]
    return step


def test_the_canary_job_alone_holds_its_oidc_token_and_only_on_a_schedule_or_a_dispatch():
    """`id-token: write` on the canary's job, never on the workflow (another job added there would
    hold it too); the token never reaches a pull request's code: no pull_request*, no workflow_run,
    no push of another branch."""
    doc = _load(CANARY)
    assert doc["permissions"] == {"contents": "read"}
    assert _canary_job()["permissions"] == {"contents": "read", "id-token": "write"}
    assert set(doc["on"]) == {"schedule", "workflow_dispatch"}


def test_the_canary_holds_no_client_secret_and_takes_its_identifiers_from_secrets():
    """Secrets, never repository variables (`vars.*` print in clear in a public log); OIDC on, and
    Terraform kept off the az login (use_cli false): a green canary proves the provider's OIDC."""
    text = CANARY.read_text(encoding="utf-8")
    assert "CLIENT_SECRET" not in text.upper() and "--password" not in text
    assert not re.search(r"\baz\s+login\b[^\n]*\s-p\s", text)
    assert "vars." not in text
    env = _canary_job()["env"]
    for arm, secret in CANARY_SECRETS.items():
        assert env[arm] == "${{ secrets.%s }}" % secret, (arm, env.get(arm))
    assert set(re.findall(r"secrets\.(\w+)", text)) == set(CANARY_SECRETS.values())
    assert str(env["ARM_USE_OIDC"]).lower() == "true" and str(env["ARM_USE_CLI"]).lower() == "false"


def test_the_canary_runs_no_third_partys_action_beside_its_token():
    """GitHub's own checkout, pinned; Terraform from HashiCorp's signed apt repository; the login
    by the runner's az — never azure/login, hashicorp/setup-terraform or any other owner's."""
    used = _actions(_load(CANARY))
    assert used and all(a.startswith("actions/checkout@") and PINNED.match(a) for a in used), used


def _sh(script: str, env: dict, tmp_path: Path, path_dir: Path | None = None):
    import os
    import subprocess
    base = {"PATH": (f"{path_dir}:" if path_dir else "") + os.environ.get("PATH", ""),
            "HOME": str(tmp_path), "TMPDIR": str(tmp_path)}
    return subprocess.run(["bash", "-e", "-c", script], env={**base, **env}, capture_output=True,
                          text=True, timeout=60, cwd=tmp_path)


@pytest.mark.parametrize("missing", [None, "ARM_CLIENT_ID", "ARM_TENANT_ID", "ARM_SUBSCRIPTION_ID", "ref"])
def test_the_canary_fails_without_its_identifiers_or_off_main(tmp_path, missing):
    """T16: a canary green while testing nothing is worse than none. The check fails, and every
    later step waits on its output."""
    job = _canary_job()
    check = _canary_step(job, "GITHUB_OUTPUT")
    out = tmp_path / "out"
    env = {k: "x" for k in CANARY_SECRETS} | {"GITHUB_OUTPUT": str(out), "GITHUB_REF": "refs/heads/main"}
    if missing == "ref":
        env["GITHUB_REF"] = "refs/heads/feature"
    elif missing:
        env[missing] = ""
    res = _sh(check["run"], env, tmp_path)
    if missing:
        assert res.returncode == 1 and "::error::" in res.stdout and not out.exists(), res
    else:
        assert res.returncode == 0 and out.read_text() == "ok=true\n", res
    later = job["steps"][job["steps"].index(check) + 1:]
    assert later and all(s.get("if") == "steps.creds.outputs.ok == 'true'" for s in later)
    assert check.get("id") == "creds"


def _fake(path: Path, body: str) -> None:
    path.write_text("#!/usr/bin/env bash\n" + body)
    path.chmod(0o755)


@pytest.mark.parametrize("endpoint", [True, False])
def test_the_canary_logs_az_in_with_githubs_token_never_a_secret(tmp_path, endpoint):
    bin_ = tmp_path / "bin"
    bin_.mkdir()
    log = tmp_path / "log"
    _fake(bin_ / "curl", f'echo "curl $*" >> {log}; echo \'{{"value": "jwt-from-github"}}\'\n')
    _fake(bin_ / "az", f'echo "az $*" >> {log}; echo "AZ-CALLED $1"\n')
    step = _canary_step(_canary_job(), "az login")
    env = {"ARM_CLIENT_ID": "app", "ARM_TENANT_ID": "tenant", "ARM_SUBSCRIPTION_ID": "sub",
           "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "bearer-x"}
    if endpoint:
        env["ACTIONS_ID_TOKEN_REQUEST_URL"] = "https://token.example/x?api-version=2.0"
    res = _sh(step["run"], env, tmp_path, bin_)
    if not endpoint:
        assert res.returncode == 1 and "id-token: write" in res.stdout and not log.exists(), res
        return
    assert res.returncode == 0, res
    calls = log.read_text().splitlines()
    assert calls[0].startswith("curl ") and "&audience=api://AzureADTokenExchange" in calls[0]
    assert "Authorization: bearer bearer-x" in calls[0]
    (login,) = [c for c in calls if c.startswith("az login")]
    assert "--service-principal -u app --tenant tenant --federated-token jwt-from-github" in login
    # The JWT is said once, to mask it, before az is called — never traced, never on stderr.
    assert res.stdout.count("jwt-from-github") == 1 and "jwt-from-github" not in res.stderr, res
    assert res.stdout.index("::add-mask::jwt-from-github") < res.stdout.index("AZ-CALLED login"), res.stdout


def test_each_run_of_the_matrix_has_its_own_suffix():
    """The three lines run side by side in one group: the suffix names the run, its attempt (a
    re-run after a killed one) and the line."""
    step = _canary_step(_canary_job(), "jit-terraform/run.sh")
    assert step["run"].strip() == "exec infra/canary/jit-terraform/run.sh"     # a cancel's signals reach it
    suffix = step["env"]["CANARY_SUFFIX"]
    for part in ("${{ github.run_id }}", "${{ github.run_attempt }}", "${{ strategy.job-index }}"):
        assert part in suffix, suffix
    assert _canary_job()["env"]["CANARY_RESOURCE_GROUP"] == "rg-eregion-canary"


def _blocks(tf: str) -> dict[tuple[str, str], str]:
    """Each top-level `resource "type" "name" { … }` of a Terraform file, its text."""
    out, cur, body = {}, None, []
    for line in tf.splitlines():
        m = re.match(r'^resource "(\w+)" "(\w+)" \{', line)
        if m:
            cur, body = (m.group(1), m.group(2)), []
            continue
        if cur and line == "}":
            out[cur] = "\n".join(body)
            cur = None
        elif cur:
            body.append(line)
    return out


def test_the_canary_stack_creates_no_group_and_names_each_resource_with_its_suffix():
    tf = (JIT / "main.tf").read_text(encoding="utf-8")
    blocks = _blocks(tf)
    assert len(blocks) >= 6
    assert not [k for k in blocks if k[0] == "azurerm_resource_group"]
    assert 'data "azurerm_resource_group" "t"' in tf
    for (kind, name), body in blocks.items():
        if kind in ("azurerm_subnet", "azurerm_network_interface_security_group_association"):
            continue                                    # a VNet's child; an association has no name
        own = re.search(r'^  name\s+=\s+"([^"]+)"', body, re.M)
        assert own and "${var.suffix}" in own.group(1), (kind, name)
        assert re.search(r"^  tags\s+=.*local\.tags", body, re.M), (kind, name)    # the sweep finds it


_FAKE_TERRAFORM = r'''echo "terraform $* SKIP=${ARM_SKIP_PROVIDER_REGISTRATION:-} RPR=${ARM_RESOURCE_PROVIDER_REGISTRATIONS:-}" >> "$FAKE_LOG"
case " ${FAKE_BLOCK:-} " in       # FAKE_BLOCK="apply destroy": wait there until the test says go
  *" $1 "*) touch "$FAKE_STATE/at-$1"
            for _ in $(seq 200); do [ -e "$FAKE_STATE/go-$1" ] && break; sleep 0.05; done ;;
esac
case "$1" in
  version) echo '{"provider_selections": {"registry.terraform.io/hashicorp/azurerm": "4.81.0"}}' ;;
  destroy) [ -z "${FAKE_DESTROY_OUT:-}" ] || cat "$FAKE_DESTROY_OUT"
           exit "${FAKE_DESTROY_RC:-0}" ;;
  # CAN1: an apply that fails, saying what a file holds (the setup's, or the NIC's update)
  apply) case " $* " in *" nic_tag=v2 "*) out="${FAKE_APPLY2_OUT:-}" ;; *) out="${FAKE_APPLY1_OUT:-}" ;; esac
         if [ -n "$out" ]; then cat "$out"; exit 1; fi ;;
  plan) exit "${FAKE_PLAN_RC:-0}" ;;
esac
exit 0
'''
# A fake az, in Python: what the canary calls, as the real CLI answers it. `az resource list`
# refuses --tag with -g, as azure-cli does (2.85.0, resource/custom.py: IncorrectUsageError);
# a list's --query is evaluated in the two forms the sweep may use, any other is refused.
_FAKE_AZ = r'''import os, re, sys
from pathlib import Path
a = sys.argv[1:]
with open(os.environ["FAKE_LOG"], "a") as f:
    f.write("az " + " ".join(a) + "\n")


def opt(name):
    return a[a.index(name) + 1] if name in a else ""


if a[:2] == ["resource", "list"] and "--tag" in a and ("-g" in a or "--resource-group" in a):
    print("ERROR: you cannot use '--tag' with '--resource-group'", file=sys.stderr)
    sys.exit(2)
state, name = Path(os.environ["FAKE_STATE"]), opt("-n")
if a[:2] == ["group", "show"]:
    if os.environ.get("FAKE_GROUP_ERR"):                # CAN1: the group's read refused, said
        print(Path(os.environ["FAKE_GROUP_ERR"]).read_text(), file=sys.stderr)
    sys.exit(int(os.environ.get("FAKE_GROUP_RC", "0")))
elif a[:3] == ["network", "nsg", "show"]:
    print(f"/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/{name}")
elif a[:3] == ["network", "nic", "update"]:
    if os.environ.get("FAKE_NIC_UPDATE_ERR"):           # CAN1: Azure refuses, its error on stderr
        print(Path(os.environ["FAKE_NIC_UPDATE_ERR"]).read_text(), file=sys.stderr)
        sys.exit(1)
    (state / name).write_text(opt("--network-security-group"))
elif a[:3] == ["network", "nic", "show"]:
    print((state / name).read_text() if (state / name).exists() else "")
elif a[:1] == ["network"] and a[2:3] == ["list"]:
    # The group holds, of each kind, this run's resource, another run's, and one without the tag.
    items = [{"id": f"/{a[1]}/{run or 'untagged'}", "tags": {"canary-run": run} if run else {}}
             for run in ("gh1-1-0", "gh9-9-9", "")]
    q = opt("--query")
    m = re.fullmatch(r"""\[\?tags\."canary-run"=='([^']*)'\]\.id""", q)
    if m:
        print("\n".join(i["id"] for i in items if i["tags"].get("canary-run") == m.group(1)))
    elif q == "[].id":
        print("\n".join(i["id"] for i in items))
    else:
        print(f"fake az: query not understood: {q}", file=sys.stderr)
        sys.exit(3)
'''


def _fake_py(path: Path, body: str) -> None:
    import sys
    path.write_text(f"#!{sys.executable}\n" + body)
    path.chmod(0o755)


def _run_canary(tmp_path: Path, **env):
    bin_, state = tmp_path / "bin", tmp_path / "state"
    bin_.mkdir(exist_ok=True)               # a test may have put a fake of its own there first
    state.mkdir()
    _fake(bin_ / "terraform", _FAKE_TERRAFORM)
    _fake_py(bin_ / "az", _FAKE_AZ)
    log = tmp_path / "log"
    env = {"FAKE_LOG": str(log), "FAKE_STATE": str(state), "ARM_SUBSCRIPTION_ID": "sub",
           "CANARY_SUFFIX": "gh1-1-0"} | env
    res = _sh(f"exec {JIT / 'run.sh'}", env, tmp_path, bin_)
    return res, (log.read_text().splitlines() if log.exists() else [])


def test_the_canary_works_in_its_group_named_by_its_suffix_and_cleans_up(tmp_path):
    res, calls = _run_canary(tmp_path)
    assert res.returncode == 0 and "PASS" in res.stdout, res.stdout + res.stderr
    az = [c for c in calls if c.startswith("az ")]
    assert not [c for c in az if c.startswith(("az group create", "az group delete"))]
    assert az[0].startswith("az group show -n rg-eregion-canary")
    for c in az[1:]:
        assert "-g rg-eregion-canary" in c, c
        assert re.search(r" -n \S+-gh1-1-0 ", c) or " -n " not in c, c
    tf = [c for c in calls if c.startswith(("terraform apply", "terraform plan", "terraform destroy"))]
    assert tf and all("suffix=gh1-1-0" in c and "resource_group=rg-eregion-canary" in c for c in tf)
    # the end: Terraform's stack destroyed, then the quarantine NSG it never knew
    destroy = next(i for i, c in enumerate(calls) if c.startswith("terraform destroy"))
    assert calls[destroy + 1] == \
        "az network nsg delete -g rg-eregion-canary -n nsg-glorfindel-quarantine-canary-gh1-1-0 -o none"
    assert not list(tmp_path.glob("tmp.*")), "the stack's copy left behind"


def test_a_failed_destroy_sweeps_this_runs_resources_by_their_tag_nics_first(tmp_path):
    """Only this run's resources, by their tag compared on the client (az refuses --tag with -g:
    the sweep deleted nothing on the real CLI, its error hidden), NICs first; never another
    run's, never one without the tag, never the group."""
    res, calls = _run_canary(tmp_path, FAKE_DESTROY_RC="1")
    assert res.returncode == 0, res.stdout + res.stderr
    assert "sweeping" in res.stdout and "fake az" not in res.stderr and "cannot use" not in res.stderr, res.stderr
    lists = [c for c in calls if " list " in c]
    assert [c.split()[2] for c in lists] == ["nic", "nsg", "vnet"]
    assert all("-g rg-eregion-canary" in c and "--tag" not in c for c in lists), lists
    deleted = [c for c in calls if " delete --ids " in c]
    assert deleted == [f"az network {k} delete --ids /{k}/gh1-1-0 -o none" for k in ("nic", "nsg", "vnet")]
    assert not [c for c in calls if c.startswith("az group delete")]


def test_the_fake_az_refuses_a_tag_with_a_group_as_the_real_one_does(tmp_path):
    bin_ = tmp_path / "bin"
    bin_.mkdir()
    _fake_py(bin_ / "az", _FAKE_AZ)
    env = {"FAKE_LOG": str(tmp_path / "log"), "FAKE_STATE": str(tmp_path)}
    res = _sh("az resource list -g rg --tag canary-run=x", env, tmp_path, bin_)
    assert res.returncode == 2 and "you cannot use '--tag' with '--resource-group'" in res.stderr
    res = _sh(r"""az network nic list -g rg --query "[?tags.\"canary-run\"=='gh9-9-9'].id" -o tsv""",
              env, tmp_path, bin_)
    assert res.returncode == 0 and res.stdout == "/nic/gh9-9-9\n", res


def test_without_its_group_the_canary_creates_nothing_and_fails(tmp_path):
    res, calls = _run_canary(tmp_path, FAKE_GROUP_RC="3")
    assert res.returncode == 2 and "create it once" in res.stdout, res.stdout
    assert not [c for c in calls if c.startswith(("terraform", "az network", "az group create"))]


@pytest.mark.parametrize("constraint, skip, rpr", [
    ("~> 3.0", "true", ""), ("~> 4.0", "", "none"), ("~> 5.0", "", "none"),
])
def test_the_provider_never_registers_resource_providers(tmp_path, constraint, skip, rpr):
    """The principal may not register one (Contributor on a group): 3.x is told by
    skip_provider_registration, 4.x and 5.x by resource_provider_registrations = none (the
    provider's docs at v3.117.1, v4.81.0, v5.12.0)."""
    res, calls = _run_canary(tmp_path, AZURERM_CONSTRAINT=constraint)
    assert res.returncode == 0, res.stdout + res.stderr
    tf = [c for c in calls if c.startswith(("terraform apply", "terraform plan"))]
    assert tf and all(c.endswith(f"SKIP={skip} RPR={rpr}") for c in tf), tf


@pytest.mark.parametrize("suffix", ["GH1", "a b", "x" * 41, "a;rm"])
def test_a_suffix_that_could_collide_or_inject_is_refused(tmp_path, suffix):
    res, calls = _run_canary(tmp_path, CANARY_SUFFIX=suffix)
    assert res.returncode == 2 and not calls, (res.stdout, calls)


OPS = ROOT / "docs" / "operations.md"


def _canary_section() -> str:
    text = OPS.read_text(encoding="utf-8")
    start = text.index("## Le canari azurerm, sans secret")
    return text[start:text.index("\n## ", start + 1)]


def test_the_old_principal_goes_without_cutting_the_operators_machine():
    """The repository's four AZURE_* secrets go in every case: no workflow reads them any more. A
    credential of the old principal is deleted only once its hint was compared with the machine's
    secrets, and only by its keyId: the one the machine holds never goes (P04 review)."""
    assert not [p.name for p in WORKFLOWS if re.search(r"secrets\.AZURE_", p.read_text(encoding="utf-8"))]
    removal = _canary_section().split("**Puis, après un canari vert seulement**", 1)[1]
    loop = removal.index('gh secret delete "$s"')
    assert loop < removal.index("Si l'ancien principal sert ailleurs")
    assert "for s in AZURE_CLIENT_SECRET AZURE_CLIENT_ID AZURE_TENANT_ID AZURE_SUBSCRIPTION_ID; do" in removal[:loop]
    compare = removal.index('[ "${${(P)sec}[1,3]}" = "$h" ]')
    # A hint is the start of a secret: compared, never shown — only the keyId and the variable.
    assert "hint" not in re.sub(r'--query "\[\]\.\[keyId,hint\]" -o tsv \| while read -r k h', "", removal.split("```bash", 2)[2].split("```")[0])
    assert 'echo "keyId $k : $sec, le poste s\'en sert"' in removal
    deletes = [m.start() for m in re.finditer(r"az ad app credential delete", removal)]
    assert deletes and compare < min(deletes)
    assert all("--key-id <keyId de cet identifiant>" in removal[d:d + 80] for d in deletes)


def _environment(job: dict) -> str | None:
    env = job.get("environment")
    return env.get("name") if isinstance(env, dict) else env


def test_the_canarys_token_names_its_environment_which_no_other_job_enters():
    """publish.yml holds `id-token: write` on main too: a federated credential on refs/heads/main
    would hand its pinned third-party actions the canary's principal. The canary's job is in the
    environment `canary`, which only main deploys; the credential's subject names it, and no
    other job enters it; its identifiers are that environment's secrets (P04 review)."""
    assert _environment(_canary_job()) == "canary"
    others = [(p.name, n) for p in WORKFLOWS if p != CANARY
              for n, j in (_load(p).get("jobs") or {}).items() if isinstance(j, dict) and _environment(j) == "canary"]
    assert others == []
    section = _canary_section()
    # The subject GitHub really issues — immutable, the owner and the repository by their ids — read
    # from the API, never typed: no id in the document (REN1, measured on 04/11).
    assert re.findall(r'"subject": "([^"]+)"', section) == ["$PREFIX:environment:canary"]
    assert 'PREFIX=$(gh api "repos/$REPO/actions/oidc/customization/sub" --jq .sub_claim_prefix)' in section
    assert "cat > /tmp/eregion-canary-fic.json <<EOF\n" in section     # unquoted: $PREFIX expands
    assert not re.search(r"@[0-9]{3,}", section)
    put = section.index('gh api -X PUT "repos/$REPO/environments/canary"')
    assert '"protected_branches": false, "custom_branch_policies": true' in section[put:put + 200]
    assert 'deployment-branch-policies" -f name=main -f type=branch' in section[put:]
    sets = [line for line in section.splitlines() if "gh secret set" in line]
    assert len(sets) == 3 and all("--env canary" in line for line in sets), sets


def test_the_canarys_principal_is_network_contributor_on_its_group_alone():
    """Network Contributor, not Contributor: Microsoft.Network/* and the group's read, never the
    group deleted, a VM created or a role granted. Assigned by the principal's object id (Graph
    may not have replicated a principal just created). Contributor on that same group is the
    fallback, written after a 403 only (P04 review)."""
    section = _canary_section()
    joined = re.sub(r"\\\n\s*", "", section)
    creates = [line for line in joined.splitlines() if line.startswith("az role assignment create")]
    first = creates[0]
    assert '--role "Network Contributor"' in first, first
    assert '--assignee-object-id "$(az ad sp show --id "$APP" --query id -o tsv)"' in first, first
    assert "--assignee-principal-type ServicePrincipal" in first and "--assignee " not in first, first
    assert all(c.rstrip().endswith("--scope /subscriptions/$SUB/resourceGroups/rg-eregion-canary") for c in creates)
    fallback = joined.index("# Seulement après un 403")
    assert all(joined.index(c) > fallback for c in creates if '"Network Contributor"' not in c)


def test_a_cancelled_canary_cleans_up_through_the_runners_second_signal(tmp_path):
    """On a cancel, the runner sends SIGINT, SIGTERM some 7.5 s later, then SIGKILL. The first
    starts the cleanup; the second, arriving during the destroy, must not cut it short: the
    quarantine NSG is still deleted after the destroy (P04 review)."""
    import os
    import signal
    import subprocess
    import time
    bin_, state = tmp_path / "bin", tmp_path / "state"
    bin_.mkdir()
    state.mkdir()
    _fake(bin_ / "terraform", _FAKE_TERRAFORM)
    _fake_py(bin_ / "az", _FAKE_AZ)
    log = tmp_path / "log"
    env = {"PATH": f"{bin_}:{os.environ.get('PATH', '')}", "HOME": str(tmp_path), "TMPDIR": str(tmp_path),
           "FAKE_LOG": str(log), "FAKE_STATE": str(state), "FAKE_BLOCK": "apply destroy",
           "ARM_SUBSCRIPTION_ID": "sub", "CANARY_SUFFIX": "gh1-1-0"}

    def reach(name):
        for _ in range(200):
            if (state / name).exists():
                return
            time.sleep(0.05)
        raise AssertionError(f"never reached {name}: {log.read_text() if log.exists() else ''}")

    proc = subprocess.Popen(["bash", str(JIT / "run.sh")], env=env, cwd=tmp_path,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        reach("at-apply")
        proc.send_signal(signal.SIGINT)
        (state / "go-apply").touch()
        reach("at-destroy")
        proc.send_signal(signal.SIGTERM)
        (state / "go-destroy").touch()
        out, err = proc.communicate(timeout=30)
    finally:
        proc.kill()
    calls = log.read_text().splitlines()
    assert proc.returncode == 130, (out, err)
    destroy = next(i for i, c in enumerate(calls) if c.startswith("terraform destroy"))
    assert calls[destroy + 1:] == [
        "az network nsg delete -g rg-eregion-canary -n nsg-glorfindel-quarantine-canary-gh1-1-0 -o none"], calls
    assert not list(tmp_path.glob("tmp.*")), "the stack's copy left behind"


# ── CAN1 (#501): a failed apply says the end of its error, nothing real in a public log ──────
# The canary sent the apply's output to /dev/null: a red line could not tell a passing 429 from
# a change of Azure. Now terraform's output and az's stderr go through redact.py only — the
# canary's identifiers, resource ids, GUIDs, tokens, e-mails and IPs taken out —, the end of it
# said, and a transient error said as such (exit 3, re-run). Every value below is made up.
CAN1_SUB, CAN1_TENANT, CAN1_CLIENT = ("0a1b2c3d-1111-4222-8333-444455556666",
                                      "7f6e5d4c-aaaa-4bbb-8ccc-dddd0000eeee", "app-canary-client-x")
CAN1_CORRELATION = "98765432-abcd-4ef0-9123-456789abcdef"
CAN1_RID = (f"/subscriptions/{CAN1_SUB}/resourceGroups/rg-eregion-canary/providers/Microsoft.Network"
            "/networkInterfaces/nic-with-nsg-gh1-1-0")
CAN1_REAL = [CAN1_SUB, CAN1_TENANT, CAN1_CLIENT, CAN1_CORRELATION, "10.0.0.4", "10.0.1.0/24", "20.50.1.2",
             "2001:db8::1", "fe80:0:0:0:200:f8ff:fe21:67cf", "ops@example.com", "eyJhbGciOi",
             "/subscriptions/", "%2Fsubscriptions%2F",
             # a resource id's end: it goes whole, never its subscription alone
             "resourceGroups/", "%2FresourceGroups", "Microsoft.Network/",
             # review of c914ccd0: escaped in JSON, a tenant's domain, a SAS, a GUID without its
             # dashes, an opaque bearer token, an IPv6 after a word and a colon
             "\\/subscriptions\\/", "resourceGroups\\/", "contoso-canary.onmicrosoft.com", "AbC%2Bsecret",
             "2026-11-05T00", "0a1b2c3d11114222833344445555abcd", "opaque-token-xyz123", "db8::"]
CAN1_GUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I)
CAN1_IPV4 = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
CAN1_ENV = {"ARM_SUBSCRIPTION_ID": CAN1_SUB, "ARM_TENANT_ID": CAN1_TENANT, "ARM_CLIENT_ID": CAN1_CLIENT}


def _can1_error(code: str = "AnotherOperationInProgress", status: str = "409 (409 Conflict)") -> str:
    """A failed apply as azurerm prints it, its error loaded with every form a log must not keep;
    its first line (the resource's id) and 35 more come before the error, beyond the tail."""
    head = [f"azurerm_network_interface.with_nsg: Modifying... [id={CAN1_RID}]"]
    head += [f"plan line {n} of the update" for n in range(1, 36)]
    error = [
        f'Error: updating Network Interface (Subscription: "{CAN1_SUB}"',
        'Resource Group Name: "rg-eregion-canary"',
        'Network Interface Name: "nic-with-nsg-gh1-1-0"): performing CreateOrUpdate: unexpected status '
        f"{status} with error: {code}: Operation PutNetworkInterfaceOperation ({CAN1_CORRELATION}) "
        f"on resource {CAN1_RID} is in progress.",
        f"tenant {CAN1_TENANT}, client {CAN1_CLIENT}, by ops@example.com at 12:03:04 (azurerm 4.81.0)",
        "private 10.0.0.4 in 10.0.1.0/24, public 20.50.1.2, and 2001:db8::1, fe80:0:0:0:200:f8ff:fe21:67cf.",
        f"GET https://management.azure.com/subscriptions%2F{CAN1_SUB}%2FresourceGroups?api-version=2024-05-01",
        f"PUT ?resource=%2Fsubscriptions%2F{CAN1_SUB}%2FresourceGroups%2Frg-eregion-canary",
        "token eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0.c2lnbmF0dXJl",
        '{"id":"\\/subscriptions\\/' + CAN1_SUB + '\\/resourceGroups\\/rg-eregion-canary\\/providers'
        '\\/Microsoft.Network\\/networkInterfaces\\/nic-with-nsg-gh1-1-0"}',
        "AADSTS700016: application not found in the directory contoso-canary.onmicrosoft.com.",
        "blob https://stcanary.blob.core.windows.net/c?sv=2024-05-04&se=2026-11-05T00%3A00Z&sig=AbC%2Bsecret%3D",
        "request 0a1b2c3d11114222833344445555abcd, Authorization: Bearer opaque-token-xyz123",
        "address:2001:db8::1, at 2026-11-04T12:03:29.429+00:00",
        "::add-mask::nothing",
        "::stop-commands::canary",
        "Error: tag value ##[add-mask]PASS and ###[set-output name=x]y",
        "",
        "  with azurerm_network_interface.with_nsg,",
        '  on main.tf line 52, in resource "azurerm_network_interface" "with_nsg":',
        "",
    ]
    return "\n".join(head + error) + "\n"


def _can1_clean(text: str) -> None:
    """Nothing real in what the canary printed: no value of the sample, no GUID, no IPv4, and no
    line that could start a workflow command — `::name::` at a line's start, leading spaces
    aside, or the historical `##[name]` anywhere in it (actions/runner, ActionCommand.cs)."""
    left = [v for v in CAN1_REAL if v.lower() in text.lower()]
    assert left == [], left
    assert not CAN1_GUID.search(text) and not CAN1_IPV4.search(text), text
    assert not [ln for ln in text.splitlines() if ln.lstrip().startswith("::")], text
    assert "##[" not in text, text


def _can1_module():
    import importlib.util
    spec = importlib.util.spec_from_file_location("can1_redact", JIT / "redact.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_can1_the_filter_takes_out_every_real_form_of_a_loaded_error(tmp_path):
    """The filter, run as the canary runs it, on an error loaded with each form: the canary's
    three identifiers (one not even a GUID), a resource id, URL-encoded ones, a correlation id,
    IPv4 and IPv6 addresses and a prefix, a token, an e-mail. What tells the error apart stays:
    its code, its status, the resource's address in the code, the NIC's name, a clock, the
    provider's version."""
    import subprocess
    import sys
    sample = tmp_path / "out"
    sample.write_text(_can1_error())
    with sample.open() as stdin:
        res = subprocess.run([sys.executable, "-I", str(JIT / "redact.py"), "--label",
                              "terraform apply failed (exit 1)", "--tail", "30", "--verdict"],
                             stdin=stdin, capture_output=True, text=True,
                             env={"PATH": "/usr/bin:/bin", **CAN1_ENV}, timeout=30)
    assert res.returncode == 3, res
    out = res.stdout
    _can1_clean(out)
    for kept in ("AnotherOperationInProgress", "409 (409 Conflict)", "azurerm_network_interface.with_nsg",
                 "main.tf line 52", 'Network Interface Name: "nic-with-nsg-gh1-1-0"', "12:03:04", "4.81.0",
                 "<subscription>", "<tenant>", "<client>", "<resource-id>", "<guid>", "<ip>", "<email>", "<token>",
                 "<tenant-domain>", "se=<sas>", "sig=<sas>", "Bearer <token>", "address:<ip>",
                 '{"id":"<resource-id>"}', "# #[add-mask]PASS", "## #[set-output", "12:03:29.429+00:00"):
        assert kept in out, (kept, out)
    lines = out.splitlines()
    assert lines[0] == "   terraform apply failed (exit 1); its end, ids, GUIDs and addresses masked:"
    assert lines[-1].startswith("   transient (AnotherOperationInProgress): Azure said to retry")
    said = lines[1:-1]
    assert len(said) == 30 and all(ln.startswith("   | ") for ln in said), said
    assert "plan line 6 of" not in out and "Modifying..." not in out         # the end only: its last 30 lines
    assert said[-1] == '   |   on main.tf line 52, in resource "azurerm_network_interface" "with_nsg":'
    assert res.stderr == ""


@pytest.mark.parametrize("code, status, transient", [
    ("AnotherOperationInProgress", "409 (409 Conflict)", True),
    ("RetryableError", "500 (500 Internal Server Error)", True),
    ("TooManyRequests", "429 (429 Too Many Requests)", True),
    ("ReferencedResourceNotProvisioned", "400 (400 Bad Request)", True),
    ("InvalidResourceReference", "400 (400 Bad Request)", False),
])
def test_can1_the_filter_says_a_transient_error_as_such(code, status, transient):
    mod = _can1_module()
    out, rc = mod.report(_can1_error(code, status), "terraform apply failed (exit 1)", 30, True, CAN1_ENV)
    _can1_clean(out)
    assert (rc == 3) is transient, out
    assert ("   transient (" in out) is transient and ("not a known transient error" in out) is not transient
    # no verdict asked (an az warning): never 3, never a verdict line
    out, rc = mod.report(_can1_error(code, status), "az network nic warned", 10, False, CAN1_ENV)
    assert rc == 0 and out.splitlines()[-1].startswith("   | "), out


def test_can1_a_clock_a_version_a_mac_and_a_short_value_are_not_taken_for_real_ones():
    text = "at 12:03:04, azurerm v4.81.0, subnet snet-a, MAC 00:0d:3a:12:34:56"
    assert _can1_module().redact(text, {"ARM_SUBSCRIPTION_ID": "sub"}) == text


def _can1_run(tmp_path: Path, **env):
    res, calls = _run_canary(tmp_path, **CAN1_ENV, **env)
    return res, calls, res.stdout + res.stderr


@pytest.mark.parametrize("code, status, verdict, rc", [
    ("AnotherOperationInProgress", "409 (409 Conflict)", "INCONCLUSIVE", 3),
    ("InvalidResourceReference", "400 (400 Bad Request)", "CHANGED", 1),
])
def test_can1_the_nics_failed_apply_says_its_end_filtered_and_whether_it_passes(tmp_path, code, status, verdict, rc):
    """The apply of the issue (« apply updating the NIC succeeds », exit 1): its end said, nothing
    real; on a transient error the line is inconclusive (exit 3, re-run), else changed (exit 1)."""
    err = tmp_path / "apply2.out"
    err.write_text(_can1_error(code, status))
    res, calls, both = _can1_run(tmp_path, FAKE_APPLY2_OUT=str(err))
    assert res.returncode == rc, both
    _can1_clean(both)
    assert "  FAIL apply updating the NIC succeeds — got '1', expected '0'" in res.stdout
    assert "terraform apply failed (exit 1); its end" in res.stderr and code in res.stderr, both
    result = res.stdout.split("== result:", 1)[1]
    assert verdict in result and {"INCONCLUSIVE", "CHANGED"} - {verdict} - set(result.split()), result
    # the cleanup still runs, after the verdict
    assert any(c.startswith("terraform destroy") for c in calls)
    assert not list(tmp_path.glob("tmp.*")), "the stack's copy left behind"


def test_can1_a_check_failed_before_the_transient_error_stays_a_change(tmp_path):
    """A plan that shows a change (exit 2), then a 429 on the apply: the change is not a passing
    hitch — CHANGED, exit 1, never inconclusive."""
    err = tmp_path / "apply2.out"
    err.write_text(_can1_error("TooManyRequests", "429 (429 Too Many Requests)"))
    res, _calls, both = _can1_run(tmp_path, FAKE_APPLY2_OUT=str(err), FAKE_PLAN_RC="2")
    assert res.returncode == 1 and "CHANGED" in res.stdout and "INCONCLUSIVE" not in res.stdout, both
    assert "transient (429)" in res.stderr, res.stderr
    assert "terraform plan failed" not in both            # a plan's exit 2 is its answer, not an error


@pytest.mark.parametrize("code, rc", [("RetryableError", 3), ("AuthorizationFailed", 2)])
def test_can1_a_failed_setup_says_its_end_and_whether_to_re_run(tmp_path, code, rc):
    err = tmp_path / "apply1.out"
    err.write_text(_can1_error(code, "500 (500 Internal Server Error)" if rc == 3 else "403 (403 Forbidden)"))
    res, calls, both = _can1_run(tmp_path, FAKE_APPLY1_OUT=str(err))
    assert res.returncode == rc, both
    _can1_clean(both)
    assert "terraform apply failed (exit 1); its end" in res.stderr
    assert ("INCONCLUSIVE — the setup failed on a transient error" in res.stdout) is (rc == 3), res.stdout
    assert not [c for c in calls if c.startswith("az network nsg create")]     # stopped there


def test_can1_an_az_error_is_said_filtered_too(tmp_path):
    """az's stderr carries the same forms (a NIC update refused): said, filtered, its transient
    error noted; nothing of it raw."""
    err = tmp_path / "az.err"
    err.write_text(f"ERROR: (AnotherOperationInProgress) Operation on {CAN1_RID} by {CAN1_CORRELATION} "
                   "is in progress (10.0.0.4).\nCode: AnotherOperationInProgress")
    res, _calls, both = _can1_run(tmp_path, FAKE_NIC_UPDATE_ERR=str(err))
    _can1_clean(both)
    assert "az network nic update failed (exit 1); its end" in res.stderr, both
    assert "<resource-id>" in res.stderr and "transient (AnotherOperationInProgress)" in res.stderr
    assert res.returncode == 3 and "INCONCLUSIVE" in res.stdout, both


def test_can1_the_canary_prints_no_command_output_but_through_the_filter():
    """Read from run.sh: terraform runs through tf() alone (its version aside, which names no
    resource), az through its wrapper, and both outputs reach the log through the filter only."""
    text = (JIT / "run.sh").read_text(encoding="utf-8")
    code = [ln.split("  # ", 1)[0] for ln in text.splitlines() if not ln.lstrip().startswith("#")]
    raw_tf = [ln for ln in code if re.search(r"(?<![\w-])terraform\s", ln)
              and 'terraform "$@" > "$OUT.tf" 2>&1' not in ln and "terraform version -json" not in ln
              and 'say "terraform' not in ln]
    assert raw_tf == [], raw_tf
    assert 'command az "$@" 2> "$OUT.az"' in text
    # the filter's words kept aside, its errors silenced; printed on its exits 0 and 3 alone
    assert re.search(r'python3 -I "\$SRC/redact\.py" .*< "\$2" \\\n\s+> "\$OUT\.said" 2>/dev/null', text)
    # every az, the group's read first, through the wrapper: defined before it is called
    assert text.index("\naz() {") < text.index("az group show")
    assert not [ln for ln in code if "command az" in ln and 'command az "$@" 2> "$OUT.az"' not in ln]


@pytest.mark.parametrize("text, transient", [
    ("Error: InvalidResourceReference at 2026-11-04T12:03:29.429+00:00", False),   # milliseconds, no status
    ("Error: request 1429 failed, code 4290", False),
    ("unexpected status 429 (429 Too Many Requests)", True),
    ("StatusCode=429 -- Original Error: x", True),
    ('{"status": 429, "message": "slow down"}', True),
    ("HTTP/1.1 429", True),
])
def test_can1_a_429_is_a_status_never_a_timestamps_milliseconds(text, transient):
    """Review of c914ccd0: `…:29.429+00:00` said « transient ». A 429 counts as a status only."""
    out, rc = _can1_module().report(text, "terraform apply failed (exit 1)", 30, True, {})
    assert (rc == 3) is transient, out


def test_can1_a_filter_that_fails_says_nothing_of_the_text(tmp_path):
    """The filter stopped halfway (a fake python3 that echoes the text, raw, then exits 1): the
    canary says the output was withheld, and nothing of it reaches the log."""
    import sys
    bin_ = tmp_path / "bin"
    bin_.mkdir()
    _fake(bin_ / "python3", f'for a in "$@"; do case "$a" in */redact.py) cat; echo "Traceback: raw" >&2; exit 1;; '
                            f'esac; done\nexec {sys.executable} "$@"\n')
    err = tmp_path / "apply2.out"
    err.write_text(_can1_error())
    res, _calls, both = _can1_run(tmp_path, FAKE_APPLY2_OUT=str(err))
    _can1_clean(both)
    assert "terraform apply failed (exit 1): its output withheld (the filter failed)" in res.stderr, both
    assert "Traceback" not in both and "plan line" not in both
    assert res.returncode == 1 and "CHANGED" in res.stdout, both       # no transient error was said


def test_can1_a_transient_error_in_the_cleanup_asks_for_no_re_run(tmp_path):
    """The checks passed; the destroy then fails on a 429: said, the sweep follows, and the line
    stays green — never « re-run this line before reading a change »."""
    err = tmp_path / "destroy.out"
    err.write_text(_can1_error("TooManyRequests", "429 (429 Too Many Requests)"))
    res, _calls, both = _can1_run(tmp_path, FAKE_DESTROY_RC="1", FAKE_DESTROY_OUT=str(err))
    _can1_clean(both)
    assert res.returncode == 0 and "PASS" in res.stdout, both
    assert "terraform destroy failed (exit 1); its end" in res.stderr and "sweeping" in res.stdout
    assert "transient (429): Azure said to retry — the cleanup goes on" in res.stderr, res.stderr
    assert "re-run this line" not in both


@pytest.mark.parametrize("code, rc", [("AuthorizationFailed", 2), ("TooManyRequests", 3)])
def test_can1_the_groups_read_goes_through_the_wrapper(tmp_path, code, rc):
    """`az group show` was silenced, outside the wrapper: its error is said now, filtered — a
    transient one makes the line inconclusive (3), any other a setup error (2)."""
    err = tmp_path / "group.err"
    err.write_text(f"ERROR: ({code}) The client '{CAN1_CLIENT}' with object id '{CAN1_CORRELATION}' "
                   f"has no read on scope '{CAN1_RID}'.\nCode: {code}")
    res, calls, both = _can1_run(tmp_path, FAKE_GROUP_RC="1", FAKE_GROUP_ERR=str(err))
    _can1_clean(both)
    assert res.returncode == rc and "create it once" in res.stdout, both
    assert "az group show -n failed (exit 1); its end" in res.stderr and code in res.stderr, both
    assert not [c for c in calls if c.startswith(("terraform", "az network"))]
    assert not list(tmp_path.glob("tmp.*")), "the stack's copy left behind"


# ── CI4 (#389): the Terraform tests run on each push and pull request, the providers locked ──
# Jonathan, 31/10: each module's lock is committed (versions and hashes, linux_amd64 and darwin),
# `init` never upgrades on its own, and an upgrade is wanted (`make providers-lock`, then a PR).

TF_MODULES = ("terraform", "glorfindel-host", "orodruin")


def _terraform_job() -> dict:
    return _load(ROOT / ".github" / "workflows" / "ci.yml")["jobs"]["terraform-test"]


# What the job runs, word for word (review of #402, point 2): a `|| true`, a step skipped by an
# `if:`, or a job that may fail and stay green would let a broken test through, unseen.
TF_RUNS = {
    "Terraform test — Celebrimbor (mock providers)":
        "terraform -chdir=infra/terraform init -backend=false -lockfile=readonly -input=false -no-color\n"
        "terraform -chdir=infra/terraform test -no-color\n",
    # SEC11 (R-03): the session drain, VM by VM, planned against a mock azurerm.
    "Terraform test — Glorfindel's host (mock providers)":
        "terraform -chdir=infra/glorfindel-host init -backend=false -lockfile=readonly -input=false -no-color\n"
        "terraform -chdir=infra/glorfindel-host validate -no-color\n"
        "terraform -chdir=infra/glorfindel-host test -no-color\n",
    "Terraform validate — Orodruin":
        "terraform -chdir=infra/orodruin init -backend=false -lockfile=readonly -input=false -no-color\n"
        "terraform -chdir=infra/orodruin validate -no-color\n",
}


def test_the_terraform_tests_run_on_each_push_and_pull_request():
    doc = _load(ROOT / ".github" / "workflows" / "ci.yml")
    assert {"push", "pull_request"} <= _events(doc)
    job = _terraform_job()
    assert isinstance(job.get("timeout-minutes"), int) and job["timeout-minutes"] <= 30
    steps = job["steps"]
    assert {s.get("name"): s.get("run") for s in steps if s.get("name") in TF_RUNS} == TF_RUNS
    # Nothing that would keep it green on a failure, nor skip a step; skipped at night only (CI5:
    # the night of ci.yml is macOS's), never on a push or a pull request.
    assert "continue-on-error" not in job
    assert {e: _runs(job, e) for e in ("push", "pull_request", "schedule")} == {
        "push": True, "pull_request": True, "schedule": False}
    for step in steps:
        assert "continue-on-error" not in step and "if" not in step, step.get("name") or step.get("uses")
        assert "||" not in str(step.get("run") or ""), step.get("name")
    (checkout,) = [s for s in steps if str(s.get("uses") or "").startswith("actions/checkout@")]
    assert checkout["with"]["persist-credentials"] is False
    assert job["env"]["CHECKPOINT_DISABLE"] == "1"
    # Every module with Terraform tests has them run here: Celebrimbor's, and Glorfindel's host
    # since SEC11 — each named in a step that runs its `test`. Orodruin's since WC1, once its step
    # is in the workflow (TF_AWAITING_STEP): until then its `validate` still runs.
    tested = {p.parent.parent.name for p in ROOT.glob("infra/*/tests/*.tftest.hcl")}
    assert tested == {"terraform", "glorfindel-host", "orodruin"}
    for module in tested:
        runs_it = any(f"terraform -chdir=infra/{module} test -no-color" in str(s.get("run") or "") for s in steps)
        # Awaiting, it is not run yet; run, it is awaiting no more — the list empties itself.
        assert runs_it is (module not in TF_AWAITING_STEP), module
    for module in TF_AWAITING_STEP:
        assert any(f"terraform -chdir=infra/{module} validate -no-color" in str(s.get("run") or "")
                   for s in steps), module


# A module whose tests wait for their step in ci.yml: a session never writes under .github/ (the
# agents' App has no Workflows permission, SEC12) — Jonathan adds the step, then empties this. WC1
# (#523): `terraform -chdir=infra/orodruin test -no-color` after its `validate`, in « Terraform
# validate — Orodruin » (and TF_RUNS above).
TF_AWAITING_STEP = {"orodruin": "WC1 (#523): infra/orodruin/tests/watch_writers.tftest.hcl; "
                                "IDI1 (#546): infra/orodruin/tests/graph_read.tftest.hcl"}


def test_every_terraform_test_only_plans():
    """Review of #402, point 5: a `run` block applies by default — against mock providers, but
    vm.tf holds a local-exec. Each `run` of the repository's tests says `command = plan`."""
    for path in sorted(ROOT.glob("infra/*/tests/*.tftest.hcl")):
        text = path.read_text(encoding="utf-8")
        blocks = re.split(r'^run "', text, flags=re.M)[1:]
        assert blocks, path.name
        for block in blocks:
            name = block.split('"', 1)[0]
            assert re.search(r"^\s*command\s*=\s*plan\s*$", block, re.M), f"{path.name}: run {name} applies"


def test_the_terraform_job_installs_a_pinned_terraform_by_hashicorps_key_only():
    """As the canary: the key checked against HashiCorp's published fingerprint before apt
    trusts it, only that key in apt's keyring — and here, one exact version."""
    (install,) = [s for s in _terraform_job()["steps"] if "apt.releases.hashicorp.com/gpg" in str(s.get("run") or "")]
    assert install["env"]["HASHICORP_APT_FPR"] == HASHICORP_APT_FPR
    assert re.fullmatch(r"\d+\.\d+\.\d+-\d+", install["env"]["TERRAFORM_VERSION"])
    run = install["run"]
    assert ("""'$1=="pub"{n++;p=1;next} $1=="fpr"&&p{k=$10;p=0} END{exit !(n==1&&k==f)}'""" in run
            and '-v f="$HASHICORP_APT_FPR"' in run)
    assert run.index("exit 1") < run.index("/usr/share/keyrings/hashicorp-archive-keyring.gpg")
    assert '--export "$HASHICORP_APT_FPR"' in run
    assert 'apt-get install -y -qq "terraform=${TERRAFORM_VERSION}"' in run


def test_the_terraform_job_holds_no_azure_identity_nor_secret():
    """Mock providers only: no secret, no token GitHub would mint, no ARM_ variable."""
    job = _terraform_job()
    text = yaml.safe_dump(job)
    assert "secrets." not in text and "ARM_" not in text and "AZURE_" not in text
    assert "permissions" not in job                         # the workflow's: contents: read
    assert _load(ROOT / ".github" / "workflows" / "ci.yml")["permissions"] == {"contents": "read"}


@pytest.mark.parametrize("module", TF_MODULES)
def test_each_module_commits_its_lock_with_every_provider_it_requires(module):
    import subprocess
    lock = ROOT / "infra" / module / ".terraform.lock.hcl"
    assert lock.exists()
    ignored = subprocess.run(["git", "check-ignore", "-q", str(lock)], cwd=ROOT).returncode == 0
    assert not ignored, f"{lock.name} of infra/{module} is ignored: the lock must be committed"
    text = lock.read_text(encoding="utf-8")
    config = "\n".join(p.read_text(encoding="utf-8") for p in (ROOT / "infra" / module).glob("*.tf"))
    required = {s.lower() for s in re.findall(r'source\s*=\s*"([\w-]+/[\w-]+)"', config)}
    locked = {s.lower() for s in re.findall(r'provider "registry\.terraform\.io/([\w-]+/[\w-]+)"', text)}
    assert required and required <= locked, required - locked
    # The three platforms the team runs (Linux, both Macs): a hash of each package per provider.
    for name, block in re.findall(r'provider "registry\.terraform\.io/([^"]+)" \{(.*?)\n\}', text, re.S):
        assert block.count('"h1:') >= 3, name
        assert re.search(r'version\s*=\s*"\d+\.\d+\.\d+"', block), name


def test_init_never_upgrades_the_providers_on_its_own():
    """Review of #402, point 1: nowhere in the repository does `init` upgrade the providers — the
    lock would be rewritten without a PR — but in `make providers-lock`, the wanted upgrade, and
    the canary (infra/canary/: the latest azurerm, by design). Every tracked file is read, docs
    and this file aside. Outside a checkout (the mutants' copy), the tree (MUT1, #503)."""
    from .tracked_files import tracked
    files = tracked(ROOT)
    upgrade = re.compile(r"""\binit\b.*-upgrade|["']init["']\s*,\s*["']-upgrade["']""")
    lines = (ROOT / "Makefile").read_text(encoding="utf-8").splitlines()
    start = next(i for i, ln in enumerate(lines) if ln.startswith("providers-lock:"))
    end = next(i for i in range(start + 1, len(lines)) if lines[i] and not lines[i].startswith("\t"))
    found = []
    for name in files:
        if name.endswith(".md") or name.startswith("infra/canary/") or name == "tests/unit/test_workflows.py":
            continue
        try:
            text = (ROOT / name).read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        for n, line in enumerate(text.splitlines()):
            if upgrade.search(line) and not (name == "Makefile" and start < n < end):
                found.append(f"{name}:{n + 1}: {line.strip()}")
    assert found == []
    assert any(upgrade.search(ln) for ln in lines[start:end]), "providers-lock no longer upgrades"
    for var in ("$(TF)", "$(HOST_TF)", "$(ORO_TF)"):
        assert any(f"{var} init" in ln for ln in lines), var
    recipe = "\n".join(lines[start:end])
    assert "-platform=linux_amd64" in "\n".join(lines) and "providers lock $(TF_PLATFORMS)" in recipe
    assert 'case "$(MODULE)" in ""|terraform|glorfindel-host|orodruin)' in recipe


# ── SEC14 (#420): the SBOM's tool pinned, the bot's token kept from forks, the advisories on each PR ──

FORK_GUARD_PR = "github.event.pull_request.head.repo.full_name == github.repository"
FORK_GUARD_RUN = "github.event.workflow_run.head_repository.full_name == github.repository"


def test_the_sbom_tool_is_pinned_by_its_sha256_never_fetched_by_an_action():
    """R-14: the job that signs installs syft itself, from its archive checked against its sha256."""
    steps = _load(PUBLISH)["jobs"]["publish"]["steps"]
    assert not [a for a in _actions(_load(PUBLISH)) if a.startswith("anchore/")]
    names = [s.get("name") or s["uses"].split("@")[0] for s in steps]
    runs = {s.get("name"): s.get("run", "") for s in steps}
    assert runs["syft"] == 'python3 scripts/published_image.py install-syft "$RUNNER_TEMP/syft"'
    assert runs["SBOM"].startswith('"$RUNNER_TEMP/syft" scan "docker:$REF" -o spdx-json=sbom.spdx.json')
    order = [names.index(n) for n in ("Push", "syft", "SBOM", "actions/attest-sbom")]
    assert order == sorted(order)
    sbom = next(s for s in steps if s.get("name") == "SBOM")
    assert sbom["env"]["REF"] == "${{ steps.meta.outputs.ref }}"     # an output, never a chosen value


def _env(workflow: str, job: str) -> dict:
    (step,) = [s for s in _load(ROOT / ".github" / "workflows" / workflow)["jobs"][job]["steps"]
               if s.get("name") == "Discord"]
    return step["env"]


def test_the_bots_token_is_never_given_to_an_event_a_fork_triggers():
    """R-15: a fork's pull request (pull_request_target) or a red run of a fork's head
    (workflow_run) gets neither the bot's token nor its forum; its own events keep them."""
    notify = _env("notify.yml", "notify")
    for key in ("EREGION_DISCORD_BOT_TOKEN", "EREGION_DISCORD_LOTS_FORUM"):
        value = notify[key].replace(" ", "")
        assert value.startswith("${{(") and value.endswith(f"&&secrets.{key}||''}}}}"), value
        assert FORK_GUARD_PR.replace(" ", "") in value and FORK_GUARD_RUN.replace(" ", "") in value
        assert "github.event_name=='pull_request_target'&&" in value and "github.event_name=='workflow_run'&&" in value
    roadmap = _env("roadmap.yml", "roadmap")
    for key in ("EREGION_DISCORD_BOT_TOKEN", "EREGION_DISCORD_LOTS_FORUM", "EREGION_DISCORD_ROADMAP_CHANNEL"):
        value = roadmap[key].replace(" ", "")
        assert value == (f"${{{{(github.event_name!='pull_request_target'||{FORK_GUARD_PR.replace(' ', '')})"
                         f"&&secrets.{key}||''}}}}"), value
    # No other secret of the bot reaches these jobs unguarded.
    for workflow, job in (("notify.yml", "notify"), ("roadmap.yml", "roadmap")):
        text = (ROOT / ".github" / "workflows" / workflow).read_text(encoding="utf-8")
        assert text.count("secrets.EREGION_DISCORD_BOT_TOKEN") == 1


def test_the_advisories_are_read_on_each_push_and_pull_request_read_only():
    """P-03: ci.yml's audit job — the locks read by pip-audit from its own lock, red only for an
    advisory with a fix no one accepted; it writes no issue, holds no secret."""
    doc = _load(ROOT / ".github" / "workflows" / "ci.yml")
    assert {"push", "pull_request"} <= _events(doc)
    job = doc["jobs"]["audit"]
    assert job["runs-on"] == "ubuntu-24.04" and "permissions" not in job
    assert doc["permissions"] == {"contents": "read"}
    runs = "\n".join(s.get("run") or "" for s in job["steps"])
    assert '/pip" install --require-hashes -r requirements/audit.txt' in runs
    assert "scripts/pip_audit_issues.py pr " in runs and "--accepted requirements/audit-accepted.json" in runs
    for lock in ("requirements/dev.txt", "requirements/glorfindel.txt", "requirements/annatar.txt",
                 "requirements/audit.txt"):
        assert lock in runs
    # Red on a pull request; never on a push — H0's CD reads every check-run of a release's commit
    # (infra/glorfindel-host/cd/eregion_cd.py): only the step may continue, never the job.
    assert "continue-on-error" not in job
    # The install too: PyPI down during a push must not hold a release back either.
    (advisories,) = [s for s in job["steps"] if "pip_audit_issues.py pr" in (s.get("run") or "")]
    (install,) = [s for s in job["steps"] if s.get("name") == "Install pip-audit"]
    for step in (install, advisories):
        assert step["continue-on-error"].replace(" ", "") == "${{github.event_name=='push'}}"
    assert [s for s in job["steps"] if "continue-on-error" in s] == [install, advisories]
    assert "secrets." not in (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    checkout = [s for s in job["steps"] if str(s.get("uses", "")).startswith("actions/checkout@")]
    assert checkout and checkout[0]["with"]["persist-credentials"] is False


# ── CI6 (#514): the release gate, the strongest measure on the tree a release publishes ──────
# Jonathan, 04/11. Read from the file; its last job's script run against chosen `needs`.
GATE = ROOT / ".github" / "workflows" / "release-gate.yml"
GATE_SCOPE = ("github.event_name == 'workflow_dispatch' || (startsWith(github.head_ref, 'chore/release-') "
              "&& github.event.pull_request.head.repo.full_name == github.repository)")
GATE_REF = "${{ github.event.pull_request.head.sha || github.sha }}"
MUTANT_SHARDS, CONTROL_SHARDS = 14, 2
MACOS_SAID = "Said in the run's summary, never blocking"


def _gate() -> dict:
    return _load(GATE)


def test_the_gate_runs_on_the_version_s_pull_request_or_by_dispatch_only():
    """A pull request that changes pyproject.toml (a version's always does), or a dispatch: never a
    push (main's checks stay what they are), a schedule, nor an event a fork runs with the default
    branch's rights. A new push cancels the run it replaces: one battery per tree."""
    doc = _gate()
    assert doc["name"] == "Release gate"
    assert doc["on"] == {"pull_request": {"paths": ["pyproject.toml"]}, "workflow_dispatch": None}
    # As ci.yml (CI5): a new push on the pull request cancels the run it replaces, a dispatch never.
    assert doc["concurrency"] == {
        "group": "${{ github.workflow }}-${{ github.event_name == 'pull_request' && "
                 "format('pr-{0}', github.event.pull_request.number) || github.run_id }}",
        "cancel-in-progress": "${{ github.event_name == 'pull_request' }}"}


def test_no_job_of_the_gate_takes_the_name_of_a_ci_check():
    """The gate runs under a path filter: a check named as one of ci.yml's (a required check of
    main) would stand for it on the version's pull request, or stay « expected »."""
    names = lambda doc: {str(job.get("name", key)) for key, job in doc["jobs"].items()}  # noqa: E731
    ci = _load(ROOT / ".github" / "workflows" / "ci.yml")
    assert names(_gate()) & names(ci) == set()
    assert _gate()["jobs"]["terraform"]["name"] == "terraform test (release gate)"


def test_every_job_of_the_gate_runs_only_for_a_version_or_a_dispatch():
    """Any other pull request that touches pyproject.toml skips every job: the battery runs on this
    repository's chore/release-… branch, or a dispatch. The last job runs whatever came before."""
    jobs = _gate()["jobs"]
    for name, job in jobs.items():
        want = f"${{{{ always() && ({GATE_SCOPE}) }}}}" if name == "gate" else f"${{{{ {GATE_SCOPE} }}}}"
        assert job.get("if") == want, (name, job.get("if"))


def test_the_gate_holds_contents_read_and_nothing_else():
    doc = _gate()
    assert doc["permissions"] == {"contents": "read"}
    assert all("permissions" not in job for job in doc["jobs"].values())
    text = GATE.read_text(encoding="utf-8")
    assert "secrets." not in text and "github.token" not in text and "GITHUB_TOKEN" not in text


def test_every_job_of_the_gate_measures_the_pull_request_s_head_exactly():
    """The tree release.py compares with origin/main's: the PR's head, never GitHub's merge commit."""
    for name, job in _gate()["jobs"].items():
        checkouts = [s for s in job["steps"] if str(s.get("uses") or "").startswith("actions/checkout@")]
        if name == "gate":
            assert checkouts == []                    # it reads `needs`, nothing of the repository
            continue
        assert len(checkouts) == 1 and checkouts[0]["with"] == {"ref": GATE_REF, "persist-credentials": False}, name


def test_every_job_of_the_gate_is_bounded():
    jobs = _gate()["jobs"]
    for name, job in jobs.items():
        bound = job.get("timeout-minutes")
        assert isinstance(bound, int) and 0 < bound <= 180, (name, bound)
        # Only macOS may fail without failing the run: it informs (H1c, #518).
        assert ("continue-on-error" not in job) is (name != "macos"), name
        for step in job["steps"]:
            assert "continue-on-error" not in step, (name, step.get("name") or step.get("uses"))
            if "if" in step:                          # macOS's summary alone, said whatever came before
                assert (name, step.get("name"), step["if"]) == ("macos", MACOS_SAID, "always()"), (name, step)
    assert jobs["invariants"]["timeout-minutes"] <= 75 and jobs["gate"]["timeout-minutes"] <= 5


def test_the_gate_runs_every_test_with_2000_invariant_sequences_on_linux():
    job = _gate()["jobs"]["invariants"]
    assert job["runs-on"] == "ubuntu-latest"
    (step,) = [s for s in job["steps"] if "pytest" in (s.get("run") or "")]
    assert step["run"].startswith("python -m pytest tests/ -q")
    assert step["env"] == {"GLORFINDEL_INVARIANT_EXAMPLES": "2000", "GLORFINDEL_INVARIANT_DB": ".hypothesis-invariants"}
    assert any("actions/cache/restore" in (s.get("uses") or "") and s["with"]["path"] == ".hypothesis-invariants"
               for s in job["steps"])


def test_the_gate_runs_the_whole_mutation_in_shards_control_set_included():
    """`--examples 500 --rounds 2 --jobs 4`, each shard of the matrix once; the control set too; the
    total checks every shard, then that no mutant survived a round outside the known survivors
    (CI6e: `min_caught` before) — the harness holds it, nothing of the workflow passes over it."""
    jobs = _gate()["jobs"]
    for name, n, flag in (("mutants", MUTANT_SHARDS, ""), ("control", CONTROL_SHARDS, "--control ")):
        job = jobs[name]
        assert job["strategy"] == {"fail-fast": False, "matrix": {"shard": list(range(1, n + 1))}}, name
        (step,) = [s for s in job["steps"] if "mutation_check.py" in (s.get("run") or "")]
        assert step["run"] == (f"python scripts/mutation_check.py {flag}--examples 500 --rounds 2 --jobs 4 "
                               f'--shard "$SHARD/{n}" --json "{name}-$SHARD.json"'), step["run"]
        assert step["env"] == {"SHARD": "${{ matrix.shard }}"}
        (up,) = [s for s in job["steps"] if str(s.get("uses") or "").startswith("actions/upload-artifact@")]
        assert up["with"]["name"] == f"{name}-${{{{ matrix.shard }}}}" and up["with"]["if-no-files-found"] == "error"
    total = jobs["mutants-total"]
    assert total["needs"] == ["mutants", "control"]
    (step,) = [s for s in total["steps"] if "mutation_check.py" in (s.get("run") or "")]
    assert step["run"] == (f"python3 scripts/mutation_check.py --total mutants-results --shards {MUTANT_SHARDS} "
                           f'--control-shards {CONTROL_SHARDS} --examples 500 --rounds 2')
    assert "env" not in step and "continue-on-error" not in step and "continue-on-error" not in total
    (down,) = [s for s in total["steps"] if str(s.get("uses") or "").startswith("actions/download-artifact@")]
    assert down["with"] == {"path": "mutants-results"}


# CI6d (#545): the Monday measure in the gate's shards — on one runner it outlasted its 180 min.
MONDAY = ROOT / ".github" / "workflows" / "mutants.yml"
MONDAY_INPUTS = {"EXAMPLES": "${{ inputs.examples || '1000' }}", "ROUNDS": "${{ inputs.rounds || '2' }}"}


def test_the_monday_measure_runs_in_the_gate_s_shards_and_their_total():
    """Fourteen shards of the mutants and two of the control set, as release-gate.yml cuts them, then
    their total: each mutant of the tree measured once, at the dispatcher's budget, the count held
    to no survivor outside the known ones (CI6e) — never more jobs than GitHub gives a public
    repository at once (20)."""
    doc, gate = _load(MONDAY), _gate()["jobs"]
    jobs = doc["jobs"]
    assert doc["on"]["schedule"] == [{"cron": "41 4 * * 1"}] and doc["permissions"] == {"contents": "read"}
    assert set(jobs) == {"mutants", "control", "mutants-total"}
    for name, n, flag in (("mutants", MUTANT_SHARDS, ""), ("control", CONTROL_SHARDS, "--control ")):
        job = jobs[name]
        assert job["strategy"] == gate[name]["strategy"] == {"fail-fast": False,
                                                             "matrix": {"shard": list(range(1, n + 1))}}
        steps = job["steps"]
        (step,) = [s for s in steps if "mutation_check.py" in (s.get("run") or "")]
        assert step["run"] == (f'python scripts/mutation_check.py {flag}--examples "$EXAMPLES" --rounds "$ROUNDS" '
                               f'--jobs 4 --shard "$SHARD/{n}" --json "{name}-$SHARD.json"'), step["run"]
        assert step["env"] == {**MONDAY_INPUTS, "SHARD": "${{ matrix.shard }}"}
        (up,) = [s for s in steps if str(s.get("uses") or "").startswith("actions/upload-artifact@")]
        assert up["with"]["name"] == f"{name}-${{{{ matrix.shard }}}}" and up["with"]["if-no-files-found"] == "error"
        restore = [i for i, s in enumerate(steps) if s.get("with") == CHROMA_CACHE]
        assert len(restore) == 1 and restore[0] < steps.index(step), name
        assert 0 < job["timeout-minutes"] <= 180
    total = jobs["mutants-total"]
    assert total["needs"] == ["mutants", "control"] and total["if"] == "${{ !cancelled() }}"
    (step,) = [s for s in total["steps"] if "mutation_check.py" in (s.get("run") or "")]
    assert step["run"] == (f"python3 scripts/mutation_check.py --total mutants-results --shards {MUTANT_SHARDS} "
                           f'--control-shards {CONTROL_SHARDS} --examples "$EXAMPLES" --rounds "$ROUNDS"')
    assert step["env"] == MONDAY_INPUTS and "continue-on-error" not in step
    assert set(doc["on"]["workflow_dispatch"]["inputs"]) == {"examples", "rounds"}     # min_caught gone (CI6e)
    (down,) = [s for s in total["steps"] if str(s.get("uses") or "").startswith("actions/download-artifact@")]
    assert down["with"] == {"path": "mutants-results"}
    width = sum(len(j.get("strategy", {}).get("matrix", {}).get("shard", [None])) for j in jobs.values())
    assert width == MUTANT_SHARDS + CONTROL_SHARDS + 1 <= 20
    # the gate's own actions, pinned by commit, and the checkout's credentials never kept
    assert all(PINNED.match(a) for a in _actions(doc)), _actions(doc)
    assert set(_actions(doc)) <= set(_actions(_gate()))
    for job in jobs.values():
        (checkout,) = [s for s in job["steps"] if str(s.get("uses") or "").startswith("actions/checkout@")]
        assert checkout["with"] == {"persist-credentials": False}


CHROMA_CACHE = {"path": "~/.cache/chroma", "key": "chroma-onnx-v1"}


def test_the_gate_s_test_runs_restore_chroma_s_model_as_ci_does():
    """CI6b (#538): the invariants, the mutants and the control set restore ChromaDB's model before
    their tests, by the same action pinned by commit, under ci.yml's key — at the gate's first real
    run, the mutants' unmutated runs fetched it at once into one place, two shards red."""
    jobs = _gate()["jobs"]
    pins = set()
    for name in ("invariants", "mutants", "control"):
        steps = jobs[name]["steps"]
        restores = [i for i, s in enumerate(steps) if s.get("with") == CHROMA_CACHE]
        assert len(restores) == 1, name
        uses = steps[restores[0]]["uses"]
        assert re.fullmatch(r"actions/cache/restore@[0-9a-f]{40}", uses), (name, uses)
        pins.add(uses)
        (tests,) = [i for i, s in enumerate(steps) if "pytest" in (s.get("run") or "")
                    or "mutation_check.py" in (s.get("run") or "")]
        assert restores[0] < tests, name
    assert len(pins) == 1                                     # one action, one commit
    ci = _load(ROOT / ".github" / "workflows" / "ci.yml")["jobs"]
    ci_keys = {s["with"]["key"] for job in ci.values() for s in job.get("steps", [])
               if (s.get("with") or {}).get("path") == CHROMA_CACHE["path"]}
    assert ci_keys == {CHROMA_CACHE["key"]}


def _run_steps(job: dict) -> list[dict]:
    return [{k: s.get(k) for k in ("name", "run", "env")} for s in job["steps"] if s.get("run")]


def test_the_gate_runs_ci_s_macos_job_and_its_terraform_tests_word_for_word():
    """The macOS job a pull request no longer runs (CI5), and the Terraform tests: the same
    commands as ci.yml's, so neither drifts from what the CI runs."""
    ci, jobs = _load(ROOT / ".github" / "workflows" / "ci.yml")["jobs"], _gate()["jobs"]
    assert jobs["macos"]["runs-on"] == ci["test-macos"]["runs-on"] == "macos-latest"
    assert [s for s in _run_steps(jobs["macos"]) if s["name"] != MACOS_SAID] == _run_steps(ci["test-macos"])
    assert jobs["macos"]["timeout-minutes"] == ci["test-macos"]["timeout-minutes"]
    assert _run_steps(jobs["terraform"]) == _run_steps(ci["terraform-test"])
    assert {s.get("name"): s.get("run") for s in jobs["terraform"]["steps"] if s.get("name") in TF_RUNS} == TF_RUNS
    assert jobs["terraform"]["env"] == ci["terraform-test"]["env"] == {"CHECKPOINT_DISABLE": "1"}


def test_the_last_job_waits_for_every_other_one():
    jobs = _gate()["jobs"]
    assert jobs["gate"]["name"] == "release gate"
    assert sorted(jobs["gate"]["needs"]) == sorted(n for n in jobs if n != "gate")
    (step,) = jobs["gate"]["steps"]
    # It waits for macOS too, to say it — and asks nothing of it: macOS alone informs.
    assert step["env"] == {"NEEDS": "${{ toJSON(needs) }}", "INFORMATIVE": "macos"}


def test_macos_informs_and_never_blocks():
    """Jonathan, 04/11 (H1c, #518): only what is required blocks. H0 runs Linux, and a runner GitHub
    never gives must never hold a release back — the 0.5.4's macOS was cancelled for want of one.
    The job fails without failing the run (`continue-on-error`), and says its tests' own outcome in
    the run's summary, whatever came before."""
    job = _gate()["jobs"]["macos"]
    assert job["continue-on-error"] is True
    (tests,) = [s for s in job["steps"] if "pytest" in (s.get("run") or "")]
    (said,) = [s for s in job["steps"] if s.get("name") == MACOS_SAID]
    assert tests["id"] == "tests" and said["if"] == "always()"
    assert said["env"] == {"OUTCOME": "${{ steps.tests.outcome }}"}
    assert '>> "$GITHUB_STEP_SUMMARY"' in said["run"] and "ne bloque pas" in said["run"]
    assert job["steps"].index(said) == len(job["steps"]) - 1


def _gate_says(tmp_path, needs: dict) -> tuple[int, str]:
    import json
    import subprocess
    import sys
    import textwrap
    (step,) = _gate()["jobs"]["gate"]["steps"]
    script = step["run"].split("<<'EOF'\n", 1)[1].rsplit("EOF", 1)[0]
    path, summary = tmp_path / "gate.py", tmp_path / "summary.md"
    path.write_text(textwrap.dedent(script), encoding="utf-8")
    env = {"NEEDS": json.dumps(needs), "INFORMATIVE": step["env"]["INFORMATIVE"], "GITHUB_STEP_SUMMARY": str(summary)}
    code = subprocess.run([sys.executable, str(path)], env=env, capture_output=True, text=True).returncode
    return code, summary.read_text(encoding="utf-8") if summary.exists() else ""


@pytest.mark.parametrize("results, green", [
    ({"a": "success", "b": "success"}, True),
    ({"a": "success", "b": "failure"}, False),
    ({"a": "success", "b": "cancelled"}, False),
    ({"a": "skipped", "b": "success"}, False),
    ({"a": "success", "b": None}, False),
    ({}, False),
    # macOS informs: red, cancelled, skipped, never acquired — the gate as the others say.
    ({"a": "success", "macos": "failure"}, True),
    ({"a": "success", "macos": "cancelled"}, True),
    ({"a": "success", "macos": "skipped"}, True),
    ({"a": "cancelled", "macos": "success"}, False),
    ({"macos": "success"}, False),                       # nothing that blocks: never green
])
def test_the_last_job_is_green_only_when_every_job_that_blocks_is(tmp_path, results, green):
    """Run as GitHub runs it: `needs` as JSON. A cancelled or skipped job that blocks is red; each
    job and its role said in the run's summary."""
    needs = {k: {"result": v, "outputs": {}} for k, v in results.items()}
    code, summary = _gate_says(tmp_path, needs)
    assert (code == 0) is green
    assert ("**Porte de release verte**" if green else "**Porte de release rouge**") in summary
    for k, v in results.items():
        role = "informe, ne bloque pas" if k == "macos" else "bloque"
        assert f"| {k} | {v} | {role} |" in summary, summary


def test_release_py_reads_this_workflow_by_its_file_name():
    text = (ROOT / "scripts" / "release.py").read_text(encoding="utf-8")
    assert 'GATE = "release-gate.yml"' in text and f"/actions/workflows/{GATE.name}/runs?" in text


# ── CI5 (#512): a faster CI — macOS off the pull requests, 200 invariants there, cancelled when
# replaced, Components not run for prose ───────────────────────────────────────────────────────
# An expression of GitHub's (`${{ … }}`) evaluated here for one event: the subset the workflows use
# (==, !=, &&, ||, !, parentheses, strings, format(), cancelled()), each name looked up in what
# GitHub would give. && and || return an operand, as Python's `and` / `or` do.

_TOKEN = re.compile(r"'[^']*'|&&|\|\||!=|==|!|\(|\)|,|\d+|[A-Za-z_][\w.\-]*|\s+")


def _expr(text, event: str, *, needs: dict | None = None, number: int = 7, run_id: int = 4242,
          workflow: str = "CI", cancelled: bool = False):
    if not isinstance(text, str):
        return text
    kw = {"needs": needs, "number": number, "run_id": run_id, "workflow": workflow, "cancelled": cancelled}
    whole = re.fullmatch(r"\s*\$\{\{((?:(?!\}\}).)*)\}\}\s*", text, re.S)
    if not whole:   # a plain value, or a template: each ${{ … }} replaced by its value
        return re.sub(r"\$\{\{((?:(?!\}\}).)*)\}\}", lambda x: str(_expr("${{" + x.group(1) + "}}", event, **kw)),
                      text)
    m = whole
    names = {"github.event_name": event, "github.run_id": str(run_id), "github.workflow": workflow,
             "github.event.pull_request.number": number if event in ("pull_request", "pull_request_target") else None,
             "github.ref": "refs/heads/main"}
    names |= {f"needs.{job}.result": result for job, result in (needs or {}).items()}
    out, at, src = [], 0, m.group(1)
    while at < len(src):
        tok = _TOKEN.match(src, at)
        assert tok, f"cannot read {src[at:]!r}"
        t, at = tok.group(0), tok.end()
        if t.isspace():
            continue
        if t in ("&&", "||", "!"):
            out.append({"&&": " and ", "||": " or ", "!": " not "}[t])
        elif t in ("==", "!=", "(", ")", ",") or t.startswith("'") or t.isdigit():
            out.append(t)
        elif t == "cancelled":
            out.append("_cancelled")
        elif t == "format":
            out.append("_format")
        else:
            assert t in names, f"a name this evaluator does not know: {t}"
            out.append(repr(names[t]))
    def _format(fmt, *args):
        return fmt.format(*args)
    return eval("".join(out), {"__builtins__": {}}, {"_cancelled": lambda: cancelled, "_format": _format})


def test_the_expression_reader_reads_as_github_does():
    assert _expr("${{ github.event_name == 'pull_request' && '200' || '500' }}", "pull_request") == "200"
    assert _expr("${{ github.event_name == 'pull_request' && '200' || '500' }}", "push") == "500"
    assert _expr("${{ !cancelled() && needs.a.result == 'failure' }}", "push", needs={"a": "failure"}) is True
    assert _expr("${{ !cancelled() && needs.a.result == 'failure' }}", "push", needs={"a": "failure"},
                 cancelled=True) is False
    assert _expr("${{ format('pr-{0}', github.event.pull_request.number) }}", "pull_request", number=12) == "pr-12"
    assert _expr("plain", "push") == "plain"


CI = ROOT / ".github" / "workflows" / "ci.yml"
MACOS = "tests (macOS, case-insensitive file system)"
EVENTS = ("push", "pull_request", "schedule")


def _runs(job: dict, event: str) -> bool:
    """Whether a job runs on this event, by its `if` (one without runs)."""
    needs = job.get("needs") or []
    needs = [needs] if isinstance(needs, str) else needs
    return "if" not in job or bool(_expr(job["if"], event, needs={n: "success" for n in needs}))


def test_macos_runs_on_a_push_to_main_and_at_night_never_on_a_pull_request():
    doc = _load(CI)
    assert {"push", "pull_request", "schedule"} <= _events(doc)
    assert doc["on"]["push"] == {"branches": ["main"]} and doc["on"]["schedule"]
    macos = doc["jobs"]["test-macos"]
    assert macos["name"] == MACOS
    assert {e: _runs(macos, e) for e in EVENTS} == {"push": True, "pull_request": False, "schedule": True}
    # Its budget stays 500: it never runs on a pull request.
    (step,) = [s for s in macos["steps"] if "test_invariants.py" in (s.get("run") or "")]
    assert step["env"]["GLORFINDEL_INVARIANT_EXAMPLES"] == "500"


def test_the_night_of_ci_yml_is_macos_s_alone():
    """On the schedule the other jobs do not run: the audit would turn red on main's commit for an
    advisory, and H0's CD refuses a release whose commit has a red check-run."""
    doc = _load(CI)
    for name, job in doc["jobs"].items():
        if name in ("test-macos", "macos-red"):
            continue
        assert {e: _runs(job, e) for e in EVENTS} == {"push": True, "pull_request": True, "schedule": False}, name


def test_a_red_macos_on_main_opens_an_issue_or_comments_the_open_one():
    """Red or cancelled: a timeout or a runner never acquired says `cancelled`, nothing cancels a
    run of main, and H0's CD counts it red (CI5, review)."""
    job = _load(CI)["jobs"]["macos-red"]
    assert job["needs"] == "test-macos" and isinstance(job.get("timeout-minutes"), int)
    when = {(e, r): bool(_expr(job["if"], e, needs={"test-macos": r}))
            for e in EVENTS for r in ("failure", "success", "skipped", "cancelled")}
    assert {k for k, v in when.items() if v} == {("push", "failure"), ("schedule", "failure"),
                                                 ("push", "cancelled"), ("schedule", "cancelled")}
    assert _expr(job["if"], "push", needs={"test-macos": "failure"}, cancelled=True) is False


# A fake gh: each call logged on one line; `issue list` answers the issues given, only those of the
# author asked for when --author is passed, as GitHub filters them.
_FAKE_GH_LIST = r'''
author=""; prev=""
for a in "$@"; do [ "$prev" = "--author" ] && author="$a"; prev="$a"; done
AUTHOR="$author" python3 -c 'import json, os, sys; a = os.environ["AUTHOR"]; print(json.dumps([i for i in json.load(open(sys.argv[1])) if not a or i["author"] == a]))' "$ISSUES"
'''


def _fake_gh(bin_: Path, log: Path, issues: list) -> Path:
    import json
    data = bin_.parent / "issues.json"
    data.write_text(json.dumps(issues))
    _fake(bin_ / "gh", f'printf "gh %s\\n" "$(printf "%s" "$*" | tr "\\n" " ")" >> {log}\n'
                       f'if [ "$1 $2" = "issue list" ]; then {_FAKE_GH_LIST}fi\n')
    return data


BOT = "app/github-actions"
TITLE = "CI : les tests macOS sont rouges sur main"


@pytest.mark.parametrize("issues, expected", [
    ([], "create"),
    ([{"number": 3, "title": TITLE + " (autre)", "author": BOT}], "create"),
    ([{"number": 5, "title": TITLE, "author": "someone"}], "create"),          # the same title, not ours
    ([{"number": 5, "title": TITLE, "author": "someone"}, {"number": 9, "title": TITLE, "author": BOT}],
     "comment"),
])
def test_the_issue_script_creates_one_or_comments_the_open_one(tmp_path, issues, expected):
    job = _load(CI)["jobs"]["macos-red"]
    (step,) = job["steps"]
    bin_, log = tmp_path / "bin", tmp_path / "gh.log"
    bin_.mkdir()
    data = _fake_gh(bin_, log, issues)
    env = {k: str(v) for k, v in step["env"].items() if "${{" not in str(v)}
    env |= {"RUN_URL": "https://example.org/run/1", "SHA": "abc123", "EVENT": "push", "RESULT": "cancelled",
            "GH_TOKEN": "t", "GH_REPO": "o/r", "ISSUES": str(data)}
    res = _sh(step["run"], env, tmp_path, bin_)
    assert res.returncode == 0, res
    calls = log.read_text().splitlines()
    assert calls[0].startswith(f"gh issue list --state open --author {BOT} "), calls
    assert len(calls) == 2, calls
    if expected == "create":
        assert calls[1].startswith(f"gh issue create --title {TITLE} --body ")
    else:
        assert calls[1].startswith("gh issue comment 9 --body ")
    assert "abc123" in calls[1] and "https://example.org/run/1" in calls[1] and "(push : cancelled)" in calls[1]
    assert "rouge ou annulé" in calls[1] and "relancer le job" in calls[1]


PR_WORKFLOWS = ("ci.yml", "images.yml", "components.yml", "release-gate.yml")


@pytest.mark.parametrize("workflow", PR_WORKFLOWS)
def test_a_new_push_on_a_pull_request_cancels_the_run_it_replaces_never_on_main(workflow):
    doc = _load(ROOT / ".github" / "workflows" / workflow)
    c = doc["concurrency"]
    pr = [_expr(c["group"], "pull_request", number=12, run_id=n, workflow=doc["name"]) for n in (1, 2)]
    assert pr[0] == pr[1] == f"{doc['name']}-pr-12"                       # one group per pull request
    assert _expr(c["group"], "pull_request", number=13, workflow=doc["name"]) != pr[0]
    assert _expr(c["cancel-in-progress"], "pull_request") is True
    for event in ("push", "schedule", "merge_group"):
        runs = {_expr(c["group"], event, run_id=n, workflow=doc["name"]) for n in (1, 2)}
        assert len(runs) == 2, (event, runs)                             # its own group: never held pending
        assert _expr(c["cancel-in-progress"], event) is False


def test_no_other_workflow_cancels_a_run_in_progress():
    """Publish, Notify, the canary, the night: never cancelled by a newer run."""
    for path in WORKFLOWS:
        doc = _load(path)
        c = doc.get("concurrency") or {}
        if path.name in PR_WORKFLOWS:
            continue
        assert str(c.get("cancel-in-progress", False)).lower() in ("false", "none"), path.name


# The checks the rule of main requires, as docs/sessions.md lists them (Jonathan sets the rule:
# docs/operations.md, « La CI, plus rapide »).
def _required() -> list[str]:
    text = (ROOT / "docs" / "sessions.md").read_text(encoding="utf-8")
    block = text.split("**Require status checks to pass**", 1)[1].split("**Vérifier :**", 1)[0]
    return re.findall(r"^\s+- `([^`]+)`", block, re.M)


def _check_names(doc: dict) -> set[str]:
    """The check-run names of a workflow's jobs, a one-axis matrix expanded."""
    out = set()
    for key, job in doc["jobs"].items():
        name = job.get("name", key)
        axes = ((job.get("strategy") or {}).get("matrix") or {})
        for axis, values in axes.items():
            if f"${{{{ matrix.{axis} }}}}" in name:
                out |= {name.replace(f"${{{{ matrix.{axis} }}}}", str(v)) for v in values}
                break
        else:
            out.add(name)
    return out


def test_the_required_checks_run_on_every_pull_request_and_macos_is_not_one():
    required = _required()
    assert len(required) == 5 and MACOS not in required, required
    on_prs = set()
    for path in WORKFLOWS:
        doc = _load(path)
        if "pull_request" not in _events(doc):
            continue
        pr = doc["on"]["pull_request"] or {}
        names = _check_names(doc)
        # A workflow a path filter skips leaves a required check « expected » for ever.
        if "paths" in pr or "paths-ignore" in pr:
            assert not names & set(required), (path.name, names & set(required))
            continue                        # its jobs never stand for a required check (CI6)
        for key, job in doc["jobs"].items():
            if _runs(job, "pull_request"):
                on_prs |= _check_names({"jobs": {key: job}})
    assert set(required) <= on_prs, set(required) - on_prs


def test_components_skips_prose_alone_on_a_pull_request_and_always_runs_on_main():
    doc = _load(ROOT / ".github" / "workflows" / "components.yml")
    assert doc["on"]["push"] == {"branches": ["main"]}                     # no filter on main
    ignored = doc["on"]["pull_request"]["paths-ignore"]
    assert set(ignored) == {"**/*.md", "docs/**", "changes/**", "LICENSE"}
    assert "paths" not in doc["on"]["pull_request"]
    # Images keeps no filter: its first step decides, its required checks green (CI1).
    assert "paths" not in (_load(ROOT / ".github" / "workflows" / "images.yml")["on"]["pull_request"] or {})


def test_the_gesture_on_the_rule_of_main_is_written():
    ops = (ROOT / "docs" / "operations.md").read_text(encoding="utf-8")
    section = ops.split("## La CI, plus rapide (CI5", 1)[1].split("\n## ", 1)[0]
    assert f"« {MACOS} »" in section and "Require status checks to pass" in section
