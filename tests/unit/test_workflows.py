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
    assert env.get("GLORFINDEL_INVARIANT_EXAMPLES") == "500", env


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
    docs = {p.name: _load(p) for p in WORKFLOWS}
    assert all("permissions" in doc for doc in docs.values()), "a workflow without its permissions"
    writers = {name for name, doc in docs.items() if any(_writes_issues(p) for p in _permission_sets(doc))}
    assert writers == {"pip-audit.yml"}


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
    for part in ("github.repository=='Vanyar53/eregion'", "github.ref=='refs/heads/main'",
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
    _fake(bin_ / "az", f'echo "az $*" >> {log}\n')
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
    assert "::add-mask::jwt-from-github" in res.stdout


def test_each_run_of_the_matrix_has_its_own_suffix():
    """The three lines run side by side in one group: the suffix names the run, its attempt (a
    re-run after a killed one) and the line."""
    step = _canary_step(_canary_job(), "jit-terraform/run.sh")
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
case "$1" in
  version) echo '{"provider_selections": {"registry.terraform.io/hashicorp/azurerm": "4.81.0"}}' ;;
  destroy) exit "${FAKE_DESTROY_RC:-0}" ;;
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
    sys.exit(int(os.environ.get("FAKE_GROUP_RC", "0")))
elif a[:3] == ["network", "nsg", "show"]:
    print(f"/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/{name}")
elif a[:3] == ["network", "nic", "update"]:
    (state / name).write_text(opt("--network-security-group"))
elif a[:3] == ["network", "nic", "show"]:
    print((state / name).read_text())
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
    bin_.mkdir()
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
    assert re.findall(r'"subject": "([^"]+)"', section) == ["repo:Vanyar53/eregion:environment:canary"]
    put = section.index('gh api -X PUT "repos/$REPO/environments/canary"')
    assert '"protected_branches": false, "custom_branch_policies": true' in section[put:put + 200]
    assert 'deployment-branch-policies" -f name=main -f type=branch' in section[put:]
    sets = [line for line in section.splitlines() if "gh secret set" in line]
    assert len(sets) == 3 and all("--env canary" in line for line in sets), sets
