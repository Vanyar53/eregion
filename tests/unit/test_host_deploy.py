"""M-3 (#183): the hosted Glorfindel deploys a named reference, never a branch.

`make glorfindel-host-start` ran `git pull --ff-only` on main and rebuilt: H0 ran whatever
had just been merged. It now sends infra/glorfindel-host/deploy.sh over ssh, which checks out
a tag or a commit (by default the latest `v*` tag), detached, and labels the image with it;
`make glorfindel-host-status` reads the label back.

Everything really runs — git, the script, the Makefile recipe — against local repositories
(an `origin` and the VM's clone in a tmp dir) and fake `ssh` / `docker` first on the PATH:
no network, no VM, no Docker.
"""
import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
DEPLOY = ROOT / "infra" / "glorfindel-host" / "deploy.sh"

pytestmark = pytest.mark.skipif(shutil.which("git") is None or shutil.which("bash") is None,
                                reason="git and bash needed")


def _env(tmp_path, **extra):
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_") and k != "REF"}
    env.update({"HOME": str(home), "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid",
                "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid"})
    env.update(extra)
    return env


def _git(cwd, env, *args):
    return subprocess.run(["git", *args], cwd=cwd, env=env, check=True,
                          capture_output=True, text=True).stdout.strip()


class Repo:
    """An `origin` with three commits on main — c1 tagged v0.2.0 and v0.9.0, c2 tagged
    v0.10.0 (after v0.9.0 in version order, before it in text order), c3 untagged — and
    the VM's clone of main, as cloud-init makes it."""

    def __init__(self, tmp_path):
        self.env = _env(tmp_path)
        self.origin, self.work, self.vm = tmp_path / "origin.git", tmp_path / "work", tmp_path / "vm"
        _git(tmp_path, self.env, "init", "-q", "--bare", "-b", "main", str(self.origin))
        _git(tmp_path, self.env, "init", "-q", "-b", "main", str(self.work))
        rules = self.work / "glorfindel" / "rules" / "azure"
        rules.mkdir(parents=True)
        self.commits = []
        for i in (1, 2, 3):
            (self.work / "app.py").write_text(f"VERSION = {i}\n")
            (rules / "detection_rules.yaml").write_text(f"rules: {i}\n")
            _git(self.work, self.env, "add", "-A")
            _git(self.work, self.env, "commit", "-q", "-m", f"c{i}")
            self.commits.append(_git(self.work, self.env, "rev-parse", "HEAD"))
        c1, c2, _ = self.commits
        for tag, commit in (("v0.2.0", c1), ("v0.9.0", c1), ("v0.10.0", c2)):
            _git(self.work, self.env, "tag", tag, commit)
        _git(self.work, self.env, "remote", "add", "origin", str(self.origin))
        _git(self.work, self.env, "push", "-q", "origin", "main", "--tags")
        _git(tmp_path, self.env, "clone", "-q", "--branch", "main", str(self.origin), str(self.vm))

    def head(self):
        return _git(self.vm, self.env, "rev-parse", "HEAD")

    def detached(self):
        return subprocess.run(["git", "symbolic-ref", "-q", "HEAD"], cwd=self.vm, env=self.env,
                              capture_output=True).returncode != 0

    def deploy(self, *args, env=None):
        return subprocess.run(["bash", str(DEPLOY), *args], cwd=self.vm, env=env or self.env,
                              capture_output=True, text=True, timeout=60)


@pytest.fixture
def repo(tmp_path):
    return Repo(tmp_path)


def test_without_a_reference_the_latest_v_tag_is_checked_out_detached(repo):
    c1, c2, c3 = repo.commits
    assert repo.head() == c3                                   # the clone sits on main
    res = repo.deploy("--checkout-only")
    assert res.returncode == 0, res.stderr
    assert res.stdout.strip().splitlines()[-1] == f"v0.10.0 {c2}"   # v0.10.0 > v0.9.0
    assert repo.head() == c2 and repo.detached()


def test_a_tag_pushed_after_the_clone_is_fetched(repo):
    c3 = repo.commits[2]
    _git(repo.work, repo.env, "tag", "v0.11.0", c3)
    _git(repo.work, repo.env, "push", "-q", "origin", "v0.11.0")
    res = repo.deploy("--checkout-only")
    assert res.returncode == 0, res.stderr
    assert repo.head() == c3 and res.stdout.split()[-2:] == ["v0.11.0", c3]


@pytest.mark.parametrize("which", ["tag", "full", "short"])
def test_a_named_tag_or_commit_is_deployed(repo, which):
    c1, _, c3 = repo.commits
    ref, want = {"tag": ("v0.2.0", c1), "full": (c3, c3), "short": (c3[:9], c3)}[which]
    res = repo.deploy("--checkout-only", ref)
    assert res.returncode == 0, res.stderr
    assert repo.head() == want and repo.detached()
    assert res.stdout.split()[-2:] == [ref, want]


@pytest.mark.parametrize("ref, said", [
    ("main", "branche"),                    # a branch moves
    ("origin/main", "invalide"),
    ("HEAD", "branche"),                    # origin/HEAD: the branch it points to
    ("HEAD~1", "invalide"),
    ("v9.9.9", "ni un tag ni un commit"),
    ("deadbee", "ni un tag ni un commit"),  # hexadecimal, but no such commit
    ("v0.10.0;touch pwned", "invalide"),
    ("--detach", "invalide"),
])
def test_anything_but_a_tag_or_a_commit_is_refused_and_nothing_moves(repo, ref, said):
    before = repo.head()
    res = repo.deploy("--checkout-only", ref)
    assert res.returncode != 0
    assert said in res.stderr
    assert repo.head() == before and not repo.detached()
    assert not (repo.vm / "pwned").exists()


def test_a_branch_named_like_a_commit_is_still_a_branch(repo):
    """`deadbee` as a branch on origin: hexadecimal, so it could pass for a short commit id;
    the commit it points to does not start with it — refused, named a branch."""
    c1 = repo.commits[0]
    _git(repo.work, repo.env, "push", "-q", "origin", f"{c1}:refs/heads/deadbee")
    res = repo.deploy("--checkout-only", "deadbee")
    assert res.returncode != 0 and "branche" in res.stderr


def test_a_tracked_file_changed_on_the_vm_stops_the_deployment(repo):
    before = repo.head()
    (repo.vm / "app.py").write_text("VERSION = 'patched on the VM'\n")
    res = repo.deploy("--checkout-only", "v0.2.0")
    assert res.returncode != 0 and "app.py" in res.stderr
    assert repo.head() == before


@pytest.mark.parametrize("ref", ["v0.11.0", "v0.2.0"])
def test_rules_approved_on_the_vm_before_p1_stop_it_with_what_to_do(repo, tmp_path, ref):
    """P1: the containers no longer write glorfindel/rules (mounted read-only; approved
    rules live in ~/.glorfindel/client_rules.yaml). A rules file modified on the VM holds
    rules approved before P1: whether the reference leaves the file as it is (v0.11.0, c3)
    or changes it (v0.2.0, c1), it would ride into the image or make git refuse — the script
    stops first, names the file, says where the migration is and what never to do."""
    c3 = repo.commits[2]
    _git(repo.work, repo.env, "tag", "v0.11.0", c3)
    _git(repo.work, repo.env, "push", "-q", "origin", "v0.11.0")
    rules = repo.vm / "glorfindel" / "rules" / "azure" / "detection_rules.yaml"
    rules.write_text("rules: 3\napproved: 1\n")
    before = repo.head()
    bin_dir, log, fake = _fake_bin(tmp_path)
    env = {**repo.env, **fake, "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}"}
    res = repo.deploy(ref, env=env)
    assert res.returncode != 0
    assert "glorfindel/rules/azure/detection_rules.yaml" in res.stderr
    assert "avant P1" in res.stderr and "rien n'est déployé" in res.stderr
    assert "Migrer les règles approuvées vers la couche du client" in res.stderr
    assert "Jamais git checkout -- glorfindel/rules" in res.stderr
    assert "gardé" not in res.stderr and "error:" not in res.stderr       # not git's words
    assert repo.head() == before and not repo.detached() and log.read_text() == ""
    assert rules.read_text() == "rules: 3\napproved: 1\n"               # nothing lost
    readme = (ROOT / "infra" / "glorfindel-host" / "README.md").read_text(encoding="utf-8")
    assert "### Migrer les règles approuvées vers la couche du client" in readme


def _fake_bin(tmp_path, ref="", rev=""):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    log = tmp_path / "docker.log"
    log.write_text("")
    docker = bin_dir / "docker"
    docker.write_text('#!/bin/bash\necho "$*" >> "$FAKE_DOCKER_LOG"\n'
                      'case "$1" in inspect) case "$3" in *version*) echo "$FAKE_REF";; '
                      '*revision*) echo "$FAKE_REV";; esac;; esac\n')
    docker.chmod(0o755)
    return bin_dir, log, {"FAKE_DOCKER_LOG": str(log), "FAKE_REF": ref, "FAKE_REV": rev}


def test_the_image_carries_the_reference_it_was_built_from(repo, tmp_path):
    c2 = repo.commits[1]
    bin_dir, log, fake = _fake_bin(tmp_path)
    env = {**repo.env, **fake, "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}"}
    res = repo.deploy(env=env)
    assert res.returncode == 0, res.stderr
    calls = log.read_text().splitlines()
    build = next(c for c in calls if c.startswith("build "))
    assert "--label org.opencontainers.image.version=v0.10.0" in build
    assert f"--label org.opencontainers.image.revision={c2}" in build
    assert "-f glorfindel/Dockerfile -t eregion-glorfindel ." in build
    assert any(c.startswith("compose --profile bot up -d watch war-room bot") for c in calls)
    assert calls.index(build) < next(i for i, c in enumerate(calls) if c.startswith("compose"))
    assert f"déployé : v0.10.0 ({c2[:12]})" in res.stdout


def _migration_steps():
    """The README's procedure, « Migrer les règles approuvées vers la couche du client »:
    its bash blocks, line by line, as written."""
    import re
    import textwrap
    readme = (ROOT / "infra" / "glorfindel-host" / "README.md").read_text(encoding="utf-8")
    section = readme.split("### Migrer les règles approuvées vers la couche du client\n")[1]
    section = re.split(r"\n#{2,3} ", section)[0]
    blocks = re.findall(r"```bash\n(.*?)```", section, re.S)
    return [line for b in blocks for line in textwrap.dedent(b).splitlines() if line.strip()]


def test_the_migration_procedure_of_the_readme_runs_as_written(repo, tmp_path, monkeypatch):
    """P1, H0: a VM on a reference from before P1, a rule approved into the tracked base,
    the deployment refused. The README's steps, run as written — the VM's shell lines in
    bash, `glorfindel …` as `docker exec eregion-watch` would run it, with ~/.glorfindel
    mounted at /root/.glorfindel — leave a clean checkout that deploys, the approved rule
    in the client's layer and loaded as the client's, the base the reference's."""
    import yaml
    from click.testing import CliRunner

    import glorfindel.detection_rules as dr
    from glorfindel.cli import cli
    from glorfindel.detection_rules import load_config

    base_v1 = ("rules:\n  - name: ssh-brute-force\n    ttp: T1110.001\n    assets: [auto]\n"
               "    query: |\n      Syslog | where SyslogMessage has \"Failed password\"\n")
    rel = "glorfindel/rules/azure/detection_rules.yaml"
    for tag, text in (("v0.12.0", base_v1), ("v0.13.0", base_v1.replace("Failed password", "Invalid user"))):
        (repo.work / rel).write_text(text)
        _git(repo.work, repo.env, "commit", "-qam", tag)
        _git(repo.work, repo.env, "tag", tag)
    _git(repo.work, repo.env, "push", "-q", "origin", "main", "--tags")
    assert repo.deploy("--checkout-only", "v0.12.0").returncode == 0   # H0 before P1
    with open(repo.vm / rel, "a") as f:                                 # what the old approve did
        f.write("\n  - name: log-clearing\n    description: >\n      Auto-proposed by Glorfindel.\n"
                "    enabled: true\n    source: azure_monitor\n    workspace_id: \"ws-example\"\n"
                "    ttp: T1070.002\n    resource_id: \"/subscriptions/s/rg/vm-example\"\n"
                "    interval_s: 30\n    query: |\n      Syslog | where SyslogMessage has \"rm -f\"\n")
    refused = repo.deploy("--checkout-only", "v0.13.0")
    assert refused.returncode != 0 and "Migrer les règles approuvées" in refused.stderr

    home = Path(repo.env["HOME"])
    monkeypatch.setattr(dr, "_CLIENT_RULES_FILE", home / ".glorfindel" / "client_rules.yaml")
    # H0's glorfindel-config.yaml: the backend that watches the approved rule's workspace.
    import glorfindel.config as config
    monkeypatch.setattr(config, "load_glorfindel_config", lambda *a, **k: config.GlorfindelConfig(
        monitoring_backends=[config.MonitoringBackendConfig(
            name="law-main", type="azure_monitor", workspace_id="ws-example")]))
    monkeypatch.chdir(repo.vm)                    # the container's cwd holds glorfindel/rules
    steps, outputs, shell = _migration_steps(), [], []

    def flush():
        if shell:
            res = subprocess.run(["bash", "-euc", "\n".join(shell)], cwd=repo.vm, env=repo.env,
                                 capture_output=True, text=True, timeout=60)
            assert res.returncode == 0, res.stderr
            shell.clear()

    for line in steps:
        if line.startswith("docker exec eregion-watch glorfindel "):
            flush()
            args = line.split("glorfindel ", 1)[1].replace("/root/", f"{home}/").split()
            res = CliRunner().invoke(cli, args, catch_exceptions=False)
            assert res.exit_code == 0, res.output
            outputs.append(res.output)
        elif line.startswith("docker compose"):
            flush()                                   # restarting the watch: nothing to run here
        else:
            shell.append(line)
            if line.startswith("git stash push"):
                flush()
                deployed = repo.deploy("--checkout-only", "v0.13.0")   # step 2, from the poste
                assert deployed.returncode == 0, deployed.stderr
    flush()

    assert any("log-clearing: added" in o for o in outputs)              # dry run, then for good
    assert any("bound" in o and "law-main" in o for o in outputs), outputs   # inert before, bound now
    assert _git(repo.vm, repo.env, "status", "--porcelain", "--untracked-files=no") == ""
    assert _git(repo.vm, repo.env, "stash", "list") == ""                 # step 4: dropped
    layer = yaml.safe_load((home / ".glorfindel" / "client_rules.yaml").read_text())
    assert [r["name"] for r in layer["rules"]] == ["log-clearing"] and "disable" not in layer
    assert layer["rules"][0]["assets"] == ["auto"] and layer["rules"][0]["monitoring_backends"] == ["law-main"]
    rules = {r.name: r for r in load_config(repo.vm / rel, glorfindel_cfg=config.load_glorfindel_config()).rules}
    assert rules["log-clearing"].layer == "client"
    assert rules["log-clearing"].auto_apply and rules["log-clearing"].monitoring_backend_name == "law-main"
    assert "Invalid user" in rules["ssh-brute-force"].query                # the reference's base
    assert (home / ".glorfindel" / "migration-p1" / "approved.yaml").exists()


def test_a_refused_reference_builds_nothing(repo, tmp_path):
    bin_dir, log, fake = _fake_bin(tmp_path)
    env = {**repo.env, **fake, "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}"}
    res = repo.deploy("main", env=env)
    assert res.returncode != 0 and log.read_text() == ""


@pytest.mark.parametrize("case", ["same", "moved", "unlabelled", "branch"])
def test_show_says_what_runs(repo, tmp_path, case):
    c1, c2, c3 = repo.commits
    repo.deploy("--checkout-only", "v0.10.0")
    ref, rev = ("", "<no value>") if case == "unlabelled" else ("v0.10.0", c2)
    if case == "moved":
        _git(repo.vm, repo.env, "checkout", "-q", "--detach", c1)
    if case == "branch":
        _git(repo.vm, repo.env, "checkout", "-q", "main")
        rev = c3
    bin_dir, _, fake = _fake_bin(tmp_path, ref=ref or "<no value>", rev=rev)
    env = {**repo.env, **fake, "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}"}
    out = repo.deploy("--show", env=env).stdout.strip()
    expected = {
        "same": f"✓ référence déployée : v0.10.0 ({c2[:12]})",
        "moved": "⚠ référence déployée : v0.10.0",
        "unlabelled": "⚠ référence déployée : inconnue",
        "branch": "⚠ référence déployée : v0.10.0",
    }[case]
    assert out.startswith(expected), out
    if case == "moved":
        assert "ailleurs" in out
    if case == "branch":
        assert "branche" in out


# ── the Makefile recipe, through a fake ssh that runs the remote command in the fake VM ──

def _make_start(repo, tmp_path, *args, environ=None):
    vm_home = repo.vm.parent / "vmhome"
    vm_home.mkdir(exist_ok=True)
    (vm_home / ".eregion-host-ready").touch()
    if not (vm_home / "eregion").exists():
        (vm_home / "eregion").symlink_to(repo.vm)
    bin_dir, log, fake = _fake_bin(tmp_path)
    ssh = bin_dir / "ssh"
    ssh.write_text('#!/bin/bash\necho "$*" >> "$FAKE_SSH_LOG"\ncd "$FAKE_VM_HOME" && exec bash -c "${@: -1}"\n')
    ssh.chmod(0o755)
    ssh_log = tmp_path / "ssh.log"
    ssh_log.write_text("")
    env = {**repo.env, **fake, "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
           "FAKE_VM_HOME": str(vm_home), "FAKE_SSH_LOG": str(ssh_log), **(environ or {})}
    res = subprocess.run(["make", "-s", "--no-print-directory", "-C", str(ROOT), "glorfindel-host-start",
                          "HOST_IP=203.0.113.9", *args], env=env, capture_output=True, text=True, timeout=120)
    return res, log.read_text().splitlines(), ssh_log.read_text()


@pytest.mark.skipif(shutil.which("make") is None, reason="make not installed")
def test_make_glorfindel_host_start_deploys_the_reference_it_is_given(repo, tmp_path):
    c1 = repo.commits[0]
    res, docker_calls, ssh_calls = _make_start(repo, tmp_path, "REF=v0.2.0")
    assert res.returncode == 0, res.stdout + res.stderr
    assert repo.head() == c1 and repo.detached()
    assert "git pull" not in ssh_calls
    assert any(f"revision={c1}" in c for c in docker_calls)


@pytest.mark.skipif(shutil.which("make") is None, reason="make not installed")
def test_make_glorfindel_host_start_refuses_a_branch_or_a_shell_word(repo, tmp_path):
    before = repo.head()
    pwned = tmp_path / "pwned"
    for ref in ("main", "'v1;id'", f"$$(touch {pwned})", f"$(shell touch {pwned})", "v1$(id)"):
        res, docker_calls, _ = _make_start(repo, tmp_path, f"REF={ref}")
        assert res.returncode != 0 and docker_calls == [], ref
    assert repo.head() == before
    assert not pwned.exists()           # the refused word was never run, by make nor the shell


@pytest.mark.skipif(shutil.which("make") is None, reason="make not installed")
@pytest.mark.parametrize("ref", ["--checkout-only", "--show", "-x", "--checkout-only=v0.2.0"])
def test_make_glorfindel_host_start_refuses_a_reference_that_reads_as_an_option(repo, tmp_path, ref):
    """`REF=--checkout-only` checked out without building, and make then printed its
    messages as if the deployment had happened; `REF=--show` only showed (review of M-3)."""
    before = repo.head()
    res, docker_calls, ssh_calls = _make_start(repo, tmp_path, f"REF={ref}")
    assert res.returncode != 0 and "REF invalide" in res.stderr
    assert ssh_calls == "" and docker_calls == []
    assert repo.head() == before and not repo.detached()
    assert "Arrête le Glorfindel local" not in res.stdout


@pytest.mark.skipif(shutil.which("make") is None, reason="make not installed")
def test_make_glorfindel_host_start_never_deploys_a_ref_from_the_environment(repo, tmp_path):
    """REF is a generic name: one exported for something else must not be deployed in
    silence. Given on the command line, it wins over the environment's."""
    c1, c2 = repo.commits[:2]
    res, docker_calls, ssh_calls = _make_start(repo, tmp_path, environ={"REF": "v0.2.0"})
    assert res.returncode != 0 and "environnement" in res.stderr and "v0.2.0" in res.stderr
    assert ssh_calls == "" and docker_calls == [] and not repo.detached()
    # `make glorfindel-host-start REF=` : the latest v* tag, whatever the environment says.
    res, docker_calls, _ = _make_start(repo, tmp_path, "REF=", environ={"REF": "v0.2.0"})
    assert res.returncode == 0, res.stdout + res.stderr
    assert repo.head() == c2 and any(f"revision={c2}" in c for c in docker_calls)
    res, docker_calls, _ = _make_start(repo, tmp_path, "REF=v0.2.0", environ={"REF": "main"})
    assert res.returncode == 0, res.stdout + res.stderr
    assert repo.head() == c1


def test_the_recipe_no_longer_pulls_a_branch():
    recipe = (ROOT / "Makefile").read_text(encoding="utf-8").split("\nglorfindel-host-start:\n")[1].split("\n\n")[0]
    assert "git pull" not in recipe and "infra/glorfindel-host/deploy.sh" in recipe
    status = (ROOT / "infra" / "glorfindel-host" / "status.sh").read_text(encoding="utf-8")
    assert "--show" in status and "git log --oneline" not in status
