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


def test_rules_approved_on_the_vm_ride_along(repo):
    """The containers write glorfindel/rules (approved rules, mounted read-write): kept, said."""
    c3 = repo.commits[2]
    rules = repo.vm / "glorfindel" / "rules" / "azure" / "detection_rules.yaml"
    _git(repo.work, repo.env, "tag", "v0.11.0", c3)
    _git(repo.work, repo.env, "push", "-q", "origin", "v0.11.0")
    rules.write_text("rules: 3\napproved: 1\n")
    res = repo.deploy("--checkout-only", "v0.11.0")
    assert res.returncode == 0, res.stderr
    assert "glorfindel/rules" in res.stderr and rules.read_text().endswith("approved: 1\n")


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

def _make_start(repo, tmp_path, *args):
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
           "FAKE_VM_HOME": str(vm_home), "FAKE_SSH_LOG": str(ssh_log)}
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
    for ref in ("main", "'v1;id'"):
        res, docker_calls, _ = _make_start(repo, tmp_path, f"REF={ref}")
        assert res.returncode != 0 and docker_calls == []
    assert repo.head() == before


def test_the_recipe_no_longer_pulls_a_branch():
    recipe = (ROOT / "Makefile").read_text(encoding="utf-8").split("\nglorfindel-host-start:")[1].split("\n\n")[0]
    assert "git pull" not in recipe and "infra/glorfindel-host/deploy.sh" in recipe
    status = (ROOT / "infra" / "glorfindel-host" / "status.sh").read_text(encoding="utf-8")
    assert "--show" in status and "git log --oneline" not in status
