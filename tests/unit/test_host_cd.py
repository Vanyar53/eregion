"""H1 (#244) — the CD of H0: the release Jonathan publishes reaches H0 on its own.

The agent (infra/glorfindel-host/cd/eregion_cd.py) runs as on H0, installed in its own
~/.eregion-cd/ with deploy.sh and notify_discord.py, against:
- real git: an `origin` and the VM's clone in a tmp dir, deployed on v0.3.1;
- a fake `docker` first on the PATH, keeping its images and containers in a file — it builds,
  tags, runs the preflight's commands, starts the services and writes the watch's heartbeat;
- the fake server (tests/unit/fake_discord.py): GitHub's latest release and check runs,
  H0's console, and #deploy's webhook.
No network, no VM, no Docker.
"""
import fcntl
import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from .fake_discord import FakeDiscord

ROOT = Path(__file__).resolve().parents[2]
AGENT = ROOT / "infra" / "glorfindel-host" / "cd" / "eregion_cd.py"
MODEL = "anthropic/claude-sonnet-5-5"
SECRET = "DEPLOY-SECRET-xyz"

pytestmark = pytest.mark.skipif(shutil.which("git") is None or shutil.which("bash") is None,
                                reason="git and bash needed")

FAKE_DOCKER = r'''#!PYTHON
"""A fake docker: images and containers in $FAKE_DOCKER_STATE, every call in $FAKE_DOCKER_LOG."""
import json, os, sys
from pathlib import Path
state_p = Path(os.environ["FAKE_DOCKER_STATE"])
st = json.loads(state_p.read_text())
args = sys.argv[1:]
with open(os.environ["FAKE_DOCKER_LOG"], "a") as f:
    f.write(" ".join(args) + "\n")
def save():
    state_p.write_text(json.dumps(st))
cmd = args[0]
if cmd == "build":
    if os.environ.get("FAKE_BUILD_FAIL"):
        sys.exit("build failed")
    labels = dict(args[i + 1].split("=", 1) for i, a in enumerate(args) if a == "--label")
    for t in [args[i + 1] for i, a in enumerate(args) if a == "-t"]:
        st["images"][t] = {"version": labels["org.opencontainers.image.version"],
                           "revision": labels["org.opencontainers.image.revision"], "n": len(st["images"])}
    save()
elif cmd == "tag":
    st["images"][args[2]] = dict(st["images"][args[1]])
    save()
elif cmd == "image":
    if args[1] == "inspect" and args[2] == "-f":
        if args[4] not in st["images"]:
            sys.exit(1)
        print(st["images"][args[4]]["revision" if "revision" in args[3] else "version"])
    elif args[1] == "inspect":
        sys.exit(0 if args[2] in st["images"] else 1)
    if args[1] == "ls":
        for t, i in st["images"].items():
            if ":" in t:
                print("2026-10-28 10:%02d:00 +0000 UTC\t%s" % (i.get("n", 0), t.split(":")[1]))
    if args[1] == "rm":
        st["images"].pop(args[2], None)
        save()
elif cmd == "inspect":
    fmt, name = args[2], args[3]
    c = st["containers"].get(name)
    if not c:
        sys.exit(1)
    if "State.Status" in fmt:
        print(c["status"], c["restarts"], c["version"])
    elif "revision" in fmt and "version" in fmt:
        print(c["version"], c["revision"])
    elif "version" in fmt:
        print(c["version"])
    else:
        print(c["revision"])
elif cmd == "run":
    img = next(a for a in args if a.startswith("eregion-glorfindel:"))
    rest = " ".join(args[args.index(img) + 1:])
    if "--version" in rest:
        print("glorfindel, version", os.environ.get("FAKE_PKG_VERSION") or st["images"][img]["version"].lstrip("v"))
    elif "load_glorfindel_config" in rest and os.environ.get("FAKE_CONFIG_FAIL"):
        sys.exit("glorfindel-config.yaml refusé — clé inconnue : quarantaine_nsg")
elif cmd == "exec":
    # H2: `glorfindel rules check --live --json` in the watch's container, said as FAKE_RULES_OUT says.
    import time
    st.setdefault("execs", []).append({"container": args[1], "on": st["containers"][args[1]]["version"],
                                       "args": args[2:]})
    save()
    # What runs before the switch (v0.3.1) says FAKE_BASE_*; the candidate, FAKE_RULES_*.
    pre = "FAKE_BASE_" if st["containers"][args[1]]["version"] == "v0.3.1" else "FAKE_RULES_"
    time.sleep(float(os.environ.get(pre + "SLEEP") or 0))
    out = os.environ.get(pre + "OUT")
    if out is None:
        out = json.dumps({"schema": "eregion.rules-check/1", "live": True, "error": "",
                          "rules": [{"name": "ssh-brute-force", "status": "ok", "rows": 0, "kind": "", "error": ""}]})
    sys.stderr.write(os.environ.get(pre + "ERR", ""))
    print(out)
    sys.exit(int(os.environ.get(pre + "RC") or 0))
elif cmd == "logs":
    # V-34: what each container's journal says since the switch — FAKE_BASE_LOGS for what ran
    # (v0.3.1), FAKE_RULES_LOGS for the candidate.
    c = st["containers"].get(args[-1])
    if not c:
        sys.exit(1)
    pre = "FAKE_BASE_" if c["version"] == "v0.3.1" else "FAKE_RULES_"
    sys.stderr.write(os.environ.get(pre + "LOGS", ""))
    sys.exit(int(os.environ.get(pre + "LOGS_RC") or 0))
elif cmd == "compose":
    if "config" in args:
        sys.exit(1 if os.environ.get("FAKE_COMPOSE_FAIL") else 0)
    if "up" in args:
        img = st["images"]["eregion-glorfindel"]
        sick = img["version"] == os.environ.get("FAKE_SICK", "-")
        for name in ("eregion-watch", "eregion-war-room", "eregion-bot"):
            st["containers"][name] = {"status": "restarting" if sick else "running", "restarts": 3 if sick else 0,
                                      "version": img["version"], "revision": img["revision"]}
        save()
        if not sick and not os.environ.get("FAKE_NO_HEARTBEAT"):
            hb = Path(os.environ["FAKE_HEARTBEAT"])
            hb.parent.mkdir(parents=True, exist_ok=True)
            hb.write_text("now")
'''


def _git(cwd, env, *args):
    return subprocess.run(["git", *args], cwd=cwd, env=env, check=True, capture_output=True, text=True).stdout.strip()


class H0:
    """origin + a clone deployed on v0.3.1 (c1); v0.4.0 (c2) published on main; v0.9.9 off main."""

    def __init__(self, tmp_path, fake, *, c2_files=None):
        self.tmp, self.fake = tmp_path, fake
        self.home = tmp_path / "home"
        self.home.mkdir()
        self.env = {k: v for k, v in os.environ.items() if not k.startswith(("GIT_", "EREGION_", "FAKE_"))}
        self.env.update({"HOME": str(self.home), "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1",
                         "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid",
                         "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid"})
        origin, work, self.vm = tmp_path / "origin.git", tmp_path / "work", self.home / "eregion"
        _git(tmp_path, self.env, "init", "-q", "--bare", "-b", "main", str(origin))
        _git(tmp_path, self.env, "init", "-q", "-b", "main", str(work))
        files = {"requirements/glorfindel.txt": "litellm==1.86.1\n",
                 "eregion_core/models.py": f'DEFAULT_LLM_MODEL = "{MODEL}"\n',
                 "docker-compose.yml": "services: {}\n", "glorfindel/Dockerfile": "FROM scratch\n", "app.py": "V = 1\n"}
        self.commits = {}
        for name, change in (("c1", {}), ("c2", {"app.py": "V = 2\n", **(c2_files or {})})):
            for rel, text in {**files, **change}.items():
                (work / rel).parent.mkdir(parents=True, exist_ok=True)
                (work / rel).write_text(text)
            _git(work, self.env, "add", "-A")
            _git(work, self.env, "commit", "-q", "-m", name)
            self.commits[name] = _git(work, self.env, "rev-parse", "HEAD")
            files.update(change)
        _git(work, self.env, "tag", "v0.3.1", self.commits["c1"])
        _git(work, self.env, "tag", "v0.4.0", self.commits["c2"])
        _git(work, self.env, "checkout", "-q", "-b", "side")
        (work / "app.py").write_text("V = 'side'\n")
        _git(work, self.env, "commit", "-qam", "side")
        self.commits["side"] = _git(work, self.env, "rev-parse", "HEAD")
        _git(work, self.env, "tag", "v0.9.9")
        _git(work, self.env, "remote", "add", "origin", str(origin))
        _git(work, self.env, "push", "-q", "origin", "main", "--tags")
        _git(tmp_path, self.env, "clone", "-q", str(origin), str(self.vm))
        _git(self.vm, self.env, "-c", "advice.detachedHead=false", "checkout", "-q", "--detach", self.commits["c1"])
        (self.vm / ".env").write_text("EREGION_CONSOLE_TOKEN=tok\n")
        (self.vm / "glorfindel-config.yaml").write_text("autonomy: {}\n")
        # The agent, installed as make glorfindel-host-cd-install does.
        self.cd = self.home / ".eregion-cd"
        self.cd.mkdir()
        for src in (AGENT, ROOT / "infra" / "glorfindel-host" / "deploy.sh", ROOT / "scripts" / "notify_discord.py",
                    ROOT / "glorfindel" / "chat_text.py"):
            shutil.copy(src, self.cd / src.name)
        (self.cd / "discord.env").write_text(
            f"EREGION_DISCORD_WEBHOOK_DEPLOY={fake.base}/api/webhooks/9/{SECRET}\nEREGION_DISCORD_MENTION=42\n")
        (self.cd / "installed-from").write_text(self.commits["c1"] + "\n")   # installed while v0.3.1 ran
        # docker: v0.3.1 runs.
        bin_dir = tmp_path / "bin"
        bin_dir.mkdir()
        (bin_dir / "docker").write_text(FAKE_DOCKER.replace("#!PYTHON", f"#!{sys.executable}"))
        (bin_dir / "docker").chmod(0o755)
        self.state, self.log = tmp_path / "docker.json", tmp_path / "docker.log"
        c1 = self.commits["c1"]
        running = {"status": "running", "restarts": 0, "version": "v0.3.1", "revision": c1}
        self.state.write_text(json.dumps({
            "images": {"eregion-glorfindel:v0.3.1": {"version": "v0.3.1", "revision": c1, "n": 0},
                       "eregion-glorfindel": {"version": "v0.3.1", "revision": c1, "n": 0}},
            "containers": {n: dict(running) for n in ("eregion-watch", "eregion-war-room", "eregion-bot")}}))
        self.log.write_text("")
        self.heartbeat = self.home / ".glorfindel" / "watch_heartbeat"
        self.env.update({
            "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
            "FAKE_DOCKER_STATE": str(self.state), "FAKE_DOCKER_LOG": str(self.log), "FAKE_HEARTBEAT": str(self.heartbeat),
            "EREGION_CD_HOME": str(self.cd), "EREGION_CD_REPO": str(self.vm), "EREGION_CD_GITHUB_REPO": "o/r",
            "EREGION_CD_GITHUB_API": f"{fake.base}/gh", "EREGION_CD_CONSOLE": f"{fake.base}/console",
            "EREGION_CD_HEARTBEAT": str(self.heartbeat), "EREGION_CD_HEALTH_S": "0.2", "EREGION_CD_STEP_S": "0.05",
            "EREGION_DISCORD_ENV": os.devnull})
        fake.console_token = "tok"
        self.publish("v0.4.0")

    def publish(self, tag):
        self.fake.gh["release"] = {"tag_name": tag, "html_url": f"https://example.invalid/releases/{tag}"}

    def run(self, mode="run", **env):
        return subprocess.run([sys.executable, str(self.cd / "eregion_cd.py"), mode], cwd=self.home,
                              env={**self.env, **env}, capture_output=True, text=True, timeout=120)

    def docker(self):
        return json.loads(self.state.read_text())

    def calls(self):
        return self.log.read_text().splitlines()

    def running(self):
        return {c["version"] for c in self.docker()["containers"].values()}

    def head(self):
        return _git(self.vm, self.env, "rev-parse", "HEAD")

    def posts(self):
        return [r["body"] for r in self.fake.requests if r["method"] == "POST" and SECRET in r["path"]]

    def outcome(self, tag):
        try:
            return json.loads((self.cd / "state.json").read_text())["outcomes"].get(tag, {}).get("result")
        except FileNotFoundError:
            return None


@pytest.fixture
def fake():
    f = FakeDiscord()
    yield f
    f.close()


@pytest.fixture
def h0(tmp_path, fake):
    return H0(tmp_path, fake)


def _titles(h0):
    return [p["embeds"][0]["title"] for p in h0.posts()]


def _alerts(h0):
    return [p for p in h0.posts() if p.get("content") == "<@42>"]


# ── the published release reaches H0 ──────────────────────────────────────────────

def test_a_published_release_is_verified_built_aside_switched_and_said(h0):
    res = h0.run()
    assert res.returncode == 0, res.stdout + res.stderr
    c2 = h0.commits["c2"]
    assert h0.running() == {"v0.4.0"} and h0.head() == c2
    calls = h0.calls()
    build = next(i for i, c in enumerate(calls) if c.startswith("build "))
    assert calls[build].endswith("-t eregion-glorfindel:v0.4.0 .")      # the candidate only
    preflight = [i for i, c in enumerate(calls) if c.startswith(("run --rm", "compose -f"))]
    switch = calls.index("tag eregion-glorfindel:v0.4.0 eregion-glorfindel")
    assert build < min(preflight) and max(preflight) < switch
    assert any("load_glorfindel_config" in c and "glorfindel-config.yaml:/app/glorfindel-config.yaml:ro" in c
               for c in calls)                                         # H0's config, under A3
    assert [t.split(" ")[0] for t in _titles(h0)] == ["🚀", "✅"] and not _alerts(h0)
    assert h0.outcome("v0.4.0") == "deployed"


def test_what_runs_already_does_nothing(h0):
    h0.publish("v0.3.1")
    assert h0.run().returncode == 0
    assert h0.calls() and all(c.startswith("inspect -f ") for c in h0.calls())   # the three containers read
    assert h0.posts() == []


def test_an_older_release_is_never_deployed(h0):
    """What runs is ahead of the latest release (deployed by hand from a later commit)."""
    assert h0.run().returncode == 0
    h0.fake.requests.clear()
    h0.publish("v0.3.1")
    res = h0.run()
    assert res.returncode == 0 and "plus ancienne" in res.stdout
    assert h0.running() == {"v0.4.0"} and h0.posts() == []


# ── verified first ─────────────────────────────────────────────────────────────────

def test_a_tag_off_main_is_refused_said_and_not_tried_again(h0):
    h0.publish("v0.9.9")
    assert h0.run().returncode == 1
    assert not any(c.startswith("build") for c in h0.calls())
    (alert,) = _alerts(h0)
    assert "pas sur main" in alert["embeds"][0]["description"] and "flags" not in alert
    assert h0.outcome("v0.9.9") == "refused"
    h0.log.write_text("")
    assert h0.run().returncode == 0 and len(h0.posts()) == 1 and not any(c.startswith("build") for c in h0.calls())


def test_a_red_ci_is_refused(h0):
    h0.fake.gh["checks"][h0.commits["c2"]] = [
        {"name": "lint + tests (py3.12)", "status": "completed", "conclusion": "success"},
        {"name": "tests (macOS)", "status": "completed", "conclusion": "failure"}]
    assert h0.run().returncode == 1
    assert h0.running() == {"v0.3.1"} and "CI rouge" in _alerts(h0)[0]["embeds"][0]["description"]
    assert "tests (macOS)" in _alerts(h0)[0]["embeds"][0]["description"]


def test_a_ci_still_running_waits_said_once_then_deploys(h0):
    c2 = h0.commits["c2"]
    h0.fake.gh["checks"][c2] = [{"name": "lint + tests (py3.12)", "status": "in_progress", "conclusion": None}]
    assert h0.run().returncode == 0 and h0.run().returncode == 0
    assert h0.running() == {"v0.3.1"} and [t.split(" ")[0] for t in _titles(h0)] == ["⏳"]
    assert h0.outcome("v0.4.0") is None
    h0.fake.gh["checks"][c2] = [{"name": "lint + tests (py3.12)", "status": "completed", "conclusion": "success"}]
    assert h0.run().returncode == 0 and h0.running() == {"v0.4.0"}


# ── a new lock needs the harness ───────────────────────────────────────────────────

NEW_LOCK = "litellm==1.90.0\n"


def _attestation(**over):
    att = {"lock": "requirements/glorfindel.txt", "lock_sha256": hashlib.sha256(NEW_LOCK.encode()).hexdigest(),
           "date": "2026-10-28", "runs": 3, "draws": "3",
           "models": [{"model": MODEL, "integration": 24, "judgment": 24, "slots": 24, "overconfident_errors": 0}]}
    for k, v in over.items():
        if k in att:
            att[k] = v
        else:
            att["models"][0][k] = v
    return json.dumps(att)


@pytest.mark.parametrize("attestation, said", [
    (None, "sans attestation"),
    (_attestation(lock_sha256="0" * 64), "un autre verrou"),
    (_attestation(model="ollama/qwen3"), "ne couvre pas le modèle de H0"),
    (_attestation(overconfident_errors=1), "surconfiante"),
    (_attestation(judgment=21), "pas complet"),
    (_attestation(runs=1), "il en faut 3"),
])
def test_a_new_lock_without_a_matching_attestation_is_refused(tmp_path, fake, attestation, said):
    files = {"requirements/glorfindel.txt": NEW_LOCK}
    if attestation:
        files["requirements/harness.json"] = attestation
    h0 = H0(tmp_path, fake, c2_files=files)
    assert h0.run().returncode == 1
    assert h0.running() == {"v0.3.1"} and not any(c.startswith("build") for c in h0.calls())
    assert said in _alerts(h0)[0]["embeds"][0]["description"]


def test_a_new_lock_with_its_attestation_is_deployed(tmp_path, fake):
    h0 = H0(tmp_path, fake, c2_files={"requirements/glorfindel.txt": NEW_LOCK,
                                       "requirements/harness.json": _attestation()})
    res = h0.run()
    assert res.returncode == 0, res.stdout + res.stderr
    assert h0.running() == {"v0.4.0"}


def test_h0s_own_model_is_the_one_attested(tmp_path, fake):
    h0 = H0(tmp_path, fake, c2_files={"requirements/glorfindel.txt": NEW_LOCK,
                                       "requirements/harness.json": _attestation()})
    (h0.vm / ".env").write_text("EREGION_CONSOLE_TOKEN=tok\nGLORFINDEL_LLM_MODEL=ollama/qwen3  # en test\n")
    assert h0.run().returncode == 1
    assert "ollama/qwen3" in _alerts(h0)[0]["embeds"][0]["description"]


# ── preflight in the candidate, before anything moves ──────────────────────────────

@pytest.mark.parametrize("env, said", [
    ({"FAKE_CONFIG_FAIL": "1"}, "lecture stricte d'A3"),
    ({"FAKE_PKG_VERSION": "0.3.1"}, "glorfindel --version"),
    ({"FAKE_COMPOSE_FAIL": "1"}, "docker compose refuse"),
    ({"FAKE_BUILD_FAIL": "1"}, "construction"),
])
def test_a_failed_preflight_leaves_what_runs_untouched(h0, env, said):
    assert h0.run(**env).returncode == 1
    images = h0.docker()["images"]
    assert h0.running() == {"v0.3.1"} and h0.head() == h0.commits["c1"]
    assert images["eregion-glorfindel"]["version"] == "v0.3.1"             # the candidate never replaced it
    assert not any(c.startswith(("tag ", "compose --profile")) for c in h0.calls())
    assert said in _alerts(h0)[0]["embeds"][0]["description"]
    assert h0.outcome("v0.4.0") == "refused"


def test_the_config_refusal_says_what_a3_said_in_the_journal_only(h0):
    """A3's words name the config's keys and values — workspace ids, resource groups: the
    journal (make glorfindel-host-cd-status) has them, #deploy only says where to look."""
    res = h0.run(FAKE_CONFIG_FAIL="1")
    assert "quarantaine_nsg" in res.stdout
    assert "quarantaine_nsg" not in json.dumps(h0.posts()) and "cd-status" in json.dumps(h0.posts())


# ── health, and going back ─────────────────────────────────────────────────────────

def test_an_unhealthy_release_is_rolled_back_said_and_not_tried_again(h0):
    assert h0.run(FAKE_SICK="v0.4.0").returncode == 1
    assert h0.running() == {"v0.3.1"} and h0.head() == h0.commits["c1"]
    calls = h0.calls()
    assert not [c for c in calls[calls.index("tag eregion-glorfindel:v0.4.0 eregion-glorfindel"):] if c.startswith("build")]
    assert "tag eregion-glorfindel:v0.3.1 eregion-glorfindel" in calls      # a retag, no build
    (alert,) = _alerts(h0)
    assert alert["embeds"][0]["title"].startswith("↩️") and "redémarrage" in alert["embeds"][0]["description"]
    assert h0.outcome("v0.4.0") == "rolled back"
    h0.log.write_text("")
    assert h0.run().returncode == 0 and not any(c.startswith("build") for c in h0.calls())


def test_a_host_deployed_before_h1_can_still_go_back(h0):
    """H0 today: its image was built by the deploy.sh of before H1, as `eregion-glorfindel` only.
    Before switching, the CD tags it by its reference — else no image to go back to."""
    st = h0.docker()
    del st["images"]["eregion-glorfindel:v0.3.1"]
    h0.state.write_text(json.dumps(st))
    assert h0.run(FAKE_SICK="v0.4.0").returncode == 1
    calls = h0.calls()
    assert calls.index("tag eregion-glorfindel eregion-glorfindel:v0.3.1") < calls.index(
        "tag eregion-glorfindel:v0.4.0 eregion-glorfindel")
    assert h0.running() == {"v0.3.1"} and h0.outcome("v0.4.0") == "rolled back"


READ_ONLY = "OSError: [Errno 30] Read-only file system: '/app/glorfindel/x.json'\n"


def test_a_release_that_writes_outside_its_mounts_is_rolled_back(h0):
    """V-34 (SEC7): the root filesystem read-only, a write outside the mounts fails in the
    candidate's journal — a regression: H0 goes back, said, with the reason."""
    assert h0.run(FAKE_RULES_LOGS=READ_ONLY).returncode == 1
    assert h0.running() == {"v0.3.1"} and h0.outcome("v0.4.0") == "rolled back"
    (alert,) = _alerts(h0)
    assert "Read-only file system" in alert["embeds"][0]["description"]
    assert any(c.startswith("logs --since") for c in h0.calls())


def test_a_read_only_error_that_ran_before_the_switch_is_no_regression(h0):
    """H2's rule: only a regression goes back. What ran already logged it: the release is kept."""
    assert h0.run(FAKE_BASE_LOGS=READ_ONLY, FAKE_RULES_LOGS=READ_ONLY).returncode == 0
    assert h0.running() == {"v0.4.0"} and h0.outcome("v0.4.0") == "deployed"


def test_the_way_back_is_never_judged_on_the_read_only_probe(agent, monkeypatch):
    seen = []
    monkeypatch.setattr(agent, "read_only_errors", lambda since: seen.append(since) or (["eregion-watch"], []))
    monkeypatch.setattr(agent, "health_once", lambda ref, since: "")
    monkeypatch.setattr(agent, "HEALTH_S", 0.0)
    monkeypatch.setattr(agent, "run_rules_check", lambda budget, label: {"state": "ok", "rules": []})
    assert agent.health("v0.3.1", 0.0) == ("", {}) and seen == []
    why, _ = agent.health("v0.4.0", 5.0, rules=True, base={"state": "ok", "rules": []})
    assert "Read-only file system" in why and seen == [5.0]
    why, _ = agent.health("v0.4.0", 5.0, rules=True, base={"state": "absent", "rules": [],
                                                           "read_only": ["eregion-watch"]})
    assert "Read-only" not in why


def test_a_journal_that_cannot_be_read_is_said_in_orange_never_a_rollback(h0):
    """SEC7, second review: `docker logs` failing proves nothing — H2's rule: said in orange
    with the success, H0 kept."""
    assert h0.run(FAKE_RULES_LOGS_RC="1").returncode == 0
    assert h0.running() == {"v0.4.0"} and h0.outcome("v0.4.0") == "deployed"
    said = json.dumps(h0.posts(), ensure_ascii=False)
    assert "journaux illisibles" in said and "non prouvée" in said


def test_a_heartbeat_from_before_the_switch_is_not_health(h0):
    h0.heartbeat.parent.mkdir(parents=True)
    h0.heartbeat.write_text("old")
    os.utime(h0.heartbeat, (1, 1))
    assert h0.run(FAKE_NO_HEARTBEAT="1").returncode == 1
    assert "battu" in _alerts(h0)[0]["embeds"][0]["description"]


def test_a_console_that_does_not_answer_is_not_health(h0):
    h0.fake.console_status = 503
    assert h0.run().returncode == 1
    assert "console" in _alerts(h0)[0]["embeds"][0]["description"]


def test_retry_tries_the_release_again(h0):
    h0.run(FAKE_SICK="v0.4.0")
    res = h0.run("retry")
    assert res.returncode == 0, res.stdout + res.stderr
    assert h0.running() == {"v0.4.0"} and h0.outcome("v0.4.0") == "deployed"


def test_a_failed_rollback_is_said_loudly(h0):
    assert h0.run(FAKE_SICK="v0.4.0", EREGION_CD_HEALTH_S="0.1").returncode == 1
    h0.log.write_text("")
    h0.fake.requests.clear()
    state = json.loads((h0.cd / "state.json").read_text())
    state["outcomes"].clear()
    (h0.cd / "state.json").write_text(json.dumps(state))
    h0.fake.console_status = 503                                     # nothing is healthy now
    assert h0.run().returncode == 1
    (alert,) = _alerts(h0)
    assert alert["embeds"][0]["title"].startswith("🔥") and h0.outcome("v0.4.0") == "rollback failed"


# ── the first installation, by hand: a dry run ─────────────────────────────────────

def test_check_verifies_builds_and_preflights_but_never_switches(h0):
    res = h0.run("check")
    assert res.returncode == 0, res.stdout + res.stderr
    images = h0.docker()["images"]
    assert "eregion-glorfindel:v0.4.0" in images and images["eregion-glorfindel"]["version"] == "v0.3.1"
    assert h0.running() == {"v0.3.1"} and h0.head() == h0.commits["c1"]
    (post,) = h0.posts()
    assert post["embeds"][0]["title"] == "✅ À blanc : v0.4.0 est prête" and post["flags"] == 4096
    assert h0.outcome("v0.4.0") is None


def test_check_says_a_refusal_without_remembering_it(h0):
    assert h0.run("check", FAKE_CONFIG_FAIL="1").returncode == 1
    assert h0.posts()[0]["embeds"][0]["title"].startswith("⛔ À blanc") and h0.outcome("v0.4.0") is None


# ── one pass at a time, secrets kept, the agent's own updates said ─────────────────

def test_one_pass_at_a_time_and_none_during_a_deployment_by_hand(h0):
    with open(h0.home / ".eregion-deploy.lock", "w") as held:
        fcntl.flock(held, fcntl.LOCK_EX)
        res = h0.run()
    assert res.returncode == 0 and "en cours" in res.stdout and h0.calls() == []


def test_the_webhook_never_shows_even_when_discord_fails(h0):
    h0.fake.fail["/api/webhooks"] = 500
    res = h0.run()
    assert res.returncode == 0 and h0.running() == {"v0.4.0"}
    assert "HTTP 500" in res.stderr and SECRET not in res.stdout + res.stderr


def test_a_release_with_another_agent_says_to_reinstall_it(tmp_path, fake):
    h0 = H0(tmp_path, fake, c2_files={"infra/glorfindel-host/cd/eregion_cd.py": "# a newer agent\n"})
    assert h0.run().returncode == 0
    assert any(t.startswith("🔧 Agent de CD à mettre à jour") for t in _titles(h0))
    assert "eregion_cd.py" in h0.posts()[-1]["embeds"][0]["description"]
    assert (h0.cd / "eregion_cd.py").read_text() == AGENT.read_text()     # never replaced by itself


def test_the_installation_never_carries_the_bots_token(tmp_path):
    conf = tmp_path / "discord.env"
    conf.write_text("EREGION_DISCORD_BOT_TOKEN=BOT-SECRET\nEREGION_DISCORD_WEBHOOK_DEPLOY=https://x/hook\n"
                    "EREGION_DISCORD_MENTION=42\nEREGION_DISCORD_WEBHOOK_AGENTS=https://x/agents\n")
    env = {k: v for k, v in os.environ.items() if not k.startswith("EREGION_")}
    res = subprocess.run([sys.executable, str(AGENT), "export-discord-env"], capture_output=True, text=True,
                         env={**env, "EREGION_DISCORD_ENV": str(conf)}, timeout=30)
    assert res.returncode == 0
    assert res.stdout.splitlines() == ["EREGION_DISCORD_WEBHOOK_DEPLOY=https://x/hook", "EREGION_DISCORD_MENTION=42"]


def test_the_timer_runs_the_installed_agent_and_starts_disabled():
    cd = ROOT / "infra" / "glorfindel-host" / "cd"
    service, install = (cd / "eregion-cd.service").read_text(), (cd / "install.sh").read_text()
    assert "ExecStart=/usr/bin/python3 @HOME@/.eregion-cd/eregion_cd.py run" in service
    assert "User=@USER@" in service and "OnUnitActiveSec=5min" in (cd / "eregion-cd.timer").read_text()
    assert "enable" not in "\n".join(line for line in install.splitlines() if not line.lstrip().startswith("#")
                                      and "disable" not in line and "is-enabled" not in line and "enabled" not in line)


# ── after the review of 28/10 ──────────────────────────────────────────────────────

def _images(h0, **tags):
    st = h0.docker()
    for tag, (version, n) in tags.items():
        st["images"][f"eregion-glorfindel:{tag}"] = {"version": version, "revision": h0.commits["c1"], "n": n}
    h0.state.write_text(json.dumps(st))


def test_two_refused_candidates_then_a_sick_release_still_go_back(h0):
    """1: nothing is pruned before the health is green. Two newer candidates (refused before,
    their images kept) made the one before the oldest: a prune at the switch removed it."""
    _images(h0, **{"v0.3.5": ("v0.3.5", 1), "v0.3.6": ("v0.3.6", 2)})
    assert h0.run(FAKE_SICK="v0.4.0").returncode == 1
    assert h0.running() == {"v0.3.1"} and h0.outcome("v0.4.0") == "rolled back"
    assert not any(c.startswith("image rm") for c in h0.calls())


def test_after_a_green_health_the_old_images_go_and_the_one_before_stays(h0):
    _images(h0, **{"v0.2.0": ("v0.2.0", 1), "v0.3.5": ("v0.3.5", 2), "v0.3.6": ("v0.3.6", 3)})
    assert h0.run().returncode == 0
    images = h0.docker()["images"]
    assert "eregion-glorfindel:v0.3.1" in images and "eregion-glorfindel:v0.4.0" in images
    assert "eregion-glorfindel:v0.2.0" not in images


def test_no_way_back_no_switch(h0):
    """The image running now has neither its tag nor its label: refused, nothing moves."""
    st = h0.docker()
    del st["images"]["eregion-glorfindel:v0.3.1"]
    st["images"]["eregion-glorfindel"]["version"] = "v0.2.0"
    h0.state.write_text(json.dumps(st))
    assert h0.run().returncode == 1
    assert h0.running() == {"v0.3.1"} and h0.head() == h0.commits["c1"]
    assert "pas d'image eregion-glorfindel:v0.3.1" in _alerts(h0)[0]["embeds"][0]["description"]
    assert not any(c.startswith(("tag eregion-glorfindel:v0.4.0", "compose --profile")) for c in h0.calls())


@pytest.mark.parametrize("sick", [False, True])
def test_a_pass_cut_after_its_switch_is_taken_up(h0, sick):
    """2: a reboot or a timeout between the switch and the end of the health. The next pass
    reads the switch it wrote down, watches the health, keeps the release or goes back."""
    import time
    c2 = h0.commits["c2"]
    st = h0.docker()
    st["images"]["eregion-glorfindel:v0.4.0"] = {"version": "v0.4.0", "revision": c2, "n": 5}
    st["images"]["eregion-glorfindel"] = dict(st["images"]["eregion-glorfindel:v0.4.0"])
    for c in st["containers"].values():
        c.update(version="v0.4.0", revision=c2, status="restarting" if sick else "running", restarts=4 if sick else 0)
    h0.state.write_text(json.dumps(st))
    _git(h0.vm, h0.env, "checkout", "-q", "--detach", c2)
    (h0.cd / "state.json").write_text(json.dumps({"outcomes": {"v0.4.0": {
        "result": "switching", "from": "v0.3.1", "url": "", "why": "", "at": time.time() - 2}}, "said": {}}))
    h0.heartbeat.parent.mkdir(parents=True, exist_ok=True)
    h0.heartbeat.write_text("now")
    res = h0.run()
    assert "reprise" in res.stdout
    if sick:
        assert res.returncode == 1 and h0.running() == {"v0.3.1"} and h0.outcome("v0.4.0") == "rolled back"
    else:
        assert res.returncode == 0, res.stdout + res.stderr
        assert h0.running() == {"v0.4.0"} and h0.outcome("v0.4.0") == "deployed"
        assert "repris" in h0.posts()[-1]["embeds"][0]["description"]


def test_running_already_but_not_all_three_is_said(h0):
    """2: « runs already » means the three containers, not the watch alone."""
    assert h0.run().returncode == 0
    st = h0.docker()
    st["containers"]["eregion-war-room"]["version"] = "v0.3.1"
    h0.state.write_text(json.dumps(st))
    h0.fake.requests.clear()
    assert h0.run().returncode == 0 and h0.run().returncode == 0
    (alert,) = _alerts(h0)
    assert "eregion-war-room" in alert["embeds"][0]["description"]


def test_a_moved_tag_is_refused(h0):
    """4: v0.4.0 deployed, then its tag rewritten onto a newer commit of main: refused, said."""
    assert h0.run().returncode == 0
    work = h0.tmp / "work"
    _git(work, h0.env, "checkout", "-q", "main")
    (work / "app.py").write_text("V = 3\n")
    _git(work, h0.env, "commit", "-qam", "c3")
    _git(work, h0.env, "tag", "-f", "v0.4.0")
    _git(work, h0.env, "push", "-q", "--force", "origin", "main", "refs/tags/v0.4.0")
    assert h0.run().returncode == 1
    assert h0.running() == {"v0.4.0"} and h0.head() == h0.commits["c2"]
    assert "a bougé" in _alerts(h0)[-1]["embeds"][0]["description"]


def test_the_main_ci_job_is_waited_for_an_hour_then_refused(h0):
    """Another workflow can finish before the CI's job is even created: a wait, not a refusal."""
    h0.fake.gh["checks"][h0.commits["c2"]] = [{"name": "Components", "status": "completed", "conclusion": "success"}]
    assert h0.run().returncode == 0 and h0.run().returncode == 0
    assert [t.split(" ")[0] for t in _titles(h0)] == ["⏳"] and h0.outcome("v0.4.0") is None
    state = json.loads((h0.cd / "state.json").read_text())
    state["waits"]["v0.4.0"] = 12
    (h0.cd / "state.json").write_text(json.dumps(state))
    assert h0.run().returncode == 1 and "CI principale" in _alerts(h0)[0]["embeds"][0]["description"]


def test_the_version_is_compared_exactly(h0):
    assert h0.run(FAKE_PKG_VERSION="0.4.01").returncode == 1
    assert "0.4.01" in _alerts(h0)[0]["embeds"][0]["description"]


def test_the_config_compose_mounts_is_the_one_preflighted(h0, tmp_path):
    cfg = tmp_path / "elsewhere.yaml"
    cfg.write_text("autonomy: {}\n")
    (h0.vm / ".env").write_text(f"EREGION_CONSOLE_TOKEN=tok\nEREGION_CONFIG={cfg}\n")
    assert h0.run().returncode == 0
    assert any(f"{cfg}:/app/glorfindel-config.yaml:ro" in c for c in h0.calls())


def test_a_malformed_release_is_quiet(h0):
    h0.fake.gh["release"] = [{"tag_name": "v0.4.0"}]
    res = h0.run()
    assert res.returncode == 0 and "illisible" in res.stdout and h0.posts() == []


def test_an_unexpected_error_is_said_once(h0, tmp_path):
    for _ in range(2):
        res = h0.run(EREGION_CD_REPO=str(tmp_path / "no-such-checkout"))
        assert res.returncode == 1
    (alert,) = _alerts(h0)
    assert alert["embeds"][0]["title"] == "⚠️ Le CD de H0 a échoué"


def test_check_rebuilds_and_preflights_the_release_running_already(h0):
    """6: v0.4.0 runs; the dry run still checks it on the real Docker — aside, then gone."""
    assert h0.run().returncode == 0
    h0.fake.requests.clear()
    res = h0.run("check")
    assert res.returncode == 0, res.stdout + res.stderr
    assert any(c.endswith("-t eregion-glorfindel:check-v0.4.0 .") for c in h0.calls())
    assert "eregion-glorfindel:check-v0.4.0" not in h0.docker()["images"]
    assert h0.running() == {"v0.4.0"}
    assert h0.posts()[0]["embeds"][0]["title"] == "✅ À blanc : v0.4.0, en service, reconstruite et préflightée"


# ── after the second review of 28/10 ───────────────────────────────────────────────

def _cut_switch(h0):
    import time
    (h0.cd / "state.json").write_text(json.dumps({"outcomes": {"v0.4.0": {
        "result": "switching", "from": "v0.3.1", "url": "", "why": "", "at": time.time() - 2}}, "said": {}}))


def test_a_cut_switch_then_a_deployment_by_hand_is_left_alone(h0):
    """1: the switch to v0.4.0 cut, then Jonathan deploys a hotfix by hand: the next pass
    never puts v0.3.1 back over it."""
    _cut_switch(h0)
    st = h0.docker()
    st["images"]["eregion-glorfindel:hotfix"] = {"version": "hotfix", "revision": h0.commits["c2"], "n": 7}
    for c in st["containers"].values():
        c.update(version="hotfix")
    h0.state.write_text(json.dumps(st))
    h0.publish("v0.3.1")
    res = h0.run()
    assert res.returncode == 0, res.stdout + res.stderr
    assert h0.running() == {"hotfix"} and h0.outcome("v0.4.0") == "superseded"
    assert not any(c.startswith(("tag ", "compose ")) for c in h0.calls())
    (post,) = h0.posts()
    assert post["embeds"][0]["title"].startswith("ℹ️") and not post.get("content")


def test_a_switch_cut_before_the_containers_moved_is_interrupted_not_sick(h0):
    """1: cut after the checkout, before compose: H0 put back in one piece on v0.3.1, the
    release never called sick nor marked rolled back — and the next pass deploys it."""
    _cut_switch(h0)
    _git(h0.vm, h0.env, "checkout", "-q", "--detach", h0.commits["c2"])
    res = h0.run()
    assert res.returncode == 0, res.stdout + res.stderr
    assert h0.running() == {"v0.3.1"} and h0.head() == h0.commits["c1"]
    assert h0.outcome("v0.4.0") == "interrupted" and not _alerts(h0)
    assert h0.posts()[-1]["embeds"][0]["title"].startswith("⏸️")
    assert h0.run().returncode == 0 and h0.running() == {"v0.4.0"} and h0.outcome("v0.4.0") == "deployed"


def test_retry_keeps_a_cut_switch(h0):
    _cut_switch(h0)
    st = json.loads((h0.cd / "state.json").read_text())
    st["outcomes"]["v0.3.9"] = {"result": "refused", "why": "x", "at": 1}
    (h0.cd / "state.json").write_text(json.dumps(st))
    res = h0.run("retry")
    assert "reprise" in res.stdout and h0.outcome("v0.3.9") is None


# ── after the third review of 28/10 ────────────────────────────────────────────────

def test_a_watch_gone_after_a_cut_compose_is_put_back_not_superseded(h0):
    """1: cut during `compose up` — the old watch removed, the new one not created yet. Not a
    deployment by hand: H0 put back on v0.3.1, Glorfindel running again."""
    _cut_switch(h0)
    st = h0.docker()
    del st["containers"]["eregion-watch"]
    h0.state.write_text(json.dumps(st))
    res = h0.run()
    assert res.returncode == 0, res.stdout + res.stderr
    assert h0.outcome("v0.4.0") == "interrupted"
    assert h0.running() == {"v0.3.1"} and "eregion-watch" in h0.docker()["containers"]


def test_a_switch_interrupted_twice_is_refused_and_said(h0):
    """2: a switch always cut at the same place is not tried forever without a word."""
    _cut_switch(h0)
    assert h0.run().returncode == 0 and h0.outcome("v0.4.0") == "interrupted"
    state = json.loads((h0.cd / "state.json").read_text())
    state["outcomes"]["v0.4.0"].update(result="switching", **{"from": "v0.3.1"})
    (h0.cd / "state.json").write_text(json.dumps(state))
    assert h0.run().returncode == 1 and h0.outcome("v0.4.0") == "refused"
    (alert,) = _alerts(h0)
    assert "interrompue deux fois" in alert["embeds"][0]["title"]
    h0.log.write_text("")
    assert h0.run().returncode == 0 and not any(c.startswith("build") for c in h0.calls())
    res = h0.run("retry")
    assert res.returncode == 0 and h0.outcome("v0.4.0") == "deployed"


# ── « Agent de CD à mettre à jour » only for a newer release (28/10, after v0.4.1) ──

def test_a_release_older_than_the_agent_never_asks_to_reinstall_it(tmp_path, fake):
    """v0.4.1 had no H1: its deploy.sh is older than the agent's, and installing from it
    would break the CD. The agent was installed from a later commit: nothing said."""
    h0 = H0(tmp_path, fake, c2_files={"infra/glorfindel-host/cd/eregion_cd.py": "# an older agent\n"})
    work = h0.tmp / "work"
    _git(work, h0.env, "checkout", "-q", "main")
    (work / "app.py").write_text("V = 3\n")
    _git(work, h0.env, "commit", "-qam", "c3: the agent's own commit")
    _git(work, h0.env, "push", "-q", "origin", "main")
    (h0.cd / "installed-from").write_text(_git(work, h0.env, "rev-parse", "HEAD") + "\n")
    res = h0.run()
    assert res.returncode == 0, res.stdout + res.stderr
    assert not any("Agent de CD" in t for t in _titles(h0)) and "pas plus ancien" in res.stdout


@pytest.mark.parametrize("installed_from", [None, "HEAD", "side"])
def test_an_agent_whose_origin_is_lost_says_it_once_without_the_mention(tmp_path, fake, installed_from):
    """installed-from missing, a ref name (HEAD made every release look newer), or a commit off
    main (a lot's branch: no release will descend from it): never « 🔧 », said once, silent."""
    h0 = H0(tmp_path, fake, c2_files={"infra/glorfindel-host/cd/eregion_cd.py": "# another agent\n"})
    if installed_from is None:
        (h0.cd / "installed-from").unlink()
    else:
        (h0.cd / "installed-from").write_text(h0.commits.get(installed_from, installed_from) + "\n")
    res = h0.run()
    assert res.returncode == 0, res.stdout + res.stderr
    assert not any("Agent de CD à mettre à jour" in t for t in _titles(h0))
    (info,) = [p for p in h0.posts() if p["embeds"][0]["title"].startswith("ℹ️ L'agent de CD")]
    assert not info.get("content") and info["flags"] == 4096


def test_a_newer_release_with_the_same_agent_says_nothing(tmp_path, fake):
    """The release is newer than the agent, its three files are the installed ones: nothing to update."""
    same = {path: (ROOT / path).read_text(encoding="utf-8") for path in (
        "infra/glorfindel-host/cd/eregion_cd.py", "infra/glorfindel-host/deploy.sh", "scripts/notify_discord.py",
        "glorfindel/chat_text.py")}
    h0 = H0(tmp_path, fake, c2_files=same)
    res = h0.run()
    assert res.returncode == 0, res.stdout + res.stderr
    assert not any("Agent de CD" in t or "L'agent de CD" in t for t in _titles(h0))


@pytest.mark.skipif(shutil.which("make") is None, reason="make not installed")
def test_the_installation_writes_the_commit_it_installs_from():
    res = subprocess.run(["make", "-n", "--no-print-directory", "-C", str(ROOT), "glorfindel-host-cd-install",
                          "HOST_IP=203.0.113.9"], capture_output=True, text=True, timeout=60)
    assert res.returncode == 0, res.stderr
    assert "git rev-parse HEAD |" in res.stdout and "cat > .eregion-cd/installed-from" in res.stdout


# ── H2 (#266): every rule the release loads runs once after the switch ─────────────────
# Placeholders only (never a real infrastructure): what an error may carry, that #deploy never says.
WS = "00000000-0000-0000-0000-0000000000aa"
SUB = "00000000-0000-0000-0000-0000000000bb"
LEAKS = (WS, SUB, "/subscriptions/", "rg-example", "vm-example-01", "internal.example.net", "10.0.0.4")
NO_CHECK = "Usage: glorfindel rules [OPTIONS]\nTry 'glorfindel rules --help' for help.\n\nError: No such option: --live\n"


def _rules(*rules, error=""):
    return json.dumps({"schema": "eregion.rules-check/1", "live": True, "error": error, "rules": list(rules)})


def _rule(name, status="ok", kind="", error="", code=""):
    return {"name": name, "status": status, "rows": 0 if status == "ok" else None, "kind": kind, "error": error,
            "code": code}


def _execs(h0):
    return h0.docker().get("execs", [])


def _desc(post):
    return post["embeds"][0]["description"]


def _titled(h0, start):
    return [p for p in h0.posts() if p["embeds"][0]["title"].startswith(start)]


def _arg(args, flag):
    return float(args[args.index(flag) + 1])


BROKEN = _rule("sudo-root", "error", "syntax", f"Query could not be parsed at 'BROKEN' — workspace {WS} at "
               f"/subscriptions/{SUB}/resourceGroups/rg-example on vm-example-01.internal.example.net (10.0.0.4)",
               "SYN0002")


def test_the_rules_run_once_before_and_once_after_the_switch(h0):
    res = h0.run(FAKE_RULES_OUT=_rules(_rule("ssh-brute-force"), _rule("sudo-root")))
    assert res.returncode == 0, res.stdout + res.stderr
    before, after = _execs(h0)                                # once each, never again
    assert (before["container"], before["on"]) == ("eregion-watch", "v0.3.1")   # what ran, before it moved
    assert (after["container"], after["on"]) == ("eregion-watch", "v0.4.0")     # the candidate, switched to
    for ex in (before, after):
        assert ex["args"][:5] == ["glorfindel", "rules", "check", "--live", "--json"]
        assert 0 < _arg(ex["args"], "--query-timeout") <= _arg(ex["args"], "--total")
    calls = h0.calls()
    assert calls.index(next(c for c in calls if c.startswith("exec "))) < calls.index(
        "tag eregion-glorfindel:v0.4.0 eregion-glorfindel")
    (ok,) = _titled(h0, "✅")
    assert "règles : 2 sur 2" in _desc(ok) and h0.outcome("v0.4.0") == "deployed"
    assert not _titled(h0, "⚠️")


def test_a_rule_without_rows_is_no_error(h0):
    """Zero rows is the usual answer of a rule: nothing happened."""
    assert h0.run(FAKE_RULES_OUT=_rules(_rule("quiet"))).returncode == 0
    assert h0.running() == {"v0.4.0"} and not _alerts(h0)


@pytest.mark.parametrize("rule, said", [
    (BROKEN, "requête invalide (SYN0002)"),
    (_rule("sudo-root", "error", "table", "'where' operator: Failed to resolve table 'NoSuchTable'", "SEM0100"),
     "table ou colonne absente (SEM0100)"),
    (_rule("sudo-root", "error", "backend", "workspace en ligne sans backend"), "backend non lié"),
])
def test_a_rule_ok_before_and_broken_after_rolls_back_said_by_name_kind_and_code(h0, rule, said):
    base = _rules(_rule("ssh-brute-force"), _rule("sudo-root"))
    out = _rules(_rule("ssh-brute-force"), rule)
    assert h0.run(FAKE_BASE_OUT=base, FAKE_RULES_OUT=out, FAKE_RULES_RC="1").returncode == 1
    assert h0.running() == {"v0.3.1"} and h0.head() == h0.commits["c1"] and h0.outcome("v0.4.0") == "rolled back"
    (alert,) = _alerts(h0)
    assert alert["embeds"][0]["title"].startswith("↩️")
    assert "« sudo-root »" in _desc(alert) and said in _desc(alert) and "cassée(s) par cette release" in _desc(alert)
    posted = json.dumps(h0.posts(), ensure_ascii=False)
    assert "BROKEN" not in posted and "Failed to resolve" not in posted     # the error's words: the journal only
    for leak in LEAKS:
        assert leak not in posted, leak
    assert [e["on"] for e in _execs(h0)] == ["v0.3.1", "v0.4.0"]           # the way back runs no check


def test_a_new_rule_broken_in_the_release_rolls_back(h0):
    """Absent before, in a lasting error after: this release brought it."""
    assert h0.run(FAKE_RULES_OUT=_rules(_rule("ssh-brute-force"), BROKEN), FAKE_RULES_RC="1").returncode == 1
    assert h0.running() == {"v0.3.1"} and "« sudo-root »" in _desc(_alerts(h0)[0])


def test_a_rule_broken_before_as_after_is_said_with_the_mention_never_a_rollback(h0):
    """A table the workspace never had (C2's AuditLogs on H0, maybe), a client rule broken, a role
    taken away: the release did not bring it — H0 keeps it, Jonathan is told."""
    base = _rules(_rule("ssh-brute-force"), _rule("entra-app-consent", "error", "table", "x", "SEM0100"))
    out = _rules(_rule("ssh-brute-force"), _rule("entra-app-consent", "error", "table", "x", "SEM0100"))
    res = h0.run(FAKE_BASE_OUT=base, FAKE_BASE_RC="1", FAKE_RULES_OUT=out, FAKE_RULES_RC="1")
    assert res.returncode == 0, res.stdout + res.stderr
    assert h0.running() == {"v0.4.0"} and h0.outcome("v0.4.0") == "deployed"
    (warn,) = _titled(h0, "⚠️")
    assert warn.get("content") == "<@42>"
    assert "« entra-app-consent »" in _desc(warn) and "avant la bascule" in _desc(warn)


def test_a_reference_without_the_command_compares_nothing_and_rolls_nothing_back(h0):
    """v0.4.3 and before: no `rules check` in what runs — « non comparé », in orange."""
    res = h0.run(FAKE_BASE_OUT=NO_CHECK, FAKE_BASE_RC="2", FAKE_RULES_OUT=_rules(_rule("ssh-brute-force"), BROKEN),
                 FAKE_RULES_RC="1")
    assert res.returncode == 0, res.stdout + res.stderr
    assert h0.running() == {"v0.4.0"} and h0.outcome("v0.4.0") == "deployed"
    (warn,) = _titled(h0, "⚠️")
    assert "non comparé" in _desc(warn) and "« sudo-root »" in _desc(warn) and warn.get("content") == "<@42>"


def test_a_reference_with_an_error_that_may_pass_rolls_nothing_back(h0):
    """sudo-root unproven before (a 429): nothing says it was ok — no rollback, said."""
    base = _rules(_rule("ssh-brute-force"), _rule("sudo-root", "unproven", "throttled", "Too Many Requests", "429"))
    res = h0.run(FAKE_BASE_OUT=base, FAKE_BASE_RC="3", FAKE_RULES_OUT=_rules(_rule("ssh-brute-force"), BROKEN),
                 FAKE_RULES_RC="1")
    assert res.returncode == 0, res.stdout + res.stderr
    assert h0.running() == {"v0.4.0"} and "« sudo-root »" in _desc(_titled(h0, "⚠️")[0])


@pytest.mark.parametrize("status", ["unproven", "error"])
@pytest.mark.parametrize("kind, code", [("throttled", "429"), ("service", "503"), ("network", "ServiceRequestError"),
                                        ("auth", "ClientAuthenticationError"), ("partial", "RuntimeError"),
                                        ("other", "Exception")])
def test_an_error_that_may_pass_keeps_the_release(h0, kind, code, status):
    """The command says these unproven; the CD rolls back on its own list of lasting kinds only —
    even for one a command would call an error."""
    out = _rules(_rule("ssh-brute-force"), _rule("sudo-root", status, kind, "x", code))
    res = h0.run(FAKE_RULES_OUT=out, FAKE_RULES_RC="3")
    assert res.returncode == 0, res.stdout + res.stderr
    assert h0.running() == {"v0.4.0"} and h0.outcome("v0.4.0") == "deployed"
    (warn,) = _titled(h0, "⚠️")
    assert "« sudo-root »" in _desc(warn)
    if status == "unproven":
        assert "non prouvée" in _desc(warn) and not warn.get("content")


def test_what_a_rule_says_is_escaped_for_discord(h0):
    """SEC6: a rule's name and code are text from outside — no masked link, no mention."""
    out = _rules(_rule("[Support](https://evil.example.com) @everyone", "error", "syntax", "**bold**", "SEM`0100"))
    assert h0.run(FAKE_RULES_OUT=out, FAKE_RULES_RC="1").returncode == 1
    text = _desc(_alerts(h0)[0])
    assert "\\[Support\\]" in text and "evil.example.com" not in text and "@​everyone" in text
    assert "bold" not in text and "`" not in text


def test_rules_without_an_answer_are_said_never_a_rollback(h0):
    out = _rules(_rule("ssh-brute-force"), _rule("slow-one", "timeout", "timeout", "pas de réponse en 20 s"))
    res = h0.run(FAKE_RULES_OUT=out, FAKE_RULES_RC="3")
    assert res.returncode == 0, res.stdout + res.stderr
    assert h0.running() == {"v0.4.0"} and h0.outcome("v0.4.0") == "deployed" and not _alerts(h0)
    (slow,) = _titled(h0, "⚠️")
    assert "slow-one" in _desc(slow) and "délai dépassé" in _desc(slow)
    assert len(_execs(h0)) == 2                                # said, not tried again


def test_a_check_that_never_ends_is_cut_said_and_the_release_kept(h0):
    import time
    started = time.monotonic()
    res = h0.run(FAKE_RULES_SLEEP="20", EREGION_CD_RULES_MARGIN_S="0.5")
    assert time.monotonic() - started < 15                    # cut at its budget, never waited for
    assert res.returncode == 0, res.stdout + res.stderr
    assert h0.running() == {"v0.4.0"} and len(_execs(h0)) == 2
    assert "non prouvées" in _desc(_titled(h0, "⚠️")[0])


def test_a_release_from_before_h2_is_kept_its_rules_unproven(h0):
    """Its `glorfindel rules` takes no `check`: click's code 2 and its words — said, not a rollback."""
    res = h0.run(FAKE_RULES_OUT=NO_CHECK, FAKE_RULES_RC="2")
    assert res.returncode == 0, res.stdout + res.stderr
    assert "non vérifiées" in _desc(_titled(h0, "✅")[0])


def test_a_code_2_that_is_no_missing_command_is_said_in_orange(h0):
    res = h0.run(FAKE_RULES_OUT="", FAKE_RULES_ERR="Error: Invalid value for '--total': 9999 is not in the range",
                 FAKE_RULES_RC="2")
    assert res.returncode == 0, res.stdout + res.stderr
    assert "refusé ses options" in _desc(_titled(h0, "⚠️")[0]) and "non vérifiées" not in json.dumps(h0.posts())


@pytest.mark.parametrize("out, rc, said", [
    ("Traceback (most recent call last):\n  ImportError: boom", "1", "rien dit de lisible"),
    (_rules(error="glorfindel-config.yaml refusé par la lecture stricte (A3)"), "1", "A3"),
    (_rules(), "0", "aucune règle chargée"),
])
def test_a_check_that_proves_nothing_where_the_reference_was_checked_rolls_back(h0, out, rc, said):
    assert h0.run(FAKE_RULES_OUT=out, FAKE_RULES_RC=rc).returncode == 1
    assert h0.running() == {"v0.3.1"} and said in _desc(_alerts(h0)[0])


def test_the_full_words_go_to_the_journal_only(h0):
    res = h0.run(FAKE_RULES_OUT=_rules(_rule("ssh-brute-force"), BROKEN), FAKE_RULES_RC="1",
                 FAKE_RULES_ERR=f"sudo-root [error/syntax] : (BadArgumentError) workspace {WS}\n")
    assert WS in res.stdout                                    # the journal (journalctl, private)
    assert WS not in json.dumps(h0.posts())


def test_a_switch_taken_up_after_a_cut_compares_with_what_was_checked_before(h0):
    import time
    c2 = h0.commits["c2"]
    st = h0.docker()
    st["images"]["eregion-glorfindel:v0.4.0"] = {"version": "v0.4.0", "revision": c2, "n": 5}
    st["images"]["eregion-glorfindel"] = dict(st["images"]["eregion-glorfindel:v0.4.0"])
    for c in st["containers"].values():
        c.update(version="v0.4.0", revision=c2)
    h0.state.write_text(json.dumps(st))
    _git(h0.vm, h0.env, "checkout", "-q", "--detach", c2)
    base = {"state": "ok", "rules": [{"name": "sudo-root", "status": "ok"}]}
    (h0.cd / "state.json").write_text(json.dumps({"outcomes": {"v0.4.0": {
        "result": "switching", "from": "v0.3.1", "url": "", "why": "", "at": time.time() - 2, "base": base}},
        "said": {}}))
    h0.heartbeat.parent.mkdir(parents=True, exist_ok=True)
    h0.heartbeat.write_text("now")
    res = h0.run(FAKE_RULES_OUT=_rules(BROKEN), FAKE_RULES_RC="1")
    assert "reprise" in res.stdout and res.returncode == 1
    assert h0.running() == {"v0.3.1"} and h0.outcome("v0.4.0") == "rolled back"


# The agent, imported as a module (its functions alone): sys.path is put back after.
@pytest.fixture
def agent(monkeypatch):
    import importlib.util
    monkeypatch.setattr(sys, "path", list(sys.path))
    spec = importlib.util.spec_from_file_location("eregion_cd_h2", AGENT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    mod.read_only_errors = lambda since: ([], [])   # no real docker here (V-34's own tests set it)
    return mod


@pytest.mark.parametrize("budget", [3.0, 40.0, 180.0, 900.0])
def test_the_rules_check_fits_in_what_is_left_of_the_health(agent, monkeypatch, budget):
    seen = {}

    def run(args, **kw):
        seen.update(args=args, timeout=kw["timeout"])
        return subprocess.CompletedProcess(args, 0, _rules(_rule("a")), "")
    monkeypatch.setattr(agent.subprocess, "run", run)
    assert agent.run_rules_check(budget, "t")["state"] == "ok"
    total, query = _arg(seen["args"], "--total"), _arg(seen["args"], "--query-timeout")
    assert seen["timeout"] <= budget                                   # within the health
    assert seen["timeout"] <= agent.RULES_S + agent.RULES_MARGIN_S       # and bounded on its own
    assert total <= seen["timeout"] - agent.RULES_MARGIN_S or total <= 0.1
    assert 0 < query <= min(agent.RULE_QUERY_S, total)


@pytest.mark.parametrize("env, want", [
    ({"EREGION_CD_RULES_S": "99999", "EREGION_CD_RULE_QUERY_S": "0"}, (3600, 1)),
    ({"EREGION_CD_RULES_S": "inf", "EREGION_CD_RULE_QUERY_S": "nan"}, (90, 20)),
    ({"EREGION_CD_RULES_S": "x", "EREGION_CD_RULE_QUERY_S": "700"}, (90, 600)),
])
def test_the_rules_settings_stay_within_what_the_command_accepts(monkeypatch, env, want):
    import importlib.util
    monkeypatch.setattr(sys, "path", list(sys.path))
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    spec = importlib.util.spec_from_file_location("eregion_cd_h2_env", AGENT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    assert (mod.RULES_S, mod.RULE_QUERY_S) == want


def test_the_rules_run_once_the_watch_is_healthy_even_at_the_last_look(agent, monkeypatch):
    """The rules run once the containers are healthy — once: healthy only at the health's last
    look, they still run, with the one second run_rules_check grants (then said unproven)."""
    import time
    end = time.monotonic() + 0.15
    budgets = []
    monkeypatch.setattr(agent, "HEALTH_S", 0.15)
    monkeypatch.setattr(agent, "STEP_S", 0.03)
    monkeypatch.setattr(agent, "health_once", lambda ref, since: "" if time.monotonic() >= end else "pas encore")
    monkeypatch.setattr(agent, "run_rules_check", lambda budget, label: budgets.append(budget) or {
        "state": "ok", "rules": [_rule("a")]})
    why, proof = agent.health("v0.4.0", 0.0, rules=True, base={"state": "ok", "rules": []})
    assert why == "" and proof["note"].startswith("règles : 1 sur 1")
    assert len(budgets) == 1 and budgets[0] <= 0.05
    assert agent.health("v0.3.1", 0.0) == ("", {}) and len(budgets) == 1    # the way back: no rule check


def test_the_last_look_comes_after_the_check(agent, monkeypatch):
    """The check took the rest of the health: the containers are looked at once more — a watch
    that died meanwhile is no green health."""
    import time
    looks = iter(["", "eregion-bot : exited, 0 redémarrage(s)"])
    monkeypatch.setattr(agent, "HEALTH_S", 0.05)
    monkeypatch.setattr(agent, "health_once", lambda ref, since: next(looks, "eregion-bot : exited"))
    monkeypatch.setattr(agent, "run_rules_check", lambda budget, label: time.sleep(0.1) or {
        "state": "ok", "rules": [_rule("a")]})
    why, _ = agent.health("v0.4.0", 0.0, rules=True, base=None)
    assert why.startswith("eregion-bot")


def test_a_regression_ends_the_health_at_once(agent, monkeypatch):
    import time
    monkeypatch.setattr(agent, "HEALTH_S", 30)
    monkeypatch.setattr(agent, "health_once", lambda ref, since: "")
    monkeypatch.setattr(agent, "run_rules_check", lambda budget, label: {"state": "ok", "rules": [
        _rule("a", "error", "syntax", code="SYN0002")]})
    started = time.monotonic()
    why, _ = agent.health("v0.4.0", 0.0, rules=True, base={"state": "ok", "rules": [{"name": "a", "status": "ok"}]})
    assert "cassée(s)" in why and time.monotonic() - started < 5   # no need to watch 30 s: H0 goes back now


def test_the_scrub_keeps_what_is_no_host(agent):
    s = agent.scrubbed("LogsQueryStatus.PARTIAL ssh.v2 client_rules.yaml vm-a.internal.example.net example.com")
    assert "LogsQueryStatus.PARTIAL" in s and "ssh.v2" in s and "client\\_rules.yaml" in s
    assert "internal.example.net" not in s and "example.com" not in s


def test_the_commands_json_is_what_the_cd_reads(agent, monkeypatch, tmp_path):
    """The contract, end to end without Docker: `glorfindel rules check --live --json` on a
    fake backend, read and judged by the CD."""
    from click.testing import CliRunner

    import glorfindel.config as config
    import glorfindel.detectors as detectors
    from glorfindel.cli import cli
    from glorfindel.config import GlorfindelConfig, MonitoringBackendConfig

    class Throttled(Exception):
        status_code = 429

    class Backend:
        def run_query(self, query, timespan=None):
            if "BROKEN" in query:
                raise Exception(f'(BadArgumentError) syntax error in workspace {WS} {{"code": "SYN0002"}}')
            if "SLOW" in query:
                raise Throttled("Too Many Requests")
            return []
    monkeypatch.setattr(detectors, "detector_for", lambda source, **kw: Backend())
    monkeypatch.setattr(config, "load_glorfindel_config", lambda *a, **k: GlorfindelConfig(monitoring_backends=[
        MonitoringBackendConfig(name="law-main", type="azure_monitor", workspace_id=WS)]))
    base = tmp_path / "base.yaml"
    rule = "  - name: {}\n    assets: [auto]\n    query: |\n      {}\n"

    def check(*rules):
        base.write_text("rules:\n" + "".join(rule.format(n, q) for n, q in rules))
        res = CliRunner().invoke(cli, ["rules", "check", "--rules", str(base), "--live", "--json"])
        return agent.read_rules_check(res.exit_code, res.stdout, res.stderr)

    before = check(("good", "Syslog | take 1"), ("bad", "Syslog | take 1"))
    after = check(("good", "Syslog | take 1"), ("bad", "BROKEN("), ("slow", "Syslog // SLOW"))
    proof = agent.verdict(after, before)
    assert "« bad »" in proof["why"] and "SYN0002" in proof["why"] and WS not in json.dumps(proof)
    assert "« slow »" in proof["orange"] and "limité (429)" in proof["orange"]


def test_the_installation_carries_chat_text():
    """SEC6's escaping goes to H0 with the agent: install.sh refuses an agent without it."""
    assert "chat_text.py" in (ROOT / "infra" / "glorfindel-host" / "cd" / "install.sh").read_text()
    if shutil.which("make") is None:
        pytest.skip("make not installed")
    res = subprocess.run(["make", "-n", "--no-print-directory", "-C", str(ROOT), "glorfindel-host-cd-install",
                          "HOST_IP=203.0.113.9"], capture_output=True, text=True, timeout=60)
    assert res.returncode == 0 and "glorfindel/chat_text.py" in res.stdout
