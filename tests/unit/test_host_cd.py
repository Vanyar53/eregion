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
        print(st["images"][args[4]]["version"])
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
        for src in (AGENT, ROOT / "infra" / "glorfindel-host" / "deploy.sh", ROOT / "scripts" / "notify_discord.py"):
            shutil.copy(src, self.cd / src.name)
        (self.cd / "discord.env").write_text(
            f"EREGION_DISCORD_WEBHOOK_DEPLOY={fake.base}/api/webhooks/9/{SECRET}\nEREGION_DISCORD_MENTION=42\n")
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


def test_the_main_ci_job_must_have_run(h0):
    h0.fake.gh["checks"][h0.commits["c2"]] = [{"name": "Components", "status": "completed", "conclusion": "success"}]
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
