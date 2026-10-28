#!/usr/bin/env python3
"""eregion_cd — the release Jonathan publishes reaches H0 on its own (H1, #244;
infra/glorfindel-host/README.md, « Le CD de H0 »).

  eregion_cd.py run      the timer's pass (systemd, every 5 min): the latest release, if new,
                         verified, built aside, preflighted, switched to, kept if healthy —
                         else H0 goes back to what ran
  eregion_cd.py check    the same pass up to the preflight, never switching (the first
                         installation, by hand): verified, built, preflighted, said
  eregion_cd.py retry    forget that the latest release failed or was refused, then run
  eregion_cd.py status   what runs, the latest release, the outcomes
  eregion_cd.py export-discord-env   on the operator's machine: #deploy's webhook and the
                         mention, for make glorfindel-host-cd-install (never the bot's token)

The trigger is Jonathan publishing a release (sessions prepare drafts). A pass:
  1. the latest release (GitHub's public API, outbound, no token; drafts and pre-releases are
     not in it); nothing to do when it runs already, or failed or was refused before;
  2. its tag on origin/main, never older than what runs; every check run of its commit
     completed and none red (still running: wait for the next pass, said once);
  3. requirements/glorfindel.txt changed since what runs: requirements/harness.json must match
     the lock (its sha256), H0's model, a complete judgment and no overconfident error;
  4. the candidate eregion-glorfindel:<tag> built in a worktree of its own: the running image
     and the checkout of ~/eregion do not move;
  5. preflight in the candidate: `glorfindel --version` is the tag, the watch, the bot and the
     console import, H0's glorfindel-config.yaml passes A3's strict reading, compose renders;
  6. the switch (deploy.sh --activate), then the health for a few minutes: three containers
     running, never restarted, built from the tag; the watch's heartbeat written after the
     switch; the console answering;
  7. unhealthy: deploy.sh --activate on what ran (its image is kept: a retag) and its health;
     the release is marked failed, never tried again on its own (a new release, or `retry`);
  8. said in #deploy (~/.eregion-cd/discord.env): the start and the success silently; a
     refusal, a rollback, a failed rollback with Jonathan's mention.

Installed in ~/.eregion-cd/ with deploy.sh and notify_discord.py, never run from the checkout it
deploys, and never replaced by a deployment: after one, a release whose agent differs is said
(make glorfindel-host-cd-install). One pass at a time, and none while a deployment by hand runs
(~/.eregion-deploy.lock). Python 3.10 (the VM's), standard library only.
"""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
# Installed next to this file on H0; in the repository (export-discord-env), in scripts/.
sys.path[:0] = [str(HERE), str(HERE.parents[2] / "scripts")]
import notify_discord as nd  # noqa: E402

HOME = Path.home()
CD_HOME = Path(os.environ.get("EREGION_CD_HOME") or HOME / ".eregion-cd")
REPO = Path(os.environ.get("EREGION_CD_REPO") or HOME / "eregion")
SLUG = os.environ.get("EREGION_CD_GITHUB_REPO") or "Vanyar53/eregion"
API = (os.environ.get("EREGION_CD_GITHUB_API") or "https://api.github.com").rstrip("/")
CONSOLE = (os.environ.get("EREGION_CD_CONSOLE") or "http://127.0.0.1:7007").rstrip("/")
HEARTBEAT = Path(os.environ.get("EREGION_CD_HEARTBEAT") or HOME / ".glorfindel" / "watch_heartbeat")
HEALTH_S = float(os.environ.get("EREGION_CD_HEALTH_S") or 180)
STEP_S = float(os.environ.get("EREGION_CD_STEP_S") or 10)
IMAGE = "eregion-glorfindel"
CONTAINERS = ("eregion-watch", "eregion-war-room", "eregion-bot")
VERSION = '{{index .Config.Labels "org.opencontainers.image.version"}}'
LABELS = VERSION + ' {{index .Config.Labels "org.opencontainers.image.revision"}}'
RED = {"failure", "timed_out", "cancelled", "action_required", "startup_failure", "stale"}
LOCK = "requirements/glorfindel.txt"
ATTESTATION = "requirements/harness.json"
AGENT_FILES = {"eregion_cd.py": "infra/glorfindel-host/cd/eregion_cd.py",
               "deploy.sh": "infra/glorfindel-host/deploy.sh",
               "notify_discord.py": "scripts/notify_discord.py"}


class Quiet(Exception):
    """Nothing to do, or nothing to do yet: no message."""


class Refused(Exception):
    """The release will not be deployed: said with the mention, remembered."""


class Unhealthy(Exception):
    """Switched to, and not healthy: H0 goes back."""


# ── tools ────────────────────────────────────────────────────────────────────────────

def sh(*args: str, cwd: Path | None = None, check: bool = True, env: dict | None = None) -> subprocess.CompletedProcess:
    res = subprocess.run(list(args), cwd=cwd, capture_output=True, text=True,
                         env={**os.environ, **(env or {})})
    if check and res.returncode != 0:
        raise subprocess.CalledProcessError(res.returncode, args, res.stdout, res.stderr)
    return res


def tail(res, n: int = 8) -> str:
    text = ((getattr(res, "stderr", "") or "") + "\n" + (getattr(res, "stdout", "") or "")).strip()
    return "\n".join(text.splitlines()[-n:])[:1500]


def git(*args: str, cwd: Path = REPO, check: bool = True) -> subprocess.CompletedProcess:
    return sh("git", *args, cwd=cwd, check=check)


def github(path: str):
    """GitHub's public API, without a token; None for a 404."""
    req = urllib.request.Request(f"{API}/repos/{SLUG}{path}", headers={
        "Accept": "application/vnd.github+json", "User-Agent": "eregion-cd (H0)"})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        raise Quiet(f"GitHub API: HTTP {e.code}") from None
    except Exception as e:  # the network is down: the next pass tries again
        raise Quiet(f"GitHub API: {type(e).__name__}") from None


def env_value(path: Path, key: str) -> str:
    """A key of a compose-style .env: the last line wins, « # … » after a blank is a comment."""
    value = ""
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.startswith(f"{key}="):
                value = re.sub(r"\s+#.*$", "", line.split("=", 1)[1]).strip()
    except OSError:
        pass
    return value


# ── state, lock, messages ────────────────────────────────────────────────────────────

def load_state() -> dict:
    try:
        state = json.loads((CD_HOME / "state.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        state = {}
    state.setdefault("outcomes", {})
    state.setdefault("said", {})
    return state


def save_state(state: dict) -> None:
    tmp = CD_HOME / "state.json.tmp"
    tmp.write_text(json.dumps(state, indent=1, ensure_ascii=False), encoding="utf-8")
    os.replace(tmp, CD_HOME / "state.json")


def say(title: str, text: str = "", *, color: int = nd.GREY, alert: bool = False, url: str = "") -> None:
    """To the terminal or the journal, and to #deploy when its webhook is set."""
    print(f"{title}" + (f"\n{text}" if text else ""), flush=True)
    conf = CD_HOME / "discord.env"
    hook, mention = env_value(conf, "EREGION_DISCORD_WEBHOOK_DEPLOY"), env_value(conf, "EREGION_DISCORD_MENTION")
    if not hook:
        return
    try:
        nd.post_webhook(hook, nd.message(nd.embed(title, text, color, url), silent=not alert,
                                         mention=mention if alert and mention.isdigit() else ""), "webhook #deploy")
    except nd.Failure as e:
        nd.say(e)


def say_once(state: dict, tag: str, kind: str, title: str, text: str = "", **kw) -> None:
    said = state["said"].setdefault(tag, [])
    if kind not in said:
        said.append(kind)
        say(title, text, **kw)


# ── the pass ─────────────────────────────────────────────────────────────────────────

def deployed() -> tuple[str, str]:
    """The reference and the commit the running watch was built from (its image's labels)."""
    res = sh("docker", "inspect", "-f", LABELS, CONTAINERS[0], check=False)
    parts = res.stdout.split() if res.returncode == 0 else []
    parts = [p for p in parts if p != "<no" and p != "value>"]
    return (parts[0], parts[1]) if len(parts) == 2 else ("", "")


def is_ancestor(a: str, b: str) -> bool:
    return git("merge-base", "--is-ancestor", a, b, check=False).returncode == 0


def verify(tag: str, commit: str, dep_commit: str, state: dict) -> None:
    if not is_ancestor(commit, "refs/remotes/origin/main"):
        raise Refused(f"son tag n'est pas sur main ({commit[:12]}) : seule une release de main se déploie")
    if dep_commit and is_ancestor(commit, dep_commit):
        raise Quiet(f"{tag} est plus ancienne que ce qui tourne ({dep_commit[:12]})")
    runs = (github(f"/commits/{commit}/check-runs?per_page=100") or {}).get("check_runs") or []
    red = sorted({r.get("name", "?") for r in runs if r.get("conclusion") in RED})
    if red:
        raise Refused(f"CI rouge sur {commit[:12]} : {', '.join(red)}")
    if not runs or any(r.get("status") != "completed" for r in runs):
        say_once(state, tag, "ci", f"⏳ {tag} attend sa CI", f"commit {commit[:12]} : pas encore verte, "
                 "le CD repasse toutes les 5 minutes", color=nd.BLUE)
        raise Quiet(f"{tag} : CI en cours")


def h0_model(commit: str) -> str:
    """The model the hosted watch runs: H0's .env, else the default of the release."""
    model = env_value(REPO / ".env", "GLORFINDEL_LLM_MODEL")
    if model:
        return model
    src = git("show", f"{commit}:eregion_core/models.py", check=False).stdout
    m = re.search(r'^DEFAULT_LLM_MODEL\s*=\s*"([^"]+)"', src, re.M)
    return m.group(1) if m else ""


def lock_guard(tag: str, commit: str, dep_commit: str) -> None:
    """A new lock is deployed only with the harness's attestation for it (M-3, H1)."""
    if dep_commit and git("diff", "--quiet", dep_commit, commit, "--", LOCK, check=False).returncode == 0:
        return
    model = h0_model(commit)
    hint = f"make llm-compare MODELS={model or '<modèle de H0>'} RUNS=3 ATTEST=1, dans la PR du verrou"
    raw = git("show", f"{commit}:{ATTESTATION}", check=False)
    if raw.returncode != 0:
        raise Refused(f"{LOCK} a changé depuis ce qui tourne, sans attestation du harnais ({ATTESTATION}) : {hint}")
    try:
        att = json.loads(raw.stdout)
    except ValueError:
        raise Refused(f"{ATTESTATION} illisible : {hint}") from None
    shown = git("show", f"{commit}:{LOCK}", check=False)
    if shown.returncode != 0:
        raise Refused(f"{tag} n'a pas de {LOCK}")
    lock = shown.stdout.encode()
    if att.get("lock_sha256") != hashlib.sha256(lock).hexdigest():
        raise Refused(f"l'attestation du harnais porte sur un autre verrou que celui de {tag} : {hint}")
    entry = next((m for m in att.get("models") or [] if m.get("model") == model), None)
    if entry is None:
        raise Refused(f"l'attestation du harnais ne couvre pas le modèle de H0 ({model}) : {hint}")
    if int(att.get("runs") or 0) < 3:
        raise Refused(f"l'attestation du harnais n'a que {att.get('runs')} run(s), il en faut 3 : {hint}")
    slots = int(entry.get("slots") or 0)
    if not slots or entry.get("integration") != slots or entry.get("judgment") != slots:
        raise Refused(f"le harnais n'est pas complet pour {model} : intégration {entry.get('integration')}/{slots}, "
                      f"jugement {entry.get('judgment')}/{slots}")
    if entry.get("overconfident_errors") != 0:
        raise Refused(f"le harnais compte {entry.get('overconfident_errors')} erreur(s) surconfiante(s) pour {model}")


def build(tag: str, commit: str) -> None:
    """The candidate, from a worktree of its own: nothing that runs moves."""
    work = CD_HOME / "build"
    git("worktree", "remove", "--force", str(work), check=False)
    git("worktree", "prune", check=False)
    made = git("worktree", "add", "-q", "--detach", str(work), commit, check=False)
    if made.returncode != 0:
        raise Refused(f"le worktree de construction n'a pas pu être fait :\n{tail(made)}")
    res = sh("bash", str(CD_HOME / "deploy.sh"), "--build-only", tag, cwd=work, check=False,
             env={"EREGION_DEPLOY_LOCKED": "1"})
    if res.returncode != 0:
        raise Refused(f"la construction de {IMAGE}:{tag} a échoué :\n{tail(res)}")


def preflight(tag: str) -> None:
    img = f"{IMAGE}:{tag}"
    res = sh("docker", "run", "--rm", img, "glorfindel", "--version", check=False)
    want = tag[1:] if re.fullmatch(r"v\d+\.\d+\.\d+", tag) else ""
    if res.returncode != 0 or (want and want not in res.stdout):
        raise Refused(f"préflight : glorfindel --version ne dit pas {want or tag} :\n{tail(res)}")
    res = sh("docker", "run", "--rm", img, "python", "-c",
             "import glorfindel.cli, glorfindel.bot, eregion_console.api", check=False)
    if res.returncode != 0:
        raise Refused(f"préflight : la watch, le bot ou la console n'importent pas :\n{tail(res)}")
    cfg = REPO / "glorfindel-config.yaml"
    if cfg.exists():
        res = sh("docker", "run", "--rm", "-v", f"{cfg}:/app/glorfindel-config.yaml:ro", img, "python", "-c",
                 "from glorfindel.config import load_glorfindel_config as load; load('/app/glorfindel-config.yaml')",
                 check=False)
        if res.returncode != 0:
            raise Refused(f"préflight : la config de H0 est refusée par la lecture stricte d'A3 "
                          f"(la watch sortirait en 2) :\n{tail(res)}")
    envfile = ["--env-file", str(REPO / ".env")] if (REPO / ".env").exists() else []
    res = sh("docker", "compose", "-f", str(CD_HOME / "build" / "docker-compose.yml"), "--project-directory",
             str(REPO), *envfile, "--profile", "bot", "config", "-q", check=False)
    if res.returncode != 0:
        raise Refused(f"préflight : docker compose refuse le fichier de {tag} avec le .env de H0 :\n{tail(res)}")


def keep_the_way_back(ref: str) -> None:
    """The image running now, tagged by its reference: a deployment from before H1 left it as
    `eregion-glorfindel` only, and without its tag going back would have nothing to retag."""
    if not ref or sh("docker", "image", "inspect", f"{IMAGE}:{ref}", check=False).returncode == 0:
        return
    label = sh("docker", "image", "inspect", "-f", VERSION, IMAGE, check=False)
    if label.returncode == 0 and label.stdout.strip() == ref:
        sh("docker", "tag", IMAGE, f"{IMAGE}:{ref}", check=False)


def activate(ref: str) -> None:
    res = sh("bash", str(CD_HOME / "deploy.sh"), "--activate", ref, cwd=REPO, check=False,
             env={"EREGION_DEPLOY_LOCKED": "1"})
    if res.returncode != 0:
        raise Unhealthy(f"deploy.sh --activate {ref} a échoué :\n{tail(res)}")


def health_once(ref: str, since: float) -> str:
    """'' when healthy, else why not."""
    for name in CONTAINERS:
        res = sh("docker", "inspect", "-f", "{{.State.Status}} {{.RestartCount}} " + VERSION, name, check=False)
        parts = res.stdout.split()
        if res.returncode != 0 or len(parts) < 3:
            return f"{name} absent"
        if parts[0] != "running" or parts[1] != "0":
            return f"{name} : {parts[0]}, {parts[1]} redémarrage(s)"
        if parts[2] != ref:
            return f"{name} tourne sur {parts[2]}, pas {ref}"
    try:
        if HEARTBEAT.stat().st_mtime < since:
            return "la watch n'a pas battu depuis la bascule"
    except OSError:
        return "aucun battement de la watch"
    token = env_value(REPO / ".env", "EREGION_CONSOLE_TOKEN") or env_value(REPO / ".env", "GLORFINDEL_WARROOM_TOKEN")
    req = urllib.request.Request(f"{CONSOLE}/api/sections",
                                 headers={"Authorization": f"Bearer {token}"} if token else {})
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            if r.status != 200:
                return f"la console répond {r.status}"
    except Exception as e:
        return f"la console ne répond pas ({getattr(e, 'code', type(e).__name__)})"
    return ""


def health(ref: str, since: float) -> str:
    """Watched for HEALTH_S: '' when healthy at the end, else the last reason."""
    deadline = time.monotonic() + HEALTH_S
    why = health_once(ref, since)
    while time.monotonic() < deadline:
        time.sleep(STEP_S)
        why = health_once(ref, since)
    return why


def agent_drift(tag: str) -> list[str]:
    """The agent's files that differ from the release just deployed."""
    out = []
    for local, path in AGENT_FILES.items():
        theirs = git("show", f"refs/tags/{tag}:{path}", check=False)
        try:
            ours = (CD_HOME / local).read_text(encoding="utf-8")
        except OSError:
            ours = ""
        if theirs.returncode == 0 and theirs.stdout != ours:
            out.append(local)
    return out


def run_pass(check: bool = False) -> int:
    state = load_state()
    release = github("/releases/latest")
    if not release:
        raise Quiet("aucune release publiée")
    tag, url = str(release.get("tag_name") or ""), str(release.get("html_url") or "")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", tag):
        raise Quiet(f"tag de release illisible : {tag!r}")
    done = state["outcomes"].get(tag, {}).get("result")
    if not check and done in ("refused", "rolled back", "rollback failed"):
        raise Quiet(f"{tag} : {done} (make glorfindel-host-cd-retry pour réessayer)")
    try:
        git("fetch", "-q", "--tags", "--force", "origin")
    except subprocess.CalledProcessError as e:   # the network: the next pass tries again
        raise Quiet(f"git fetch : {tail(e, 2)}") from None
    commit = git("rev-parse", "-q", "--verify", f"refs/tags/{tag}^{{commit}}", check=False).stdout.strip()
    if not commit:
        raise Quiet(f"{tag} : tag introuvable après git fetch")
    dep_ref, dep_commit = deployed()
    if commit == dep_commit:
        if check:
            print(f"✓ {tag} tourne déjà sur H0 ({commit[:12]})")
        raise Quiet(f"{tag} tourne déjà")
    try:
        verify(tag, commit, dep_commit, state)
        lock_guard(tag, commit, dep_commit)
        if not check:
            say(f"🚀 H0 : déploiement de {tag}", f"{dep_ref or 'inconnu'} → {tag} ({commit[:12]})", color=nd.BLUE, url=url)
        build(tag, commit)
        preflight(tag)
    except Refused as e:
        if check:
            say(f"⛔ À blanc : {tag} serait refusée", str(e), color=nd.RED)
            return 1
        state["outcomes"][tag] = {"result": "refused", "why": str(e), "at": int(time.time())}
        say(f"⛔ {tag} refusée : H0 reste sur {dep_ref or 'ce qui tourne'}", str(e), color=nd.RED, alert=True, url=url)
        return 1
    finally:
        save_state(state)
    if check:
        say(f"✅ À blanc : {tag} est prête", f"vérifiée, construite, préflight passé ; H0 reste sur {dep_ref}. "
            "make glorfindel-host-cd-enable pour que le CD la déploie.", color=nd.GREEN, url=url)
        return 0
    started, since = time.monotonic(), time.time()
    keep_the_way_back(dep_ref)
    try:
        activate(tag)
        why = health(tag, since)
        if why:
            raise Unhealthy(why)
    except Unhealthy as e:
        back = rollback(dep_ref)
        state["outcomes"][tag] = {"result": "rollback failed" if back else "rolled back", "why": str(e),
                                  "at": int(time.time())}
        save_state(state)
        if back:
            say(f"🔥 {tag} malade, et le retour à {dep_ref or '?'} aussi", f"{e}\nretour : {back}\n"
                "H0 est à regarder : make glorfindel-host-status", color=nd.RED, alert=True, url=url)
        else:
            say(f"↩️ {tag} malade : H0 est revenu sur {dep_ref}", str(e), color=nd.ORANGE, alert=True, url=url)
        return 1
    state["outcomes"][tag] = {"result": "deployed", "why": "", "at": int(time.time())}
    save_state(state)
    say(f"✅ H0 tourne sur {tag}", f"{commit[:12]} · {int(time.monotonic() - started)} s, santé verte "
        f"pendant {int(HEALTH_S)} s", color=nd.GREEN, url=url)
    drift = agent_drift(tag)
    if drift:
        say(f"🔧 Agent de CD à mettre à jour ({tag})", f"diffèrent de la release : {', '.join(drift)} — "
            "make glorfindel-host-cd-install", color=nd.ORANGE)
    return 0


def rollback(ref: str) -> str:
    """'' when H0 is back on `ref` and healthy, else why not."""
    if not ref:
        return "aucune référence précédente connue"
    since = time.time()
    try:
        activate(ref)
    except Unhealthy as e:
        return str(e)
    return health(ref, since)


def locked(fn):
    """One pass at a time, and none while a deployment by hand runs (deploy.sh's lock)."""
    with open(HOME / ".eregion-deploy.lock", "a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            print("un déploiement est en cours : ce passage s'efface")
            return 0
        return fn()


def status() -> int:
    state = load_state()
    ref, commit = deployed()
    print(f"  tourne : {ref or 'inconnu'} ({commit[:12]})")
    try:
        release = github("/releases/latest") or {}
        print(f"  dernière release : {release.get('tag_name', 'aucune')}")
    except Quiet as e:
        print(f"  dernière release : illisible ({e})")
    for tag, o in sorted(state["outcomes"].items(), key=lambda kv: kv[1].get("at", 0))[-5:]:
        print(f"  {tag} : {o['result']}" + (f" — {o['why'].splitlines()[0]}" if o.get("why") else ""))
    return 0


def export_discord_env() -> int:
    """On the operator's machine: the two values the CD needs, never the bot's token."""
    cfg = nd.load_config()
    if not cfg.deploy:
        print("EREGION_DISCORD_WEBHOOK_DEPLOY manque (environnement ou ~/.config/eregion/discord.env) : "
              "créer le webhook de #deploy (docs/atelier-discord.md)", file=sys.stderr)
        return 1
    print(f"EREGION_DISCORD_WEBHOOK_DEPLOY={cfg.deploy}")
    if cfg.mention:
        print(f"EREGION_DISCORD_MENTION={cfg.mention}")
    return 0


def main(argv: list[str]) -> int:
    mode = argv[0] if argv else "run"
    if mode == "export-discord-env":
        return export_discord_env()
    if mode == "status":
        return status()
    if mode not in ("run", "check", "retry"):
        print(__doc__)
        return 2
    CD_HOME.mkdir(parents=True, exist_ok=True)

    def one() -> int:
        if mode == "retry":
            state = load_state()
            state["outcomes"].clear()
            state["said"].clear()
            save_state(state)
        try:
            return run_pass(check=mode == "check")
        except Quiet as e:
            print(f"· {e}")
            return 0
    return locked(one)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
