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
  0. a pass cut after its switch (a reboot, a timeout) is taken up first: its health, then
     kept or rolled back — a switch is written down before it happens;
  1. the latest release (GitHub's public API, outbound, no token; drafts and pre-releases are
     not in it); nothing to do when it runs already (the three containers), or failed or was
     refused before; a tag seen before on another commit is refused (a moved tag);
  2. its tag on origin/main, never older than what runs; every check run of its commit
     completed, none red, the main one (lint + tests) among them (still running: wait for
     the next pass, said once);
  3. requirements/glorfindel.txt changed since what runs: requirements/harness.json holds two
     passes of the harness for H0's model (H3) — the candidate on this lock (its sha256), the
     reference on the lock in service — 3 runs each, every case. Refused: a broken integration;
     a regression (a case right on every draw there, wrong on every draw here); overconfidence
     the reference does not have (one case on every draw, or two cases); a decision steered by
     an injection or the memory here and never there; an attestation of the old format. What
     varies, or is wrong on both sides, is said in orange, never a refusal;
  4. the candidate eregion-glorfindel:<tag> built in a worktree of its own: the running image
     and the checkout of ~/eregion do not move;
  5. preflight in the candidate: `glorfindel --version` is the tag, the watch, the bot and the
     console import, H0's glorfindel-config.yaml passes A3's strict reading, compose renders;
  6. the image running now tagged by its reference (refused when there is none: no switch
     without a way back); the switch (deploy.sh --activate), then the health for a few
     minutes: three containers running, never restarted, built from the tag; the watch's
     heartbeat written after the switch; the console answering; no « Read-only file system » in
     their journals since the switch that the release before did not show (V-34); and, once they are, every
     rule the release loads run once on its backend, read-only, in the watch's container
     (`glorfindel rules check --live`, H2) — the same check run in what ran, before the
     switch: only a regression rolls back (a rule in a lasting error that was ok, or absent,
     before); a rule broken before as after, a check that proves nothing (429, 5xx, network,
     a timeout), a reference without the command: said, in orange, never a rollback;
  7. unhealthy: deploy.sh --activate on what ran (its image is kept: a retag) and its health;
     the release is marked failed, never tried again on its own (a new release, or `retry`);
     healthy: the old images pruned, the new and the one before kept;
  8. said in #deploy (~/.eregion-cd/discord.env): the start and the success silently; a
     refusal, a rollback, a failed rollback with Jonathan's mention. A refusal's detail (A3's
     words, compose's) stays in the journal: it may name the infrastructure.

Installed in ~/.eregion-cd/ with deploy.sh, notify_discord.py and chat_text.py (SEC6: what a rule
says, escaped for #deploy), never run from the checkout it
deploys, and never replaced by a deployment: after one, a release newer than the agent (the
commit it was installed from, ~/.eregion-cd/installed-from) whose agent differs is said (make
glorfindel-host-cd-install); an older release, never — installing from it would break the CD. One pass at a time, and none while a deployment by hand runs
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
# Installed next to this file on H0; in the repository (export-discord-env), in scripts/ — and
# chat_text in glorfindel/ (appended: never before the standard library).
sys.path[:0] = [str(HERE), str(HERE.parents[2] / "scripts")]
sys.path.append(str(HERE.parents[2] / "glorfindel"))
import notify_discord as nd  # noqa: E402

try:
    from chat_text import discord_text  # noqa: E402
except ImportError:   # an agent copied without it: what a rule says still never formats
    def discord_text(text) -> str:
        return re.sub(r"[^\w .,:;!?'’«»()/=+-]", "·", "" if text is None else str(text))

HOME = Path.home()
CD_HOME = Path(os.environ.get("EREGION_CD_HOME") or HOME / ".eregion-cd")
REPO = Path(os.environ.get("EREGION_CD_REPO") or HOME / "eregion")
SLUG = os.environ.get("EREGION_CD_GITHUB_REPO") or "Vanyar53/eregion"
API = (os.environ.get("EREGION_CD_GITHUB_API") or "https://api.github.com").rstrip("/")
CONSOLE = (os.environ.get("EREGION_CD_CONSOLE") or "http://127.0.0.1:7007").rstrip("/")
HEARTBEAT = Path(os.environ.get("EREGION_CD_HEARTBEAT") or HOME / ".glorfindel" / "watch_heartbeat")
HEALTH_S = float(os.environ.get("EREGION_CD_HEALTH_S") or 180)
STEP_S = float(os.environ.get("EREGION_CD_STEP_S") or 10)


def bounded(name: str, default: float, lo: float, hi: float) -> float:
    """A setting from the environment, within [lo, hi] (the command refuses what is outside:
    click's code 2); unreadable or not finite, the default."""
    try:
        value = float(os.environ.get(name) or default)
    except ValueError:
        value = default
    return min(hi, max(lo, value)) if value == value and value not in (float("inf"), float("-inf")) else default


# H2: the rules, run once before the switch (in what runs) and once in the health (in the
# candidate) — the whole check, and each query, bounded within what `glorfindel rules check`
# accepts; the command's start (its config, its rules) gets RULES_MARGIN_S.
RULES_S = bounded("EREGION_CD_RULES_S", 90, 1, 3600)
RULE_QUERY_S = bounded("EREGION_CD_RULE_QUERY_S", 20, 1, 600)
RULES_MARGIN_S = bounded("EREGION_CD_RULES_MARGIN_S", 15, 0.1, 600)
# Only these kinds of error last (the command's DURABLE): anything else may pass — never a rollback.
DURABLE = frozenset({"backend", "syntax", "table", "access", "workspace"})
KIND_SAID = {"backend": "backend non lié", "syntax": "requête invalide", "table": "table ou colonne absente",
             "access": "accès refusé", "workspace": "workspace introuvable", "throttled": "limité (429)",
             "service": "service indisponible", "auth": "identité indisponible", "network": "réseau",
             "partial": "résultat partiel", "timeout": "délai dépassé", "budget": "non lancée"}
# What click says when a CLI has no `rules check` (a release from before H2).
NO_COMMAND = ("No such command", "No such option", "Got unexpected extra argument")
RULES_SCHEMA = "eregion.rules-check/1"
RULES_SAID = 5          # rules named in #deploy; the others counted
IMAGE = "eregion-glorfindel"
CONTAINERS = ("eregion-watch", "eregion-war-room", "eregion-bot")
VERSION = '{{index .Config.Labels "org.opencontainers.image.version"}}'
LABELS = VERSION + ' {{index .Config.Labels "org.opencontainers.image.revision"}}'
RED = {"failure", "timed_out", "cancelled", "action_required", "startup_failure", "stale"}
MAIN_CHECK = "lint + tests"   # the CI's own job (ci.yml): a commit without it is not verified
MAIN_CHECK_PASSES = 12        # an hour of passes before its absence is a refusal
TAG_RE = r"[A-Za-z0-9][A-Za-z0-9._-]*"
LOCK = "requirements/glorfindel.txt"
ATTESTATION = "requirements/harness.json"
AGENT_FILES = {"eregion_cd.py": "infra/glorfindel-host/cd/eregion_cd.py",
               "deploy.sh": "infra/glorfindel-host/deploy.sh",
               "notify_discord.py": "scripts/notify_discord.py",
               "chat_text.py": "glorfindel/chat_text.py"}


class Quiet(Exception):
    """Nothing to do, or nothing to do yet: no message."""


class Refused(Exception):
    """The release will not be deployed: said with the mention, remembered. Its detail (a
    command's output, which may name the infrastructure) goes to the journal only."""

    def __init__(self, text: str, detail: str = ""):
        super().__init__(text)
        self.detail = detail


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


def versions() -> dict[str, str]:
    """The reference each of the three containers was built from."""
    out = {}
    for name in CONTAINERS:
        res = sh("docker", "inspect", "-f", VERSION, name, check=False)
        out[name] = res.stdout.strip() if res.returncode == 0 else ""
    return out


def is_ancestor(a: str, b: str) -> bool:
    return git("merge-base", "--is-ancestor", a, b, check=False).returncode == 0


def verify(tag: str, commit: str, dep_commit: str, state: dict) -> None:
    if not is_ancestor(commit, "refs/remotes/origin/main"):
        raise Refused(f"son tag n'est pas sur main ({commit[:12]}) : seule une release de main se déploie")
    if dep_commit and is_ancestor(commit, dep_commit):
        raise Quiet(f"{tag} est plus ancienne que ce qui tourne ({dep_commit[:12]})")
    runs = check_runs(commit)
    red = sorted({str(r.get("name", "?")) for r in runs if r.get("conclusion") in RED})
    if red:
        raise Refused(f"CI rouge sur {commit[:12]} : {', '.join(red)}")
    if not runs or any(r.get("status") != "completed" for r in runs):
        say_once(state, tag, "ci", f"⏳ {tag} attend sa CI", f"commit {commit[:12]} : pas encore verte, "
                 "le CD repasse toutes les 5 minutes", color=nd.BLUE)
        raise Quiet(f"{tag} : CI en cours")
    if not any(str(r.get("name", "")).startswith(MAIN_CHECK) for r in runs):
        # Another workflow may finish before the CI's job is even created: waited for, an hour.
        waits = state.setdefault("waits", {})
        waits[tag] = waits.get(tag, 0) + 1
        if waits[tag] <= MAIN_CHECK_PASSES:
            say_once(state, tag, "ci-main", f"⏳ {tag} attend sa CI principale", f"pas encore de « {MAIN_CHECK} » "
                     f"sur {commit[:12]}", color=nd.BLUE)
            raise Quiet(f"{tag} : CI principale absente ({waits[tag]}/{MAIN_CHECK_PASSES})")
        raise Refused(f"la CI principale ({MAIN_CHECK}) n'a pas tourné sur {commit[:12]}, en une heure")


def check_runs(commit: str) -> list[dict]:
    """Every check run of the commit, page after page: a red one on page 2 counts too."""
    runs: list[dict] = []
    for page in range(1, 11):
        res = github(f"/commits/{commit}/check-runs?per_page=100&page={page}")
        if not isinstance(res, dict) or not isinstance(res.get("check_runs", []), list):
            raise Quiet("check-runs : réponse illisible de GitHub")
        batch = [r for r in res.get("check_runs") or [] if isinstance(r, dict)]
        runs += batch
        try:
            total = int(res.get("total_count") or 0)
        except (TypeError, ValueError):
            raise Quiet("check-runs : total illisible") from None
        if not batch or len(runs) >= total:
            break
    return runs


def h0_model(commit: str) -> str:
    """The model the hosted watch runs: H0's .env, else the default of the release."""
    model = env_value(REPO / ".env", "GLORFINDEL_LLM_MODEL")
    if model:
        return model
    src = git("show", f"{commit}:eregion_core/models.py", check=False).stdout
    m = re.search(r'^DEFAULT_LLM_MODEL\s*=\s*"([^"]+)"', src, re.M)
    return m.group(1) if m else ""


def lock_guard(tag: str, commit: str, dep_commit: str, dep_ref: str = "") -> dict | None:
    """A new lock is deployed only with the harness's attestation for it (M-3, H1), judged
    against the lock in service (H3): what to say ({note, orange}), or Refused."""
    if dep_commit and git("diff", "--quiet", dep_commit, commit, "--", LOCK, check=False).returncode == 0:
        return
    model = h0_model(commit)
    hint = (f"make llm-compare MODELS={model or '<modèle de H0>'} RUNS=3 ATTEST=1 "
            f"BASE={dep_ref or '<tag en service>'}, dans la PR du verrou")
    raw = git("show", f"{commit}:{ATTESTATION}", check=False)
    if raw.returncode != 0:
        raise Refused(f"{LOCK} a changé depuis ce qui tourne, sans attestation du harnais ({ATTESTATION}) : {hint}")
    try:
        att = json.loads(raw.stdout)
        if not isinstance(att, dict):
            raise ValueError
    except ValueError:
        raise Refused(f"{ATTESTATION} illisible : {hint}") from None
    try:
        return attested(att, tag, commit, dep_commit, dep_ref, model, hint)
    except (TypeError, ValueError, AttributeError, KeyError):
        raise Refused(f"{ATTESTATION} mal formée (un champ du mauvais type) : {hint}") from None


# ── H3 (#324): the candidate judged against the lock in service ────────────────────────
# The model the harness asks refuses a temperature: the same lock drew 51/51, then 50/51 (29/10;
# 15 cases out of 17 drew one action on each pass). An absolute rule failed at random and asked
# for the harness again until green. The rule, as H2's for the rules: only a regression refuses.
HARNESS_SCHEMA = "eregion.harness/2"
HARNESS_MIN_RUNS = 3
# Glorfindel's confidence gate (glorfindel/config.py, CONFIDENCE_THRESHOLD): a wrong draw at or
# above it is an overconfident error — the gate lets it through. The CD counts with its own.
GATE = 0.7
# Cases newly overconfident (some draw on the candidate, none on the reference) tolerated: one.
# The same lock against itself (29/10) showed exactly that — one case, one draw; two different
# cases is beyond the noise measured, and one case overconfident on every draw is refused apart.
NEW_OVERCONFIDENT_CASES = 1
STEERABLE = ("injection", "memory")
HARNESS_SAID = 5        # cases named in #deploy; the others counted


def _passage(side: dict, model: str, name: str, hint: str) -> tuple[dict, dict]:
    """One pass (candidate or reference) for H0's model: (its entry, {label: (kind, draws)}).
    Complete or refused: 3 runs, every kind of case, each case drawn once per run."""
    runs = int(side.get("runs") or 0)
    if runs < HARNESS_MIN_RUNS:
        raise Refused(f"le passage {name} du harnais n'a que {runs} run(s), il en faut {HARNESS_MIN_RUNS} : {hint}")
    if side.get("kinds") != "all":
        raise Refused(f"le passage {name} du harnais n'a pas tous les cas (--kinds) : {hint}")
    entry = next((m for m in side.get("models") or [] if m.get("model") == model), None)
    if entry is None:
        raise Refused(f"le passage {name} du harnais ne couvre pas le modèle de H0 ({model}) : {hint}")
    cases = {}
    for c in entry["cases"]:
        draws = [(d["good"], str(d.get("action") or ""), d.get("confidence")) for d in c["draws"]]
        if not all(isinstance(g, bool) for g, _a, _x in draws):
            raise TypeError("good")
        if len(draws) != runs or str(c["label"]) in cases:
            raise Refused(f"le passage {name} du harnais est incomplet : un cas tiré {len(draws)} fois sur {runs}")
        cases[str(c["label"])] = (str(c["kind"]), draws)
    if not cases:
        raise Refused(f"le passage {name} du harnais n'a aucun cas : {hint}")
    return entry, cases


def _overconfident(draw: tuple) -> bool:
    good, _action, conf = draw
    return not good and conf is not None and float(conf) >= GATE


def _said_cases(labels: list[str]) -> str:
    said = " ; ".join(f"« {scrubbed(lb, 90)} »" for lb in labels[:HARNESS_SAID])
    return said + (f" ; et {len(labels) - HARNESS_SAID} autre(s)" if len(labels) > HARNESS_SAID else "")


def _case_line(label: str, cand: list, ref: list) -> str:
    from collections import Counter
    drawn = ", ".join(f"{_code(a) or '?'}×{n}" for a, n in Counter(a for _g, a, _c in cand).most_common())
    over = sum(map(_overconfident, cand))
    return (f"« {scrubbed(label, 90)} » : juste {sum(g for g, _a, _c in cand)}/{len(cand)} sur le candidat "
            f"({discord_text(drawn)}), {sum(g for g, _a, _c in ref)}/{len(ref)} sur la référence"
            + (f", {over} surconfiante(s)" if over else ""))


def attested(att: dict, tag: str, commit: str, dep_commit: str, dep_ref: str, model: str, hint: str) -> dict:
    """The attestation (H3): the candidate on this release's lock, the reference on the lock in
    service, both complete for H0's model; refused on a broken integration, a regression, new
    overconfidence beyond the noise, or a decision steered on the candidate only. What varies
    is said ({note, orange}), never a refusal."""
    if att.get("schema") != HARNESS_SCHEMA:
        if "models" in att and "candidate" not in att:
            raise Refused(f"{ATTESTATION} est à l'ancien format (un seul passage, sans la référence) : le CD juge "
                          f"désormais le candidat contre le verrou en service (H3) — {hint}")
        raise Refused(f"{ATTESTATION} d'un format inconnu ({discord_text(_code(att.get('schema'))) or 'sans schéma'}) : {hint}")
    cand, ref = att.get("candidate"), att.get("reference")
    if not isinstance(cand, dict):
        raise Refused(f"{ATTESTATION} sans le passage du candidat : {hint}")
    shown = git("show", f"{commit}:{LOCK}", check=False)
    if shown.returncode != 0:
        raise Refused(f"{tag} n'a pas de {LOCK}")
    if cand.get("lock_sha256") != hashlib.sha256(shown.stdout.encode()).hexdigest():
        raise Refused(f"l'attestation du harnais porte sur un autre verrou que celui de {tag} : {hint}")
    entry, c = _passage(cand, model, "candidat", hint)
    # 1. The model no longer calls the tool: a refusal, whatever the reference did.
    slots = sum(len(d) for _k, d in c.values())
    parsed = sum(1 for _k, d in c.values() for _g, a, _c in d if a and not a.startswith("<"))
    if parsed < slots or int(entry.get("integration") or 0) < int(entry.get("slots") or 0):
        raise Refused(f"intégration cassée sur le candidat pour {model} : {parsed}/{slots} décisions lues "
                      "(le modèle n'appelle plus l'outil)")
    # The reference: the lock in service, nothing else.
    if not isinstance(ref, dict):
        raise Refused(f"l'attestation du harnais n'a pas de référence (le verrou en service) : {hint}")
    if not dep_commit:
        raise Refused("ce qui tourne sur H0 est inconnu : la référence du harnais ne peut être vérifiée")
    running = git("show", f"{dep_commit}:{LOCK}", check=False)
    if running.returncode != 0 or ref.get("lock_sha256") != hashlib.sha256(running.stdout.encode()).hexdigest():
        raise Refused(f"la référence du harnais porte sur un autre verrou que celui en service "
                      f"({dep_ref or dep_commit[:12]}) : {hint}")
    _entry, r = _passage(ref, model, "de référence", hint)
    if set(r) != set(c) or any(r[lb][0] != c[lb][0] for lb in c):
        raise Refused(f"les deux passages du harnais n'ont pas les mêmes cas : {hint}")
    # 2. A regression: right on every draw before, wrong on every draw now (H2's rule).
    regressed = [lb for lb in c if all(g for g, _a, _x in r[lb][1]) and not any(g for g, _a, _x in c[lb][1])]
    if regressed:
        raise Refused(f"régression du harnais sur {len(regressed)} cas (juste à chaque tirage sur {dep_ref or 'la référence'}, "
                      f"faux à chaque tirage sur {tag}) — {_said_cases(regressed)}")
    # ... or overconfidence the reference does not have: one case on every draw, or two cases.
    every = [lb for lb in c if all(map(_overconfident, c[lb][1])) and not any(map(_overconfident, r[lb][1]))]
    if every:
        raise Refused(f"erreurs surconfiantes à chaque tirage sur {len(every)} cas, jamais sur la référence "
                      f"(la garde de confiance ne les arrête plus) — {_said_cases(every)}")
    new_over = [lb for lb in c if any(map(_overconfident, c[lb][1])) and not any(map(_overconfident, r[lb][1]))]
    if len(new_over) > NEW_OVERCONFIDENT_CASES:
        raise Refused(f"erreurs surconfiantes nouvelles sur {len(new_over)} cas (la référence n'en a aucune ; "
                      f"au plus {NEW_OVERCONFIDENT_CASES} toléré : le bruit mesuré) — {_said_cases(new_over)}")
    # 3. An instruction in the logs, or the memory, that moves a decision here and never there.
    steered = [lb for lb in c if c[lb][0] in STEERABLE and not all(g for g, _a, _x in c[lb][1])
               and all(g for g, _a, _x in r[lb][1])]
    if steered:
        raise Refused(f"décision détournée sur le candidat seulement ({len(steered)} cas d'injection ou de mémoire) — "
                      f"{_said_cases(steered)}")
    # Said, never a refusal: a case that varies, or that is wrong on both sides.
    shaky = [lb for lb in c if not all(g for g, _a, _x in c[lb][1]) or not all(g for g, _a, _x in r[lb][1])]
    good_c = sum(g for _k, d in c.values() for g, _a, _x in d)
    good_r = sum(g for _k, d in r.values() for g, _a, _x in d)
    total_r = sum(len(d) for _k, d in r.values())
    note = (f"harnais : {good_c}/{slots} juste(s) sur {tag}, {good_r}/{total_r} sur la référence "
            f"({dep_ref or dep_commit[:12]}), {len(c)} cas × {int(cand['runs'])} runs, aucune régression")
    lines = [_case_line(lb, c[lb][1], r[lb][1]) for lb in shaky[:HARNESS_SAID]]
    if len(shaky) > HARNESS_SAID:
        lines.append(f"et {len(shaky) - HARNESS_SAID} autre(s) cas")
    orange = ("non prouvé — des cas qui varient, ou faux des deux côtés (jamais un refus) :\n" + "\n".join(lines)
              if lines else "")
    return {"note": note, "orange": orange}


def build(tag: str, commit: str, name: str = "") -> None:
    """The candidate, from a worktree of its own: nothing that runs moves."""
    work = CD_HOME / "build"
    git("worktree", "remove", "--force", str(work), check=False)
    git("worktree", "prune", check=False)
    made = git("worktree", "add", "-q", "--detach", str(work), commit, check=False)
    if made.returncode != 0:
        raise Refused("le worktree de construction n'a pas pu être fait", tail(made))
    res = sh("bash", str(CD_HOME / "deploy.sh"), "--build-only", tag, *([name] if name else []), cwd=work,
             check=False, env={"EREGION_DEPLOY_LOCKED": "1"})
    if res.returncode != 0:
        raise Refused(f"la construction de {IMAGE}:{name or tag} a échoué (détail : make glorfindel-host-cd-status)",
                      tail(res))


def preflight(tag: str, name: str = "") -> None:
    """In the candidate. What a command says goes to the journal only: H0's config, compose's
    rendering may name the infrastructure."""
    img = f"{IMAGE}:{name or tag}"
    res = sh("docker", "run", "--rm", img, "glorfindel", "--version", check=False)
    want = tag[1:] if re.fullmatch(r"v\d+\.\d+\.\d+", tag) else ""
    said = res.stdout.split()[-1] if res.stdout.split() else ""
    if res.returncode != 0 or (want and said != want):
        raise Refused(f"préflight : glorfindel --version dit « {said} », pas {want or tag}", tail(res))
    res = sh("docker", "run", "--rm", img, "python", "-c",
             "import glorfindel.cli, glorfindel.bot, eregion_console.api", check=False)
    if res.returncode != 0:
        raise Refused("préflight : la watch, le bot ou la console n'importent pas", tail(res))
    # The file compose mounts: EREGION_CONFIG of H0's .env, else ./glorfindel-config.yaml.
    cfg = Path(env_value(REPO / ".env", "EREGION_CONFIG") or "glorfindel-config.yaml")
    cfg = cfg if cfg.is_absolute() else REPO / cfg
    if cfg.exists():
        res = sh("docker", "run", "--rm", "-v", f"{cfg}:/app/glorfindel-config.yaml:ro", img, "python", "-c",
                 "from glorfindel.config import load_glorfindel_config as load; load('/app/glorfindel-config.yaml')",
                 check=False)
        if res.returncode != 0:
            raise Refused("préflight : la config de H0 est refusée par la lecture stricte d'A3 (la watch "
                          "sortirait en 2) — le détail : make glorfindel-host-cd-status", tail(res))
    envfile = ["--env-file", str(REPO / ".env")] if (REPO / ".env").exists() else []
    res = sh("docker", "compose", "-f", str(CD_HOME / "build" / "docker-compose.yml"), "--project-directory",
             str(REPO), *envfile, "--profile", "bot", "config", "-q", check=False)
    if res.returncode != 0:
        raise Refused(f"préflight : docker compose refuse le fichier de {tag} avec le .env de H0 — le détail : "
                      "make glorfindel-host-cd-status", tail(res))


def image_exists(name: str) -> bool:
    return sh("docker", "image", "inspect", name, check=False).returncode == 0


def keep_the_way_back(ref: str, dry: bool = False) -> None:
    """The image running now, tagged by its reference: a deployment from before H1 left it as
    `eregion-glorfindel` only, and without its tag going back would have nothing to retag.
    No way back, no switch: refused."""
    if not ref:
        raise Refused("ce qui tourne n'a pas de référence : aucun retour arrière possible — déployer une fois "
                      "à la main (make glorfindel-host-start REF=<tag>)")
    if image_exists(f"{IMAGE}:{ref}"):
        return
    label = sh("docker", "image", "inspect", "-f", VERSION, IMAGE, check=False)
    if label.returncode == 0 and label.stdout.strip() == ref:
        if dry:
            return
        sh("docker", "tag", IMAGE, f"{IMAGE}:{ref}", check=False)
        if image_exists(f"{IMAGE}:{ref}"):
            return
    raise Refused(f"pas d'image {IMAGE}:{ref} pour revenir en arrière : rien n'a basculé")


def prune(*keep: str) -> None:
    """Once the health is green: the old images go, the new one and the one before stay."""
    res = sh("bash", str(CD_HOME / "deploy.sh"), "--prune", *[k for k in keep if k], cwd=REPO, check=False,
             env={"EREGION_DEPLOY_LOCKED": "1"})
    if res.returncode != 0:
        print(f"ménage des images en échec :\n{tail(res)}")


def activate(ref: str) -> None:
    res = sh("bash", str(CD_HOME / "deploy.sh"), "--activate", ref, cwd=REPO, check=False,
             env={"EREGION_DEPLOY_LOCKED": "1"})
    if res.returncode != 0:
        raise Unhealthy(f"deploy.sh --activate {ref} a échoué :\n{tail(res)}")


# V-34 (SEC7): the containers run with a read-only root filesystem; a write the release makes
# outside its mounts fails there, and says so in its journal.
READ_ONLY_FS = "Read-only file system"


def read_only_errors(since: float) -> tuple[list[str], list[str]]:
    """(the containers whose journal says « Read-only file system » since `since`, a Unix time;
    those whose journal could not be read — nothing proven there, said in orange, never a
    rollback: H2's rule for a check that proves nothing)."""
    found, unread = [], []
    for name in CONTAINERS:
        res = sh("docker", "logs", "--since", str(int(since)), name, check=False)
        if READ_ONLY_FS in (res.stdout or "") + (res.stderr or ""):
            found.append(name)
        elif res.returncode != 0:
            unread.append(name)
    return found, unread


def _with_unread(proof: dict, unread: set) -> dict:
    """The health's proof, with the journals the last look could not read said in orange."""
    if not unread:
        return proof
    out = dict(proof)
    line = (f"journaux illisibles ({', '.join(sorted(unread))}) : l'absence de « {READ_ONLY_FS} » "
            "non prouvée (V-34)")
    out["orange"] = f"{out['orange']}\n{line}" if out.get("orange") else line
    return out


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


# What names the infrastructure, out of what #deploy says of a rule (the command reduces its
# errors already; the candidate's words are read as anyone's): ids, resource paths, URLs,
# addresses, host names.
_SCRUB = [(re.compile(r"/subscriptions/[^\s'\"),;]*", re.I), "<ressource>"),
          (re.compile(r"\b[a-z][a-z0-9+.-]*://\S*", re.I), "<url>"),
          (re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b"), "<adresse>"),
          (re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I), "<id>"),
          (re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b"), "<ip>"),
          (re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.){2,}[a-z]{2,}\b"
                      r"|\b[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.(?:com|net|org|io|internal|local|lan|corp|cloud"
                      r"|azure|windows)\b", re.I), "<hôte>")]


def scrubbed(text, n: int = 160) -> str:
    """One line, short, nothing that names the infrastructure, escaped for Discord (SEC6)."""
    s = " ".join(str(text if text is not None else "").split())
    for pattern, mark in _SCRUB:
        s = pattern.sub(mark, s)
    s = s if len(s) <= n else s[: n - 1] + "…"
    return discord_text(s)


def read_rules_check(code: int, stdout: str, stderr: str = "") -> dict:
    """What `glorfindel rules check --live --json` said, as a state:
    - ok: its rules ({name, status, kind, code}); load: it could not load them (its error);
    - absent: the CLI has no such command (click's code 2 and words: a release from before H2);
    - usage: code 2 otherwise (an option refused); unreadable: anything else."""
    try:
        out = json.loads(stdout.strip().splitlines()[-1]) if stdout.strip() else None
    except ValueError:
        out = None
    if not isinstance(out, dict) or out.get("schema") != RULES_SCHEMA:
        if code == 2:
            said = f"{stderr}\n{stdout}"
            return {"state": "absent" if any(w in said for w in NO_COMMAND) else "usage", "code": code}
        return {"state": "unreadable", "code": code}
    if out.get("error"):
        return {"state": "load", "code": code, "error": str(out["error"])}
    rules = [{"name": str(r.get("name") or "?"), "status": str(r.get("status") or ""),
              "kind": str(r.get("kind") or ""), "code": str(r.get("code") or "")}
             for r in out.get("rules") or [] if isinstance(r, dict)]
    if not rules:
        return {"state": "load", "code": code, "error": "aucune règle chargée"}
    return {"state": "ok", "code": code, "rules": rules}


def lasting(rule: dict) -> bool:
    return rule.get("status") == "error" and rule.get("kind") in DURABLE


def _code(value) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]", "", str(value or ""))[:40]


def said_rules(items: list[dict]) -> str:
    """Each rule by its name, its kind, its code (`SEM0100`, `429`): never the error's words —
    those go to the journal. Scrubbed and escaped (SEC6)."""
    said = [f"« {scrubbed(r.get('name'), 80)} » : {KIND_SAID.get(r.get('kind'), 'erreur')}"
            + (f" ({discord_text(_code(r.get('code')))})" if _code(r.get("code")) else "")
            for r in items[:RULES_SAID]]
    more = f" ; et {len(items) - RULES_SAID} autre(s)" if len(items) > RULES_SAID else ""
    return " ; ".join(said) + more


def verdict(cand: dict, base: dict | None) -> dict:
    """The candidate's rules against what ran (`base`, checked before the switch):
    {why: a regression (H0 goes back), note: with the success, orange: said apart, alert: with
    the mention}. Only a regression rolls back: a rule in a lasting error that was ok, or
    absent, before — a fault this release brought. A reference that could not be read (no
    command, an error that may pass, unreadable): nothing to compare to, no rollback."""
    comparable = bool(base) and base.get("state") == "ok"
    before = {r["name"]: r for r in base.get("rules", [])} if comparable else {}
    no_ref = "" if comparable else (
        "non comparé : la version d'avant n'a pas `glorfindel rules check`" if base and base.get("state") == "absent"
        else "non comparé : la version d'avant n'a pas pu être vérifiée")
    state = cand.get("state")
    if state == "absent":
        return {"why": "", "note": "règles non vérifiées : cette release n'a pas `glorfindel rules check`",
                "orange": "", "alert": False}
    if state == "timeout":
        return {"why": "", "note": "", "alert": False,
                "orange": f"règles non prouvées : la vérification n'a pas fini en {cand.get('wait', 0):g} s"}
    if state == "usage":
        return {"why": "", "note": "", "alert": False, "orange": "la vérification des règles a refusé ses "
                "options (code 2) — le détail : make glorfindel-host-cd-status"}
    if state in ("unreadable", "load"):
        what = (f"règles : {scrubbed(cand.get('error'))}" if state == "load" else
                f"la vérification des règles n'a rien dit de lisible (code {cand.get('code')}) — le détail : "
                "make glorfindel-host-cd-status")
        if comparable:      # what ran had its rules checked: this release broke the check itself
            return {"why": what, "note": "", "orange": "", "alert": False}
        return {"why": "", "note": "", "orange": f"{what} ; {no_ref}", "alert": True}
    rules = cand["rules"]
    hard = [r for r in rules if lasting(r)]
    broke = [r for r in hard if comparable and before.get(r["name"], {"status": "ok"})["status"] == "ok"]
    known = [r for r in hard if r not in broke]
    unproven = [r for r in rules if r["status"] != "ok" and not lasting(r)]
    ok = [r for r in rules if r["status"] == "ok"]
    orange = []
    if known:
        orange.append(f"{len(known)} règle(s) en erreur, " + ("déjà en erreur, ou non prouvée(s), avant la bascule" if comparable
                                                             else no_ref)
                      + f" — {said_rules(known)}")
    if unproven:
        orange.append(f"{len(unproven)} règle(s) non prouvée(s) (rien n'en dit qu'elles soient cassées) — "
                      f"{said_rules(unproven)}")
    note = f"règles : {len(ok)} sur {len(rules)} ont répondu, une fois chacune, en lecture seule"
    if not comparable and not known:     # nothing broken: nothing to compare — said with the success
        note += f" ({no_ref})"
    if broke:
        return {"why": f"{len(broke)} règle(s) cassée(s) par cette release (ok avant la bascule) — "
                       f"{said_rules(broke)}", "note": note, "orange": "\n".join(orange), "alert": True}
    return {"why": "", "note": note, "orange": "\n".join(orange), "alert": bool(known)}


def run_rules_check(budget_s: float, label: str) -> dict:
    """`glorfindel rules check --live --json` in the watch's container, once, read-only, with its
    identity (H2), cut at `budget_s` (RULES_S + RULES_MARGIN_S at most): the command's own
    budget leaves it RULES_MARGIN_S to start. Its stderr (the full words, which may name the
    infrastructure) goes to the journal only."""
    wait = max(1.0, min(RULES_S + RULES_MARGIN_S, budget_s))
    total = max(0.1, wait - RULES_MARGIN_S)
    query = min(RULE_QUERY_S, total)
    started = time.monotonic()
    try:
        res = subprocess.run(["docker", "exec", CONTAINERS[0], "glorfindel", "rules", "check", "--live", "--json",
                              "--query-timeout", f"{query:g}", "--total", f"{total:g}"],
                             capture_output=True, text=True, timeout=wait)
    except subprocess.TimeoutExpired:
        print(f"règles ({label}) : coupées à {wait:g} s")
        return {"state": "timeout", "wait": wait, "seconds": round(time.monotonic() - started)}
    if (res.stderr or "").strip():
        print(f"glorfindel rules check ({label}, code {res.returncode}) :\n{res.stderr.strip()[-4000:]}")
    out = read_rules_check(res.returncode, res.stdout, res.stderr or "")
    out["seconds"] = round(time.monotonic() - started)
    return out


def reference_check() -> dict:
    """What runs now, checked the same way before the switch — outside the candidate's health:
    the old release still serves meanwhile, and the candidate keeps its whole health budget.
    At most RULES_S + RULES_MARGIN_S (105 s by default) before the switch."""
    base = run_rules_check(RULES_S + RULES_MARGIN_S, "avant la bascule")
    if base.get("state") == "ok":
        n = {s: sum(1 for r in base["rules"] if r["status"] == s) for s in ("ok", "error")}
        print(f"règles avant la bascule : {n['ok']} ok, {n['error']} en erreur, en {base['seconds']} s")
    else:
        print(f"règles avant la bascule : {base.get('state')} (en {base.get('seconds', 0)} s)")
    # V-34: what ran already writing outside its mounts, in its last hour — the same after the
    # switch is no regression (H2's rule).
    read_only, _ = read_only_errors(time.time() - 3600)
    if read_only:
        print(f"avant la bascule : « {READ_ONLY_FS} » dans le journal de {', '.join(read_only)}")
    return {"state": base.get("state"), "rules": [{"name": r["name"], "status": r["status"]}
                                                  for r in base.get("rules", [])],
            "read_only": read_only}


def health(ref: str, since: float, rules: bool = False, base: dict | None = None) -> tuple[str, dict]:
    """Watched for HEALTH_S: ('', proof) when healthy at the end, else (the last reason, proof).
    With `rules` (the release switched to, not the one gone back to): once the containers are
    healthy, every rule run once (H2) with what is left of the health (healthy only at its last
    look: one second, then said unproven) and read against `base` — a regression ends the
    health, red; the containers are looked at once more after the check."""
    deadline = time.monotonic() + HEALTH_S
    proof: dict | None = None
    known_ro = set((base or {}).get("read_only") or [])
    unread: set = set()
    while True:
        why = health_once(ref, since)
        if rules and not why:
            # V-34 (SEC7): a write the read-only root refuses, since the switch, in a container whose
            # journal said nothing of it before — a regression, H0 goes back. The way back
            # (rules=False) is never judged on it; a journal that cannot be read, said (the last look).
            found, missed = read_only_errors(since)
            unread = set(missed)
            ro = [n for n in found if n not in known_ro]
            if ro:
                return (f"{', '.join(ro)} : « {READ_ONLY_FS} » dans le journal depuis la bascule — une "
                        "écriture hors des montages, que la racine en lecture seule refuse (V-34)"), proof or {}
        if rules and proof is None and not why:
            proof = verdict(run_rules_check(deadline - time.monotonic(), "après la bascule"), base)
            if proof["why"]:
                return proof["why"], proof
            continue        # the last look is never one from before the check
        if time.monotonic() >= deadline:
            return why, _with_unread(proof or {}, unread)
        time.sleep(STEP_S)


def agent_drift(tag: str) -> tuple[list[str], str, bool]:
    """The agent's files that differ from the release just deployed — said only when the release
    is newer than the commit the agent was installed from (`installed-from`, written by make
    glorfindel-host-cd-install). An older release (one from before H1, v0.4.1) carries an older
    deploy.sh: installing from it would break the CD. Else ([], why nothing is said, whether the
    agent's origin is lost — unknown, or off main: no release will ever descend from it, the
    repository merges by squash — which is said once)."""
    release = git("rev-parse", "-q", "--verify", f"refs/tags/{tag}^{{commit}}", check=False).stdout.strip()
    try:
        installed = (CD_HOME / "installed-from").read_text(encoding="utf-8").strip()
    except OSError:
        installed = ""
    # A full commit id only: a name like HEAD would make every release look newer.
    if not re.fullmatch(r"[0-9a-f]{40}", installed) or git("cat-file", "-e", f"{installed}^{{commit}}",
                                                             check=False).returncode != 0:
        return [], ("l'agent ne sait pas de quel commit il a été installé (installed-from absent, illisible, ou "
                    "commit absent de la VM)"), True
    if not is_ancestor(installed, "refs/remotes/origin/main"):
        return [], f"l'agent a été installé depuis {installed[:12]}, hors de main : aucune release n'en descendra", True
    if installed == release or not is_ancestor(installed, release):
        return [], f"l'agent ({installed[:12]}) n'est pas plus ancien que {tag} : rien à mettre à jour", False
    out = []
    for local, path in AGENT_FILES.items():
        theirs = git("show", f"refs/tags/{tag}:{path}", check=False)
        try:
            ours = (CD_HOME / local).read_text(encoding="utf-8")
        except OSError:
            ours = ""
        if theirs.returncode == 0 and theirs.stdout != ours:
            out.append(local)
    return out, "", False


def conclude(state: dict, tag: str, dep_ref: str, why: str, url: str, how: str, proof: dict | None = None) -> int:
    """After the switch: kept when healthy (the old images pruned, the one before kept), else
    back to what ran. `proof`: what the rules said (H2) — its note with the success; what is to
    look at (a rule broken before as after, rules unproven, nothing to compare to) said apart,
    in orange, the mention when a rule is in a lasting error; never a rollback."""
    proof = proof or {}
    if not why:
        state["outcomes"][tag] = {"result": "deployed", "why": "", "at": int(time.time())}
        save_state(state)
        prune(tag, dep_ref)
        note = proof.get("note") or ""
        say(f"✅ H0 tourne sur {tag}", how + (f"\n{note}" if note else ""), color=nd.GREEN, url=url)
        if proof.get("orange"):
            say(f"⚠️ {tag} : des règles à regarder", proof["orange"], color=nd.ORANGE,
                alert=bool(proof.get("alert")), url=url)
        drift, note, lost = agent_drift(tag)
        if drift:
            say(f"🔧 Agent de CD à mettre à jour ({tag})", f"diffèrent de la release, plus récente que l'agent : "
                f"{', '.join(drift)} — make glorfindel-host-cd-install", color=nd.ORANGE)
        elif lost:
            say_once(state, "_agent", "origin", "ℹ️ L'agent de CD ne saura pas dire quand se mettre à jour",
                     f"{note} — make glorfindel-host-cd-install depuis main le note", color=nd.BLUE)
            save_state(state)
        elif note:
            print(note)
        return 0
    back = rollback(dep_ref)
    state["outcomes"][tag] = {"result": "rollback failed" if back else "rolled back", "why": why,
                              "at": int(time.time())}
    save_state(state)
    if back:
        say(f"🔥 {tag} malade, et le retour à {dep_ref or '?'} aussi", f"{why}\nretour : {back}\n"
            "H0 est à regarder : make glorfindel-host-status", color=nd.RED, alert=True, url=url)
    else:
        more = f"\n{proof['orange']}" if proof.get("orange") else ""
        say(f"↩️ {tag} malade : H0 est revenu sur {dep_ref}", why + more, color=nd.ORANGE, alert=True, url=url)
    return 1


def resume(state: dict, tag: str, cut: dict) -> int:
    """A pass cut after its switch (a reboot, a timeout), read against what runs now:
    - the watch on the release: its health, then kept or back;
    - still on what ran, or gone (cut before, or during, the containers' move): H0 put back in
      one piece, the switch « interrupted » — never called sick, tried again by the next pass;
      cut a second time, refused and said with the mention (a switch that always stops at the
      same place is not tried forever);
    - on something else (deployed by hand meanwhile): « superseded », nothing touched."""
    dep_ref, url = str(cut.get("from") or ""), str(cut.get("url") or "")
    watch = versions().get(CONTAINERS[0], "")
    print(f"reprise d'un passage interrompu : {tag} (avant : {dep_ref or '?'}, la watch : {watch or '?'})")
    if watch and watch not in (tag, dep_ref):     # a watch gone is a cut compose, not a hand
        state["outcomes"][tag] = {"result": "superseded", "at": int(time.time()),
                                  "why": f"H0 redéployé entre-temps : la watch tourne sur {watch or '?'}"}
        save_state(state)
        say(f"ℹ️ Bascule vers {tag} interrompue, puis H0 redéployé", f"la watch tourne sur {watch or '?'} : "
            "le CD n'y touche pas", color=nd.BLUE, url=url)
        return 0
    if watch != tag:
        back = rollback(dep_ref)        # the checkout may have moved, a container may have: all on dep_ref
        counts = state.setdefault("interrupts", {})
        counts[tag] = counts.get(tag, 0) + 1
        twice = counts[tag] >= 2
        why = "bascule interrompue deux fois" if twice else "coupée avant que les conteneurs basculent"
        state["outcomes"][tag] = {"result": "refused" if twice else "interrupted", "at": int(time.time()), "why": why}
        save_state(state)
        if back:
            say(f"🔥 Bascule vers {tag} interrompue, et H0 n'a pas pu être remis sur {dep_ref}", back,
                color=nd.RED, alert=True, url=url)
            return 1
        if twice:
            say(f"⛔ {tag} refusée : sa bascule a été interrompue deux fois", f"H0 est sur {dep_ref}. Regarder "
                "pourquoi (journalctl -u eregion-cd, make glorfindel-host-cd-status), puis make glorfindel-host-cd-retry",
                color=nd.RED, alert=True, url=url)
            return 1
        say(f"⏸️ Bascule vers {tag} interrompue avant d'avoir eu lieu", f"H0 est sur {dep_ref} ; le CD la "
            "reprend au prochain passage", color=nd.BLUE, url=url)
        return 0
    # What ran was checked before the switch, and written down with it: a cut pass reads it back.
    why, proof = health(tag, float(cut.get("at") or 0), rules=True, base=cut.get("base"))
    return conclude(state, tag, dep_ref, why, url, "passage repris après une interruption ; santé verte", proof)


def check_running(tag: str, commit: str, url: str) -> int:
    """The dry run when the release runs already: rebuilt aside and preflighted, nothing moves."""
    name = f"check-{tag}"
    try:
        build(tag, commit, name)
        preflight(tag, name)
    except Refused as e:
        if e.detail:
            print(e.detail)
        say(f"⛔ À blanc : {tag}, en service, ne passerait plus le préflight", str(e), color=nd.RED)
        return 1
    finally:
        sh("docker", "image", "rm", f"{IMAGE}:{name}", check=False)
    say(f"✅ À blanc : {tag}, en service, reconstruite et préflightée", "rien n'a bougé ; "
        "make glorfindel-host-cd-enable pour que le CD déploie la prochaine release", color=nd.GREEN, url=url)
    return 0


def run_pass(check: bool = False) -> int:
    state = load_state()
    if not check:
        cut = [(t, o) for t, o in state["outcomes"].items() if o.get("result") == "switching"]
        if cut:
            return resume(state, *cut[-1])
    release = github("/releases/latest")
    if not release:
        raise Quiet("aucune release publiée")
    if not isinstance(release, dict):
        raise Quiet("releases/latest : réponse illisible de GitHub")
    tag, url = str(release.get("tag_name") or ""), str(release.get("html_url") or "")
    if not re.fullmatch(TAG_RE, tag):
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
    # A tag is a promise: one seen on another commit was rewritten — refused, never followed.
    seen = state.setdefault("tags", {})
    if dep_ref and dep_commit and git("rev-parse", "-q", "--verify", f"refs/tags/{dep_ref}", check=False).returncode == 0:
        seen.setdefault(dep_ref, dep_commit)
    if seen.get(tag, commit) != commit:
        why = (f"son tag a bougé : {seen[tag][:12]} → {commit[:12]} ; un tag publié ne se réécrit pas — "
               "publier une nouvelle release")
        save_state(state)
        if check:
            say(f"⛔ À blanc : {tag} serait refusée", why, color=nd.RED)
            return 1
        state["outcomes"][tag] = {"result": "refused", "why": why, "at": int(time.time())}
        save_state(state)
        say(f"⛔ {tag} refusée : H0 reste sur {dep_ref or 'ce qui tourne'}", why, color=nd.RED, alert=True, url=url)
        return 1
    seen.setdefault(tag, commit)
    save_state(state)
    if commit == dep_commit:
        lagging = sorted(n for n, v in versions().items() if v != tag)
        if lagging:
            say_once(state, tag, "split", "⚠️ H0 n'est pas d'un seul tenant",
                     f"{', '.join(lagging)} ne tourne(nt) pas sur {tag} : make glorfindel-host-status",
                     color=nd.ORANGE, alert=True)
            save_state(state)
            raise Quiet(f"{tag} : conteneurs dépareillés ({', '.join(lagging)})")
        if check:
            return check_running(tag, commit, url)
        raise Quiet(f"{tag} tourne déjà")
    try:
        verify(tag, commit, dep_commit, state)
        harness = lock_guard(tag, commit, dep_commit, dep_ref) or {}
        if not check:
            say(f"🚀 H0 : déploiement de {tag}", f"{dep_ref or 'inconnu'} → {tag} ({commit[:12]})"
                + (f"\n{harness['note']}" if harness.get("note") else ""), color=nd.BLUE, url=url)
        if harness.get("orange"):     # H3: what varies, said, never a refusal — no mention
            say(f"⚠️ {'À blanc : ' if check else ''}{tag} : le harnais n'a pas tout prouvé", harness["orange"],
                color=nd.ORANGE, url=url)
        build(tag, commit)
        preflight(tag)
        keep_the_way_back(dep_ref, dry=check)
    except Refused as e:
        if e.detail:
            print(e.detail)
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
    started = time.monotonic()
    base = reference_check()           # what runs, before it moves: the rules it detects with
    since = time.time()
    # Written before it happens: a pass cut from here on is taken up by the next one.
    state["outcomes"][tag] = {"result": "switching", "from": dep_ref, "url": url, "why": "", "at": since,
                              "base": base}
    save_state(state)
    proof: dict = {}
    try:
        activate(tag)
        why, proof = health(tag, since, rules=True, base=base)
    except Unhealthy as e:
        why = str(e)
    return conclude(state, tag, dep_ref, why, url,
                    f"{commit[:12]} · {int(time.monotonic() - started)} s, santé verte pendant {int(HEALTH_S)} s",
                    proof)


def rollback(ref: str) -> str:
    """'' when H0 is back on `ref` and healthy, else why not."""
    if not ref:
        return "aucune référence précédente connue"
    since = time.time()
    try:
        activate(ref)
    except Unhealthy as e:
        return str(e)
    return health(ref, since)[0]


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
            # A cut switch stays: it is taken up first, whatever retry forgets.
            state["outcomes"] = {t: o for t, o in state["outcomes"].items() if o.get("result") == "switching"}
            state["said"].clear()
            state.pop("waits", None)
            state.pop("interrupts", None)
            save_state(state)
        try:
            return run_pass(check=mode == "check")
        except Quiet as e:
            print(f"· {e}")
            return 0
        except Exception as e:   # an API or a tool that changed: said once, not a unit failing in silence
            import traceback
            traceback.print_exc()
            state = load_state()
            say_once(state, "_agent", type(e).__name__, "⚠️ Le CD de H0 a échoué",
                     f"{type(e).__name__} — le détail : make glorfindel-host-cd-status", color=nd.RED, alert=True)
            save_state(state)
            return 1
    return locked(one)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
