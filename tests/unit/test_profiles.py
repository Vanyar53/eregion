"""D1 — the usage profiles (docs/profils/): docker compose profiles, Make targets, a page each.

Glorfindel is always present (docs/design/console.md, §2): a profile adds Annatar, Gothmog,
both, or one Glorfindel per team. Read from docker-compose.yml and the Makefile, and the
team targets run against a fake `docker` that records what it receives — no container
starts, nothing reaches Azure. The oracles are written here.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import stat
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
COMPOSE = yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
SERVICES = COMPOSE["services"]
MAKEFILE = (ROOT / "Makefile").read_text(encoding="utf-8")

needs_make = pytest.mark.skipif(shutil.which("make") is None, reason="make not installed")

# compose profiles selected → services that start. Glorfindel (watch + console) in each.
PROFILES = {
    (): {"watch", "war-room"},
    ("annatar",): {"watch", "war-room", "annatar"},
    ("gothmog",): {"watch", "war-room", "gothmog"},
    ("annatar", "gothmog"): {"watch", "war-room", "annatar", "gothmog"},
    ("bot",): {"watch", "war-room", "bot"},
}
INJECTORS = ("annatar", "gothmog")
# Make target → (its prerequisites, its page).
TARGETS = {
    "profile-discover": (["glorfindel-start"], "docs/profils/decouvrir.md"),
    "profile-detection": (["glorfindel-start", "build-annatar"], "docs/profils/detection.md"),
    "profile-resilience": (["glorfindel-start", "build-annatar"], "docs/profils/resilience.md"),
    "profile-proven": (["glorfindel-start", "build-annatar"], "docs/profils/eprouvee.md"),
}
PAGES = ("decouvrir.md", "detection.md", "resilience.md", "eprouvee.md", "equipes.md")


def _started(selected: tuple[str, ...]) -> set[str]:
    return {name for name, s in SERVICES.items()
            if not s.get("profiles") or set(s["profiles"]) & set(selected)}


def _interpolate(text: str, env: dict) -> str:
    """docker compose's ${VAR:-default} (VAR when set and not empty, else the default)."""
    return re.sub(r"\$\{(\w+):-([^}]*)\}", lambda m: env.get(m.group(1)) or m.group(2), text)


def test_glorfindel_starts_in_every_profile():
    for selected, expected in PROFILES.items():
        assert _started(selected) == expected, selected
    assert not SERVICES["watch"].get("profiles") and not SERVICES["war-room"].get("profiles")


def test_an_injector_never_runs_without_glorfindel():
    """V1 in compose: running an injector starts the watch, the injector reads its heartbeat
    in ~/.glorfindel without being able to write it, and shares the runs/ the watch reads."""
    watch_runs = next(v for v in SERVICES["watch"]["volumes"] if v.endswith(":/app/runs"))
    for name in INJECTORS:
        s = SERVICES[name]
        assert "watch" in s["depends_on"], name
        assert "${HOME}/.glorfindel:/root/.glorfindel:ro" in s["volumes"], name
        assert watch_runs in s["volumes"], name
        assert s["image"] == "eregion-annatar" and s["entrypoint"] == [name], name
        assert s["restart"] == "no" and s["profiles"] == [name], name


def test_an_injector_gets_its_own_principal_and_none_of_glorfindels_secrets():
    for name in INJECTORS:
        env = {k: str(v) for k, v in SERVICES[name]["environment"].items()}
        assert env["AZURE_CLIENT_ID"] == "${ANNATAR_AZURE_CLIENT_ID:-}", name
        assert env["AZURE_CLIENT_SECRET"] == "${ANNATAR_AZURE_CLIENT_SECRET:-}", name
        for secret in ("GLORFINDEL_WEBHOOK_URL", "DISCORD_BOT_TOKEN", "EREGION_CONSOLE_TOKEN",
                       "GLORFINDEL_WARROOM_TOKEN", "OPENAI_API_KEY", "MISTRAL_API_KEY"):
            assert secret not in env, (name, secret)
        # The contract of Orodruin: empty, the verdict is passive (fail closed).
        for var in ("EREGION_MAX_INJECTIONS", "EREGION_MAX_RUN_S", "EREGION_CHANNEL_SCOPE"):
            assert env[var] == "${%s:-}" % var, (name, var)
    assert "ANTHROPIC_API_KEY" not in SERVICES["gothmog"]["environment"]


def test_without_a_team_the_names_are_those_h0_reads():
    """infra/glorfindel-host/status.sh and deploy.sh read eregion-watch and eregion-war-room;
    the console listens on 127.0.0.1:7007; runs/ and the config are the repository's."""
    want = {"watch": "eregion-watch", "war-room": "eregion-war-room", "bot": "eregion-bot"}
    for name, container in want.items():
        s = SERVICES[name]
        assert _interpolate(s["container_name"], {}) == container
        vols = [_interpolate(v, {}) for v in s["volumes"]]
        assert "./runs:/app/runs" in vols, name
        assert any(v.startswith("./glorfindel-config.yaml:/app/glorfindel-config.yaml") for v in vols), name
    assert [_interpolate(p, {}) for p in SERVICES["war-room"]["ports"]] == ["127.0.0.1:7007:7007"]
    team = {"EREGION_INSTANCE": "eregion-blue", "EREGION_CONSOLE_PORT": "7101"}
    assert _interpolate(SERVICES["watch"]["container_name"], team) == "eregion-blue-watch"
    assert [_interpolate(p, team) for p in SERVICES["war-room"]["ports"]] == ["127.0.0.1:7101:7007"]


def _recipe(target: str) -> tuple[list[str], list[str]]:
    lines = MAKEFILE.splitlines()
    head = next(i for i, ln in enumerate(lines) if re.match(rf"^{re.escape(target)}:", ln))
    prereqs = lines[head].split(":", 1)[1].split()
    recipe = []
    for line in lines[head + 1:]:
        if not line.startswith("\t"):
            break
        recipe.append(line)
    return prereqs, recipe


def test_every_profile_target_starts_glorfindel_and_names_its_page():
    phony = MAKEFILE.split(".PHONY:", 1)[1].split("\n\n", 1)[0]
    for target, (prereqs, page) in TARGETS.items():
        got, recipe = _recipe(target)
        assert got == prereqs, target
        assert page in "\n".join(recipe), target
        assert (ROOT / page).is_file(), page
        assert target in phony, target
        assert f"make {target}" in "\n".join(_recipe("help")[1]), target


# Make target → the compose profiles it is for.
TARGET_PROFILES = {"profile-discover": (), "profile-detection": ("annatar",),
                   "profile-resilience": ("gothmog",), "profile-proven": ("annatar", "gothmog")}


def test_every_profile_target_creates_what_its_services_mount_from_home():
    """A directory of $HOME that docker bind-mounts without it existing is created by docker,
    as root: the operator's CLI can no longer write it. Each profile's target creates them
    first, as the operator (its recipe, or glorfindel-start's)."""
    assert set(TARGET_PROFILES) == set(TARGETS)
    for target, selected in TARGET_PROFILES.items():
        mounted = {v.split(":", 1)[0].replace("${HOME}", "$(HOME)")
                   for name in _started(selected) for v in SERVICES[name]["volumes"]
                   if v.startswith("${HOME}/")}
        assert mounted, target
        made = " ".join(ln for ln in _recipe(target)[1] + _recipe("glorfindel-start")[1]
                        if "mkdir -p" in ln).split()
        assert mounted <= set(made), (target, mounted - set(made))


def test_each_profile_has_its_page():
    index = (ROOT / "docs" / "profils" / "README.md").read_text(encoding="utf-8")
    for page in PAGES:
        assert (ROOT / "docs" / "profils" / page).is_file(), page
        assert f"]({page})" in index, page
    assert "docs/profils/" in (ROOT / "README.md").read_text(encoding="utf-8")
    equipes = (ROOT / "docs" / "profils" / "equipes.md").read_text(encoding="utf-8")
    assert "make team-start" in equipes and "make team-init" in equipes


def test_every_variable_of_the_team_example_reaches_its_instance_and_holds_no_secret():
    """team.env.example: each key reaches a container (or names the console's port), and a
    secret-looking one ships empty."""
    passed = set()
    for s in SERVICES.values():
        for v in (s.get("environment") or {}).values():
            passed |= set(re.findall(r"\$\{(\w+)", str(v)))
    lines = [ln for ln in (ROOT / "team.env.example").read_text(encoding="utf-8").splitlines()
             if ln.strip() and not ln.startswith("#")]
    keys = dict(ln.split("=", 1) for ln in lines)
    assert set(keys) - passed == {"EREGION_CONSOLE_PORT"}
    for k, v in keys.items():
        if re.search(r"KEY|TOKEN|SECRET|WEBHOOK", k):
            assert v == "", k
    assert re.fullmatch(r"\d+", keys["EREGION_CONSOLE_PORT"]) and keys["EREGION_CONSOLE_PORT"] != "7007"


# ── The team targets, against a fake docker ───────────────────────────────────────────

@pytest.fixture
def fake_docker(tmp_path):
    """A `docker` first on PATH that records its arguments and environment, then succeeds."""
    bindir = tmp_path / "bin"
    bindir.mkdir()
    log = tmp_path / "docker-calls.jsonl"
    script = bindir / "docker"
    script.write_text("#!/usr/bin/env python3\nimport json, os, sys\n"
                      f"open({str(log)!r}, 'a').write(json.dumps("
                      "{'argv': sys.argv[1:], 'env': dict(os.environ)}) + '\\n')\n")
    script.chmod(script.stat().st_mode | stat.S_IXUSR)

    def calls():
        return [json.loads(ln) for ln in log.read_text().splitlines()] if log.exists() else []
    return bindir, calls


def _make(*args, bindir=None, extra_env=None):
    env = dict(os.environ, **(extra_env or {}))
    if bindir:
        env["PATH"] = f"{bindir}{os.pathsep}{env['PATH']}"
    return subprocess.run(["make", "-s", "--no-print-directory", "-C", str(ROOT), *args],
                          capture_output=True, text=True, env=env, timeout=60)


def _team(tmp_path, body: str) -> Path:
    d = tmp_path / "teams" / "blue"
    d.mkdir(parents=True)
    (d / "team.env").write_text(body)
    (d / "glorfindel-config.yaml").write_text("assets: {}\n")
    return d


@needs_make
@pytest.mark.parametrize("name", ["", "Blue", "../x", "-p", "a b", "x;y"])
def test_a_team_name_is_refused_unless_lowercase_digits_and_dashes(name):
    res = _make("team-check", f"TEAM={name}")
    assert res.returncode != 0, name
    assert "TEAM=<nom> requis" in res.stdout + res.stderr


@needs_make
def test_a_team_name_that_fits_is_accepted():
    assert _make("team-check", "TEAM=blue-2").returncode == 0


@needs_make
def test_a_team_instance_receives_its_team_env_and_nothing_of_the_shell(tmp_path, fake_docker):
    """docker compose prefers the environment to --env-file: an operator's .envrc (its own
    subscription, its keys) must never reach a team's Glorfindel."""
    bindir, calls = fake_docker
    d = _team(tmp_path, "AZURE_SUBSCRIPTION_ID=team-sub\nEREGION_CONSOLE_PORT=7101\n")
    res = _make("team-logs", "TEAM=blue", f"TEAM_DIR={d}", bindir=bindir,
                extra_env={"AZURE_SUBSCRIPTION_ID": "shell-sub", "ANTHROPIC_API_KEY": "shell-key",
                           "EREGION_INSTANCE": "shell-instance"})
    assert res.returncode == 0, res.stdout + res.stderr
    [call] = calls()
    assert call["argv"] == ["compose", "-p", "eregion-blue", "--env-file", f"{d}/team.env", "logs", "-f"]
    env = call["env"]
    assert "AZURE_SUBSCRIPTION_ID" not in env and "ANTHROPIC_API_KEY" not in env
    assert env["HOME"] == str(d)
    assert env["EREGION_INSTANCE"] == "eregion-blue"
    assert env["EREGION_RUNS"] == f"{d}/runs"
    assert env["EREGION_CONFIG"] == f"{d}/glorfindel-config.yaml"


@needs_make
@pytest.mark.parametrize("body, said", [
    ("EREGION_CONSOLE_PORT=7101\n", "AZURE_SUBSCRIPTION_ID vide"),
    ("AZURE_SUBSCRIPTION_ID=\nEREGION_CONSOLE_PORT=7101\n", "AZURE_SUBSCRIPTION_ID vide"),
    ("AZURE_SUBSCRIPTION_ID=team-sub\n", "EREGION_CONSOLE_PORT absent"),
])
def test_team_start_refuses_a_blind_or_portless_instance(tmp_path, fake_docker, body, said):
    bindir, calls = fake_docker
    d = _team(tmp_path, body)
    res = _make("team-start", "TEAM=blue", f"TEAM_DIR={d}", "-o", "build-glorfindel", bindir=bindir)
    assert res.returncode != 0 and said in res.stdout + res.stderr
    assert calls() == []


@needs_make
@pytest.mark.parametrize("bot, argv", [
    ("", ["up", "-d", "watch", "war-room"]),
    ("1", ["--profile", "bot", "up", "-d", "watch", "war-room", "bot"]),
])
def test_team_start_starts_its_glorfindel(tmp_path, fake_docker, bot, argv):
    bindir, calls = fake_docker
    d = _team(tmp_path, "AZURE_SUBSCRIPTION_ID=team-sub\nEREGION_CONSOLE_PORT=7101\n")
    res = _make("team-start", "TEAM=blue", f"TEAM_DIR={d}", f"BOT={bot}", "-o", "build-glorfindel",
                bindir=bindir)
    assert res.returncode == 0, res.stdout + res.stderr
    [call] = calls()
    assert call["argv"][:5] == ["compose", "-p", "eregion-blue", "--env-file", f"{d}/team.env"]
    assert call["argv"][5:] == argv
    assert "http://localhost:7101" in res.stdout
    for sub in ("runs", ".glorfindel", ".cache/chroma", ".eregion/analysis"):
        assert (d / sub).is_dir(), sub
