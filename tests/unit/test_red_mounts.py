"""SEC20 (#467): the red never writes what the operator runs.

An injector's container (Annatar, Gothmog) mounts read-write no directory of code, scripts or
configuration that the operator, the watch or a `make` runs afterwards — nor one that holds one
(the repository whole, the home whole). What it writes is data: its directories of runs/ (SEC18).
The one file a red container runs at its start, the shell's ``.bashrc`` (``make annatar-shell``,
``--init-file``), is read-only in every red container that mounts it.

The oracle is written here: what a red container may mount read-write (WRITABLE, and the
inventory below, with what each mount serves to write) and what it never writes (OPERATOR_RUNS).
Read from the compose file and from every ``docker run`` of the Makefile whose image is the
injectors' — the workstation's and Orodruin's —, its variables expanded as make would (a mount a
``$(if …)`` may add counts as made). No container starts.
"""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import NamedTuple

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
COMPOSE = yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))["services"]
MAKEFILE = (ROOT / "Makefile").read_text(encoding="utf-8")
RED_IMAGE = "eregion-annatar"   # the injectors' image: Annatar and Gothmog, on a workstation and on Orodruin

# What a red container may write: its directories of runs/ (each one's writer: test_runs_mounts.py),
# on the workstation (the clone's runs/) and on Orodruin (~/runs), and the shell's history.
WRITABLE = {"runs/annatar", "runs/gothmog", "runs/orodruin", "~/runs/annatar", "~/runs/gothmog",
            "~/runs/orodruin", "~/.annatar"}
# The migration of the former layout, once, at `make orodruin-push`: ~/runs whole — data, never run.
MIGRATION = {"ORO_MIGRATE": {"~/runs"}}

# What the operator, the watch or a make runs (code, scripts, configuration), in the clone and in the
# home: a red container writes none of it, nor what holds it.
OPERATOR_RUNS = ("scripts", "glorfindel", "annatar", "gothmog", "eregion_core", "eregion_console", "analysis",
                 "infra", "technique_catalog.yaml", "glorfindel-config.yaml", "Makefile", "docker-compose.yml",
                 "~/.glorfindel", "~/.eregion")
WHOLE = ("", "~")   # the repository whole, the home whole

# The inventory: each red container's read-write mounts, and what each serves to write.
INVENTORY = {
    # compose, on a workstation (D1: `docker compose --profile annatar run --rm annatar …`)
    "annatar": {"runs/annatar",       # its signals, run reports, exercise windows, campaigns (SEC18)
                "runs/orodruin"},     # the journal before each call, the lock of « one run at a time »
    "gothmog": {"runs/gothmog", "runs/orodruin"},
    # the Makefile, on the workstation
    "DOCKER_ANNATAR": {"runs/annatar", "runs/orodruin"},                    # make annatar-run, -dry-run
    "annatar-shell": {"runs/annatar", "runs/orodruin", "~/.annatar"},       # + the shell's history
    "annatar-validate": set(), "annatar-list": set(),                       # they write nothing
    # Orodruin
    "ORO_RUN": {"~/runs/annatar", "~/runs/orodruin"},
    "ORO_RUN_GOTHMOG": {"~/runs/gothmog", "~/runs/orodruin"},
    "ORO_RUN_CONTRACT": {"~/runs/orodruin"},                                # the contract's verdict
    "ORO_RUN_REQUEST": {"~/runs/annatar", "~/runs/gothmog", "~/runs/orodruin"},   # it launches both
    "ORO_MIGRATE": {"~/runs"},
}


class Mount(NamedTuple):
    src: str     # normalised: relative to the clone ("" = the clone whole), or "~/…" for the home
    dst: str
    ro: bool


# ── The Makefile, expanded as make would ─────────────────────────────────────────────────────

def _logical(text: str) -> list[str]:
    return text.replace("\\\n", " ").splitlines()


DEFS: dict[str, str] = {}
for _line in _logical(MAKEFILE):
    _m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)\s*[:?]?=\s?(.*)$", _line)
    if _m:
        DEFS.setdefault(_m[1], _m[2])


def _close(text: str, i: int) -> int:
    depth = 0
    for j in range(i, len(text)):
        depth += text[j] == "("
        depth -= text[j] == ")"
        if depth == 0:
            return j
    raise AssertionError(f"unbalanced: {text}")


def _args(text: str) -> list[str]:
    out, depth, cur = [], 0, ""
    for ch in text:
        if ch == "," and depth == 0:
            out.append(cur)
            cur = ""
            continue
        depth += ch == "("
        depth -= ch == ")"
        cur += ch
    return [*out, cur]


def _expand(text: str, depth: int = 0) -> str:
    assert depth < 20, text
    out, i = [], 0
    while i < len(text):
        if text.startswith("$$", i):
            out.append("$$")
            i += 2
        elif text.startswith("$(", i):
            j = _close(text, i + 1)
            out.append(_ref(text[i + 2:j], depth))
            i = j + 1
        else:
            out.append(text[i])
            i += 1
    return "".join(out)


def _ref(inner: str, depth: int) -> str:
    fn, _, rest = inner.partition(" ")
    if fn == "if":                       # the mount a condition may add counts as made
        return _expand((_args(rest) + ["", ""])[1], depth + 1)
    if fn == "call":
        name, *args = _args(rest)
        body = DEFS[name.strip()]
        for n, a in enumerate(args, 1):
            body = body.replace(f"$({n})", a)
        return _expand(body, depth + 1)
    if inner in DEFS:
        return _expand(DEFS[inner], depth + 1)
    return f"$({inner})"


def _make_runs() -> dict[str, str]:
    """Every `docker run` of the Makefile whose image is the injectors', by the variable that
    holds it or the target whose recipe it is, expanded."""
    out, target = {}, ""
    for line in _logical(MAKEFILE):
        t = re.match(r"^([A-Za-z0-9_.-]+(?:\s+[A-Za-z0-9_.-]+)*)\s*:(?!=)", line)
        if t and not line.startswith("\t"):
            target = t[1].split()[0]
        if line.lstrip().startswith("#") or "docker run" not in line:
            continue
        text = _expand(line)
        if RED_IMAGE not in text:
            continue
        d = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)\s*[:?]?=", line)
        name = d[1] if d else target
        assert name not in out, name
        out[name] = text
    return out


# ── A volume, normalised ─────────────────────────────────────────────────────────────────────

def _path(src: str) -> str:
    s = src.strip("'\"")
    for home in ("${HOME}", "$(HOME)", "$$HOME", "$HOME", "~"):
        if s == home:
            return "~"
        if s.startswith(home + "/"):
            rest = os.path.normpath(s[len(home) + 1:])
            return "~" if rest == "." else f"~/{rest}"
    for clone in ("$(PWD)", "$(CURDIR)", "${PWD}", "."):
        if s == clone:
            return ""
        if s.startswith(clone + "/"):
            s = s[len(clone) + 1:]
            break
    return os.path.normpath(s) if s.strip("/") else ""


def _mount(volume: str) -> Mount:
    v = re.sub(r"\$\{\w+:-([^}]*)\}", r"\1", volume.strip("'\""))   # compose: ${VAR:-default} → default
    src, dst, *opts = v.split(":")
    return Mount(_path(src), dst, "ro" in (opts[0].split(",") if opts else []))


def _red() -> dict[str, list[Mount]]:
    """Every red container's mounts: the compose services of the injectors' image, the Makefile's
    docker runs of it."""
    out = {}
    for name, s in COMPOSE.items():
        if str(s.get("image", "")).split(":")[0] == RED_IMAGE:
            assert all(isinstance(v, str) for v in s.get("volumes") or []), name   # the short syntax only
            out[name] = [_mount(v) for v in s.get("volumes") or []]
    for name, text in _make_runs().items():
        assert "--mount" not in text and "--volume" not in text, (name, "only -v is read here")
        out[name] = [_mount(v) for v in re.findall(r"(?:^|\s)-v\s+(\S+)", text)]
    return out


def _within(path: str, tree: str) -> bool:
    if tree in WHOLE:
        return path == tree or (path.startswith("~/") if tree == "~" else not path.startswith("~"))
    return path == tree or path.startswith(tree + "/")


def _writes(mounts: list[Mount], path: str) -> bool:
    """Whether these mounts give ``path`` read-write: the deepest mount that holds it is, or a
    mount below it is."""
    holding = [m for m in mounts if _within(path, m.src)]
    if holding and not max(holding, key=lambda m: len(m.src)).ro:
        return True
    return path not in WHOLE and any(not m.ro and _within(m.src, path) for m in mounts)


def _run_at_start() -> set[str]:
    """The host files a red container runs at its start (``--init-file``), through its mounts."""
    out = set()
    for name, text in _make_runs().items():
        for inside in re.findall(r"--init-file\s+(\S+)", text):
            mounts = [m for m in _red()[name] if inside == m.dst or inside.startswith(m.dst.rstrip("/") + "/")]
            if mounts:
                m = max(mounts, key=lambda m: len(m.dst))
                out.add(m.src + inside[len(m.dst):])
    return out


# ── The tests ────────────────────────────────────────────────────────────────────────────────

def test_every_red_container_is_read():
    """The parser finds them all: the compose services, the workstation's docker runs, Orodruin's."""
    assert set(_red()) >= set(INVENTORY), set(INVENTORY) - set(_red())
    assert _run_at_start() == {"~/.annatar/.bashrc"}


@pytest.mark.parametrize("path", [*WHOLE, *OPERATOR_RUNS])
def test_the_red_never_writes_what_the_operator_runs(path):
    """M3400–M3405, M3409: scripts/ and the scenarios read-only — the red reads them, sends
    a script to its target by Run Command, never writes one; nothing of the clone's code, of the
    blue's state, of the home whole."""
    for who, mounts in _red().items():
        assert not _writes(mounts, path), f"{who} mounts {path or 'the repository whole'} read-write"


def test_the_shell_a_red_container_starts_is_never_written_by_the_red():
    """M3406, M3407: the ``.bashrc`` that ``make annatar-shell`` runs is read-only in every red
    container — the shell's own, which writes its history beside it, and the compose service,
    which no longer mounts ~/.annatar."""
    for path in _run_at_start():
        for who, mounts in _red().items():
            assert not _writes(mounts, path), f"{who} mounts {path} read-write"


def test_a_red_container_writes_only_its_runs_and_the_shells_history():
    """M3408: what is not data the red must write is read-only, or not mounted."""
    for who, mounts in _red().items():
        allowed = WRITABLE | MIGRATION.get(who, set())
        for m in mounts:
            assert m.ro or m.src in allowed, f"{who} mounts {m.src or 'the repository whole'} read-write"


def test_the_inventory_of_the_reds_writes():
    """The table of docs/fichiers-cles.md, « Ce que le rouge monte en écriture »."""
    red = _red()
    for who, want in INVENTORY.items():
        assert {m.src for m in red[who] if not m.ro} == want, who


def test_the_scripts_the_red_sends_stay_mounted_read_only():
    """The local scripts reach the container read-only (a change applies without a rebuild); the
    image holds them too. setup_testdata.sh writes on its target VM, by Run Command, never here."""
    for who in ("annatar", "DOCKER_ANNATAR", "annatar-shell"):
        assert Mount("scripts", "/app/scripts", True) in _red()[who], who
        assert Mount("annatar/scenarios", "/app/annatar/scenarios", True) in _red()[who], who
