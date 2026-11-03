"""SEC20 (#467): the red never writes what the operator runs.

An injector's container (Annatar, Gothmog) mounts read-write no directory of code, scripts or
configuration that the operator, the watch or a `make` runs afterwards — nor one that holds one
(the repository whole, the home whole). What it writes is data: its directories of runs/ (SEC18),
and the history of Annatar's shell — that one file, never its directory. The one file a red
container runs at its start, the shell's ``.bashrc`` (``make annatar-shell``, ``--init-file``), is
read-only in every red container that mounts it.

The oracle is written here: what a red container may mount read-write (WRITABLE, and the
inventory below, with what each mount serves to write) and what it never writes (OPERATOR_RUNS).
Read from the compose file and from every ``docker run`` of the Makefile whose image is the
injectors' — the workstation's and Orodruin's —, every line expanded as make would (a mount a
``$(if …)`` may add counts as made; the last definition kept). What such a reader would not see is
refused: a variable of a red run defined twice or appended to, a docker run whose image is not
written plainly, a `compose run` that adds a mount. No container starts.
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
# on the workstation (the clone's runs/) and on Orodruin (~/runs), and the shell's history: that one
# file, never ~/.annatar (where the red would leave what the shell runs next).
WRITABLE = {"runs/annatar", "runs/gothmog", "runs/orodruin", "~/runs/annatar", "~/runs/gothmog",
            "~/runs/orodruin", "~/.annatar/.bash_history"}
# The migration of the former layout, once, at `make orodruin-push` (ORO_MIGRATE): ~/runs whole —
# data, never run; the one run whose command is the migration.
MIGRATION = {"~/runs"}


def _migrates(name: str) -> bool:
    return name not in COMPOSE and MAKE.runs()[name][1].lstrip().startswith("python -m eregion_core.runs_layout migrate")

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
    "annatar-shell": {"runs/annatar", "runs/orodruin", "~/.annatar/.bash_history"},   # + its history
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


# A variable's definition: global (`X = …`, `:=`, `?=`, `+=`, `export X = …`, `override …`) or for
# a target (`t: X = …`, `t: export X = …`).
_DEF = re.compile(r"^(?:(?P<targets>[A-Za-z0-9_.%$()-]+(?:\s+[A-Za-z0-9_.%$()-]+)*)\s*:\s*)?"
                  r"(?:(?:export|override|private)\s+)*(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*(?P<op>::|[:?+!])?="
                  r"\s?(?P<value>.*)$")
# The images a docker run of the Makefile may name: the injectors', and the others known.
KNOWN_IMAGES = ("eregion-glorfindel",)


class Make:
    """A Makefile read as make would: its logical lines, its variables, its docker runs."""

    def __init__(self, text: str):
        self.lines = _logical(text)
        self.defs: dict[str, list[tuple[str, str]]] = {}   # every definition: (op, how)
        # The global values, in order: make keeps the last (`+=` appends to the one before it, a
        # `:=` that names itself reads the one before it); `?=` counts only for a first one.
        self.values: dict[str, list[str]] = {}
        self._runs: dict[str, tuple[str, str, set[str]]] | None = None
        for line in self.lines:
            m = _DEF.match(line) if not line.startswith("\t") and not line.lstrip().startswith("#") else None
            if not m:
                continue
            how = "for a target" if m["targets"] else (m["op"] or "") + "="
            self.defs.setdefault(m["name"], []).append((m["op"] or "", how))
            if m["targets"] or (m["op"] == "?" and m["name"] in self.values):
                continue
            value = f"$({m['name']}) {m['value']}" if m["op"] == "+" else m["value"]
            self.values.setdefault(m["name"], []).append(value)

    def expand(self, text: str, seen: set[str] | None = None, depth: int = 0,
               stack: dict[str, int] | None = None) -> str:
        assert depth < 30, f"too deep: {text[:120]}"
        seen = set() if seen is None else seen
        stack = {} if stack is None else stack
        out, i = [], 0
        while i < len(text):
            if text.startswith("$$", i):
                out.append("$$")
                i += 2
            elif text.startswith("$(", i):
                j = _close(text, i + 1)
                out.append(self._ref(text[i + 2:j], seen, depth, stack))
                i = j + 1
            else:
                out.append(text[i])
                i += 1
        return "".join(out)

    def _value(self, name: str, stack: dict[str, int]) -> tuple[int, str] | None:
        """The value of ``name`` here: the last, or, inside its own expansion, the one before."""
        i = stack.get(name, len(self.values.get(name, []))) - 1
        return (i, self.values[name][i]) if i >= 0 else None

    def _ref(self, inner: str, seen: set[str], depth: int, stack: dict[str, int]) -> str:
        fn, _, rest = inner.partition(" ")
        if fn == "if":                       # the mount a condition may add counts as made
            return self.expand((_args(rest) + ["", ""])[1], seen, depth + 1, stack)
        name, args = (inner, [])
        if fn == "call":
            name, *args = (a.strip() for a in _args(rest))
        found = self._value(name, stack)
        if not found:
            return f"$({inner})"
        seen.add(name)
        i, body = found
        for n, a in enumerate(args, 1):
            body = body.replace(f"$({n})", a)
        return self.expand(body, seen, depth + 1, {**stack, name: i})

    def runs(self) -> dict[str, tuple[str, str, set[str]]]:
        """Every `docker run` of the injectors' image, by the variable that holds it or the
        target whose recipe it is (``target#n`` past the first): its options (up to its image),
        the command it runs (what follows, up to the next run), and the variables it is made of. Every line is expanded: a run inside a variable, a run
        reached by ``ssh … '$(ORO_RUN) …'``, are read where they are used too."""
        if self._runs is not None:
            return self._runs
        out, target = {}, ""
        for line in self.lines:
            t = re.match(r"^([A-Za-z0-9_.-]+(?:\s+[A-Za-z0-9_.-]+)*)\s*:(?![:?+!]?=)", line)
            if t and not line.startswith("\t") and not _DEF.match(line):
                target = t[1].split()[0]
            if line.lstrip().startswith("#"):
                continue
            seen: set[str] = set()
            text = self.expand(line, seen)
            d = _DEF.match(line) if not line.startswith("\t") else None
            base = d["name"] if d and not d["targets"] else target
            for k, seg in enumerate(text.split("docker run")[1:]):
                image = re.search(rf"(?<![\w-]){RED_IMAGE}(?::[\w.-]+)?(?![\w-])", seg)
                if not image:
                    continue
                name = base if base not in out else f"{base}#{k}"
                n = 1
                while name in out:
                    n += 1
                    name = f"{base}#{n}"
                out[name] = (seg[:image.end()], seg[image.end():], seen)
        self._runs = out
        return out

    def unread_runs(self) -> list[str]:
        """The docker runs whose image is neither the injectors' nor a known one, written plainly
        (``$$(cat …)``, ``"$$img"``): never read here, so refused."""
        out = []
        for line in self.lines:
            if line.lstrip().startswith("#"):
                continue
            for seg in self.expand(line).split("docker run")[1:]:
                if not re.search(rf"(?<![\w-])(?:{RED_IMAGE}|{'|'.join(KNOWN_IMAGES)})(?::[\w.-]+)?(?![\w-])", seg):
                    out.append(line.strip()[:160])
        return out

    def compose_runs_with_mounts(self) -> list[str]:
        """`docker compose … run -v …` in a recipe: a mount the compose file does not hold."""
        out = []
        for line in self.lines:
            if line.lstrip().startswith("#"):
                continue
            m = re.search(r"\bcompose\b.*?\brun\b(?P<rest>.*)", self.expand(line))
            if m and re.search(r"(?:^|\s)(?:-v|--volume|--mount)(?:\s|=|$)", m["rest"]):
                out.append(line.strip()[:160])
        return out

    def redefined(self) -> list[str]:
        """The variables a red docker run is made of that make defines more than once (`+=`, a
        second `=`/`:=`, one for a target): read here as the last, where make may keep another —
        or append a mount this test never sees."""
        made = set().union(*(seen for _, _, seen in self.runs().values()))
        return [f"{name}: {', '.join(how for _, how in self.defs[name])}" for name in sorted(made)
                if len(self.defs.get(name, [])) > 1 or any(op == "+" for op, _ in self.defs.get(name, []))]


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


MAKE = Make(MAKEFILE)


def _make_runs() -> dict[str, str]:
    return {name: options for name, (options, _, _) in MAKE.runs().items()}


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
    for name, (_, command, _) in MAKE.runs().items():
        for inside in re.findall(r"--init-file\s+(\S+)", command):
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
        allowed = WRITABLE | (MIGRATION if _migrates(who) else set())
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


def test_the_shells_history_is_the_one_file_it_writes_of_its_home():
    """M3406: ``make annatar-shell`` mounts the history file alone, read-write, where HISTFILE
    puts it (nothing set it since the .bashrc the Makefile writes holds only the alias); never
    ~/.annatar, whose .bashrc it runs."""
    options = _make_runs()["annatar-shell"]
    assert "-e HISTFILE=/root/.annatar/.bash_history" in options
    mounts = _red()["annatar-shell"]
    assert Mount("~/.annatar/.bash_history", "/root/.annatar/.bash_history", False) in mounts
    assert Mount("~/.annatar/.bashrc", "/root/.annatar/.bashrc", True) in mounts
    assert all(m.src != "~/.annatar" for m in mounts)


def _shell(text: str, home: Path):
    import subprocess
    return subprocess.run(["bash", "-c", text.replace("$$", "$")], cwd=home,
                          env={"HOME": str(home), "PATH": "/usr/bin:/bin"}, capture_output=True, text=True)


@pytest.mark.parametrize("link", [".annatar", ".annatar/.bashrc", ".annatar/.bash_history"])
def test_the_shells_files_that_are_links_stop_it_before_docker(link, tmp_path):
    """A link in place of ~/.annatar, its .bashrc or its history stops `make annatar-shell`
    before docker (which resolves a bind's source on the host): its target never written."""
    recipe = MAKE.expand(MAKE.values["ANNATAR_SHELL_FILES"][-1])
    assert "ANNATAR_SHELL_FILES" in "".join(ln for ln in MAKE.lines if ln.startswith("\t@$(ANNATAR_SHELL_FILES)"))
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    target = elsewhere / "x"
    (tmp_path / ".annatar").mkdir()
    if link == ".annatar":
        (tmp_path / ".annatar").rmdir()
        (tmp_path / ".annatar").symlink_to(elsewhere)
    else:
        (tmp_path / link).symlink_to(target)
    res = _shell(recipe, tmp_path)
    assert res.returncode != 0 and "un lien" in res.stderr, res
    assert list(elsewhere.iterdir()) == []
    (tmp_path / link).unlink()
    assert _shell(recipe, tmp_path).returncode == 0
    assert (tmp_path / ".annatar" / ".bashrc").is_file() and (tmp_path / ".annatar" / ".bash_history").is_file()


def test_annatar_shell_makes_its_files_before_it_writes_the_alias():
    """The check runs first: the alias is appended to a .bashrc held as a real file."""
    recipe = [ln.strip() for ln in MAKE.lines[MAKE.lines.index("annatar-shell: build-annatar") + 1:]
              if ln.startswith("\t")][:3]
    assert recipe[0] == "@$(ANNATAR_SHELL_FILES)" and "alias ar=" in recipe[1], recipe


# ── What the reader of the Makefile would not see ────────────────────────────────────────────

def test_no_variable_of_a_red_run_is_defined_twice():
    """Read here as make keeps it; but a `+=`, a second definition or one for a target is where a
    mount slips past a reader — refused, said."""
    assert MAKE.redefined() == [], "variables of a red docker run defined more than once: " + "; ".join(
        MAKE.redefined())


def test_a_mount_appended_with_plus_equals_is_refused_and_read():
    make = Make(MAKEFILE + "\nANNATAR_VOLS += -v $(PWD)/scripts:/app/scripts\n")
    assert any(r.startswith("ANNATAR_VOLS: :=, +=") for r in make.redefined()), make.redefined()
    assert "-v $(PWD)/scripts:/app/scripts " in make.runs()["DOCKER_ANNATAR"][0] + " "


def test_a_variable_defined_again_with_itself_is_refused_and_read():
    make = Make(MAKEFILE + "\nANNATAR_VOLS := $(ANNATAR_VOLS) -v $(PWD)/glorfindel:/app/glorfindel\n")
    assert any(r.startswith("ANNATAR_VOLS: :=, :=") for r in make.redefined()), make.redefined()
    assert "-v $(PWD)/glorfindel:/app/glorfindel" in make.runs()["DOCKER_ANNATAR"][0]


def test_every_docker_run_names_its_image_plainly():
    """A docker run whose image is read at run time (``$$(cat …)``, ``"$$img"``) is never read
    here: neither the injectors' image nor a known one, it is refused."""
    assert MAKE.unread_runs() == []
    for line in ("\tdocker run --rm -v $(PWD)/scripts:/app/scripts $$(cat .image) annatar",
                 '\timg=eregion-x; docker run --rm -v $(PWD):/app "$$img" annatar'):
        assert Make(MAKEFILE + "\nx-run:\n" + line + "\n").unread_runs(), line


def test_no_recipe_mounts_by_hand_through_compose_run():
    """`docker compose … run -v …` adds a mount the compose file does not hold: refused."""
    assert MAKE.compose_runs_with_mounts() == []
    for line in ("\tdocker compose --profile annatar run --rm -v $(PWD)/scripts:/app/scripts annatar list",
                 "\tdocker-compose run --volume=$(PWD):/app annatar list"):
        assert Make(MAKEFILE + "\nx-run:\n" + line + "\n").compose_runs_with_mounts(), line
