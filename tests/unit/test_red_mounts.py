"""SEC20 (#467): the red never writes what the operator runs.

An injector's container (Annatar, Gothmog) mounts read-write no directory of code, scripts or
configuration that the operator, the watch or a `make` runs afterwards — nor one that holds one
(the repository whole, the home whole). What it writes is data: its directories of runs/ (SEC18),
and the history of Annatar's shell — that one file, never its directory. The one file a red
container runs at its start, the shell's ``.bashrc`` (``make annatar-shell``, ``--init-file``), is
read-only in every red container that mounts it.

The oracle is written here: what a red container may mount read-write (WRITABLE, and the
inventory below, with what each mount serves to write) and what it never writes (OPERATOR_RUNS).
Read from the compose file and from every launch of the Makefile (``docker run``, ``docker create``,
``docker container …``) whose image is the injectors' — the workstation's and Orodruin's —, every
line expanded as make would (a mount a ``$(if …)`` may add counts as made; the last definition
kept), each launch's options read as docker reads them, up to its image: a mount in any of its
forms. What such a reader would not see is refused (SEC20, SEC20b #494): a variable of a red run
defined twice or appended to; a directive that makes make read what this reader does not (an
included file, a ``define``, an ``$(eval …)``); in a launch's options, a reference left unexpanded
— the home and the clone aside — or a word not plain, an option it does not know, another
container's mounts, what the red is never given (the host's devices or namespaces, more
capabilities, its confinement lifted); a comment continued onto the next line (a recipe's
continuation is read as the shell joins it); a launch whose image is not written plainly, or behind docker's own options; a
`compose run` that adds a mount; a compose launch told to read another file, or a file beside the
compose that compose would merge on its own. No container starts.
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
    return name not in COMPOSE and MAKE.runs()[name].command.startswith("python -m eregion_core.runs_layout migrate")

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
    "ORO_CHECK_RUN": set(),   # OI2: the image received, run once without network before its tag; no mount
}


class Mount(NamedTuple):
    src: str     # normalised: relative to the clone ("" = the clone whole), or "~/…" for the home
    dst: str
    ro: bool


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


# ── A launch's options, read as docker reads them ────────────────────────────────────────────

# A launch: `docker run`, `docker create`, either as `docker container …`, whatever the spaces.
LAUNCH = re.compile(r"docker\s+(?:container\s+)?(?:run|create)\b")
# docker's own options before its command: a launch behind them is never read here, so refused.
_DOCKER_OPTIONS = re.compile(r"\bdocker\s+-")
# The images a launch of the Makefile may name: the injectors', and the others known.
KNOWN_IMAGES = ("eregion-glorfindel",)
_IMAGE = re.compile(rf"(?:{RED_IMAGE}|{'|'.join(KNOWN_IMAGES)})(?::[\w.-]+)?")
_RED = re.compile(rf"{RED_IMAGE}(?::[\w.-]+)?")

# docker's options of a launch, as its parser reads them: a short one alone or in a group (`-it`,
# `-itv x`), its value glued to it (`-vx`, `-v=x`) or the next word; a long one, its value after
# `=` or the next word. An option this table does not know is refused: whether it takes a value —
# so which word is the image — is not known.
_SHORT_FLAGS = set("ditPq")
_SHORT_VALUED = set("acehlmpuwv")
_LONG_FLAGS = {"--rm", "--read-only", "--init", "--interactive", "--tty", "--detach", "--quiet",
               "--publish-all", "--no-healthcheck"}
_LONG_VALUED = {"--env", "--env-file", "--entrypoint", "--tmpfs", "--cap-drop", "--security-opt", "--name",
                "--user", "--workdir", "--network", "--net", "--ipc", "--uts", "--publish", "--label",
                "--hostname", "--memory", "--cpus", "--pull", "--platform", "--add-host", "--restart",
                "--stop-signal", "--log-driver", "--log-opt", "--volume", "--mount", "--volumes-from"}
# What a red launch is never given — the host's devices, processes, namespaces, more capabilities,
# its confinement lifted —, refused by name, read before the tables above: none of these is ever in
# them (test_no_dangerous_option_is_read_as_an_ordinary_one). True: it takes a value.
_NEVER_TO_THE_RED = {"--privileged": False, "--device": True, "--cap-add": True, "--pid": True, "--userns": True}
# Options read, but some of their values never given to the red: the host's namespace (or another
# container's), a confinement other than « no new privileges ».
_NEVER_AS = {"--network": r"host|container:.*", "--net": r"host|container:.*", "--ipc": r"host|container:.*",
             "--uts": r"host", "--security-opt": r"(?!no-new-privileges(?::true|=true)?$).*"}
_MOUNTS = {"-v": "volume", "--volume": "volume", "--mount": "mount", "--volumes-from": "from"}
_MOUNT_KEYS = {"type": "type", "source": "src", "src": "src", "target": "dst", "destination": "dst",
               "dst": "dst", "readonly": "ro", "ro": "ro"}
# What a word of a launch's options may be: plain text, and three references — the home and the
# clone. Any other is a reference this reader leaves unexpanded (a variable of a `define` or of an
# included file, `$(shell …)`, a variable of the shell): what make or the shell would make of it,
# a mount among others, is never seen.
_PLAIN = re.compile(r"[\w./:,=@+%-]*")
_ALLOWED_REFS = re.compile(r"\$\((?:HOME|PWD)\)|\$\$HOME(?!\w)")


class Launch(NamedTuple):
    options: str          # its words up to its image, the image included
    image: str            # "" when its options could not be read up to it
    command: str          # what follows its image, up to the next launch
    mounts: list[Mount]
    faults: list[str]     # what this reader does not read in it: the launch refused
    dangers: list[str]    # what it gives that the red is never given: refused for a red launch


def _bind(spec: str, faults: list[str]) -> list[Mount]:
    """A ``--mount`` read: a bind or a volume, its source, its target, read-only or not."""
    fields: dict[str, str | None] = {}
    for part in spec.split(","):
        key, eq, value = part.partition("=")
        if key not in _MOUNT_KEYS or _MOUNT_KEYS[key] in fields:
            faults.append(f"--mount {spec}: {key!r} never read here")
            return []
        fields[_MOUNT_KEYS[key]] = value if eq else None
    kind, ro = fields.get("type") or "volume", fields.get("ro", "false")
    if kind == "tmpfs" and "src" not in fields:
        return []
    if kind not in ("bind", "volume") or not fields.get("src") or not fields.get("dst") or (
            ro is not None and ro.lower() not in ("1", "t", "true", "0", "f", "false")):
        faults.append(f"--mount {spec}: never read here")
        return []
    return [Mount(_path(fields["src"]), fields["dst"], ro is None or ro.lower() in ("1", "t", "true"))]


def _mounts(flag: str, value: str, faults: list[str]) -> list[Mount]:
    kind = _MOUNTS[flag]
    if kind == "from":
        faults.append(f"{flag} {value}: another container's mounts, which this reader does not see")
        return []
    if kind == "mount":
        return _bind(value, faults)
    if ":" not in value:
        faults.append(f"{flag} {value}: a volume without its source, never read here")
        return []
    return [_mount(value)]


def _quote_at(text: str, end: int) -> str | None:
    """The quote the shell is inside of at ``end`` in ``text``: ``'``, ``"`` or none."""
    quote, i = None, 0
    while i < end:
        c = text[i]
        if c == "\\" and quote != "'":
            i += 2
            continue
        if c in "'\"" and quote in (None, c):
            quote = None if quote else c
        i += 1
    return quote


def _segments(text: str):
    """What follows each launch of ``text``, up to the next one, with the quote it starts inside of
    (a launch that ends a quoted command: ``ssh … 'docker run … image'``)."""
    starts = list(LAUNCH.finditer(text))
    for n, m in enumerate(starts):
        end = starts[n + 1].start() if n + 1 < len(starts) else len(text)
        yield text[m.end():end], _quote_at(text, m.start())


def _launch(seg: str, quote: str | None = None) -> Launch:
    """The words that follow a launch, read as docker does: its options and their mounts up to the
    image, then the image, then the command. A launch inside a quoted command may end it: the quote
    that closes it, at the very end of the image, is not the image's — any other quote is."""
    words, mounts, faults, dangers = seg.split(), [], [], []

    def word(j: int) -> str | None:
        if j >= len(words):
            return None
        rest = _ALLOWED_REFS.sub("", words[j])
        if not _PLAIN.fullmatch(rest):
            faults.append(f"{words[j]}: " + ("a reference left unexpanded" if re.search(r"[$`]", rest)
                                              else "not plain text"))
        return words[j]

    def unread(why: str, at: int) -> Launch:
        faults.append(why)
        return Launch(" ".join(words[:at + 1]), "", "", mounts, faults, dangers)

    i = 0
    closed = False
    while i < len(words):
        if (quote and not words[i].startswith("-") and words[i].endswith(quote)
                and quote not in words[i][:-1]):
            words[i], closed = words[i][:-1], True
        w = word(i)
        if w == "--":
            i += 1
            word(i)
            break
        if not w.startswith("-") or w == "-":
            break
        flag, value = None, None
        if w.startswith("--"):
            flag, eq, value = w.partition("=")
            if flag in _NEVER_TO_THE_RED:
                dangers.append(f"{w}: never given to the red")
                if _NEVER_TO_THE_RED[flag] and not eq:
                    i += 1
                    word(i)
                i += 1
                continue
            if flag in _LONG_FLAGS:
                i += 1
                continue
            if flag not in _LONG_VALUED:
                return unread(f"{flag}: an option this reader does not know", i)
            if not eq:
                i += 1
                value = word(i)
        else:
            for k, c in enumerate(w[1:], 1):
                if c in _SHORT_FLAGS:
                    continue
                if c not in _SHORT_VALUED:
                    return unread(f"{w}: an option this reader does not know (-{c})", i)
                flag, value = f"-{c}", w[k + 1:].removeprefix("=")
                if not value:
                    i += 1
                    value = word(i)
                break
        if flag and value is None:
            return unread(f"{flag}: its value missing", i)
        if flag in _NEVER_AS and re.fullmatch(_NEVER_AS[flag], value):
            dangers.append(f"{flag} {value}: never given to the red")
        if flag in _MOUNTS:
            mounts += _mounts(flag, value, faults)
        i += 1
    image = words[i] if i < len(words) else ""
    command = "" if closed else " ".join(words[i + 1:])     # past the quote: no longer the container's
    return Launch(" ".join(words[:i + 1]), image, command, mounts, faults, dangers)


# ── The Makefile, expanded as make would ─────────────────────────────────────────────────────

def _logical(text: str) -> list[str]:
    """The logical lines, as make joins them: outside a recipe, a backslash-newline is a space; in a
    recipe (a line that starts with a tab), make passes it to the shell, the next line's tab taken
    off, and the shell joins the two lines with nothing between them."""
    out, cur = [], None
    for raw in text.split("\n"):
        if cur is None:
            cur = raw
        elif cur.startswith("\t"):
            cur += raw.removeprefix("\t")
        else:
            cur += " " + raw
        if cur.endswith("\\"):
            cur = cur[:-1]
            continue
        out.append(cur)
        cur = None
    return out if cur is None else [*out, cur]


# A variable's definition: global (`X = …`, `:=`, `?=`, `+=`, `export X = …`, `override …`) or for
# a target (`t: X = …`, `t: export X = …`).
_DEF = re.compile(r"^(?:(?P<targets>[A-Za-z0-9_.%$()-]+(?:\s+[A-Za-z0-9_.%$()-]+)*)\s*:\s*)?"
                  r"(?:(?:export|override|private)\s+)*(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*(?P<op>::|[:?+!])?="
                  r"\s?(?P<value>.*)$")
# SEC20b: what makes make read what this reader does not — another file (`include`, `-include`,
# `sinclude`), a value over several lines (`define`, and `undefine`, which takes one back), text
# made a makefile while it runs (`$(eval …)`) —, refused rather than read. Reading them would make
# this test a second make (its search path, a missing file a rule rebuilds, the order an
# evaluation runs in); the Makefile needs none of them.
_DIRECTIVE = re.compile(r"^\s*(?:(?:override|export|private)\s+)*(?:define|undefine)\b"
                        r"|^\s*(?:-?include|sinclude)\b|\$[({]eval\b")
# A recipe's make told to read another makefile, or this one from another directory: its launches
# never read here, so refused.
# What decides how make runs a recipe — a shell of its own (`SHELL`, `.SHELLFLAGS`), the recipe
# as one script (`.ONESHELL`), an object loaded into make (`load`): refused, the Makefile sets none.
_MAKE_SETTING = re.compile(r"(?:^|[\s:])(?:SHELL|\.SHELLFLAGS)\s*(?::{1,3}|[?+!])?=|^\s*\.ONESHELL\s*:"
                           r"|^\s*-?load\b")
# A comment continued onto the next line: in a recipe, the shell ends it there and runs what
# follows; never read here, so refused.
_CONTINUED_COMMENT = re.compile(r"^\s*#.*\\$")
_SUBMAKE = re.compile(r"\$[({]MAKE[)}](?P<rest>[^;&|]*)")
_SUBMAKE_FILE = re.compile(r"(?:^|\s)(?:-[A-Za-z]*[fC]|--(?:file|makefile|directory)\b)")


class Run(NamedTuple):
    options: str          # up to its image, the image included
    command: str          # what it runs, up to the next launch
    seen: set[str]        # the variables it is made of
    mounts: list[Mount]


class Make:
    """A Makefile read as make would: its logical lines, its variables, its docker runs."""

    def __init__(self, text: str):
        self.text = text
        self.lines = _logical(text)
        self.defs: dict[str, list[tuple[str, str]]] = {}   # every definition: (op, how)
        # The global values, in order: make keeps the last (`+=` appends to the one before it, a
        # `:=` that names itself reads the one before it); `?=` counts only for a first one.
        self.values: dict[str, list[str]] = {}
        self._runs: dict[str, Run] | None = None
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

    def _launches(self):
        """Every launch of the Makefile, with the line it is on, that line expanded and the
        variables it is made of."""
        for line in self.lines:
            if line.lstrip().startswith("#"):
                continue
            seen: set[str] = set()
            text = self.expand(line, seen)
            for k, (seg, quote) in enumerate(_segments(text)):
                yield line, k, _launch(seg, quote), seen

    def runs(self) -> dict[str, Run]:
        """Every launch of the injectors' image, by the variable that holds it or the target
        whose recipe it is (``target#n`` past the first): its options (up to its image), the
        command it runs (what follows, up to the next launch), the variables it is made of, its
        mounts. Every line is expanded: a run inside a variable, a run reached by
        ``ssh … '$(ORO_RUN) …'``, are read where they are used too."""
        if self._runs is not None:
            return self._runs
        out, target = {}, ""
        for line in self.lines:
            t = re.match(r"^([A-Za-z0-9_.-]+(?:\s+[A-Za-z0-9_.-]+)*)\s*:(?![:?+!]?=)", line)
            if t and not line.startswith("\t") and not _DEF.match(line):
                target = t[1].split()[0]
            if line.lstrip().startswith("#"):
                continue
            d = _DEF.match(line) if not line.startswith("\t") else None
            base = d["name"] if d and not d["targets"] else target
            seen: set[str] = set()
            text = self.expand(line, seen)
            for k, (seg, quote) in enumerate(_segments(text)):
                launch = _launch(seg, quote)
                if not _RED.fullmatch(launch.image):
                    continue
                name = base if base not in out else f"{base}#{k}"
                n = 1
                while name in out:
                    n += 1
                    name = f"{base}#{n}"
                out[name] = Run(launch.options, launch.command, seen, launch.mounts)
        self._runs = out
        return out

    def unread(self) -> list[str]:
        """What a launch of the Makefile holds that this reader does not read, and the directives
        that make make read beyond it: refused, each said with its line."""
        out = []
        for line in self.lines:
            if line.lstrip().startswith("#"):
                continue
            said = line.strip()[:160]
            if _DIRECTIVE.search(line) or (not line.startswith("\t") and _MAKE_SETTING.search(line)):
                out.append(f"{said}: a directive of make this reader does not follow")
            if any(_SUBMAKE_FILE.search(m["rest"]) for m in _SUBMAKE.finditer(line)):
                out.append(f"{said}: a make told to read another makefile (a directive this reader does not follow)")
            if _DOCKER_OPTIONS.search(self.expand(line)):
                out.append(f"{said}: docker's own options before its command, never read here")
        out += [f"{raw.strip()[:160]}: a comment continued onto the next line, never read here"
                for raw in self.text.split("\n") if _CONTINUED_COMMENT.match(raw)]
        for line, _, launch, _ in self._launches():
            said = line.strip()[:160]
            out += [f"{said}: {fault}" for fault in launch.faults]
            if _RED.fullmatch(launch.image):
                out += [f"{said}: {danger}" for danger in launch.dangers]
            if not launch.faults and not _IMAGE.fullmatch(launch.image):
                out.append(f"{said}: an image not written plainly ({launch.image or 'none'})")
        return out

    def _compose(self):
        """Every compose of the Makefile, expanded: the words before its command, its command,
        the words after it."""
        for line in self.lines:
            if line.lstrip().startswith("#"):
                continue
            text = self.expand(line)
            for m in re.finditer(r"\bcompose\b", text):
                words = text[m.end():].split()
                at = next((i for i, w in enumerate(words) if w in _COMPOSE_COMMANDS), None)
                if at is not None:
                    yield line, words[:at], words[at], words[at + 1:]

    def compose_runs_with_mounts(self) -> list[str]:
        """`docker compose … run -v …` in a recipe: a mount the compose file does not hold."""
        return [line.strip()[:160] for line, _, command, after in self._compose()
                if command == "run" and any(re.match(r"-[A-Za-z]*v|--volume|--mount", w) for w in after)]

    def compose_other_files(self) -> list[str]:
        """A compose launch told to read a file other than docker-compose.yml (`-f`, `--file`,
        `--project-directory`, ``COMPOSE_FILE``): what it would start is never read here."""
        out = [f"{line.strip()[:160]}: {' '.join(before)}" for line, before, command, _ in self._compose()
               if command in _COMPOSE_LAUNCH and any(re.match(r"-f|--file\b|--project-directory\b", w)
                                                     for w in before)]
        return out + [line.strip()[:160] for line in self.lines
                      if not line.lstrip().startswith("#") and re.search(r"\bCOMPOSE_FILE\b", line)]

    def redefined(self) -> list[str]:
        """The variables a red docker run is made of that make defines more than once (`+=`, a
        second `=`/`:=`, one for a target): read here as the last, where make may keep another —
        or append a mount this test never sees."""
        made = set().union(*(run.seen for run in self.runs().values()))
        return [f"{name}: {', '.join(how for _, how in self.defs[name])}" for name in sorted(made)
                if len(self.defs.get(name, [])) > 1 or any(op == "+" for op, _ in self.defs.get(name, []))]


# compose's commands, all of them: the first of its words that is one is its command, what comes
# before are its own options. Those that start a container from its files:
_COMPOSE_COMMANDS = {"attach", "build", "commit", "config", "cp", "create", "down", "events", "exec", "export",
                     "images", "kill", "logs", "ls", "pause", "port", "ps", "pull", "push", "restart", "rm",
                     "run", "scale", "start", "stats", "stop", "top", "unpause", "up", "version", "wait",
                     "watch"}
_COMPOSE_LAUNCH = {"run", "up", "create", "start", "restart", "watch"}
# What compose reads unasked, beside docker-compose.yml (compose's lookup: the first of its
# names found is the file, and an override beside it merged into it): none is read here, so
# none may be there.
COMPOSE_LOOKUP = ("compose.yaml", "compose.yml", "docker-compose.yaml",
                  "compose.override.yml", "compose.override.yaml",
                  "docker-compose.override.yml", "docker-compose.override.yaml")


def compose_files_beside(root: Path) -> list[str]:
    return [name for name in COMPOSE_LOOKUP if os.path.lexists(root / name)]


def compose_unread(doc: dict) -> list[str]:
    """What the compose file holds that this reader does not read: another file it includes, a
    service that extends another or takes another's mounts, an image not written plainly (red or
    not, never known)."""
    out = ["include: another compose file"] if "include" in doc else []
    for name, s in doc.get("services", {}).items():
        out += [f"{name}: {key}" for key in ("extends", "volumes_from") if key in s]
        if not re.fullmatch(r"[\w./:@-]+", str(s.get("image", ""))):
            out.append(f"{name}: an image not written plainly ({s.get('image')!r})")
    return out


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
    return {name: run.options for name, run in MAKE.runs().items()}


def _red(make: Make | None = None) -> dict[str, list[Mount]]:
    """Every red container's mounts: the compose services of the injectors' image, the Makefile's
    launches of it."""
    out = {}
    for name, s in COMPOSE.items():
        if str(s.get("image", "")).split(":")[0] == RED_IMAGE:
            assert all(isinstance(v, str) for v in s.get("volumes") or []), name   # the short syntax only
            out[name] = [_mount(v) for v in s.get("volumes") or []]
    for name, run in (make or MAKE).runs().items():
        out[name] = run.mounts
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
    for name, run in MAKE.runs().items():
        for inside in re.findall(r"--init-file\s+(\S+)", run.command):
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
    """The recipe run by bash, in a home of the test's own: its history too, never the operator's."""
    import subprocess
    return subprocess.run(["bash", "-c", text.replace("$$", "$")], cwd=home,
                          env={"HOME": str(home), "HISTFILE": str(home / ".probe_history"), "PATH": "/usr/bin:/bin"},
                          capture_output=True, text=True)


@pytest.mark.parametrize("link", [".annatar", ".annatar/.bashrc", ".annatar/.bash_history"])
def test_the_shells_files_that_are_links_stop_it_before_docker(link, tmp_path):
    """M3498, M3499: a link in place of ~/.annatar, its .bashrc or its history stops `make
    annatar-shell` before docker (which resolves a bind's source on the host): its target never
    written — neither without the check nor by a file made before it."""
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

def _recipe(*lines: str) -> Make:
    """The Makefile and one more target, whose recipe is these lines."""
    return Make(MAKEFILE + "\nx-run:\n" + "".join(f"\t{line}\n" for line in lines))


def test_no_variable_of_a_red_run_is_defined_twice():
    """Read here as make keeps it; but a `+=`, a second definition or one for a target is where a
    mount slips past a reader — refused, said."""
    assert MAKE.redefined() == [], "variables of a red docker run defined more than once: " + "; ".join(
        MAKE.redefined())


def test_a_mount_appended_with_plus_equals_is_refused_and_read():
    make = Make(MAKEFILE + "\nANNATAR_VOLS += -v $(PWD)/scripts:/app/scripts\n")
    assert any(r.startswith("ANNATAR_VOLS: :=, +=") for r in make.redefined()), make.redefined()
    assert "-v $(PWD)/scripts:/app/scripts " in make.runs()["DOCKER_ANNATAR"].options + " "


def test_a_variable_defined_again_with_itself_is_refused_and_read():
    make = Make(MAKEFILE + "\nANNATAR_VOLS := $(ANNATAR_VOLS) -v $(PWD)/glorfindel:/app/glorfindel\n")
    assert any(r.startswith("ANNATAR_VOLS: :=, :=") for r in make.redefined()), make.redefined()
    assert "-v $(PWD)/glorfindel:/app/glorfindel" in make.runs()["DOCKER_ANNATAR"].options


def test_every_launch_of_the_makefile_is_read_whole():
    """M3493–M3495 (SEC20b): no directive makes make read beyond this reader, and every launch's
    options are read up to its image — none is refused in the Makefile as it is."""
    assert MAKE.unread() == []


def test_every_docker_run_names_its_image_plainly():
    """A docker run whose image is read at run time (``$$(cat …)``, ``"$$img"``) is never read
    here: neither the injectors' image nor a known one, it is refused."""
    for line in ("docker run --rm -v $(PWD)/scripts:/app/scripts $$(cat .image) annatar",
                 'img=eregion-x; docker run --rm -v $(PWD):/app "$$img" annatar',
                 "docker run --rm -v $(PWD):/app eregion-other annatar"):
        assert _recipe(line).unread(), line


@pytest.mark.parametrize("form", [
    "-v=$(PWD)/scripts:/app/scripts", "-v$(PWD)/scripts:/app/scripts", "-itv $(PWD)/scripts:/app/scripts",
    "-itv$(PWD)/scripts:/app/scripts", "-itv=$(PWD)/scripts:/app/scripts", "-it -v $(PWD)/scripts:/app/scripts",
    "--volume=$(PWD)/scripts:/app/scripts", "--volume $(PWD)/scripts:/app/scripts",
    "--mount type=bind,source=$(PWD)/scripts,target=/app/scripts",
    "--mount=type=bind,src=$(PWD)/scripts,dst=/app/scripts,readonly=false",
])
def test_every_form_of_a_mount_is_read(form):
    """M3490–M3492 (SEC20b): a mount is read in each form docker takes — glued, after `=`, in a
    group of short options, long, by `--mount` —, never refused, never missed."""
    make = _recipe(f"docker run --rm {form} $(IMAGE_ANNATAR) list")
    assert make.unread() == [], make.unread()
    assert _writes(_red(make)["x-run"], "scripts"), _red(make)["x-run"]


def test_a_read_only_mount_is_read_read_only():
    for form in ("--mount type=bind,source=$(PWD)/scripts,target=/app/scripts,readonly",
                 "--mount type=bind,src=$(PWD)/scripts,dst=/app/scripts,ro=true", "-v=$(PWD)/scripts:/app/scripts:ro"):
        make = _recipe(f"docker run --rm {form} $(IMAGE_ANNATAR) list")
        assert _red(make)["x-run"] == [Mount("scripts", "/app/scripts", True)], form


@pytest.mark.parametrize("form", [
    "--volumes-from other", "--volumes-from=other:ro",                              # another container's mounts
    "--mount type=bind,source=$(PWD)/scripts,target=/app/scripts,bind-propagation=shared",   # a key not read
    "--mount type=bind,target=/app/scripts",                                        # no source
    "-v /app/scripts",                                                              # no source
    "-x", "--oom-score-adj=1",                                                      # options not known here
])
def test_what_a_launch_holds_beyond_this_reader_is_refused(form):
    """M3528 (SEC20b): another container's mounts, a `--mount` not read whole, an option not known."""
    assert _recipe(f"docker run --rm {form} $(IMAGE_ANNATAR) list").unread(), form


@pytest.mark.parametrize("launch", ["docker container run", "docker  run", "docker\trun", "docker create",
                                    "docker container create", "docker container   create"])
def test_every_launch_form_is_read(launch):
    """M3493 (SEC20b): `docker container run`, `docker create`, whatever the spaces — a launch."""
    make = _recipe(f"{launch} --rm -v $(PWD)/scripts:/app/scripts $(IMAGE_ANNATAR) list")
    assert make.unread() == [] and _writes(_red(make)["x-run"], "scripts"), launch


@pytest.mark.parametrize("form", [
    "--privileged", "--privileged=true", "--device /dev/sda", "--device=/dev/sda", "--cap-add SYS_ADMIN",
    "--cap-add=ALL", "--pid host", "--pid=container:x", "--userns host", "--ipc host", "--ipc=container:x",
    "--uts host", "--network host", "--net=host", "--network container:x", "--security-opt apparmor=unconfined",
    "--security-opt=seccomp=unconfined", "--security-opt label=disable",
])
def test_what_the_red_is_never_given_is_refused_by_name(form):
    """M3527, M3529 (SEC20b): the host's devices, processes and namespaces, more capabilities, a
    confinement lifted — never given to a red launch, refused by name, not as options unknown."""
    make = _recipe(f"docker run --rm {form} $(IMAGE_ANNATAR) list")
    assert any("never given to the red" in r for r in make.unread()), make.unread()


def test_what_the_red_keeps_is_not_refused():
    for form in ("--security-opt no-new-privileges:true", "--security-opt=no-new-privileges", "--network bridge",
                 "--cap-drop ALL", "--ipc private"):
        assert _recipe(f"docker run --rm {form} $(IMAGE_ANNATAR) list").unread() == [], form


def test_no_dangerous_option_is_read_as_an_ordinary_one():
    """What the red is never given is never in the tables of options read: it is refused before them."""
    assert not set(_NEVER_TO_THE_RED) & (_LONG_FLAGS | _LONG_VALUED)


def test_a_launch_that_ends_a_quoted_command_is_read():
    """A launch inside ``ssh … '…'`` or ``"…"`` may end the quoted command: the quote that closes
    it is not the image's. A mount inside is read; past the quote, nothing is the container's."""
    for line in ("$(ORO_SSH) 'docker run --rm -v $$HOME/runs/annatar:/a $(IMAGE_ANNATAR)'",
                 '$(ORO_SSH) "docker run --rm -v $$HOME/runs/annatar:/a $(IMAGE_ANNATAR)"',
                 "$(ORO_SSH) 'timeout -k 10 '\"$$T\"' docker run --rm -v $$HOME/runs/annatar:/a $(IMAGE_ANNATAR)' || x"):
        make = _recipe(line)
        assert make.unread() == [], (line, make.unread())
        assert make.runs()["x-run"].mounts == [Mount("~/runs/annatar", "/a", False)], line
        assert make.runs()["x-run"].command == "", line


@pytest.mark.parametrize("line", [
    "docker run --rm $(IMAGE_ANNATAR)'",                       # no quote opened before it
    "$(ORO_SSH) 'docker run --rm $(IMAGE_ANNATAR)'x'",         # glued past the quote
    "$(ORO_SSH) 'docker run --rm $(IMAGE_ANNATAR)\"'",          # another quote
    "$(ORO_SSH) \"docker run --rm $(IMAGE_ANNATAR)'\"",          # the quote that is not the one opened
    "$(ORO_SSH) 'docker run --rm -v $(PWD)/x:/x' $(IMAGE_ANNATAR)",   # an option that closes the quote
])
def test_an_image_glued_to_anything_else_stays_refused(line):
    assert _recipe(line).unread(), line


def test_orodruins_control_run_is_read_whole():
    """OI2: the image received is run once, without network, before its tag — read whole, its
    options all known, no mount; `--network none` is the red's to keep."""
    run = MAKE.runs()["ORO_CHECK_RUN"]
    for option in ("--rm", "--read-only", "--cap-drop ALL", "--pull never", "--network none", "--no-healthcheck",
                   "--name eregion-annatar-check", "--entrypoint true"):
        assert option in run.options, option
    assert run.options.endswith(" eregion-annatar:incoming") and run.mounts == [] and "timeout" not in run.options
    assert any(name.startswith("orodruin-push") and r.options == run.options for name, r in MAKE.runs().items())


def test_a_launch_behind_dockers_own_options_is_refused():
    for line in ("docker --context other run --rm $(IMAGE_ANNATAR) list",
                 "docker -H unix:///run/docker.sock container run --rm $(IMAGE_ANNATAR) list"):
        assert _recipe(line).unread(), line


@pytest.mark.parametrize("reference", [
    "$(shell cat mounts.txt)", "-v $(shell cat mounts.txt):/app", "$(NEW_OF_A_DEFINE)", "$(OF_AN_INCLUDED_FILE)",
    "-v $(OF_AN_INCLUDED_FILE)/scripts:/app/scripts", "${PWD}", "$$EXTRA", "$${EXTRA}", "$$(cat mounts.txt)",
    "-v $$HOMEDIR/x:/app", "`cat mounts.txt`", "-e X=$$(id -u)",
])
def test_a_reference_left_unexpanded_is_refused(reference):
    """M3494 (SEC20b): in a launch's options, a reference this reader does not expand — a variable
    of a `define` or of an included file, `$(shell …)`, a variable of the shell — is refused: the
    mounts it would add are never seen. The home and the clone, `$(HOME)`, `$(PWD)`, `$$HOME`,
    are read."""
    make = _recipe(f"docker run --rm {reference} -v $(PWD)/runs/annatar:/app/runs/annatar $(IMAGE_ANNATAR) list")
    assert any("unexpanded" in r for r in make.unread()), make.unread()
    variable = Make(MAKEFILE + f"\nANNATAR_VOLS := $(ANNATAR_VOLS) {reference}\n")
    assert any("unexpanded" in r for r in variable.unread()), variable.unread()


def test_a_recipes_continuation_joins_its_lines_with_nothing_between():
    """M3525 (SEC20b): in a recipe, make passes a backslash-newline to the shell, the next line's tab
    taken off, and the shell joins the lines with nothing between — a word cut there is one word.
    Outside a recipe, make joins with a space."""
    make = _recipe("docker run --rm -e X=1\\", "$(IMAGE_ANNATAR) -v $(PWD)/scripts:/app/scripts $(IMAGE_ANNATAR) list")
    assert _writes(_red(make)["x-run"], "scripts"), _red(make)["x-run"]
    assert _logical("X := a\\\n\tb\n") == ["X := a \tb", ""]
    assert _logical("t:\n\tdocker run --rm\\\n\t\t-v a:b\n") == ["t:", "\tdocker run --rm\t-v a:b", ""]


def test_a_comment_continued_onto_the_next_line_is_refused():
    """M3526 (SEC20b): the shell ends a recipe's comment at its line and runs what follows; a reader
    that skips the comment would miss it — refused."""
    make = _recipe("# une note \\", "docker run --rm -v $(PWD)/scripts:/app/scripts $(IMAGE_ANNATAR) list")
    assert any("comment continued" in r for r in make.unread()), make.unread()
    assert any("comment continued" in r for r in Make(MAKEFILE + "\n# a note \\\nX := 1\n").unread())


def test_the_three_references_allowed_are_read():
    make = _recipe("docker run --rm -v $(HOME)/runs/annatar:/a -v $(PWD)/runs/annatar:/b -v $$HOME/runs/annatar:/c "
                   "$(IMAGE_ANNATAR) list")
    assert make.unread() == []
    assert {m.src for m in _red(make)["x-run"]} == {"~/runs/annatar", "runs/annatar"}


@pytest.mark.parametrize("directive", [
    "include other.mk", "-include local.mk", "sinclude local.mk",
    "define EXTRA\n-v $(PWD):/app\nendef", "define ANNATAR_VOLS =\n-v $(PWD):/app\nendef",
    "override define EXTRA\nendef", "export define EXTRA\nendef", "undefine ANNATAR_VOLS",
    "$(eval ANNATAR_VOLS += -v $(PWD):/app)", "x-eval:\n\t$(eval ANNATAR_VOLS := -v $(PWD):/app)",
    "${eval EXTRA := 1}",
    "SHELL := /bin/sh", "SHELL = ./x", "export SHELL := ./x", "x-run: SHELL := ./x", ".SHELLFLAGS := -ec",
    ".ONESHELL:", "load ./x.so", "-load x.so",
])
def test_a_directive_that_reads_beyond_this_reader_is_refused(directive):
    """M3495 (SEC20b): `include` and its kin, `define`, `undefine`, `$(eval …)` make make read
    what this reader does not; `SHELL`, `.SHELLFLAGS`, `.ONESHELL`, `load` change how it runs a
    recipe — refused, never read."""
    make = Make(MAKEFILE + "\n" + directive + "\n")
    assert any("directive" in r for r in make.unread()), make.unread()


def test_a_make_told_to_read_another_makefile_is_refused():
    for line in ("$(MAKE) -f other.mk annatar-run", "$(MAKE) --file=other.mk x", "$(MAKE) -sC elsewhere x",
                 "$(MAKE) --directory elsewhere x", "${MAKE} --makefile other.mk x"):
        assert any("another makefile" in r for r in _recipe(line).unread()), line
    for line in ("$(MAKE) --no-print-directory console-url || true", "$(MAKE) -s --no-print-directory x TEAM=check"):
        assert _recipe(line).unread() == [], line


def test_the_compose_file_holds_nothing_this_reader_does_not_read():
    """No `include` of another compose file, no service that extends another or takes another's
    mounts, every image written plainly."""
    doc = yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
    assert compose_unread(doc) == []
    for probe in ({"include": ["other.yml"]}, {"services": {"annatar": {"extends": {"service": "watch"}}}},
                  {"services": {"annatar": {"volumes_from": ["watch"]}}},
                  {"services": {"annatar": {"image": "${IMAGE:-eregion-annatar}"}}}):
        merged = {**doc, **probe, "services": {**doc["services"], **{
            n: {**doc["services"][n], **s} for n, s in probe.get("services", {}).items()}}}
        assert compose_unread(merged), probe


def test_no_recipe_mounts_by_hand_through_compose_run():
    """`docker compose … run -v …` adds a mount the compose file does not hold: refused."""
    assert MAKE.compose_runs_with_mounts() == []
    for line in ("docker compose --profile annatar run --rm -v $(PWD)/scripts:/app/scripts annatar list",
                 "docker-compose run --volume=$(PWD):/app annatar list",
                 "docker compose run --rm -v$(PWD):/app annatar list",
                 "docker compose run -dv $(PWD):/app annatar list",
                 "docker compose run --mount type=bind,source=$(PWD),target=/app annatar list"):
        assert _recipe(line).compose_runs_with_mounts(), line


def test_compose_reads_its_one_file():
    """M3496, M3497 (SEC20b): a compose launch of a recipe reads docker-compose.yml alone — never a
    file named by `-f`, `--file`, `--project-directory` or ``COMPOSE_FILE`` — and nothing beside it
    that compose would take in its place or merge into it."""
    assert MAKE.compose_other_files() == []
    assert compose_files_beside(ROOT) == []
    for line in ("docker compose -f other.yml --profile annatar run --rm annatar list",
                 "docker compose --profile annatar --file=other.yml up -d", "docker compose -fother.yml up -d",
                 "docker compose -p x --file other.yml create", "docker compose --project-directory elsewhere up -d",
                 "COMPOSE_FILE=other.yml docker compose up -d", "docker compose -f a.yml -f b.yml watch"):
        assert _recipe(line).compose_other_files(), line
    for line in ("docker compose logs -f", "docker compose -f other.yml config", "docker compose stop watch"):
        assert _recipe(line).compose_other_files() == [], line


@pytest.mark.parametrize("name", COMPOSE_LOOKUP)
def test_a_file_compose_would_read_beside_its_own_is_refused(name, tmp_path):
    (tmp_path / "docker-compose.yml").write_text("services: {}\n")
    assert compose_files_beside(tmp_path) == []
    (tmp_path / name).symlink_to(tmp_path / "nowhere")      # even a link, even dangling
    assert compose_files_beside(tmp_path) == [name]
