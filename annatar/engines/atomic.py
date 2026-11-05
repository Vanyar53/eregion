"""Atomic Red Team adapter (R1): read a pinned atomic test and give the runner the exact
``command`` and ``cleanup_command`` to run on the target VM — no home-grown offensive logic.

The adapter is the only reader of the vendored definitions (``annatar/atomics/``, pinned in
``annatar/atomics/PIN``). Orodruin has no Internet, so the atomics ship in the image; we do
NOT run the upstream ``invoke-atomicredteam`` runner — we extract the test's own commands and
run them through Azure Run Command (every call journaled and capped by the Orodruin contract,
``annatar/executors/azure_vm.py``).

An ``engine_ref`` names one test: ``"<technique>/<auto_generated_guid>"`` — e.g.
``"T1136.001/40d8eabd-e394-46f6-8785-b9bfa1d011d2"``. We refuse anything we would not run
faithfully (fail closed), so a run never half-executes a test it could not prepare:
  - a test whose platform is not ``linux`` (gondolin is Linux; Run Command runs a shell);
  - an executor other than ``sh`` / ``bash`` (a Windows/PowerShell test is not ours to run);
  - a test with ``dependencies`` (prereqs) — out of scope for R1, kept deterministic;
  - a test declaring ``elevation_required: false`` (Run Command runs as root — that would
    misrepresent a test written for an unprivileged user);
  - a command/cleanup that still holds a ``#{...}`` placeholder after substitution (the
    regex only fills ``#{word}``; ``#{user-name}`` would otherwise reach the shell, where
    ``#`` opens a comment and the rest of the command vanishes);
  - a command/cleanup referring to ``PathToAtomicsFolder`` (only the YAML is vendored — the
    upstream atomics tree is not on the VM, so the path does not exist there).

The file is checked against its sha256 in ``annatar/atomics/PIN`` before it is read, at every
run (SEC5, V-30) — not only in CI: a vendored atomic edited alone, or a file the PIN does not
list, is refused before anything touches the target. The PIN lives beside the YAML, in the
same image: an edit that changes both together is not seen — this catches a drifted or
half-edited file, not a hostile image (that is the image's provenance, M-3).

The command and cleanup we hand the runner carry an explicit ``#!/bin/<executor>`` shebang:
Run Command's default interpreter is not guaranteed to be the test's executor (``bash`` vs
``sh``/dash), so a bash-only test would otherwise run under the wrong shell. This is the
adapter's equivalent of invoke-atomicredteam's ``bash -c``.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

ATOMICS_DIR = Path(__file__).resolve().parents[1] / "atomics"
SHELL_EXECUTORS = frozenset({"sh", "bash"})
LINUX = "linux"
_PLACEHOLDER = re.compile(r"#\{([a-zA-Z0-9_]+)\}")
# The upstream tree is not on the VM — only the YAML is vendored — so a command that points
# into it would run against a path that does not exist (bare or with a leading '$').
_NO_ATOMICS_FOLDER = "PathToAtomicsFolder"
# A PIN line: "#   <sha256>  <path relative to the atomics directory>".
_PIN_LINE = re.compile(r"^#\s+([0-9a-f]{64})\s+(\S+)\s*$")
# What an override (engine_args, VM3) may hold: a word, a number, an address or a path —
# nothing a shell would read as anything else.
_ARG_VALUE = re.compile(r"^[A-Za-z0-9._/:-]+$")
# The scenario's own revert (E1 `revert`, VM3): the one action an atomic run knows — remove
# the files the test leaves behind its upstream cleanup, in a temporary directory only.
REVERT_ACTIONS = frozenset({"remove_files"})
_REVERT_DIRS = ("/tmp/", "/var/tmp/")
_REVERT_KEYS = frozenset({"name", "action", "paths"})


class AtomicError(ValueError):
    """The ref cannot be run faithfully — refused before anything touches the target."""


@dataclass
class ResolvedAtomic:
    """One atomic test, resolved to the commands the runner will send to the VM."""

    technique: str
    guid: str
    name: str
    executor: str
    command: str
    cleanup_command: str
    args: dict = field(default_factory=dict)

    def substitute(self, text: str) -> str:
        """Fill ``#{var}`` in arbitrary text (a steady-state probe) with this test's args."""
        return _substitute(text, self.args)


def parse_ref(engine_ref: str) -> tuple[str, str]:
    """``"<technique>/<guid>"`` → ``(technique, guid)``; both parts are required."""
    parts = (engine_ref or "").split("/")
    if len(parts) != 2 or not parts[0].strip() or not parts[1].strip():
        raise AtomicError(
            f"engine_ref {engine_ref!r}: expected '<technique>/<auto_generated_guid>' "
            "(e.g. 'T1136.001/40d8eabd-e394-46f6-8785-b9bfa1d011d2')"
        )
    return parts[0].strip(), parts[1].strip()


def pinned_digests(atomics_dir: Path) -> dict[str, str]:
    """``{relative path: sha256}`` as ``PIN`` records them — {} when there is no PIN."""
    try:
        text = (atomics_dir / "PIN").read_text(encoding="utf-8")
    except OSError:
        return {}
    return {m.group(2): m.group(1) for m in map(_PIN_LINE.match, text.splitlines()) if m}


def _load_technique(technique: str, atomics_dir: Path) -> dict:
    path = atomics_dir / technique / f"{technique}.yaml"
    if not path.is_file():
        raise AtomicError(
            f"no vendored atomic for {technique!r} at {path} — vendor it (annatar/atomics/PIN)"
        )
    # SEC5 (V-30): the bytes we read are the bytes the PIN vouches for, checked at run time.
    raw = path.read_bytes()
    rel = f"{technique}/{technique}.yaml"
    pinned = pinned_digests(atomics_dir).get(rel)
    if pinned is None:
        raise AtomicError(f"{rel} has no sha256 in annatar/atomics/PIN — not run")
    if hashlib.sha256(raw).hexdigest() != pinned:
        raise AtomicError(
            f"{rel} does not match its sha256 in annatar/atomics/PIN — the vendored atomic "
            "was changed; not run"
        )
    doc = yaml.safe_load(raw.decode("utf-8"))
    if not isinstance(doc, dict) or not isinstance(doc.get("atomic_tests"), list):
        raise AtomicError(f"{path}: not an Atomic Red Team technique file")
    return doc


def _find_test(doc: dict, guid: str) -> dict:
    for test in doc["atomic_tests"]:
        if isinstance(test, dict) and test.get("auto_generated_guid") == guid:
            return test
    known = [t.get("auto_generated_guid") for t in doc["atomic_tests"] if isinstance(t, dict)]
    raise AtomicError(f"no atomic test with guid {guid!r}; this technique has {known}")


def _resolve_args(test: dict, overrides) -> dict:
    """Input-argument defaults, overridden by what the caller passed (``engine_args``, VM3).

    An override reaches a shell command as written, so it is held (fail closed): a mapping
    only, each key one of the test's own ``input_arguments``, each value a string or a number
    of ``_ARG_VALUE``'s characters (no space, no quote, no ``;``, ``$``, ``|``, ``&``…). Whether
    the values are the catalog's is the catalog's question (``catalog_destructive``)."""
    declared = test.get("input_arguments") or {}
    args = {name: (spec or {}).get("default") for name, spec in declared.items()}
    if overrides is None:
        return args
    if not isinstance(overrides, dict):
        raise AtomicError(
            f"engine_args must be a mapping of the test's input arguments, not "
            f"{type(overrides).__name__}"
        )
    for name, value in overrides.items():
        if name not in declared:
            raise AtomicError(
                f"engine_args {name!r} is not an input argument of this test "
                f"({sorted(declared)}) — refused"
            )
        if isinstance(value, bool) or not isinstance(value, (str, int, float)) \
                or not _ARG_VALUE.fullmatch(str(value)):
            raise AtomicError(
                f"engine_args {name!r}: {str(value)[:80]!r} is not a plain value "
                f"({_ARG_VALUE.pattern}) — refused, never sent to a shell"
            )
        args[name] = value
    return args


def _substitute(text: str, args: dict) -> str:
    def repl(match: re.Match) -> str:
        name = match.group(1)
        if name not in args or args[name] is None:
            raise AtomicError(f"unresolved atomic argument #{{{name}}} (no default, none given)")
        return str(args[name])

    return _PLACEHOLDER.sub(repl, text)


def _finalize(executor_name: str, text: str, guid: str, what: str) -> str:
    """The substituted command/cleanup, checked for anything we would not run faithfully,
    then given an explicit interpreter (Run Command's default shell is not guaranteed)."""
    if "#{" in text:
        raise AtomicError(
            f"atomic {guid} {what} still holds a '#{{...}}' placeholder after substitution: "
            f"{text!r} — the regex only fills '#{{word}}'; refused rather than sent raw "
            "(in a shell '#' opens a comment and the rest of the line is dropped)"
        )
    if _NO_ATOMICS_FOLDER in text:
        raise AtomicError(
            f"atomic {guid} {what} references {_NO_ATOMICS_FOLDER} — only the YAML is "
            "vendored, the upstream atomics tree is not on the VM, so the path does not exist"
        )
    return f"#!/bin/{executor_name}\n{text}"


def revert_commands(revert, resolved: ResolvedAtomic) -> list[tuple[str, str]]:
    """The scenario's ``revert`` (E1), as the commands the runner sends AFTER the atomic's own
    cleanup — ``[(name, command)]``, ``[]`` when there is none (VM3, #548).

    An upstream cleanup may restore the state and still leave its own files: T1053.003's keeps
    root's crontab in ``/tmp/notevil`` and the evil one in ``#{tmp_cron}``. The vendored test is
    never edited; the scenario says what to remove, and only that (fail closed): a list of
    steps, each ``{name, action: remove_files, paths: [...]}`` and nothing else; each path, its
    ``#{var}`` filled with the test's arguments, an absolute plain path (``_ARG_VALUE``, no
    ``..``) inside ``/tmp/`` or ``/var/tmp/``. The command is ``rm -f --``: a file or a link,
    never a directory, never what a link points to. Whether this revert is the catalog's is the
    catalog's question (``catalog_destructive``), as for ``engine_args``."""
    if revert is None:
        return []
    if not isinstance(revert, list):
        raise AtomicError(f"revert must be a list of steps, not {type(revert).__name__}")
    commands = []
    for i, step in enumerate(revert):
        if not isinstance(step, dict):
            raise AtomicError(f"revert step {i}: a mapping (name, action, paths), not "
                              f"{type(step).__name__}")
        extra = sorted(set(map(str, step)) - _REVERT_KEYS)
        if extra:
            raise AtomicError(f"revert step {i}: {extra} — only name, action and paths")
        name = step.get("name")
        if not isinstance(name, str) or not name.strip():
            raise AtomicError(f"revert step {i}: needs a name")
        if step.get("action") not in REVERT_ACTIONS:
            raise AtomicError(f"revert {name!r}: action {step.get('action')!r} is not one of "
                              f"{sorted(REVERT_ACTIONS)} — refused")
        paths = step.get("paths")
        if not isinstance(paths, list) or not paths:
            raise AtomicError(f"revert {name!r}: paths must be a non-empty list")
        filled = []
        for raw in paths:
            if not isinstance(raw, str):
                raise AtomicError(f"revert {name!r}: a path is text, not {type(raw).__name__}")
            path = resolved.substitute(raw)
            if not _ARG_VALUE.fullmatch(path) or ".." in path.split("/") \
                    or not path.startswith(_REVERT_DIRS) or path in _REVERT_DIRS:
                raise AtomicError(
                    f"revert {name!r}: {path[:80]!r} is not a plain file path inside "
                    f"{' or '.join(_REVERT_DIRS)} — refused, never sent to a shell"
                )
            filled.append(path)
        commands.append((name, "#!/bin/sh\nrm -f -- " + " ".join(filled)))
    return commands


def resolve_ref(engine_ref: str, args: dict | None = None,
                atomics_dir: Path | None = None) -> ResolvedAtomic:
    """Load and resolve the test an ``engine_ref`` names — ready to run, or refused."""
    technique, guid = parse_ref(engine_ref)
    doc = _load_technique(technique, atomics_dir or ATOMICS_DIR)
    test = _find_test(doc, guid)

    platforms = [str(p).lower() for p in (test.get("supported_platforms") or [])]
    if LINUX not in platforms:
        raise AtomicError(
            f"atomic {guid} runs on {platforms or ['(none)']}, not linux — not ours to run"
        )
    if test.get("dependencies"):
        raise AtomicError(f"atomic {guid} declares dependencies (prereqs) — out of scope for R1")

    executor = test.get("executor") or {}
    name = str(executor.get("name") or "").lower()
    if name not in SHELL_EXECUTORS:
        raise AtomicError(
            f"atomic {guid} executor is {name!r}, not one of {sorted(SHELL_EXECUTORS)}"
        )
    # Run Command runs as root. A test written for an unprivileged user (elevation_required:
    # false) would be misrepresented, so we refuse rather than silently escalate it.
    if executor.get("elevation_required") is False:
        raise AtomicError(
            f"atomic {guid} declares elevation_required: false — Run Command runs as root, "
            "which would misrepresent a test meant for an unprivileged user"
        )
    command = (executor.get("command") or "").strip()
    cleanup = (executor.get("cleanup_command") or "").strip()
    if not command:
        raise AtomicError(f"atomic {guid} has no command")
    if not cleanup:
        raise AtomicError(
            f"atomic {guid} has no cleanup_command — R1 requires a declared return to the "
            "initial state (we never leave the target changed)"
        )

    resolved_args = _resolve_args(test, args)
    return ResolvedAtomic(
        technique=technique,
        guid=guid,
        name=str(test.get("name") or guid),
        executor=name,
        command=_finalize(name, _substitute(command, resolved_args), guid, "command"),
        cleanup_command=_finalize(
            name, _substitute(cleanup, resolved_args), guid, "cleanup_command"
        ),
        args=resolved_args,
    )
