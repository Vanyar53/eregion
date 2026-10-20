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

The command and cleanup we hand the runner carry an explicit ``#!/bin/<executor>`` shebang:
Run Command's default interpreter is not guaranteed to be the test's executor (``bash`` vs
``sh``/dash), so a bash-only test would otherwise run under the wrong shell. This is the
adapter's equivalent of invoke-atomicredteam's ``bash -c``.
"""
from __future__ import annotations

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


def _load_technique(technique: str, atomics_dir: Path) -> dict:
    path = atomics_dir / technique / f"{technique}.yaml"
    if not path.is_file():
        raise AtomicError(
            f"no vendored atomic for {technique!r} at {path} — vendor it (annatar/atomics/PIN)"
        )
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(doc, dict) or not isinstance(doc.get("atomic_tests"), list):
        raise AtomicError(f"{path}: not an Atomic Red Team technique file")
    return doc


def _find_test(doc: dict, guid: str) -> dict:
    for test in doc["atomic_tests"]:
        if isinstance(test, dict) and test.get("auto_generated_guid") == guid:
            return test
    known = [t.get("auto_generated_guid") for t in doc["atomic_tests"] if isinstance(t, dict)]
    raise AtomicError(f"no atomic test with guid {guid!r}; this technique has {known}")


def _resolve_args(test: dict, overrides: dict | None) -> dict:
    """Input-argument defaults, overridden by anything the caller passed."""
    args = {}
    for name, spec in (test.get("input_arguments") or {}).items():
        args[name] = (spec or {}).get("default")
    for name, value in (overrides or {}).items():
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
