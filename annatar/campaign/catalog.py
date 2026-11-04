"""Load the shared technique catalog (``technique_catalog.yaml``).

This is the ONLY coupling contract between Annatar (red) and Glorfindel (blue).
Annatar reads the RED block (``reference_script``, ``setup_scripts``, ``destructive``,
``requires_testdata``, ``safe_target``, ``testdata_marker``, ``params``) plus the
shared ``ttp``/``tactic``/``status``; the blue block is informative for the synthesizer's
``detection.hints``.

Mirrors ``glorfindel/detection_authoring.py``'s loader (same file, same candidate paths)
but lives here so Annatar does not import from the glorfindel package.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Any

import yaml

# The kill-chain order: one definition, in the shared core (DG-e), which the console's
# « Ask Annatar for a drill » reads too — never this package (D1).
from eregion_core.proposal import CANONICAL_TACTIC_ORDER, tactic_rank  # noqa: F401


def _catalog_candidates(path: str | Path | None) -> list[Path]:
    if path:
        return [Path(path)]
    return [
        Path("technique_catalog.yaml"),  # cwd (repo root)
        Path(__file__).resolve().parents[2] / "technique_catalog.yaml",  # repo root from annatar/campaign/
    ]


def load_catalog(path: str | Path | None = None) -> dict[str, dict[str, Any]]:
    """Return ``{ttp: entry}`` with ``resource_type`` merged into each entry.

    Best-effort: a missing/unreadable file yields ``{}`` (the planner then has no
    techniques to pick — a clean, loud-but-non-crashing degradation).
    """
    for candidate in _catalog_candidates(path):
        if not candidate.exists():
            continue
        try:
            data = yaml.safe_load(candidate.read_text()) or {}
        except yaml.YAMLError:
            return {}
        out: dict[str, dict[str, Any]] = {}
        for rtype, body in (data.get("resource_types") or {}).items():
            for entry in (body or {}).get("techniques") or []:
                ttp = entry.get("ttp")
                if not ttp:
                    continue
                out[ttp] = {**entry, "resource_type": rtype}
        return out
    return {}


def implemented_techniques(
    catalog: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    """Techniques the synthesizer may materialize+execute now (``status: implemented``)."""
    return [e for e in catalog.values() if e.get("status") == "implemented"]


REPO_ROOT = Path(__file__).resolve().parents[2]


def script_digest(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _relative(script: str) -> str:
    """A script's path as the catalog writes it: normal (``./``, ``a/../``), relative to the
    repository — an absolute path under it made relative (SEC14 review, V-19)."""
    path = os.path.normpath(script)
    if os.path.isabs(path):
        root = os.path.normpath(str(REPO_ROOT))
        if os.path.commonpath([path, root]) == root:
            path = os.path.relpath(path, root)
    return path


def script_pin(script: str, catalog: dict[str, dict[str, Any]] | None = None) -> str | None:
    """The sha256 the catalog gives a local script (``script_sha256`` of the entry that names it,
    SEC14 V-19) — None when no entry pins it. The path is compared normal: ``./scripts/vm/x.sh``,
    ``scripts/../scripts/vm/x.sh`` or its absolute path are the catalog's ``scripts/vm/x.sh``."""
    want = _relative(script)
    for entry in (load_catalog() if catalog is None else catalog).values():
        for path, pin in (entry.get("script_sha256") or {}).items():
            if isinstance(pin, str) and _relative(str(path)) == want:
                return pin
    return None


def _pinned(entry: dict[str, Any], script: str) -> bool:
    """The script on disk is the one the entry vouched for: its sha256 is the entry's pin."""
    pin = (entry.get("script_sha256") or {}).get(script)
    try:
        return isinstance(pin, str) and script_digest((REPO_ROOT / script).read_bytes()) == pin
    except OSError:
        return False


def catalog_destructive(ttp: str, *, engine: str = "", engine_ref: str = "",
                        scripts: list[str] | tuple[str, ...] | None = None,
                        catalog: dict[str, dict[str, Any]] | None = None) -> bool | None:
    """Does the catalog say this technique destroys or alters data? ``None`` when it does not
    say (SEC5, V-19) — the caller counts that as destructive, never as harmless.

    The catalog decides, not the scenario: the entry of the technique, and only for the source
    the catalog names. An atomic (``engine: atomic``) must be the entry's own ``engine_ref``;
    a local script, the entry's ``reference_script`` or one of its ``setup_scripts`` — each of
    ``scripts``, when given —, its content the one the entry pins (``script_sha256``, SEC14
    V-19: a path is not a content; ``scripts/`` may be written). Another test, another script,
    a script changed, or an engine the entry does not declare is not what the catalog vouched
    for: ``None``."""
    entry = (load_catalog() if catalog is None else catalog).get(ttp) or {}
    if not entry:
        return None
    if engine and engine != "local-script":
        if entry.get("engine") != engine or entry.get("engine_ref") != engine_ref:
            return None
    elif scripts:
        known = {entry.get("reference_script")} | set(entry.get("setup_scripts") or [])
        if any(s not in known or not _pinned(entry, s) for s in scripts):
            return None
    flag = entry.get("destructive")
    return flag if isinstance(flag, bool) else None
