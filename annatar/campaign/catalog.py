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
from pathlib import Path
from typing import Any

import yaml

CANONICAL_TACTIC_ORDER: list[str] = [
    "reconnaissance",
    "resource-development",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
]


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


def tactic_rank(tactic: str) -> int:
    """Kill-chain ordering index; unknown tactics sort last (stable)."""
    try:
        return CANONICAL_TACTIC_ORDER.index(tactic)
    except ValueError:
        return len(CANONICAL_TACTIC_ORDER)


REPO_ROOT = Path(__file__).resolve().parents[2]


def script_digest(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def script_pin(script: str, catalog: dict[str, dict[str, Any]] | None = None) -> str | None:
    """The sha256 the catalog gives a local script (``script_sha256`` of the entry that names it,
    SEC14 V-19) — None when no entry pins it."""
    for entry in (load_catalog() if catalog is None else catalog).values():
        pin = (entry.get("script_sha256") or {}).get(script)
        if isinstance(pin, str):
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
