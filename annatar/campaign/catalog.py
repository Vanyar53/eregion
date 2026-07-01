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
