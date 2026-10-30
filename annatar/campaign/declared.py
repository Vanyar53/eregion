"""A declared campaign (BL1, #280): techniques and faults chosen by a human, in order, from the
catalog — never by a planner, never a home-grown script.

    annatar campaign plan --target <resource_id> --declared annatar/campaign/declared/bl1-reponse.yaml

The file names what the campaign plays (``steps``: a technique by its ATT&CK id, a fault by its
id, a recovery between them), on which bench VMs (``targets``), in which zone and autonomy
mode, and what Glorfindel is expected to do at each step (``expect``). Annatar plans its
techniques from it (the synthesizer of the catalog, E1); Gothmog plays its faults
(``gothmog run <id>``); the operator plays the recoveries. Until the unified run of C1, the
campaign is these runs together: the campaign report attaches a fault run on one of its targets
around it (analysis/containment.py).

``problems`` checks a declaration against the catalog before anything is planned: each
technique implemented, on a public library's engine (never ``local-script``: no offensive logic
of our own), not destructive; each fault implemented, not destructive, declared by its
experiment file on the same targets, in the zone ``bench``; the zone ``bench`` (a fault and a
response run nowhere else — the production rule, O0) and the mode ``non_disruptive``.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

from annatar.campaign.catalog import load_catalog

REPO = Path(__file__).resolve().parents[2]
DECLARED_DIR = Path(__file__).resolve().parent / "declared"
# Gothmog's experiments, read as files (D1: Annatar never imports Gothmog).
FAULTS_DIR = REPO / "gothmog" / "experiments"
STEP_KINDS = ("technique", "fault", "recovery")
EXPECTATIONS = {"technique": ("contain",), "fault": ("no_disruptive_action",),
                "recovery": ("release",)}


@dataclass
class Step:
    kind: str
    ref: str = ""
    expect: str = ""


@dataclass
class Declared:
    id: str
    zone: str
    autonomy: str
    targets: list[str]
    steps: list[Step] = field(default_factory=list)
    description: str = ""

    @property
    def techniques(self) -> list[str]:
        return [s.ref for s in self.steps if s.kind == "technique"]

    @property
    def faults(self) -> list[str]:
        return [s.ref for s in self.steps if s.kind == "fault"]


def load(path: str | Path) -> Declared:
    """Read a declaration; a file that is not one raises ``ValueError``, saying why."""
    try:
        doc = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as e:
        raise ValueError(f"declared campaign unreadable: {e}") from e
    if not isinstance(doc, dict):
        raise ValueError("declared campaign: not a mapping")
    steps = []
    for i, s in enumerate(doc.get("steps") or [], 1):
        if not isinstance(s, dict):
            raise ValueError(f"step {i}: not a mapping")
        steps.append(Step(kind=str(s.get("kind") or ""), ref=str(s.get("ref") or ""),
                          expect=str(s.get("expect") or "")))
    targets = doc.get("targets") or []
    if not isinstance(targets, list):
        raise ValueError("targets: a list of VM names")
    return Declared(id=str(doc.get("id") or ""), zone=str(doc.get("zone") or ""),
                    autonomy=str(doc.get("autonomy") or ""), targets=[str(t) for t in targets],
                    steps=steps, description=str(doc.get("description") or ""))


def problems(d: Declared, catalog: dict | None = None, faults_dir: Path = FAULTS_DIR) -> list[str]:
    """What keeps this declaration from being played — ``[]`` when nothing does."""
    catalog = load_catalog() if catalog is None else catalog
    out = []
    if not d.id:
        out.append("id: missing")
    if d.zone != "bench":
        out.append(f"zone {d.zone or '(none)'}: a declared campaign with a fault and a response "
                   "runs on the bench only (the production rule)")
    if d.autonomy != "non_disruptive":
        out.append(f"autonomy {d.autonomy or '(none)'}: the response is measured in non_disruptive")
    if not d.targets:
        out.append("targets: none")
    if not d.techniques:
        out.append("steps: no technique — no incident to contain")
    for i, s in enumerate(d.steps, 1):
        where = f"step {i} ({s.kind} {s.ref})".replace(" )", ")")
        if s.kind not in STEP_KINDS:
            out.append(f"{where}: kind must be one of {', '.join(STEP_KINDS)}")
            continue
        if s.expect not in EXPECTATIONS[s.kind]:
            out.append(f"{where}: expect must be {' or '.join(EXPECTATIONS[s.kind])}")
        if s.kind == "technique":
            entry = catalog.get(s.ref)
            if not entry:
                out.append(f"{where}: not in the catalog")
                continue
            if entry.get("status") != "implemented":
                out.append(f"{where}: not implemented")
            if (entry.get("engine") or "local-script") == "local-script":
                out.append(f"{where}: a home-grown script — a public library's engine only")
            if entry.get("destructive") is not False:
                out.append(f"{where}: destructive (or unsaid) — not in a response campaign")
        elif s.kind == "fault":
            out += [f"{where}: {p}" for p in _fault_problems(s.ref, d.targets, faults_dir)]
    return out


def _fault_problems(fault_id: str, targets: list[str], faults_dir: Path) -> list[str]:
    path = Path(faults_dir) / f"{fault_id}.yaml"
    try:
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError):
        return [f"no experiment file {path.name} under {faults_dir.name}/"]
    if not isinstance(doc, dict) or doc.get("kind") != "fault" or doc.get("id") != fault_id:
        return [f"{path.name}: not the fault {fault_id}"]
    out = []
    if doc.get("status") != "implemented":
        out.append("not implemented")
    if doc.get("destructive") is not False:
        out.append("destructive (or unsaid)")
    declared = doc.get("targets") if isinstance(doc.get("targets"), dict) else {}
    if declared.get("zone") != "bench":
        out.append("its experiment does not run in the zone bench")
    names = {str(n).lower() for n in declared.get("names") or []}
    if not names or not names <= {t.lower() for t in targets}:
        out.append(f"its targets ({', '.join(sorted(names)) or 'none'}) are not the campaign's")
    return out
