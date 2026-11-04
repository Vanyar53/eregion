"""Dagorlad's drills (DG-d, docs/design/console.md §7, « Les drills »): attacks and faults drawn
towards targets, kept and played again.

A drill is an object of the instance — neither Annatar's nor Gothmog's —, with a name and an
author (``operator``, ``annatar``, ``eregion``). It lives in layers, as the detection rules do:

- **shipped**: ``drills/<name>.yaml`` in the repository, reviewed in a PR, replaced by an update;
  its targets are **selectors** (a zone), never a VM's name: it does not know a client's VMs;
- **instance**: the client's, in the console's own directory (``~/.eregion/console/drills/``,
  ``EREGION_DRILLS_DIR``) — never ``runs/`` nor ``~/.glorfindel/``: a drill carries the red
  side's plan, which the decision never reads. Its targets are **names**. An update never
  touches it; one named as a shipped drill replaces it in this instance, and says so;
- the browser's draft, and the export (``to_yaml``), are this same format.

Never a resource id: it changes when Celebrimbor rebuilds the bench. ``read`` is the one way in,
exact (no field more, none of the wrong kind), on the console's host and on the operator's
machine alike.

Its targets are never chosen in the operator's place (Jonathan, 03/11): a named wire takes its VM
when it is enrolled here; a selector's wire stays **unplaced** until the operator gives its VMs —
one or several of its zone's candidates, or all of them (``place``). Nothing starts by itself: a
drill placed is wires on the board, or a request (``eregion_core.exercise_request``) the operator
then carries to Orodruin, which judges every wire again.

D1: the shared core — the console, the operator's command and Orodruin read it, none of them
importing another.
"""
from __future__ import annotations

import json
import os
import re
import sys
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from eregion_core.orodruin import CEILING_INJECTIONS

SHIPPED, INSTANCE = "shipped", "instance"
AUTHORS = ("operator", "annatar", "eregion")
ZONES = ("bench", "twin", "production")
FIELDS = ("name", "author", "wires")
OPTIONAL = ("description", "updated")
WIRE_FIELDS = ("experiment", "target")
MAX_WIRES = CEILING_INJECTIONS
MAX_BYTES = 64 * 1024
MAX_DESCRIPTION = 300
# A drill directory lists at most this many: an instance's drills are a handful.
MAX_DRILLS = 200

DRILLS_ENV = "EREGION_DRILLS_DIR"

# ASCII only, matched whole: a drill's name is a file's name and a word of a command.
_NAME = re.compile(r"[a-z0-9][a-z0-9-]{0,47}")
# As a request reads them (eregion_core/exercise_request.py): a catalogue id, a VM's name — never
# a path, never a resource id (no '/').
_EXPERIMENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
_VM_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")


class DrillRefused(ValueError):
    """A drill the one reader does not take, or cannot place: why, in a sentence."""


@dataclass(frozen=True)
class DrillWire:
    experiment: str
    name: str = ""      # a VM's name (an instance's drill)
    zone: str = ""      # a selector: the enrolled VMs of this zone (a shipped drill)

    def target_doc(self) -> dict:
        return {"name": self.name} if self.name else {"zone": self.zone}


@dataclass(frozen=True)
class Drill:
    name: str
    author: str
    wires: tuple[DrillWire, ...]
    description: str = ""
    updated: str = ""
    layer: str = ""

    def to_doc(self) -> dict:
        doc: dict = {"name": self.name, "author": self.author}
        if self.description:
            doc["description"] = self.description
        if self.updated:
            doc["updated"] = self.updated
        doc["wires"] = [{"experiment": w.experiment, "target": w.target_doc()} for w in self.wires]
        return doc


def valid_name(value) -> bool:
    return isinstance(value, str) and bool(_NAME.fullmatch(value))


def _exact(doc, required: tuple[str, ...], optional: tuple[str, ...], what: str) -> None:
    if not isinstance(doc, dict):
        raise DrillRefused(f"{what} is not a mapping")
    extra = sorted(str(k) for k in set(doc) - set(required) - set(optional))
    if extra:
        raise DrillRefused(f"{what} carries a field it never holds: {', '.join(extra)}")
    missing = [f for f in required if f not in doc]
    if missing:
        raise DrillRefused(f"{what} lacks {', '.join(missing)}")


def read(doc, layer: str) -> Drill:
    """The drill, or ``DrillRefused``: exactly its fields — a name, an author, 1 to MAX_WIRES
    wires, an optional description and time —, each of its kind. A shipped drill is Eregion's
    and aims by selector only; an instance's aims by name only. The same pair once."""
    if layer not in (SHIPPED, INSTANCE):
        raise DrillRefused(f"no layer {layer!r}")
    _exact(doc, FIELDS, OPTIONAL, "the drill")
    if not valid_name(doc["name"]):
        raise DrillRefused("its name is not 1 to 48 of a-z, 0-9 and '-', starting with a letter or a digit")
    author = doc["author"]
    if author not in AUTHORS:
        raise DrillRefused(f"its author is not one of {', '.join(AUTHORS)}")
    if (layer == SHIPPED) != (author == "eregion"):
        raise DrillRefused("a shipped drill is Eregion's, an instance's never is" if layer == SHIPPED
                           else "an instance's drill is never Eregion's: Eregion's are shipped")
    description = doc.get("description", "")
    if not isinstance(description, str) or len(description) > MAX_DESCRIPTION \
            or not all(c.isprintable() for c in description):
        raise DrillRefused(f"its description is not one line of at most {MAX_DESCRIPTION} characters")
    updated = doc.get("updated", "")
    if updated or layer == INSTANCE:
        try:
            when = datetime.fromisoformat(updated) if isinstance(updated, str) else None
        except ValueError:
            when = None
        if when is None or when.tzinfo is None:
            raise DrillRefused("its time (updated) is not an ISO time with its zone")
    wires = doc["wires"]
    if not isinstance(wires, list) or not 1 <= len(wires) <= MAX_WIRES:
        raise DrillRefused(f"its wires are not a list of 1 to {MAX_WIRES}")
    out, seen = [], set()
    for i, w in enumerate(wires, 1):
        _exact(w, WIRE_FIELDS, (), f"wire {i}")
        e, t = w["experiment"], w["target"]
        if not isinstance(e, str) or not _EXPERIMENT.fullmatch(e):
            raise DrillRefused(f"wire {i}: its experiment is not a catalogue id")
        if not isinstance(t, dict) or len(t) != 1 or not set(t) <= {"name", "zone"}:
            raise DrillRefused(f"wire {i}: its target is exactly {{name: <a VM>}} or {{zone: <a zone>}}")
        if "name" in t:
            if layer == SHIPPED:
                raise DrillRefused(f"wire {i}: a shipped drill never names a VM — a selector "
                                   f"({{zone: {'|'.join(ZONES)}}})")
            if not isinstance(t["name"], str) or not _VM_NAME.fullmatch(t["name"]):
                raise DrillRefused(f"wire {i}: its target is not a VM's name")
            wire = DrillWire(e, name=t["name"])
        else:
            if layer == INSTANCE:
                raise DrillRefused(f"wire {i}: an instance's drill names its VMs — never a selector")
            if t["zone"] not in ZONES:
                raise DrillRefused(f"wire {i}: its zone is not one of {', '.join(ZONES)}")
            wire = DrillWire(e, zone=t["zone"])
        key = (e, wire.name.lower(), wire.zone)
        if key in seen:
            raise DrillRefused(f"wire {i}: the same pair twice")
        seen.add(key)
        out.append(wire)
    return Drill(doc["name"], author, tuple(out), description, updated, layer)


def to_yaml(drill: Drill) -> str:
    """The drill as its file holds it — the export: the same format in every layer."""
    import yaml
    return yaml.safe_dump(drill.to_doc(), sort_keys=False, allow_unicode=True, default_flow_style=False,
                          width=1000)


# ── The layers ──────────────────────────────────────────────────────────────────────────

def shipped_dir() -> Path:
    """Eregion's reference drills: ``drills/`` at the repository's root."""
    return Path(__file__).resolve().parents[1] / "drills"


def instance_dir() -> Path:
    """The client's drills: the console's own directory (``~/.eregion/console/drills``, or
    ``EREGION_DRILLS_DIR``) — never under ``runs/`` nor ``~/.glorfindel/``."""
    return Path(os.environ.get(DRILLS_ENV) or Path.home() / ".eregion" / "console" / "drills")


def load_file(path: str | Path, layer: str) -> Drill:
    """One drill's file: read bounded, never through a link, its name its file's."""
    import yaml
    path = Path(path)
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    except OSError as e:
        raise DrillRefused(f"{path.name} unreadable: {e.strerror or e}") from None
    with os.fdopen(fd, "rb") as f:
        if not _regular(f.fileno()):
            raise DrillRefused(f"{path.name} is not a regular file")
        body = f.read(MAX_BYTES + 1)
    if len(body) > MAX_BYTES:
        raise DrillRefused(f"{path.name} larger than {MAX_BYTES} bytes")
    try:
        doc = yaml.safe_load(body.decode("utf-8"))
    except (UnicodeDecodeError, yaml.YAMLError):
        raise DrillRefused(f"{path.name} is not YAML") from None
    drill = read(doc, layer)
    if f"{drill.name}.yaml" != path.name:
        raise DrillRefused(f"{path.name} holds the drill {drill.name!r}: a drill's file is <its name>.yaml")
    return drill


def _regular(fd: int) -> bool:
    import stat
    return stat.S_ISREG(os.fstat(fd).st_mode)


def _files(directory: Path) -> tuple[list[Path], int]:
    """The first MAX_DRILLS drill files of ``directory``, and how many more it holds."""
    try:
        paths = sorted(p for p in directory.glob("*.yaml"))
    except OSError:
        return [], 0
    return paths[:MAX_DRILLS], max(0, len(paths) - MAX_DRILLS)


def listing(shipped: Path | None = None, instance: Path | None = None) -> list[dict]:
    """Every drill of the two layers, the instance's over the shipped ones: name, layer, author,
    updated, description, wires — a file that cannot be read is listed with why (never left out
    unsaid), and an instance's drill named as a shipped one says that it replaces it. A layer of
    more than MAX_DRILLS drills says how many are not listed."""
    found: dict[str, dict] = {}
    for layer, directory in ((SHIPPED, shipped or shipped_dir()), (INSTANCE, instance or instance_dir())):
        paths, more = _files(Path(directory))
        if more:
            found[f"…{layer}"] = {"name": "…", "layer": layer, "author": "", "updated": "", "description": "",
                                  "wires": [], "replaces": "",
                                  "error": f"{more} more drill(s) in this layer, past the first {MAX_DRILLS}: not listed"}
        for path in paths:
            entry = {"name": path.stem, "layer": layer, "author": "", "updated": "", "description": "",
                     "wires": [], "error": "", "replaces": ""}
            try:
                d = load_file(path, layer)
                entry.update(author=d.author, updated=d.updated, description=d.description,
                             wires=[{"experiment": w.experiment, "target": w.target_doc()} for w in d.wires])
            except DrillRefused as e:
                entry["error"] = str(e)
            if layer == INSTANCE and path.stem in found and found[path.stem]["layer"] == SHIPPED:
                entry["replaces"] = SHIPPED
            found[path.stem] = entry
    return sorted(found.values(), key=lambda e: (e["layer"] != INSTANCE, e["name"]))


def find(name: str, shipped: Path | None = None, instance: Path | None = None) -> Drill:
    """The drill named ``name``: the instance's when it holds one — even unreadable: then refused,
    never the shipped one in its place —, else the shipped one."""
    if not valid_name(name):
        raise DrillRefused(f"{name!r} is not a drill's name")
    own = Path(instance or instance_dir()) / f"{name}.yaml"
    if os.path.lexists(own):
        return load_file(own, INSTANCE)
    ref = Path(shipped or shipped_dir()) / f"{name}.yaml"
    if os.path.lexists(ref):
        return load_file(ref, SHIPPED)
    raise DrillRefused(f"no drill {name!r} in this instance nor among the shipped ones")


def new(name: str, pairs: list[tuple[str, str]], *, author: str = "operator", description: str = "",
        now: datetime | None = None) -> Drill:
    """An instance's drill of these (experiment, VM name) pairs, in their order, dated now —
    passed through ``read`` like any other."""
    now = now or datetime.now(timezone.utc)
    doc = {"name": name, "author": author, "updated": now.isoformat(timespec="seconds"),
           "wires": [{"experiment": e, "target": {"name": t}} for e, t in pairs]}
    if description:
        doc["description"] = description
    return read(doc, INSTANCE)


def save(drill: Drill, directory: Path | None = None, *, replace: bool = False) -> Path:
    """Write an instance's drill whole — beside it first, then in its place — mode 600 in a
    directory 700; over a drill of the same name only with ``replace``."""
    if drill.layer != INSTANCE:
        raise DrillRefused("only an instance's drill is written here: the shipped ones are the repository's")
    directory = Path(directory or instance_dir())
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = directory / f"{drill.name}.yaml"
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=f".{drill.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(to_yaml(drill))
        if replace:
            os.replace(tmp, path)
        else:
            try:
                os.link(tmp, path)          # never over another: refused when it exists
            except FileExistsError:
                raise DrillRefused(f"a drill {drill.name!r} exists already: replace it, or choose another name") from None
            os.unlink(tmp)
    except BaseException:
        if os.path.lexists(tmp):
            os.unlink(tmp)
        raise
    return path


# ── Placing a drill's wires on targets (Jonathan, 03/11) ─────────────────────────────────

@dataclass(frozen=True)
class Candidate:
    """An enrolled VM read now: its name, its resource id, its zone."""
    name: str
    resource_id: str
    zone: str


def candidates(vms: list[dict], bench: str | None = None) -> list[Candidate]:
    """The enrolled VMs among ``vms`` (``TagEnrollment.vms``' shape: name, resource_id, tags,
    rg_tags), each with its zone — the only VMs a drill's wire may take. ``bench``: the bench's
    id, else ``EREGION_BENCH`` (``Scope.for_bench``'s)."""
    from eregion_core.inscription import BENCH_ENV, DEFAULT_BENCH, enrollment
    bench = bench or os.environ.get(BENCH_ENV, DEFAULT_BENCH)
    out = []
    for vm in vms or []:
        if not isinstance(vm, dict) or not vm.get("resource_id"):
            continue
        verdict = enrollment(vm.get("rg_tags"), vm.get("tags"), bench=bench)
        if verdict.allowed:
            rid = str(vm["resource_id"])
            out.append(Candidate(str(vm.get("name") or rid.rstrip("/").rsplit("/", 1)[-1]), rid, verdict.zone))
    return sorted(out, key=lambda c: (c.zone, c.name.lower()))


@dataclass
class Placed:
    """One wire of the drill, placed: the VMs it takes (``targets``), and for a selector its
    zone's candidates; ``why`` says why it takes none (a name not enrolled here, a selector
    waiting for its VMs)."""
    rank: int
    experiment: str
    name: str = ""
    zone: str = ""
    targets: list[Candidate] = field(default_factory=list)
    candidates: list[Candidate] = field(default_factory=list)
    why: str = ""

    def to_dict(self) -> dict:
        return {"rank": self.rank, "experiment": self.experiment, "name": self.name, "zone": self.zone,
                "targets": [c.__dict__ for c in self.targets],
                "candidates": [c.__dict__ for c in self.candidates], "why": self.why}


def parse_targets(value: str | None) -> list[str] | str | None:
    """``TARGETS``: empty → None (nothing given), ``all``, or VM names separated by commas."""
    value = (value or "").strip()
    if not value:
        return None
    if value == "all":
        return "all"
    names = [n.strip() for n in value.split(",") if n.strip()]
    bad = [n for n in names if not _VM_NAME.fullmatch(n)]
    if bad:
        raise DrillRefused(f"TARGETS: {', '.join(map(repr, bad))} is not a VM's name")
    return names


def place(drill: Drill, cands: list[Candidate], targets: list[str] | str | None = None) -> list[Placed]:
    """Each wire of the drill on its VMs — never one chosen in the operator's place: a named wire
    takes its VM when it is enrolled here, and only one is (a name that several enrolled VMs bear —
    a twin copied from a bench — takes none, its VMs as candidates); a selector's wire takes the VMs of its zone that
    ``targets`` gives (a list of names, or ``all``) — none without it. ``targets`` names that no
    selector's wire can take are refused (``unknown_targets``)."""
    by_zone: dict[str, list[Candidate]] = {}
    for c in cands:
        by_zone.setdefault(c.zone, []).append(c)
    wanted = None if targets in (None, "all") else {n.lower() for n in targets}
    out = []
    for rank, w in enumerate(drill.wires, 1):
        p = Placed(rank, w.experiment, name=w.name, zone=w.zone)
        if w.name:
            found = [c for c in cands if c.name.lower() == w.name.lower()]
            if len(found) > 1:
                # A twin copied from a bench keeps its names: never one of them taken unsaid.
                p.candidates = found
                p.why = f"{w.name} names {len(found)} enrolled VMs here"
            elif found:
                p.targets = found
            else:
                p.why = f"{w.name} is not an enrolled VM read here"
        else:
            zone = by_zone.get(w.zone, [])
            p.candidates = list(zone)
            if targets is None:
                p.why = f"to place: zone {w.zone}, {len(zone)} candidate(s)"
            else:
                p.targets = list(zone) if targets == "all" else [c for c in zone if c.name.lower() in wanted]
                if not p.targets:
                    p.why = (f"zone {w.zone}: no enrolled VM read here" if not zone
                             else f"zone {w.zone}: none of the VMs given is one of its candidates")
        out.append(p)
    return out


def unknown_targets(placed: list[Placed], targets: list[str] | str | None) -> list[str]:
    """The names of ``targets`` that no selector's wire of the drill can take."""
    if targets in (None, "all"):
        return []
    takeable = {c.name.lower() for p in placed if p.zone for c in p.candidates}
    return [n for n in targets if n.lower() not in takeable]


def pairs(placed: list[Placed]) -> list[tuple[str, str]]:
    """The (experiment, resource id) pairs of a placed drill, in the drill's order — each wire's
    VMs in its candidates' order: the wires of a request."""
    return [(p.experiment, c.resource_id) for p in placed for c in p.targets]


# ── On the operator's machine: a request from a drill (``make orodruin-exercise DRILL=``) ──

def _read_vms(path: str | None) -> list[dict]:
    """The bench's VMs read now by Azure with the operator's identity — or, given on the command
    line only (``--vms``, ``make … DRILL_VMS=``), a listing read elsewhere (tests; a machine without
    Azure access), said."""
    if path:
        with open(path, encoding="utf-8") as f:
            vms = json.load(f)
        if not isinstance(vms, list):
            raise DrillRefused(f"--vms {path}: not a list of VMs")
        print(f"the bench's VMs read from {path}, not from Azure", file=sys.stderr)
        return vms
    from eregion_core.inscription import TagEnrollment
    return TagEnrollment().vms(os.environ.get("AZURE_SUBSCRIPTION_ID", ""))


def request_from(drill: Drill, vms: list[dict], targets: list[str] | str | None, *, catalog: dict,
                 bench: str | None = None, now: datetime | None = None):
    """The request this drill makes on the VMs read now, judged as Orodruin will judge it — or
    ``DrillRefused``, with every wire's candidates when one waits for its VMs. Nothing is chosen
    in the operator's place, nothing is written here."""
    from eregion_core import exercise_plan as xp
    from eregion_core import exercise_request as xr
    cands = candidates(vms, bench)
    placed = place(drill, cands, targets)
    unknown = unknown_targets(placed, targets)
    if unknown:
        raise DrillRefused(f"TARGETS: {', '.join(unknown)} is the candidate of no wire of {drill.name}")
    waiting = [p for p in placed if not p.targets]
    if waiting:
        lines = []
        for p in waiting:
            if p.zone:
                names = " | ".join(c.name for c in p.candidates) or "none"
                lines.append(f"  wire {p.rank} ({p.experiment}): {p.why} — choose: {names}")
            else:
                said = " | ".join(f"{c.name} (group {c.resource_id.split('/')[4]}, zone {c.zone})" for c in p.candidates)
                lines.append(f"  wire {p.rank} ({p.experiment}): {p.why}" + (
                    f" — {said}: load it on the board and choose the VM there" if said else ""))
        hint = "\n  give TARGETS=<vm>,<vm>… or TARGETS=all" if any(p.zone for p in waiting) else ""
        raise DrillRefused(f"the drill {drill.name} is not placed:\n" + "\n".join(lines) + hint)
    wires = pairs(placed)
    by_id = {str(vm.get("resource_id") or "").lower(): vm for vm in vms if isinstance(vm, dict)}
    seen = {rid.lower(): xp.Target(by_id[rid.lower()]["resource_id"], by_id[rid.lower()].get("rg_tags") or {},
                                   by_id[rid.lower()].get("tags") or {}) for _, rid in wires}
    verdicts = xp.plan(wires, seen, catalog=catalog)   # the bench's scope: EREGION_BENCH, as Orodruin's
    refused = [v for v in verdicts if v.code]
    if refused:
        raise DrillRefused("a wire refused, nothing is sent:\n" + "\n".join(
            f"  {v.experiment} → {xr.shown(v.target.rsplit('/', 1)[-1])}: {v.code} — {v.reason}" for v in refused))
    return xr.new(wires, now=now)


def main(argv: list[str] | None = None) -> int:
    """``python -m eregion_core.drill request <drill.yaml> <request.json> --layer <layer>
    [--targets all|<vm>,…]`` (the operator's machine, ``make orodruin-exercise DRILL=``): prints
    the request's id; ``check-name <name>``."""
    import argparse
    from eregion_core import exercise_request as xr

    ap = argparse.ArgumentParser(prog="python -m eregion_core.drill")
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("request")
    r.add_argument("drill")
    r.add_argument("request")
    r.add_argument("--layer", choices=(SHIPPED, INSTANCE), required=True)
    r.add_argument("--name", required=True, help="the drill asked for (DRILL=)")
    r.add_argument("--targets", default="")
    r.add_argument("--vms", default="", help="a listing of the bench's VMs read elsewhere, not Azure")
    k = sub.add_parser("check-name")
    k.add_argument("name")
    args = ap.parse_args(argv)
    if args.cmd == "check-name":
        if valid_name(args.name):
            return 0
        print(f"✗ DRILL={args.name!r}: not a drill's name (a-z, 0-9, '-')", file=sys.stderr)
        return 1
    from eregion_core.exercise_plan import load_catalog
    try:
        drill = load_file(args.drill, args.layer)
        if drill.name != args.name:
            raise DrillRefused(f"the drill read is {drill.name!r}, not {args.name!r}")
        targets = parse_targets(args.targets)
        req = request_from(drill, _read_vms(args.vms or None), targets, catalog=load_catalog(),
                           bench=os.environ.get("EREGION_BENCH") or None)
    except (DrillRefused, OSError, ValueError) as e:
        lines = str(e).splitlines() or [""]
        print("✗ " + "\n".join(xr.shown(line) for line in lines) + " — nothing is sent", file=sys.stderr)
        return 1
    fd = os.open(args.request, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(req.to_dict(), f, indent=2)
        f.write("\n")
    print(f"drill {drill.name} ({drill.layer}, {len(req.wires)} wire(s)) → request {req.id}", file=sys.stderr)
    print(req.id)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
