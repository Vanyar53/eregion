"""Dagorlad (docs/design/console.md, §7): may a wire run — an experiment of the catalogue, a
technique or a fault, towards one target — and if not, why.

The rules Orodruin applies at each injection (eregion_core/inscription.py: the bench's
perimeter, the enrollment, the zone and the production rule), plus those a request answers to
as a whole: the catalogue (an entry implemented, of the target's type, destructive or not — the
catalogue's word, never the browser's), a live watch (V1), a fault's engine aiming at this VM,
Orodruin's ceilings. The console judges with them on what it reads now, to advise (phase a);
Orodruin will judge again with them, at execution, and decide (phase b).

Pure: no Azure, no model, nothing written — the reader passes what it read. A refusal has a
stable code and its sentence, the first that holds (``REFUSALS``, in that order); a warning
leaves the wire valid and says what to watch for. D1: the shared core, read by the console and
by the injectors, none of them importing another.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from eregion_core.inscription import Scope, check_zone, enrollment
from eregion_core.orodruin import CEILING_INJECTIONS, CEILING_RUN_S

# In the order they are checked: the first that holds is the wire's.
REFUSALS = ("unknown_experiment", "not_implemented", "wrong_target_type", "outside_scope",
            "not_enrolled", "zone_forbids", "no_watch", "no_engine", "over_cap", "typed_name")
# ``typed_name``: Orodruin's alone (DG-b, eregion_core/exercise_runner.py) — a wire that asks for
# its target's name typed, without it or with another; the console never holds a name.
# A destructive technique asks for the target's name, typed (phase b); a fault whose engine's
# targets this host cannot read is judged by Gothmog's preflight, on Orodruin.
WARNINGS = ("typed_name", "engine_unknown")
# How long a wire holds Orodruin, for the ceiling of a request run one wire after the other: an
# estimate, never a measure — a technique, its attack, the wait for its detection and its
# cleanup; a fault, its declared duration, the return of its VM and the probes after.
TECHNIQUE_S = 10 * 60
FAULT_S = 15 * 60


@dataclass(frozen=True)
class Experiment:
    """An entry of the catalogue (technique_catalog.yaml, E1): a technique by its ATT&CK id, a
    fault by its id. ``destructive`` is None when the entry does not say."""
    id: str
    kind: str
    name: str
    resource_type: str
    status: str
    destructive: bool | None
    engine: str
    tactic: str = ""
    expected_latency_s: int | None = None

    @property
    def injector(self) -> str:
        return "gothmog" if self.kind == "fault" else "annatar"


def load_catalog(path: str | Path | None = None) -> dict[str, Experiment]:
    """The catalogue's techniques and faults, every resource type, planned ones too."""
    import yaml
    from eregion_core.experiment import CATALOG

    data = yaml.safe_load(Path(path or CATALOG).read_text(encoding="utf-8")) or {}
    out: dict[str, Experiment] = {}
    for rtype, body in (data.get("resource_types") or {}).items():
        for kind, key in (("technique", "techniques"), ("fault", "faults")):
            for e in (body or {}).get(key) or []:
                if not isinstance(e, dict):
                    continue
                eid = str(e.get("ttp") or e.get("id") or "")
                if not eid or eid in out:
                    continue
                d = e.get("destructive")
                latency = e.get("expected_latency_s")
                out[eid] = Experiment(
                    id=eid, kind=kind, name=str(e.get("name") or ""), resource_type=str(rtype),
                    status=str(e.get("status") or ""), destructive=d if isinstance(d, bool) else None,
                    engine=str(e.get("engine") or "local-script"), tactic=str(e.get("tactic") or ""),
                    expected_latency_s=latency if isinstance(latency, int) and latency > 0 else None)
    return out


@dataclass
class Target:
    """A target as read now, with its tags and its resource group's (inscription, O0)."""
    resource_id: str
    rg_tags: dict = field(default_factory=dict)
    tags: dict = field(default_factory=dict)
    resource_type: str = "azure_vm"

    @property
    def name(self) -> str:
        return self.resource_id.rstrip("/").rsplit("/", 1)[-1]


@dataclass
class Verdict:
    experiment: str
    target: str
    code: str = ""                  # a REFUSALS code, "" when the wire may run
    reason: str = ""
    zone: str = ""
    warnings: list[dict] = field(default_factory=list)   # [{code, text}]
    order: int | None = None        # its rank in the request, when it may run
    estimate_s: int | None = None

    @property
    def status(self) -> str:
        return "refused" if self.code else "warn" if self.warnings else "ok"

    def refuse(self, code: str, reason: str) -> "Verdict":
        assert code in REFUSALS, code
        self.code, self.reason = code, reason
        return self

    def to_dict(self) -> dict:
        return {"experiment": self.experiment, "target": self.target, "status": self.status,
                "code": self.code, "reason": self.reason, "zone": self.zone,
                "warnings": list(self.warnings), "order": self.order, "estimate_s": self.estimate_s}


def judge(experiment_id: str, target_id: str, target: Target | None, *,
          catalog: dict[str, Experiment], watch_refusal: str = "",
          fault_targets: dict[str, list[str] | None] | None = None,
          scope: Scope | None = None) -> Verdict:
    """One wire. ``target`` is what the reader read for ``target_id`` — None when it is not
    among the bench's VMs read now. ``watch_refusal`` is ``watch_gate.refusal()`` ("" when a
    live watch of these targets stands behind). ``fault_targets``: for a fault, the VM names its
    engine aims at, or None when this host cannot read them."""
    v = Verdict(experiment_id, target_id)
    e = catalog.get(experiment_id)
    if e is None:
        return v.refuse("unknown_experiment", f"{experiment_id!r} is not in the catalogue")
    if e.status != "implemented":
        return v.refuse("not_implemented", f"{e.id} is {e.status or 'not implemented'} in the catalogue: "
                                           "nothing runs it yet")
    rtype = target.resource_type if target is not None else "azure_vm"
    if e.resource_type != rtype:
        return v.refuse("wrong_target_type", f"{e.id} aims at {e.resource_type}, the target is {rtype}")
    scope = scope or Scope.for_bench()
    inside = scope.check(target_id)
    if not inside.allowed:
        return v.refuse("outside_scope", inside.reason)
    if target is None:
        return v.refuse("not_enrolled", "not among the bench's VMs read now: enrolled targets only")
    enrolled = enrollment(target.rg_tags, target.tags, bench=scope.sandbox)
    if not enrolled.allowed:
        return v.refuse("not_enrolled", enrolled.reason)
    v.zone = enrolled.zone
    zone = check_zone(enrolled.zone, kind=e.kind, destructive=e.destructive)
    if not zone.allowed:
        return v.refuse("zone_forbids", f"zone {enrolled.zone}: {zone.reason}")
    if watch_refusal:
        return v.refuse("no_watch", f"no live Glorfindel watch behind the run: {watch_refusal}")
    if e.kind == "fault":
        aimed = (fault_targets or {}).get(e.id)
        if aimed is None:
            v.warnings.append({"code": "engine_unknown", "text": f"the targets of {e.id}'s engine are "
                               "not readable here: Gothmog's preflight decides, on Orodruin"})
        elif target.name.lower() not in {n.lower() for n in aimed}:
            return v.refuse("no_engine", f"{e.id}'s engine aims at {', '.join(aimed) or 'no VM'}, "
                                         f"not {target.name}")
        elif len({n.lower() for n in aimed}) > 1:
            # A wire takes one VM (DG-b review): a fault that would act on others than the one
            # the operator sees and types is refused, never run wider.
            return v.refuse("no_engine", f"{e.id}'s engine aims at {', '.join(aimed)}: a wire "
                                         f"takes {target.name} alone")
    # Destructive, or nobody declared it is not (A0): the name is typed — an unknown is never
    # taken for harmless, here as in production (check_zone), and DG-b makes this a guard.
    if e.kind == "technique" and e.destructive is not False:
        what = "destructive" if e.destructive else "destructiveness not declared"
        v.warnings.append({"code": "typed_name", "text": f"{what}: the target's name will be typed "
                           "to run it, and checked by Orodruin"})
    return v


def plan(wires: list[tuple[str, str]], targets: dict[str, Target], *,
         catalog: dict[str, Experiment], watch_refusal: str = "",
         fault_targets: dict[str, list[str] | None] | None = None,
         scope: Scope | None = None, max_injections: int | None = None,
         max_run_s: int | None = None) -> list[Verdict]:
    """Every wire of a request, in the order drawn — the same pair once — and their rank: they
    run one after the other (Jonathan, 30/10). Past Orodruin's ceilings (``CEILING_INJECTIONS``
    wires at least one injection each, ``CEILING_RUN_S`` in all — or the cap Orodruin declares,
    lower, when it judges: DG-b), a wire is refused. With today's estimates the time comes first
    (12 techniques fill 2 h before 20 wires do); the count holds should an estimate shrink."""
    max_injections = CEILING_INJECTIONS if max_injections is None else min(max_injections, CEILING_INJECTIONS)
    max_run_s = CEILING_RUN_S if max_run_s is None else min(max_run_s, CEILING_RUN_S)
    seen: set[tuple[str, str]] = set()
    out: list[Verdict] = []
    rank, total = 0, 0
    for experiment_id, target_id in wires:
        key = (experiment_id, target_id.lower())
        if key in seen:
            continue
        seen.add(key)
        v = judge(experiment_id, target_id, targets.get(target_id.lower()), catalog=catalog,
                  watch_refusal=watch_refusal, fault_targets=fault_targets, scope=scope)
        if not v.code:
            estimate = FAULT_S if catalog[experiment_id].kind == "fault" else TECHNIQUE_S
            if rank + 1 > max_injections or total + estimate > max_run_s:
                v.refuse("over_cap", f"past Orodruin's ceilings: {max_injections} injections, "
                                     f"{max_run_s // 60} min in all, one wire after the other")
            else:
                rank += 1
                total += estimate
                v.order, v.estimate_s = rank, estimate
        out.append(v)
    return out
