"""Dagorlad's board (docs/design/console.md, §7, phase a): the red cards, the blue ones, and the
plan of the wires drawn between them — read only.

The red cards are the catalogue's entries; the blue ones, Glorfindel and the targets Celebrimbor
enrolled, with their zone and autonomy mode. A wire's verdict is the shared core's
(eregion_core/exercise_plan.py: the rules Orodruin applies, on what is read now); this module
adds what only Glorfindel's side knows — the VM isolated now, not seen by the watch, no rule for
the technique — and what to expect: the rule that detects, the delay, and what Glorfindel's
guards allow it at most in the target's mode. Computed from the configuration, never by the
model; nothing is written, nothing is launched. Glorfindel is never told: no part of this goes
where its decision reads.

Pure functions over what the routes read (eregion_console/api.py): the catalogue, the rules,
``/api/state``, the bench's VMs, the watch's gate.
"""
from __future__ import annotations

from eregion_core.exercise_plan import Experiment, Target, Verdict, plan as judge_plan


def same_technique(a: str, b: str) -> bool:
    """T1110.001 and T1110.001; a technique and one of its sub-techniques too."""
    a, b = a.upper(), b.upper()
    return bool(a and b) and (a == b or a.startswith(b + ".") or b.startswith(a + "."))


def rules_for(ttp: str, rules: list[dict], backend: str | None) -> list[dict]:
    """The enabled rules of the technique — bound to ``backend`` when the target's is known."""
    return [r for r in rules if r.get("enabled", True) and same_technique(ttp, r.get("ttp", ""))
            and (backend is None or not r.get("backend") or r["backend"] == backend)]


def _assets(state: dict) -> dict[str, dict]:
    return {str(a.get("resource_id") or "").lower(): a for a in state.get("discovered_assets") or []
            if a.get("resource_id")}


def _response(state: dict) -> dict[str, list[str]]:
    """resource id → what holds it now: ``isolated``, ``blocked``."""
    out: dict[str, list[str]] = {}
    for r in state.get("resources") or []:
        kinds = sorted({s.get("type", "") for s in r.get("states") or []} - {""})
        if kinds:
            out[str(r.get("resource_id") or "").lower()] = kinds
    return out


def red_cards(catalog: dict[str, Experiment], rules: list[dict], sections: dict) -> list[dict]:
    """Every entry of the catalogue: what runs first (techniques, then faults), then what is only
    planned. ``available`` is false for an entry nothing runs yet, or whose injector is not set up
    here — a card without a handle."""
    active = {s.get("id"): bool(s.get("active")) for s in sections.get("sections") or []}
    out = []
    for e in sorted(catalog.values(), key=lambda e: (e.status != "implemented", e.kind != "technique", e.id)):
        why = ""
        if e.status != "implemented":
            why = f"{e.status or 'not implemented'} in the catalogue"
        elif not active.get(e.injector, False):
            why = f"{e.injector.capitalize()} is not set up here"
        detecting = rules_for(e.id, rules, None) if e.kind == "technique" else []
        out.append({
            "id": e.id, "kind": e.kind, "name": e.name, "tactic": e.tactic, "injector": e.injector,
            "engine": e.engine, "resource_type": e.resource_type, "status": e.status,
            "destructive": e.destructive, "expected_latency_s": e.expected_latency_s,
            "rules": sorted({r["name"] for r in detecting}), "available": not why, "why": why,
        })
    return out


def blue_cards(vms: list[dict], state: dict, rules: list[dict], *, bench: str) -> list[dict]:
    """The bench's VMs that are enrolled — only those: a VM of the perimeter that is not (bree,
    the VM with a real load) has no card. Each with its zone, its effective mode and what holds
    it, what holds it now, whether the watch sees it, and the rules that apply to it."""
    from eregion_core.inscription import enrollment
    assets, held = _assets(state), _response(state)
    modes, holds = state.get("autonomy_modes") or {}, state.get("autonomy_holds") or {}
    out = []
    for vm in vms:
        verdict = enrollment(vm.get("rg_tags"), vm.get("tags"), bench=bench)
        if not verdict.allowed:
            continue
        rid, name = str(vm["resource_id"]), str(vm.get("name") or "")
        asset = assets.get(rid.lower())
        backend = (asset or {}).get("monitoring_backend") or None
        hold = holds.get(name) or {}
        out.append({
            "resource_id": rid, "name": name, "zone": verdict.zone, "legacy": verdict.legacy,
            "mode": "human_only" if state.get("read_only") else modes.get(name, state.get("autonomy_default") or "human_only"),
            "hold": hold.get("message") or hold.get("reason") or "",
            "read_only": bool(state.get("read_only")),
            "holds_now": held.get(rid.lower(), []),
            "seen": (asset or {}).get("last_seen") or "", "backend": backend or "",
            "rules": len([r for r in rules if r.get("enabled", True)
                          and (backend is None or not r.get("backend") or r["backend"] == backend)]),
        })
    return sorted(out, key=lambda c: (("bench", "twin", "production").index(c["zone"])
                                      if c["zone"] in ("bench", "twin", "production") else 3, c["name"]))


def other_types(catalog: dict[str, Experiment]) -> list[dict]:
    """The catalogue's target types other than a VM: no target of theirs is enrolled yet, and
    Glorfindel reads the activity log and Entra ID only once ID1 sends them to the workspace."""
    types: dict[str, dict] = {}
    for e in catalog.values():
        if e.resource_type != "azure_vm":
            t = types.setdefault(e.resource_type, {"type": e.resource_type, "entries": 0, "implemented": 0})
            t["entries"] += 1
            t["implemented"] += e.status == "implemented"
    return sorted(types.values(), key=lambda t: t["type"])


def glorfindel_card(watch: dict, rules: list[dict], state: dict, watch_refusal: str) -> dict:
    """Glorfindel, at the head of the blue side: never a wire's end, never told the plan."""
    enabled = [r for r in rules if r.get("enabled", True)]
    return {
        "watch": {k: watch.get(k) for k in ("status", "age_s")},
        "gate": watch_refusal,
        "rules": len(enabled), "client_rules": len([r for r in enabled if r.get("layer") == "client"]),
        "backends": sorted({r["backend"] for r in enabled if r.get("backend")}),
        "default_mode": state.get("autonomy_default") or "human_only",
        "read_only": bool(state.get("read_only")),
    }


def expected(e: Experiment, card: dict | None, rules: list[dict], threshold: float | None) -> dict:
    """What to expect from a wire allowed to run — an envelope from the configuration: what
    Glorfindel's guards allow it at most in the target's mode, never a forecast of its decision,
    and no call to the model. ``summary`` is the wire's pill."""
    if e.kind == "fault":
        return {"summary": "nothing disruptive", "rules": [], "latency_s": None,
                "glorfindel": "Glorfindel must neither isolate nor block on this noise (G0, G1); the steady "
                              "state is checked before and after, the return verified."}
    card = card or {}
    backend = card.get("backend") or None
    detecting = rules_for(e.id, rules, backend)
    latencies = [r["expected_latency_s"] for r in detecting if r.get("expected_latency_s")]
    latency = min(latencies) if latencies else e.expected_latency_s
    if not detecting:
        return {"summary": "no rule: blind, expect a miss", "rules": [], "latency_s": None,
                "glorfindel": "No enabled rule of this technique on the target's backend: Glorfindel is "
                              "blind to it. The run should end missed, and the purple loop propose a rule."}
    seen = f"detected ~{_minutes(latency)}" if latency else "detected"
    mode, hold = card.get("mode") or "human_only", card.get("hold") or ""
    gate = f" (confidence ≥ {round(threshold * 100)} %" if threshold is not None else " ("
    if card.get("read_only"):
        what, short = "It detects and recommends; nothing is executed (a read-only deployment).", "recommends"
    elif mode == "non_disruptive":
        what = ("It may isolate or block alone if every guard passes" + gate + ", a characterized "
                "signal attributed to this VM, telemetry read, draws that agree), then verify on Azure; "
                "otherwise a card naming the guard that held it.")
        short = "may contain alone"
    else:
        what = "A card to judge; a human acts" + (f" — held: {hold}." if hold else ".")
        short = "card"
    if e.destructive:
        what += " A restore is never autonomous: at most an isolation and a snapshot, the restore waits for a human."
    return {"summary": f"{seen} · {short}", "rules": sorted(r["name"] for r in detecting),
            "latency_s": latency, "glorfindel": what, "mode": mode}


def _minutes(seconds: int | None) -> str:
    if not seconds:
        return "?"
    return f"{round(seconds / 60)} min" if seconds >= 90 else f"{seconds} s"


def plan_view(wires: list[tuple[str, str]], *, catalog: dict[str, Experiment], vms: list[dict],
              state: dict, rules: list[dict], watch_refusal: str, bench: str,
              fault_targets: dict[str, list[str] | None], threshold: float | None,
              targets_error: str = "") -> dict:
    """The plan of the wires drawn: each one judged as Orodruin would judge it now (the shared
    core), with what only Glorfindel's side knows and what to expect; then what the phase (b)
    will check before anything runs. Nothing is launched, nothing is written."""
    from eregion_core.inscription import Scope
    cards = {c["resource_id"].lower(): c for c in blue_cards(vms, state, rules, bench=bench)}
    targets = {str(vm["resource_id"]).lower(): Target(str(vm["resource_id"]), vm.get("rg_tags") or {},
                                                       vm.get("tags") or {}) for vm in vms}
    verdicts = judge_plan(wires, targets, catalog=catalog, watch_refusal=watch_refusal,
                          fault_targets=fault_targets, scope=Scope(sandbox=bench))
    out = []
    for v in verdicts:
        card = cards.get(v.target.lower())
        if not v.code:
            _side_warnings(v, catalog[v.experiment], card, rules)
        row = v.to_dict()
        row["target_name"] = (card or {}).get("name") or v.target.rstrip("/").rsplit("/", 1)[-1]
        if not v.code:
            row["expected"] = expected(catalog[v.experiment], card, rules, threshold)
        out.append(row)
    allowed = [r for r in out if not r["code"]]
    checks = [
        {"ok": not watch_refusal, "text": "Glorfindel's watch live, of these targets"
         + (f" — {watch_refusal}" if watch_refusal else "")},
        {"ok": not targets_error, "text": "targets enrolled, zone read per wire"
         + (f" — {targets_error}" if targets_error else "")},
        {"ok": True, "text": "the catalogue decides what is destructive"},
        {"ok": None, "text": "Orodruin's contract: unknown here — it checks it before anything runs"},
    ]
    return {"wires": out, "checks": checks, "phase": "a",
            "total": {"wires": len(out), "allowed": len(allowed),
                      "refused": len(out) - len(allowed),
                      "estimate_s": sum(r["estimate_s"] or 0 for r in allowed)}}


def _side_warnings(v: Verdict, e: Experiment, card: dict | None, rules: list[dict]) -> None:
    """What only Glorfindel's side knows: the wire stays valid, its pill says it."""
    card = card or {}
    if card.get("holds_now"):
        v.warnings.append({"code": "isolated_now", "text": f"{card.get('name')} is "
                           f"{' and '.join(card['holds_now'])} now: the run would measure that, not the detection"})
    if not card.get("seen"):
        v.warnings.append({"code": "not_seen", "text": "Glorfindel does not see this VM now (deallocated, "
                           "or outside its workspaces): if it does not report once started, the run ends unknown"})
    if e.kind == "technique" and not rules_for(e.id, rules, card.get("backend") or None):
        v.warnings.append({"code": "no_rule", "text": "no enabled rule of this technique on the target's "
                           "backend: Glorfindel is blind to it, the run should end missed"})
