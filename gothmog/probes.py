"""Steady-state probes (G0): what "normal" is for a target, checked before, during and
after a fault — Chaos Toolkit's steady-state hypothesis, declared in the experiment
(``steady_state.probes``, ``schemas/experiment.schema.json``).

Three kinds, by ``verify``:

    power_state   the VM's power state (ARM, instanceView)        expect: PowerState/running
    vm_agent      the guest agent's status: the OS answers         expect: Ready
    <KQL>         a query on the bench's Log Analytics, ``{target}`` replaced by the VM's
                  id; its first row's ``LastSeen`` must be younger than N minutes and,
                  after a fault, later than its end                expect: fresh <N>m
                  (not ``last``: a KQL keyword, a syntax error — measured 19/10)

The heartbeat matters on its own: Chaos Studio ignores extension errors when it restarts
a VM (fault library, 09/2026) — a fault can "succeed" with the monitoring agent down, and
Glorfindel blind on that VM.

A probe marked ``during: true`` must hold while the fault runs too (G1): benign noise — load,
disk writes — leaves the VM serving; noise that takes it down is no longer benign, and the run
cancels it — at once on a reading that says so, after a few polls in a row on a probe that
cannot be read (a throttled API is not the VM down). A shutdown marks none: the VM is down by
design.

The fault's effect (G1, ``effect.probes``) is what shows it happened, as Glorfindel's own
telemetry sees it — a noise never seen there would pass for a noise Glorfindel ignored:

    power_state   the VM on its way down, or down, while the fault runs  expect: down
    <KQL>         a query, ``{target}``, ``{start}`` and ``{end}`` replaced by the VM's id and
                  the fault's start and end (or now); its first row's ``Peak`` must be above N
                                                                        expect: above <N>

A probe that cannot be read is not normal (fail closed). An expectation Gothmog cannot
evaluate is refused when the experiment is loaded (``declared_errors``), never guessed.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from gothmog.engines.chaos_studio import DOWN, _parse, agent_status, power_state

ARM_PROBES = ("power_state", "vm_agent")
_FRESH = re.compile(r"^fresh\s+(\d+)\s*m$")
_ABOVE = re.compile(r"^above\s+(\d+(?:\.\d+)?)$")
EFFECT_DOWN = "down"
UNREADABLE = "unreadable"   # how a probe that could not be read says so (its ``observed``)


@dataclass
class ProbeResult:
    name: str
    ok: bool
    observed: str
    expect: str


def declared_errors(probes: list[dict] | None) -> list[str]:
    if not probes:
        return ["steady_state declares no probe: 'normal' would be unverifiable"]
    errors = []
    for p in probes:
        name, verify, expect = p.get("name") or "?", p.get("verify") or "", str(p.get("expect") or "")
        if not verify or not expect:
            errors.append(f"probe {name}: verify and expect are both required")
        elif verify not in ARM_PROBES and not _FRESH.match(expect):
            errors.append(f"probe {name}: a query expects 'fresh <N>m', not {expect!r}")
        if not isinstance(p.get("during", False), bool):
            errors.append(f"probe {name}: during is true or false")
    return errors


def effect_errors(probes: list[dict] | None) -> list[str]:
    if not probes:
        return ["effect declares no probe: a fault never seen would pass for one Glorfindel ignored"]
    errors = []
    for p in probes:
        name, verify, expect = p.get("name") or "?", p.get("verify") or "", str(p.get("expect") or "")
        if verify == "power_state":
            if expect != EFFECT_DOWN:
                errors.append(f"effect {name}: power_state expects {EFFECT_DOWN!r}, not {expect!r}")
        elif verify in ARM_PROBES or not verify:
            errors.append(f"effect {name}: power_state or a query, not {verify!r}")
        elif not _ABOVE.match(expect):
            errors.append(f"effect {name}: a query expects 'above <N>', not {expect!r}")
    return errors


def evaluate(probes: list[dict], target: str, bench, *, since: datetime | None = None,
             now: datetime | None = None) -> list[ProbeResult]:
    """Each probe against ``target``. ``since``: a query's last row must be later (after a
    fault, its end — an old heartbeat proves nothing about the return)."""
    now = now or datetime.now(timezone.utc)
    vm = None
    out = []
    for p in probes:
        name, verify, expect = p["name"], p["verify"], str(p["expect"])
        try:
            if verify in ARM_PROBES:
                vm = vm or bench.vm(target)
                observed = power_state(vm) if verify == "power_state" else agent_status(vm)
                ok = observed == expect
            else:
                minutes = int(_FRESH.match(expect).group(1))
                rows = bench.query(verify.replace("{target}", target.replace("'", "")))
                last = _parse(rows[0].get("LastSeen")) if rows else None
                observed = last.isoformat() if last else "no row"
                ok = (last is not None and last >= now - timedelta(minutes=minutes)
                      and (since is None or last > since))
        except Exception as e:  # unreadable is not normal
            observed, ok = f"{UNREADABLE}: {type(e).__name__}: {e}"[:200], False
        out.append(ProbeResult(name, ok, observed, expect))
    return out


def holds(results: list[ProbeResult]) -> bool:
    return bool(results) and all(r.ok for r in results)


def _kql_time(t: datetime) -> str:
    return t.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def observe(probes: list[dict], target: str, bench, *, start: datetime,
            end: datetime) -> list[ProbeResult]:
    """Each effect probe against ``target``, the fault running from ``start`` to ``end``. A
    query is bounded by them: noise before the fault, or after it, is not its effect."""
    vm = None
    out = []
    for p in probes:
        name, verify, expect = p["name"], p["verify"], str(p["expect"])
        try:
            if verify == "power_state":
                vm = vm or bench.vm(target)
                observed = power_state(vm)
                ok = observed in DOWN
            else:
                floor = float(_ABOVE.match(expect).group(1))
                rows = bench.query(verify.replace("{target}", target.replace("'", ""))
                                   .replace("{start}", _kql_time(start)).replace("{end}", _kql_time(end)))
                peak = rows[0].get("Peak") if rows else None
                ok = isinstance(peak, (int, float)) and not isinstance(peak, bool) and peak > floor
                observed = "no row" if not rows else str(peak) if peak is not None else \
                    "nothing between the fault's start and end"
        except Exception as e:  # unreadable is not seen
            observed, ok = f"{UNREADABLE}: {type(e).__name__}: {e}"[:200], False
        out.append(ProbeResult(name, ok, observed, expect))
    return out
