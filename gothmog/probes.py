"""Steady-state probes (G0): what "normal" is for a target, checked before, during and
after a fault — Chaos Toolkit's steady-state hypothesis, declared in the experiment
(``steady_state.probes``, ``schemas/experiment.schema.json``).

Three kinds, by ``verify``:

    power_state   the VM's power state (ARM, instanceView)        expect: PowerState/running
    vm_agent      the guest agent's status: the OS answers         expect: Ready
    <KQL>         a query on the bench's Log Analytics, ``{target}`` replaced by the VM's
                  id; its first row's ``last`` must be younger than N minutes and, after
                  a fault, later than its end                      expect: fresh <N>m

The heartbeat matters on its own: Chaos Studio ignores extension errors when it restarts
a VM (fault library, 09/2026) — a fault can "succeed" with the monitoring agent down, and
Glorfindel blind on that VM.

A probe that cannot be read is not normal (fail closed). An expectation Gothmog cannot
evaluate is refused when the experiment is loaded (``declared_errors``), never guessed.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from gothmog.engines.chaos_studio import _parse, agent_status, power_state

ARM_PROBES = ("power_state", "vm_agent")
_FRESH = re.compile(r"^fresh\s+(\d+)\s*m$")


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
                last = _parse(rows[0].get("last")) if rows else None
                observed = last.isoformat() if last else "no row"
                ok = (last is not None and last >= now - timedelta(minutes=minutes)
                      and (since is None or last > since))
        except Exception as e:  # unreadable is not normal
            observed, ok = f"unreadable: {type(e).__name__}: {e}"[:200], False
        out.append(ProbeResult(name, ok, observed, expect))
    return out


def holds(results: list[ProbeResult]) -> bool:
    return bool(results) and all(r.ok for r in results)
