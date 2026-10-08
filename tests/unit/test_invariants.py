"""Invariants of isolation, release, reassertion and crashes (L24).

Random customer networks (fake_azure.FakeAzure) and random sequences of operations,
with faults injected anywhere: a throttled call (429), a crash before a write, a crash
after a write whose answer never came back, a full disk on the local state. Hypothesis
shrinks any failure to the shortest sequence that breaks a property.

What must hold whatever happens:
  I1  no VM is ever more reachable than the customer designed it;
  I2  the customer's configuration is never changed: rules, subnet associations, and a
      NIC carries its own NSG or Glorfindel's quarantine NSG, never none or another;
  I3  no success on a falsehood: "isolated" (no bypass reported) means isolated,
      "released" means back to the design, a verification that says True is true;
  I4  an operation on one VM changes nothing for another — homonyms included;
  I5  the reassertion never opens anything, never acts on a VM it has no state for,
      and writes nothing to Azure in human_only;
  I6  one VM, one state file, whatever the case of the id it was reached with;
  I7  from any state reached, with or without the local state, release brings every
      VM back to its design.

GLORFINDEL_INVARIANT_EXAMPLES raises the number of sequences (default 60);
GLORFINDEL_INVARIANT_STATS=1 prints what the sequences went through (run with -s).
"""
from __future__ import annotations

import collections
import os
import shutil
import tempfile
from pathlib import Path
from types import SimpleNamespace

from hypothesis import HealthCheck, event, settings, strategies as st
from hypothesis.stateful import (
    RuleBasedStateMachine, initialize, invariant, rule, run_state_machine_as_test,
)

from glorfindel import actions, escalations, reassert
from glorfindel.actions import AzureConnector, _load_isolation_state

from .fake_azure import AZURE_DNS, AZURE_IMDS, Crash, FakeAzure, key, open_flows

# ── the customer's network ───────────────────────────────────────────────────────

_TEMPLATES = {
    "allow-ssh": dict(direction="Inbound", source_address_prefix="*",
                      destination_address_prefix="*", destination_port_range="22"),
    "allow-https": dict(direction="Inbound", source_address_prefix="Internet",
                        destination_address_prefix="*", destination_port_range="443"),
    "allow-lateral-out": dict(direction="Outbound", source_address_prefix="*",
                              destination_address_prefix="VirtualNetwork", destination_port_range="*"),
}
# 100 is where Glorfindel's denies go first: a customer allow there precedes them.
_PRIORITIES = {"allow-ssh": [100, 101, 150, 1000], "allow-https": [100, 110, 1100],
               "allow-lateral-out": [100, 120, 1200]}

# Two VMs named `web` in two resource groups, NICs of the same name, one subnet in a
# hub resource group; a multi-NIC VM whose name has capitals and a double dash.
_VMS = [
    ("rg-app1", "web", [("rg-app1", "web-nic", ["10.0.0.4"])]),
    ("rg-app2", "web", [("rg-app2", "web-nic", ["10.0.0.5"])]),
    ("rg-app1", "Db--01", [("rg-app1", "db-nic-0", ["10.0.0.6"]),
                           ("rg-app1", "db-nic-1", ["10.0.0.7", "10.0.0.8"])]),
]


@st.composite
def _customer_rules(draw):
    rules, used = [], set()
    for name, tpl in _TEMPLATES.items():
        if not draw(st.booleans()):
            continue
        prio = draw(st.sampled_from(_PRIORITIES[name]))
        if (tpl["direction"], prio) in used:
            continue
        used.add((tpl["direction"], prio))
        rules.append(SimpleNamespace(name=name, priority=prio, access="Allow", protocol="*",
                                     source_port_range="*", **tpl))
    return rules


@st.composite
def _networks(draw):
    return {
        "quarantine": draw(st.booleans()),
        "subnet_nsg": draw(st.one_of(st.none(), _customer_rules())),
        "tier_rules": draw(_customer_rules()),
        "nics": {nic: {"own": draw(st.sampled_from([None, "dedicated", "tier"])),
                       "rules": draw(_customer_rules()),
                       "policy": draw(st.booleans())}
                 for _, _, nics in _VMS for _, nic, _ in nics},
    }


# A fault on the n-th call of an operation, before it reaches Azure (a throttled read or
# write, a crash) — or on the n-th WRITE, after Azure applied it and before the answer
# came back (the answer is an error, or the process is gone).
_FAULTS = st.one_of(st.none(), st.tuples(
    st.integers(1, 15), st.sampled_from(["before-429", "after-429", "before-crash", "after-crash"])))


class _Chaos:
    def __init__(self):
        self.plan = None
        self.calls = self.writes = 0

    def arm(self, fault):
        self.plan, self.calls, self.writes = fault, 0, 0

    def __call__(self, op: str, phase: str, write: bool):
        if phase == "before":
            self.calls += 1
        elif write:
            self.writes += 1
        if not self.plan:
            return
        when, what = self.plan[1].split("-")
        if phase != when or (self.calls if when == "before" else self.writes) != self.plan[0]:
            return
        if when == "after" and (not write or what == "429" and op == "state.write"):
            return
        self.plan = None
        if what == "crash":
            raise Crash(op)
        if op == "state.write":
            raise OSError(28, "No space left on device")
        from .fake_azure import throttled
        raise throttled(op)


_CURRENT = SimpleNamespace(chaos=None, mode="human_only")
_SEEN: collections.Counter = collections.Counter()


def _note(what: str) -> None:
    event(what)
    _SEEN[what] += 1


class IsolationMachine(RuleBasedStateMachine):
    def __init__(self):
        super().__init__()
        self.home = Path(tempfile.mkdtemp(prefix="glorfindel-l24-"))
        actions._ISOLATION_STATE_DIR = self.home / "isolation"
        actions._BLOCK_STATE_DIR = self.home / "blocks"
        escalations._STORE = self.home / "escalations.jsonl"
        self.chaos = _CURRENT.chaos = _Chaos()
        self.fake = FakeAzure(self.chaos)

    @initialize(net=_networks())
    def build(self, net):
        f = self.fake
        tier = f.add_nsg("rg-net", "nsg-tier", net["tier_rules"])
        subnet_nsg = None if net["subnet_nsg"] is None else f.add_nsg("rg-net", "nsg-subnet", net["subnet_nsg"])
        subnet = f.add_subnet("rg-net", "vnet-hub", "app", subnet_nsg)
        self.vms = []
        for rg, name, nics in _VMS:
            specs = []
            for nic_rg, nic, ips in nics:
                n = net["nics"][nic]
                own = {None: None, "tier": tier}.get(n["own"]) if n["own"] != "dedicated" \
                    else f.add_nsg(nic_rg, f"nsg-{nic}", n["rules"])
                specs.append({"rg": nic_rg, "name": nic, "ips": ips, "subnet": subnet,
                              "nsg": own, "policy": n["policy"]})
            self.vms.append(f.add_vm(rg, name, specs))
        self.design = f.snapshot()
        self.customer_nsgs = [n["id"] for n in self.design["nsgs"].values()]
        c = AzureConnector(dry_run=False)
        c._network, c._compute = f.network, f.compute
        c._quarantine_settings = lambda: (net["quarantine"], "")
        c._forensic_sources = lambda: []
        c.recent_changes = lambda *a, **k: []
        self.connector = c

    def teardown(self):
        try:
            if getattr(self, "connector", None) is not None:
                self._recover_everything(lose_state=True)
        finally:
            shutil.rmtree(self.home, ignore_errors=True)

    # ── observing ───────────────────────────────────────────────────────────────

    def _world(self) -> dict:
        f = self.fake
        return {"nsgs": f.nsgs, "nics": f.nics, "subnets": f.subnets, "vms": f.vms}

    def _flows(self) -> dict:
        world = self._world()
        return {vm: open_flows(world, vm) for vm in self.vms}

    def _designed(self, vm: str) -> frozenset:
        return open_flows(self.design, vm)

    def _state(self, vm: str):
        return _load_isolation_state(vm)

    def _nics_as_designed(self, vm: str) -> bool:
        return all(key(self.fake.nics[key(n)]["nsg"]) == key(self.fake.nics[key(n)]["design_nsg"])
                   for n in self.fake.vms[key(vm)]["nics"])

    def _released(self, vm: str) -> bool:
        return (open_flows(self._world(), vm) == self._designed(vm)
                and self._nics_as_designed(vm) and self._state(vm) is None)

    def _run(self, fault, fn, label=""):
        self.chaos.arm(fault)
        try:
            out, err = fn(), None
        except Crash as exc:
            out, err = None, exc
        except Exception as exc:
            out, err = None, exc
        finally:
            fired = fault is not None and self.chaos.plan is None
            self.chaos.plan = None
        if label:
            what = type(err).__name__ if err else (out or {}).get("status", (out or {}).get("verified", "ok"))
            _note(f"{label}: {what}" + (f" after {fault[1]}" if fired else ""))
        return out, err

    def _undeclared(self, vm: str, claim: dict) -> frozenset:
        """Open flows the claim doesn't admit: an isolation by rules can't deny Azure's DNS
        and IMDS to one VM (measured) — it must say so (`platform_open`), never hide it."""
        declared = set(claim.get("platform_open") or [])
        return frozenset(f for f in open_flows(self._world(), vm)
                         if not (f[0] in declared and f[3] in (AZURE_DNS, AZURE_IMDS)))

    def _draw(self, data):
        vm = data.draw(st.sampled_from(self.vms), label="vm")
        # The canonical id, or the lowercase id Log Analytics reports (_ResourceId).
        rid = data.draw(st.sampled_from([vm, vm.lower()]), label="rid")
        return vm, rid, data.draw(_FAULTS, label="fault")

    def _in_quarantine(self, vm: str) -> bool:
        """A NIC of the VM carries Glorfindel's quarantine NSG: it is meant to be cut
        off. That NSG is shared by every isolation of the region — putting its rules
        back for one VM re-seals the others, as it should."""
        return any(n["nsg"] and actions._is_quarantine_nsg(n["nsg"])
                   for n in (self.fake.nics[key(i)] for i in self.fake.vms[key(vm)]["nics"]))

    def _only_sealed(self, vm: str, before: frozenset, after: frozenset, what: str):
        assert after <= before, f"{what} opened flows of {vm}"
        assert after == before or self._in_quarantine(vm), f"{what} cut off {vm}"

    def _others_unchanged(self, vm: str, flows_before: dict, states_before: dict):
        flows = self._flows()
        for other in self.vms:
            if other == vm:
                continue
            self._only_sealed(other, flows_before[other], flows[other], f"I4: an operation on {vm}")
            assert self._state(other) == states_before[other], (
                f"I4: an operation on {vm} changed the state of {other}")

    # ── operations ──────────────────────────────────────────────────────────────

    @rule(data=st.data())
    def isolate(self, data):
        vm, rid, fault = self._draw(data)
        flows, states = self._flows(), {v: self._state(v) for v in self.vms}
        out, _ = self._run(fault, lambda: self.connector.isolate_vm(rid), "isolate")
        if out and out.get("status") == "isolated" and not out.get("bypass"):
            assert not self._undeclared(vm, out), f"I3: isolate_vm said isolated, {vm} still reachable"
            # ...and its verification agrees: a false alarm would have the reassertion
            # put back an isolation that holds.
            check, _ = self._run(None, lambda: self.connector.verify_isolation(rid))
            assert check and check.get("verified") is True, f"I3: fresh isolation of {vm} not verified: {check}"
            assert not self._undeclared(vm, check), f"I3: verify_isolation hides open flows of {vm}"
        self._others_unchanged(vm, flows, states)

    @rule(data=st.data())
    def release(self, data):
        vm, rid, fault = self._draw(data)
        flows, states = self._flows(), {v: self._state(v) for v in self.vms}
        out, _ = self._run(fault, lambda: self.connector.release_isolation(rid), "release")
        if out and out.get("status") == "released":
            assert self._released(vm), f"I3: release said released, {vm} is not back to its design"
        self._others_unchanged(vm, flows, states)

    @rule(data=st.data())
    def verify(self, data):
        vm, rid, fault = self._draw(data)
        iso, _ = self._run(fault, lambda: self.connector.verify_isolation(rid), "verify_isolation")
        if iso and iso.get("verified") is True:
            assert not self._undeclared(vm, iso), f"I3: verify_isolation True, {vm} reachable"
        rel, _ = self._run(None, lambda: self.connector.verify_release(rid))
        if rel and rel.get("verified") is True:
            assert open_flows(self._world(), vm) == self._designed(vm), (
                f"I3: verify_release True, {vm} not back to its design")

    @rule(data=st.data())
    def reassert(self, data):
        _CURRENT.mode = data.draw(st.sampled_from(["human_only", "non_disruptive"]), label="mode")
        fault = data.draw(_FAULTS, label="fault")
        flows = self._flows()
        had_state = {vm: self._state(vm) is not None for vm in self.vms}
        nics_before = {k: n["nsg"] for k, n in self.fake.nics.items()}
        report, _ = self._run(fault, lambda: reassert.reassert_active(self.connector, None))
        for r in report or []:
            _note(f"reassert ({_CURRENT.mode}): {r['outcome']}")
        after = self._flows()
        for vm in self.vms:
            assert after[vm] <= flows[vm], f"I5: the reassertion opened flows of {vm}"
            if _CURRENT.mode == "human_only":
                assert after[vm] == flows[vm], f"I5: the reassertion acted on {vm} in human_only"
            elif not had_state[vm]:
                self._only_sealed(vm, flows[vm], after[vm], "I5: the reassertion (no state)")
        if _CURRENT.mode == "human_only":
            assert {k: n["nsg"] for k, n in self.fake.nics.items()} == nics_before

    # ── the world moving under Glorfindel ───────────────────────────────────────

    @rule(data=st.data())
    def terraform_apply(self, data):
        """An NSG with inline rules: `apply` removes every rule absent from the code."""
        nsg = data.draw(st.sampled_from(self.customer_nsgs), label="nsg")
        rules = self.fake.nsgs[key(nsg)]["rules"]
        for name in [n for n in rules if n.startswith("glorfindel-")]:
            del rules[name]

    @rule(data=st.data())
    def strip_quarantine_nsg(self, data):
        """Someone deletes the deny rules of Glorfindel's own quarantine NSG."""
        ours = sorted(k for k, n in self.fake.nsgs.items() if n["tags"].get("managed-by") == "glorfindel")
        if ours:
            rules = self.fake.nsgs[data.draw(st.sampled_from(ours), label="quarantine")]["rules"]
            for name in ("glorfindel-quarantine-deny-in", "glorfindel-quarantine-deny-out"):
                rules.pop(name, None)

    @rule(data=st.data())
    def redeploy_nic(self, data):
        """A Bicep/ARM redeploy of the NIC puts the designed NSG back."""
        nic = data.draw(st.sampled_from(sorted(self.fake.nics)), label="nic")
        self.fake.nics[nic]["nsg"] = self.fake.nics[nic]["design_nsg"]

    @rule(data=st.data())
    def lose_state(self, data):
        """The state directory is lost (new container without its volume, disk wiped)."""
        vm = data.draw(st.sampled_from(self.vms), label="vm")
        for f in (actions._ISOLATION_STATE_DIR.glob("*.json")
                  if actions._ISOLATION_STATE_DIR.exists() else []):
            if actions._file_rid(f) == key(vm):
                f.unlink()

    @rule()
    def recover(self):
        self._recover_everything(lose_state=False)

    def _recover_everything(self, lose_state: bool):
        """I7: whatever was reached, release brings every VM back to its design."""
        self.chaos.plan = None
        for vm in self.vms:
            if lose_state and actions._ISOLATION_STATE_DIR.exists():
                for f in actions._ISOLATION_STATE_DIR.glob("*.json"):
                    if actions._file_rid(f) == key(vm):
                        f.unlink()
            for _ in range(3):
                if self.connector.release_isolation(vm)["status"] == "released":
                    break
        for vm in self.vms:
            assert self._released(vm), f"I7: {vm} could not be brought back to its design"

    # ── always ──────────────────────────────────────────────────────────────────

    @invariant()
    def never_more_open_than_designed(self):
        if not getattr(self, "design", None):
            return
        flows = self._flows()
        for vm in self.vms:
            assert flows[vm] <= self._designed(vm), f"I1: {vm} more reachable than designed"

    @invariant()
    def customer_configuration_untouched(self):
        if not getattr(self, "design", None):
            return
        for k, nsg in self.design["nsgs"].items():
            live = {n: r for n, r in self.fake.nsgs[k]["rules"].items() if not n.startswith("glorfindel-")}
            assert live == nsg["rules"], f"I2: customer rules of {nsg['id']} changed"
        for k, s in self.design["subnets"].items():
            assert key(self.fake.subnets[k]["nsg"]) == key(s["nsg"]), "I2: subnet NSG changed"
        for k, n in self.fake.nics.items():
            ok = key(n["nsg"]) == key(n["design_nsg"]) or (
                n["nsg"] and actions._is_quarantine_nsg(n["nsg"])
                and self.fake.nsgs[key(n["nsg"])]["tags"].get("managed-by") == "glorfindel")
            assert ok, f"I2: {n['id']} carries {n['nsg']}, designed {n['design_nsg']}"

    @invariant()
    def one_vm_one_state_file(self):
        d = actions._ISOLATION_STATE_DIR
        if not d.exists():
            return
        seen: dict[str, str] = {}
        for f in d.glob("*.json"):
            rid = actions._file_rid(f)
            assert rid not in seen, f"I6: two state files for {rid}: {seen.get(rid)}, {f.name}"
            seen[rid] = f.name
            assert f.name == f.name.lower(), f"I6: {f.name} is not lowercase"


def test_isolation_invariants(monkeypatch):
    real_write = actions._atomic_write_text

    def chaotic_write(path, text):
        _CURRENT.chaos("state.write", "before", True)
        real_write(path, text)
        _CURRENT.chaos("state.write", "after", True)

    monkeypatch.setattr(actions, "_atomic_write_text", chaotic_write)
    monkeypatch.setattr(reassert, "_mode", lambda autonomy, vm, ref="": _CURRENT.mode)
    run_state_machine_as_test(IsolationMachine, settings=settings(
        max_examples=int(os.environ.get("GLORFINDEL_INVARIANT_EXAMPLES", "60")),
        stateful_step_count=20, deadline=None, database=None,
        suppress_health_check=[HealthCheck.too_slow, HealthCheck.filter_too_much]))
    if os.environ.get("GLORFINDEL_INVARIANT_STATS"):
        for what, n in sorted(_SEEN.items()):
            print(f"{n:7d}  {what}")
