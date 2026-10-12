"""Invariants of isolation, blocking, release, reassertion and crashes (L24, L26).

Random customer networks (fake_azure.FakeAzure) and random sequences of operations,
with faults injected anywhere — a throttled call (429), a crash before a write, a crash
after a write whose answer never came back, a full disk on the local state — and a
world that moves under Glorfindel: the customer adds, narrows and removes rules,
deletes an NSG, changes an IP, sets a policy, redeploys a NIC, runs `terraform apply`;
someone edits Glorfindel's own rules or tags; the role is removed; the configuration
changes or can't be read; a VM is deleted. Hypothesis shrinks any failure to the
shortest sequence that breaks a property.

What must hold whatever happens:
  I1  no VM is ever more reachable than its owner designed it — the design follows the
      customer's own changes; the forensic access the operator configured is the one
      deliberate exception;
  I2  Glorfindel never changes the customer's configuration: the customer's rules are
      what the customer last wrote, a subnet keeps its NSG, a NIC carries the NSG the
      customer gave it or Glorfindel's quarantine NSG, never none or another;
  I3  no success on a falsehood: "isolated" (no bypass reported) means isolated,
      "blocked" means the attacker is cut off, "released" means back to the design with
      nothing of Glorfindel's left on the NICs, a verification that says True is true;
  I4  an operation on one VM changes nothing for another — homonyms included (a
      perimeter block closes the attacker's flows on its subnet, and only those);
  I5  the reassertion never opens anything, never acts on a VM it has no state for,
      and writes nothing to Azure in human_only;
  I6  one VM, one state file, whatever the case of the id it was reached with;
  I7  from any state reached, release brings every VM back to its design — or, when a
      NIC's original NSG can't be known or no longer exists, keeps that NIC in
      quarantine and says so; once the operator supplies it, the release completes;
  I8  what Glorfindel leaves on Azure after an operation that returned is in its state;
  I9  a release that has started is never undone by the reassertion;
  I10 the configuration is honoured: no quarantine NSG when the operator turned it off
      or when the configuration can't be read, and only in the group it names.

GLORFINDEL_INVARIANT_EXAMPLES raises the number of sequences (default 60);
GLORFINDEL_INVARIANT_STEPS their length (default 30);
GLORFINDEL_INVARIANT_DB keeps the failing sequences in that directory and replays them
first (the nightly run fills it, every push replays it);
GLORFINDEL_INVARIANT_STATS=1 prints what the sequences went through (run with -s);
GLORFINDEL_INVARIANT_NO_SHRINK=1 reports a failure as found, unshrunk (the mutation
harness, scripts/mutation_check.py, only needs to know there is one).
"""
from __future__ import annotations

import collections
import hashlib
import os
import shutil
import tempfile
from pathlib import Path
from types import SimpleNamespace

from hypothesis import HealthCheck, Phase, event, settings, strategies as st
from hypothesis.database import DirectoryBasedExampleDatabase
from hypothesis.errors import InvalidArgument
from hypothesis.stateful import (
    RuleBasedStateMachine, initialize, invariant, rule, run_state_machine_as_test,
)

from glorfindel import actions, config, escalations, reassert
from glorfindel.actions import AzureConnector, _load_isolation_state

from .fake_azure import (
    ATTACKER, AZURE_DNS, AZURE_IMDS, LATERAL, Crash, FakeAzure, _rule_record, key, open_flows,
)

# ── the customer's network ───────────────────────────────────────────────────────

_TEMPLATES = {
    "allow-ssh": dict(access="Allow", direction="Inbound", source_address_prefix="*",
                      destination_address_prefix="*", destination_port_range="22"),
    "allow-https": dict(access="Allow", direction="Inbound", source_address_prefix="Internet",
                        destination_address_prefix="*", destination_port_range="443"),
    "allow-lateral-out": dict(access="Allow", direction="Outbound", source_address_prefix="*",
                              destination_address_prefix="VirtualNetwork", destination_port_range="*"),
    "deny-lateral-in": dict(access="Deny", direction="Inbound", source_address_prefix="VirtualNetwork",
                            destination_address_prefix="*", destination_port_range="*"),
}
# 100 is where Glorfindel's denies go first: a customer allow there precedes them.
_PRIORITIES = {"allow-ssh": [100, 101, 150, 1000], "allow-https": [100, 110, 1100],
               "allow-lateral-out": [100, 120, 1200], "deny-lateral-in": [130, 1300]}

# Two VMs named `web` in two resource groups, NICs of the same name, one subnet in a
# hub resource group; a multi-NIC VM whose name has capitals and a double dash; a VM
# in another region, on its own subnet.
_HUB, _EDGE = "westeurope", "northeurope"
_VMS = [
    ("rg-app1", "web", _HUB, [("rg-app1", "web-nic", ["10.0.0.4"])]),
    ("rg-app2", "web", _HUB, [("rg-app2", "web-nic", ["10.0.0.5"])]),
    ("rg-app1", "Db--01", _HUB, [("rg-app1", "db-nic-0", ["10.0.0.6"]),
                                 ("rg-app1", "db-nic-1", ["10.0.0.7", "10.0.0.8"])]),
    ("rg-edge", "api", _EDGE, [("rg-edge", "api-nic", ["10.1.0.4"])]),
]


def _rule(name, priority, tpl):
    return SimpleNamespace(name=name, priority=priority, protocol="*", source_port_range="*", **tpl)


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
        rules.append(_rule(name, prio, tpl))
    return rules


@st.composite
def _networks(draw):
    return {
        "subnet_nsg": draw(st.one_of(st.none(), _customer_rules())),
        "edge_nsg": draw(st.one_of(st.none(), _customer_rules())),
        "tier_rules": draw(_customer_rules()),
        "nics": {nic: {"own": draw(st.sampled_from([None, "dedicated"] + (["tier"] if loc == _HUB else []))),
                       "rules": draw(_customer_rules()),
                       "policy": draw(st.booleans())}
                 for _, _, loc, nics in _VMS for _, nic, _ in nics},
        "windows": draw(st.sampled_from([None, "Db--01", "api"])),
        "config": draw(_configs()),
    }


def _configs():
    return st.fixed_dictionaries({
        "quarantine": st.booleans(),
        "rg": st.sampled_from(["", "rg-sec"]),
        "forensic": st.sampled_from([[], [LATERAL]]),
        "readable": st.just(True),
    })


# A fault on the n-th call of an operation, before it reaches Azure (a throttled read or
# write, a crash) — or on the n-th WRITE, after Azure applied it and before the answer
# came back (the answer is an error, or the process is gone) — or one API throttled for
# the whole operation (every call to it answers 429).
_THROTTLED_APIS = ["nic.get", "subnet.get", "nsg.get", "rule.list", "vm.get"]
_FAULTS = st.one_of(
    st.none(),
    st.tuples(st.integers(1, 15), st.sampled_from(["before-429", "after-429", "before-crash", "after-crash"])),
    st.tuples(st.sampled_from(_THROTTLED_APIS), st.just("always-429")))


class _Chaos:
    def __init__(self):
        self.plan = None
        self.calls = self.writes = 0
        self.fired = False

    def arm(self, fault):
        self.plan, self.calls, self.writes, self.fired = fault, 0, 0, False

    def __call__(self, op: str, phase: str, write: bool):
        if phase == "before":
            self.calls += 1
        elif write:
            self.writes += 1
        if not self.plan:
            return
        when, what = self.plan[1].split("-")
        if when == "always":
            if phase == "before" and op == self.plan[0]:
                self.fired = True
                from .fake_azure import throttled
                raise throttled(op)
            return
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
    try:
        event(what)
    except InvalidArgument:            # replayed outside Hypothesis (the regressions)
        pass
    _SEEN[what] += 1


def _nic_hash(nic_id: str) -> str:
    """The NIC part of Glorfindel's rule names — the convention, restated here so a
    leftover is found by its name even when it no longer applies to the NIC's
    addresses (its IP changed, its VM is gone)."""
    return hashlib.sha1(nic_id.rstrip("/").lower().encode()).hexdigest()[:6]


class IsolationMachine(RuleBasedStateMachine):
    def __init__(self):
        super().__init__()
        self.home = Path(tempfile.mkdtemp(prefix="glorfindel-l24-"))
        actions._ISOLATION_STATE_DIR = self.home / "isolation"
        actions._BLOCK_STATE_DIR = self.home / "blocks"
        escalations._STORE = self.home / "escalations.jsonl"
        config._DEFAULT_PATHS = [self.home / "glorfindel-config.yaml"]
        self.chaos = _CURRENT.chaos = _Chaos()
        self.fake = FakeAzure(self.chaos)
        self.deleted: dict[str, list[str]] = {}         # VM id → its NIC ids, once deleted

    @initialize(net=_networks())
    def build(self, net):
        f = self.fake
        tier = f.add_nsg("rg-net", "nsg-tier", net["tier_rules"])
        subnets = {
            _HUB: f.add_subnet("rg-net", "vnet-hub", "app", None if net["subnet_nsg"] is None
                               else f.add_nsg("rg-net", "nsg-subnet", net["subnet_nsg"])),
            _EDGE: f.add_subnet("rg-edge", "vnet-edge", "edge", None if net["edge_nsg"] is None
                                else f.add_nsg("rg-edge", "nsg-edge", net["edge_nsg"], location=_EDGE)),
        }
        self.vms = []
        for rg, name, loc, nics in _VMS:
            specs = []
            for nic_rg, nic, ips in nics:
                n = net["nics"][nic]
                own = {None: None, "tier": tier}.get(n["own"]) if n["own"] != "dedicated" \
                    else f.add_nsg(nic_rg, f"nsg-{nic}", n["rules"], location=loc)
                specs.append({"rg": nic_rg, "name": nic, "ips": ips, "subnet": subnets[loc],
                              "nsg": own, "policy": n["policy"], "location": loc})
            self.vms.append(f.add_vm(rg, name, specs, os_type="Windows" if name == net["windows"] else "Linux"))
        self.design = f.snapshot()
        self.config = dict(net["config"])
        self._write_config()
        c = AzureConnector(dry_run=False)
        c._network, c._compute = f.network, f.compute
        c.recent_changes = lambda *a, **k: []
        self.connector = c

    def teardown(self):
        try:
            if getattr(self, "connector", None) is not None:
                # I7, with the local state as it is, then without it.
                self._recover_everything(lose_state=False)
                self._recover_everything(lose_state=True)
        finally:
            shutil.rmtree(self.home, ignore_errors=True)

    def _write_config(self):
        path = config._DEFAULT_PATHS[0]
        c = self.config
        if not c["readable"]:
            path.write_text("isolation: [quarantine_nsg: true\n")      # broken YAML
            return
        lines = ["isolation:", f"  quarantine_nsg: {'true' if c['quarantine'] else 'false'}"]
        if c["rg"]:
            lines.append(f"  quarantine_rg: {c['rg']}")
        if c["forensic"]:
            lines.append(f"  forensic_sources: [{', '.join(c['forensic'])}]")
        path.write_text("\n".join(lines) + "\n")

    # ── observing ───────────────────────────────────────────────────────────────

    @property
    def live(self) -> list[str]:
        return [vm for vm in self.vms if vm not in self.deleted]

    def _world(self) -> dict:
        f = self.fake
        return {"nsgs": f.nsgs, "nics": f.nics, "subnets": f.subnets, "vms": f.vms}

    def _open(self, vm: str, own: bool = False) -> frozenset:
        """The VM's open flows, less the investigation access the operator configured
        (isolation.forensic_sources: TCP 22 and 3389 from those sources) on a NIC in
        quarantine — open there on purpose, whatever the NIC's own NSG says.

        own=True: as if the rules named for OTHER NICs weren't there. A VM given the old
        IP of another, whose isolation was left behind (state lost, not yet released),
        is cut off by that rule — the other VM's leftover, not this VM's claim."""
        world = self._world()
        if own:
            others = self._other_marks(vm)
            world = {**world, "nsgs": {k: {**g, "rules": {
                n: r for n, r in g["rules"].items()
                if not (self._owned_by(n, others) and self._scoped(r))}}
                for k, g in world["nsgs"].items()}}
        quarantined = {n["id"].rsplit("/", 1)[-1] for n in self._nics(vm)
                       if n["nsg"] and actions._is_quarantine_nsg(n["nsg"])}
        return frozenset(f for f in open_flows(world, vm)
                         if not (f[0] in quarantined and f[2] == "in" and f[3] == LATERAL
                                 and f[4] in (22, 3389)))

    def _other_marks(self, vm: str) -> set:
        mine = {_nic_hash(n) for n in self.fake.vms[key(vm)]["nics"]}
        return ({_nic_hash(n["id"]) for n in self.fake.nics.values()}
                | {_nic_hash(n) for nics in self.deleted.values() for n in nics}) - mine

    @staticmethod
    def _scoped(r: dict) -> bool:
        """A deny addressed to explicit IPs on the side of the NIC it protects."""
        side = "destination" if r["direction"].lower() == "inbound" else "source"
        values = [v for v in [r.get(f"{side}_address_prefix")] + list(r.get(f"{side}_address_prefixes") or []) if v]
        return bool(values) and "*" not in values

    @staticmethod
    def _owned_by(rule_name: str, marks: set) -> bool:
        return rule_name.startswith("glorfindel-") and any(h in rule_name for h in marks)

    def _flows(self) -> dict:
        return {vm: self._open(vm) for vm in self.live}

    def _designed(self, vm: str) -> frozenset:
        return open_flows(self.design, vm)

    def _state(self, vm: str):
        return _load_isolation_state(vm)

    def _nics(self, vm: str) -> list[dict]:
        return [self.fake.nics[key(n)] for n in self.fake.vms[key(vm)]["nics"]]

    def _nics_as_designed(self, vm: str) -> bool:
        return all(key(n["nsg"]) == key(n["design_nsg"]) for n in self._nics(vm))

    def _back_to_design(self, vm: str, own: bool = False) -> bool:
        """Every flow as designed — the attacker's excepted while a block of it stands
        (a block legitimately closes them, and outlives a release)."""
        live, design = self._open(vm, own), self._designed(vm)
        if actions._load_block_entries(vm) or self._block_rules_for(vm):
            return ({f for f in live if f[3] != ATTACKER} == {f for f in design if f[3] != ATTACKER}
                    and live <= design)
        return live == design

    def _named_leftovers(self, nic_ids: list[str], prefix: str = "glorfindel-iso") -> list[str]:
        """Rules of `prefix` named for one of these NICs, on any NSG — applying to their
        addresses or not (a changed IP, a deleted VM)."""
        marks = {_nic_hash(n) for n in nic_ids}
        return [f'{n["id"].rsplit("/", 1)[-1]}/{r["name"]}' for n in self.fake.nsgs.values()
                for r in n["rules"].values()
                if r["name"].lower().startswith(prefix) and any(m in r["name"].lower() for m in marks)]

    def _released(self, vm: str, own: bool = False) -> bool:
        return (self._back_to_design(vm, own) and self._nics_as_designed(vm) and self._state(vm) is None
                and not self._named_leftovers(self.fake.vms[key(vm)]["nics"]))

    def _footprint(self, vm: str) -> set:
        """What of Glorfindel's isolation applies to the VM: a NIC in quarantine, a
        glorfindel-iso deny that covers one of a NIC's addresses."""
        fp = set()
        others = self._other_marks(vm)
        for nic in self._nics(vm):
            if nic["nsg"] and actions._is_quarantine_nsg(nic["nsg"]):
                fp.add(("quarantine", key(nic["id"])))
            sub = self.fake.subnets[key(nic["subnet"])]["nsg"]
            for g in {key(nic["nsg"]), key(nic["design_nsg"]), key(sub)} - {""}:
                for r in self.fake.nsgs.get(g, {}).get("rules", {}).values():
                    if (not r["name"].lower().startswith("glorfindel-iso") or r["access"].lower() != "deny"
                            or self._owned_by(r["name"].lower(), others)):
                        continue
                    side = "destination" if r["direction"].lower() == "inbound" else "source"
                    values = [r.get(f"{side}_address_prefix")] + list(r.get(f"{side}_address_prefixes") or [])
                    if any(v in ("*", *nic["ips"]) for v in values if v):
                        fp.add(("rule", g, r["name"].lower()))
        return fp

    def _run(self, fault, fn, label=""):
        self.chaos.arm(fault)
        try:
            out, err = fn(), None
        except Crash as exc:
            out, err = None, exc
        except Exception as exc:
            out, err = None, exc
        finally:
            fired = fault is not None and (self.chaos.plan is None or self.chaos.fired)
            self.chaos.plan = None
        if label:
            what = type(err).__name__ if err else (out or {}).get("status", (out or {}).get("verified", "ok"))
            _note(f"{label}: {what}" + (f" after {fault[1]}" if fired else ""))
        return out, err

    def _undeclared(self, vm: str, claim: dict) -> frozenset:
        """Open flows the claim doesn't admit: an isolation by rules can't deny Azure's DNS
        and IMDS to one VM (measured) — it must say so (`platform_open`), never hide it."""
        declared = set(claim.get("platform_open") or [])
        return frozenset(f for f in self._open(vm)
                         if not (f[0] in declared and f[3] in (AZURE_DNS, AZURE_IMDS)))

    def _draw(self, data, deleted_too: bool = False):
        vm = data.draw(st.sampled_from(self.vms if deleted_too else self.live), label="vm")
        # The canonical id, or the lowercase id Log Analytics reports (_ResourceId).
        rid = data.draw(st.sampled_from([vm, vm.lower()]), label="rid")
        return vm, rid, data.draw(_FAULTS, label="fault")

    def _in_quarantine(self, vm: str) -> bool:
        """A NIC of the VM carries Glorfindel's quarantine NSG: it is meant to be cut
        off. That NSG is shared by every isolation of the region — putting its rules
        back for one VM re-seals the others, as it should."""
        return any(n["nsg"] and actions._is_quarantine_nsg(n["nsg"]) for n in self._nics(vm))

    def _only_sealed(self, vm: str, before: frozenset, after: frozenset, what: str,
                     reopenable: frozenset = frozenset()):
        """Nothing opened — but what only another NIC's leftover rule closed (an IP that
        moved from one VM to another): re-isolating that NIC rewrites its rule for its
        own new address and gives the flows back."""
        assert after - before <= reopenable, f"{what} opened flows of {vm}"
        assert after <= before | reopenable and (before <= after or self._in_quarantine(vm)), (
            f"{what} cut off {vm}")

    def _others_unchanged(self, vm: str, flows_before: dict, states_before: dict, perimeter: bool = False):
        flows = self._flows()
        for other in self.live:
            if other == vm:
                continue
            before, after = flows_before[other], flows[other]
            if perimeter:
                # A perimeter block closes the attacker's flows on its subnet, by design.
                before = frozenset(f for f in before if f[3] != ATTACKER)
                after = frozenset(f for f in after if f[3] != ATTACKER)
            self._only_sealed(other, before, after, f"I4: an operation on {vm}",
                              flows_before[("own", other)] - before)
            assert self._state(other) == states_before[other], (
                f"I4: an operation on {vm} changed the state of {other}")

    def _before(self):
        flows = self._flows()
        flows.update({("own", v): self._open(v, own=True) for v in self.live})
        return flows, {v: self._state(v) for v in self.live}

    def _quarantined_nics(self) -> dict:
        return {k: n["nsg"] for k, n in self.fake.nics.items()
                if n["nsg"] and actions._is_quarantine_nsg(n["nsg"])}

    def _config_honoured(self, before: dict, what: str):
        """I10, for the NICs this operation put in quarantine."""
        for k, nsg in self._quarantined_nics().items():
            if key(before.get(k)) == key(nsg):
                continue
            c = self.config
            assert c["readable"], f"I10: {what} put {k} in quarantine with an unreadable configuration"
            assert c["quarantine"], f"I10: {what} put {k} in quarantine, the configuration turns it off"
            vm = next(v for v, nics in ((v, self.fake.vms[key(v)]["nics"]) for v in self.live)
                      if k in {key(n) for n in nics})
            want = c["rg"] or vm.split("/")[4]
            got = nsg.split("/")[4]
            assert got.lower() == want.lower(), f"I10: {what} used a quarantine NSG in {got}, not {want}"

    def _isolation_recorded(self, vm: str, what: str):
        """I8: an isolation or release that returned has recorded what it left on Azure."""
        if self._footprint(vm):
            assert self._state(vm) is not None, f"I8: {what} left an isolation of {vm} on Azure without state"

    def _block_recorded(self, vm: str, what: str):
        if [r for r in self._block_rules_for(vm) if not self._perimeter_rule(r)]:
            assert actions._load_block_entries(vm), f"I8: {what} left a block on {vm} without state"

    # ── operations ──────────────────────────────────────────────────────────────

    @rule(data=st.data())
    def isolate(self, data):
        vm, rid, fault = self._draw(data)
        self._isolate(vm, rid, fault)

    def _isolate(self, vm, rid, fault):
        (flows, states), nics = self._before(), self._quarantined_nics()
        azure_before = self.fake.snapshot() if not self.config["readable"] else None
        out, err = self._run(fault, lambda: self.connector.isolate_vm(rid), "isolate")
        if azure_before is not None:
            # S1: the configuration can't be read — refused before any write.
            assert self.fake.snapshot() == azure_before, (
                f"I10: isolate_vm wrote to Azure for {vm} with an unreadable configuration")
        if out and out.get("status") == "isolated" and not out.get("bypass"):
            assert not self._undeclared(vm, out), f"I3: isolate_vm said isolated, {vm} still reachable"
            # ...and its verification agrees: a false alarm would have the reassertion
            # put back an isolation that holds.
            check, _ = self._run(None, lambda: self.connector.verify_isolation(rid))
            assert check and check.get("verified") is True, f"I3: fresh isolation of {vm} not verified: {check}"
            assert not self._undeclared(vm, check), f"I3: verify_isolation hides open flows of {vm}"
        if out and self.fake.vms[key(vm)]["os"] == "Windows":
            assert (out.get("drain") or {}).get("status") != "drained", (
                f"I3: sessions said cut on the Windows VM {vm}")
        if err is None:
            self._isolation_recorded(vm, "isolate_vm")
        self._config_honoured(nics, "isolate_vm")
        self._others_unchanged(vm, flows, states)

    @rule(data=st.data())
    def release(self, data):
        vm, rid, fault = self._draw(data, deleted_too=True)
        self._release(vm, rid, fault)

    @staticmethod
    def _recorded_rules(state) -> set:
        return {n.lower() for p in (state or {}).get("placements") or []
                for n in (p.get("rule_in"), p.get("rule_out")) if n}

    def _release(self, vm, rid, fault):
        flows, states = self._before()
        states_before_release = self._state(vm)
        out, err = self._run(fault, lambda: self.connector.release_isolation(rid), "release")
        if vm in self.deleted:
            recorded = self._recorded_rules(states_before_release)
            if out and out.get("status") == "released":
                left = [r for r in self._named_leftovers(self.deleted[vm]) if r.split("/")[-1] in recorded]
                assert not left, f"I3: release of the deleted {vm} said released, rules left: {left}"
        else:
            if out and out.get("status") == "released":
                assert self._released(vm, own=True), f"I3: release said released, {vm} is not back to its design"
            if err is None:
                self._isolation_recorded(vm, "release_isolation")
        self._others_unchanged(vm, flows, states)
        return out, err

    @rule(data=st.data())
    def interrupted_release(self, data):
        """A rare state made common: an isolation, then a release cut off midway (War
        Room timeout, container killed), then the reassertion — which must not undo it
        (I9)."""
        vm, rid, _ = self._draw(data)
        self._isolate(vm, rid, None)
        self._release(vm, rid, (data.draw(st.integers(1, 8), label="cut at"),
                                data.draw(st.sampled_from(["before-crash", "after-crash"]), label="how")))
        if data.draw(st.booleans(), label="then reassert"):
            self.reassert(data)

    @rule(data=st.data())
    def block_then_isolate(self, data):
        """The usual incident: the attacker's IP blocked, then the VM isolated — by
        quarantine, the NSG that holds the block is off the NIC until the release. Then
        someone may touch the quarantine NSG, and the VM is released."""
        vm, rid, fault = self._draw(data)
        self._block(vm, rid, fault, data.draw(st.sampled_from([22, None]), label="threat_port"))
        self._isolate(vm, rid, data.draw(_FAULTS, label="isolate fault"))
        if data.draw(st.booleans(), label="strip the quarantine NSG"):
            self._strip_quarantine_nsg(data)
            self._claims_after_a_change()
        if data.draw(st.booleans(), label="release"):
            self._release(vm, rid, None)

    @rule(data=st.data())
    def isolate_two(self, data):
        """Neighbours isolated one after the other (a tier NSG, a subnet): what one
        isolation leaves must not reach the other, now or when it comes back."""
        first, rid1, f1 = self._draw(data)
        self._isolate(first, rid1, f1)
        second, rid2, f2 = self._draw(data)
        self._isolate(second, rid2, f2)
        if data.draw(st.booleans(), label="release the first"):
            self._release(first, rid1, None)

    @rule(data=st.data())
    def interrupted_isolation(self, data):
        """Another: an isolation cut off midway, retried under a fault, then released —
        the state then knows only part of what is on Azure."""
        vm, rid, _ = self._draw(data)
        self._isolate(vm, rid, (data.draw(st.integers(1, 10), label="cut at"),
                                data.draw(st.sampled_from(["before-crash", "after-crash"]), label="how")))
        self._isolate(vm, rid, data.draw(_FAULTS, label="retry fault"))
        self._release(vm, rid, None)

    def _attacker_flows(self, vm: str, port: int | None) -> frozenset:
        """What a block must close: the attacker's way in on the threat port (any port
        when unknown) and the VM's way out to it."""
        return frozenset(f for f in self._open(vm)
                         if f[3] == ATTACKER and (f[2] == "out" or port is None or f[4] == port))

    def _block_rules_for(self, vm: str) -> list[str]:
        """Glorfindel block rules for the attacker that apply to one of this VM's NICs."""
        found = []
        for nic in self._nics(vm):
            for g in {nic["nsg"], nic["design_nsg"], self.fake.subnets[key(nic["subnet"])]["nsg"]} - {None}:
                for r in self.fake.nsgs.get(key(g), {}).get("rules", {}).values():
                    if not r["name"].startswith("glorfindel-block-"):
                        continue
                    sides = [r.get("source_address_prefix"), r.get("destination_address_prefix"),
                             *(r.get("source_address_prefixes") or []), *(r.get("destination_address_prefixes") or [])]
                    if ATTACKER in sides and any(v in ("*", *nic["ips"]) for v in sides):
                        found.append(r["name"])
        return found

    def _subnet_mates(self, vm: str) -> list[str]:
        subnets = {key(n["subnet"]) for n in self._nics(vm)}
        return [v for v in self.live if subnets & {key(n["subnet"]) for n in self._nics(v)}]

    @rule(data=st.data())
    def block(self, data):
        vm, rid, fault = self._draw(data)
        self._block(vm, rid, fault, data.draw(st.sampled_from([22, None]), label="threat_port"))

    def _block(self, vm, rid, fault, port):
        flows, states = self._before()
        out, err = self._run(fault, lambda: self.connector.block_suspicious_ip(
            ATTACKER, rid, scope="vm", threat_port=port), "block")
        if out and out.get("status") == "blocked" and not out.get("bypass"):
            assert not self._attacker_flows(vm, port), f"I3: block said blocked, {ATTACKER} reaches {vm}"
            check, _ = self._run(None, lambda: self.connector.verify_block_ip(ATTACKER, rid))
            assert check and check.get("verified") is True, f"I3: fresh block on {vm} not verified: {check}"
        if err is None:
            self._block_recorded(vm, "block_suspicious_ip")
        self._others_unchanged(vm, flows, states)

    @rule(data=st.data())
    def block_perimeter(self, data):
        """The operator's subnet-wide block, or the promotion of a VM block to it."""
        vm, rid, fault = self._draw(data)
        replace = data.draw(st.booleans(), label="replace")
        flows, states = self._before()
        out, err = self._run(fault, lambda: self.connector.block_suspicious_ip(
            ATTACKER, rid, scope="subnet", replace=replace), "block_perimeter" + (" (promote)" if replace else ""))
        if out and out.get("status") == "blocked" and not out.get("bypass"):
            for mate in self._subnet_mates(vm):
                assert not self._attacker_flows(mate, None), (
                    f"I3: perimeter block said blocked, {ATTACKER} reaches {mate}")
        self._others_unchanged(vm, flows, states, perimeter=True)

    @rule(data=st.data())
    def unblock(self, data):
        vm, rid, fault = self._draw(data)
        flows, states = self._before()
        out, _ = self._run(fault, lambda: self.connector.unblock_ip(ATTACKER, rid), "unblock")
        if out and out.get("status") in ("unblocked", "not_found"):
            left = [r for r in self._block_rules_for(vm) if not self._perimeter_rule(r)]
            assert not left, f"I3: unblock said {out['status']}, rules left for {vm}: {left}"
        self._others_unchanged(vm, flows, states, perimeter=True)

    @staticmethod
    def _perimeter_rule(name: str) -> bool:
        """A perimeter block: one rule for every VM of a subnet, its name the IP alone —
        kept by a VM's unblock unless that VM's state recorded it."""
        bare = "glorfindel-block-" + ATTACKER.replace(".", "-")
        return name.lower() in (bare, f"{bare}-out")

    @rule(data=st.data())
    def verify(self, data):
        """The verifications under faults (every_claim_is_true checks them without):
        the drawn one, then each API throttled for the whole verification in turn — a
        read that fails must give an unknown, never a yes."""
        vm, rid, fault = self._draw(data)
        iso, _ = self._run(fault, lambda: self.connector.verify_isolation(rid), "verify_isolation")
        if iso and iso.get("verified") is True:
            assert not self._undeclared(vm, iso), f"I3: verify_isolation True, {vm} reachable"
        self._check_claims(vm, rid, fault)
        for api in _THROTTLED_APIS:
            self._check_claims(vm, rid, (api, "always-429"))

    @rule(data=st.data())
    def reassert(self, data):
        _CURRENT.mode = data.draw(st.sampled_from(["human_only", "non_disruptive"]), label="mode")
        fault = data.draw(_FAULTS, label="fault")
        flows, _ = self._before()
        had_state = {vm: self._state(vm) is not None or bool(actions._load_block_entries(vm))
                     for vm in self.live}
        releasing = [vm for vm in self.live if (self._state(vm) or {}).get("releasing_at")]
        footprints = {vm: self._footprint(vm) for vm in releasing}
        nics_before = {k: n["nsg"] for k, n in self.fake.nics.items()}
        # A perimeter block put back closes the attacker's flows of every VM on its
        # subnet, those without state included — by design.
        perimeter = any(e.get("scoped") is False for vm in self.vms for e in actions._load_block_entries(vm))
        report, _ = self._run(fault, lambda: reassert.reassert_active(self.connector, None))
        for r in report or []:
            _note(f"reassert ({_CURRENT.mode}): {r['outcome']}")
        after = self._flows()
        for vm in self.live:
            reopenable = flows[("own", vm)] - flows[vm]
            assert after[vm] - flows[vm] <= reopenable, f"I5: the reassertion opened flows of {vm}"
            if _CURRENT.mode == "human_only":
                assert after[vm] == flows[vm], f"I5: the reassertion acted on {vm} in human_only"
            elif not had_state[vm]:
                strip = (lambda fl: frozenset(f for f in fl if f[3] != ATTACKER)) if perimeter else (lambda fl: fl)
                self._only_sealed(vm, strip(flows[vm]), strip(after[vm]), "I5: the reassertion (no state)",
                                  reopenable)
        for vm in releasing:
            assert self._footprint(vm) <= footprints[vm], f"I9: the reassertion isolated {vm} again mid-release"
        if _CURRENT.mode == "human_only":
            assert {k: n["nsg"] for k, n in self.fake.nics.items()} == nics_before
        self._config_honoured({k: v for k, v in nics_before.items() if v}, "the reassertion")

    @rule(data=st.data())
    def reset_from_azure(self, data):
        """`glorfindel reset --from-azure`: Azure as the source of truth."""
        vm, rid, fault = self._draw(data)
        flows, states = self._before()
        out, _ = self._run(fault, lambda: self.connector.sweep_vm_rules(rid), "reset --from-azure")
        if out and out.get("status") == "swept":
            assert self._back_to_design(vm, own=True) and self._nics_as_designed(vm), (
                f"I3: reset --from-azure said swept, {vm} is not back to its design")
            assert self._state(vm) is None
        self._others_unchanged(vm, flows, states, perimeter=True)

    # ── the customer's world moving ─────────────────────────────────────────────

    def _customer_nsgs(self) -> list[str]:
        return sorted(k for k in self.design["nsgs"] if k in self.fake.nsgs)

    def _both(self, nsg: str):
        return self.fake.nsgs[nsg]["rules"], self.design["nsgs"][nsg]["rules"]

    @rule(data=st.data())
    def customer_adds_rule(self, data):
        self._customer_adds_rule(data)
        self._claims_after_a_change()

    def _customer_adds_rule(self, data):
        """An allow (or a deny) added by the customer — before Glorfindel's denies, often."""
        nsgs = self._customer_nsgs()
        if not nsgs:
            return
        nsg = data.draw(st.sampled_from(nsgs), label="nsg")
        tpl_name = data.draw(st.sampled_from(sorted(_TEMPLATES)), label="template")
        prio = data.draw(st.sampled_from([100, 101, 102, 140, 2000]), label="priority")
        live, design = self._both(nsg)
        name = f"{tpl_name}-{prio}"
        rec = _rule_record(_rule(name, prio, _TEMPLATES[tpl_name]))
        try:
            FakeAzure._put_rule(self.fake.nsgs[nsg], rec)        # refused on a priority taken
        except Exception:
            _note("customer: rule refused (priority taken)")
            return
        design[name.lower()] = dict(rec)

    @rule(data=st.data())
    def customer_edits_rule(self, data):
        self._customer_edits_rule(data)
        self._claims_after_a_change()

    def _customer_edits_rule(self, data):
        """A customer rule narrowed or widened: another source, another port."""
        nsgs = [n for n in self._customer_nsgs() if self._both(n)[1]]
        if not nsgs:
            return
        nsg = data.draw(st.sampled_from(nsgs), label="nsg")
        live, design = self._both(nsg)
        name = data.draw(st.sampled_from(sorted(design)), label="rule")
        change = data.draw(st.sampled_from([("source_address_prefix", "10.9.0.0/16"),
                                            ("source_address_prefix", "*"),
                                            ("destination_port_range", "443"),
                                            ("destination_port_range", "*")]), label="change")
        for rules in (live, design):
            if name in rules:
                rules[name][change[0]] = change[1]

    @rule(data=st.data())
    def customer_removes_rule(self, data):
        self._customer_removes_rule(data)
        self._claims_after_a_change()

    def _customer_removes_rule(self, data):
        nsgs = [n for n in self._customer_nsgs() if self._both(n)[1]]
        if not nsgs:
            return
        nsg = data.draw(st.sampled_from(nsgs), label="nsg")
        live, design = self._both(nsg)
        name = data.draw(st.sampled_from(sorted(design)), label="rule")
        live.pop(name, None)
        design.pop(name, None)

    @rule(data=st.data())
    def customer_deletes_nsg(self, data):
        """An NSG that governs nothing any more — its NIC is in quarantine — looks
        unused, and is cleaned up. Azure refuses while it is attached."""
        nsgs = self._customer_nsgs()
        if nsgs and self.fake.delete_nsg(self.fake.nsgs[data.draw(st.sampled_from(nsgs), label="nsg")]["id"]):
            _note("customer: NSG deleted")

    @rule(data=st.data())
    def customer_changes_ip(self, data):
        self._customer_changes_ip(data)
        self._claims_after_a_change()

    def _customer_changes_ip(self, data):
        nic = data.draw(st.sampled_from(sorted(k for k in self.fake.nics if k in self.design["nics"])), label="nic")
        ips = self.fake.nics[nic]["ips"]
        used = {ip for n in self.fake.nics.values() for ip in n["ips"]}
        base = ips[0].rsplit(".", 1)[0]
        new = next(f"{base}.{i}" for i in range(20, 250) if f"{base}.{i}" not in used)
        at = data.draw(st.integers(0, len(ips) - 1), label="which")
        for n in (self.fake.nics[nic], self.design["nics"][nic]):
            n["ips"][at] = new

    @rule(data=st.data())
    def customer_sets_policy(self, data):
        nic = data.draw(st.sampled_from(sorted(self.fake.nics)), label="nic")
        self.fake.nics[nic]["policy"] = data.draw(st.booleans(), label="policy")

    @rule(data=st.data())
    def terraform_apply(self, data):
        self._terraform_apply(data)
        self._claims_after_a_change()

    def _terraform_apply(self, data):
        """An NSG with inline rules: `apply` removes every rule absent from the code."""
        nsgs = self._customer_nsgs()
        if not nsgs:
            return
        rules = self.fake.nsgs[data.draw(st.sampled_from(nsgs), label="nsg")]["rules"]
        for name in [n for n in rules if n.startswith("glorfindel-")]:
            del rules[name]

    @rule(data=st.data())
    def redeploy_nic(self, data):
        self._redeploy_nic(data)
        self._claims_after_a_change()

    def _redeploy_nic(self, data):
        """A Bicep/ARM redeploy of the NIC puts the designed NSG back."""
        nic = data.draw(st.sampled_from(sorted(self.fake.nics)), label="nic")
        n = self.fake.nics[nic]
        if n["design_nsg"] is None or key(n["design_nsg"]) in self.fake.nsgs:
            n["nsg"] = n["design_nsg"]

    @rule(data=st.data())
    def delete_vm(self, data):
        """The VM is deleted with its NICs (the subnet and the NSGs stay)."""
        if len(self.live) <= 2:
            return
        vm = data.draw(st.sampled_from(self.live), label="vm")
        nics = self.fake.vms.pop(key(vm))["nics"]
        for n in nics:
            self.fake.nics.pop(key(n))
            self.design["nics"].pop(key(n))
        self.design["vms"].pop(key(vm))
        self.deleted[vm] = nics

    # ── someone else touching what is Glorfindel's ──────────────────────────────

    @rule(data=st.data())
    def strip_quarantine_nsg(self, data):
        self._strip_quarantine_nsg(data)
        self._claims_after_a_change()

    def _strip_quarantine_nsg(self, data):
        """Someone deletes the deny rules of Glorfindel's own quarantine NSG."""
        ours = sorted(k for k, n in self.fake.nsgs.items() if n["tags"].get("managed-by") == "glorfindel")
        if ours:
            rules = self.fake.nsgs[data.draw(st.sampled_from(ours), label="quarantine")]["rules"]
            for name in ("glorfindel-quarantine-deny-in", "glorfindel-quarantine-deny-out"):
                rules.pop(name, None)

    @rule(data=st.data())
    def tags_lost(self, data):
        self._tags_lost(data)
        self._claims_after_a_change()

    def _tags_lost(self, data):
        """Someone replaces the tags of the quarantine NSG (`az tag update --operation
        replace`, a policy): the original NSG of each NIC is gone with them."""
        ours = sorted(k for k, n in self.fake.nsgs.items() if n["tags"].get("managed-by") == "glorfindel")
        if ours:
            n = self.fake.nsgs[data.draw(st.sampled_from(ours), label="quarantine")]
            n["tags"] = {k: v for k, v in n["tags"].items() if not k.startswith("glorfindel-orig-")}

    @rule(data=st.data())
    def tamper_with_our_rule(self, data):
        self._tamper_with_our_rule(data)
        self._claims_after_a_change()

    def _tamper_with_our_rule(self, data):
        """One of Glorfindel's denies narrowed by hand: to one port, to part of its
        addresses. Only ever narrowed — it then denies less, never something else."""
        ours = sorted((k, n) for k, g in self.fake.nsgs.items() for n, r in g["rules"].items()
                      if n.startswith("glorfindel-") and r["access"].lower() == "deny")
        if not ours:
            return
        nsg, name = data.draw(st.sampled_from(ours), label="rule")
        r = self.fake.nsgs[nsg]["rules"][name]
        how = data.draw(st.sampled_from(["port", "source", "destination"]), label="how")
        if how == "port":
            if r.get("destination_port_range") in ("*", None) and not r.get("destination_port_ranges"):
                r["destination_port_range"] = "22"
            return
        values = [v for v in [r.get(f"{how}_address_prefix")] + list(r.get(f"{how}_address_prefixes") or []) if v]
        if values == ["*"]:
            r[f"{how}_address_prefix"], r[f"{how}_address_prefixes"] = "10.9.0.0/16", None
        elif len(values) > 1:
            r[f"{how}_address_prefix"], r[f"{how}_address_prefixes"] = values[0], None

    @rule(data=st.data())
    def access_changes(self, data):
        """The role is removed (or a deny assignment, a lock): every write refused — or
        given back."""
        self.fake.write_denied = data.draw(st.booleans(), label="denied")

    @rule(data=st.data())
    def config_changes(self, data):
        self.config = dict(data.draw(_configs(), label="config"))
        self.config["readable"] = data.draw(st.booleans(), label="readable")
        self._write_config()

    @rule(data=st.data())
    def lose_state(self, data):
        """The state directory is lost (new container without its volume, disk wiped)."""
        vm = data.draw(st.sampled_from(self.vms), label="vm")
        for f in (actions._ISOLATION_STATE_DIR.glob("*.json")
                  if actions._ISOLATION_STATE_DIR.exists() else []):
            if actions._file_rid(f) == key(vm):
                f.unlink()

    @rule(data=st.data())
    def lose_everything(self, data):
        """A rare state made common: an isolation whose state AND tags are lost — its
        NICs' original NSGs can be known from nowhere (Q7)."""
        vm, rid, _ = self._draw(data)
        self._isolate(vm, rid, None)
        self.lose_state(data)
        self._tags_lost(data)
        then = data.draw(st.sampled_from(["stop", "reisolate", "reisolate+redeploy"]), label="then")
        if then != "stop":
            self._isolate(vm, rid, None)
        if then == "reisolate+redeploy":
            for n in self.fake.vms[key(vm)]["nics"]:
                nic = self.fake.nics[key(n)]
                if nic["design_nsg"] is None or key(nic["design_nsg"]) in self.fake.nsgs:
                    nic["nsg"] = nic["design_nsg"]
            out, _ = self._release(vm, rid, None)
            if (out or {}).get("status") != "released":
                self._recover_everything(lose_state=False)     # I7, from this very state

    @rule()
    def recover(self):
        self._recover_everything(lose_state=False)

    def _release_until_done(self, vm: str) -> dict:
        out = {}
        for _ in range(3):
            out = self.connector.release_isolation(vm)
            if out["status"] == "released":
                if vm not in self.deleted:
                    assert self._released(vm, own=True), f"I3: release said released, {vm} is not back to its design"
                break
        return out

    def _operator_supplies_originals(self, vm: str, out: dict):
        """I7 with Q7: a NIC whose original NSG is unknown or gone stays in quarantine,
        and the release says so. The operator then does what the message says: puts the
        customer's NSG back if it was deleted, sets the tag."""
        assert out.get("failed"), f"I7: release of {vm} not done and nothing said: {out}"
        for nic in self._nics(vm):
            if not (nic["nsg"] and actions._is_quarantine_nsg(nic["nsg"])):
                continue
            want = nic["design_nsg"]
            if want and key(want) not in self.fake.nsgs:
                d = self.design["nsgs"][key(want)]
                self.fake.nsgs[key(want)] = {**d, "rules": {k: dict(r) for k, r in d["rules"].items()},
                                             "tags": dict(d["tags"])}
            q = self.fake.nsgs[key(nic["nsg"])]
            q["tags"][self.connector._orig_tag(nic["id"])] = want or self.connector._NO_ORIGINAL

    def _recover_everything(self, lose_state: bool):
        """I7: whatever was reached, release brings every VM back to its design."""
        self.chaos.plan = None
        self.fake.write_denied = False
        self.config["readable"] = True
        self._write_config()
        deleted_records = {vm: self._recorded_rules(self._state(vm)) for vm in self.deleted}
        for vm in self.vms:
            if lose_state and vm not in self.deleted and actions._ISOLATION_STATE_DIR.exists():
                for f in actions._ISOLATION_STATE_DIR.glob("*.json"):
                    if actions._file_rid(f) == key(vm):
                        f.unlink()
            out = self._release_until_done(vm)
            if out["status"] != "released" and vm not in self.deleted:
                self._operator_supplies_originals(vm, out)
                out = self._release_until_done(vm)
            assert out["status"] == "released", f"I7: {vm} could not be released: {out}"
            for _ in range(3):
                if self.connector.unblock_ip(ATTACKER, vm)["status"] in ("unblocked", "not_found"):
                    break
            if vm not in self.deleted:
                left = self._named_leftovers(self.fake.vms[key(vm)]["nics"], "glorfindel-block-")
                assert not left, f"I7: block rules of {vm} left after unblock: {left}"
        for vm in self.live:
            assert self._released(vm), f"I7: {vm} could not be brought back to its design"
        for vm, recorded in deleted_records.items():
            left = [r for r in self._named_leftovers(self.deleted[vm]) if r.split("/")[-1] in recorded]
            assert not left, f"I7: rules of the deleted {vm} left: {left}"

    # ── always ──────────────────────────────────────────────────────────────────

    @invariant()
    def never_more_open_than_designed(self):
        if not getattr(self, "design", None):
            return
        flows = self._flows()
        for vm in self.live:
            extra = flows[vm] - self._designed(vm)
            assert not extra, f"I1: {vm} more reachable than designed: {sorted(extra)}"

    @invariant()
    def customer_configuration_untouched(self):
        if not getattr(self, "design", None):
            return
        for k, nsg in self.design["nsgs"].items():
            if k not in self.fake.nsgs:
                continue                        # deleted by the customer
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
    def scoped_on_a_shared_nsg(self):
        """I4, directly: on an NSG the design shares (several NICs, a subnet), every deny
        of Glorfindel's is addressed to its NIC's IPs — but a perimeter block, the
        operator's subnet-wide decision. An any/any there cut off every VM behind it,
        now or when a VM in quarantine comes back to it."""
        if not getattr(self, "design", None):
            return
        users: collections.Counter = collections.Counter()
        for n in self.design["nics"].values():
            users[key(n["nsg"])] += 1
        for s in self.design["subnets"].values():
            users[key(s["nsg"])] += 2
        for k, g in self.fake.nsgs.items():
            if users[k] < 2:
                continue
            for name, r in g["rules"].items():
                if (name.startswith("glorfindel-") and r["access"].lower() == "deny"
                        and not self._perimeter_rule(name)):
                    assert self._scoped(r), f"I4: {name} on the shared {g['id']} is not scoped to its NIC"

    @invariant()
    def every_claim_is_true(self):
        """I3 at every step, for one VM in turn: what the verifications say is so."""
        if not getattr(self, "design", None) or not self.live:
            return
        self.turn = getattr(self, "turn", -1) + 1
        vm = self.live[self.turn % len(self.live)]
        self._check_claims(vm, vm)

    def _check_claims(self, vm: str, rid: str, fault=None):
        iso, _ = self._run(fault, lambda: self.connector.verify_isolation(rid))
        if iso and iso.get("verified") is True:
            assert not self._undeclared(vm, iso), f"I3: verify_isolation True, {vm} reachable"
        rel, _ = self._run(fault, lambda: self.connector.verify_release(rid))
        if rel and rel.get("verified") is True:
            assert self._back_to_design(vm, own=True) and self._nics_as_designed(vm), (
                f"I3: verify_release True, {vm} not back to its design")
        entry = next((e for e in actions._load_block_entries(vm) if e.get("ip") == ATTACKER), None)
        if entry and entry.get("scoped", True) is not False:          # not a perimeter block
            blk, _ = self._run(fault, lambda: self.connector.verify_block_ip(ATTACKER, rid))
            if blk and blk.get("verified") is True:
                assert not self._attacker_flows(vm, entry.get("threat_port")), (
                    f"I3: verify_block_ip True, {ATTACKER} reaches {vm}")

    def _claims_after_a_change(self):
        """The world just moved: every claim of every VM is checked again — a change
        that makes a verification false must not wait for that VM's turn."""
        for vm in self.live:
            self._check_claims(vm, vm)

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


def invariant_env(monkeypatch) -> None:
    """What the machine needs around it: faults on the state writes, the reassertion's
    mode from the sequence, the configuration file of the machine's own home."""
    real_write = actions._atomic_write_text

    def chaotic_write(path, text):
        _CURRENT.chaos("state.write", "before", True)
        real_write(path, text)
        _CURRENT.chaos("state.write", "after", True)

    monkeypatch.setattr(actions, "_atomic_write_text", chaotic_write)
    monkeypatch.setattr(reassert, "_mode", lambda autonomy, vm, ref="": _CURRENT.mode)
    monkeypatch.setattr(config, "_DEFAULT_PATHS", list(config._DEFAULT_PATHS))
    monkeypatch.delenv("GLORFINDEL_QUARANTINE_NSG", raising=False)


def test_isolation_invariants(monkeypatch):
    invariant_env(monkeypatch)
    db = os.environ.get("GLORFINDEL_INVARIANT_DB")
    run_state_machine_as_test(IsolationMachine, settings=settings(
        max_examples=int(os.environ.get("GLORFINDEL_INVARIANT_EXAMPLES", "60")),
        stateful_step_count=int(os.environ.get("GLORFINDEL_INVARIANT_STEPS", "30")),
        deadline=None, database=DirectoryBasedExampleDatabase(db) if db else None,
        phases=[Phase.explicit, Phase.reuse, Phase.generate] if os.environ.get("GLORFINDEL_INVARIANT_NO_SHRINK")
        else list(Phase),
        suppress_health_check=[HealthCheck.too_slow, HealthCheck.filter_too_much]))
    if os.environ.get("GLORFINDEL_INVARIANT_STATS"):
        for what, n in sorted(_SEEN.items()):
            print(f"{n:7d}  {what}")
