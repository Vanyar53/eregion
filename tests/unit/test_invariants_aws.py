"""The invariants on AWS (MC1): the machine of test_invariants.py, on the simulated AWS world.

Random customer networks (fake_aws.FakeAws: VPCs, subnets, security groups, network ACLs,
multi-ENI instances) and random sequences of operations by the AWS adapter
(glorfindel/providers/aws/), with faults anywhere — a throttled call, a crash before or
after a write, an API throttled for the whole operation, a full disk on the local state —
and a world that moves: the customer adds and removes rules and ACL entries, deletes a
group no ENI carries, changes an address, sets a policy on an ENI; `terraform apply` puts
an ENI's groups back (H11) or strips an ACL of the entries absent from its code; someone
alters our quarantine group, takes an ENI out of it onto `default`, loses its tags, turns
one of our ACL entries around; another host writes an ENI right after Glorfindel did; an
instance is created or deleted; the role is removed; the configuration changes or can't
be read; the clock moves on. Two operations at once, interleaved call by call, with the
real locks (L27).

The properties of test_invariants.py, as docs/design/monde-aws.md transposes them:
  I1  no instance is ever more reachable than its owner designed it (the forensic access
      the operator configured excepted);
  I2  the customer's groups, ACL entries and associations are what the customer last
      wrote; an ENI carries its groups or Glorfindel's quarantine group; and, by author
      (the fake's journal), Glorfindel only writes its quarantine group, its tags on it, an
      ENI's groups to or from its quarantine, and ACL entries it created, unchanged;
  I3  no success on a falsehood — Amazon's DNS and IMDS always declared (H6);
  I4  an operation on one instance changes nothing for another, but the attacker's flows
      on a shared ACL (every block is subnet-wide on AWS) — and the block another
      instance holds intact still holds;
  I5  the reassertion never opens anything, never acts without state, writes nothing in
      human_only;
  I6  one instance, one state file;
  I7  from any state, release brings every instance back to its design, or keeps an ENI
      in quarantine and says so; once the operator supplies the original, it completes;
  I8  what Glorfindel leaves on AWS is in its state: an ENI in quarantine after an
      operation that returned, and — always — an ACL entry of Glorfindel's;
  I9  a release that has started is never undone by the reassertion;
  I10 the configuration is honoured: off or unreadable, an isolation writes nothing;
  I11 two operations at once end as one after the other would;
  I12 an instance of another account or region, or an id that is no instance ARN, is
      never acted on, nor vouched for;
  L1  a block whose entries all vanished is put back, or said.
U1 has no equivalent: no rule of Glorfindel's is addressed to an ENI's address.

Oracles are the test's own (the journal of the fake, what the test lost and when) —
never the markers the code under test leaves. The same environment variables as
test_invariants.py (GLORFINDEL_INVARIANT_EXAMPLES, _STEPS, _DB, _STATS, _NO_SHRINK).
"""
from __future__ import annotations

import copy
import os
import shutil
import tempfile
from pathlib import Path

from hypothesis import HealthCheck, Phase, settings, strategies as st
from hypothesis.database import DirectoryBasedExampleDatabase
from hypothesis.stateful import (
    RuleBasedStateMachine, initialize, invariant, rule, run_state_machine_as_test,
)

from glorfindel import actions, config, escalations, reassert
from glorfindel.providers.aws.connector import AwsConnector, WrongAccountError

from .fake_aws import (
    ACCOUNT, ATTACKER, AWS_DNS, AWS_IMDS, LATERAL, REGION, ClientError, Crash, FakeAws, acl_entry, arn,
    open_flows, sg_rule, throttled,
)
from .test_invariants import _CURRENT, _SEEN, _Scheduler, _note, _valid_sources, invariant_env

QSG = "glorfindel-quarantine"
CIDR = f"{ATTACKER}/32"

# ── the customer's network ───────────────────────────────────────────────────────

_SG_TEMPLATES = {
    "ssh": ("ingress", sg_rule("tcp", 22, "0.0.0.0/0")),
    "https": ("ingress", sg_rule("tcp", 443, "0.0.0.0/0")),
    "lateral-in": ("ingress", sg_rule(cidr="10.0.0.0/8")),
    "egress-all": ("egress", sg_rule(cidr="0.0.0.0/0")),
    "egress-vpc": ("egress", sg_rule(cidr="10.0.0.0/8")),
}
# (egress, action, cidr, protocol, port, to)
_ACL_TEMPLATES = {
    "in-ssh": (False, "allow", "0.0.0.0/0", "tcp", 22, None),
    "in-https": (False, "allow", "0.0.0.0/0", "tcp", 443, None),
    "in-ephemeral": (False, "allow", "0.0.0.0/0", "tcp", 1024, 65535),
    "in-lateral": (False, "allow", "10.0.0.0/8", "-1", None, None),
    "in-deny-lateral": (False, "deny", "10.9.0.0/16", "-1", None, None),
    "in-all": (False, "allow", "0.0.0.0/0", "-1", None, None),
    "out-all": (True, "allow", "0.0.0.0/0", "-1", None, None),
    "out-https": (True, "allow", "0.0.0.0/0", "tcp", 443, None),
    "out-ephemeral": (True, "allow", "0.0.0.0/0", "tcp", 1024, 65535),
    "out-vpc": (True, "allow", "10.0.0.0/8", "-1", None, None),
}
# 1: no number is free before it — a block can't be placed ahead of that allow.
_ACL_NUMBERS = [1, 50, 100, 110, 120, 200]

_SUBNETS = {"subnet-app": ("vpc-a", "10.0.0.0/24"), "subnet-data": ("vpc-a", "10.0.1.0/24"),
            "subnet-edge": ("vpc-b", "10.1.0.0/24")}
# Two instances on one subnet, one with two ENIs on two subnets (a secondary address on
# the second), one in another VPC.
_INSTANCES = [
    ("i-web1", [("eni-web1", "subnet-app", ["10.0.0.4"])]),
    ("i-web2", [("eni-web2", "subnet-app", ["10.0.0.5"])]),
    ("i-db", [("eni-db0", "subnet-app", ["10.0.0.6"]), ("eni-db1", "subnet-data", ["10.0.1.7", "10.0.1.8"])]),
    ("i-api", [("eni-api", "subnet-edge", ["10.1.0.4"])]),
]
_ENIS = [eni for _, enis in _INSTANCES for eni, _, _ in enis]


@st.composite
def _sg_rules(draw):
    rules = {"ingress": [], "egress": []}
    for name, (side, r) in _SG_TEMPLATES.items():
        if draw(st.booleans()):
            rules[side].append(dict(r))
    return rules


@st.composite
def _acl_rules(draw):
    entries, used = [], set()
    for name, (egress, action, cidr, proto, port, to) in _ACL_TEMPLATES.items():
        if not draw(st.booleans()):
            continue
        n = draw(st.sampled_from(_ACL_NUMBERS))
        if (egress, n) in used:
            continue
        used.add((egress, n))
        entries.append(acl_entry(n, egress, action, cidr, proto, port, to))
    return entries


def _configs():
    return st.fixed_dictionaries({
        "quarantine": st.booleans(),
        "rg": st.sampled_from(["", "rg-sec"]),                  # ignored on AWS
        "forensic": st.sampled_from([[], [LATERAL], ["10.9.0.0/16"], [ATTACKER]]),
        "readable": st.just(True),
    })


@st.composite
def _networks(draw):
    return {
        "web": draw(_sg_rules()),
        "own": {eni: draw(_sg_rules()) for eni in _ENIS},
        "default_extra": draw(st.booleans()),       # the customer opened SSH on `default`
        "groups": {eni: draw(st.lists(st.sampled_from(
            ["default", "own"] + (["web"] if eni != "eni-api" else [])), max_size=3, unique=True))
            for eni in _ENIS},
        "policy": {eni: draw(st.booleans()) for eni in _ENIS},
        "acl": {"subnet-app": draw(st.sampled_from(["default", "shared"])),
                "subnet-data": draw(st.sampled_from(["default", "shared", "own"])),
                "subnet-edge": draw(st.sampled_from(["default", "own"]))},
        "acl_rules": {k: draw(_acl_rules()) for k in ("shared", "own-data", "own-edge")},
        "windows": draw(st.sampled_from([None, "i-db", "i-api"])),
        "config": draw(_configs()),
    }


# A fault on the n-th call of an operation (before), or the n-th write (after), or one
# API throttled for the whole operation.
_THROTTLED_APIS = ["instance.describe", "eni.describe", "sg.describe", "acl.describe"]
_FAULTS = st.one_of(
    st.none(),
    st.tuples(st.integers(1, 15), st.sampled_from(["before-429", "after-429", "before-crash", "after-crash"])),
    st.tuples(st.sampled_from(_THROTTLED_APIS), st.just("always-429")))


class _Chaos:
    """test_invariants._Chaos, on AWS's journal: a foreign write puts back what the ENI
    carried right after Glorfindel's write (another host)."""

    def __init__(self):
        self.plan = None
        self.calls = self.writes = 0
        self.fired = False

    def arm(self, fault):
        self.plan, self.calls, self.writes, self.fired = fault, 0, 0, False

    def __call__(self, op: str, phase: str, write: bool):
        if phase == "before":
            if _CURRENT.scheduler is not None:
                _CURRENT.scheduler.point()
            self.calls += 1
        elif write:
            self.writes += 1
        if not self.plan:
            return
        when, what = self.plan[1].split("-")
        if what == "foreign":
            if phase == "after" and op == self.plan[0]:
                self.fired = True
                if when == "after":
                    self.plan = None
                e = _CURRENT.fake.journal[-1]
                _CURRENT.fake.enis[e["eni"]]["groups"] = list(e["before"])     # not through the API
            return
        if when == "always":
            if phase == "before" and op == self.plan[0]:
                self.fired = True
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
        raise throttled(op)


def _ours(sg: dict | None) -> bool:
    return bool(sg) and sg["name"] == QSG and sg["tags"].get("managed-by") == "glorfindel"


class AwsIsolationMachine(RuleBasedStateMachine):
    def __init__(self):
        super().__init__()
        self.home = Path(tempfile.mkdtemp(prefix="glorfindel-mc1-"))
        actions._ISOLATION_STATE_DIR = self.home / "isolation"
        actions._BLOCK_STATE_DIR = self.home / "blocks"
        escalations._STORE = self.home / "escalations.jsonl"
        config._DEFAULT_PATHS = [self.home / "glorfindel-config.yaml"]
        self.chaos = _CURRENT.chaos = _Chaos()
        _CURRENT.clock = 0
        self.fake = _CURRENT.fake = FakeAws(self.chaos)
        self.releasing: set[str] = set()                # the test's own journal (I9)
        self.unblocking: set[str] = set()
        self.journal_seen = 0
        self.ticks = 0
        self.recorded_at: dict[str, tuple[int, str]] = {}   # ENI → (tick, quarantine group)
        self.state_lost_at: dict[str, int] = {}
        self.tags_lost_at: dict[str, int] = {}
        self.state_had: dict[str, int] = {}
        self.before_quarantine: dict[str, list] = {}
        self.detached: set[str] = set()                 # ENIs someone took out onto `default`
        self.tampered: dict[tuple, tuple[dict, dict]] = {}   # ACL entry key → (before, after)
        self.altered: set[str] = set()                  # quarantine groups someone opened
        self.deleted: dict[str, list[str]] = {}         # instance → its ENIs, once deleted
        self.deleted_sgs: set[str] = set()
        self._serial = 0

    @initialize(net=_networks())
    def build(self, net):
        f = self.fake
        f.add_vpc("vpc-a", "10.0.0.0/16")
        f.add_vpc("vpc-b", "10.1.0.0/16")
        if net["default_extra"]:
            f.sgs["sg-default-vpc-a"]["ingress"].append(sg_rule("tcp", 22, "0.0.0.0/0"))
        f.add_acl("vpc-a", "acl-shared", net["acl_rules"]["shared"])
        f.add_acl("vpc-a", "acl-data", net["acl_rules"]["own-data"])
        f.add_acl("vpc-b", "acl-edge", net["acl_rules"]["own-edge"])
        acl_of = {("subnet-app", "default"): "acl-default-vpc-a", ("subnet-app", "shared"): "acl-shared",
                  ("subnet-data", "default"): "acl-default-vpc-a", ("subnet-data", "shared"): "acl-shared",
                  ("subnet-data", "own"): "acl-data",
                  ("subnet-edge", "default"): "acl-default-vpc-b", ("subnet-edge", "own"): "acl-edge"}
        for subnet, (vpc, cidr) in _SUBNETS.items():
            f.add_subnet(vpc, subnet, cidr, acl_of[(subnet, net["acl"][subnet])])
        f.add_sg("vpc-a", "sg-web", "web", **net["web"])
        self.vms = []
        for iid, enis in _INSTANCES:
            specs = []
            for eni, subnet, ips in enis:
                vpc = _SUBNETS[subnet][0]
                f.add_sg(vpc, f"sg-own-{eni}", f"own-{eni}", **net["own"][eni])
                groups = [{"default": f"sg-default-{vpc}", "web": "sg-web", "own": f"sg-own-{eni}"}[g]
                          for g in net["groups"][eni]]
                specs.append({"id": eni, "subnet": subnet, "ips": ips, "groups": groups, "policy": net["policy"][eni]})
            f.add_instance(iid, specs, platform="windows" if iid == net["windows"] else "linux")
            self.vms.append(iid)
        self.design = f.snapshot()
        self.config = dict(net["config"])
        self._write_config()
        self.connector = AwsConnector(ec2=f, account=ACCOUNT, region=REGION, read_only=False)

    def teardown(self):
        try:
            if getattr(self, "connector", None) is not None:
                self._recover_everything(lose_state=False)
                self._recover_everything(lose_state=True)
                self._check_authors()
        finally:
            shutil.rmtree(self.home, ignore_errors=True)

    def _write_config(self):
        path = config._DEFAULT_PATHS[0]
        c = self.config
        if c["readable"]:
            self.forensic_now = _valid_sources(c["forensic"])
            self.forensic_ever = getattr(self, "forensic_ever", []) + self.forensic_now
        if not c["readable"]:
            path.write_text("isolation: [quarantine_nsg: true\n")
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

    def _enis(self, vm: str) -> list[dict]:
        return [self.fake.enis[e] for e in self.fake.instances[vm]["enis"]]

    def _in_quarantine(self, eni: dict) -> bool:
        return len(eni["groups"]) >= 1 and any(_ours(self.fake.sgs.get(g)) for g in eni["groups"])

    def _quarantine_intact(self, sg_id: str) -> bool:
        """By the test's own reading: nothing out, in only forensic TCP 22/3389."""
        sg = self.fake.sgs.get(sg_id, {})
        return not sg.get("egress") and all(
            r["proto"] == "tcp" and r["from"] in (22, 3389) and r["from"] == r["to"] and r["cidr"]
            for r in sg.get("ingress", []))

    def _world(self, untampered: bool = False) -> dict:
        w = self.fake.world()
        if untampered and self.tampered:
            acls = {k: dict(a, entries=dict(a["entries"])) for k, a in w["acls"].items()}
            for (acl, eg, n), (_, after) in self.tampered.items():
                entries = acls.get(acl, {}).get("entries", {})
                if entries.get((eg, n)) == after:
                    del entries[(eg, n)]
            w = {**w, "acls": acls}
        return w

    def _open(self, vm: str, forensic: str | None = "ever", untampered: bool = False) -> frozenset:
        import ipaddress
        quarantined = {e["id"] for e in self._enis(vm) if self._in_quarantine(e)}
        nets = {"ever": getattr(self, "forensic_ever", []), "now": getattr(self, "forensic_now", [])}.get(forensic, [])

        def investigation(fl) -> bool:
            return (fl[0] in quarantined and fl[2] == "in" and fl[4] in (22, 3389)
                    and any(ipaddress.ip_address(fl[3]) in n for n in nets))
        return frozenset(fl for fl in open_flows(self._world(untampered), vm) if not investigation(fl))

    def _designed(self, vm: str) -> frozenset:
        return open_flows(self.design, vm)

    def _flows(self) -> dict:
        return {vm: self._open(vm) for vm in self.live}

    def _state(self, vm: str):
        return actions._load_isolation_state(arn(vm))

    def _blocks(self, vm: str) -> list[dict]:
        return actions._load_block_entries(arn(vm))

    def _footprint(self, vm: str) -> set:
        return {e["id"] for e in self._enis(vm) if self._in_quarantine(e)}

    def _untraceable(self, vm: str, eni: dict) -> bool:
        """An ENI someone took out of our quarantine onto `default`, whose original nothing
        records any more — the TEST lost the tags after Glorfindel recorded it, and the
        state too (or a fault cut the operation before the state was written). Judged
        from the test's journal (see test_invariants._untraceable)."""
        if eni["id"] not in self.detached or not self._on_default(eni):
            return False
        self._check_authors()
        rec = self.recorded_at.get(eni["id"])
        if rec is None:
            return False
        at, q = rec
        if self.tags_lost_at.get(q, -1) <= at:
            return False
        if self.state_lost_at.get(vm, -1) > at:
            return True
        if self.state_had.get(eni["id"]) == at:
            return False
        stt = self._state(vm) or {}
        return not any(p.get("nic_id") == eni["id"] and p.get("original_groups")
                       for p in stt.get("placements") or [])

    def _on_default(self, eni: dict) -> bool:
        return eni["groups"] == [f"sg-default-{eni['vpc']}"]

    def _enis_as_designed(self, vm: str) -> bool:
        return all(sorted(e["groups"]) == sorted(e["design_groups"]) or self._untraceable(vm, e)
                   for e in self._enis(vm))

    def _back_to_design(self, vm: str) -> bool:
        """Every flow as designed — the attacker's may be closed (a block, any instance's
        on a shared ACL, outlives a release)."""
        live, design = self._open(vm, untampered=True), self._designed(vm)
        bare = {e["id"] for e in self._enis(vm) if self._untraceable(vm, e)}
        live = frozenset(fl for fl in live if fl[0] not in bare)
        design = frozenset(fl for fl in design if fl[0] not in bare)
        return {fl for fl in live if fl[3] != ATTACKER} == {fl for fl in design if fl[3] != ATTACKER} \
            and live <= design

    def _released(self, vm: str) -> bool:
        return self._back_to_design(vm) and self._enis_as_designed(vm) and self._state(vm) is None

    def _why(self, vm: str) -> str:
        """What keeps `vm` from its design, for a failure's message."""
        live, design = self._open(vm, untampered=True), self._designed(vm)
        return (f"opened {sorted(live - design)}, closed {sorted(design - live)}, "
                f"ENIs {[(e['id'], e['groups'], e['design_groups']) for e in self._enis(vm)]}, "
                f"state {self._state(vm)}"
                + (f", journal {[j for j in self.fake.journal if j.get('eni') in self.fake.instances[vm]['enis']]}"
                   f", recorded {self.recorded_at}, tags lost {self.tags_lost_at}, state lost {self.state_lost_at}"
                   f", state had {self.state_had}, detached {self.detached}"
                   if os.environ.get("GLORFINDEL_INVARIANT_TRACE") else ""))

    def _attacker_flows(self, vm: str) -> frozenset:
        return frozenset(fl for fl in self._open(vm, forensic=None) if fl[3] == ATTACKER)

    def _undeclared(self, vm: str, claim: dict) -> frozenset:
        declared = set(claim.get("platform_open") or [])
        return frozenset(fl for fl in self._open(vm, forensic="now")
                         if not (fl[0] in declared and fl[3] in (AWS_DNS, AWS_IMDS)))

    def _vm_acls(self, vm: str) -> set[str]:
        return {self.fake.subnets[e["subnet"]]["acl"] for e in self._enis(vm)}

    def _our_entry(self, acl: str, egress: bool, n) -> bool:
        e = self.fake.acls.get(acl, {}).get("entries", {}).get((egress, n))
        return bool(e) and e["action"] == "deny" and e["proto"] == "-1" and e["cidr"] == CIDR and e["from"] is None

    def _block_intact(self, vm: str) -> bool:
        """The instance's recorded block of the attacker, held by no operation, with its
        entries on every ACL of its subnets as written."""
        entry = next((e for e in self._blocks(vm) if e.get("ip") == ATTACKER), None)
        if (entry is None or vm in self.unblocking
                or any(entry.get(k) for k in ("partial", "unblock_failed", "unblocking_at"))):
            return False
        ps = entry.get("placements") or []
        return all(any(p.get("acl_id") == acl and self._our_entry(acl, False, p.get("rule_in"))
                       and self._our_entry(acl, True, p.get("rule_out")) for p in ps)
                   for acl in self._vm_acls(vm))

    def _block_vanished(self, vm: str) -> bool:
        entry = next((e for e in self._blocks(vm) if e.get("ip") == ATTACKER), None)
        if (entry is None or vm in self.unblocking
                or any(entry.get(k) for k in ("partial", "unblock_failed", "unblocking_at"))):
            return False
        ps = [p for p in entry.get("placements") or [] if p.get("acl_id")]
        return bool(ps) and not any(self._our_entry(p["acl_id"], eg, p.get(k)) for p in ps
                                    for eg, k in ((False, "rule_in"), (True, "rule_out")))

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
            _note(f"aws {label}: {what}" + (f" after {fault[1]}" if fired else ""))
        return out, err

    def _draw(self, data, deleted_too: bool = False):
        vm = data.draw(st.sampled_from(self.vms if deleted_too else self.live), label="vm")
        return vm, data.draw(_FAULTS, label="fault")

    def _before(self):
        return self._flows(), {v: self._state(v) for v in self.live}, {v: self._block_intact(v) for v in self.live}

    def _others_unchanged(self, vm: str, before, what: str):
        """I4: nothing of another instance opens, nor closes but its attacker's flows (a
        shared ACL) and what a repair of the shared quarantine group seals; its state
        stays; the block it holds intact still holds."""
        flows_before, states_before, intact_before = before
        flows = self._flows()
        for other in self.live:
            if other == vm or other not in flows_before:
                continue
            b = frozenset(fl for fl in flows_before[other] if fl[3] != ATTACKER)
            a = frozenset(fl for fl in flows[other] if fl[3] != ATTACKER)
            assert a <= b, f"I4: {what} on {vm} opened flows of {other}: {sorted(a - b)}"
            assert b <= a or self._footprint(other), f"I4: {what} on {vm} cut {other} off: {sorted(b - a)}"
            assert self._state(other) == states_before[other], f"I4: {what} on {vm} changed the state of {other}"
            if intact_before[other] and not self._attacker_flows_before_open(flows_before[other]):
                assert not self._attacker_flows(other), (
                    f"I4: {what} on {vm} reopened {ATTACKER} to {other}, whose block was intact")

    @staticmethod
    def _attacker_flows_before_open(flows: frozenset) -> bool:
        return any(fl[3] == ATTACKER for fl in flows)

    def _isolation_recorded(self, vm: str, what: str):
        if self._footprint(vm):
            assert self._state(vm) is not None, f"I8: {what} left {vm} in quarantine without state"

    def _quarantined(self) -> dict:
        return {k: list(e["groups"]) for k, e in self.fake.enis.items() if self._in_quarantine(e)}

    def _config_honoured(self, before: dict, what: str):
        for k, groups in self._quarantined().items():
            if sorted(before.get(k) or []) == sorted(groups):
                continue
            c = self.config
            assert c["readable"], f"I10: {what} put {k} in quarantine with an unreadable configuration"
            assert c["quarantine"], f"I10: {what} put {k} in quarantine, the configuration turns it off"

    # ── operations ──────────────────────────────────────────────────────────────

    @rule(data=st.data())
    def isolate(self, data):
        vm, fault = self._draw(data)
        self._isolate(vm, fault)

    def _isolate(self, vm, fault):
        before, quarantined = self._before(), self._quarantined()
        refused = not self.config["readable"] or not self.config["quarantine"]
        aws_before = self.fake.snapshot() if refused else None
        writes = len(self.fake.journal)
        out, err = self._run(fault, lambda: self.connector.isolate_vm(arn(vm)), "isolate")
        if (out or {}).get("status") == "isolated" or len(self.fake.journal) > writes:
            self.releasing.discard(vm)
        if aws_before is not None:
            assert self.fake.snapshot() == aws_before, f"I10: isolate_vm wrote for {vm}, quarantine off or unreadable"
            assert err is not None, f"I10: isolate_vm on {vm} did not refuse: {out}"
        if out and out.get("status") == "isolated" and not out.get("bypass"):
            assert not self._undeclared(vm, out), f"I3: isolate_vm said isolated, {vm} still reachable"
            check, _ = self._run(None, lambda: self.connector.verify_isolation(arn(vm)))
            assert check and check.get("verified") is True, f"I3: fresh isolation of {vm} not verified: {check}"
        if out:
            assert (out.get("drain") or {}).get("status") != "drained", f"I3: sessions said cut on {vm}"
        if err is None:
            self._isolation_recorded(vm, "isolate_vm")
        self._config_honoured(quarantined, "isolate_vm")
        self._others_unchanged(vm, before, "isolate")

    @rule(data=st.data())
    def release(self, data):
        vm, fault = self._draw(data, deleted_too=True)
        self._release(vm, fault)

    def _release(self, vm, fault):
        before = self._before()
        self.releasing.add(vm)
        writes = len(self.fake.journal)
        out, err = self._run(fault, lambda: self.connector.release_isolation(arn(vm)), "release")
        if (out or {}).get("status") == "released" or (err is not None and len(self.fake.journal) == writes):
            self.releasing.discard(vm)
        if vm not in self.deleted:
            if out and out.get("status") == "released":
                assert self._released(vm), f"I3: release said released, {vm} is not back to its design: {self._why(vm)}"
            if err is None:
                self._isolation_recorded(vm, "release_isolation")
        elif out and out.get("status") == "released":
            assert self._state(vm) is None, f"I3: release of the deleted {vm} said released, state kept"
        self._others_unchanged(vm, before, "release")
        return out, err

    @rule(data=st.data())
    def interrupted_release(self, data):
        vm, _ = self._draw(data)
        self._isolate(vm, None)
        self._release(vm, (data.draw(st.integers(1, 8), label="cut at"),
                           data.draw(st.sampled_from(["before-crash", "after-crash"]), label="how")))
        if data.draw(st.booleans(), label="then reassert"):
            self.reassert(data)

    @rule(data=st.data())
    def another_host_writes(self, data):
        """Another host puts back what the ENI carried right after Glorfindel wrote it."""
        vm, _ = self._draw(data)
        foreign = ("eni.write", data.draw(st.sampled_from(["after-foreign", "always-foreign"]), label="how often"))
        if data.draw(st.booleans(), label="during the release"):
            self._isolate(vm, None)
            self._release(vm, foreign)
        else:
            self._isolate(vm, foreign)

    @rule(data=st.data())
    def block_then_isolate(self, data):
        vm, fault = self._draw(data)
        self._block(vm, fault, data.draw(st.sampled_from([22, None]), label="threat_port"))
        self._isolate(vm, data.draw(_FAULTS, label="isolate fault"))
        if data.draw(st.booleans(), label="release"):
            self._release(vm, None)

    @rule(data=st.data())
    def isolate_two(self, data):
        first, f1 = self._draw(data)
        self._isolate(first, f1)
        second, f2 = self._draw(data)
        self._isolate(second, f2)
        if data.draw(st.booleans(), label="release the first"):
            self._release(first, None)

    @rule(data=st.data())
    def interrupted_isolation(self, data):
        vm, _ = self._draw(data)
        self._isolate(vm, (data.draw(st.integers(1, 10), label="cut at"),
                           data.draw(st.sampled_from(["before-crash", "after-crash"]), label="how")))
        self._isolate(vm, data.draw(_FAULTS, label="retry fault"))
        self._release(vm, None)

    @rule(data=st.data())
    def block(self, data):
        vm, fault = self._draw(data)
        self._block(vm, fault, data.draw(st.sampled_from([22, None]), label="threat_port"),
                    data.draw(st.sampled_from(["vm", "subnet"]), label="scope"))

    def _block(self, vm, fault, port, scope="vm"):
        before = self._before()
        out, err = self._run(fault, lambda: self.connector.block_suspicious_ip(
            ATTACKER, arn(vm), scope=scope, threat_port=port), "block")
        if out and out.get("status") == "blocked" and not out.get("bypass"):
            assert not self._attacker_flows(vm), f"I3: block said blocked, {ATTACKER} reaches {vm}"
            check, _ = self._run(None, lambda: self.connector.verify_block_ip(ATTACKER, arn(vm)))
            assert check and check.get("verified") is True, f"I3: fresh block on {vm} not verified: {check}"
        self._others_unchanged(vm, before, "block")

    @rule(data=st.data())
    def unblock(self, data):
        vm, fault = self._draw(data, deleted_too=True)
        before = self._before()
        self.unblocking.add(vm)
        out, _ = self._run(fault, lambda: self.connector.unblock_ip(ATTACKER, arn(vm)), "unblock")
        if (out or {}).get("status") in ("unblocked", "not_found"):
            self.unblocking.discard(vm)
            assert not [e for e in self._blocks(vm) if e.get("ip") == ATTACKER], (
                f"I3: unblock said {out['status']}, the block of {vm} still recorded")
        self._others_unchanged(vm, before, "unblock")

    @rule(data=st.data())
    def verify(self, data):
        vm, fault = self._draw(data)
        self._check_claims(vm, fault)
        for api in _THROTTLED_APIS:
            self._check_claims(vm, (api, "always-429"))

    @rule(data=st.data())
    def reassert(self, data):
        _CURRENT.mode = data.draw(st.sampled_from(["human_only", "non_disruptive"]), label="mode")
        fault = data.draw(_FAULTS, label="fault")
        flows = self._flows()
        had_state = {vm: self._state(vm) is not None or bool(self._blocks(vm)) for vm in self.live}
        releasing = [vm for vm in self.live if vm in self.releasing]
        footprints = {vm: self._footprint(vm) for vm in releasing}
        quarantined = self._quarantined()
        writes = len(self.fake.journal)
        vanished = [vm for vm in self.live if self._block_vanished(vm)]
        report, err = self._run(fault, lambda: reassert.reassert_active(self.connector, None))
        for r in report or []:
            _note(f"aws reassert ({_CURRENT.mode}): {r['outcome']}")
        if fault is None and err is None:
            told = {(e.get("resource_id") or "") for e in escalations.pending()
                    if e.get("action") == "block_suspicious_ip"}
            for vm in vanished:
                assert not self._block_vanished(vm) or arn(vm) in told, (
                    f"L1: the block on {vm} vanished; the reassertion neither put it back nor said so"
                    + (f": {self._blocks(vm)}, report {report}, pending {escalations.pending()}"
                       if os.environ.get("GLORFINDEL_INVARIANT_TRACE") else ""))
        after = self._flows()
        for vm in self.live:
            assert after[vm] <= flows[vm], f"I5: the reassertion opened flows of {vm}: {sorted(after[vm] - flows[vm])}"
            if _CURRENT.mode == "non_disruptive" and not had_state[vm] and not self._footprint(vm):
                strip = lambda fl: frozenset(x for x in fl if x[3] != ATTACKER)   # noqa: E731
                assert strip(after[vm]) == strip(flows[vm]), f"I5: the reassertion acted on {vm}, which has no state"
        if _CURRENT.mode == "human_only":
            assert len(self.fake.journal) == writes, "I5: the reassertion wrote in human_only"
        for vm in releasing:
            assert self._footprint(vm) <= footprints[vm], f"I9: the reassertion isolated {vm} again mid-release"
        self._config_honoured(quarantined, "the reassertion")

    @rule(data=st.data())
    def drift_then_reassert(self, data):
        """A rare state made common (none in 500 sequences without it): an instance
        isolated and its attacker blocked, then what Glorfindel put there goes — `terraform
        apply` puts an ENI's groups back, or strips an ACL — and the watch reasserts."""
        vm = data.draw(st.sampled_from(self.live), label="vm")
        self._isolate(vm, None)
        self._block(vm, None, 22)
        if data.draw(st.booleans(), label="the ENI"):
            eni = data.draw(st.sampled_from(self.fake.instances[vm]["enis"]), label="eni")
            e = self.fake.enis[eni]
            if all(g in self.fake.sgs for g in e["design_groups"]):
                e["groups"] = list(e["design_groups"])
        else:
            acl = data.draw(st.sampled_from(sorted(self._vm_acls(vm))), label="acl")
            entries = self.fake.acls[acl]["entries"]
            for k in [k for k in entries if k not in self.design["acls"][acl]["entries"]]:
                del entries[k]
                self.fake.authored.pop((acl, *k), None)
                self.tampered.pop((acl, *k), None)
        self._claims_after_a_change()
        self.reassert(data)

    @rule(data=st.data())
    def another_account(self, data):
        """An instance of another account or region, or an id that is no instance ARN:
        refused, nothing written, no state changed (I12)."""
        vm = data.draw(st.sampled_from(self.live), label="vm")
        rid = data.draw(st.sampled_from([arn(vm, account="444455556666"), arn(vm, region="eu-central-1"), vm,
                                         f"/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/"
                                         f"virtualMachines/{vm}"]), label="id")
        kind = data.draw(st.sampled_from(["isolate", "release", "block", "unblock", "verify_isolation",
                                          "verify_release", "verify_block"]), label="operation")
        c = self.connector
        fn = {"isolate": lambda: c.isolate_vm(rid), "release": lambda: c.release_isolation(rid),
              "block": lambda: c.block_suspicious_ip(ATTACKER, rid, threat_port=22),
              "unblock": lambda: c.unblock_ip(ATTACKER, rid), "verify_isolation": lambda: c.verify_isolation(rid),
              "verify_release": lambda: c.verify_release(rid),
              "verify_block": lambda: c.verify_block_ip(ATTACKER, rid)}[kind]
        aws, state, blocks = self.fake.snapshot(), self._state(vm), self._blocks(vm)
        out, err = self._run(None, fn, f"another account: {kind}")
        assert isinstance(err, WrongAccountError), f"I12: {kind} on {rid} was not refused: {out or err!r}"
        assert self.fake.snapshot() == aws, f"I12: {kind} on {rid} wrote"
        assert self._state(vm) == state and self._blocks(vm) == blocks, f"I12: {kind} on {rid} changed a state"

    # ── two operations at once (L27) ────────────────────────────────────────────

    def _consistent(self, vm: str) -> bool:
        """The local state says what AWS has: an ENI in quarantine ⟺ an isolation state
        (unless it says it is partial or in progress); a block recorded, held by no
        operation ⟹ its entries are there."""
        stt = self._state(vm)
        held = bool(stt and (stt.get("partial") or stt.get("release_failed") or stt.get("releasing_at")))
        if bool(self._footprint(vm)) != (stt is not None) and not (held and stt is not None):
            return False
        entry = next((e for e in self._blocks(vm) if e.get("ip") == ATTACKER), None)
        if entry and not any(entry.get(k) for k in ("partial", "unblock_failed", "unblocking_at")):
            ps = [p for p in entry.get("placements") or [] if p.get("acl_id")]
            return all(any(self._our_entry(acl, False, p.get("rule_in")) and self._our_entry(acl, True, p.get("rule_out"))
                           for p in ps if p["acl_id"] == acl) for acl in {p["acl_id"] for p in ps})
        return True

    def _concurrent_op(self, data, n: int, vm: str | None = None, kind: str | None = None):
        vm = vm or data.draw(st.sampled_from(self.live), label=f"vm {n}")
        kind = kind or data.draw(st.sampled_from(["isolate", "release", "block", "unblock", "reassert"]),
                                 label=f"operation {n}")
        c, rid = self.connector, arn(vm)
        fn = {"isolate": lambda: c.isolate_vm(rid), "release": lambda: c.release_isolation(rid),
              "block": lambda: c.block_suspicious_ip(ATTACKER, rid, threat_port=22),
              "unblock": lambda: c.unblock_ip(ATTACKER, rid),
              "reassert": lambda: reassert.reassert_active(c, None)}[kind]
        return vm, kind, fn

    @rule(data=st.data())
    def concurrently(self, data):
        first = self._concurrent_op(data, 1)
        same = data.draw(st.integers(0, 3), label="other vm") != 0
        second = self._concurrent_op(data, 2, first[0] if same else None)
        _CURRENT.mode = data.draw(st.sampled_from(["human_only", "non_disruptive"]), label="mode")
        self._race(data, first, second)

    _RACES = [("release", "reassert"), ("isolate", "release"), ("release", "release"),
              ("block", "unblock"), ("unblock", "reassert"), ("block", "block"), ("unblock", "block")]

    @rule(data=st.data())
    def race(self, data):
        vm = data.draw(st.sampled_from(self.live), label="vm")
        self._isolate(vm, None)
        self._block(vm, None, 22)
        one, two = data.draw(st.sampled_from(self._RACES), label="race")
        # Two blocks at once, or an unblock while another instance blocks: on two
        # instances, mostly sharing an ACL — the entries one holds, the other may reuse.
        other = vm
        if (one, two) in (("block", "block"), ("unblock", "block")):
            mates = [v for v in self.live if v != vm and self._vm_acls(v) & self._vm_acls(vm)]
            other = data.draw(st.sampled_from(mates or self.live), label="second vm")
        _CURRENT.mode = "non_disruptive"
        self._race(data, self._concurrent_op(data, 1, vm, one), self._concurrent_op(data, 2, other, two))

    def _race(self, data, first, second):
        order = data.draw(st.integers(0, 2**32 - 1), label="interleaving")
        involved = {first[0], second[0]}
        consistent = {vm: self._consistent(vm) for vm in involved}
        flows = self._flows()
        self.chaos.arm(None)
        for vm, kind, _ in (first, second):
            if kind == "release":
                self.releasing.add(vm)
        _CURRENT.scheduler = _Scheduler(order)
        try:
            results = _CURRENT.scheduler.run([("op-1", first[2]), ("op-2", second[2])])
        finally:
            _CURRENT.scheduler = None
        for name, (vm, kind, _) in (("op-1", first), ("op-2", second)):
            out = (results.get(name) or (None, None))[0]
            status = out.get("status") if isinstance(out, dict) else None
            if (kind, status) in (("release", "released"), ("isolate", "isolated")):
                self.releasing.discard(vm)
        errors = [e for _, e in results.values() if e is not None]
        for name, (out, err) in sorted(results.items()):
            kind = (first if name == "op-1" else second)[1]
            _note(f"aws concurrently {kind}: " + (type(err).__name__ if err else (
                str((out or {}).get("status", "ok")) if not isinstance(out, list) else "ok")))
        if not errors:
            for vm in involved:
                if consistent[vm]:
                    assert self._consistent(vm), (
                        f"I11: {first[1]} and {second[1]} at once left {vm} with a state that isn't AWS's")
        after = self._flows()
        for other in self.live:
            if other not in involved and "reassert" not in {first[1], second[1]}:
                b = frozenset(fl for fl in flows[other] if fl[3] != ATTACKER)
                a = frozenset(fl for fl in after[other] if fl[3] != ATTACKER)
                assert a <= b and (b <= a or self._footprint(other)), f"I4: two operations elsewhere changed {other}"
        self._claims_after_a_change()

    # ── the customer's world moving ─────────────────────────────────────────────

    def _customer_sgs(self) -> list[str]:
        return sorted(k for k in self.design["sgs"] if k in self.fake.sgs)

    @rule(data=st.data())
    def customer_adds_sg_rule(self, data):
        sgs = self._customer_sgs()
        sg = data.draw(st.sampled_from(sgs), label="sg")
        side, r = _SG_TEMPLATES[data.draw(st.sampled_from(sorted(_SG_TEMPLATES)), label="template")]
        if r not in self.fake.sgs[sg][side]:
            self.fake.sgs[sg][side].append(dict(r))
            self.design["sgs"][sg][side].append(dict(r))
        self._claims_after_a_change()

    @rule(data=st.data())
    def customer_removes_sg_rule(self, data):
        sgs = [s for s in self._customer_sgs() if self.fake.sgs[s]["ingress"] or self.fake.sgs[s]["egress"]]
        if not sgs:
            return
        sg = data.draw(st.sampled_from(sgs), label="sg")
        rules = [(side, i) for side in ("ingress", "egress") for i in range(len(self.fake.sgs[sg][side]))]
        side, i = data.draw(st.sampled_from(rules), label="rule")
        r = self.fake.sgs[sg][side].pop(i)
        self.design["sgs"][sg][side].remove(r)
        self._claims_after_a_change()

    @rule(data=st.data())
    def customer_deletes_sg(self, data):
        """A group no ENI carries now — an ENI in quarantine left it — looks unused, and is
        deleted. AWS refuses it while an ENI carries it (H4)."""
        sgs = [s for s in self._customer_sgs() if self.fake.sgs[s]["name"] != "default"]
        if not sgs:
            return
        sg = data.draw(st.sampled_from(sgs), label="sg")
        if self.fake.delete_sg(sg):
            self.deleted_sgs.add(sg)
            _note("aws customer: group deleted")

    def _customer_acls(self) -> list[str]:
        return sorted(self.design["acls"])

    @rule(data=st.data())
    def customer_adds_acl_entry(self, data):
        acl = data.draw(st.sampled_from(self._customer_acls()), label="acl")
        egress, action, cidr, proto, port, to = _ACL_TEMPLATES[
            data.draw(st.sampled_from(sorted(_ACL_TEMPLATES)), label="template")]
        n = data.draw(st.sampled_from([1, 50, 98, 99, 100, 150, 300]), label="number")
        entries = self.fake.acls[acl]["entries"]
        if (egress, n) in entries:
            _note("aws customer: entry refused (number taken)")
            return
        entries[(egress, n)] = acl_entry(n, egress, action, cidr, proto, port, to)
        self.design["acls"][acl]["entries"][(egress, n)] = dict(entries[(egress, n)])
        self._claims_after_a_change()

    @rule(data=st.data())
    def customer_removes_acl_entry(self, data):
        acl = data.draw(st.sampled_from(self._customer_acls()), label="acl")
        keys = sorted(self.design["acls"][acl]["entries"])
        if not keys:
            return
        k = data.draw(st.sampled_from(keys), label="entry")
        self.fake.acls[acl]["entries"].pop(k, None)
        self.design["acls"][acl]["entries"].pop(k)
        self._claims_after_a_change()

    @rule(data=st.data())
    def terraform_apply_acl(self, data):
        """An ACL with inline entries (H11): `apply` removes every entry absent from the
        code — Glorfindel's blocks among them."""
        acl = data.draw(st.sampled_from(self._customer_acls()), label="acl")
        entries = self.fake.acls[acl]["entries"]
        for k in [k for k in entries if k not in self.design["acls"][acl]["entries"]]:
            del entries[k]
            self.fake.authored.pop((acl, *k), None)
            self.tampered.pop((acl, *k), None)
        self._claims_after_a_change()

    @rule(data=st.data())
    def terraform_reverts_eni(self, data):
        """`terraform apply` on an ENI's (or an instance's) groups puts the code's back
        (H11): a quarantine is undone."""
        eni = data.draw(st.sampled_from(sorted(self.fake.enis)), label="eni")
        e = self.fake.enis[eni]
        if all(g in self.fake.sgs for g in e["design_groups"]):
            e["groups"] = list(e["design_groups"])
        self._claims_after_a_change()

    @rule(data=st.data())
    def customer_changes_ip(self, data):
        eni = data.draw(st.sampled_from(sorted(self.fake.enis)), label="eni")
        e = self.fake.enis[eni]
        at = data.draw(st.integers(0, len(e["ips"]) - 1), label="which")
        base = self.fake.subnets[e["subnet"]]["cidr"].rsplit(".", 1)[0]
        used = {ip for x in self.fake.enis.values() for ip in x["ips"]}
        new = next(f"{base}.{i}" for i in range(4, 250) if f"{base}.{i}" not in used)
        e["ips"][at] = new
        self.design["enis"][eni]["ips"][at] = new
        self._claims_after_a_change()

    @rule(data=st.data())
    def customer_sets_policy(self, data):
        eni = data.draw(st.sampled_from(sorted(self.fake.enis)), label="eni")
        self.fake.enis[eni]["policy"] = data.draw(st.booleans(), label="policy")

    @rule(data=st.data())
    def create_instance(self, data):
        if len(self.vms) >= len(_INSTANCES) + 3:
            return
        self._serial += 1
        subnet = data.draw(st.sampled_from(sorted(_SUBNETS)), label="subnet")
        vpc = _SUBNETS[subnet][0]
        iid, eni = f"i-new{self._serial}", f"eni-new{self._serial}"
        options = sorted(s for s in self._customer_sgs() if self.fake.sgs[s]["vpc"] == vpc)
        groups = data.draw(st.lists(st.sampled_from(options), min_size=1, max_size=2, unique=True), label="groups")
        base = _SUBNETS[subnet][1].rsplit(".", 1)[0]
        used = {ip for x in self.fake.enis.values() for ip in x["ips"]}
        ip = next(f"{base}.{i}" for i in range(4, 250) if f"{base}.{i}" not in used)
        self.fake.add_instance(iid, [{"id": eni, "subnet": subnet, "ips": [ip], "groups": groups}],
                               platform=data.draw(st.sampled_from(["linux", "windows"]), label="os"))
        self.vms.append(iid)
        self.design["instances"][iid] = copy.deepcopy(self.fake.instances[iid])
        self.design["enis"][eni] = copy.deepcopy(self.fake.enis[eni])
        _note(f"aws created {iid} at {ip}")

    @rule(data=st.data())
    def delete_instance(self, data):
        if len(self.live) <= 2:
            return
        vm = data.draw(st.sampled_from(self.live), label="vm")
        enis = self.fake.instances.pop(vm)["enis"]
        for e in enis:
            self.fake.enis.pop(e)
            self.design["enis"].pop(e)
        self.design["instances"].pop(vm)
        self.deleted[vm] = enis

    # ── someone else touching what is Glorfindel's ──────────────────────────────

    def _ours_ids(self) -> list[str]:
        return sorted(k for k, s in self.fake.sgs.items() if _ours(s))

    @rule(data=st.data())
    def someone_opens_the_quarantine(self, data):
        """Someone adds an allow to our quarantine group (in from anywhere, or out)."""
        ours = self._ours_ids()
        if ours:
            sg = self.fake.sgs[data.draw(st.sampled_from(ours), label="quarantine")]
            side = data.draw(st.sampled_from(["ingress", "egress"]), label="side")
            r = sg_rule(cidr="0.0.0.0/0")
            if r not in sg[side]:
                sg[side].append(r)
            self.altered.add(sg["id"])
            self._claims_after_a_change()

    @rule(data=st.data())
    def someone_detaches_the_quarantine(self, data):
        """Someone takes an ENI out of our quarantine onto the VPC's `default` group — an
        ENI can't carry no group (H2): the AWS analog of a NIC left bare."""
        enis = sorted(k for k, e in self.fake.enis.items() if self._in_quarantine(e))
        if enis:
            eni = data.draw(st.sampled_from(enis), label="eni")
            e = self.fake.enis[eni]
            e["groups"] = [f"sg-default-{e['vpc']}"]
            self.detached.add(eni)
            self._claims_after_a_change()

    @rule(data=st.data())
    def tags_lost(self, data):
        self._tags_lost(data)
        self._claims_after_a_change()

    def _tags_lost(self, data):
        ours = self._ours_ids()
        if ours:
            sg = self.fake.sgs[data.draw(st.sampled_from(ours), label="quarantine")]
            sg["tags"] = {k: v for k, v in sg["tags"].items() if not k.startswith("glorfindel-orig-")}
            self._check_authors()
            self.ticks += 1
            self.tags_lost_at[sg["id"]] = self.ticks

    @rule(data=st.data())
    def tamper_with_our_entry(self, data):
        """Someone replaces one of Glorfindel's ACL entries: an allow now, another address,
        or TCP only. What an allow lets through is theirs (I1 is judged without it)."""
        ours = sorted(k for k, content in self.fake.authored.items()
                      if self.fake.acls.get(k[0], {}).get("entries", {}).get(k[1:]) == content)
        if not ours:
            return
        k = data.draw(st.sampled_from(ours), label="entry")
        e = self.fake.acls[k[0]]["entries"][k[1:]]
        before = dict(e)
        how = data.draw(st.sampled_from(["allow", "cidr", "tcp"]), label="how")
        if how == "allow":
            e["action"] = "allow"
        elif how == "cidr":
            e["cidr"] = "10.0.0.99/32"
        else:
            e["proto"], e["from"], e["to"] = "6", 22, 22
        self.tampered[k] = (before, dict(e))
        self._claims_after_a_change()

    @rule()
    def time_passes(self):
        _CURRENT.clock += 40

    @rule(data=st.data())
    def access_changes(self, data):
        self.fake.write_denied = data.draw(st.booleans(), label="denied")

    @rule(data=st.data())
    def config_changes(self, data):
        self.config = dict(data.draw(_configs(), label="config"))
        self.config["readable"] = data.draw(st.booleans(), label="readable")
        self._write_config()

    @rule(data=st.data())
    def lose_state(self, data):
        vm = data.draw(st.sampled_from(self.vms), label="vm")
        self._check_authors()
        self.ticks += 1
        self.state_lost_at[vm] = self.ticks
        for f in (actions._ISOLATION_STATE_DIR.glob("*.json") if actions._ISOLATION_STATE_DIR.exists() else []):
            if actions._file_rid(f) == arn(vm).lower():
                f.unlink()

    @rule(data=st.data())
    def lose_everything(self, data):
        vm, _ = self._draw(data)
        self._isolate(vm, None)
        self.lose_state(data)
        self._tags_lost(data)
        if data.draw(st.booleans(), label="reisolate"):
            self._isolate(vm, None)

    @rule()
    def recover(self):
        self._recover_everything(lose_state=False)

    def _release_until_done(self, vm: str) -> dict:
        out = {}
        for _ in range(3):
            out = self.connector.release_isolation(arn(vm))
            if out["status"] == "released":
                if vm not in self.deleted:
                    assert self._released(vm), f"I3: release said released, {vm} is not back to its design: {self._why(vm)}"
                break
        return out

    def _recreate(self, sg_id: str) -> str:
        """The operator recreates a deleted group: a new id (H4), its design rules."""
        self._serial += 1
        d = self.design["sgs"].pop(sg_id)
        new = f"{sg_id}-r{self._serial}"
        self.fake.add_sg(d["vpc"], new, d["name"] + f"-r{self._serial}", d["ingress"], d["egress"])
        self.design["sgs"][new] = copy.deepcopy(self.fake.sgs[new])
        for enis in (self.fake.enis, self.design["enis"]):
            for e in enis.values():
                e["design_groups"] = [new if g == sg_id else g for g in e["design_groups"]]
                if enis is self.design["enis"]:
                    e["groups"] = list(e["design_groups"])
        self.deleted_sgs.discard(sg_id)
        return new

    def _operator_supplies_originals(self, vm: str, out: dict):
        """I7: an ENI whose original is unknown, or one of its groups deleted, stays in
        quarantine and the release says so. The operator then does what it says:
        recreates the group, sets the tag."""
        assert out.get("failed"), f"I7: release of {vm} not done and nothing said: {out}"
        failed = {f["nic"] for f in out["failed"]}
        for e in self._enis(vm):
            if e["id"] not in failed:
                continue
            for g in list(e["design_groups"]):
                if g not in self.fake.sgs:
                    self._recreate(g)
            # The tag on the quarantine group of its VPC (the one it carries, or the one it
            # was taken out of).
            q = next(s for s in self.fake.sgs.values() if _ours(s) and s["vpc"] == e["vpc"])
            q["tags"][f"glorfindel-orig-{e['id']}"] = ",".join(e["design_groups"])

    def _recover_everything(self, lose_state: bool):
        """I7: whatever was reached, release brings every instance back to its design."""
        self.chaos.plan = None
        self.fake.write_denied = False
        for e in self.fake.enis.values():
            e["policy"] = False
        self.config["readable"] = True
        self._write_config()
        for vm in self.live:
            for e in self._enis(vm):
                if self._untraceable(vm, e) and all(g in self.fake.sgs for g in e["design_groups"]):
                    e["groups"] = list(e["design_groups"])
        # What someone turned around is theirs to put back: the operator removes it.
        for (acl, eg, n), (_, after) in list(self.tampered.items()):
            entries = self.fake.acls.get(acl, {}).get("entries", {})
            if entries.get((eg, n)) == after:
                del entries[(eg, n)]
        self.tampered.clear()
        for vm in self.vms:
            if lose_state and vm not in self.deleted and actions._ISOLATION_STATE_DIR.exists():
                for f in actions._ISOLATION_STATE_DIR.glob("*.json"):
                    if actions._file_rid(f) == arn(vm).lower():
                        f.unlink()
            out = self._release_until_done(vm)
            if out["status"] != "released" and vm not in self.deleted:
                self._operator_supplies_originals(vm, out)
                out = self._release_until_done(vm)
            assert out["status"] == "released", f"I7: {vm} could not be released: {out}"
            for _ in range(3):
                if self.connector.unblock_ip(ATTACKER, arn(vm))["status"] in ("unblocked", "not_found"):
                    break
            assert not [e for e in self._blocks(vm) if e.get("ip") == ATTACKER], f"I7: the block of {vm} is left"
        for vm in self.live:
            assert self._released(vm), f"I7: {vm} could not be brought back to its design: {self._why(vm)}"
        left = [k for k, content in self.fake.authored.items()
                if self.fake.acls.get(k[0], {}).get("entries", {}).get(k[1:]) == content]
        assert not left, f"I7: ACL entries of Glorfindel's left after every unblock: {left}"
        # Someone's allows on our quarantine groups: the operator takes them off (an
        # empty quarantine group carried by nothing is left, as on Azure).
        for sg in self._ours_ids():
            self.fake.sgs[sg]["ingress"], self.fake.sgs[sg]["egress"] = [], []
        self._check_authors()                  # judged against what was detached when written
        self.altered.clear()

    # ── always ──────────────────────────────────────────────────────────────────

    @invariant()
    def writes_only_its_own(self):
        self._check_authors()

    def _check_authors(self):
        """I2 by author, from the fake's journal: what went through the API is
        Glorfindel's (the test plays everyone else on the dicts)."""
        if not getattr(self, "fake", None):
            return
        for e in self.fake.journal[self.journal_seen:]:
            op = e["op"]
            if op == "sg.create":
                assert e["name"] == QSG and e["tags"].get("managed-by") == "glorfindel", (
                    f"I2: Glorfindel created a group not its quarantine: {e}")
            elif op in ("sg.rules", "tags"):
                sg = e.get("sg") or e.get("resource")
                assert _ours(self.fake.sgs.get(sg)), f"I2: Glorfindel wrote {op} on {sg}, not its quarantine group"
            elif op == "acl.create":
                content = self.fake.authored.get((e["acl"], e["egress"], e["number"]))
                assert content is None or content["action"] == "deny", f"I2: Glorfindel wrote an allow: {e}"
            elif op == "acl.delete":
                assert e["authored"], f"I2: Glorfindel deleted an ACL entry it did not write as it is: {e}"
            elif op == "eni.groups":
                eni, was, now = e["eni"], e["before"], e["after"]
                if len(now) == 1 and _ours(self.fake.sgs.get(now[0])):
                    if not any(_ours(self.fake.sgs.get(g)) for g in was):
                        self.before_quarantine[eni] = list(was)
                        # From `default` where someone left it (the AWS analog of a bare
                        # NIC): not an original Glorfindel learns — only what it carried
                        # before counts (test_invariants._check_authors, `if was`).
                        if not (eni in self.detached and was == [f"sg-default-{self.fake.enis[eni]['vpc']}"]):
                            self.ticks += 1
                            self.recorded_at[eni] = (self.ticks, now[0])
                    continue
                design = (self.fake.enis.get(eni) or {}).get("design_groups") or []
                allowed = [sorted(design)] + ([sorted(self.before_quarantine[eni])]
                                              if eni in self.before_quarantine else [])
                from_ours = any(_ours(self.fake.sgs.get(g)) for g in was)
                from_detached = eni in self.detached and was == [f"sg-default-{self.fake.enis[eni]['vpc']}"]
                assert (from_ours or from_detached) and sorted(now) in allowed, (
                    f"I2: Glorfindel set {eni}'s groups from {was} to {now} "
                    f"(before quarantine: {self.before_quarantine.get(eni, 'never in quarantine')})")
        self.journal_seen = len(self.fake.journal)
        for vm in self.live:
            for p in (self._state(vm) or {}).get("placements") or []:
                nk = p.get("nic_id") or ""
                if p.get("original_groups") and nk in self.recorded_at:
                    self.state_had[nk] = self.recorded_at[nk][0]

    @invariant()
    def never_more_open_than_designed(self):
        if not getattr(self, "design", None):
            return
        for vm in self.live:
            gone = {e["id"] for e in self._enis(vm) if e["id"] in self.detached or
                    any(g in self.altered and not self._quarantine_intact(g) for g in e["groups"])}
            extra = {fl for fl in self._open(vm, untampered=True) - self._designed(vm) if fl[0] not in gone}
            assert not extra, f"I1: {vm} more reachable than designed: {sorted(extra)}"

    @invariant()
    def customer_configuration_untouched(self):
        if not getattr(self, "design", None):
            return
        for k, sg in self.design["sgs"].items():
            if k not in self.fake.sgs:
                continue
            live = self.fake.sgs[k]
            assert (live["ingress"], live["egress"]) == (sg["ingress"], sg["egress"]), (
                f"I2: customer rules of {k} changed")
        for k, acl in self.design["acls"].items():
            live = {key: e for key, e in self.fake.acls[k]["entries"].items()
                    if (k, *key) not in self.fake.authored and (k, *key) not in self.tampered}
            assert live == acl["entries"], f"I2: customer entries of {k} changed"
        for k, s in self.design["subnets"].items():
            assert self.fake.subnets[k]["acl"] == s["acl"], f"I2: the ACL of {k} changed"
        self._check_authors()                  # the writes so far, against what is detached now
        for k, e in self.fake.enis.items():
            if not self._in_quarantine(e) and not self._on_default(e):
                self.detached.discard(k)              # a customer group is back on it
            ok = sorted(e["groups"]) == sorted(e["design_groups"]) or (
                len(e["groups"]) == 1 and _ours(self.fake.sgs.get(e["groups"][0]))
            ) or (k in self.detached and self._on_default(e))
            assert ok, f"I2: {k} carries {e['groups']}, designed {e['design_groups']}"

    @invariant()
    def every_entry_of_glorfindel_is_recorded(self):
        """I8 for the blocks, always: an ACL entry has no name — an entry of Glorfindel's
        (still as it wrote it) that no recorded block names would never be removed."""
        if not getattr(self, "design", None):
            return
        named = {(p.get("acl_id"), eg, p.get(k)) for vm in self.vms for b in self._blocks(vm)
                 for p in b.get("placements") or [] for eg, k in ((False, "rule_in"), (True, "rule_out"))}
        for k, content in self.fake.authored.items():
            if self.fake.acls.get(k[0], {}).get("entries", {}).get(k[1:]) == content:
                assert k in named, f"I8: the ACL entry {k} of Glorfindel's is in no state"

    @invariant()
    def every_claim_is_true(self):
        if not getattr(self, "design", None) or not self.live:
            return
        self.turn = getattr(self, "turn", -1) + 1
        self._check_claims(self.live[self.turn % len(self.live)])

    def _check_claims(self, vm: str, fault=None):
        iso, err = self._run(fault, lambda: self.connector.verify_isolation(arn(vm)))
        assert fault is not None or err is None, f"I3: verify_isolation of {vm} raised: {err!r}"
        if iso and iso.get("verified") is True:
            assert not self._undeclared(vm, iso), f"I3: verify_isolation True, {vm} reachable"
        rel, _ = self._run(fault, lambda: self.connector.verify_release(arn(vm)))
        if rel and rel.get("verified") is True:
            assert self._back_to_design(vm) and self._enis_as_designed(vm), (
                f"I3: verify_release True, {vm} not back to its design")
        if any(e.get("ip") == ATTACKER for e in self._blocks(vm)):
            blk, _ = self._run(fault, lambda: self.connector.verify_block_ip(ATTACKER, arn(vm)))
            if blk and blk.get("verified") is True:
                assert not self._attacker_flows(vm), f"I3: verify_block_ip True, {ATTACKER} reaches {vm}"

    def _claims_after_a_change(self):
        for vm in self.live:
            self._check_claims(vm)

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


def test_isolation_invariants_on_aws(monkeypatch):
    invariant_env(monkeypatch)
    db = os.environ.get("GLORFINDEL_INVARIANT_DB")
    run_state_machine_as_test(AwsIsolationMachine, settings=settings(
        max_examples=int(os.environ.get("GLORFINDEL_INVARIANT_EXAMPLES", "60")),
        stateful_step_count=int(os.environ.get("GLORFINDEL_INVARIANT_STEPS", "30")),
        deadline=None, database=DirectoryBasedExampleDatabase(db) if db else None,
        phases=[Phase.explicit, Phase.reuse, Phase.generate] if os.environ.get("GLORFINDEL_INVARIANT_NO_SHRINK")
        else list(Phase),
        suppress_health_check=[HealthCheck.too_slow, HealthCheck.filter_too_much]))
    if os.environ.get("GLORFINDEL_INVARIANT_STATS"):
        for what, n in sorted(_SEEN.items()):
            if what.startswith("aws "):
                print(f"{n:7d}  {what}")


def test_the_fake_refuses_what_aws_refuses():
    """The hypotheses the fake encodes (H2, H4, H5, H9), checked on the fake itself."""
    f = FakeAws()
    f.add_vpc("vpc-a", "10.0.0.0/16")
    f.add_vpc("vpc-b", "10.1.0.0/16")
    f.add_subnet("vpc-a", "s", "10.0.0.0/24", "acl-default-vpc-a")
    f.add_instance("i-1", [{"id": "eni-1", "subnet": "s", "ips": ["10.0.0.4"], "groups": []}])
    assert f.enis["eni-1"]["groups"] == ["sg-default-vpc-a"]
    codes = []
    for call in (lambda: f.modify_network_interface_attribute(NetworkInterfaceId="eni-1", Groups=[]),
                 lambda: f.modify_network_interface_attribute(NetworkInterfaceId="eni-1", Groups=["sg-default-vpc-b"]),
                 lambda: f.create_network_acl_entry(NetworkAclId="acl-default-vpc-a", RuleNumber=100, Protocol="-1",
                                                    RuleAction="deny", Egress=False, CidrBlock="1.2.3.4/32"),
                 lambda: f.delete_network_acl_entry(NetworkAclId="acl-default-vpc-a", RuleNumber=7, Egress=False),
                 lambda: f.revoke_security_group_ingress(GroupId="sg-default-vpc-a", IpPermissions=[
                     {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])):
        try:
            call()
        except ClientError as exc:
            codes.append(exc.response["Error"]["Code"])
    assert codes == ["InvalidParameterValue", "InvalidGroup.NotFound", "NetworkAclEntryAlreadyExists",
                     "InvalidNetworkAclEntry.NotFound", "InvalidPermission.NotFound"]
    assert not f.delete_sg("sg-default-vpc-a")
