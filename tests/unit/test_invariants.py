"""Invariants of isolation, blocking, release, reassertion and crashes (L24, L26, A0).

Random customer networks (fake_azure.FakeAzure) and random sequences of operations,
with faults injected anywhere — a throttled call (429), a crash before a write, a crash
after a write whose answer never came back, a full disk on the local state — and a
world that moves under Glorfindel: the customer adds, narrows and removes rules,
deletes an NSG, changes an IP, sets a policy, redeploys a NIC, runs `terraform apply`;
someone edits Glorfindel's own rules or tags; the role is removed; the configuration
changes or can't be read; a VM is deleted or created (on the lowest free address, often
a deleted VM's); someone turns one of Glorfindel's rules around (an allow, behind a
customer allow, another protocol, another target) or adds an allow under one of its
names; another host writes a NIC right after Glorfindel did; an older version left
its isolation (fixed names, single-NSG state); the clock moves on. Hypothesis shrinks
any failure to the shortest sequence that breaks a property.

What must hold whatever happens:
  I1  no VM is ever more reachable than its owner designed it — the design follows the
      customer's own changes; the forensic access the operator configured is the one
      deliberate exception;
  I2  Glorfindel never changes the customer's configuration: the customer's rules are
      what the customer last wrote, a subnet keeps its NSG, a NIC carries the NSG the
      customer gave it or Glorfindel's quarantine NSG, never none or another — and, by
      author (the fake's journal of API writes), it only writes rules it wrote, its own
      NSG, and a NIC's NSG to or from its quarantine;
  I3  no success on a falsehood: "isolated" (no bypass reported) means isolated,
      "blocked" means the attacker is cut off, "released" means back to the design with
      nothing of Glorfindel's left on the NICs, a verification that says True is true;
  I4  an operation on one VM changes nothing for another — homonyms included (a
      perimeter block closes the attacker's flows on its subnet, and only those; an
      unblock or a reset that lifts one opens them, never cuts one off — I4B) — and
      never deletes another VM's older isolation, even where no flow tells (I4S);
  I5  the reassertion never opens anything, never acts on a VM it has no state for,
      and writes nothing to Azure in human_only;
  I6  one VM, one state file, whatever the case of the id it was reached with;
  I7  from any state reached, release brings every VM back to its design — or, when a
      NIC's original NSG can't be known or no longer exists, keeps that NIC in
      quarantine and says so; once the operator supplies it, the release completes;
  I8  what Glorfindel leaves on Azure after an operation that returned is in its state;
  I9  a release that has started is never undone by the reassertion;
  I10 the configuration is honoured: no quarantine NSG when the operator turned it off
      or when the configuration can't be read, and only in the group it names;
  I11 two operations at once (the watch, the War Room, the CLI) end as one of them
      after the other would: what the local state says is what Azure has (L27);
  I12 a VM of another subscription is never acted on — nor vouched for (A0);
  L1  a block whose rules all vanished from Azure is put back, or said — even behind the
      quarantine (A0);
  L2  a quarantine NSG someone altered, still holding NICs, is put back or said — its
      NICs' state lost too (I1F); once said, it stays said while the NSG is out of the
      listing — its role removed (a hypothesis: no error, fake_azure), our tag taken off (I1S);
  U1  a rule left by a NIC that no longer exists, cutting a live NIC off, is reported (L28)
      — and the orphan sweep takes it off, nothing else (A3): after it, every live VM is
      back to its design, not only in its own view.

Oracles are the test's own: what was released, what was lost and when, who wrote what
— never the markers and records the code under test leaves (a bug that deletes them
must not earn an exemption).

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
import contextlib
import copy
import hashlib
import os
import shutil
import tempfile
import threading
from pathlib import Path
from types import SimpleNamespace

from hypothesis import HealthCheck, Phase, event, settings, strategies as st
from hypothesis.database import DirectoryBasedExampleDatabase
from hypothesis.errors import InvalidArgument
from hypothesis.stateful import (
    RuleBasedStateMachine, initialize, invariant, rule, run_state_machine_as_test,
)

from glorfindel import actions, config, escalations, orphans, reassert
from glorfindel.response import locks
from glorfindel.actions import AzureConnector, _load_isolation_state

from .fake_azure import (
    ATTACKER, AZURE_DNS, AZURE_IMDS, LATERAL, Crash, FakeAzure, _rule_record, key, nic_id, open_flows,
    vm_id,
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
        # An isolation left by an older version on a NIC's dedicated NSG — its state kept
        # or lost (A0, M02).
        "legacy": draw(st.one_of(st.none(), st.tuples(st.sampled_from(["web-nic", "api-nic"]), st.booleans()))),
        # Db--01's second NIC on a subnet of its own, behind its own NSG (RB1): a perimeter
        # block covers the primary NIC's subnet only. Drawn last: the earlier draws keep
        # their bytes.
        "data_subnet": draw(st.one_of(st.none(), _customer_rules())),
    }


def _configs():
    return st.fixed_dictionaries({
        "quarantine": st.booleans(),
        "rg": st.sampled_from(["", "rg-sec"]),
        # A bastion, a whole /16 (must be refused), the attacker's own address.
        "forensic": st.sampled_from([[], [LATERAL], ["10.9.0.0/16"], [ATTACKER]]),
        "readable": st.just(True),
    })


def _valid_sources(values) -> list:
    """What an operator may declare as an investigation source, by the test's own rule
    (not the code's): one address or a prefix of 256 addresses at most, not reserved."""
    import ipaddress
    ok = []
    for v in values or []:
        try:
            net = ipaddress.ip_network(str(v), strict=False)
        except ValueError:
            continue
        if net.num_addresses <= 256 and not (net.is_loopback or net.is_reserved or net.is_link_local
                                             or net.is_multicast or net.network_address.is_unspecified):
            ok.append(net)
    return ok


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
            if _CURRENT.scheduler is not None:
                _CURRENT.scheduler.point()
            self.calls += 1
        elif write:
            self.writes += 1
        if not self.plan:
            return
        when, what = self.plan[1].split("-")
        if what == "foreign":
            # after: once; always: every write of the operation (a second watch that
            # keeps reasserting what it saw).
            if phase == "after" and op == self.plan[0]:
                self.fired = True
                if when == "after":
                    self.plan = None
                e = _CURRENT.fake.journal[-1]
                _CURRENT.fake.nics[e["nic"]]["nsg"] = e["before"]      # not through the API
            return
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


_CURRENT = SimpleNamespace(chaos=None, fake=None, mode="human_only", scheduler=None, clock=0)


class _Abandoned(BaseException):
    """The race failed (I11): a thread waiting for its turn unwinds — not an Exception,
    so no `except Exception` of the code under test swallows it — and its locks go with
    it. It used to wait there forever, holding them, and the teardown behind it: the job
    hung instead of failing (I3F's review, U3F)."""


# Turns in a row where every thread only tried a driven lock and found it taken: a
# deadlock between driven locks (op-1 holds A and wants B, op-2 holds B and wants A) —
# each thread gives its turn away at every try, and no turn ever times out (U3F review).
# A real race's longest such run is 10 to 16 turns depending on the seed (measured at 500
# sequences, docs/design/preuves.md); the limit is far above it, reached in under a second.
_IDLE_TURNS = 2000
_RACES_RUN = [0]                   # numbers each race's threads: a name is never reused
_LONGEST_IDLE = [0]                # the longest run of idle turns seen (STATS)


class _Scheduler:
    """Glorfindel operations at once, one Azure call (or state write) at a time, in an
    order drawn from a seed (L27). A thread waits for its turn before each call; a lock
    that is taken costs it a turn (see _scheduled) — the real locks decide.
    `timeout`: the seconds a turn may take (real time) before the race is called stuck;
    `idle_turns`: the turns in a row spent only on taken locks before it is called a
    livelock."""

    def __init__(self, seed: int, timeout: float = 20, idle_turns: int = _IDLE_TURNS):
        import random
        self.cv = threading.Condition()
        self.rng = random.Random(seed)
        self.state: dict[str, str] = {}
        self.turn = None
        self.timeout = timeout
        self.idle_turns = idle_turns
        self.abandoned = False
        self.retried: dict[str, bool] = {}
        self.hung: list[str] = []        # threads still running once abandoned

    def _me(self):
        name = threading.current_thread().name
        return name if name in self.state else None

    def point(self, retry: bool = False):
        """Wait for a turn. `retry`: the turn that ends here was spent only on a driven
        lock found taken (no progress)."""
        with self.cv:
            me = self._me()
            if me is None:
                return
            if self.turn == me:
                self.turn = None
            if self.abandoned:
                raise _Abandoned(me)
            self.retried[me] = retry
            self.state[me] = "wait"
            self.cv.notify_all()
            self.cv.wait_for(lambda: self.turn == me or self.abandoned)
            if self.abandoned:
                raise _Abandoned(me)
            self.state[me] = "run"

    def _seen(self) -> dict:
        """The state by the operations' own names (op-1, op-2), for the messages."""
        return {self.short.get(n, n): s for n, s in self.state.items()}

    def run(self, ops: list) -> dict:
        results: dict = {}
        # Each thread's name is unique to this race (op-1#7): a thread of an earlier race
        # that never unwound, woken later, is never taken for one of this race's (_me).
        _RACES_RUN[0] += 1
        self.short = {f"{name}#{_RACES_RUN[0]}": name for name, _ in ops}
        ops = [(f"{name}#{_RACES_RUN[0]}", name, fn) for name, fn in ops]

        def body(uid, name, fn):
            try:
                self.point()
                results[name] = (fn(), None)
            except BaseException as exc:            # a Crash ends this thread only
                results[name] = (None, exc)
            finally:
                with self.cv:
                    self.state[uid] = "done"
                    if self.turn == uid:
                        self.turn = None
                    self.cv.notify_all()

        with self.cv:
            self.state.update({uid: "start" for uid, _, _ in ops})
        threads = [threading.Thread(target=body, args=op, name=op[0], daemon=True) for op in ops]
        for th in threads:
            th.start()
        settled = ("wait", "blocked", "done")
        stuck = None
        idle = 0
        with self.cv:
            while True:
                ok = self.cv.wait_for(
                    lambda: all(s in settled for s in self.state.values())
                    and (any(s == "wait" for s in self.state.values())
                         or all(s == "done" for s in self.state.values())), timeout=self.timeout)
                if not ok:
                    stuck = f"I11: operations stuck (deadlock?): {self._seen()}"
                    break
                ready = sorted(n for n, s in self.state.items() if s == "wait")
                if not ready:
                    break
                pick = ready[self.rng.randrange(len(ready))]
                self.turn, self.state[pick] = pick, "go"
                self.cv.notify_all()
                if not self.cv.wait_for(lambda: self.state[pick] in settled, timeout=self.timeout):
                    stuck = f"I11: {self.short[pick]} never came back: {self._seen()}"
                    break
                if self.state[pick] == "wait" and self.retried.get(pick):
                    idle += 1
                    _LONGEST_IDLE[0] = max(_LONGEST_IDLE[0], idle)
                    if idle > self.idle_turns:
                        stuck = (f"I11: livelock (deadlock between driven locks?): {idle} turns "
                                 f"in a row only found taken locks: {self._seen()}")
                        break
                else:
                    idle = 0
            if stuck:
                # Every thread waiting for a turn unwinds, its locks released, before the
                # failure is raised: the teardown takes them next (_Abandoned).
                self.abandoned = True
                self.cv.notify_all()
        for th in threads:
            th.join(timeout=min(5, self.timeout))
        # A thread blocked out of the scheduler's sight doesn't unwind: whatever it holds
        # stays held, and whoever runs next must not wait behind it (the teardown, _race).
        self.hung = [self.short[th.name] for th in threads if th.is_alive()]
        if self.hung:
            # It holds the real locks it took — objects of the process-wide registries, never
            # reset between examples: Hypothesis replays one while shrinking, and its first
            # write on that VM waited forever. Those that come next get registries of their
            # own (the flock is no matter: a new example has a new home, new lock files).
            _fresh_lock_registries()
        assert stuck is None, stuck + (f" — still running, never unwound: {self.hung}" if self.hung else "")
        return results


def _fresh_lock_registries() -> None:
    """New registries of in-process locks: nothing shared with a thread that never unwound."""
    locks._VM_LOCKS, locks._QUARANTINE_LOCKS, locks._FILE_LOCKS = {}, {}, {}


def _scheduled(real):
    """A lock the scheduler drives: a thread never blocks in it. It tries the real lock
    without waiting; taken, it gives its turn away and tries again at its next turn —
    so the interleaving depends on the drawn seed only, never on when the OS wakes a
    waiting thread. A caller's timeout is honoured as a number of turns."""
    @contextlib.contextmanager
    def lock(*args, **kwargs):
        sched = _CURRENT.scheduler
        if sched is None or threading.current_thread().name not in sched.state:
            with real(*args, **kwargs):
                yield
            return
        tries = 0
        while True:
            cm = real(*args, **{**kwargs, "timeout": 0})
            try:
                cm.__enter__()
                break
            except TimeoutError:
                tries += 1
                if kwargs.get("timeout") is not None and tries > 40:
                    raise
                sched.point(retry=True)
        try:
            sched.point()
            yield
        finally:
            cm.__exit__(None, None, None)
    return lock
_SEEN: collections.Counter = collections.Counter()


def _note(what: str) -> None:
    try:
        event(what)
    except InvalidArgument:            # replayed outside Hypothesis (the regressions)
        pass
    _SEEN[what] += 1


class _Drawn:
    """A rule's draws, some of them set: by label, a value, or a narrower strategy —
    the rest drawn as the rule would (a composite rule reuses the others, I1F)."""

    def __init__(self, data, **fixed):
        self.data, self.fixed = data, fixed

    def draw(self, strategy, label=None):
        if label in self.fixed:
            v = self.fixed[label]
            return self.data.draw(v, label=label) if isinstance(v, st.SearchStrategy) else v
        return self.data.draw(strategy, label=label)


class _Given:
    """A rule's draws given in order: a composite rule calls another on its own VM (I8F)."""

    def __init__(self, *values):
        self.values = list(values)

    def draw(self, strategy, label=None):
        return self.values.pop(0)


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
        _CURRENT.clock = 0                              # minutes the test clock is ahead
        self.releasing: set[str] = set()                # the test's own journal (I9)
        self.unblocking: set[str] = set()
        self.journal_seen = 0                           # I2 by author: entries checked
        self.journal_at = 0                             # I4: where the operation began (_before)
        # Untraceability from the test's own journal (A0): when Glorfindel recorded a NIC's
        # original (moved it from a real NSG into quarantine), and when the test destroyed
        # the records — never from the records as the code left them, or a bug that
        # deletes them earns the exemption (M24–M26, M29 went unseen).
        self.ticks = 0
        self.recorded_at: dict[str, tuple[int, str]] = {}   # NIC → (tick, quarantine NSG)
        self.state_lost_at: dict[str, int] = {}             # VM → tick
        self.tags_lost_at: dict[str, int] = {}              # quarantine NSG → tick
        self.retagged_at: dict[str, int] = {}               # NIC → tick Glorfindel wrote its original as a tag
        self.state_had: dict[str, int] = {}                 # NIC → record a state once held
        self.quarantine_held: dict[str, int] = {}           # NIC → last tick a state held it in quarantine, bare
        self.unknown_held: dict[str, int] = {}              # ... and recorded no original for it (I3F)
        self.before_quarantine: dict[str, str | None] = {}   # NIC → what it carried
        # (NSG, rule) someone turned into an allow → (the rule before, the rule after);
        # before = None for an allow they added under one of our names.
        self.tampered: dict[tuple[str, str], tuple[dict | None, dict]] = {}
        # Quarantine NSGs the TEST altered (stripped, a rule tampered with): only these
        # earn I1's exemption while they no longer deny everything — one Glorfindel
        # wrote wrong earns none (I1F, as the AWS machine's `altered`).
        self.altered: set[str] = set()
        # I1S: the altered NSGs L2 last held on (said by Glorfindel), and those the test
        # then took out of the listing — its role removed, our tag taken off — and how.
        self.l2_held_on: set[str] = set()
        self.out_of_sight: dict[str, str] = {}
        self.fake = _CURRENT.fake = FakeAzure(self.chaos)
        self.deleted: dict[str, list[str]] = {}         # VM id → its NIC ids, once deleted
        self.detached: set[str] = set()                 # NICs someone left without any NSG

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
        split = net.get("data_subnet") is not None
        data = f.add_subnet("rg-net", "vnet-hub", "data", f.add_nsg("rg-net", "nsg-data", net["data_subnet"])) \
            if split else None
        self.vms = []
        for rg, name, loc, nics in _VMS:
            specs = []
            for nic_rg, nic, ips in nics:
                n = net["nics"][nic]
                own = {None: None, "tier": tier}.get(n["own"]) if n["own"] != "dedicated" \
                    else f.add_nsg(nic_rg, f"nsg-{nic}", n["rules"], location=loc)
                subnet = data if split and nic == "db-nic-1" else subnets[loc]
                specs.append({"rg": nic_rg, "name": nic, "ips": ips, "subnet": subnet,
                              "nsg": own, "policy": n["policy"], "location": loc})
            self.vms.append(f.add_vm(rg, name, specs, os_type="Windows" if name == net["windows"] else "Linux"))
        self.design = f.snapshot()
        self.legacy: dict[tuple[str, str], str] = {}   # (NSG, rule) of an old version → its VM
        if net.get("legacy") and net["nics"][net["legacy"][0]]["own"] == "dedicated":
            self._legacy_isolation(*net["legacy"])
        self.config = dict(net["config"])
        self._write_config()
        c = AzureConnector(dry_run=False)
        c._network, c._compute = f.network, f.compute
        c._subscription_id = "s"                 # the subscription the clients act in
        c.recent_changes = lambda *a, **k: []
        self.connector = c

    def _legacy_isolation(self, nic_name: str, keep_state: bool):
        """What an older version left: the fixed names, a deny any/any on what was then
        the VM's own NSG, and its single-NSG state. Not in the design (Glorfindel's)."""
        f = self.fake
        vm = next(v for v in self.vms if any(n.rsplit("/", 1)[-1] == nic_name for n in f.vms[key(v)]["nics"]))
        nic = self._nics(vm)[0]
        nsg = f.nsgs[key(nic["nsg"])]
        taken = {r["priority"] for r in nsg["rules"].values()}
        prio = next(p for p in range(100, 4096) if p not in taken)
        name = AzureConnector.ISOLATION_RULE_NAME
        for n, direction in ((name, "Inbound"), (f"{name}-out", "Outbound")):
            FakeAzure._put_rule(nsg, _rule_record(_rule(n, prio, dict(
                access="Deny", direction=direction, source_address_prefix="*",
                destination_address_prefix="*", destination_port_range="*"))))
            self.legacy[(key(nsg["id"]), n.lower())] = vm
            f.authored.add((key(nsg["id"]), n.lower()))
        if keep_state:
            import json
            d = actions._ISOLATION_STATE_DIR
            d.mkdir(parents=True, exist_ok=True)
            (d / f"{vm.rsplit('/', 1)[-1]}.json").write_text(json.dumps({
                "resource_id": vm, "nsg_rg": nsg["id"].split("/")[4], "nsg_name": nsg["id"].rsplit("/", 1)[-1],
                "rule_names": [name, f"{name}-out"], "bumped": [], "isolated_at": "2026-05-01T00:00:00+00:00"}))
        _note(f"legacy isolation of {vm.rsplit('/', 1)[-1]}" + ("" if keep_state else ", state lost"))

    def _not_its_legacy(self, vm: str, nsg_key: str, rule_name: str) -> bool:
        """A rule an older version left for ANOTHER VM."""
        return self.legacy.get((nsg_key, rule_name.lower()), vm) != vm

    def teardown(self):
        try:
            if getattr(self, "hung", None):
                # A race failed with a thread blocked out of the scheduler's sight, its
                # locks held: the recovery would wait behind them forever. I11 has failed
                # already; that failure is the one to see (U3F review).
                return
            if getattr(self, "connector", None) is not None:
                # I7, with the local state as it is, then without it.
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

    def _world(self, untampered: bool = False) -> dict:
        """untampered: without each rule someone turned into an allow, as long as it is
        still as they left it (Glorfindel may have repaired or removed it). Not read as
        the deny it was: an older version's name turned into an allow can't be told to
        be Glorfindel's (homonyms share it), and a release rightly leaves it."""
        f = self.fake
        nsgs = f.nsgs
        if untampered and self.tampered:
            nsgs = {k: dict(g, rules=dict(g["rules"])) for k, g in nsgs.items()}
            for (k, n), (before, after) in self.tampered.items():
                rules = nsgs.get(k, {}).get("rules", {})
                if rules.get(n) == after:
                    del rules[n]
        return {"nsgs": nsgs, "nics": f.nics, "subnets": f.subnets, "vms": f.vms}

    def _open(self, vm: str, own: bool = False, forensic: str | None = "ever",
              untampered: bool = False) -> frozenset:
        """The VM's open flows, less the investigation access the operator configured
        (isolation.forensic_sources: TCP 22 and 3389 from those sources) on a NIC in
        quarantine — open there on purpose, whatever the NIC's own NSG says. Only valid
        sources (_valid_sources), and only those configured: "ever" (I1 — an allow the
        config no longer wants is the operator's own until it is purged), "now" (what an
        isolation may claim), None (a block: the attacker gets no exemption).

        own=True: as if the rules named for OTHER NICs weren't there. A VM given the old
        IP of another, whose isolation was left behind (state lost, not yet released),
        is cut off by that rule — the other VM's leftover, not this VM's claim.

        untampered: see _world."""
        world = self._world(untampered)
        if own:
            others = self._other_marks(vm)
            world = {**world, "nsgs": {k: {**g, "rules": {
                n: r for n, r in g["rules"].items()
                if not (self._owned_by(n, others) and self._scoped(r)) and not self._not_its_legacy(vm, k, n)}}
                for k, g in world["nsgs"].items()}}
        import ipaddress
        quarantined = {n["id"].rsplit("/", 1)[-1] for n in self._nics(vm)
                       if n["nsg"] and actions._is_quarantine_nsg(n["nsg"])}
        nets = {"ever": getattr(self, "forensic_ever", []), "now": getattr(self, "forensic_now", [])}.get(forensic, [])

        def investigation(f) -> bool:
            return (f[0] in quarantined and f[2] == "in" and f[4] in (22, 3389)
                    and any(ipaddress.ip_address(f[3]) in n for n in nets))
        return frozenset(f for f in open_flows(world, vm) if not investigation(f))

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
        return all(key(n["nsg"]) == key(n["design_nsg"]) or self._untraceable(vm, n) for n in self._nics(vm))

    def _untraceable(self, vm: str, nic: dict) -> bool:
        """A NIC someone left bare, whose original nothing records any more — the TEST
        lost the tags of the quarantine NSG after Glorfindel recorded it, and the VM's state
        too (or a fault it injected cut the operation off before the state was written):
        Glorfindel can't even tell it was in quarantine. Its release may say
        `released`; the operator puts the NSG back (_recover_everything). Judged from the
        test's journal, not from the records as the code left them (see __init__)."""
        if key(nic["id"]) not in self.detached or nic["nsg"] is not None:
            return False
        return self._record_lost(vm, nic)

    def _record_lost(self, vm: str, nic: dict) -> bool:
        """What _untraceable reads, the NIC bare or not: Glorfindel recorded the NIC's own
        NSG when it moved it into quarantine, and the TEST lost every record of it since
        (the quarantine's tags, and the VM's state or the state never had it) — by the
        test's journal, never by the records as the code left them."""
        self._check_authors()
        rec = self.recorded_at.get(key(nic["id"]))
        if rec is None:
            return False
        at, quarantine = rec
        if self.tags_lost_at.get(quarantine, -1) <= at:
            return False                      # the test didn't lose the tag: it traces it
        if self.retagged_at.get(key(nic["id"]), -1) > self.tags_lost_at.get(quarantine, -1):
            return False                      # Glorfindel wrote it again since: it traces it
        if self.state_lost_at.get(key(vm), -1) > at:
            return True
        if self.state_had.get(key(nic["id"])) == at:
            return False                      # a state held it: Glorfindel dropped it, a bug
        # The state never had it either: the operation that swapped the NIC was cut off (a
        # fault the test injected) before writing it. A record of "none" says nothing.
        st = self._state(vm) or {}
        return not any(key(p.get("nic_id")) == key(nic["id"]) and p.get("original_nsg_id")
                       for p in st.get("placements") or [])

    def _back_to_design(self, vm: str, own: bool = False) -> bool:
        """Every flow as designed — the attacker's excepted while a block of it stands
        (a block legitimately closes them, and outlives a release). Read without what
        someone turned into an allow (_world): theirs, not Glorfindel's to have undone.
        One of ours left behind is still seen by its name (_named_leftovers)."""
        live, design = self._open(vm, own, untampered=True), self._designed(vm)
        bare = {n["id"].rsplit("/", 1)[-1] for n in self._nics(vm) if self._untraceable(vm, n)}
        if bare:                                   # nothing records what they carried
            live = frozenset(f for f in live if f[0] not in bare)
            design = frozenset(f for f in design if f[0] not in bare)
        if actions._load_block_entries(vm) or self._block_rules_for(vm):
            return ({f for f in live if f[3] != ATTACKER} == {f for f in design if f[3] != ATTACKER}
                    and live <= design)
        return live == design

    def _named_leftovers(self, nic_ids: list[str], prefix: str = "glorfindel-iso",
                         skip: frozenset = frozenset()) -> list[str]:
        """Rules of `prefix` named for one of these NICs, on any NSG — applying to their
        addresses or not (a changed IP, a deleted VM). `skip`: (NSG key, NIC mark) pairs
        not counted."""
        marks = {_nic_hash(n) for n in nic_ids}
        return [f'{n["id"].rsplit("/", 1)[-1]}/{r["name"]}' for k, n in self.fake.nsgs.items()
                for r in n["rules"].values()
                if r["name"].lower().startswith(prefix) and any(
                    m in r["name"].lower() and (k, m) not in skip for m in marks)]

    def _nic_of_tag(self, tag: str) -> str | None:
        """The NIC (key) a `glorfindel-orig-<hash>` tag names — live or deleted."""
        import hashlib
        nics = list(self.fake.nics) + [key(n) for nics in self.deleted.values() for n in nics]
        return next((n for n in nics if "glorfindel-orig-" + hashlib.sha1(
            n.rstrip("/").lower().encode()).hexdigest()[:12] == tag), None)

    def _untied(self, vm: str) -> frozenset:
        """NICs of the VM left bare whose own NSG nothing ties to them any more, by the
        test's journal (A0): untraceable, and the test lost the VM's state after the last
        time it saw a state hold the NIC in quarantine while it was bare — that state
        knew someone took our NSG off; lost by the code itself, it earns nothing (I8F)."""
        self._check_authors()
        lost = self.state_lost_at.get(key(vm), -1)
        return frozenset(key(n["id"]) for n in self._nics(vm)
                         if lost > self.quarantine_held.get(key(n["id"]), -1) and self._untraceable(vm, n))

    def _held_unknown(self, vm: str) -> list[str]:
        """NICs of the VM left bare, off their design, that the test saw a state hold in
        quarantine with no original since it last lost that state: Glorfindel knows it
        doesn't know what they carried — "released" there is a guess, whatever the test
        lost before (_untraceable exempts them: it can't tell the state was written after
        the loss). Only ever stricter: a code that drops a known original earns nothing,
        one that writes a wrong one is judged as before (I3F, #287)."""
        self._check_authors()
        lost = self.state_lost_at.get(key(vm), -1)
        return [n["id"].rsplit("/", 1)[-1] for n in self._nics(vm)
                if n["nsg"] is None and n["design_nsg"] and key(n["design_nsg"]) in self.fake.nsgs
                and key(n["id"]) in self.unknown_held and self.unknown_held[key(n["id"])] >= lost]

    def _released(self, vm: str, own: bool = False) -> bool:
        # Glorfindel's own rules named for an untied NIC, on its own NSG off it, are out of
        # the release's reach — as I8 judges them (_isolation_recorded).
        untied = self._untied(vm)
        skip = frozenset((key(n["design_nsg"]), _nic_hash(n["id"])) for n in self._nics(vm)
                         if key(n["id"]) in untied and n["design_nsg"])
        left = self._named_leftovers(self.fake.vms[key(vm)]["nics"], skip=skip)
        return (self._back_to_design(vm, own) and self._nics_as_designed(vm) and self._state(vm) is None
                and not left and not self._held_unknown(vm))

    def _footprint(self, vm: str, untied: frozenset = frozenset()) -> set:
        """What of Glorfindel's isolation applies to the VM: a NIC in quarantine, a
        glorfindel-iso deny that covers one of a NIC's addresses. `untied`: NICs whose own
        NSG is off them and tied to them by nothing any more — its rules don't count."""
        fp = set()
        others = self._other_marks(vm)
        for nic in self._nics(vm):
            if nic["nsg"] and actions._is_quarantine_nsg(nic["nsg"]):
                fp.add(("quarantine", key(nic["id"])))
            sub = self.fake.subnets[key(nic["subnet"])]["nsg"]
            design = None if key(nic["id"]) in untied else nic["design_nsg"]
            for g in {key(nic["nsg"]), key(design), key(sub)} - {""}:
                for r in self.fake.nsgs.get(g, {}).get("rules", {}).values():
                    if (not r["name"].lower().startswith("glorfindel-iso") or r["access"].lower() != "deny"
                            or self._owned_by(r["name"].lower(), others) or self._not_its_legacy(vm, g, r["name"])):
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
        return frozenset(f for f in self._open(vm, forensic="now")
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

    def _attacker_never_cut(self, vm: str, before: frozenset, after: frozenset, what: str,
                            reopenable: frozenset = frozenset()):
        """Lifting a perimeter opens the attacker's flows of the VMs behind it; it never
        cuts one off (I4B) — but a VM in quarantine, re-sealed as in _only_sealed. And it
        opens them only where a perimeter was lifted: a perimeter rule of ours (the IP's
        name alone) taken off an NSG that governs one of the VM's NICs — the test's
        journal of API writes; elsewhere only what another NIC's leftover rule closed
        (`reopenable`, as in _only_sealed)."""
        lost = {f for f in before if f[3] == ATTACKER} - after
        assert not lost or self._in_quarantine(vm), f"{what} cut off {vm} ({sorted(lost)[:3]})"
        if self._perimeter_lifted_for(vm):
            return
        opened = {f for f in after if f[3] == ATTACKER} - before - reopenable
        assert not opened, f"{what} opened flows of {vm} ({sorted(opened)[:3]})"

    def _perimeter_lifted_for(self, vm: str) -> bool:
        """Since the operation began (_before): a rule under the attacker's perimeter name
        (`glorfindel-block-<ip>`, `-out`) deleted from an NSG that governs a NIC of `vm`."""
        plain = "glorfindel-block-" + ATTACKER.replace(".", "-")
        chain = {key(g) for n in self._nics(vm) for g in (n["nsg"], self.fake.subnets[key(n["subnet"])]["nsg"]) if g}
        return any(e["op"] == "rule.delete" and e["nsg"] in chain and e["rule"] in (plain, f"{plain}-out")
                   for e in self.fake.journal[self.journal_at:])

    def _only_sealed(self, vm: str, before: frozenset, after: frozenset, what: str,
                     reopenable: frozenset = frozenset()):
        """Nothing opened — but what only another NIC's leftover rule closed (an IP that
        moved from one VM to another): re-isolating that NIC rewrites its rule for its
        own new address and gives the flows back."""
        assert after - before <= reopenable, f"{what} opened flows of {vm}"
        assert after <= before | reopenable and (before <= after or self._in_quarantine(vm)), (
            f"{what} cut off {vm}")

    def _others_unchanged(self, vm: str, flows_before: dict, states_before: dict, perimeter: bool | str = False):
        """I4. `perimeter`: True for a perimeter block (it closes the attacker's flows on
        its subnet, by design); "lift" for an unblock or a reset, which may lift one — the
        attacker's flows of another VM may open then, never be cut (I4B: they were taken
        out of the comparison, and a turned allow the unblock took off, the VM given the
        old address lost the flows it gave it, unseen)."""
        flows = self._flows()
        for other in self.live:
            if other == vm:
                continue
            before, after = flows_before[other], flows[other]
            if perimeter:
                # A perimeter block closes the attacker's flows on its subnet, by design.
                before = frozenset(f for f in before if f[3] != ATTACKER)
                after = frozenset(f for f in after if f[3] != ATTACKER)
                if perimeter == "lift":
                    self._attacker_never_cut(other, flows_before[other], flows[other], f"I4: an operation on {vm}",
                                             flows_before[("own", other)] - flows_before[other])
            self._only_sealed(other, before, after, f"I4: an operation on {vm}",
                              flows_before[("own", other)] - before)
            assert self._state(other) == states_before[other], (
                f"I4: an operation on {vm} changed the state of {other}")
        self._old_isolations_kept({vm}, f"I4: an operation on {vm}")

    def _old_isolations_kept(self, acting: set, what: str):
        """I4, by the test's journal (A0): an older version's isolation is its VM's, and
        an operation on another VM never deletes it — even with that VM's NIC away in
        quarantine, where no flow tells (I4S, #239). A VM that no longer exists has none
        to keep; nor, for Glorfindel to know, a VM whose NIC is away from that NSG with
        every record of where it belongs lost by the TEST (_record_lost): nothing on Azure
        or in a state ties the NIC to it any more. The deletes since _before, from the
        fake's journal; the owner, from the test's own record of what the older version
        left (`legacy`)."""
        mine = {key(v) for v in acting}
        for e in self.fake.journal[self.journal_at:]:
            owner = self.legacy.get((e.get("nsg"), e.get("rule"))) if e["op"] == "rule.delete" else None
            if owner and owner not in self.deleted and any(
                    key(n["design_nsg"]) == e["nsg"] and key(n["nsg"]) != e["nsg"] and self._record_lost(owner, n)
                    for n in self._nics(owner)):
                continue
            assert not owner or owner in self.deleted or key(owner) in mine, (
                f"{what} deleted {e['rule']} of {owner.rsplit('/', 1)[-1]}, an older version's isolation, "
                f"from {e['nsg'].rsplit('/', 1)[-1]}")

    def _before(self):
        self.journal_at = len(self.fake.journal)
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

    def _isolation_recorded(self, vm: str, what: str, released: bool = False):
        """I8: an isolation or release that returned has recorded what it left on Azure.
        After a release: a NIC left bare whose original nothing records (_untraceable)
        doesn't carry the rules of its own NSG, off it — as for I3 (_back_to_design) and
        the blocks (_block_rules_for) — only if the TEST lost the VM's state after the
        last time it saw a state hold that NIC in quarantine while the NIC was bare (its
        journal, A0): such a state knew someone took our NSG off. One that still held it
        when the release began, or that the code dropped itself, earns nothing —
        Glorfindel knew, and must say what it can't undo (I8F). A NIC isolated bare
        after the loss, nothing recording it was ever ours, earns it."""
        if self._footprint(vm, self._untied(vm) if released else frozenset()):
            assert self._state(vm) is not None, f"I8: {what} left an isolation of {vm} on Azure without state"

    def _block_recorded(self, vm: str, what: str):
        if [r for r in self._block_rules_for(vm, own=True) if not self._perimeter_rule(r)]:
            assert actions._load_block_entries(vm), f"I8: {what} left a block on {vm} without state"

    # ── operations ──────────────────────────────────────────────────────────────

    @rule(data=st.data())
    def isolate(self, data):
        vm, rid, fault = self._draw(data)
        self._isolate(vm, rid, fault)

    def _isolate(self, vm, rid, fault):
        (flows, states), nics = self._before(), self._quarantined_nics()
        azure_before = self.fake.snapshot() if not self.config["readable"] else None
        writes = len(self.fake.journal)
        out, err = self._run(fault, lambda: self.connector.isolate_vm(rid), "isolate")
        if (out or {}).get("status") == "isolated" or len(self.fake.journal) > writes:
            # A new isolation, the operator's call — even cut off midway, once it has
            # written to Azure: the release it supersedes is no longer under way (I9).
            self.releasing.discard(vm)
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
        self._check_authors()                      # which states held which NICs (I8F)
        flows, states = self._before()
        states_before_release = self._state(vm)
        self.releasing.add(vm)
        writes = len(self.fake.journal)
        out, err = self._run(fault, lambda: self.connector.release_isolation(rid), "release")
        if (out or {}).get("status") == "released" or (err is not None and len(self.fake.journal) == writes):
            # Released — or failed before writing anything to Azure (its intent marker
            # refused by a full disk): nothing was started, nothing to undo (I9).
            self.releasing.discard(vm)
        if vm in self.deleted:
            recorded = self._recorded_rules(states_before_release)
            if out and out.get("status") == "released":
                left = [r for r in self._named_leftovers(self.deleted[vm]) if r.split("/")[-1] in recorded]
                assert not left, f"I3: release of the deleted {vm} said released, rules left: {left}"
        else:
            if out and out.get("status") == "released":
                assert self._released(vm, own=True), f"I3: release said released, {vm} is not back to its design"
            if err is None:
                self._isolation_recorded(vm, "release_isolation", released=True)
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
    def another_host_writes(self, data):
        """A rare state made common: another host (a pipeline, a second watch — our lock
        is per host) writes the NIC right after Glorfindel did, before it reads it back,
        and puts back what it carried: during an isolation, or during the release that
        follows one (A0, M14). Only here: elsewhere the oracles would take its write for
        Glorfindel's (I9: a quarantine back mid-release)."""
        vm, rid, _ = self._draw(data)
        foreign = ("nic.write", data.draw(st.sampled_from(["after-foreign", "always-foreign"]), label="how often"))
        if data.draw(st.booleans(), label="during the release"):
            self._isolate(vm, rid, None)
            self._release(vm, rid, foreign)
        else:
            self._isolate(vm, rid, foreign)

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
        return frozenset(f for f in self._open(vm, forensic=None)
                         if f[3] == ATTACKER and (f[2] == "out" or port is None or f[4] == port))

    def _block_rules_for(self, vm: str, own: bool = False) -> list[str]:
        """Glorfindel block rules for the attacker that apply to one of this VM's NICs.
        own=True: not those named for another NIC — a deleted VM's, aimed at an address
        this VM got since (they are orphans: see orphans_are_reported)."""
        others = self._other_marks(vm) if own else set()
        found = []
        for nic in self._nics(vm):
            # The NIC's own NSG counts even off the NIC (hidden by the quarantine) — not
            # for a NIC left bare that nothing ties to it any more (_untraceable).
            design = None if own and self._untraceable(vm, nic) else nic["design_nsg"]
            for g in {nic["nsg"], design, self.fake.subnets[key(nic["subnet"])]["nsg"]} - {None}:
                for r in self.fake.nsgs.get(key(g), {}).get("rules", {}).values():
                    if not r["name"].startswith("glorfindel-block-"):
                        continue
                    sides = [r.get("source_address_prefix"), r.get("destination_address_prefix"),
                             *(r.get("source_address_prefixes") or []), *(r.get("destination_address_prefixes") or [])]
                    if (ATTACKER in sides and any(v in ("*", *nic["ips"]) for v in sides)
                            and not self._owned_by(r["name"].lower(), others)):
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
        clean, start = self._chain_start()
        out, err = self._run(fault, lambda: self.connector.block_suspicious_ip(
            ATTACKER, rid, scope="vm", threat_port=port), "block")
        self._chain_end(clean, start, fault is None and err is None)
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
        clean, start = self._chain_start()
        out, err = self._run(fault, lambda: self.connector.block_suspicious_ip(
            ATTACKER, rid, scope="subnet", replace=replace), "block_perimeter" + (" (promote)" if replace else ""))
        self._chain_end(clean, start, fault is None and err is None)
        if out and out.get("status") in ("blocked", "blocked_partial") and not out.get("bypass"):
            # The VM blocked: every one of its NICs is cut off — behind the perimeter, or, on
            # another subnet (RB1's second subnet), by its own block — but those it names as
            # uncovered, which must be off the perimeter's subnet (the test's own knowledge).
            # Restricted to the perimeter's subnet, this hid a promotion that took the block
            # off the other NIC, `blocked` said (RB1, review).
            home = key(self._nics(vm)[0]["subnet"])
            off = {n["id"].rsplit("/", 1)[-1] for n in self._nics(vm) if key(n["subnet"]) != home}
            said = set(out.get("uncovered_nics") or []) | (off if out.get("nics_unread") else set())
            assert said <= off, f"I3: perimeter block named {sorted(said - off)} of {vm} uncovered, behind it"
            assert out["status"] == "blocked_partial" or not said, f"I3: perimeter block said blocked, {sorted(said)} open"
            entry = next((e for e in actions._load_block_entries(vm) if e.get("ip") == ATTACKER), {})
            reached = ({f[0] for f in self._attacker_flows(vm, None) if f[0] not in off}
                       | {f[0] for f in self._attacker_flows(vm, entry.get("threat_port")) if f[0] in off}) - said
            assert not reached, f"I3: perimeter block said blocked, {ATTACKER} reaches {vm} ({sorted(reached)})"
            # Its subnet's other VMs: their NICs behind it.
            for mate in self._subnet_mates(vm):
                if mate == vm:
                    continue
                behind = {n["id"].rsplit("/", 1)[-1] for n in self._nics(mate) if key(n["subnet"]) == home}
                assert not {f for f in self._attacker_flows(mate, None) if f[0] in behind}, (
                    f"I3: perimeter block said blocked, {ATTACKER} reaches {mate}")
        self._others_unchanged(vm, flows, states, perimeter=True)

    @rule(data=st.data())
    def unblock(self, data):
        vm, rid, fault = self._draw(data)
        flows, states = self._before()
        self.unblocking.add(vm)
        out, _ = self._run(fault, lambda: self.connector.unblock_ip(ATTACKER, rid), "unblock")
        if (out or {}).get("status") in ("unblocked", "not_found"):
            self.unblocking.discard(vm)
        if out and out.get("status") in ("unblocked", "not_found"):
            left = [r for r in self._block_rules_for(vm, own=True) if not self._perimeter_rule(r)]
            assert not left, f"I3: unblock said {out['status']}, rules left for {vm}: {left}"
        self._others_unchanged(vm, flows, states, perimeter="lift")

    def _block_vanished(self, vm: str) -> bool:
        """The VM's block of the attacker is recorded, no operation holds it (the test's
        journal, and the entry's own partial/failure marks), and none of its rules is on
        Azure any more."""
        entry = next((e for e in actions._load_block_entries(vm) if e.get("ip") == ATTACKER), None)
        if (entry is None or vm in self.unblocking
                or any(entry.get(k) for k in ("partial", "unblock_failed", "unblocking_at"))):
            return False
        from .fake_azure import nsg_id

        def gone(where) -> bool:
            for rg, name, rule_name in where:
                g = self.fake.nsgs.get(key(nsg_id(rg, name)))
                if g and ({rule_name.lower(), f"{rule_name.lower()}-out"} & set(g["rules"])):
                    return False
            return bool(where)
        where = [(p["nsg_rg"], p["nsg_name"], p["rule"]) for p in entry.get("placements") or [] if p.get("rule")]
        pair = [(*entry["nsg"].split("/", 1), entry["rule"])] if (
            entry.get("nsg") and entry.get("rule") and "/" in entry["nsg"]) else []
        if not where:
            return gone(pair)
        # Merged with a perimeter block (RB1): the VM's rules all gone, OR its perimeter pair
        # gone — each a disappearance; never both required (fifth review: L1 weakened).
        return gone(where) or (entry.get("scoped") is False and gone(pair))

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
        # I9 from the test's own journal: a release it started and didn't see finish —
        # not from the marker the code writes (the property would trust what it judges).
        releasing = [vm for vm in self.live if vm in self.releasing]
        footprints = {vm: self._footprint(vm) for vm in releasing}
        nics_before = {k: n["nsg"] for k, n in self.fake.nics.items()}
        # A perimeter block put back closes the attacker's flows of every VM on its
        # subnet, those without state included — by design.
        perimeter = any(e.get("scoped") is False for vm in self.vms for e in actions._load_block_entries(vm))
        vanished = [vm for vm in self.live if self._block_vanished(vm)]
        cards_before = {e["id"] for e in escalations.pending()}
        journal_at = len(self.fake.journal)
        quiet = self._chain_start()[0] if getattr(self, "chain", None) else None
        named = {vm: self._named_block_rules(vm) for vm in self.live} if quiet else {}
        self.chain = None                       # the pass writes: the chain ends here
        report, err = self._run(fault, lambda: reassert.reassert_pass(self.connector, None))
        for r in report or []:
            _note(f"reassert ({_CURRENT.mode}): {r['outcome']}")
        if fault is None and err is None:
            self._block_cards_true(cards_before, journal_at)
            self._no_drift_on_untouched(cards_before, quiet, named)
            # Liveness: a block whose rules all vanished from Azure is put back, or told
            # about — not left gone in silence.
            told = {key(e.get("resource_id", "")) for e in escalations.pending()
                    if e.get("action") == "block_suspicious_ip"}
            # A drift card the operator acknowledged (`operator_acknowledges`) stays said
            # for its episode — one card per disappearance, by design — only while the
            # entry's rules on Azure, its perimeter pair included, are exactly as they were
            # at the acknowledgement: anything worse since must be said again (RB1, 4th
            # review — "no rewrite by Glorfindel" let a perimeter deleted after it pass).
            acked = getattr(self, "acked_drift", {})
            told |= {key(v) for v, seen in acked.items() if self._block_rules_now(v) == seen}
            for vm in vanished:
                assert not self._block_vanished(vm) or key(vm) in told, (
                    f"L1: the block on {vm} vanished from Azure; the reassertion neither put it back nor said so")
            # L2 (I1F): a quarantine NSG someone altered, still holding NICs, is whole
            # again or said — its NICs' state lost too (I1's exemption ends here).
            # Out of sight (I1S): its role removed, or our tag taken off, after L2 held on it
            # here — the test's own journal (`out_of_sight`), never the code's cards.
            said = {key(e.get("resource_id", "")) for e in escalations.pending()}
            required = set()
            for k in sorted(self.altered):
                if self.fake.nsgs.get(k, {}).get("tags", {}).get("managed-by") != "glorfindel" \
                        and k not in self.out_of_sight:
                    continue                    # gone, or not ours
                held = [n for n, c in self.fake.nics.items() if key(c["nsg"]) == k]
                if held and not self._quarantine_intact(k):
                    required.add(k)
                assert not held or self._quarantine_intact(k) or k in said, (
                    f"L2: the quarantine NSG {k} was altered, holds {held}; "
                    "the reassertion neither put it back nor said so"
                    + (f" — its card closed while it was out of sight ({self.out_of_sight[k]})"
                       if k in self.out_of_sight else ""))
            self.l2_held_on = required
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

    def _chain_start(self) -> tuple[set, int]:
        """The rules Glorfindel wrote with nothing else touching the world since (`chain`:
        the journal's length and the world as its last block left them, those rules) —
        empty when anything moved: a customer's change, a fault, another operation."""
        chain = getattr(self, "chain", None)
        start = len(self.fake.journal)
        if chain and chain[0] == start and self.fake.snapshot() == chain[1]:
            return set(chain[2]), start
        return set(), start

    def _chain_end(self, clean: set, start: int, ok: bool):
        if not ok:
            self.chain = None
            return
        done = self.fake.journal[start:]
        clean -= {(e["nsg"], e["rule"]) for e in done if e.get("op") == "rule.delete"}
        clean |= {(e["nsg"], e["rule"]) for e in done if e.get("op") == "rule.write"}
        self.chain = (len(self.fake.journal), self.fake.snapshot(), clean)

    def _named_block_rules(self, vm: str) -> set:
        """(NSG, rule) of every rule the VM's block entry names — where to look on Azure."""
        from .fake_azure import nsg_id
        entry = next((b for b in actions._load_block_entries(vm) if b.get("ip") == ATTACKER), None)
        if not entry:
            return set()
        named = {(key(nsg_id(p["nsg_rg"], p["nsg_name"])), f"{p['rule']}{x}".lower())
                 for p in entry.get("placements") or [] for x in ("", "-out")}
        if entry.get("scoped") is False and "/" in (entry.get("nsg") or ""):
            named |= {(key(nsg_id(*entry["nsg"].split("/", 1))), f"{entry['rule']}{x}".lower())
                      for x in ("", "-out")}
        return named

    def _block_rules_now(self, vm: str) -> dict:
        """Each rule the VM's block entry names, as Azure has it now (None: absent)."""
        return {(k, n): copy.deepcopy(self.fake.nsgs.get(k, {}).get("rules", {}).get(n))
                for k, n in sorted(self._named_block_rules(vm))}

    def _no_drift_on_untouched(self, cards_before: set, quiet: set | None, named: dict):
        """I3, a drift that wasn't (RB1, second review): a block whose every rule — as its
        entry named them before the pass — Glorfindel wrote, nothing touching the world
        since (the blocks and promotions in a row, then this pass), gets no card that it
        vanished. A promotion leaves a NIC to the perimeter; read as a NIC added since, its
        rules gone, the pass said a drift and, outside human_only, put them back over the
        promotion."""
        if not quiet:
            return
        for e in escalations.pending():
            if (e["id"] in cards_before or e.get("action") != "block_suspicious_ip"
                    or "disparu" not in (e.get("reason") or "")):
                continue
            vm = next((v for v in self.live if key(v) == key(e.get("resource_id") or "")), None)
            rules = named.get(vm) or set()
            assert not rules or not rules <= quiet, (
                f"I3: the reassertion said the block on {vm} vanished; every one of its rules is as "
                f"Glorfindel wrote it, nothing touched since ({e.get('reason', '')[:100]}…)")

    def _block_cards_true(self, cards_before: set, journal_at: int):
        """I3 for what the reassertion's block cards say (RB1), NIC by NIC, on the NICs a
        card names (all of the VM's when it names none), on the cards this pass made:
        "reposé une fois" or "reste bloquée" means the attacker is cut off from them;
        "n'est plus bloquée" is never said of a NIC our perimeter block, intact on its
        subnet, cuts off on every port — but one this pass wrote that perimeter for, a card
        said before the write (another VM's entry put it back: true when it was written;
        not a re-application's card, said after its own re-read). Judged from the world and
        the fake's journal, never from the verification the code ran."""
        import re
        bare = "glorfindel-block-" + ATTACKER.replace(".", "-")
        written = {e["nsg"] for e in self.fake.journal[journal_at:]
                   if e.get("op") == "rule.write" and e.get("rule") in (bare, f"{bare}-out")}
        for e in escalations.pending():
            if (e["id"] in cards_before or e.get("action") != "block_suspicious_ip"
                    or not (e.get("signal_id") or "").startswith("reassert-")):
                continue
            vm = next((v for v in self.live if key(v) == key(e.get("resource_id") or "")), None)
            if vm is None:
                continue
            reason = e.get("reason") or ""
            entry = next((b for b in actions._load_block_entries(vm) if b.get("ip") == ATTACKER), {})
            nics = [n["id"].rsplit("/", 1)[-1] for n in self._nics(vm)]

            def named(claim: str) -> list[str]:
                m = re.search(re.escape(claim) + r" sur ([^;.(]+?)(?: par |[;.(]|$)", reason)
                return [n for n in nics if m and n in [x.strip() for x in m.group(1).split(",")]]
            held = (nics if "reposé une fois" in reason else []) + \
                ((named("reste bloquée") or nics) if "reste bloquée" in reason else [])
            reached = {f[0] for f in self._attacker_flows(vm, entry.get("threat_port"))} & set(held)
            assert not reached, (
                f"I3: the reassertion said the block on {vm} holds ({reason[:100]}…), {ATTACKER} reaches "
                f"{sorted(reached)}")
            if "n'est plus bloquée" in reason:
                said = named("n'est plus bloquée")
                cut = [n for n in (said or nics) if self._perimeter_cuts(vm, n)
                       and ("réécrites" in reason or key(self._subnet_nsg_of(vm, n) or "") not in written)]
                assert not cut if said else len(cut) < len(nics), (
                    f"I3: the reassertion said {ATTACKER} no longer blocked on {vm} ({said}); "
                    "our perimeter block still cuts it off")

    def _subnet_nsg_of(self, vm: str, nic: str) -> str | None:
        n = next(x for x in self._nics(vm) if x["id"].rsplit("/", 1)[-1] == nic)
        return self.fake.subnets[key(n["subnet"])]["nsg"]

    def _perimeter_cuts(self, vm: str, nic: str) -> bool:
        """Our perimeter block, intact on this NIC's subnet, cuts the attacker off it alone —
        what nothing else of ours does."""
        return bool(self._behind_our_perimeter(vm, nic) and not self._perimeter_only(vm, nic)
                    and self._perimeter_only(vm, nic, keep=False))

    def _perimeter_only(self, vm: str, nic: str, keep: bool = True) -> frozenset:
        """The attacker's flows to the NIC with none of Glorfindel's denies but the perimeter
        block (keep), or none at all: what the perimeter alone cuts off is the difference —
        an isolation or the VM's own block don't count for it. A rule of ours someone turned
        into an allow stays: it is theirs now. The subnet's NSG alone, the NICs' own left
        out: a perimeter an allow passes before, on its NSG, is bypassed — the code's model
        of precedence, one NSG at a time (a NIC's own NSG that happens to close the port as
        well is no reason for the card to say the perimeter blocks)."""
        bare = "glorfindel-block-" + ATTACKER.replace(".", "-")
        mine = {bare, f"{bare}-out"} if keep else set()
        world = self._world()
        world = {**world, "nics": {k: {**n, "nsg": None} for k, n in world["nics"].items()}, "nsgs": {k: {**g, "rules": {
            n: r for n, r in g["rules"].items()
            if not n.startswith("glorfindel-") or n in mine or r["access"].lower() != "deny"}}
            for k, g in world["nsgs"].items()}}
        return frozenset(f for f in open_flows(world, vm) if f[3] == ATTACKER and f[0] == nic)

    def _behind_our_perimeter(self, vm: str, nic: str) -> bool:
        """The NIC sits on a subnet whose NSG carries our perimeter block of the attacker as
        Glorfindel writes it (the test's own restatement of its shape)."""
        bare = "glorfindel-block-" + ATTACKER.replace(".", "-")
        shape = {"inbound": (ATTACKER, "*"), "outbound": ("*", ATTACKER)}
        g = self._subnet_nsg_of(vm, nic)
        rules = self.fake.nsgs.get(key(g), {}).get("rules", {}) if g else {}
        for name, direction in ((bare, "inbound"), (f"{bare}-out", "outbound")):
            r = rules.get(name)
            if (r is None or r["access"].lower() != "deny" or r["direction"].lower() != direction
                    or str(r.get("protocol") or "*").lower() not in ("*", "any")
                    or r.get("destination_port_range") not in ("*", None) or r.get("destination_port_ranges")
                    or (r.get("source_address_prefix"), r.get("destination_address_prefix")) != shape[direction]
                    or r.get("source_address_prefixes") or r.get("destination_address_prefixes")):
                return False
        return True

    @rule(data=st.data())
    def reset_from_azure(self, data):
        """`glorfindel reset --from-azure`: Azure as the source of truth."""
        vm, rid, fault = self._draw(data)
        flows, states = self._before()
        consistent = self._consistent(vm)
        self.releasing.add(vm)
        writes = len(self.fake.journal)
        out, err = self._run(fault, lambda: self.connector.sweep_vm_rules(rid), "reset --from-azure")
        if (out or {}).get("status") == "swept" or (err is not None and len(self.fake.journal) == writes):
            self.releasing.discard(vm)
        if err is None and consistent:
            # I8/I11: swept or not, the state says what Azure has — a partial reset marks
            # what it couldn't finish, so the reassertion doesn't put back the rest.
            assert self._consistent(vm), f"I8: reset --from-azure left {vm} with a state that isn't Azure's"
        if out and out.get("status") == "swept":
            assert (self._back_to_design(vm, own=True) and self._nics_as_designed(vm)
                    and not self._held_unknown(vm)), (
                f"I3: reset --from-azure said swept, {vm} is not back to its design")
            assert self._state(vm) is None
        self._others_unchanged(vm, flows, states, perimeter="lift")

    @rule(data=st.data())
    def another_subscription(self, data):
        """A VM of another subscription, same group and name as one of ours — Log
        Analytics can be shared across subscriptions. The clients act in this one: any
        action would land on the homonym. Refused, nothing written (I12)."""
        vm = data.draw(st.sampled_from(self.live), label="vm")
        rid = vm.replace("/subscriptions/s/", "/subscriptions/s2/")
        kind = data.draw(st.sampled_from(["isolate", "release", "block", "unblock", "reset",
                                          "verify_isolation", "verify_release", "verify_block"]), label="operation")
        c = self.connector
        fn = {"isolate": lambda: c.isolate_vm(rid), "release": lambda: c.release_isolation(rid),
              "block": lambda: c.block_suspicious_ip(ATTACKER, rid, scope="vm", threat_port=22),
              "unblock": lambda: c.unblock_ip(ATTACKER, rid), "reset": lambda: c.sweep_vm_rules(rid),
              "verify_isolation": lambda: c.verify_isolation(rid), "verify_release": lambda: c.verify_release(rid),
              "verify_block": lambda: c.verify_block_ip(ATTACKER, rid)}[kind]
        azure, state, blocks = self.fake.snapshot(), self._state(vm), actions._load_block_entries(vm)
        out, err = self._run(None, fn, f"another subscription: {kind}")
        assert isinstance(err, actions.WrongSubscriptionError), (
            f"I12: {kind} on a VM of another subscription was not refused: {out or err!r}")
        assert self.fake.snapshot() == azure, f"I12: {kind} on another subscription wrote to Azure"
        assert self._state(vm) == state and actions._load_block_entries(vm) == blocks, (
            f"I12: {kind} on another subscription changed a local state")

    # ── two operations at once (L27) ────────────────────────────────────────────

    def _consistent(self, vm: str) -> bool:
        """The local state says what Azure has: an isolation on Azure is in the state and
        a state that claims one has it (unless it says it is partial or in progress), a
        block likewise. Not what sits on the own NSG of an untied NIC (_untied, I8F)."""
        st = self._state(vm)
        held = bool(st and (st.get("partial") or st.get("release_failed") or st.get("releasing_at")))
        if bool(self._footprint(vm, self._untied(vm))) != (st is not None) and not (held and st is not None):
            return False
        rules = [r for r in self._block_rules_for(vm, own=True) if not self._perimeter_rule(r)]
        # An entry holds the VM's placements, and the perimeter rule too when the same
        # IP was also blocked subnet-wide (one entry per IP).
        entries = [e for e in actions._load_block_entries(vm)
                   if e.get("placements") or e.get("scoped", True) is not False]
        held = any(e.get("partial") or e.get("unblock_failed") or e.get("unblocking_at") for e in entries)
        return bool(rules) == bool(entries) or held

    def _concurrent_op(self, data, n: int, vm: str | None = None, kind: str | None = None):
        vm = vm or data.draw(st.sampled_from(self.live), label=f"vm {n}")
        kind = kind or data.draw(st.sampled_from(["isolate", "release", "block", "unblock", "reassert", "reset"]),
                                 label=f"operation {n}")
        c = self.connector
        fn = {"isolate": lambda: c.isolate_vm(vm),
              "release": lambda: c.release_isolation(vm),
              "block": lambda: c.block_suspicious_ip(ATTACKER, vm, scope="vm", threat_port=22),
              "unblock": lambda: c.unblock_ip(ATTACKER, vm),
              "reassert": lambda: reassert.reassert_active(c, None),
              "reset": lambda: c.sweep_vm_rules(vm)}[kind]
        return vm, kind, fn

    @rule(data=st.data())
    def concurrently(self, data):
        """Two writers at once — a release in the War Room while the watch reasserts, a
        block from the CLI during an isolation — interleaved call by call. Whatever the
        order, the VMs end as one operation after the other would leave them."""
        first = self._concurrent_op(data, 1)
        # Mostly on the same VM: that is where the lock matters.
        same = data.draw(st.integers(0, 3), label="other vm") != 0
        second = self._concurrent_op(data, 2, first[0] if same else None)
        _CURRENT.mode = data.draw(st.sampled_from(["human_only", "non_disruptive"]), label="mode")
        self._race(data, first, second)

    _RACES = [("release", "reassert"), ("isolate", "release"), ("release", "release"),
              ("block", "unblock"), ("unblock", "reassert"), ("release", "reset")]

    @rule(data=st.data())
    def race(self, data):
        """The races that matter, from the state where they happen: the VM isolated and
        its attacker blocked, then two of the writers that can meet on it."""
        vm = data.draw(st.sampled_from(self.live), label="vm")
        self._isolate(vm, vm, None)
        self._block(vm, vm, None, 22)
        one, two = data.draw(st.sampled_from(self._RACES), label="race")
        _CURRENT.mode = "non_disruptive"
        self._race(data, self._concurrent_op(data, 1, vm, one), self._concurrent_op(data, 2, vm, two))

    def _race(self, data, first, second):
        # A seed, not a list: Hypothesis keeps drawn lists short, and an empty one ran
        # the two operations one after the other.
        order = data.draw(st.integers(0, 2**32 - 1), label="interleaving")
        involved = {first[0], second[0]}
        consistent = {vm: self._consistent(vm) for vm in involved}
        flows, states = self._before()
        self.chaos.arm(None)
        for vm, kind, _ in (first, second):
            if kind in ("release", "reset"):
                self.releasing.add(vm)
        sched = _CURRENT.scheduler = _Scheduler(order)
        try:
            results = sched.run([("op-1", first[2]), ("op-2", second[2])])
        finally:
            _CURRENT.scheduler = None
            self.hung = sched.hung
        # The journal: a release that ended released, or an isolation that ended
        # isolated (the operator's call — its order against the release is unknown).
        for name, (vm, kind, _) in (("op-1", first), ("op-2", second)):
            status = ((results.get(name) or (None, None))[0] or {})
            status = status.get("status") if isinstance(status, dict) else None
            if (kind, status) in (("release", "released"), ("reset", "swept"), ("isolate", "isolated")):
                self.releasing.discard(vm)
        errors = [e for _, e in results.values() if e is not None]
        for name, (out, err) in sorted(results.items()):
            kind = (first if name == "op-1" else second)[1]
            _note(f"concurrently {kind}: " + (type(err).__name__ if err else str((out or {}).get("status", "ok"))
                                               if not isinstance(out, list) else "ok"))
        if not errors:
            for vm in involved:
                if consistent[vm]:
                    assert self._consistent(vm), (
                        f"I11: {first[1]} and {second[1]} at once left {vm} with a state that isn't Azure's")
        # A perimeter block lives in a VM's entry: unblocking or resetting that VM lifts
        # it for its whole subnet — the attacker's flows only, as in the serial rules.
        perimeter = bool({first[1], second[1]} & {"block", "unblock", "reset"})
        strip = (lambda fl: frozenset(f for f in fl if f[3] != ATTACKER)) if perimeter else (lambda fl: fl)
        after = self._flows()
        for other in self.live:
            if other not in involved and "reassert" not in {first[1], second[1]}:
                if perimeter:
                    # Lifted, a perimeter opens the attacker's flows; none of these cuts one (I4B).
                    self._attacker_never_cut(other, flows[other], after[other], "I4: two operations elsewhere",
                                             flows[("own", other)] - flows[other])
                self._only_sealed(other, strip(flows[other]), strip(after[other]), "I4: two operations elsewhere",
                                  flows[("own", other)] - flows[other])
        # The reassertion acts on every VM it has a state for, never on its drawn one, and
        # deletes no rule outside our quarantine NSG: only the other operation's VM acts.
        self._old_isolations_kept({vm for vm, kind, _ in (first, second) if kind != "reassert"},
                                  f"I4: {first[1]} and {second[1]} at once")
        self._claims_after_a_change()

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
        at = data.draw(st.integers(0, len(ips) - 1), label="which")
        # Dynamic (Azure: the lowest free address — often one a deleted VM had) or static.
        new = self._free_ip(ips[0].rsplit(".", 1)[0],
                            data.draw(st.sampled_from([4, 20]), label="from"))
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
    def create_vm(self, data):
        """A new VM: one NIC, the lowest free address of its subnet (Azure's dynamic
        allocation hands out a deleted VM's address first), no NSG of its own, the tier
        NSG, or the NSG of another NIC. Never an id a VM had before."""
        self._create_vm(data, data.draw(st.sampled_from([_HUB, _EDGE]), label="region"))

    @rule(data=st.data())
    def address_reused(self, data):
        """How a rule becomes an orphan that cuts a VM off (U1, V-1 — rare in the drawn
        sequences, found at 5 000): a VM blocked or isolated, deleted with its state or
        after losing it, and a new VM given its address; the posture pass may follow."""
        if len(self.live) <= 2 or len(self.vms) >= len(_VMS) + 3:
            return
        vm, rid, fault = self._draw(data)
        if data.draw(st.booleans(), label="isolate"):
            self._isolate(vm, rid, fault)
        else:
            self._block(vm, rid, fault, data.draw(st.sampled_from([22, None]), label="threat_port"))
        if data.draw(st.booleans(), label="lose its state"):
            self._lose_state(vm)
        nic = self.fake.nics[key(self.fake.vms[key(vm)]["nics"][0])]
        self._delete_vm(vm)
        self._create_vm(data, nic["location"], reuse_nsg=nic["design_nsg"])
        if data.draw(st.booleans(), label="posture pass"):
            self.orphan_sweep(data)

    def _create_vm(self, data, loc: str, reuse_nsg: str | None = None):
        """reuse_nsg: the NSG of a deleted VM's NIC, offered too — a VM recreated by its
        pipeline gets the NSG its predecessor had (the NSG outlives the VM)."""
        if len(self.vms) >= len(_VMS) + 3:
            return
        rg = data.draw(st.sampled_from(["rg-app1", "rg-app2", "rg-new"]), label="rg")
        name = data.draw(st.sampled_from(["web", "api", "batch"]), label="name")
        nic_name = f"{name}-nic-{len(self.vms)}"
        if key(vm_id(rg, name)) in {key(v) for v in self.vms} or key(nic_id(rg, nic_name)) in self.fake.nics:
            return
        subnet = next(s["id"] for s in self.fake.subnets.values() if (s["id"].split("/")[4] == "rg-net") == (loc == _HUB))
        nsgs = [None] + sorted({n["design_nsg"] for n in self.fake.nics.values()
                               if n["design_nsg"] and n["location"] == loc and key(n["design_nsg"]) in self.fake.nsgs}
                               | ({reuse_nsg} if reuse_nsg and key(reuse_nsg) in self.fake.nsgs else set()))
        own = data.draw(st.sampled_from(nsgs), label="nsg")
        ip = self._free_ip("10.0.0" if loc == _HUB else "10.1.0", 4)
        vm = self.fake.add_vm(rg, name, [{"rg": rg, "name": nic_name, "ips": [ip], "subnet": subnet,
                                          "nsg": own, "policy": False, "location": loc}],
                              os_type=data.draw(st.sampled_from(["Linux", "Windows"]), label="os"))
        self.vms.append(vm)
        self.design["vms"][key(vm)] = copy.deepcopy(self.fake.vms[key(vm)])
        self.design["nics"][key(nic_id(rg, nic_name))] = copy.deepcopy(self.fake.nics[key(nic_id(rg, nic_name))])
        _note(f"created {name} in {rg} at {ip}")

    def _free_ip(self, base: str, start: int) -> str:
        used = {ip for n in self.fake.nics.values() for ip in n["ips"]}
        return next(f"{base}.{i}" for i in range(start, 250) if f"{base}.{i}" not in used)

    @rule(data=st.data())
    def delete_vm(self, data):
        """The VM is deleted with its NICs (the subnet and the NSGs stay)."""
        if len(self.live) <= 2:
            return
        self._delete_vm(data.draw(st.sampled_from(self.live), label="vm"))

    def _delete_vm(self, vm: str):
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

    def _quarantine_intact(self, nsg_key: str) -> bool:
        """Our quarantine NSG still denies everything, in and out — by the test's own
        reading of its rules, not the code's: every protocol too (a deny turned to Udp
        lets TCP reach Azure's default AllowVnetInBound, I1F)."""
        rules = self.fake.nsgs.get(nsg_key, {}).get("rules", {})

        def denies_all(direction):
            first = sorted((r for r in rules.values() if r["direction"].lower() == direction),
                           key=lambda r: r["priority"])
            for r in first:
                if r["access"].lower() == "allow" and r["name"] != "glorfindel-quarantine-forensic-in":
                    return False
                if (r["access"].lower() == "deny" and r.get("source_address_prefix") == "*"
                        and (r.get("protocol") or "*").lower() in ("*", "any")
                        and r.get("destination_address_prefix") == "*"
                        and r.get("destination_port_range") in ("*", None) and not r.get("destination_port_ranges")):
                    return True
            return False
        return denies_all("inbound") and denies_all("outbound")

    def _foreign_open(self, vm: str) -> set:
        """NICs of the VM on a quarantine NSG someone else has altered: whatever they let
        through is that someone's doing, until Glorfindel repairs it or says so (L2).
        Someone else: the test's journal (`altered`), not the rules as they read."""
        return {n["id"].rsplit("/", 1)[-1] for n in self._nics(vm)
                if n["nsg"] and actions._is_quarantine_nsg(n["nsg"]) and key(n["nsg"]) in self.altered
                and not self._quarantine_intact(key(n["nsg"]))}

    def _strip_quarantine_nsg(self, data):
        """Someone deletes the deny rules of Glorfindel's own quarantine NSG."""
        ours = sorted(k for k, n in self.fake.nsgs.items() if n["tags"].get("managed-by") == "glorfindel")
        if ours:
            nsg = data.draw(st.sampled_from(ours), label="quarantine")
            self.altered.add(nsg)
            rules = self.fake.nsgs[nsg]["rules"]
            for name in ("glorfindel-quarantine-deny-in", "glorfindel-quarantine-deny-out"):
                rules.pop(name, None)

    @rule(data=st.data())
    def someone_detaches_the_quarantine(self, data):
        """Someone takes our quarantine NSG off a NIC and leaves it with none (the
        portal, a script): not the customer's design, not Glorfindel's doing."""
        nics = sorted(k for k, n in self.fake.nics.items() if n["nsg"] and actions._is_quarantine_nsg(n["nsg"]))
        if nics:
            nic = data.draw(st.sampled_from(nics), label="nic")
            self.fake.nics[nic]["nsg"] = None
            self.detached.add(nic)
            self._claims_after_a_change()

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
            self._check_authors()
            self.ticks += 1
            self.tags_lost_at[key(n["id"])] = self.ticks

    @rule(data=st.data())
    def tamper_with_our_rule(self, data):
        self._tamper_with_our_rule(data)
        self._claims_after_a_change()

    def _tamper_with_our_rule(self, data):
        """Someone edits one of Glorfindel's denies by hand: narrows it (a port, part of
        its addresses), or turns it around — into an allow, after a customer allow, to
        another protocol, aimed at another address — or adds an allow named like ours.
        What a turned-around rule lets through is that someone's doing (I1 is judged
        without it); Glorfindel's verifications must see it (I3)."""
        how = data.draw(st.sampled_from(["port", "source", "destination", "access", "priority",
                                         "protocol", "retarget", "rogue"]), label="how")
        if how == "rogue":
            nsgs = self._customer_nsgs()
            if nsgs:
                nsg = data.draw(st.sampled_from(nsgs), label="nsg")
                rec = _rule_record(_rule("glorfindel-rogue", 95, dict(
                    access="Allow", direction="Inbound", source_address_prefix="*",
                    destination_address_prefix="*", destination_port_range="*")))
                try:
                    FakeAzure._put_rule(self.fake.nsgs[nsg], rec)    # refused on a priority taken
                except Exception:
                    return
                self.tampered[(nsg, "glorfindel-rogue")] = (None, dict(self.fake.nsgs[nsg]["rules"]["glorfindel-rogue"]))
            return
        ours = sorted((k, n) for k, g in self.fake.nsgs.items() for n, r in g["rules"].items()
                      if n.startswith("glorfindel-") and r["access"].lower() == "deny")
        if not ours:
            return
        nsg, name = data.draw(st.sampled_from(ours), label="rule")
        if actions._is_quarantine_nsg(nsg):
            self.altered.add(nsg)
        r = self.fake.nsgs[nsg]["rules"][name]
        if how in ("access", "priority", "protocol", "retarget"):
            # Only an allow can open beyond the design: the others deny less, or
            # elsewhere — as the narrowing below.
            before = dict(r)
            if how == "access":
                r["access"] = "Allow"
                self.tampered[(nsg, name)] = (before, dict(r))
            elif how == "priority":
                taken = {x["priority"] for x in self.fake.nsgs[nsg]["rules"].values()
                         if x["direction"].lower() == r["direction"].lower()}
                r["priority"] = next(p for p in range(4000, 4096) if p not in taken)
            elif how == "protocol":
                r["protocol"] = "Udp"
            else:
                side = "destination" if r["direction"].lower() == "inbound" else "source"
                r[f"{side}_address_prefix"], r[f"{side}_address_prefixes"] = "10.0.0.99", None
            return
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
    def quarantine_altered_then_reasserted(self, data):
        """A rare state made common (I1F, L2): a VM isolated, its state lost or kept, then
        someone alters our quarantine NSG — strips it, or turns one of its denies — and
        the reassertion runs, unfaulted. Drawn one by one, the steps almost never met
        (M830 and M831 went unseen at 500 sequences)."""
        vm, rid, _ = self._draw(data)
        self._isolate(vm, rid, None)
        if data.draw(st.booleans(), label="lose the state"):
            self.lose_state(_Drawn(data, vm=vm))
        if data.draw(st.booleans(), label="strip"):
            self._strip_quarantine_nsg(data)
        else:
            q = sorted((k, n) for k, g in self.fake.nsgs.items() if actions._is_quarantine_nsg(k)
                       for n, r in g["rules"].items() if n.startswith("glorfindel-") and r["access"].lower() == "deny")
            if q:
                # The inbound deny turned to another protocol half the time: what the deep
                # run found, and what M831 needs (1/2 at 500 sequences, drawn uniformly).
                inbound = [r for r in q if r[1] == "glorfindel-quarantine-deny-in"] or q
                self._tamper_with_our_rule(_Drawn(
                    data,
                    how=st.one_of(st.just("protocol"), st.sampled_from(
                        ["port", "source", "destination", "access", "priority", "protocol", "retarget"])),
                    rule=st.one_of(st.sampled_from(inbound), st.sampled_from(q))))
        self._claims_after_a_change()
        self.l2_held_on = set()
        self.reassert(_Drawn(data, fault=None))
        self._out_of_sight(data)

    def _out_of_sight(self, data):
        """Said, then out of the listing (I1S, #231): the role removed on its group — the
        listing leaves it out without an error, a hypothesis (fake_azure.unreadable) —, or
        our tag taken off as well as our rules, or both. Its card stays while it is altered
        and holds NICs (L2), then the role is given back and the tag put back (the operator,
        a policy): the rest of the sequence is not about them."""
        f = self.fake
        owed = sorted(k for k in self.l2_held_on if k in f.nsgs
                      and f.nsgs[k]["tags"].get("managed-by") == "glorfindel")
        how = data.draw(st.sampled_from(["no", "role removed", "untagged", "both"]), label="out of sight")
        if not owed or how == "no":
            return
        k = data.draw(st.sampled_from(owed), label="nsg out of sight")
        self.out_of_sight[k] = how
        _note(f"quarantine said, then out of sight: {how}")
        if how != "untagged":
            f.unreadable.add(k)
        if how != "role removed":
            del f.nsgs[k]["tags"]["managed-by"]
        try:
            for _ in range(data.draw(st.integers(1, 2), label="passes")):
                self.reassert(_Drawn(data, fault=None))
        finally:
            f.unreadable.discard(k)
            if k in f.nsgs:
                f.nsgs[k]["tags"]["managed-by"] = "glorfindel"
            del self.out_of_sight[k]

    @rule(data=st.data())
    def block_turned_then_reasserted(self, data):
        """A rare state made common (I5R): a VM blocked on its subnet, for itself, or both
        — two of our rules for one IP —, then someone turns one of our block denies
        into an allow, and the reassertion runs, unfaulted. Drawn one by one, the steps
        met once (I7S's run): a block put back under a turned rule went unseen at 500
        sequences (M1591). The VM's own inbound deny is the one turned half the time —
        what the run found."""
        vm, rid, _ = self._draw(data)
        scope = data.draw(st.sampled_from(["both", "subnet", "vm"]), label="block scope")
        if scope != "vm":
            self.block_perimeter(_Drawn(data, vm=vm, rid=rid, fault=None, replace=False))
        if scope != "subnet":
            self.block(_Drawn(data, vm=vm, rid=rid, fault=None))
        ours = sorted((k, n) for k, g in self.fake.nsgs.items() for n, r in g["rules"].items()
                      if n.startswith("glorfindel-block-") and r["access"].lower() == "deny")
        if ours:
            marks = {_nic_hash(n) for n in self.fake.vms[key(vm)]["nics"]}
            mine = [r for r in ours if r[1].rsplit("-", 1)[-1] in marks] or ours
            self._tamper_with_our_rule(_Drawn(data, how="access", rule=st.one_of(
                st.sampled_from(mine), st.sampled_from(ours))))
        self._claims_after_a_change()
        # Outside human_only half the time more: there, the reassertion writes.
        self.reassert(_Drawn(data, fault=None, mode=st.one_of(
            st.just("non_disruptive"), st.sampled_from(["human_only", "non_disruptive"]))))

    @rule(data=st.data())
    def turned_then_address_reused(self, data):
        """A rare state made common (I5Q): a VM blocked, then blocked on its subnet, for
        itself or both, one of our denies turned into an allow (block_turned_then_reasserted)
        — its own rule written first keeps the smaller number, before the perimeter one —;
        then the VM isolated or blocked, deleted, its address (and its NSG, offered) given
        to a new VM (address_reused), and the reassertion runs, unfaulted, outside
        human_only more often. Drawn one by one, the steps met on one seed at 500
        sequences (101, RB1's fourth review); M1730 went unseen by the machine alone."""
        if len(self.live) <= 2 or len(self.vms) >= len(_VMS) + 3:
            return
        vm, rid, _ = self._draw(data)
        self.block(_Drawn(data, vm=vm, rid=rid, fault=None))
        self.block_turned_then_reasserted(_Drawn(data, vm=vm, rid=rid, fault=None))
        self.address_reused(_Drawn(data, vm=vm, rid=rid, fault=None))
        self.reassert(_Drawn(data, fault=None, mode=st.one_of(
            st.just("non_disruptive"), st.sampled_from(["human_only", "non_disruptive"]))))

    @rule(data=st.data())
    def address_reused_under_a_turned_rule(self, data):
        """A rare state made common (I4A, #328): a VM blocked, one of its block rules turned
        into an allow by someone, the NIC's IP changed, a new VM given the lowest free
        address — the old one, often: the turned rule lets the attacker reach it —, then
        the VM blocked again. I4 is checked by _block: the new VM's flows are not the
        operation's to change. Drawn one by one, the steps met once (RB1's run, seed 8675
        at 500)."""
        if len(self.vms) >= len(_VMS) + 3:
            return
        vm, rid, _ = self._draw(data)
        port = data.draw(st.sampled_from([22, None]), label="threat_port")
        self._block(vm, rid, None, port)
        marks = {_nic_hash(n) for n in self.fake.vms[key(vm)]["nics"]}
        mine = sorted((k, n) for k, g in self.fake.nsgs.items() for n, r in g["rules"].items()
                      if n.startswith("glorfindel-block-") and r["access"].lower() == "deny"
                      and n.removesuffix("-out").rsplit("-", 1)[-1] in marks)
        if not mine:
            return
        self._tamper_with_our_rule(_Drawn(data, how="access", rule=st.sampled_from(mine)))
        nic = data.draw(st.sampled_from(sorted(key(n) for n in self.fake.vms[key(vm)]["nics"])), label="nic")
        self._customer_changes_ip(_Drawn(data, nic=nic))
        self._create_vm(data, self.fake.nics[nic]["location"],
                        reuse_nsg=self.fake.nics[nic]["design_nsg"])
        self._claims_after_a_change()
        self._block(vm, rid, None, port)

    @rule(data=st.data())
    def joins_an_old_isolation(self, data):
        """A rare state made common (I4F): a new VM on the NSG where an older version's
        isolation of another VM lies, isolated — its NIC then away from that NSG, in
        quarantine or left bare — and reset or released. Drawn one by one, the steps met
        once at 2 000 sequences. The operator turns the quarantine on first (as
        config_changes may): by rules, the NIC never leaves its NSG."""
        nsgs = sorted({k for k, _ in self.legacy if k in self.fake.nsgs})
        if not nsgs:
            return
        if not (self.config["quarantine"] and self.config["readable"]):
            self.config = {**self.config, "quarantine": True, "readable": True}
            self._write_config()
        g = self.fake.nsgs[data.draw(st.sampled_from(nsgs), label="old isolation's NSG")]
        count = len(self.vms)
        self.create_vm(_Drawn(data, region=g["location"], nsg=g["id"]))
        if len(self.vms) == count:
            return
        vm = self.vms[-1]
        self._isolate(vm, vm, None)
        if data.draw(st.booleans(), label="left bare"):
            away = [key(n) for n in self.fake.vms[key(vm)]["nics"]
                    if self.fake.nics[key(n)]["nsg"] and actions._is_quarantine_nsg(self.fake.nics[key(n)]["nsg"])]
            if away:
                self.someone_detaches_the_quarantine(_Drawn(data, nic=away[0]))
        # The reset three times in four: the release puts the NIC back before reading.
        if data.draw(st.sampled_from([True, True, True, False]), label="reset"):
            self.reset_from_azure(_Drawn(data, vm=vm, fault=None))
        else:
            self._release(vm, vm, None)

    @rule(data=st.data())
    def an_old_isolations_vm_goes_away(self, data):
        """The symmetric case made common (I4S, #239): the VM of an older version's
        isolation isolated by quarantine — its NIC away from that NSG, left bare or not,
        the quarantine's tags lost or not —, then a new VM attached to that NSG, alone
        there now, reset or released. Nothing opens (the quarantine holds the old VM):
        only the test's journal tells the old isolation was taken (_old_isolations_kept)."""
        owners = sorted({(k, v) for (k, _), v in self.legacy.items() if k in self.fake.nsgs and v in self.live})
        if not owners:
            return
        if not (self.config["quarantine"] and self.config["readable"]):
            self.config = {**self.config, "quarantine": True, "readable": True}
            self._write_config()
        k, owner = data.draw(st.sampled_from(owners), label="old isolation")
        g = self.fake.nsgs[k]
        self._isolate(owner, owner, None)
        away = [key(n) for n in self.fake.vms[key(owner)]["nics"]
                if self.fake.nics[key(n)]["nsg"] and actions._is_quarantine_nsg(self.fake.nics[key(n)]["nsg"])]
        held = sorted({key(self.fake.nics[n]["nsg"]) for n in away})
        if held and data.draw(st.booleans(), label="tags lost"):
            self._tags_lost(_Drawn(data, quarantine=held[0]))
            self._claims_after_a_change()
        if away and data.draw(st.booleans(), label="left bare"):
            self.someone_detaches_the_quarantine(_Drawn(data, nic=away[0]))
        count = len(self.vms)
        self.create_vm(_Drawn(data, region=g["location"], nsg=g["id"]))
        if len(self.vms) == count:
            return
        vm = self.vms[-1]
        if data.draw(st.sampled_from([True, True, True, False]), label="reset"):
            self.reset_from_azure(_Drawn(data, vm=vm, fault=None))
        else:
            self._release(vm, vm, None)

    @rule(data=st.data())
    def operator_acknowledges(self, data):
        """The operator acknowledges a pending card of the reassertion's about a block (RB1,
        third review): an acknowledged card that silenced whatever followed went unseen — a
        card « ne couvre pas » set the drift marker, and the perimeter's later disappearance
        was neither put back nor said. Block cards only: the other kinds (quarantine,
        orphans, bypass) stay said by design once acknowledged, and their oracles count
        pending cards. A drift card acknowledged stays said for its episode (L1)."""
        cards = sorted((e["id"], e.get("resource_id") or "", e.get("reason") or "") for e in escalations.pending()
                       if e.get("action") == "block_suspicious_ip"
                       and (e.get("signal_id") or "").startswith("reassert-"))
        # Drawn first, with constraints that never depend on the state: what is pending may
        # differ between two replays of a sequence (the race runner), and Hypothesis calls
        # a draw that changes with it flaky.
        pick = data.draw(st.integers(0, 7), label="card acknowledged")
        if not cards:
            return
        cid, rid, reason = cards[pick % len(cards)]
        escalations.resolve(cid)
        vm = next((v for v in self.live if key(v) == key(rid)), None)
        if vm and ("disparu" in reason or "a échoué" in reason):
            self.acked_drift = {**getattr(self, "acked_drift", {}), vm: self._block_rules_now(vm)}

    @rule()
    def time_passes(self):
        """Forty minutes go by: an operation's marker left behind is stale now."""
        _CURRENT.clock += 40

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
        self._lose_state(data.draw(st.sampled_from(self.vms), label="vm"))

    def _lose_state(self, vm: str):
        self._check_authors()                      # what Glorfindel recorded comes first
        self.ticks += 1
        self.state_lost_at[key(vm)] = self.ticks
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

    @rule(data=st.data())
    def bare_with_an_unknown_original(self, data):
        """A rare state made common (I8F): an isolation by quarantine whose state and tags
        are lost, re-isolated — its NICs' original unknown (Q7); someone then leaves a NIC
        of the VM bare, and the VM is isolated again (a fault drawn) then released,
        released twice, or reset.
        Drawn one by one, these steps met once in A3's run (186 steps), in a world where
        an older version's isolation sat on the NIC's own NSG — M860 and M861 went unseen
        at 500 sequences. In a world without one, a VM nothing touched yet, its first NIC
        on an NSG of its own, gets it now — what `build` gives a world with `legacy` (an
        older version's isolation, its state lost), only drawn later; the legacy VM is not
        favoured (M34 needs its old state). The quarantine is turned on if it is off
        (config_changes)."""
        vm, rid, _ = self._draw(data)
        if not self.legacy:
            first = self._nics(vm)[0]
            own, name = key(first["nsg"]), first["id"].rsplit("/", 1)[-1]
            dedicated = (own and own == key(first["design_nsg"])
                         and sum(own in (key(c["nsg"]), key(c["design_nsg"])) for c in self.fake.nics.values()) == 1
                         and not any(key(s["nsg"]) == own for s in self.fake.subnets.values()))
            untouched = (self._state(vm) is None and not self._footprint(vm) and not actions._load_block_entries(vm)
                         and not self._block_rules_for(vm))
            if (not self.deleted and dedicated and untouched
                    and next(v for v in self.vms if any(        # the VM _legacy_isolation finds
                        n.rsplit("/", 1)[-1] == name for n in self.fake.vms[key(v)]["nics"])) == vm):
                self._legacy_isolation(name, keep_state=False)
        if not (self.config["readable"] and self.config["quarantine"]):
            self.config = {**self.config, "quarantine": True, "readable": True}
            self._write_config()
        self._isolate(vm, rid, None)
        self.lose_state(_Given(vm))
        held = sorted({key(n["nsg"]) for n in self._nics(vm) if n["nsg"] and actions._is_quarantine_nsg(n["nsg"])})
        self._tags_lost(_Given(held[0]) if held else data)        # the tags of the VM's quarantine
        self._isolate(vm, rid, None)
        nics = sorted(k for k in (key(n) for n in self.fake.vms[key(vm)]["nics"])
                      if self.fake.nics[k]["nsg"] and actions._is_quarantine_nsg(self.fake.nics[k]["nsg"]))
        if nics:
            nic = data.draw(st.sampled_from(nics), label="nic")
            self.fake.nics[nic]["nsg"] = None
            self.detached.add(nic)
            self._claims_after_a_change()
        then = data.draw(st.sampled_from(["isolate+release", "release twice", "reset"]), label="then")
        if then == "reset":
            self.reset_from_azure(_Given(vm, rid, None))
        elif then == "release twice":
            # A release that can't finish, then the operator's retry: what the first one
            # kept is what the second one undoes (M862).
            self._release(vm, rid, None)
            self._release(vm, rid, None)
        else:
            # Isolated again, under a fault of its own — often a single 429 among the
            # first calls, where it reads our tag: read as "none" (M863).
            self._isolate(vm, rid, data.draw(st.one_of(_FAULTS, st.tuples(
                st.integers(3, 8), st.just("before-429"))), label="isolate fault"))
            self._release(vm, rid, None)

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
        ours = [g for g in self.fake.nsgs.values() if g["tags"].get("managed-by") == "glorfindel"]
        for nic in self._nics(vm):
            in_q = nic["nsg"] and actions._is_quarantine_nsg(nic["nsg"])
            if not in_q and nic["nsg"] is not None:
                continue
            want = nic["design_nsg"]
            if want and key(want) not in self.fake.nsgs:
                d = self.design["nsgs"][key(want)]
                self.fake.nsgs[key(want)] = {**d, "rules": {k: dict(r) for k, r in d["rules"].items()},
                                             "tags": dict(d["tags"])}
            # In quarantine: the tag on the NSG it carries. Left with no NSG (detached
            # outside Glorfindel): on our NSGs, where the release looks for it.
            for q in ([self.fake.nsgs[key(nic["nsg"])]] if in_q else ours):
                q["tags"][self.connector._orig_tag(nic["id"])] = want or self.connector._NO_ORIGINAL

    def _recover_everything(self, lose_state: bool):
        """I7: whatever was reached, release brings every VM back to its design."""
        self.chaos.plan = None
        self.fake.write_denied = False
        self.config["readable"] = True
        self._write_config()
        # NICs left bare whose original nothing records: the operator puts their NSG
        # back first (Glorfindel can't know they were ever in quarantine).
        for vm in self.live:
            for n in self._nics(vm):
                if self._untraceable(vm, n) and n["design_nsg"] and key(n["design_nsg"]) in self.fake.nsgs:
                    n["nsg"] = n["design_nsg"]
        # An older version's rule that nothing traces any more — its VM deleted, or its
        # NSG shared since (fixed names only count on a dedicated NSG) without the old
        # state naming it: the operator removes it.
        for (k, n), owner in self.legacy.items():
            g = self.fake.nsgs.get(k)
            if g is None or n not in g["rules"]:
                continue
            # By design too: a NIC away in quarantine comes back to it during the release.
            shared = sum(k in (key(c["nsg"]), key(c["design_nsg"])) for c in self.fake.nics.values()) > 1 or \
                any(key(s["nsg"]) == k for s in self.fake.subnets.values())
            st_ = self._state(owner) if owner not in self.deleted else None
            named = bool(st_) and "placements" not in st_ and n in {x.lower() for x in st_.get("rule_names", [])}
            if owner in self.deleted or (shared and not named):
                del g["rules"][n]
        # An allow someone added under one of our names isn't Glorfindel's to remove
        # (it never put one there): the operator does.
        for (k, n), (before, _) in self.tampered.items():
            if before is None:
                self.fake.nsgs.get(k, {}).get("rules", {}).pop(n, None)
        # A deleted VM's deny kept behind one of our rules turned into an allow (I5Q) is
        # said, by its release or the orphan sweep: the operator puts that rule back as it
        # was, as the card asks — before the releases, which keep the deny until then.
        self._operator_puts_turned_back()
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
            # Own view: what could still cut a live VM off is the leftover of a deleted
            # VM whose state was lost, on an IP the live one got since — a known limit
            # (nothing says which NSGs to look at); its recorded rules are checked below.
            assert self._released(vm, own=True), f"I7: {vm} could not be brought back to its design"
        # That known limit is lifted by the orphan sweep (A3): after it, every live VM
        # is back to its design in full — not only in its own view. The VMs given their
        # mode, as the operator gives it to free them (D-A): in human_only only a card,
        # and a mode left by an earlier sequence's rule made the teardown flaky.
        _CURRENT.mode = "non_disruptive"
        self._operator_puts_turned_back()           # and those the releases left (I5Q)
        self._orphan_sweep()
        for vm in self.live:
            assert self._released(vm), f"U1: {vm} still cut off by a deleted VM's rule after the orphan sweep"
        for vm, recorded in deleted_records.items():
            left = [r for r in self._named_leftovers(self.deleted[vm]) if r.split("/")[-1] in recorded]
            assert not left, f"I7: rules of the deleted {vm} left: {left}"

    # ── always ──────────────────────────────────────────────────────────────────

    @invariant()
    def writes_only_its_own(self):
        self._check_authors()

    def _check_authors(self):
        """I2, by author: every write that went through the API is Glorfindel's (the test
        plays everyone else on the dicts). It writes rules it wrote, new rules of its own
        names, its own quarantine NSG (anything there: Q6), and a NIC's NSG only to put
        it in quarantine or to give back what it carried before — or the customer's
        design. Read from the fake's journal, not from what the code says it did."""
        if not getattr(self, "fake", None):
            return
        journal = self.fake.journal
        for e in journal[self.journal_seen:]:
            op = e["op"]
            if op in ("rule.write", "rule.delete"):
                nsg = self.fake.nsgs.get(e["nsg"])
                ours = nsg is not None and actions._is_quarantine_nsg(e["nsg"]) and \
                    nsg["tags"].get("managed-by") == "glorfindel"
                if e["existed"]:
                    assert e["authored"] or ours, (
                        f"I2: Glorfindel {op} on a rule it never wrote: {e['nsg']} / {e['rule']}")
                else:
                    assert e["rule"].startswith("glorfindel-"), (
                        f"I2: Glorfindel created a rule not named as its own: {e['rule']}")
            elif op in ("nsg.write", "nsg.tags"):
                assert actions._is_quarantine_nsg(e["nsg"]), f"I2: Glorfindel wrote the NSG {e['nsg']}"
                before = e["before_tags"]
                assert before is None or before.get("managed-by") == "glorfindel", (
                    f"I2: Glorfindel took over an NSG that only has its name: {e['nsg']}")
                # An original written as our tag (a NIC's own NSG, not "none"): the NIC is
                # tied to it again, whatever the test lost before (I8F, second review).
                after = e.get("after_tags") or {}
                for k, v in after.items():
                    if k.startswith("glorfindel-orig-") and v != "none" and (before or {}).get(k) != v:
                        nic = self._nic_of_tag(k)
                        if nic:
                            self.ticks += 1
                            self.retagged_at[nic] = self.ticks
            elif op == "nic.write":
                nic, was, now = e["nic"], e["before"], e["after"]
                if now and actions._is_quarantine_nsg(now):
                    if not (was and actions._is_quarantine_nsg(was)):
                        self.before_quarantine[nic] = was
                        if was:
                            self.ticks += 1
                            self.recorded_at[nic] = (self.ticks, key(now))
                    continue
                design = self.fake.nics[nic]["design_nsg"]
                allowed = {key(design)} | ({key(self.before_quarantine[nic])} if nic in self.before_quarantine else set())
                assert (was is None or actions._is_quarantine_nsg(was)) and key(now) in allowed, (
                    f"I2: Glorfindel set {nic}'s NSG from {was} to {now} "
                    f"(before quarantine: {self.before_quarantine.get(nic, 'never in quarantine')})")
        self.journal_seen = len(journal)
        for vm in self.live:                     # which records a state has held
            for p in (self._state(vm) or {}).get("placements") or []:
                nk = key(p.get("nic_id") or "")
                if p.get("kind") == "quarantine" and (self.fake.nics.get(nk) or {}).get("nsg") is None:
                    self.quarantine_held[nk] = self.ticks     # a state saw it taken off our NSG
                    if "original_nsg_id" not in p:
                        self.unknown_held[nk] = self.ticks    # ...knowing it doesn't know its original
                if p.get("original_nsg_id") and nk in self.recorded_at:
                    self.state_had[nk] = self.recorded_at[nk][0]

    @invariant()
    def never_more_open_than_designed(self):
        if not getattr(self, "design", None):
            return
        # Judged without the rules someone turned around: what they let through is
        # theirs, not Glorfindel's.
        flows = {vm: self._open(vm, untampered=True) for vm in self.live}
        for vm in self.live:
            # A NIC someone else left without an NSG is open by their doing, until a
            # release (or the reassertion) puts something back on it.
            gone = {n["id"].rsplit("/", 1)[-1] for n in self._nics(vm) if key(n["id"]) in self.detached}
            gone |= self._foreign_open(vm)
            extra = {f for f in flows[vm] - self._designed(vm) if f[0] not in gone}
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
            if n["nsg"] is not None and not actions._is_quarantine_nsg(n["nsg"]):
                self.detached.discard(k)          # a customer NSG is back on it
            ok = key(n["nsg"]) == key(n["design_nsg"]) or (
                n["nsg"] and actions._is_quarantine_nsg(n["nsg"])
                and self.fake.nsgs[key(n["nsg"])]["tags"].get("managed-by") == "glorfindel"
            ) or (n["nsg"] is None and k in self.detached)          # someone else's doing
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
                        and not self._perimeter_rule(name) and (k, name) not in self.legacy):
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
        iso, err = self._run(fault, lambda: self.connector.verify_isolation(rid))
        # No fault injected: a verification answers — yes, no or unknown. Raising left
        # the reassertion to log it and move on (seventh review, U4).
        assert fault is not None or err is None, f"I3: verify_isolation of {vm} raised: {err!r}"
        if iso and iso.get("verified") is True:
            assert not self._undeclared(vm, iso), f"I3: verify_isolation True, {vm} reachable"
        rel, _ = self._run(fault, lambda: self.connector.verify_release(rid))
        if rel and rel.get("verified") is True:
            assert self._back_to_design(vm, own=True) and self._nics_as_designed(vm), (
                f"I3: verify_release True, {vm} not back to its design")
            held = self._held_unknown(vm)
            assert not held, f"I3: verify_release True, {held} of {vm} bare, their original unknown to a state"
        entry = next((e for e in actions._load_block_entries(vm) if e.get("ip") == ATTACKER), None)
        # Every entry, a perimeter block alone too: its verification reads the VM's NICs it
        # doesn't cover (RB1, review) — one merged with the VM's own is judged NIC by NIC,
        # the perimeter counted where it covers a NIC.
        if entry:
            blk, _ = self._run(fault, lambda: self.connector.verify_block_ip(ATTACKER, rid))
            if blk and blk.get("verified") is True:
                assert not self._attacker_flows(vm, entry.get("threat_port")), (
                    f"I3: verify_block_ip True, {ATTACKER} reaches {vm}")

    def _claims_after_a_change(self):
        """The world just moved: every claim of every VM is checked again — a change
        that makes a verification false must not wait for that VM's turn."""
        for vm in self.live:
            self._check_claims(vm, vm)

    def _cutting_orphans(self, spare: set = frozenset()) -> set:
        """(NSG, rule) of Glorfindel's denies named for a NIC that no longer exists, aimed
        at an address a live NIC holds, on an NSG that governs that NIC now — its own
        NSG or its subnet's. From the test's records (the NICs it deleted, the naming
        convention), never from what the code reports. `spare`: VMs whose NICs don't
        count (held by Glorfindel)."""
        gone = {_nic_hash(n) for nics in self.deleted.values() for n in nics}
        if not gone:
            return set()
        spared = {key(n) for v in self.fake.vms.values() if key(v["id"]) in spare for n in v["nics"]}
        governed: dict[str, set] = collections.defaultdict(set)
        for n in self.fake.nics.values():
            if key(n["id"]) in spared:
                continue
            for g in (n["nsg"], self.fake.subnets[key(n["subnet"])]["nsg"]):
                if g:
                    governed[key(g)] |= set(n["ips"])
        out = set()
        for k, g in self.fake.nsgs.items():
            for name, r in g["rules"].items():
                if (not name.startswith(("glorfindel-iso-", "glorfindel-block-")) or r["access"].lower() != "deny"
                        or not any(h in name for h in gone)):
                    continue
                side = "destination" if r["direction"].lower() == "inbound" else "source"
                if governed[k] & set([r.get(f"{side}_address_prefix")] + list(r.get(f"{side}_address_prefixes") or [])):
                    out.add((k, name))
        return out

    def _operator_puts_turned_back(self):
        """I5Q: the rules turned into an allow that a deny of ours holds back — a deleted
        VM's, or a live VM's aimed at the old address another VM took (an IP changed:
        its release keeps the deny, `release_partial`, the turned rule named) —, put back
        as they were by the operator, as the card or the release asks."""
        # I4B: a turned allow put back is a deny again — one of ours on another NIC's address,
        # which may hold back another turned rule in its turn (seed 101 at 500): until none is left.
        for _ in range(len(self.tampered) + 1):
            self._behind_turned(self._cutting_orphans() | self._cutting_others())
            todo = sorted(self.turned_behind | self._turned_aimed_elsewhere())
            if not todo:
                break
            for k, n in todo:
                self.fake.nsgs[k]["rules"][n] = dict(self.tampered[(k, n)][0])

    def _turned_aimed_elsewhere(self) -> set:
        """I4B: our rules someone turned into an allow, still as they left them, that let
        through to a live NIC other than their own VM's what they name — its address on an
        NSG that governs it, any address (`*`) on an NSG that governs another NIC, or a
        range or a tag (who it takes in is not read). The unblock, the reset, the release
        keep them, said (taken off, that VM lost the flows): the operator puts them back
        as they were, as said. The convention (the rule's NIC by its hash), the test's
        records (`tampered`)."""
        import ipaddress
        out = set()
        for (k, n), (before, after) in self.tampered.items():
            r = self.fake.nsgs.get(k, {}).get("rules", {}).get(n)
            if (before is None or r != after or r["access"].lower() != "allow"
                    or not n.startswith(("glorfindel-iso-", "glorfindel-block-"))):
                continue
            side = "destination" if r["direction"].lower() == "inbound" else "source"
            values = [v for v in [r.get(f"{side}_address_prefix")] + list(r.get(f"{side}_address_prefixes") or [])
                      if v] or ["*"]
            mine = {key(c) for vm in self.fake.vms.values() if any(_nic_hash(c) in n for c in vm["nics"])
                    for c in vm["nics"]}
            others = [c for ck, c in self.fake.nics.items() if ck not in mine and k in {
                key(g) for g in (c["nsg"], self.fake.subnets[key(c["subnet"])]["nsg"]) if g}]
            for v in values:
                low = v.strip().lower()
                if low in ("*", "any", "0.0.0.0/0"):
                    hit = bool(others)
                else:
                    try:
                        ipaddress.ip_address(low)
                    except ValueError:
                        hit = True
                    else:
                        hit = any(low in c["ips"] for c in others)
                if hit:
                    out.add((k, n))
                    break
        return out

    def _cutting_others(self) -> set:
        """(NSG, rule) of our denies named for one NIC, aimed at an address another live
        NIC holds now, on an NSG that governs it — the test's records, the convention."""
        out = set()
        for k, g in self.fake.nsgs.items():
            for name, r in g["rules"].items():
                if not name.startswith(("glorfindel-iso-", "glorfindel-block-")) or r["access"].lower() != "deny":
                    continue
                side = "destination" if r["direction"].lower() == "inbound" else "source"
                ips = set([r.get(f"{side}_address_prefix")] + list(r.get(f"{side}_address_prefixes") or []))
                for n in self.fake.nics.values():
                    governs = k in {key(x) for x in (n["nsg"], self.fake.subnets[key(n["subnet"])]["nsg"]) if x}
                    if governs and ips & set(n["ips"]) and _nic_hash(n["id"]) not in name:
                        out.add((k, name))
        return out

    def _behind_turned(self, cutting: set) -> dict:
        """I5Q: the orphan rules (of _cutting_orphans) that hold back one of our rules
        someone turned into an allow — the test's journal (`tampered`), the rule still as
        they left it —, on an NSG that governs a NIC the orphan cuts, on the same side,
        aimed at that NIC's address (or at all: `*`). Taken off, the orphan would let
        through what that allow lets pass: I5 keeps it, said. (NSG, rule) → the VMs it
        cuts there; `self.turned_behind` → the turned rules, for the operator."""
        import ipaddress

        def takes_in(r, side, ip):
            """As nsg._takes_in (I4A's, the code's): empty, `*` or `any`, a prefix holding the
            address — a tag or an unreadable value taken as taking it in."""
            values = [v for v in [r.get(f"{side}_address_prefix")] + list(r.get(f"{side}_address_prefixes") or []) if v]
            try:
                addr = ipaddress.ip_address(ip)
            except ValueError:
                return True
            for v in values or ["*"]:
                if v.strip().lower() in ("*", "any"):
                    return True
                try:
                    if addr in ipaddress.ip_network(v.strip(), strict=False):
                        return True
                except ValueError:
                    return True                     # a tag, or unreadable: the safe side
            return False

        turned = [(k, n, after) for (k, n), (before, after) in self.tampered.items()
                  if before is not None and n.startswith(("glorfindel-iso-", "glorfindel-block-"))
                  and after["access"].lower() == "allow" and self.fake.nsgs.get(k, {}).get("rules", {}).get(n) == after]
        out: dict = {}
        self.turned_behind, self.turned_for = set(), {}
        for k, name in cutting:
            r = self.fake.nsgs[k]["rules"][name]
            side = "destination" if r["direction"].lower() == "inbound" else "source"
            ips = {v for v in [r.get(f"{side}_address_prefix")] + list(r.get(f"{side}_address_prefixes") or []) if v}
            for vm in self.live:
                for nic in self._nics(vm):
                    chain = {key(g) for g in (nic["nsg"], self.fake.subnets[key(nic["subnet"])]["nsg"]) if g}
                    for tk, tn, t in turned:
                        if (k in chain and tk in chain and t["direction"].lower() == r["direction"].lower()
                                and any(takes_in(t, side, ip) for ip in ips & set(nic["ips"]))):
                            out.setdefault((k, name), set()).add(key(vm))
                            self.turned_behind.add((tk, tn))
                            self.turned_for.setdefault((k, name), set()).add(tn)
        return out

    def _orphan_sweep(self):
        """The sweep of the orphan rules, as the watch's pass runs it (orphans.py); the
        cut VM's mode is the sequence's (invariant_env)."""
        from glorfindel.orphans import sweep_orphan_rules
        sweep_orphan_rules(self.connector, None)

    def _held(self) -> set:
        """VMs whose isolation or block the local state holds: a rule of a NIC that no
        longer exists, cutting one of them off, may be theirs — their NIC recreated
        (first review of A3). The one exemption read from the code's records: the state
        is what Glorfindel was asked to hold."""
        out = {key(i["resource_id"]) for i in actions.active_isolations()}
        return out | {key(b["resource_id"]) for b in actions.active_blocks() if b.get("resource_id")}

    @rule(data=st.data())
    def orphan_sweep(self, data):
        """A3, U1 taken to its end: the alert, then each rule of a NIC that no longer
        exists, cutting a live VM off, is taken off — a VM given a deleted VM's address
        isn't left cut off — when that VM runs in non_disruptive (D-A); in human_only,
        only the card. Nothing else moves: every VM ends as it was, but for what those
        rules closed."""
        fault = data.draw(_FAULTS, label="fault")
        _CURRENT.mode = data.draw(st.sampled_from(["human_only", "non_disruptive"]), label="mode")
        cutting = self._cutting_orphans() if _CURRENT.mode != "human_only" else set()
        world = self._world()
        cleared = {**world, "nsgs": {k: {**g, "rules": {n: r for n, r in g["rules"].items() if (k, n) not in cutting}}
                                     for k, g in world["nsgs"].items()}}
        flows, states = self._before()
        expected = {vm: open_flows(cleared, vm) for vm in self.live}
        nics_before = {k: n["nsg"] for k, n in self.fake.nics.items()}
        _, err = self._run(fault, self._orphan_sweep, "orphan sweep")
        _note(f"orphan sweep: {len(cutting)} cutting")
        after = self._flows()
        for vm in self.live:
            assert flows[vm] <= after[vm], f"U1: the orphan sweep cut {vm} off"
            assert after[vm] <= expected[vm] | flows[vm], f"U1: the orphan sweep opened more of {vm} than orphans closed"
            assert self._state(vm) == states[vm], f"U1: the orphan sweep changed the state of {vm}"
        assert {k: n["nsg"] for k, n in self.fake.nics.items()} == nics_before, "U1: the orphan sweep wrote a NIC"
        if fault is None and err is None and not self.fake.write_denied and _CURRENT.mode != "human_only":
            left = self._cutting_orphans(spare=self._held())
            # Kept by I5 (I5Q): taken off, it would let through what one of our rules,
            # turned into an allow by someone, lets pass — then it is said, not taken off.
            behind = self._behind_turned(left)
            assert not left - set(behind), (
                f"U1: live VMs still cut off by orphan rules after the sweep: {sorted(left - set(behind))}")
            # Said with what holds it (the review of I5Q): a pending card names a rule the
            # test's journal says turned behind it, and doesn't say first to delete the
            # deny — that would open the VM. A card said before the turn that never names
            # it is not enough.
            cards = [e for e in escalations.pending() if e.get("action") == "remove_orphan_rule"]
            for (k, name), vms in behind.items():
                turned = {t.lower() for t in self.turned_for.get((k, name), ())}
                # By the whole name: the perimeter's begins every VM rule of its IP.
                import re
                naming = [e for e in cards if key(e.get("resource_id", "")) in vms | {k}       # its VM, or its NSG
                          and any(re.search(re.escape(t) + r"(?![\w-])", (e.get("reason") or "").lower())
                                  for t in turned)]
                assert naming, (f"U1: the orphan rule {name} kept behind a rule turned into an allow "
                                f"({sorted(turned)}), cutting {sorted(vms)}: no pending card names it")
                assert all(not (e.get("suggested_steps") or [""])[0].startswith("az network nsg rule delete")
                           for e in naming), f"U1: the card of {name}, kept, says first to delete it"

    @invariant()
    def orphans_are_reported(self):
        """U1: a rule left by a NIC that no longer exists, aimed at an address a live NIC
        holds now, cuts that NIC off — Glorfindel must say so (find_orphan_rules feeds a
        card). The rule's owner is told by the hash in its name, recomputed here."""
        if not getattr(self, "design", None) or not self.deleted:
            return
        gone = {_nic_hash(n) for nics in self.deleted.values() for n in nics}
        live_ips = {ip for n in self.fake.nics.values() for ip in n["ips"]}
        harmful = set()
        for g in self.fake.nsgs.values():
            for name, r in g["rules"].items():
                if not name.startswith(("glorfindel-iso-", "glorfindel-block-")) or r["access"].lower() != "deny":
                    continue
                if not any(h in name for h in gone):
                    continue
                side = "destination" if r["direction"].lower() == "inbound" else "source"
                if live_ips & set([r.get(f"{side}_address_prefix")] + list(r.get(f"{side}_address_prefixes") or [])):
                    harmful.add((key(g["id"]), name))
        if not harmful:
            return
        reported, err = self._run(None, lambda: self.connector.find_orphan_rules())
        assert err is None, f"U1: orphan rules not listed: {err}"
        got = {(key(o["nsg_id"]), o["rule"].lower()) for o in reported}
        assert harmful <= got, f"U1: orphan rules cutting a live NIC off, not reported: {sorted(harmful - got)}"

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
    monkeypatch.setattr(orphans, "_configured_mode", lambda autonomy, name: _CURRENT.mode)
    monkeypatch.setattr(config, "_DEFAULT_PATHS", list(config._DEFAULT_PATHS))
    monkeypatch.delenv("GLORFINDEL_QUARANTINE_NSG", raising=False)
    from datetime import datetime as _dt, timedelta as _td

    class _Clock(_dt):
        """The reassertion's clock, which the sequence can move forward (time_passes)."""
        @classmethod
        def now(cls, tz=None):
            return _dt.now(tz) + _td(minutes=_CURRENT.clock)
    monkeypatch.setattr(reassert, "datetime", _Clock)
    monkeypatch.setattr(actions, "_vm_lock", _scheduled(actions._vm_lock))
    monkeypatch.setattr(actions, "_quarantine_lock", _scheduled(actions._quarantine_lock))
    # The escalations store's lock (SEC3) too: a thread stopped at its write inside it
    # left the other blocked there, out of the scheduler's sight (I3F, #292).
    monkeypatch.setattr(locks, "_file_lock", _scheduled(locks._file_lock))


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
        print(f"{_LONGEST_IDLE[0]:7d}  longest run of turns only on taken locks (limit {_IDLE_TURNS})")
