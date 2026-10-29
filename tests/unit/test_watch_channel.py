"""#159: the return channel carries the hosted watch's heartbeat and its detections back to
a run launched from Orodruin — only the VMs an exercise window covers, a heartbeat only
once every detection is delivered, and a miss proven only by a heartbeat that can vouch
for it. Everything else falls toward ``unknown``. The contract gives Orodruin a read on
that container, never a write. Mutants M109–M113 (scripts/mutation_check.py) are measured
here."""
import base64
import json
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

import eregion_core.orodruin as orodruin
import eregion_core.watch_channel as wc

URL = "https://storodruin.blob.core.windows.net/watch"
VM = "/subscriptions/s/resourceGroups/rg-celebrimbor/providers/Microsoft.Compute/virtualMachines/vm-celebrimbor-gondolin"
OTHER = "/subscriptions/s/resourceGroups/rg-prod/providers/Microsoft.Compute/virtualMachines/vm-billing"
CRED = SimpleNamespace(get_token=lambda scope: SimpleNamespace(token="tok"))
T0 = datetime(2026, 10, 20, 12, 13, 29, tzinfo=timezone.utc)


def _window(run_id="20261020T121319Z", start=T0, end=None, targets=(VM,)):
    return {"run_id": run_id, "targets": [t.lower() for t in targets],
            "start": start.isoformat(), "end": end.isoformat() if end else None,
            "expires": (start + timedelta(hours=2)).isoformat()}


def _detection(resource_id=VM, at=T0 + timedelta(minutes=2, seconds=29),
               attribution="asset", sid="rule-t1136-001-v1-ab12cd34"):
    """What the RulePoller dispatches (glorfindel/detection_rules.py, _signal) — the
    Log Analytics resource id, in lower case."""
    return {"signal_id": sid, "event": "detection", "ttp": "T1136.001",
            "resource_id": resource_id.lower(), "timestamp": at.isoformat(),
            "context": {"rule_name": "t1136-001-v1", "attribution": attribution,
                        "run_id": "watch-t1136-001-v1-20261020T121559Z"}}


class Store:
    """The container: what was written, by name; a write can be made to fail."""

    def __init__(self):
        self.blobs: dict[str, dict] = {}
        self.order: list[str] = []
        self.refuse: set[str] = set()

    def put(self, url, headers, data, timeout):
        name = url[len(URL) + 1:]
        assert headers["Authorization"] == "Bearer tok"
        if any(name.startswith(p) for p in self.refuse):
            return SimpleNamespace(ok=False, status_code=503)
        self.blobs[name] = json.loads(data)
        self.order.append(name)
        return SimpleNamespace(ok=True, status_code=201)


def _publisher(store, windows):
    return wc.Publisher(URL, credential=CRED, put=store.put, windows=lambda: windows,
                        now=T0 - timedelta(hours=1))


# ── the watch's side ───────────────────────────────────────────────────────────

def test_without_a_channel_the_watch_publishes_nothing(monkeypatch):
    monkeypatch.delenv(wc.CHANNEL_ENV, raising=False)
    assert wc.start() is None


def test_a_detection_in_a_window_is_delivered_before_the_heartbeat():
    store, w = Store(), _window()
    pub = _publisher(store, [w])
    pub.note(_detection())
    pub.tick(now=T0 + timedelta(minutes=3))
    name = f"detections/{w['run_id']}/rule-t1136-001-v1-ab12cd34.json"
    assert store.order == [name, "heartbeat.json"]
    d = store.blobs[name]
    assert d == {"event": "detection", "signal_id": "rule-t1136-001-v1-ab12cd34",
                 "ttp": "T1136.001", "resource_id": VM.lower(),
                 "detected_at": (T0 + timedelta(minutes=2, seconds=29)).isoformat(),
                 "rule": "t1136-001-v1", "watch_run_id": "watch-t1136-001-v1-20261020T121559Z",
                 "exercise_run": w["run_id"]}
    beat = store.blobs["heartbeat.json"]
    assert beat == {"at": (T0 + timedelta(minutes=3)).isoformat(),
                    "since": (T0 - timedelta(hours=1)).isoformat(),
                    "windows": [w["run_id"]],
                    "perimeter": ""}   # SEC5 (N-03): no AZURE_SUBSCRIPTION_ID in the tests


def test_the_rest_of_the_fleet_is_never_published():
    """M110: only a VM a window covers at the detection's time — not another VM, not the
    same VM before the window opened, not a row the watch could not attribute."""
    store = Store()
    pub = _publisher(store, [_window()])
    pub.note(_detection(resource_id=OTHER, sid="rule-a-1"))
    pub.note(_detection(at=T0 - timedelta(minutes=5), sid="rule-a-2"))
    pub.note(_detection(attribution="unattributed", sid="rule-a-3"))
    pub.note({**_detection(sid="rule-a-4"), "event": "attack_started"})
    pub.tick(now=T0 + timedelta(minutes=3))
    assert store.order == ["heartbeat.json"]


def test_a_closed_window_still_counts_during_its_grace_then_lapses():
    store = Store()
    w = _window(end=T0 + timedelta(minutes=3))
    pub = _publisher(store, [w])
    pub.note(_detection(at=T0 + timedelta(minutes=10), sid="rule-a-1"))   # in the grace
    pub.note(_detection(at=T0 + timedelta(minutes=30), sid="rule-a-2"))   # after it
    pub.tick(now=T0 + timedelta(minutes=31))
    assert [n for n in store.order if n.startswith("detections/")] == \
        [f"detections/{w['run_id']}/rule-a-1.json"]
    assert store.blobs["heartbeat.json"]["windows"] == []  # lapsed by now


def test_a_detection_seen_before_its_window_is_delivered_when_the_window_arrives():
    """The window comes through the exercise channel, the detection through the RulePoller:
    either may come first."""
    store, windows = Store(), []
    pub = _publisher(store, windows)
    pub.note(_detection())
    pub.tick(now=T0 + timedelta(minutes=3))
    assert store.order == ["heartbeat.json"]
    assert store.blobs["heartbeat.json"]["windows"] == []  # the run cannot conclude a miss
    windows.append(_window())
    pub.tick(now=T0 + timedelta(minutes=5))
    assert store.order[-2:] == [f"detections/{windows[0]['run_id']}/rule-t1136-001-v1-ab12cd34.json",
                                "heartbeat.json"]


def test_no_heartbeat_while_a_detection_waits_to_be_delivered():
    """M109: a heartbeat vouches that everything before it was delivered — written over an
    undelivered detection, it would let a run conclude to a miss the watch did detect."""
    store = Store()
    store.refuse.add("detections/")
    pub = _publisher(store, [_window()])
    pub.note(_detection())
    pub.tick(now=T0 + timedelta(minutes=3))
    assert store.order == []
    store.refuse.clear()
    pub.tick(now=T0 + timedelta(minutes=3, seconds=5))
    assert store.order[0].startswith("detections/") and store.order[-1] == "heartbeat.json"


def test_each_detection_is_delivered_once_and_the_heartbeat_once_a_minute():
    store = Store()
    pub = _publisher(store, [_window()])
    pub.note(_detection())
    for s in (0, 5, 10, 55):
        pub.tick(now=T0 + timedelta(minutes=3, seconds=s))
    assert len(store.order) == 2
    pub.tick(now=T0 + timedelta(minutes=4))
    assert store.order[-1] == "heartbeat.json" and len(store.order) == 3


def test_a_detection_the_watch_could_not_note_moves_since():
    """A detection lost is a restart of what the watch vouches for."""
    pub = _publisher(Store(), [])
    before = pub.since
    pub.note({"event": "detection", "context": "not a dict"})
    assert pub.since > before


def test_a_window_with_an_unsafe_run_id_is_never_written_nor_vouched_for():
    store = Store()
    pub = _publisher(store, [_window(run_id="../evil")])
    pub.note(_detection())
    pub.tick(now=T0 + timedelta(minutes=3))
    assert store.order == ["heartbeat.json"] and store.blobs["heartbeat.json"]["windows"] == []


# ── the run's side ─────────────────────────────────────────────────────────────

def _listing(*names, marker=""):
    items = "".join(f"<Blob><Name>{n}</Name></Blob>" for n in names)
    return (f"<EnumerationResults><Blobs>{items}</Blobs>"
            f"<NextMarker>{marker}</NextMarker></EnumerationResults>").encode()


def test_the_run_reads_only_its_own_detections_page_by_page():
    run = "20261020T121319Z"
    calls = []

    def get(url, headers, timeout, params=None):
        calls.append((url, params))
        if params and not params.get("marker"):
            return SimpleNamespace(ok=True, content=_listing(
                f"detections/{run}/rule-a-1.json", f"detections/{run}/../x.json", marker="m2"))
        if params:
            return SimpleNamespace(ok=True, content=_listing(f"detections/{run}/rule-a-2.json"))
        return SimpleNamespace(ok=True, content=json.dumps({"signal_id": url[-13:-5]}).encode())

    got = wc.read_detections(run, channel=URL, credential=CRED, get=get)
    assert [d["signal_id"] for d in got] == ["rule-a-1", "rule-a-2"]
    assert calls[0][1]["prefix"] == f"detections/{run}/"
    assert all("../" not in url for url, _ in calls)


@pytest.mark.parametrize("status", [403, 404, 503])
def test_an_unreadable_channel_raises_never_reads_as_empty(status):
    """A listing that fails is never "no detection": the run's wait turns it into
    ``unknown`` (Annatar, after #157)."""
    def get(url, headers, timeout, params=None):
        return SimpleNamespace(ok=False, status_code=status, content=b"")
    with pytest.raises(RuntimeError, match=str(status)):
        wc.read_detections("r1", channel=URL, credential=CRED, get=get)
    with pytest.raises(RuntimeError, match=str(status)):
        wc.read_heartbeat(channel=URL, credential=CRED, get=get)


def test_without_a_channel_the_run_cannot_read_it(monkeypatch):
    monkeypatch.delenv(wc.CHANNEL_ENV, raising=False)
    with pytest.raises(RuntimeError, match=wc.CHANNEL_ENV):
        wc.read_heartbeat()
    with pytest.raises(ValueError):
        wc.read_detections("../x", channel=URL, credential=CRED, get=MagicMock())


ATTACK = T0 + timedelta(seconds=32)
UNTIL = T0 + timedelta(minutes=15)
GOOD = {"at": (UNTIL + timedelta(seconds=20)).isoformat(),
        "since": (T0 - timedelta(hours=21)).isoformat(),
        "windows": ["20261020T121319Z"]}


def test_a_heartbeat_after_the_wait_from_a_watch_that_knows_the_run_proves_a_miss():
    assert wc.miss_unprovable(GOOD, run_id="20261020T121319Z", attack_time=ATTACK, until=UNTIL) == ""


@pytest.mark.parametrize("change, reason", [
    ({"at": (UNTIL - timedelta(seconds=1)).isoformat()}, "since the end of the wait"),
    ({"since": (ATTACK + timedelta(seconds=1)).isoformat()}, "restarted"),     # M112
    ({"windows": ["another-run"]}, "does not know the run's window"),         # M111
    ({"windows": None}, "does not know the run's window"),
    ({"at": "garbage"}, "unreadable"),
])
def test_a_heartbeat_that_cannot_vouch_leaves_the_run_unknown(change, reason):
    """M111, M112: a watch that never received the window published nothing for it; a
    watch restarted after the attack lost what it noted before — neither proves a miss."""
    got = wc.miss_unprovable({**GOOD, **change}, run_id="20261020T121319Z",
                             attack_time=ATTACK, until=UNTIL)
    assert reason in got


def test_alive_is_the_local_heartbeat_test():
    beat = {"at": T0.isoformat()}
    assert wc.alive(beat, now=T0 + timedelta(seconds=89))
    assert not wc.alive(beat, now=T0 + timedelta(seconds=91))
    assert not wc.alive({}, now=T0)


# ── the contract and the return channel ───────────────────────────────────────

SUB = "sub-123"
BENCH = f"/subscriptions/{SUB}/resourceGroups/rg-celebrimbor"
ACCOUNT = (f"/subscriptions/{SUB}/resourceGroups/rg-orodruin/providers/Microsoft.Storage"
           "/storageAccounts/storodruin/blobServices/default/containers")
EXERCISES, WATCH = f"{ACCOUNT}/exercises", f"{ACCOUNT}/watch"
RIGHTS = [{"actions": list(orodruin.READ_ACTIONS)}]
# SEC5 (V-29): reads on the group, the writes on each enrolled VM and experiment.
BENCH_READ = list(orodruin.READ_ACTIONS)
ENROLLED = [(f"{BENCH}/providers/Microsoft.Compute/virtualMachines/vm-1", "vm-act"),
            (f"{BENCH}/providers/Microsoft.Chaos/experiments/exp-1", "chaos-act")]
ACT = {"vm-act": list(orodruin.VM_ACTIONS), "chaos-act": list(orodruin.CHAOS_ACTIONS)}
# The built-in roles' definitions, as role_actions reads them (data actions marked).
READER = ["Microsoft.Storage/storageAccounts/blobServices/containers/read",
          "Microsoft.Storage/storageAccounts/blobServices/generateUserDelegationKey/action",
          "data:Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read"]
CONTRIBUTOR = READER + ["data:Microsoft.Storage/storageAccounts/blobServices/containers/blobs/write",
                        "data:Microsoft.Storage/storageAccounts/blobServices/containers/blobs/delete"]


def _assess(assignments, roles, *, channel=EXERCISES, watch=WATCH):
    listed = [{"properties": {"scope": s, "roleDefinitionId": r}} for s, r in [*assignments, *ENROLLED]]
    roles = {**ACT, **roles}
    return orodruin.assess_identity(listed, lambda r: roles[r], RIGHTS, BENCH,
                                    sees_subscription=True, channel=channel, watch=watch)


def test_a_read_on_the_return_channel_is_allowed_outside_the_bench():
    roles = {"bench": BENCH_READ, "contributor": CONTRIBUTOR, "reader": READER}
    assert _assess([(BENCH, "bench"), (EXERCISES, "contributor"), (WATCH, "reader")], roles) == []


def test_a_write_on_the_return_channel_leaves_orodruin_passive():
    """M113: the injector must never be able to write what the watch says."""
    roles = {"bench": BENCH_READ, "contributor": CONTRIBUTOR, "wild": ["data:Microsoft.Storage/*"]}
    for role in ("contributor", "wild"):
        missing = _assess([(BENCH, "bench"), (WATCH, role)], roles)
        assert [m["code"] for m in missing] == ["identity_outside_bench"]
        assert "not read-only" in missing[0]["detail"]


def test_a_return_channel_declared_on_the_exercise_container_still_refuses_a_writer():
    roles = {"bench": BENCH_READ, "contributor": CONTRIBUTOR}
    missing = _assess([(BENCH, "bench"), (EXERCISES, "contributor")], roles, watch=EXERCISES)
    assert [m["code"] for m in missing] == ["identity_outside_bench"]


def test_a_read_elsewhere_than_the_declared_container_is_outside():
    roles = {"bench": BENCH_READ, "reader": READER}
    other = f"{ACCOUNT}/other"
    assert _assess([(BENCH, "bench"), (other, "reader")], roles)
    assert orodruin.watch_scope({"EREGION_WATCH_CHANNEL_SCOPE": f"/subscriptions/{SUB}"}) == ""
    assert orodruin.watch_scope({"EREGION_WATCH_CHANNEL_SCOPE": WATCH + "/"}) == WATCH


def _token(oid):
    payload = base64.urlsafe_b64encode(json.dumps({"oid": oid}).encode()).decode().rstrip("=")
    return f"h.{payload}.s"


@pytest.mark.parametrize("data_actions, armed", [
    (["Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read"], True),
    (["Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read",
      "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/write"], False),
])
def test_read_identity_reads_the_data_actions_of_the_role(monkeypatch, data_actions, armed):
    """The role's data actions are what tells a reader from a writer: read from its
    definition, as Azure returns it."""
    monkeypatch.setenv("AZURE_SUBSCRIPTION_ID", SUB)
    monkeypatch.setenv(orodruin.WATCH_SCOPE_ENV, WATCH)
    credential = MagicMock()
    credential.get_token.return_value.token = _token("oid-orodruin")

    def get(url, headers, params, timeout):
        r = MagicMock(ok=True)
        if url.endswith("/roleAssignments"):
            r.json.return_value = {"value": [
                {"properties": {"scope": BENCH, "roleDefinitionId": "/defs/injector"}},
                {"properties": {"scope": WATCH, "roleDefinitionId": "/defs/blob"}},
                *({"properties": {"scope": s, "roleDefinitionId": f"/defs/{r}"}} for s, r in ENROLLED)]}
        elif url.endswith(f"/subscriptions/{SUB}/providers/Microsoft.Authorization/permissions"):
            r.json.return_value = {"value": [{"actions": ["Microsoft.Authorization/roleAssignments/read"]}]}
        elif url.endswith("/permissions"):
            r.json.return_value = {"value": RIGHTS}
        elif url.endswith(("/defs/vm-act", "/defs/chaos-act")):
            r.json.return_value = {"properties": {"permissions": [{"actions": ACT[url.rsplit("/", 1)[1]]}]}}
        else:
            r.json.return_value = {"properties": {"permissions": [{
                "actions": READER[:2], "dataActions": data_actions}]}}
        return r

    missing = orodruin.read_identity(credential=credential, get=get)
    assert (missing == []) is armed


# ── the run's wait through the channel (Annatar, after #157) ──────────────────

from tests.unit.test_annatar_detection import (  # noqa: E402
    TTP as RUN_TTP, WATCH_RID, _iso, _wait, waiting)  # noqa: F401  (waiting: a fixture)


def _epoch(iso):
    return datetime.fromisoformat(iso).timestamp()


class FakeChannel:
    """The hosted watch seen from Orodruin: a heartbeat it keeps writing (``lag`` behind
    the clock), its detections, a channel that can break at a given time."""

    def __init__(self, clock, *, windows=("rid",), restarted_at=None, detections=(),
                 break_at=None, beating=True):
        self.clock, self.windows, self.detections = clock, list(windows), list(detections)
        self.since = restarted_at if restarted_at is not None else clock.now - 86_400
        self.break_at, self.beating, self.start = break_at, beating, clock.now
        self.reads = 0

    def _check(self):
        if self.break_at is not None and self.clock.now >= self.break_at:
            raise RuntimeError("HTTP 503 reading the watch channel")

    def read_heartbeat(self):
        """Like the real watch: no heartbeat while a detection it saw waits for delivery."""
        self._check()
        at = self.clock.now if self.beating else self.start
        pending = [_epoch(d["detected_at"]) for d in self.detections
                   if _epoch(d["detected_at"]) <= self.clock.now < d.get("_after", 0)]
        if pending:
            at = min(at, min(pending) - 1)
        return {"at": _iso(at), "since": _iso(self.since), "windows": self.windows}

    def read_detections(self, run_id):
        self._check()
        self.reads += 1
        return [{k: v for k, v in d.items() if k != "_after"} for d in self.detections
                if d.get("_after", 0) <= self.clock.now]


@pytest.fixture
def remote(waiting, monkeypatch):  # noqa: F811  (the imported fixture)
    """The run on Orodruin: no local watch, the hosted one reached through the channel."""
    (waiting.runs.parent / "home" / ".glorfindel" / "watch_heartbeat").unlink()
    monkeypatch.setenv(wc.CHANNEL_ENV, URL)

    def install(**kw):
        fake = FakeChannel(waiting.clock, **kw)
        monkeypatch.setattr(wc, "read_heartbeat", lambda **_: fake.read_heartbeat())
        monkeypatch.setattr(wc, "read_detections", lambda run_id, **_: fake.read_detections(run_id))
        return fake
    waiting.install = install
    return waiting


def _channel_detection(seen):
    return {"event": "detection", "ttp": RUN_TTP, "resource_id": WATCH_RID,
            "detected_at": _iso(seen), "rule": "t1136-001-v1"}


def test_a_detection_in_the_channel_is_the_run_s_with_its_latency(remote):
    attack = remote.clock.now - 150
    remote.install(detections=[_channel_detection(attack + 117.5)])
    engine, emitted = _wait(attack)
    assert (engine._detection_result, engine._detection_latency_s) == ("detected", 117.5)
    assert emitted == []


def test_a_detection_delivered_after_the_wait_still_counts(remote):
    attack = remote.clock.now - 30
    start = remote.clock.now
    # Seen near the end of the wait, delivered only after it: the settling read finds it.
    late = {**_channel_detection(attack + 700), "_after": start + 725}
    remote.install(detections=[late])
    engine, emitted = _wait(attack)
    assert (engine._detection_result, engine._detection_latency_s) == ("detected", 700.0)
    assert emitted == [] and remote.clock.now >= start + 720


def test_a_miss_the_hosted_watch_vouches_for_is_a_miss(remote):
    attack = remote.clock.now - 30
    remote.install()
    engine, emitted = _wait(attack)
    assert engine._detection_result == "missed"
    assert emitted == ["detection_missed"]


@pytest.mark.parametrize("kw", [
    {"break_at": "mid-wait"},                 # the channel is cut during the wait
    {"windows": ["another-run"]},             # the window never reached the watch
    {"restarted_at": "after the attack"},     # the watch lost what it noted before
    {"beating": False},                       # no heartbeat after the wait
], ids=["cut", "window-unknown", "restarted", "stale"])
def test_a_silence_the_watch_cannot_vouch_for_is_unknown(remote, kw):
    """M114, M115: a channel cut, a window the watch never had, a restart, a heartbeat that
    stops — the run writes unknown and emits no detection_missed (which would make
    Glorfindel propose a rule for a technique it may well have caught)."""
    attack = remote.clock.now - 30
    start = remote.clock.now
    if kw.get("break_at") == "mid-wait":
        kw["break_at"] = start + 300
    if kw.get("restarted_at") == "after the attack":
        kw["restarted_at"] = attack + 60
    remote.install(**kw)
    engine, emitted = _wait(attack)
    assert engine._detection_result == "unknown"
    assert engine._detection_latency_s is None
    assert emitted == []
    assert remote.clock.now <= start + 720 + wc.SETTLE_S + wc.TICK_S


def test_an_unreachable_channel_and_no_local_watch_measure_nothing(remote):
    attack = remote.clock.now - 30
    remote.install(break_at=remote.clock.now)
    engine, emitted = _wait(attack)
    assert engine._detection_result == "unknown" and emitted == []
