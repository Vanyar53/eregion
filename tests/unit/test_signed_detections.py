"""SEC21 (#530): the detections of the return channel signed by the watch's key, under their own
domain, and verified by the injectors with the key they pin (``EREGION_WATCH_KEY``) — as the
heartbeat is (SEC19, tests/unit/test_watch_key.py).

A detection that is unsigned, signed by another key or for another use, changed after it was
signed, or copied from another run or another signal is never counted for « seen »: the run says
it — in its console, in Orodruin's journal, in its report — and, refused alone, it is ``unknown``,
never ``missed``. On the fake container of the channel (tests/unit/fake_container.py): no
network, no Azure, a fake clock; the keys are fixed seeds, never a real key. Mutants M3700–M3724
(scripts/mutants/SEC21.py) are measured here.
"""
from __future__ import annotations

import json
import time as _time
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import patch

import pytest

import eregion_core.watch_channel as wc
import eregion_core.watch_gate as gate
import eregion_core.watch_key as watch_key
from annatar.runner import engine as engine_module
from annatar.runner.engine import Engine
from tests.unit.fake_container import CRED, FakeContainer

URL = "https://exampleaccount.blob.core.windows.net/watch"
WATCH = watch_key.Signer(bytes(range(32)))            # the watch's key, a fixed seed
OTHER = watch_key.Signer(bytes(range(1, 33)))         # another watch's
RUN = "20261104T101500Z"
VM = ("/subscriptions/00000000-0000-0000-0000-00000000aaaa/resourcegroups/rg-celebrimbor"
      "/providers/microsoft.compute/virtualmachines/vm-celebrimbor-gondolin")
T0 = datetime(2026, 11, 4, 10, 15, tzinfo=timezone.utc)
SID = "rule-t1136-001-v1-ab12cd34"
REAL_READ_NAMED = wc.read_named


@pytest.fixture
def pinned(monkeypatch):
    """The injector pins the watch's public key — its environment's, nothing else."""
    monkeypatch.setenv(watch_key.KEY_ENV, watch_key.public_text(WATCH.public))


def _window(run_id=RUN):
    return {"run_id": run_id, "targets": [VM], "start": T0.isoformat(), "end": None,
            "expires": (T0 + timedelta(hours=2)).isoformat()}


def _signal(sid=SID, at=T0 + timedelta(minutes=2)):
    """What the RulePoller dispatches (glorfindel/detection_rules.py)."""
    return {"signal_id": sid, "event": "detection", "ttp": "T1136.001", "resource_id": VM,
            "timestamp": at.isoformat(),
            "context": {"rule_name": "t1136-001-v1", "attribution": "asset", "run_id": "watch-t1136-x"}}


def _published(signer=WATCH, windows=None) -> FakeContainer:
    """The watch publishes one detection of RUN's window on the fake container."""
    c = FakeContainer(URL)
    pub = wc.Publisher(URL, credential=CRED, put=c.put, signer=signer,
                       windows=lambda: windows or [_window()], now=T0 - timedelta(hours=1))
    pub.note(_signal())
    pub.tick(now=T0 + timedelta(minutes=3))
    return c


def _blob(run=RUN, sid=SID) -> str:
    return f"{wc.DETECTIONS}/{run}/{sid}.json"


def _file(c: FakeContainer, name: str, body) -> None:
    """Someone who can write the channel files a blob there (WC1: not only the watch)."""
    c.put(f"{URL}/{name}", headers={}, data=json.dumps(body).encode())


def _vouched(c: FakeContainer, run=RUN):
    """(kept, refused) — the total of refusals is read where it is the point."""
    return wc.vouched_detections(run, channel=URL, credential=CRED, get=c.get)[:2]


# ── The watch signs, the injector believes ────────────────────────────────────────────

def test_a_detection_the_pinned_key_signed_is_believed(pinned):
    """M3700, M3702: every detection published carries the watch's fingerprint and its signature
    — believed with the key pinned, nothing refused."""
    c = _published()
    body = json.loads(c.body(_blob()))
    assert body["key"] == WATCH.fingerprint and len(body["sig"]) == 88
    kept, refused = _vouched(c)
    assert refused == [] and [d["signal_id"] for d in kept] == [SID]
    assert kept[0]["exercise_run"] == RUN and kept[0]["detected_at"] == (T0 + timedelta(minutes=2)).isoformat()


def test_the_signature_covers_the_run_the_signal_what_was_seen_and_when(pinned):
    """What is signed is the domain, then every field but ``sig`` — run, signal, technique,
    resource, rule, time."""
    body = json.loads(_published().body(_blob()))
    signed = watch_key.message(watch_key.DOMAIN_DETECTION, body)
    assert signed.startswith(b"eregion.watch-detection/1\n")
    for field in ("exercise_run", "signal_id", "ttp", "resource_id", "rule", "detected_at", "event",
                  "watch_run_id", "key"):
        assert f'"{field}":'.encode() in signed
    assert b'"sig"' not in signed


def test_the_detection_domain_is_never_the_heartbeat_s():
    assert watch_key.DOMAIN_DETECTION != watch_key.DOMAIN_BEAT
    assert watch_key.DOMAIN_DETECTION == "eregion.watch-detection/1"


# ── Each refusal: never counted, said ─────────────────────────────────────────────────

def _signed_body(signer=WATCH, run=RUN, sid=SID, **over) -> dict:
    body = {"event": "detection", "signal_id": sid, "ttp": "T1136.001", "resource_id": VM,
            "detected_at": (T0 + timedelta(minutes=2)).isoformat(), "rule": "t1136-001-v1",
            "watch_run_id": "watch-t1136-x", "exercise_run": run}
    return {**watch_key.sign_detection(body, signer), **over}


def _under_another_domain() -> dict:
    """The pinned key's signature, made for a heartbeat: the same key, another use."""
    body = {k: v for k, v in _signed_body().items() if k != "sig"}
    return {**body, "sig": WATCH.sign(watch_key.DOMAIN_BEAT, body)}


def _claims_the_pinned_key() -> dict:
    """Signed by another key, claiming the pinned one's fingerprint."""
    body = {k: v for k, v in _signed_body().items() if k not in ("key", "sig")}
    body["key"] = WATCH.fingerprint
    return {**body, "sig": OTHER.sign(watch_key.DOMAIN_DETECTION, body)}


REFUSALS = [
    # (what is filed under detections/RUN/SID.json, what the refusal says) — M3701, M3703–M3708
    ({k: v for k, v in _signed_body().items() if k not in ("key", "sig")}, "unsigned"),
    (_signed_body(signer=OTHER), "signed by another key"),
    (_claims_the_pinned_key(), "its signature does not hold"),
    (_under_another_domain(), "its signature does not hold"),
    (_signed_body(ttp="T1059.004"), "its signature does not hold"),
    (_signed_body(detected_at=(T0 + timedelta(seconds=1)).isoformat()), "its signature does not hold"),
    (_signed_body(resource_id=VM.replace("gondolin", "bree")), "its signature does not hold"),
    (_signed_body(extra="a field more"), "its signature does not hold"),
    ({k: v for k, v in _signed_body().items() if k != "rule"}, "its signature does not hold"),
    (_signed_body(detected_at=1793787300), "its signature does not hold"),
    (_signed_body(run="20261103T090000Z"), "a detection of another run"),
    (_signed_body(sid="rule-t1136-001-v1-ffffffff"), "a detection of another signal"),
    (_signed_body(sig="A" * 86 + "=="), "its signature does not hold"),
    (_signed_body(sig="not a signature"), "its signature is not one"),
    (["not", "an", "object"], "not a JSON object"),
]


@pytest.mark.parametrize("body, said", REFUSALS, ids=[
    "unsigned", "another-key", "claims-the-pinned-key", "another-domain", "technique-changed",
    "time-changed", "resource-changed", "field-added", "field-removed", "type-changed",
    "another-run", "another-signal",
    "forged-signature", "no-signature", "not-an-object"])
def test_a_detection_the_pinned_key_did_not_sign_for_this_run_and_signal_is_refused(pinned, body, said):
    c = FakeContainer(URL)
    _file(c, _blob(), body)
    kept, refused = _vouched(c)
    assert kept == []
    assert len(refused) == 1 and refused[0].startswith(f"{_blob()}: ") and said in refused[0]


def test_a_detection_copied_from_another_run_is_refused_there_and_believed_in_its_own(pinned):
    """M3707: the same signed blob, under another run's prefix — its own run believes it, the
    other never does."""
    c = _published()
    _file(c, _blob(run="20261104T120000Z"), json.loads(c.body(_blob())))
    assert [d["signal_id"] for d in _vouched(c)[0]] == [SID]
    kept, refused = _vouched(c, run="20261104T120000Z")
    assert kept == [] and "another run" in refused[0]


def test_a_detection_copied_under_another_signal_s_name_is_refused(pinned):
    """M3708: filed again under another name in its own run — the copy is refused, the original
    kept."""
    c = _published()
    _file(c, _blob(sid="rule-x-copy"), json.loads(c.body(_blob())))
    kept, refused = _vouched(c)
    assert [d["signal_id"] for d in kept] == [SID]
    assert refused == [f"{_blob(sid='rule-x-copy')}: a detection of another signal ('{SID}') copied under this name"]


def test_without_a_key_pinned_no_detection_counts_and_the_gate_refuses_as_sec19_does(monkeypatch):
    """M3709: no key pinned — every detection refused with SEC19's own words and gesture, and the
    gate refuses the run before it (SEC19)."""
    monkeypatch.delenv(watch_key.KEY_ENV, raising=False)
    kept, refused = _vouched(_published())
    assert kept == [] and len(refused) == 1
    assert f"no watch key pinned ({watch_key.KEY_ENV})" in refused[0] and "make watch-key" in refused[0]
    assert watch_key.proof({"at": T0.isoformat()}).startswith(f"no watch key pinned ({watch_key.KEY_ENV})")


def test_the_refusals_of_one_read_are_bounded_and_all_counted(pinned):
    """M3710, M3721: a writer of the channel may file many — a read keeps MAX_REFUSED to say, no
    more, and counts them all: 25 refused say 25."""
    c = FakeContainer(URL)
    for n in range(wc.MAX_REFUSED + 5):
        _file(c, _blob(sid=f"rule-forged-{n:03d}"), {"event": "detection"})
    kept, refused, total = wc.vouched_detections(RUN, channel=URL, credential=CRED, get=c.get)
    assert kept == [] and len(refused) == wc.MAX_REFUSED and total == 25


def test_a_fingerprint_the_channel_claims_is_said_printable_only(pinned):
    """M3723: the ``key`` a blob claims is the channel's text — never an escape sequence to the
    terminal nor the report, for a detection as for a heartbeat (SEC19)."""
    forged = _signed_body(signer=OTHER, key="SHA256:\x1b[2J\x1b]0;owned\x07abc")
    c = FakeContainer(URL)
    _file(c, _blob(), forged)
    _, refused = _vouched(c)
    assert "signed by another key" in refused[0] and "\x1b" not in refused[0] and "\x07" not in refused[0]
    beat = {**gate.beat_body(T0, signer=OTHER), "key": "SHA256:\x1b[31mred"}
    why = watch_key.verify_beat(beat, WATCH.public)
    assert why.startswith("signed by another key") and "\x1b" not in why


def test_a_watch_without_its_key_publishes_its_detection_unsigned_and_says_it(monkeypatch, tmp_path, capsys, pinned):
    """M3717: without a key the detection goes unsigned — said once in the watch's log — and the
    injector never counts it."""
    blocked = tmp_path / "blocked"
    blocked.write_text("")
    monkeypatch.setattr(watch_key, "KEY_DIR", blocked / "watch-key")
    c = FakeContainer(URL)
    pub = wc.Publisher(URL, credential=CRED, put=c.put, windows=lambda: [_window()],
                       now=T0 - timedelta(hours=1))
    pub.note(_signal())
    pub.note(_signal(sid="rule-t1136-001-v1-ab12cd35"))
    pub.tick(now=T0 + timedelta(minutes=3))
    assert "sig" not in json.loads(c.body(_blob()))
    assert capsys.readouterr().out.count("detection not signed") == 1
    kept, refused = _vouched(c)
    assert kept == [] and all("unsigned" in r for r in refused)


def test_the_local_channel_of_verdicts_keeps_its_exact_fields(tmp_path, monkeypatch, capsys):
    """M3718: SEC18's verdicts hold VERDICT_FIELDS only — no key, no signature, the watch's key
    never asked for: the watch's own directory, the red's view read-only (docs/design/watch-key.md)."""
    blocked = tmp_path / "blocked"
    blocked.write_text("")
    monkeypatch.setattr(watch_key, "KEY_DIR", blocked / "watch-key")
    d = tmp_path / "verdicts"
    d.mkdir()
    v = wc.LocalVerdicts(d, windows=lambda: [_window()])
    v.note(_signal())
    v.tick(now=T0 + timedelta(minutes=3))
    files = list((d / wc.DETECTIONS / RUN).glob("*.json"))
    assert len(files) == 1 and set(json.loads(files[0].read_text())) == set(wc.VERDICT_FIELDS)
    assert "not signed" not in capsys.readouterr().out


# ── The heartbeat unchanged ───────────────────────────────────────────────────────────

def test_the_heartbeat_is_signed_as_before_and_still_believed(pinned, monkeypatch):
    """SEC19's heartbeat keeps its fields, its domain, its counter: the gate believes it."""
    c = _published()
    beat = json.loads(c.body(wc.HEARTBEAT))
    assert set(beat) == {"at", "since", "windows", "perimeter", "seq", "key", "sig", "covers"}   # SEC21b
    assert watch_key.verify_beat(beat, WATCH.public) == ""
    monkeypatch.setenv(wc.CHANNEL_ENV, URL)
    monkeypatch.setattr(gate, "READERS", {"channel": gate.channel_beat, "local": gate.local_beat,
                                          "own": lambda: beat["perimeter"] or "p", "proof": watch_key.proof})
    monkeypatch.setattr(wc, "read_heartbeat", lambda **_: {**beat, "at": datetime.now(timezone.utc).isoformat()})
    assert "its signature does not hold" in gate.refusal()   # its date changed: SEC19 as before
    assert watch_key.proof(dict(beat)) == ""


def test_a_detection_s_signature_never_reads_as_a_heartbeat(pinned):
    """The pinned key's signature, made for a detection, put on a heartbeat — refused (the
    heartbeat's own check, SEC19: the domains keep the uses apart)."""
    body = {k: v for k, v in gate.beat_body(T0, signer=WATCH).items() if k != "sig"}
    forged = {**body, "sig": WATCH.sign(watch_key.DOMAIN_DETECTION, body)}
    assert watch_key.verify_beat(forged, WATCH.public).startswith("its signature does not hold")


# ── The run: never seen, said in the console, the journal and the report ──────────────

class _Clock:
    def __init__(self, start: float):
        self.now = start

    def time(self) -> float:
        return self.now

    def sleep(self, s: float) -> None:
        self.now += s


def _iso(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, timezone.utc).isoformat()


@pytest.fixture
def channel(monkeypatch, pinned):
    """The run on Orodruin, its return channel the fake container read through the real reader;
    a fake clock; a heartbeat that vouches for the run's whole wait."""
    c = FakeContainer(URL)
    clock = _Clock(_time.time())
    monkeypatch.setattr(engine_module, "time", clock)
    monkeypatch.setenv(wc.CHANNEL_ENV, URL)
    monkeypatch.setattr(wc, "read_named",
                        lambda run_id, **_: REAL_READ_NAMED(run_id, channel=URL, credential=CRED, get=c.get))
    monkeypatch.setattr(wc, "read_heartbeat", lambda **_: {
        "at": _iso(clock.now), "since": _iso(clock.now - 86400), "windows": [RUN],
        "covers": {RUN: []}})   # SEC21b: nothing delivered for the run
    monkeypatch.setattr(gate, "channel_beat", lambda: gate.Beat(gate.CHANNEL, datetime.fromtimestamp(clock.now, timezone.utc)))
    return SimpleNamespace(container=c, clock=clock)


def _detection_at(seen: float, signer=WATCH, run=RUN, sid=SID, **over) -> dict:
    body = {"event": "detection", "signal_id": sid, "ttp": "T1136.001", "resource_id": VM,
            "detected_at": _iso(seen), "rule": "t1136-001-v1", "watch_run_id": "watch-t1136-x",
            "exercise_run": run}
    return {**watch_key.sign_detection(body, signer), **over}


def _wait(attack_time: float, session=None):
    engine = Engine()
    engine._session = session
    emitted = []
    scenario = SimpleNamespace(mitre="T1136.001", detection={}, detection_hints={})
    emitter = SimpleNamespace(resource_id=VM, emit=lambda **k: emitted.append(k["event"]))
    engine._wait_and_emit_feedback(RUN, emitter, scenario, 600.0, attack_time)
    return engine, emitted


class _Journal:
    def __init__(self):
        self.lines = []

    def declare(self, what, detail=""):
        self.lines.append((what, detail))


def test_a_signed_detection_is_the_run_s_detection(channel):
    attack = channel.clock.now - 150
    _file(channel.container, _blob(), _detection_at(attack + 117.5))
    engine, emitted = _wait(attack)
    assert (engine._detection_result, engine._detection_latency_s) == ("detected", 117.5)
    assert engine._detection_refused == [] and emitted == []


def test_an_unsigned_detection_is_never_seen_nor_a_miss_and_it_is_said(channel, capsys):
    """M3704, M3711, M3712, M3713, M3716: a watch older than this injector (or a hand on the channel) — the run
    is unknown, never detected, never missed (no detection_missed: no rule proposed); the refusal
    said in the console and in Orodruin's journal, once."""
    attack = channel.clock.now - 150
    unsigned = {k: v for k, v in _detection_at(attack + 60).items() if k not in ("key", "sig")}
    _file(channel.container, _blob(), unsigned)
    journal = _Journal()
    engine, emitted = _wait(attack, session=journal)
    assert engine._detection_result == "unknown" and engine._detection_latency_s is None
    assert emitted == []
    assert len(engine._detection_refused) == 1 and "unsigned" in engine._detection_refused[0]
    assert journal.lines == [("detection_refused", engine._detection_refused[0])]
    out = capsys.readouterr().out
    assert out.count("A detection on the return channel refused") == 1 and "refused (SEC21)" in out
    assert "update Glorfindel" in out   # the passage: what the operator reads, and the gesture


def test_a_forged_detection_beside_a_signed_one_leaves_the_signed_one_counted(channel):
    """M3707: the signed detection counts; the forged one, of another run, is said."""
    attack = channel.clock.now - 150
    _file(channel.container, _blob(sid="rule-forged"), _detection_at(attack + 5, run="20261103T090000Z",
                                                                     sid="rule-forged"))
    _file(channel.container, _blob(), _detection_at(attack + 90))
    engine, _ = _wait(attack)
    assert (engine._detection_result, engine._detection_latency_s) == ("detected", 90.0)
    assert [r.split(": ")[1] for r in engine._detection_refused] == ["a detection of another run ('20261103T090000Z') copied here"]


def test_a_detection_signed_by_another_key_is_never_the_run_s(channel):
    attack = channel.clock.now - 150
    _file(channel.container, _blob(), _detection_at(attack + 60, signer=OTHER))
    engine, emitted = _wait(attack)
    assert engine._detection_result == "unknown" and emitted == []
    assert "signed by another key" in engine._detection_refused[0]


def test_without_a_refusal_a_vouched_silence_is_still_a_miss(channel):
    """The refusals do not turn every silence unknown: nothing filed, a heartbeat that vouches —
    a miss, as before (#159)."""
    attack = channel.clock.now - 30
    engine, emitted = _wait(attack)
    assert engine._detection_result == "missed" and emitted == ["detection_missed"]


def test_a_refused_detection_is_written_in_the_run_s_report(channel, tmp_path, monkeypatch):
    """M3714: the run's report keeps what was refused (``metrics.detection_refused``), and its
    detection unknown."""
    from tests.unit.test_annatar_atomic import ATOMIC_YAML, _atomic_executor
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("AZURE_SUBSCRIPTION_ID", "sub-123")   # the atomic target's (SEC11)
    real = Engine._wait_and_emit_feedback

    def wait(self, run_id, emitter, scenario, timeout_s, attack_time, stop_event=None):
        unsigned = {k: v for k, v in _detection_at(attack_time + 30, run=run_id).items()
                    if k not in ("key", "sig")}
        _file(channel.container, _blob(run=run_id), unsigned)
        monkeypatch.setattr(wc, "read_heartbeat", lambda **_: {
            "at": _iso(channel.clock.now), "since": _iso(channel.clock.now - 86400), "windows": [run_id]})
        return real(self, run_id, emitter, scenario, timeout_s, attack_time, stop_event)

    engine = Engine()
    with patch.object(engine, "_get_executor_collector", return_value=(_atomic_executor(), None)), \
         patch.object(Engine, "_wait_and_emit_feedback", wait):
        outcome = engine.run(ATOMIC_YAML, skip_confirm=True)
    assert outcome.detection == "unknown"
    report = json.loads(next((tmp_path / "runs" / "annatar").glob("2*.json")).read_text())
    assert report["metrics"]["detection"] == "unknown"
    assert len(report["metrics"]["detection_refused"]) == 1 and "unsigned" in report["metrics"]["detection_refused"][0]
    assert report["metrics"]["detection_refused_total"] == 1


def test_a_refused_detection_is_written_in_a_local_script_run_s_report(channel, tmp_path, monkeypatch):
    """M3715: the local-script path keeps it as the atomic one does."""
    from tests.unit.test_engine import EXFIL_YAML, _make_collector, _make_executor
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("AZURE_SUBSCRIPTION_ID", "sub-123")   # the target's (SEC11)
    real = Engine._wait_and_emit_feedback

    def wait(self, run_id, emitter, scenario, timeout_s, attack_time, stop_event=None):
        _file(channel.container, _blob(run=run_id), _detection_at(attack_time + 30, run="20261103T090000Z"))
        monkeypatch.setattr(wc, "read_heartbeat", lambda **_: {
            "at": _iso(channel.clock.now), "since": _iso(channel.clock.now - 86400), "windows": [run_id]})
        return real(self, run_id, emitter, scenario, timeout_s, attack_time, stop_event)

    engine = Engine()
    with patch.object(engine, "_get_executor_collector", return_value=(_make_executor(), _make_collector())), \
         patch.object(Engine, "_wait_and_emit_feedback", wait):
        outcome = engine.run(EXFIL_YAML, skip_confirm=True)
    assert outcome.detection == "unknown"
    report = json.loads(next((tmp_path / "runs" / "annatar").glob("2*.json")).read_text())
    assert "another run" in report["metrics"]["detection_refused"][0]


def test_a_refused_detection_is_written_in_orodruin_s_journal(channel, tmp_path, monkeypatch):
    """M3713: the run's own session declares it — on Orodruin's disk, the line of the run."""
    import os

    import eregion_core.orodruin as orodruin
    from tests.unit.test_annatar_atomic import ATOMIC_YAML, _atomic_executor
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("AZURE_SUBSCRIPTION_ID", "sub-123")   # the atomic target's (SEC11)
    real = Engine._wait_and_emit_feedback

    def wait(self, run_id, emitter, scenario, timeout_s, attack_time, stop_event=None):
        _file(channel.container, _blob(run=run_id), _detection_at(attack_time + 30, run=run_id, signer=OTHER))
        return real(self, run_id, emitter, scenario, timeout_s, attack_time, stop_event)

    engine = Engine()
    with patch.object(engine, "_get_executor_collector", return_value=(_atomic_executor(), None)), \
         patch.object(Engine, "_wait_and_emit_feedback", wait):
        engine.run(ATOMIC_YAML, skip_confirm=True)
    lines = [json.loads(x) for x in open(os.environ[orodruin.AUDIT_ENV]).read().splitlines() if x.strip()]
    refused = [x for x in lines if x["action"] == "detection_refused"]
    assert len(refused) == 1 and refused[0]["outcome"] == "declared"
    assert "signed by another key" in refused[0]["detail"]


def test_the_report_says_what_was_refused(capsys):
    """M3719: Annatar prints the refusals with the run — as written, never read as markup."""
    from annatar.runner.report import RunReport
    RunReport(run_id=RUN, scenario="s", mitre="T1136.001", result="PASS",
              metrics={"detection": "unknown", "detection_refused": ["detections/x/y.json: unsigned [bold]x[/bold]"]},
              thresholds={}, checks={}).render()
    out = capsys.readouterr().out
    assert "Refused on the return channel" in out and "[bold]x[/bold]" in out


# ── The heartbeat that proves a miss: the watch's, signed by the pinned key ───────────

@pytest.fixture
def proving(channel, monkeypatch):
    """The gate's own proof, not the conftest's stand-in: the pinned key decides. ``beat(signer,
    **over)`` makes the channel's heartbeat — written now, by a watch up for a day, that knows the
    run — signed by ``signer`` (None: unsigned)."""
    monkeypatch.setitem(gate.READERS, "proof", watch_key.proof)

    def beat(signer=WATCH, **over):
        def read(**_):
            now = datetime.fromtimestamp(channel.clock.now, timezone.utc)
            body = {"at": now.isoformat(), "since": _iso(channel.clock.now - 86400), "windows": [RUN],
                    "perimeter": "", "covers": {RUN: []}}
            body = watch_key.sign_beat(body, signer, now) if signer is not None else body
            return {**body, **over}
        monkeypatch.setattr(wc, "read_heartbeat", read)
    channel.beat = beat
    return channel


@pytest.mark.parametrize("signer, said", [(None, "unsigned"), (OTHER, "signed by another key")],
                         ids=["unsigned", "another-key"])
def test_a_heartbeat_the_pinned_key_did_not_sign_never_proves_a_miss(proving, capsys, signer, said):
    """M3720: whoever can write the channel — a silence vouched for by a heartbeat that is not the
    watch's is unknown, said, never a miss (no detection_missed, no rule proposed)."""
    proving.beat(signer)
    engine, emitted = _wait(proving.clock.now - 30)
    assert engine._detection_result == "unknown" and emitted == []
    out = capsys.readouterr().out
    assert "Detection not measured" in out and said in out


def test_a_replayed_heartbeat_never_proves_a_miss(proving, capsys):
    """M3720: a heartbeat whose counter is below one this injector already saw — a replay."""
    watch_key.remember({"key": WATCH.fingerprint, "seq": 10 ** 15, "sig": "seen"})
    proving.beat()
    engine, emitted = _wait(proving.clock.now - 30)
    assert engine._detection_result == "unknown" and emitted == []
    assert "not above one already seen" in capsys.readouterr().out


def test_a_heartbeat_the_pinned_key_signed_proves_a_silence_a_miss(proving):
    """The watch's own heartbeat, after the wait, covering the run's window: a miss, as before."""
    proving.beat()
    engine, emitted = _wait(proving.clock.now - 30)
    assert engine._detection_result == "missed" and emitted == ["detection_missed"]


def test_a_heartbeat_changed_after_its_signature_never_proves_a_miss(proving):
    """The pinned key's heartbeat, its windows rewritten after the signature: refused."""
    proving.beat(windows=[RUN, "another-run"])
    engine, emitted = _wait(proving.clock.now - 30)
    assert engine._detection_result == "unknown" and emitted == []


# ── Many refused: all counted, MAX_REFUSED said ──────────────────────────────────────

def test_twenty_five_refused_detections_say_twenty_five(channel, capsys):
    """M3721, M3724: the run says how many were refused in all, not only the ones it lists."""
    attack = channel.clock.now - 150
    for n in range(25):
        _file(channel.container, _blob(sid=f"rule-forged-{n:03d}"), {"event": "detection"})
    engine, emitted = _wait(attack)
    assert engine._detection_result == "unknown" and emitted == []
    assert engine._detection_refused_total == 25 and len(engine._detection_refused) == wc.MAX_REFUSED
    out = " ".join(capsys.readouterr().out.split())   # as said, whatever the terminal's width
    assert "25 detection(s) on the return channel refused" in out


def test_a_writer_that_rotates_its_blobs_never_floods_the_journal(channel, monkeypatch):
    """M3722: new refused blobs at every read — the run keeps and journals MAX_REFUSED, no more."""
    reads = iter(range(10 ** 6))

    def rotating(run_id, **_):
        n = next(reads)
        return [(f"rule-rot-{n:05d}-{i:02d}", {"event": "detection"}) for i in range(wc.MAX_REFUSED)]
    monkeypatch.setattr(wc, "read_named", rotating)
    journal = _Journal()
    engine, emitted = _wait(channel.clock.now - 150, session=journal)
    assert next(reads) > 3   # read again and again during the wait
    assert engine._detection_result == "unknown" and emitted == []
    assert len(engine._detection_refused) == wc.MAX_REFUSED and len(journal.lines) == wc.MAX_REFUSED
    assert engine._detection_refused_total == wc.MAX_REFUSED


def test_a_heartbeat_the_gate_believed_before_the_run_replayed_at_the_end_never_proves_a_miss(proving):
    """The gate's real proof accepts the watch's heartbeat before the run; the same heartbeat,
    replayed after the wait, never vouches for it: unknown, no detection_missed."""
    now = datetime.fromtimestamp(proving.clock.now, timezone.utc)
    before = watch_key.sign_beat({"at": now.isoformat(), "since": _iso(proving.clock.now - 86400),
                                  "windows": [RUN], "perimeter": "p"}, WATCH, now)
    gate.READERS.update(channel=lambda: gate.Beat(gate.CHANNEL, now, perimeter="p", body=dict(before)),
                        own=lambda: "p")
    assert gate.refusal(now) == ""
    with patch.object(wc, "read_heartbeat", lambda **_: dict(before)):
        engine, emitted = _wait(proving.clock.now - 30)
    assert engine._detection_result == "unknown" and emitted == []
