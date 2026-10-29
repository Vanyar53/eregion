"""SEC5 (#276): the injectors' channels and the shared core.

- V-20: an exercise window is bounded by when the blob that carries it was created, not by
  what it declares; MAX_DURATION_S caps it; in zone production it marks nothing unless it
  declares a technique that is not destructive;
- V-21: a pull reads within bounds — a blob's size, a listing's, how many — as a stream cut
  past the bound, never read whole and then checked; what goes past is said;
- N-15: a storage token goes to an Azure Storage blob endpoint only;
- N-03: the heartbeat carries the perimeter of the watch, compared with the injector's;
- V-29: the contract wants the writes on each enrolled resource, never on the group; the
  journal goes off the host, to the channel.

No Azure: the container is in memory (tests/unit/fake_container.py), the tag reads a fake.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime
from pathlib import Path
from types import SimpleNamespace

import pytest
import requests

import eregion_core.exercise as exercise
import eregion_core.exercise_channel as channel
import eregion_core.orodruin as orodruin
import eregion_core.watch_channel as wc
import eregion_core.watch_gate as gate
from tests.unit.fake_container import CRED, URL, FakeContainer

VM = ("/subscriptions/s/resourceGroups/rg-celebrimbor/providers/Microsoft.Compute"
      "/virtualMachines/vm-celebrimbor-gondolin")
WATCH_URL = "https://exampleaccount.blob.core.windows.net/watch"


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def _window(run_id="R1", start=None, **kw) -> dict:
    start = start or _now()
    return {"run_id": run_id, "injector": "annatar", "kind": "technique", "experiment": "T1041",
            "targets": [VM.lower()], "start": start.isoformat(), "end": None,
            "expires": (start + timedelta(hours=1)).isoformat(), "destructive": False, **kw}


# ── V-20: the window bounded by its blob's creation ───────────────────────────────────

def _pulled(tmp_path, window, created: datetime) -> list[dict]:
    c = FakeContainer()
    channel.publish(window, channel=URL, credential=CRED, put=c.put)
    c.created[f"{window['run_id']}.json"] = created
    d = tmp_path / "exercises"
    channel.pull(d, channel=URL, credential=CRED, get=c.get)
    return exercise.load_windows(d)


def test_a_window_dated_back_before_its_blob_was_created_is_refused(tmp_path):
    """M1272 (lab L-13): written now, it declares a start 110 minutes ago — the blob's
    creation says it was not there then. Refused, whatever it says of itself."""
    now = _now()
    antedated = _window(start=now - timedelta(minutes=110), channel_created="2020-01-01T00:00:00+00:00")
    assert _pulled(tmp_path, antedated, created=now) == []
    why = exercise.window_refusal(json.loads((tmp_path / "exercises" / "R1.json").read_text()))
    assert "before the blob that carries it was created" in why
    # The window's own claim of when it was created is overwritten by the listing's.
    assert json.loads((tmp_path / "exercises" / "R1.json").read_text())[channel.CREATED] == now.isoformat()


def test_a_window_opened_when_its_blob_was_created_is_believed(tmp_path):
    now = _now()
    (w,) = _pulled(tmp_path, _window(start=now - timedelta(seconds=30)), created=now)
    assert w["run_id"] == "R1" and w[channel.CREATED] == now.isoformat()


def test_a_closed_window_keeps_the_creation_of_its_first_pull(tmp_path):
    """Re-pulled once closed, the window keeps the creation time of its first pull: a blob
    overwritten later never moves its bound."""
    c, d = FakeContainer(), tmp_path / "exercises"
    first = _now() - timedelta(minutes=40)
    w = _window(start=first)
    channel.publish(w, channel=URL, credential=CRED, put=c.put)
    c.created["R1.json"] = first
    channel.pull(d, channel=URL, credential=CRED, get=c.get)
    os.utime(d / "R1.json", (0, 0))   # older than the closed blob
    channel.publish({**w, "end": _now().isoformat()}, channel=URL, credential=CRED, put=c.put)
    c.created["R1.json"] = _now()     # as if Azure reset it on the overwrite
    channel.pull(d, channel=URL, credential=CRED, get=c.get)
    (loaded,) = exercise.load_windows(d)
    assert loaded["end"] and loaded[channel.CREATED] == first.isoformat()


def test_the_duration_is_capped(tmp_path):
    now = _now()
    w = _window(start=now)
    w["expires"] = (now + timedelta(seconds=exercise.MAX_DURATION_S + 1)).isoformat()
    assert "MAX_DURATION_S" in exercise.window_refusal(w)
    assert _pulled(tmp_path, w, created=now) == []


class _Zones:
    """An enrollment check that reads the zone too, as TagEnrollment does."""

    def __init__(self, zone):
        self._zone = zone

    def __call__(self, rid):
        return True

    def zone(self, rid):
        return self._zone


@pytest.mark.parametrize("change, marks", [
    ({}, True),                                   # a technique, non-destructive: as in O0
    ({"destructive": True}, False),               # a destructive technique: never there
    ({"destructive": None}, False),               # nobody said: destructive
    ({"kind": "fault"}, False),                   # a fault: never there
])
def test_in_production_a_window_marks_only_a_non_destructive_technique(change, marks):
    """M1273: the production rule of O0, read by the watch — a window that says a destructive
    technique or a fault ran on a production VM is a lie, and marks nothing."""
    now = _now()
    w = {**_window(start=now - timedelta(minutes=1)), **change}
    prod, bench = _Zones("production"), _Zones("bench")
    assert (exercise.covering_runs(VM, now, [w], enrolled=prod) == ["R1"]) is marks
    assert (exercise.source_of(VM, now, run_id="R1", windows=[w], enrolled=prod)[0]
            == exercise.EXERCISE) is marks
    assert exercise.covering_runs(VM, now, [w], enrolled=bench) == ["R1"]


def test_open_window_writes_the_catalog_s_destructiveness(tmp_path):
    assert exercise.open_window("R1", injector="annatar", kind="technique", experiment="x",
                                targets=[VM], directory=tmp_path)["destructive"] is True
    assert exercise.open_window("R2", injector="annatar", kind="technique", experiment="x",
                                targets=[VM], directory=tmp_path,
                                destructive=False)["destructive"] is False


def test_the_watch_reads_the_zone_from_the_tags():
    """TagEnrollment gives the zone of an enrolled VM, cached with its verdict."""
    from eregion_core.inscription import TagEnrollment
    calls = []

    def get(url, headers=None, params=None, timeout=None):
        calls.append(url)
        return SimpleNamespace(ok=True, json=lambda: {"tags": {"eregion-target": "celebrimbor",
                                                               "eregion-zone": "production"}})
    check = TagEnrollment(credential=CRED, get=get)
    assert check(VM) is True and check.zone(VM) == "production" and len(calls) == 2


# ── V-21: bounded pulls ───────────────────────────────────────────────────────────────

class _Endless:
    """A blob far larger than any bound (32 MiB — « endless » for a pull), served as a real
    requests.Response streams it; it counts what was read of it."""

    SIZE = 32 * 1024 * 1024

    def __init__(self):
        self.read_bytes = 0

    def read(self, n=-1, **_):
        left = self.SIZE - self.read_bytes
        n = left if n is None or n < 0 else min(n, left)
        self.read_bytes += n
        return b"x" * n

    def stream(self, n, decode_content=None):
        while self.read_bytes < self.SIZE:
            yield self.read(n)

    def close(self):
        pass


def _streamed(raw, status=200, headers=None):
    r = requests.Response()
    r.status_code = status
    r.raw = raw
    r.headers.update(headers or {})
    return r


def test_a_blob_past_its_bound_is_cut_never_read_whole(monkeypatch):
    """M1274: the real client streams, and stops past MAX_BLOB_BYTES — never the whole body
    read, then checked."""
    raw, asked = _Endless(), []

    def get(url, headers=None, params=None, timeout=None, stream=False):
        asked.append(stream)
        return _streamed(raw)
    monkeypatch.setattr(requests, "get", get)
    with pytest.raises(channel.TooLarge, match="more than"):
        channel.fetch(None, f"{URL}/R1.json", {}, limit=channel.MAX_BLOB_BYTES)
    assert asked == [True]
    assert raw.read_bytes <= channel.MAX_BLOB_BYTES + 2 * 65536


def test_a_declared_length_past_the_bound_is_refused_before_a_byte(monkeypatch):
    raw = _Endless()
    monkeypatch.setattr(requests, "get", lambda *a, **k: _streamed(
        raw, headers={"Content-Length": str(channel.MAX_BLOB_BYTES + 1)}))
    with pytest.raises(channel.TooLarge):
        channel.fetch(None, f"{URL}/R1.json", {})
    assert raw.read_bytes == 0


def test_a_window_too_large_is_said_and_not_pulled(tmp_path):
    c, said = FakeContainer(), []
    c.put(f"{URL}/R1.json", data=b"{" + b" " * (channel.MAX_BLOB_BYTES + 1) + b"}")
    channel.publish(_window("R2"), channel=URL, credential=CRED, put=c.put)
    d = tmp_path / "exercises"
    assert channel.pull(d, channel=URL, credential=CRED, get=c.get, say=said.append) == 1
    assert sorted(os.listdir(d)) == ["R2.json"]
    assert any("window R1.json" in s and "not pulled" in s for s in said)


def test_a_listing_stops_at_its_bound_and_says_so(tmp_path, monkeypatch):
    """M1275: a container flooded with names lists at most MAX_BLOBS of them per pull."""
    monkeypatch.setattr(channel, "MAX_BLOBS", 5)
    c, said = FakeContainer(page_size=2), []
    for i in range(12):
        channel.publish(_window(f"R{i:02d}"), channel=URL, credential=CRED, put=c.put)
    n = channel.pull(tmp_path / "x", channel=URL, credential=CRED, get=c.get, say=said.append)
    assert n == 5 and len(c.listings) == 3
    assert any("listing stopped at 5 blobs" in s for s in said)


def test_a_pull_downloads_at_most_its_bound_the_rest_next_time(tmp_path, monkeypatch):
    monkeypatch.setattr(channel, "MAX_DOWNLOADS", 3)
    c, said, d = FakeContainer(), [], tmp_path / "x"
    for i in range(5):
        channel.publish(_window(f"R{i}"), channel=URL, credential=CRED, put=c.put)
    assert channel.pull(d, channel=URL, credential=CRED, get=c.get, say=said.append) == 3
    assert any("the rest waits for the next pull" in s for s in said)
    assert channel.pull(d, channel=URL, credential=CRED, get=c.get, say=said.append) == 2


def test_a_run_report_too_large_is_refused_by_name(tmp_path):
    c = FakeContainer()
    c.put(f"{URL}/runs/R1.json", data=b"[" + b" " * (channel.MAX_BLOB_BYTES + 1) + b"]")
    written, skipped = channel.pull_runs(tmp_path, refusal=lambda r, rid: "", channel=URL,
                                         credential=CRED, get=c.get)
    assert written == 0 and skipped["R1"].startswith("refused: ") and "more than" in skipped["R1"]


def test_a_campaign_blob_too_large_holds_its_manifest_back(tmp_path):
    c = FakeContainer()
    c.put(f"{URL}/campaigns/C1/runs/R1.json", data=b" " * (channel.MAX_BLOB_BYTES + 1))
    c.put(f"{URL}/campaigns/C1/manifest.json", data=b"{}")
    written, failed = channel.pull_campaigns(tmp_path, channel=URL, credential=CRED, get=c.get)
    assert written == 0 and failed == {"C1"}


def test_the_return_channel_reads_within_bounds_too(monkeypatch):
    raw = _Endless()
    monkeypatch.setattr(requests, "get", lambda *a, **k: _streamed(raw))
    with pytest.raises(channel.TooLarge):
        wc.read_heartbeat(channel=WATCH_URL, credential=CRED)


# ── N-15: a token for Azure Storage only ──────────────────────────────────────────────

@pytest.mark.parametrize("url", [
    "https://exampleaccount.blob.core.windows.net/exercises",
    "https://exampleaccount.blob.core.chinacloudapi.cn/exercises",
    "https://exampleaccount.blob.core.usgovcloudapi.net/exercises",
    "https://EXAMPLEACCOUNT.blob.core.windows.net:443/exercises",
])
def test_a_blob_endpoint_receives_the_token(url):
    assert channel.url_refusal(url) == ""


@pytest.mark.parametrize("url", [
    "http://exampleaccount.blob.core.windows.net/exercises",             # not https
    "https://example.com/exercises",
    "https://exampleaccount.blob.core.windows.net.example.com/x",        # a suffix inside
    "https://exampleaccount.blob.core.windows.net@example.com/x",        # a user, another host
    "https://example.com/#.blob.core.windows.net",
    "https://exampleaccount.blob.core.windows.net:8443/exercises",
    "https://a.b.blob.core.windows.net/x",                               # not an account name
    "https://exampleaccount.file.core.windows.net/x",
    "",
])
def test_any_other_url_is_refused_before_a_token_is_asked(url):
    """M1276: a misconfigured channel never receives a storage bearer token."""
    asked = []
    cred = SimpleNamespace(get_token=lambda scope: asked.append(scope) or SimpleNamespace(token="t"))
    assert channel.url_refusal(url)
    with pytest.raises(channel.ChannelRefused):
        channel.auth_headers(cred, url)
    assert asked == []


def test_every_call_of_the_channels_checks_its_url(monkeypatch):
    bad = "https://example.com/exercises"
    asked = []
    cred = SimpleNamespace(get_token=lambda scope: asked.append(scope) or SimpleNamespace(token="t"))
    sent = []
    monkeypatch.setattr(requests, "get", lambda *a, **k: sent.append(a) or None)
    monkeypatch.setattr(requests, "put", lambda *a, **k: sent.append(a) or None)
    for call in (lambda: channel.publish(_window(), channel=bad, credential=cred),
                 lambda: channel.pull(Path("/nonexistent-never-made"), channel=bad, credential=cred),
                 lambda: wc.read_heartbeat(channel=bad, credential=cred),
                 lambda: wc.read_detections("R1", channel=bad, credential=cred),
                 lambda: wc.Publisher(bad, credential=cred)._write("heartbeat.json", {})):
        with pytest.raises(channel.ChannelRefused):
            call()
    assert asked == [] and sent == []


# ── N-03: the heartbeat carries the watch's perimeter ─────────────────────────────────

SUB = "00000000-0000-0000-0000-00000000aaaa"


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setattr(gate, "READERS", {"channel": gate.channel_beat, "local": gate.local_beat,
                                          "own": gate.perimeter})
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv(gate.SUBSCRIPTION_ENV, SUB)
    (tmp_path / ".glorfindel" / "injectors").mkdir(parents=True)
    return tmp_path / ".glorfindel"


def test_the_perimeter_is_a_digest_never_the_subscription():
    p = gate.perimeter(SUB)
    assert len(p) == 16 and SUB not in p and p == gate.perimeter(SUB.upper())
    assert gate.perimeter("") == ""


def test_a_heartbeat_of_another_subscription_is_refused(home):
    (home / "injectors" / "watch_heartbeat").write_text(
        json.dumps(gate.beat_body(datetime.now(timezone.utc), "00000000-0000-0000-0000-0000000000ff")))
    assert "another subscription" in gate.refusal()
    (home / "injectors" / "watch_heartbeat").write_text(json.dumps(gate.beat_body(datetime.now(timezone.utc))))
    assert gate.refusal() == ""


def test_a_heartbeat_that_names_no_perimeter_is_refused(home):
    """An older watch writes a bare date: live, but bound to nothing."""
    (home / "injectors" / "watch_heartbeat").write_text(datetime.now(timezone.utc).isoformat())
    assert "names no perimeter" in gate.refusal()


def test_an_injector_without_a_subscription_binds_to_nothing(home, monkeypatch):
    monkeypatch.delenv(gate.SUBSCRIPTION_ENV)
    (home / "injectors" / "watch_heartbeat").write_text(json.dumps(gate.beat_body(datetime.now(timezone.utc), SUB)))
    assert gate.refusal() == gate.NO_OWN_PERIMETER


def test_the_injectors_copy_is_read_before_the_watch_s_own_file(home):
    """Outside a container both files exist: the watch's own (a bare date, for the console)
    and the injectors' copy (with the perimeter) — the copy decides."""
    now = datetime.now(timezone.utc)
    (home / "watch_heartbeat").write_text(now.isoformat())
    (home / "injectors" / "watch_heartbeat").write_text(json.dumps(gate.beat_body(now)))
    assert gate.local_beat().perimeter == gate.perimeter(SUB) and gate.refusal() == ""


def test_the_hosted_watch_writes_its_perimeter_in_the_channel(monkeypatch):
    monkeypatch.setenv(gate.SUBSCRIPTION_ENV, SUB)
    c = FakeContainer(WATCH_URL)
    pub = wc.Publisher(WATCH_URL, credential=CRED, put=c.put, windows=lambda: [])
    pub.tick()
    assert json.loads(c.body("heartbeat.json"))["perimeter"] == gate.perimeter(SUB)


# ── V-29: the contract, and the journal off the host ──────────────────────────────────

def test_the_journal_goes_to_the_channel_before_the_call(tmp_path, monkeypatch):
    """M1277: each line on this host's disk, then in the channel's audit/<run_id>.jsonl — an
    append blob created once, appended to before each call."""
    c = FakeContainer()
    monkeypatch.setenv(channel.CHANNEL_ENV, URL)
    monkeypatch.setattr(channel, "_credential", CRED)
    monkeypatch.setattr(requests, "put", c.put)
    s = orodruin.Session("R1", "annatar", 5)
    s.declare("without_glorfindel", "x")
    s.before_call("run_command", VM, "probe")
    s.before_call("run_command", VM, "atomic")
    lines = [json.loads(x) for x in c.body("audit/R1.jsonl").decode().splitlines()]
    assert [x["outcome"] for x in lines] == ["declared", "about_to_call", "about_to_call"]
    assert [x["detail"] for x in lines] == ["x", "probe", "atomic"]
    assert c.puts.count("audit/R1.jsonl") == 1 and len(c.appends) == 3
    # The windows' pull never lists it (the container's root only).
    assert channel.pull(tmp_path / "w", channel=URL, credential=CRED, get=c.get) == 0


def test_a_push_that_fails_is_journaled_here_and_the_call_goes_on(monkeypatch, capsys):
    def refused(*a, **k):
        raise RuntimeError("HTTP 403")
    s = orodruin.Session("R1", "annatar", 5, offhost=refused)
    s.before_call("run_command", VM, "cleanup")
    records = [json.loads(x) for x in orodruin.audit_path().read_text().splitlines()]
    assert [r["outcome"] for r in records] == ["about_to_call", "offhost_failed"]
    assert "HTTP 403" in records[1]["detail"] and s.calls == 1
    assert "not pushed off the host" in capsys.readouterr().out


def test_no_channel_no_push(monkeypatch):
    monkeypatch.setattr(requests, "put", lambda *a, **k: pytest.fail("pushed without a channel"))
    orodruin.Session("R1", "annatar", 5).before_call("run_command", VM, "x")


def test_the_contract_refuses_a_write_on_the_whole_group():
    """M1278: the old injector role — runCommand on the bench's group — is passive now."""
    bench = "/subscriptions/s/resourceGroups/rg-celebrimbor"
    old = [{"properties": {"scope": bench, "roleDefinitionId": "/r/old"}}]
    missing = orodruin.assess_identity(old, lambda _: list(orodruin.REQUIRED_ACTIONS),
                                       [{"actions": list(orodruin.REQUIRED_ACTIONS)}], bench,
                                       sees_subscription=True)
    assert "identity_group_wide" in [m["code"] for m in missing]


def test_the_listing_s_creation_time_is_what_the_fake_says():
    """The fake lists a Creation-Time as Azure does (API 2021-08-06), so the bound is tested
    against the listing's word."""
    c = FakeContainer()
    channel.publish(_window(), channel=URL, credential=CRED, put=c.put)
    listing = c.get(URL, params={"restype": "container", "comp": "list"}).content.decode()
    assert f"<Creation-Time>{format_datetime(c.created['R1.json'], usegmt=True)}</Creation-Time>" in listing
