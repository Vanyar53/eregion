"""CON-S (#534): the console marks each detection of the return channel as the injectors read it
(SEC21) — signed by the key pinned on the console (``EREGION_WATCH_KEY``), or refused with why.

``GET /api/channel/detections/<run_id>`` judges each blob with ``watch_key.detection_refusal`` and
the key ``watch_key.pinned`` gives, the very check of ``watch_channel.vouched_detections``: the
console never says « counted » of what a run refuses. Without a key pinned, none is shown as
verified. The refused ones shown are MAX_REFUSED at most, all counted. ``injector.js`` writes the
state, and nothing of the blob raw (#254, #257: tests/unit/test_console_escaping.py reads the page).

On the fake container of the channel (tests/unit/fake_container.py): no network, no Azure; the
keys are fixed seeds, never a real key. Mutants M3750–M3759 (scripts/mutants/CON-S.py).
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from .console_client import console  # noqa: E402

import eregion_core.watch_channel as wc  # noqa: E402
import eregion_core.watch_key as watch_key  # noqa: E402
from tests.unit.fake_container import CRED, FakeContainer  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
URL = "https://exampleaccount.blob.core.windows.net/watch"
WATCH = watch_key.Signer(bytes(range(32)))            # the watch's key, a fixed seed
OTHER = watch_key.Signer(bytes(range(1, 33)))         # another watch's
RUN = "20261105T101500Z"
SID = "rule-t1136-001-v1-ab12cd34"
VM = ("/subscriptions/00000000-0000-0000-0000-00000000aaaa/resourcegroups/rg-example"
      "/providers/microsoft.compute/virtualmachines/vm-example")
T0 = datetime(2026, 11, 5, 10, 15, tzinfo=timezone.utc)
REAL_READ_NAMED = wc.read_named


@pytest.fixture()
def channel(tmp_path, monkeypatch):
    """The return channel set on the console, read from the fake container (the real listing
    and parsing of ``read_named``)."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv(wc.CHANNEL_ENV, URL)
    c = FakeContainer(URL)
    monkeypatch.setattr(wc, "read_named",
                        lambda rid, **_: REAL_READ_NAMED(rid, channel=URL, credential=CRED, get=c.get))
    return c


@pytest.fixture()
def pinned(monkeypatch):
    """The console pins the watch's public key — its environment's, nothing else."""
    monkeypatch.setenv(watch_key.KEY_ENV, watch_key.public_text(WATCH.public))


def _body(signer=WATCH, run=RUN, sid=SID, **over) -> dict:
    body = {"event": "detection", "signal_id": sid, "ttp": "T1136.001", "resource_id": VM,
            "detected_at": (T0 + timedelta(minutes=2)).isoformat(), "rule": "t1136-001-v1",
            "watch_run_id": "watch-t1136-x", "exercise_run": run}
    return {**watch_key.sign_detection(body, signer), **over}


def _file(c: FakeContainer, body, run=RUN, sid=SID) -> None:
    c.put(f"{URL}/{wc.DETECTIONS}/{run}/{sid}.json", headers={}, data=json.dumps(body).encode())


def _read(run=RUN) -> dict:
    return console().get(f"/api/channel/detections/{run}").json()


# ── Signed, refused ───────────────────────────────────────────────────────────────────

def test_a_detection_the_pinned_key_signed_is_shown_signed(channel, pinned):
    """Signed by the pinned key, for this run, under its signal's name — shown signed, with
    the key's fingerprint; what it says is the blob's."""
    _file(channel, _body())
    got = _read()
    assert got["configured"] is True
    assert got["key"] == {"pinned": True, "fingerprint": WATCH.fingerprint}
    assert got["signed"] == 1 and got["refused"] == 0 and got["refused_shown"] == 0
    [d] = got["detections"]
    assert d["signal"] == SID and d["state"] == "signed" and d["why"] == ""
    assert d["detection"]["ttp"] == "T1136.001" and d["detection"]["exercise_run"] == RUN


def test_an_unsigned_detection_is_refused_with_why(channel, pinned):
    """M3750, M3751: a watch older than SEC21 files it unsigned — refused, SEC21's words said."""
    _file(channel, {k: v for k, v in _body().items() if k not in watch_key.SIGNED_DETECTION})
    got = _read()
    [d] = got["detections"]
    assert d["state"] == "refused" and d["why"] == watch_key.UNSIGNED_DETECTION
    assert got["signed"] == 0 and got["refused"] == 1
    assert d["detection"]["ttp"] == "T1136.001"         # what it claims, shown, never counted


def test_a_detection_of_another_key_is_refused(channel, pinned):
    """M3750, M3752: signed by another watch's key — refused, both fingerprints said."""
    _file(channel, _body(signer=OTHER))
    [d] = _read()["detections"]
    assert d["state"] == "refused" and d["why"].startswith("signed by another key")
    assert OTHER.fingerprint[:19] in d["why"] and WATCH.fingerprint[:19] in d["why"]


def test_a_detection_changed_or_copied_is_refused(channel, pinned):
    """A field changed after its signature, a copy from another run, under another signal's name."""
    _file(channel, _body(ttp="T1059.004"), sid="rule-changed")
    _file(channel, _body(run="20261104T090000Z", sid="rule-copied"), sid="rule-copied")
    _file(channel, _body(), sid="rule-renamed")
    got = {d["signal"]: d for d in _read()["detections"]}
    assert "does not hold" in got["rule-changed"]["why"]
    assert "another run" in got["rule-copied"]["why"]
    assert "another signal" in got["rule-renamed"]["why"]
    assert {d["state"] for d in got.values()} == {"refused"}


def test_a_blob_that_is_no_object_is_refused_and_shows_nothing_of_itself(channel, pinned):
    _file(channel, ["not", "an", "object"])
    [d] = _read()["detections"]
    assert d["state"] == "refused" and d["why"] == "not a JSON object" and d["detection"] is None


def test_the_console_judges_as_the_injectors_do(channel, pinned):
    """M3752: the same blobs — the console's « signed » are exactly what ``vouched_detections``
    keeps, its refusals exactly the run's, word for word."""
    _file(channel, _body(), sid=SID)
    _file(channel, _body(signer=OTHER, sid="rule-other"), sid="rule-other")
    _file(channel, {k: v for k, v in _body(sid="rule-unsigned").items() if k != "sig"}, sid="rule-unsigned")
    _file(channel, _body(sid="rule-copy"), sid="rule-renamed")
    kept, refused, total = wc.vouched_detections(RUN)     # the run's own read, on the same blobs
    got = _read()
    assert [d["detection"] for d in got["detections"] if d["state"] == "signed"] == kept
    assert [f"{wc.DETECTIONS}/{RUN}/{d['signal']}.json: {d['why']}" for d in got["detections"]
            if d["state"] == "refused"] == refused
    assert got["refused"] == total == 3 and got["signed"] == 1


# ── No key pinned ────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("pin", ["", "ed25519:short=", "ssh-ed25519 AAAA"])
def test_without_a_key_pinned_no_detection_is_shown_verified(channel, monkeypatch, pin):
    """M3753, M3754: no key pinned, or not a key — the route says so and the gesture, and every
    detection, even one the watch signed, is refused with those words: none verified."""
    if pin:
        monkeypatch.setenv(watch_key.KEY_ENV, pin)
    _file(channel, _body())
    _file(channel, _body(signer=OTHER, sid="rule-other"), sid="rule-other")
    got = _read()
    assert got["key"]["pinned"] is False and "fingerprint" not in got["key"]
    assert watch_key.KEY_ENV in got["key"]["why"] and "make watch-key" in got["key"]["why"]
    assert got["signed"] == 0 and got["refused"] == 2
    assert [d["state"] for d in got["detections"]] == ["refused", "refused"]
    assert all(d["why"] == got["key"]["why"] for d in got["detections"])


# ── The counts ───────────────────────────────────────────────────────────────────────

def test_the_refused_shown_are_bounded_all_counted_and_no_signed_one_hidden(channel, pinned):
    """M3755, M3756: 25 refused and one signed — MAX_REFUSED refused shown, 25 said, the signed
    one shown whatever its place in the listing."""
    for n in range(25):
        _file(channel, _body(signer=OTHER, sid=f"rule-a-{n:02d}"), sid=f"rule-a-{n:02d}")
    _file(channel, _body(sid="rule-z-signed"), sid="rule-z-signed")
    got = _read()
    assert got["refused"] == 25 and got["refused_shown"] == wc.MAX_REFUSED == 20
    states = [d["state"] for d in got["detections"]]
    assert states.count("refused") == wc.MAX_REFUSED and states.count("signed") == 1
    assert got["signed"] == 1 and got["detections"][-1]["signal"] == "rule-z-signed"


# ── Unchanged: no channel, a run id, an unreadable channel ───────────────────────────

def test_no_channel_no_detection(tmp_path, monkeypatch, pinned):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv(wc.CHANNEL_ENV, raising=False)
    assert _read() == {"configured": False, "detections": []}


def test_an_unreadable_channel_is_said(channel, pinned, monkeypatch):
    def _fail(rid):
        raise RuntimeError("HTTP 403 reading the watch channel")
    monkeypatch.setattr(wc, "read_named", _fail)
    assert "403" in _read()["error"]


def test_a_run_id_is_a_plain_name(channel, pinned):
    assert "plain name" in _read("_x")["error"]      # read_named refuses it: never listed


# ── The page: the state written, nothing raw ─────────────────────────────────────────

JS = (ROOT / "eregion_console" / "static" / "injector.js").read_text(encoding="utf-8")


def _channel_detections() -> str:
    start = JS.index("function channelDetections(d) {")
    return JS[start:JS.index("\n}\n", start)]


def test_the_page_says_signed_only_with_a_key_pinned_and_the_server_s_signed():
    """M3757: SIGNED only when the key is pinned and the server said signed — anything else,
    REFUSED; never « delivered » of what the run does not count."""
    fn = _channel_detections()
    assert "const pinned = key.pinned === true;" in fn
    assert "const ok = pinned && x.state === 'signed';" in fn
    assert fn.count(">SIGNED<") == 1 and fn.count(">REFUSED<") == 1
    assert "DELIVERED TO THE RUN" not in JS and "nothing delivered" not in JS
    assert "judged here with the key pinned on this console" in JS


def test_the_page_says_why_and_the_counts_escaped():
    """M3758: the refusal, the fingerprint, the reason of no key — escaped; the counts are
    numbers (#254). The whole page is read by tests/unit/test_console_escaping.py."""
    fn = _channel_detections()
    for said in ("esc(x.why)", "esc(key.fingerprint)", "esc(key.why)", "esc(det.ttp)", "esc(det.rule)",
                 "esc(vmName(det.resource_id))"):
        assert said in fn, said
    assert "Number(d.signed), refused = Number(d.refused), shown = Number(d.refused_shown)" in fn
    assert not re.search(r"\$\{(x|det|key)\.", fn)


# ── The compose: the console receives the key it pins, and nothing more ──────────────

def test_the_console_receives_the_watch_s_public_key_never_its_private_one():
    """SEC19, CON-S: the console's service has ``EREGION_WATCH_KEY`` — the public key —, never a
    mount of the watch's key directory."""
    import yaml
    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
    svc = compose["services"]["war-room"]
    assert svc["environment"]["EREGION_WATCH_KEY"] == "${EREGION_WATCH_KEY:-}"
    assert not any("watch-key" in str(v) for v in svc.get("volumes") or [])

