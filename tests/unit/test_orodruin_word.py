"""What Orodruin says to the console (DG-b, docs/design/console.md §7, « Ce qui manque ailleurs »):
its contract's verdict — armed or passive, the codes, the time; no subscription, no identifier —
and the status of each request, published to the exercise channel under its own prefix (the same
container, the same assignment: no right more), pulled by H0's watch into ``runs/orodruin/``, each
blob read against its shape first.

The container is in memory (tests/unit/fake_container.py): no network, no Azure. The oracles are
written here.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from eregion_core import exercise_channel as xc
from eregion_core import exercise_request as xr
from eregion_core import orodruin
from tests.unit.fake_container import CRED, URL, FakeContainer

AT = datetime(2026, 10, 30, 8, 0, tzinfo=timezone.utc)
RID = "r-20261030T080000Z-abcdef"
PASSIVE = orodruin.Verdict(orodruin.PASSIVE, [
    orodruin._miss("identity_outside_bench", "role assignment at /subscriptions/0000-1111/resourceGroups/rg-x"),
    orodruin._miss("network_open", "1.1.1.1:443 reachable")])
STATUS = {"request": RID, "state": "running", "at": AT.isoformat(), "codes": [],
          "wires": [{"rank": 1, "state": "done", "code": "", "runs": ["20261030T080100Z-ab12"], "result": "PASS"},
                    {"rank": 2, "state": "running", "code": "", "runs": [], "result": ""}]}


def test_the_verdict_published_is_armed_or_passive_its_codes_and_its_time_nothing_else():
    doc = orodruin.contract_doc(PASSIVE, AT)
    assert doc == {"verdict": "passive", "codes": ["identity_outside_bench", "network_open"], "at": AT.isoformat()}
    text = json.dumps(doc)
    assert "subscriptions" not in text and "rg-x" not in text and "1.1.1.1" not in text
    armed = orodruin.contract_doc(orodruin.Verdict(orodruin.ARMED, [], {"max_injections": 20}), AT)
    assert armed == {"verdict": "armed", "codes": [], "at": AT.isoformat()}
    assert orodruin.read_contract(doc) == doc and orodruin.read_contract(armed) == armed


@pytest.mark.parametrize("doc", [
    {"verdict": "armed", "codes": [], "at": AT.isoformat(), "subscription": "0000"},
    {"verdict": "armed", "codes": ["network_open"], "at": AT.isoformat()},   # armed with a gap
    {"verdict": "passive", "codes": [], "at": AT.isoformat()},                # passive, unsaid why
    {"verdict": "ARMED", "codes": [], "at": AT.isoformat()},
    {"verdict": "passive", "codes": ["role assignment at /subscriptions/x"], "at": AT.isoformat()},
    {"verdict": "armed", "codes": [], "at": "today"},
    ["armed"],
])
def test_a_verdict_not_of_its_shape_is_refused(doc):
    with pytest.raises(ValueError):
        orodruin.read_contract(doc)


def test_orodruin_check_publishes_its_verdict_with_a_channel(monkeypatch, capsys):
    c = FakeContainer()
    monkeypatch.setenv(xc.CHANNEL_ENV, URL)
    monkeypatch.setattr(xc, "_credential", CRED)
    monkeypatch.setattr("requests.put", c.put)
    assert orodruin.main() == 0
    assert c.puts == [orodruin.CONTRACT_BLOB]
    assert json.loads(c.blobs[orodruin.CONTRACT_BLOB][0])["verdict"] == "armed"


def test_a_verdict_not_published_is_said_never_a_failed_check(monkeypatch, capsys):
    c = FakeContainer()
    c.refused.add(orodruin.CONTRACT_BLOB)
    monkeypatch.setenv(xc.CHANNEL_ENV, URL)
    monkeypatch.setattr(xc, "_credential", CRED)
    monkeypatch.setattr("requests.put", c.put)
    assert orodruin.main() == 0
    assert "verdict not published" in capsys.readouterr().out


def test_only_orodruins_two_kinds_of_blob_are_published():
    c = FakeContainer()
    for name in ("orodruin/contract.json", f"orodruin/requests/{RID}.json"):
        assert xc.publish_doc(name, {}, channel=URL, credential=CRED, put=c.put)
    for name in ("contract.json", "orodruin/../x.json", "orodruin/requests/x.json", f"{RID}.json",
                 "runs/r.json", "orodruin/requests/../../a.json"):
        with pytest.raises(ValueError):
            xc.publish_doc(name, {}, channel=URL, credential=CRED, put=c.put)
    assert not xc.publish_doc("orodruin/contract.json", {}, channel="", credential=CRED, put=c.put)


def test_the_status_has_one_reader_too():
    assert xr.read_status(json.loads(json.dumps(STATUS))) == STATUS
    for change, said in [
        ({"experiment": "T1486"}, "never holds"),
        ({"state": "won"}, "state"),
        ({"codes": ["no such thing!"]}, "codes"),
        ({"request": "x"}, "request id"),
    ]:
        with pytest.raises(xr.RequestRefused, match=said):
            xr.read_status({**STATUS, **change})
    for wire_change, said in [({"target": "vm-celebrimbor-gondolin"}, "never holds"),
                              ({"rank": 3}, "rank"), ({"runs": ["../x"]}, "run ids"),
                              ({"result": "<img>"}, "result")]:
        doc = json.loads(json.dumps(STATUS))
        doc["wires"][0].update(wire_change)
        with pytest.raises(xr.RequestRefused, match=said):
            xr.read_status(doc)


def test_the_watch_pulls_orodruins_word_into_runs_orodruin_each_blob_read_first(tmp_path):
    c = FakeContainer()
    xc.publish_doc("orodruin/contract.json", orodruin.contract_doc(PASSIVE, AT), channel=URL, credential=CRED, put=c.put)
    xc.publish_doc(f"orodruin/requests/{RID}.json", STATUS, channel=URL, credential=CRED, put=c.put)
    other = "r-20261030T080000Z-ffffff"
    xc.publish_doc(f"orodruin/requests/{other}.json", {**STATUS, "target": "vm-x"}, channel=URL,
                   credential=CRED, put=c.put)                       # a field more: refused
    xc.publish_doc(f"orodruin/requests/{'r-20261030T080000Z-eeeeee'}.json", STATUS, channel=URL,
                   credential=CRED, put=c.put)                       # another request's status
    written, skipped = xc.pull_orodruin(tmp_path / "orodruin", channel=URL, credential=CRED, get=c.get)
    assert written == 2
    assert json.loads((tmp_path / "orodruin" / "contract.json").read_text())["verdict"] == "passive"
    assert json.loads((tmp_path / "orodruin" / "requests" / f"{RID}.json").read_text()) == STATUS
    assert set(skipped) == {f"orodruin/requests/{other}.json", "orodruin/requests/r-20261030T080000Z-eeeeee.json"}
    assert not (tmp_path / "orodruin" / "requests" / f"{other}.json").exists()
    # The windows' pull never takes them for windows (the container's root only).
    assert xc.pull(tmp_path / "windows", channel=URL, credential=CRED, get=c.get) == 0


def test_the_hosted_watch_pulls_it_with_the_run_reports(tmp_path, monkeypatch):
    from analysis import hosted_report
    c = FakeContainer()
    xc.publish_doc("orodruin/contract.json", orodruin.contract_doc(PASSIVE, AT), channel=URL, credential=CRED, put=c.put)
    assert hosted_report.pull_orodruin(tmp_path, channel=URL, credential=CRED, get=c.get) == 1
    assert (tmp_path / "orodruin" / "contract.json").exists()
