"""Orodruin judges a request and runs it (DG-b, eregion_core/exercise_runner.py): the contract, the
watch, the enrollment and the zone read at each injection, the name typed compared to the name it
reads, the production rule, the cap on the whole request; the wires one after the other — a fault
and a technique never overlap on a VM, a VM isolated is waited for then skipped.

Every reader is a fake: no Azure, no injector, no model. A wire's « injector » is a function that
writes what an injector writes — its window (with the request's id), its report, its journal lines.
The oracles are written here.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from eregion_core import exercise_request as xr
from eregion_core import exercise_runner as er
from eregion_core import orodruin
from eregion_core.exercise import exercises_dir
from eregion_core.exercise_plan import Target, load_catalog

RG = "/subscriptions/s/resourceGroups/rg-celebrimbor/providers/Microsoft.Compute/virtualMachines/"
GONDOLIN, SENTINEL, BREE = RG + "vm-celebrimbor-gondolin", RG + "vm-sentinel", RG + "vm-celebrimbor-bree"
BENCH_RG = {"eregion-target": "celebrimbor"}
TARGETS = {
    GONDOLIN: (Target(GONDOLIN, BENCH_RG, {"eregion-target": "celebrimbor", "eregion-zone": "bench"}),
               "vm-celebrimbor-gondolin"),
    SENTINEL: (Target(SENTINEL, BENCH_RG, {"eregion-target": "celebrimbor", "eregion-zone": "production"}),
               "vm-sentinel"),
    BREE: (Target(BREE, BENCH_RG, {}), "vm-celebrimbor-bree"),
}
ARMED = orodruin.Verdict(orodruin.ARMED, [], {"max_injections": 20, "max_run_s": 7200})
T0 = datetime(2026, 10, 30, 8, 0, tzinfo=timezone.utc)


class Clock:
    def __init__(self):
        self.t = T0

    def __call__(self):
        return self.t

    def sleep(self, s):
        self.t += timedelta(seconds=s)


class Injectors:
    """What Annatar and Gothmog leave behind, run after run: a window naming the request, a report,
    journal lines (``calls`` each) — and the VM a fault leaves down when ``returned`` is False."""

    def __init__(self, runs, clock, calls=2, returned=True, minutes=5):
        self.runs, self.clock, self.calls, self.returned, self.minutes = runs, clock, calls, returned, minutes
        self.launched: list[tuple[list[str], dict]] = []

    def __call__(self, argv, env):
        self.launched.append((argv, env))
        n = len(self.launched)
        rid = f"run-{n}"
        request = argv[argv.index("--request") + 1]
        target = argv[argv.index("--target") + 1] if "--target" in argv else argv[3]
        xdir = exercises_dir(self.runs)
        xdir.mkdir(parents=True, exist_ok=True)
        (xdir / f"{rid}.json").write_text(json.dumps(
            {"run_id": rid, "request": request, "targets": [target.lower()]}))
        fault = argv[0] == "gothmog"
        (self.runs / f"{rid}.json").write_text(json.dumps(
            {"run_id": rid, "result": "PASS",
             "checks": {"revert_verified": "PASS" if (self.returned or not fault) else "FAIL"}}))
        with open(orodruin.audit_path(), "a") as f:
            for _ in range(self.calls):
                f.write(json.dumps({"ts": self.clock().isoformat(), "request": request,
                                    "outcome": "about_to_call"}) + "\n")
        self.clock.sleep(self.minutes * 60)
        return 0


def _runner(tmp_path, *, check=lambda: ARMED, watch=lambda: "", isolated=lambda rid: "", **kw):
    clock = kw.pop("clock", None) or Clock()
    inj = kw.pop("injectors", None) or Injectors(tmp_path / "runs", clock)
    published = []
    r = er.Runner(check=check, watch=watch, read_target=lambda rid: TARGETS[rid],
                  fault_targets=lambda: {"vm-shutdown": ["vm-celebrimbor-gondolin"]},
                  isolated=isolated, launch=inj, publish=lambda s: published.append(s.to_dict()),
                  catalog=load_catalog(), runs_dir=tmp_path / "runs", now=clock, sleep=clock.sleep,
                  say=lambda *_: None, **kw)
    return r, inj, published, clock


def _req(*pairs):
    return xr.new(list(pairs), now=T0)


def test_a_request_runs_one_wire_after_the_other_each_its_injector(tmp_path):
    r, inj, published, _ = _runner(tmp_path)
    req = _req(("T1110.001", GONDOLIN), ("vm-shutdown", GONDOLIN), ("T1486", GONDOLIN))
    status = r.run(req, {3: "vm-celebrimbor-gondolin"})
    assert status.state == "finished"
    assert [(w.state, w.runs) for w in status.wires] == [
        ("done", ["run-1"]), ("done", ["run-2"]), ("done", ["run-3"])]
    argvs = [a for a, _ in inj.launched]
    assert argvs[0][:2] == ["annatar", "wire"] and argvs[0][-2:] == ["--request", req.id]
    assert argvs[1][:3] == ["gothmog", "run", "vm-shutdown"] and argvs[1][-2:] == ["--target", GONDOLIN]
    assert argvs[2][-2:] == ["--typed-name", "vm-celebrimbor-gondolin"]
    states = [p["state"] for p in published]
    assert states[0] == "judged" and states[-1] == "finished" and "running" in states


def test_the_status_never_names_the_experiment_nor_the_target(tmp_path):
    r, _, published, _ = _runner(tmp_path)
    r.run(_req(("T1110.001", GONDOLIN)), {})
    text = json.dumps(published)
    assert "T1110.001" not in text and "gondolin" not in text
    kept = (tmp_path / "runs" / "orodruin" / "requests").glob("*.json")
    assert all("gondolin" not in p.read_text() for p in kept)


@pytest.mark.parametrize("pair, code", [
    (("T1486", SENTINEL), "zone_forbids"),            # destructive, in production
    (("vm-shutdown", SENTINEL), "zone_forbids"),       # a fault in production
    (("T1110.001", BREE), "not_enrolled"),             # the VM with a real load
    (("T1110.001", RG.replace("rg-celebrimbor", "rg-prod") + "vm-x"), "outside_scope"),
    (("T9999", GONDOLIN), "unknown_experiment"),
])
def test_orodruin_refuses_what_the_console_would_and_runs_nothing(tmp_path, pair, code):
    r, inj, published, _ = _runner(tmp_path)
    status = r.run(_req(("T1110.001", GONDOLIN), pair), {2: pair[1].rsplit("/", 1)[-1]})
    assert status.state == "refused" and status.codes == ["refused_wires"]
    assert status.wires[1].code == code
    assert inj.launched == []


def test_a_passive_contract_refuses_the_request_with_its_codes(tmp_path):
    passive = orodruin.Verdict(orodruin.PASSIVE, [{"code": "network_open", "detail": "1.1.1.1:443 reachable"}], {})
    r, inj, published, _ = _runner(tmp_path, check=lambda: passive)
    status = r.run(_req(("T1110.001", GONDOLIN)), {})
    assert status.state == "refused" and status.codes == ["passive", "network_open"]
    assert inj.launched == [] and published[-1]["codes"] == ["passive", "network_open"]
    assert "1.1.1.1" not in json.dumps(published)          # the codes, never the details


def test_no_live_watch_refuses_every_wire(tmp_path):
    r, inj, _, _ = _runner(tmp_path, watch=lambda: "no heartbeat")
    status = r.run(_req(("T1110.001", GONDOLIN), ("vm-shutdown", GONDOLIN)), {})
    assert {w.code for w in status.wires} == {"no_watch"} and inj.launched == []


@pytest.mark.parametrize("typed, said", [({}, "no name typed"), ({1: "vm-celebrimbor-bree"}, "not the target's"),
                                         ({1: "VM-CELEBRIMBOR-GONDOLIN"}, "not the target's")])
def test_a_destructive_wire_without_its_name_or_with_another_is_refused(tmp_path, typed, said):
    r, inj, _, _ = _runner(tmp_path)
    status, verdicts, *_ = r.judge(_req(("T1486", GONDOLIN)), typed)
    assert status.state == "refused" and verdicts[0].code == "typed_name" and said in verdicts[0].reason
    assert r.run(_req(("T1486", GONDOLIN)), typed).state == "refused" and inj.launched == []


def test_the_name_is_compared_to_the_name_orodruin_reads_not_to_the_requests(tmp_path, monkeypatch):
    """A request forged on H0 names a target; Azure says what it is called."""
    r, inj, _, _ = _runner(tmp_path)
    renamed = dict(TARGETS)
    renamed[GONDOLIN] = (TARGETS[GONDOLIN][0], "vm-renamed")
    r.read_target = lambda rid: renamed[rid]
    status = r.run(_req(("T1486", GONDOLIN)), {1: "vm-celebrimbor-gondolin"})
    assert status.wires[0].code == "typed_name" and inj.launched == []


def test_a_harmless_technique_needs_no_name(tmp_path):
    r, inj, _, _ = _runner(tmp_path)
    assert r.run(_req(("T1110.001", GONDOLIN)), {}).wires[0].state == "done"
    assert "--typed-name" not in inj.launched[0][0]


def test_the_zone_is_read_again_at_each_injection(tmp_path):
    """O0: a target re-tagged production between two wires: the second, destructive, never runs."""
    r, inj, _, _ = _runner(tmp_path)
    real = r.read_target
    calls = {"n": 0}

    def read(rid):
        calls["n"] += 1
        if calls["n"] > 2:   # judged on bench, then production from the second wire on
            return Target(rid, BENCH_RG, {"eregion-target": "celebrimbor", "eregion-zone": "production"}), \
                "vm-celebrimbor-gondolin"
        return real(rid)
    r.read_target = read
    status = r.run(_req(("T1110.001", GONDOLIN), ("T1486", GONDOLIN)), {2: "vm-celebrimbor-gondolin"})
    assert [w.state for w in status.wires] == ["done", "refused"]
    assert status.wires[1].code == "refused_now" and len(inj.launched) == 1


def test_the_watch_lost_between_two_wires_stops_the_rest(tmp_path):
    seen = iter(["", "", "the heartbeat is 5 min old"])
    r, inj, _, _ = _runner(tmp_path, watch=lambda: next(seen, "gone"))
    status = r.run(_req(("T1110.001", GONDOLIN), ("T1548.003", GONDOLIN)), {})
    assert [(w.state, w.code) for w in status.wires] == [("done", ""), ("skipped", "no_watch")]


def test_the_cap_holds_on_the_whole_request(tmp_path):
    """Orodruin's 20 calls are the request's, not each wire's: what is journaled under the request
    counts, and each injector is given what is left."""
    small = orodruin.Verdict(orodruin.ARMED, [], {"max_injections": 5, "max_run_s": 7200})
    clock = Clock()
    inj = Injectors(tmp_path / "runs", clock, calls=3)
    r, _, _, _ = _runner(tmp_path, check=lambda: small, clock=clock, injectors=inj)
    status = r.run(_req(("T1110.001", GONDOLIN), ("T1548.003", GONDOLIN), ("T1136.001", GONDOLIN)), {})
    assert [(w.state, w.code) for w in status.wires] == [("done", ""), ("done", ""), ("skipped", "over_cap")]
    assert [env[orodruin.MAX_INJECTIONS_ENV] for _, env in inj.launched] == ["5", "2"]


def test_the_time_cap_holds_on_the_whole_request(tmp_path):
    small = orodruin.Verdict(orodruin.ARMED, [], {"max_injections": 20, "max_run_s": 1800})
    clock = Clock()
    inj = Injectors(tmp_path / "runs", clock, minutes=16)
    r, _, _, _ = _runner(tmp_path, check=lambda: small, clock=clock, injectors=inj)
    status = r.run(_req(("T1110.001", GONDOLIN), ("T1548.003", GONDOLIN), ("T1136.001", GONDOLIN)), {})
    assert [w.code for w in status.wires] == ["", "", "over_cap"]
    assert int(inj.launched[1][1][orodruin.MAX_RUN_S_ENV]) <= 1800 - 16 * 60


def test_more_wires_than_the_declared_cap_are_refused_at_judgment(tmp_path):
    small = orodruin.Verdict(orodruin.ARMED, [], {"max_injections": 2, "max_run_s": 7200})
    r, inj, _, _ = _runner(tmp_path, check=lambda: small)
    status = r.run(_req(("T1110.001", GONDOLIN), ("T1548.003", GONDOLIN), ("T1136.001", GONDOLIN)), {})
    assert status.state == "refused" and status.wires[2].code == "over_cap" and inj.launched == []


def test_a_technique_waits_for_the_return_of_its_vm_after_a_fault(tmp_path):
    """A fault whose return was not verified: no other wire on that VM — never an attack on a VM
    still down, never a fault and a technique overlapping."""
    clock = Clock()
    inj = Injectors(tmp_path / "runs", clock, returned=False)
    r, _, _, _ = _runner(tmp_path, clock=clock, injectors=inj)
    status = r.run(_req(("vm-shutdown", GONDOLIN), ("T1110.001", GONDOLIN)), {})
    assert [(w.state, w.code) for w in status.wires] == [("done", ""), ("skipped", "not_returned")]
    assert len(inj.launched) == 1


def test_a_vm_isolated_is_waited_for_then_its_wire_runs(tmp_path):
    held = iter(["Glorfindel's glorfindel-iso-vm-celebrimbor-gondolin-nic-gondolin-3f2a1b in nsg-x"] * 3)
    r, inj, _, clock = _runner(tmp_path, isolated=lambda rid: next(held, ""))
    status = r.run(_req(("T1110.001", GONDOLIN)), {})
    assert status.wires[0].state == "done" and clock.t >= T0 + timedelta(seconds=3 * er.POLL_S)


def test_a_vm_still_isolated_after_the_wait_is_skipped_never_released(tmp_path):
    r, inj, _, clock = _runner(tmp_path, isolated=lambda rid: "Glorfindel's glorfindel-iso-vm-celebrimbor-gondolin-nic-gondolin-3f2a1b-out")
    status = r.run(_req(("T1110.001", GONDOLIN), ("T1548.003", GONDOLIN)), {})
    assert [(w.state, w.code) for w in status.wires] == [("skipped", "isolated"), ("skipped", "isolated")]
    assert inj.launched == []                     # nothing launched, and nothing to release either
    assert not any("release" in " ".join(a) or "reset" in " ".join(a) for a, _ in inj.launched)


def test_main_refuses_an_unreadable_request(tmp_path, capsys):
    p = tmp_path / "r-20261030T075200Z-a1b2c3.json"
    p.write_text(json.dumps({"id": "r-20261030T075200Z-a1b2c3", "at": T0.isoformat(),
                             "wires": [{"experiment": "T1486", "target": GONDOLIN, "rank": 1, "zone": "bench"}]}))
    assert er.main([str(p)]) == 1
    assert "never holds" in capsys.readouterr().err


def test_each_journal_line_of_a_wire_names_its_request_and_the_runner_counts_them(tmp_path):
    """The injector's session writes the request on each line, before the call (O1); the runner
    counts the request's calls from it — never fewer than were made."""
    _, session = orodruin.arm("run-x", "annatar", orodruin.Verdict(orodruin.ARMED, [], {
        "max_injections": 20, "max_run_s": 3600}), request="r-20261030T080000Z-abcdef")
    session.offhost = lambda *a, **k: None
    session.before_call("runCommand", GONDOLIN)
    session.before_call("runCommand", GONDOLIN)
    lines = [json.loads(ln) for ln in orodruin.audit_path().read_text().splitlines()]
    assert {ln["request"] for ln in lines} == {"r-20261030T080000Z-abcdef"}
    r, _, _, _ = _runner(tmp_path)
    assert r._calls_used("r-20261030T080000Z-abcdef", T0 - timedelta(days=3650)) == 2
    assert r._calls_used("r-20261030T080000Z-ffffff", T0 - timedelta(days=3650)) == 0


def test_orodruin_publishes_its_verdict_and_the_requests_status_to_the_channel(tmp_path, monkeypatch):
    """Part 6: at the judgment, the verdict (orodruin/contract.json); at each step, the status
    (orodruin/requests/<id>.json) — the same container as the windows, no right more."""
    from eregion_core import exercise_channel as xc
    from tests.unit.fake_container import CRED, URL, FakeContainer
    c = FakeContainer()
    monkeypatch.setenv(xc.CHANNEL_ENV, URL)
    monkeypatch.setattr(xc, "_credential", CRED)
    monkeypatch.setattr("requests.put", c.put)
    clock = Clock()
    r = er.Runner(check=lambda: ARMED, watch=lambda: "", read_target=lambda rid: TARGETS[rid],
                  fault_targets=lambda: {}, isolated=lambda rid: "",
                  launch=Injectors(tmp_path / "runs", clock), catalog=load_catalog(),
                  runs_dir=tmp_path / "runs", now=clock, sleep=clock.sleep, say=lambda *_: None)
    req = _req(("T1110.001", GONDOLIN))
    r.run(req, {})
    name = f"orodruin/requests/{req.id}.json"
    assert c.puts[0] == "orodruin/contract.json" and name in c.puts
    assert json.loads(c.blobs[name][0])["state"] == "finished"
    assert xr.read_status(json.loads(c.blobs[name][0]))
