"""G1 (#76) — the rate of faults taken for an attack, over every Gothmog run (analysis/fault_rate.py):
per run, a fault is taken for an attack when Glorfindel recommended or executed an isolation or a
block on its target during it (BL1's ``fault_run``, unchanged); a run is measured only when its
effect was seen in Glorfindel's telemetry, with a live watch before and after it (review 2), and its
decisions read on this host — the watch's files, none cut since it started (review 1); a decision
in a fault's own window and in the next one leaves the first not measured. Mutants M2410–M2424.

The reports are Gothmog's own — one written by its real engine on G0's bench in memory
(tests/unit/test_gothmog_noise.py) — and the watch's lines as store_cycle writes them
(tests/unit/test_containment.py). No Azure, no model."""
from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone

import pytest

from analysis import fault_rate as fr
from eregion_core.run_report import read_run
from tests.unit.test_containment import OTHER, VM, _held, _iso, _line
from tests.unit.test_gothmog_noise import bench, noise  # noqa: F401  (fixtures, by their names)

T = 1_800_000_000.0     # a fault's start (epoch)


def _fault(run_id="gothmog-1", fault="vm-disk-write", start=T, end=T + 600, targets=(VM,),
           effective="PASS", started=True, without=False, watch_after="PASS"):
    """A Gothmog report, as runner/engine.py writes it, read as every reader reads it (C1)."""
    checks = {"targets": "PASS", "steady_state_before": "PASS", "execution": "PASS",
              "revert_verified": "PASS"}
    if effective is not None:
        checks["fault_effective"] = effective
    if watch_after is not None and not without:
        checks["watch_after"] = watch_after
    if not started:
        checks = {"targets": "PASS", "steady_state_before": "PASS", "fault_started": "FAIL (x)"}
    metrics = {"run_format": 1, "kind": "fault", "injector": "gothmog", "experiment_id": fault,
               "fault": fault, "targets": list(targets), "fault_start": _iso(start),
               "fault_end": _iso(end)}
    if without:
        metrics["without_glorfindel"] = True
    return read_run({"scenario": fault, "run_id": run_id, "mitre": "", "result": "PASS",
                     "metrics": metrics, "thresholds": {}, "checks": checks})


def _attack(run_id="r1", ttp="T1486", at=T + 120, resource=VM):
    return read_run({"scenario": ttp, "run_id": run_id, "mitre": ttp, "result": "PASS",
                     "metrics": {"kind": "technique", "injector": "annatar", "attack_time": _iso(at),
                                 "resource_id": resource}, "thresholds": {}, "checks": {}})


def _watch(records, mtime=T + 300):
    """The watch's records, from one file read whole — this host is the watch's."""
    return fr.Watch([fr.WatchFile("watch-ransomware-disk-write_debug.jsonl", mtime)], list(records))


def _isolate(seen, **kw):
    return _line("isolate_vm", seen=seen, at=seen + 30, verified_at=seen + 25, ttp="T1486",
                 signal_id=f"sig-{seen}", **kw)


# ── The rate, per run ──────────────────────────────────────────────────────────────────

def _recommended(seen, sid):
    """An isolation the mode held (human_only): recommended, never executed."""
    line = _held("mode_hold")
    return {**line, "signal": {**line["signal"], "timestamp": _iso(seen), "ttp": "T1486", "signal_id": sid}}


def test_a_fault_is_taken_for_an_attack_on_a_recommendation_or_an_execution():
    """M2410: recommended counts as much as executed — a held isolation is still Glorfindel
    taking benign noise for an attack. Per run: two recommendations on one run are one fault."""
    runs = [_fault("g1"), _fault("g2", start=T + 3600, end=T + 4200), _fault("g3", start=T + 7200, end=T + 7800)]
    records = [_recommended(T + 200, "h1"), _recommended(T + 260, "h2"), _isolate(T + 3900)]
    out = fr.rate(fr.measure(runs, _watch(records)))
    assert (out["measured"], out["taken"], out["recommended"], out["executed"]) == (3, 2, 3, 1)
    assert out["rate"] == pytest.approx(2 / 3)
    assert [t["run_id"] for t in out["taken_runs"]] == ["g1", "g2"]
    assert out["by_fault"]["vm-disk-write"]["taken"] == 2


def test_what_is_not_taken_for_an_attack():
    """BL1's definition, unchanged: another VM, before or long after the fault, a snapshot."""
    runs = [_fault()]
    records = [_isolate(T + 300, resource=OTHER), _isolate(T - 120), _isolate(T + 600 + 16 * 60),
               _line("snapshot", seen=T + 300, ttp="T1486", signal_id="snap")]
    out = fr.rate(fr.measure(runs, _watch(records)))
    assert (out["measured"], out["taken"], out["rate"]) == (1, 0, 0.0)


def test_noise_glorfindel_never_saw_measures_nothing():
    """M2412: a fault whose effect was not seen in Glorfindel's telemetry is not « Glorfindel did
    nothing »; an isolation during it is not its reaction to it either. Said, never counted."""
    runs = [_fault("seen"), _fault("unseen", effective="FAIL", start=T + 3600, end=T + 4200)]
    out = fr.rate(fr.measure(runs, _watch([_isolate(T + 3900)])))
    assert (out["faults"], out["measured"], out["taken"]) == (2, 1, 0)
    assert out["unmeasured"] == [{"run_id": "unseen", "fault": "vm-disk-write", "why": fr.NOT_SEEN}]


@pytest.mark.parametrize("kw, why", [
    ({"without": True}, "sans Glorfindel"),           # M2411
    ({"started": False}, fr.NOT_STARTED),
    ({"effective": None}, fr.EFFECT_UNSAID),
    ({"targets": ()}, "cibles inconnues"),
])
def test_a_run_that_cannot_measure_glorfindel_says_why(kw, why):
    out = fr.rate(fr.measure([_fault(**kw)], _watch([_isolate(T + 300)])))
    assert out["measured"] == 0 and out["taken"] == 0
    assert why in out["unmeasured"][0]["why"]


def test_the_rate_is_over_measured_faults_and_unknown_when_none_is():
    """M2414: the runs not measured stay out of the denominator; none measured, the rate is
    None — never 0."""
    runs = [_fault("g1"), _fault("g2", without=True, start=T + 3600, end=T + 4200)]
    out = fr.rate(fr.measure(runs, _watch([_isolate(T + 300)])))
    assert (out["faults"], out["measured"], out["rate"]) == (2, 1, 1.0)
    assert fr.rate(fr.measure([_fault(without=True)], _watch([])))["rate"] is None
    assert fr.rate([])["rate"] is None


def test_a_decision_on_a_technique_played_on_the_vm_is_the_techniques():
    """M2413 (X1 ahead): an attack run on the noisy VM — its isolation is the attack's, not the
    fault's; the same technique on another VM is still the fault's."""
    runs = [_fault(), _attack(at=T + 120)]
    assert fr.rate(fr.measure(runs, _watch([_isolate(T + 300)])))["taken"] == 0
    runs = [_fault(), _attack(at=T + 120, resource=OTHER)]
    assert fr.rate(fr.measure(runs, _watch([_isolate(T + 300)])))["taken"] == 1


# ── Review 1: no decision known is never « none taken »; a decision is one fault's ─────

@pytest.mark.parametrize("run, watch, why", [
    (_fault(), fr.Watch(), fr.NO_WATCH),                              # M2416: another host (Orodruin)
    (_fault(), fr.Watch([fr.WatchFile("watch-x_debug.jsonl", T + 900, "2 ligne(s) illisible(s)")]),
     fr.WATCH_CUT),                                                   # M2418
    (_fault(watch_after="FAIL (local file: last heartbeat 3 min ago)"), _watch([]), fr.WATCH_GONE),  # M2417
    (_fault(watch_after=None), _watch([]), fr.WATCH_AFTER_UNSAID),    # M2422: a report from before
])
def test_a_fault_whose_decisions_are_not_known_is_not_measured(run, watch, why):
    """Reviews 1 and 2 of #387: without the watch looking, before and after the fault, and its
    decisions read here, « 0 taken » would be a claim nobody checked."""
    out = fr.rate(fr.measure([run], watch))
    assert (out["measured"], out["rate"]) == (0, None)
    assert out["unmeasured"][0]["why"].startswith(why)


def test_a_watch_dead_during_the_fault_is_not_measured_by_a_file_written_the_next_day(tmp_path):
    """Review 2, point 1 (the reviewer's test_A): the watch writes only when it decides — a
    detection on another VM the next day says nothing of the fault. What does is the watch
    read after it, by Gothmog: gone, the fault is not measured, whatever files come later."""
    runs = tmp_path / "runs"
    runs.mkdir()
    report = {"scenario": "vm-cpu-pressure", "run_id": "g-1", "mitre": "", "result": "FAIL",
              "metrics": {"run_format": 1, "kind": "fault", "injector": "gothmog",
                          "experiment_id": "vm-cpu-pressure", "fault": "vm-cpu-pressure", "targets": [VM],
                          "fault_start": _iso(T), "fault_end": _iso(T + 600)},
              "thresholds": {}, "checks": {"fault_effective": "PASS",
                                           "watch_after": "FAIL (local file: last heartbeat 12 min ago)"}}
    (runs / "g-1.json").write_text(json.dumps(report))
    other = runs / "watch-ssh-brute-force-1_debug.jsonl"
    other.write_text(json.dumps(_isolate(T + 86400, resource=OTHER)) + "\n")
    os.utime(other, (T + 86400, T + 86400))
    s = fr.load(runs, now=T + 86400 + 60)
    assert (s["faults"], s["measured"], s["rate"]) == (1, 0, None)
    assert s["unmeasured"][0]["why"] == fr.WATCH_GONE


def test_a_fault_well_ignored_is_measured_without_any_file_written_since():
    """The other side of review 2, point 1: the watch live before and after, nothing decided —
    no file written meanwhile, and that is the measure: 0 of 1."""
    out = fr.rate(fr.measure([_fault()], _watch([], mtime=T - 7 * 86400)))
    assert (out["measured"], out["taken"], out["rate"]) == (1, 0, 0.0)


def test_a_file_cut_before_the_fault_says_nothing_of_it():
    watch = fr.Watch([fr.WatchFile("watch-old_debug.jsonl", T - 3600, "1 ligne(s) illisible(s)"),
                      fr.WatchFile("watch-new_debug.jsonl", T + 900)])
    assert fr.rate(fr.measure([_fault()], watch))["measured"] == 1


def test_the_watch_files_are_said_read_whole_or_not(tmp_path):
    runs = tmp_path / "runs"
    runs.mkdir()
    (runs / "watch-a_debug.jsonl").write_text(json.dumps(_isolate(T + 300)) + "\n\n")
    (runs / "watch-b_debug.jsonl").write_text(json.dumps(_isolate(T + 400)) + "\n{cut\n[1]\n")
    (runs / "watch-c_debug.jsonl").write_bytes(b"\xff\xfe")
    (runs / "other_debug.jsonl").write_text("not the watch's\n")
    watch = fr.read_watch(runs)
    assert {f.name: f.why for f in watch.files} == {
        "watch-a_debug.jsonl": "", "watch-b_debug.jsonl": "2 ligne(s) illisible(s)",
        "watch-c_debug.jsonl": "illisible (UnicodeDecodeError)"}
    assert len(watch.records) == 2
    # A file last written before the period is listed, never read.
    assert fr.read_watch(runs, since=datetime.now(timezone.utc).timestamp() + 3600).records == []


def test_a_decision_during_the_next_fault_is_the_next_faults():
    """Review 1, point 3: two faults one after the other on the same VM (the README's step 3);
    an isolation during the second is the second's, once — and since it also falls in the
    first's own window (its end plus the grace), the first is not measured (review 2)."""
    runs = [_fault("disk", start=T, end=T + 600),
            _fault("cpu", fault="vm-cpu-pressure", start=T + 900, end=T + 1500)]
    out = fr.rate(fr.measure(runs, _watch([_isolate(T + 1000)])))
    assert (out["taken"], out["recommended"]) == (1, 1)
    assert [t["run_id"] for t in out["taken_runs"]] == ["cpu"]
    assert out["unmeasured"] == [{"run_id": "disk", "fault": "vm-disk-write", "why": fr.SHARED}]
    # On another VM, the next fault does not cut the first one's window short.
    runs[1] = _fault("cpu", fault="vm-cpu-pressure", start=T + 900, end=T + 1500, targets=(OTHER,))
    assert [t["run_id"] for t in fr.rate(fr.measure(runs, _watch([_isolate(T + 1000)])))["taken_runs"]] == ["disk"]


def test_a_late_decision_of_a_fault_during_the_next_one_leaves_it_not_measured():
    """M2423 — review 2, point 2 (the reviewer's test_B): an isolation 150 s after the disk
    writes ended, 50 s into a CPU load whose effect was never seen. The CPU's by its window, the
    disk's tail maybe: the disk is not « measured, 0 taken »."""
    runs = [_fault("disk", start=T, end=T + 600),
            _fault("cpu", fault="vm-cpu-pressure", start=T + 700, end=T + 1300, effective="FAIL")]
    out = fr.rate(fr.measure(runs, _watch([_isolate(T + 750)])))
    assert (out["measured"], out["taken"], out["rate"]) == (0, 0, None)
    assert {u["run_id"]: u["why"] for u in out["unmeasured"]} == {"disk": fr.SHARED, "cpu": fr.NOT_SEEN}
    # Past the disk's own window (its end plus the grace), the decision is the CPU's alone.
    runs[1] = _fault("cpu", fault="vm-cpu-pressure", start=T + 700, end=T + 2700, effective="FAIL")
    out = fr.rate(fr.measure(runs, _watch([_isolate(T + 1600)])))
    assert (out["measured"], out["taken"]) == (1, 0)


def test_a_decision_at_two_faults_at_once_is_counted_once():
    runs = [_fault("a"), _fault("b")]                       # the same start, the same VM
    out = fr.rate(fr.measure(runs, _watch([_isolate(T + 300)])))
    assert (out["taken"], out["recommended"]) == (1, 1)


def test_the_exercise_window_bounds_the_fault():
    """Closed with its grace before the end plus 15 min: a decision after it is not the fault's."""
    runs = [_fault()]
    late = [_isolate(T + 600 + 10 * 60)]
    assert fr.rate(fr.measure(runs, _watch(late)))["taken"] == 1
    assert fr.rate(fr.measure(runs, _watch(late), windows={"gothmog-1": T + 600 + 5 * 60}))["taken"] == 0


def test_the_unified_view_says_whether_a_fault_was_seen():
    """M2415 (C1's view, eregion_core/run_report.py): False only when the report says FAIL."""
    assert _fault()["effective"] is True
    assert _fault(effective="FAIL")["effective"] is False
    assert _fault(effective=None)["effective"] is None


# ── From the files: Gothmog's own report, the watch's lines, the CLI ────────────────────

def test_the_rate_reads_the_report_gothmog_writes(noise, tmp_path):  # noqa: F811
    """End to end on this host's files: a noise fault run by Gothmog's real engine, then the
    watch's line recommending an isolation of its VM during it — taken for an attack, 1 of 1."""
    clock, world, engine = noise
    world()
    out = engine().run("vm-disk-write", skip_confirm=True)
    assert out.result == "PASS", out.report["checks"]
    m = out.report["metrics"]
    start = datetime.fromisoformat(m["fault_start"]).timestamp()
    held = _line("isolate_vm", seen=start + 240, at=start + 270, verified_at=None, executed=False,
                 verified=None, status="escalated", escalation_type="mode_hold", escalate=True,
                 resource=m["targets"][0].lower(), ttp="T1486", signal_id="sig-noise")
    (tmp_path / "runs" / "watch-ransomware-disk-write_debug.jsonl").write_text(json.dumps(held) + "\n")
    now = start + 3600
    summary = fr.load(tmp_path / "runs", now=now)
    assert (summary["measured"], summary["taken"], summary["recommended"], summary["executed"]) == (1, 1, 1, 0)
    assert summary["by_fault"] == {"vm-disk-write": {"faults": 1, "measured": 1, "taken": 1, "rate": 1.0,
                                                     "recommended": 1, "executed": 0}}
    assert "**1 sur 1**" in fr.render(summary)
    # Older than the period: out of it.
    assert fr.load(tmp_path / "runs", now=now + 31 * 86400)["faults"] == 0


def test_the_cli_prints_the_rate_and_json(tmp_path, capsys):
    runs = tmp_path / "runs"
    runs.mkdir()
    now = datetime.now(timezone.utc)
    report = {"scenario": "vm-restart", "run_id": "gothmog-x", "mitre": "", "result": "FAIL",
              "metrics": {"kind": "fault", "injector": "gothmog", "experiment_id": "vm-restart",
                          "targets": [VM], "fault_start": (now - timedelta(hours=1)).isoformat(),
                          "fault_end": (now - timedelta(minutes=58)).isoformat()},
              "thresholds": {}, "checks": {"fault_effective": "FAIL"}}
    (runs / "gothmog-x.json").write_text(json.dumps(report))
    assert fr.main(["--runs-dir", str(runs)]) == 0
    text = capsys.readouterr().out
    assert "0 sur 0" in text and "taux inconnu" in text and "gothmog-x" in text
    assert fr.main(["--runs-dir", str(runs), "--json"]) == 0
    body = json.loads(capsys.readouterr().out)
    assert body["rate"] is None and body["unmeasured"][0]["why"] == fr.NOT_SEEN


def test_the_make_targets_check_their_days_before_any_shell():
    """Phony; DAYS a plain number before the command, here and on H0 (read only)."""
    from pathlib import Path
    makefile = (Path(__file__).resolve().parents[2] / "Makefile").read_text()
    phony = makefile.split(".PHONY:", 1)[1].split("\n\n", 1)[0]
    lines = makefile.splitlines()
    for target in ("fault-rate", "glorfindel-host-fault-rate"):
        start = next(i for i, ln in enumerate(lines) if ln.split(" ")[0] == f"{target}:")
        recipe = [ln for ln in lines[start + 1:start + 4] if ln.startswith("\t")]
        assert target in phony
        assert recipe[0].startswith('\t@case "$(DAYS)" in *[!0-9]*) echo "DAYS invalide')
        assert "-m analysis.fault_rate --runs-dir runs --days $(or $(DAYS),30)" in recipe[1]
