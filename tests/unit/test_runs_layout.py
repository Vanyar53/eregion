"""SEC18 (N-05, #455): runs/ — one directory per writer (eregion_core/runs_layout.py).

A reader looks for a file only in its writer's directory; anything else is never read and is said
(``survey``). A report's own word is held against its directory. The former layout is moved once,
on the host, to its writers' directories when the writer is told without ambiguity — the rest left
and said, nothing deleted. No Azure, no model.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone

import pytest

from eregion_core import exercise, run_report, runs_layout as L


@pytest.fixture
def root(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("EREGION_EXERCISES_DIR", raising=False)
    return tmp_path / "runs"


def _report(injector=None, kind=None, rid="r1"):
    m = {"attack_time": 1_800_000_000.0}
    if injector:
        m["injector"] = injector
    if kind:
        m["kind"] = kind
    return {"run_id": rid, "scenario": "s", "mitre": "T1136.001", "result": "PASS", "metrics": m}


# ── Where each writer writes ─────────────────────────────────────────────────────────────

def test_each_writer_has_its_own_directory(root):
    assert [L.dir_of(w) for w in L.WRITERS] == [L.ROOT / w for w in
                                                ("glorfindel", "console", "annatar", "gothmog", "orodruin",
                                                 "verdicts", "bot")]
    assert L.dir_of(L.ANNATAR, root) == root / "annatar"
    with pytest.raises(ValueError):
        L.dir_of("runs")
    assert L.beside(root / "annatar", L.GLORFINDEL) == root / "glorfindel"
    assert L.beside(root / "glorfindel", L.GLORFINDEL) == root / "glorfindel"


def test_a_window_goes_to_its_injectors_own_directory(root):
    """M3230: Annatar's window in runs/annatar/exercises, Gothmog's in runs/gothmog/exercises —
    never the watch's directory, never the former runs/exercises."""
    exercise.open_window("a1", injector="annatar", kind="technique", experiment="T1110.001", targets=["/x/vm"])
    exercise.open_window("g1", injector="gothmog", kind="fault", experiment="vm-shutdown", targets=["/x/vm"])
    assert (root / "annatar" / "exercises" / "a1.json").is_file()
    assert (root / "gothmog" / "exercises" / "g1.json").is_file()
    assert not (root / "exercises").exists() and not (root / "glorfindel" / "exercises").exists()
    exercise.close_window("a1", injector="annatar")
    assert json.loads((root / "annatar" / "exercises" / "a1.json").read_text())["end"]


def test_the_watch_reads_every_windows_directory_and_purges_only_its_own(root):
    """M3231: the injectors' windows are read-only to the watch — an old one there is left as it
    is (never believed); the pulled one, in the watch's directory, is purged (its tombstone)."""
    old = datetime.now(timezone.utc) - timedelta(seconds=exercise.PURGE_AFTER_S + 3 * 3600)
    for writer, rid in (("annatar", "a-old"), ("glorfindel", "p-old")):
        exercise.open_window(rid, injector="annatar", kind="technique", experiment="x", targets=["/x/vm"],
                             now=old, directory=L.dir_of(writer) / "exercises")
    exercise.open_window("live", injector="annatar", kind="technique", experiment="x", targets=["/x/vm"])
    for p in (root / "annatar" / "exercises").glob("*.json"):   # written long enough ago
        ts = (old if p.stem == "a-old" else datetime.now(timezone.utc)).timestamp()
        os.utime(p, (ts, ts))
    pulled = root / "glorfindel" / "exercises" / "p-old.json"
    os.utime(pulled, (old.timestamp(), old.timestamp()))
    # The watch saw both when they were written (SEC14): believed, then past their purge.
    seen = root.parent / "seen.json"
    seen.write_text(json.dumps({
        rid: {"seen": old.isoformat(), "end": None,
              "fields": exercise._fields(json.loads((L.dir_of(w) / "exercises" / f"{rid}.json").read_text()))}
        for w, rid in (("annatar", "a-old"), ("glorfindel", "p-old"))}))
    got = exercise.load_windows(seen=seen)
    assert [w["run_id"] for w in got] == ["live"]
    assert "purged_at" in json.loads(pulled.read_text())
    assert "purged_at" not in json.loads((root / "annatar" / "exercises" / "a-old.json").read_text())


# ── What a reader does not read: said ──────────────────────────────────────────────────

def test_the_survey_says_the_former_layout_and_another_writers_file(root):
    """M3237: a file flat in runs/ (the former layout), an injector's signal in the console's
    directory, a cycle of the watch in Annatar's — each said, never read; a write in progress
    (a dot) and the writers' own files are not."""
    for w in L.WRITERS:
        L.dir_of(w, root).mkdir(parents=True)
    (root / "old_signals.jsonl").write_text("{}\n")
    (root / "console" / "x_signals.jsonl").write_text("{}\n")
    (root / "annatar" / "r1_debug.jsonl").write_text("{}\n")
    (root / "annatar" / "r1_signals.jsonl").write_text("{}\n")
    (root / "console" / "manual_actions.jsonl").write_text("{}\n")
    (root / "glorfindel" / ".r1.json.abc").write_text("{}")
    (root / "glorfindel" / "campaigns").mkdir()
    found = {str(p.relative_to(root)): why for p, why in L.survey(root)}
    assert set(found) == {"old_signals.jsonl", "console/x_signals.jsonl", "annatar/r1_debug.jsonl"}
    assert "ancienne disposition" in found["old_signals.jsonl"] and "make runs-migrate" in found["old_signals.jsonl"]
    assert "pas un fichier de console" in found["console/x_signals.jsonl"]
    assert "runs/annatar/ ou runs/gothmog/" in found["console/x_signals.jsonl"]
    assert "runs/glorfindel/" in found["annatar/r1_debug.jsonl"]


def test_a_stray_is_said_once_whatever_the_passes(root):
    (root / "console").mkdir(parents=True)
    (root / "console" / "x_signals.jsonl").write_text("{}\n")
    said: list[str] = []
    assert L.say_strays(root, said.append) == 1
    assert L.say_strays(root, said.append) == 0
    assert len(said) == 1 and "x_signals.jsonl" in said[0]


def test_a_report_in_an_injectors_directory_says_that_injector(root, capsys):
    """M3233: Annatar's directory holds Annatar's runs only — a report there that says Gothmog
    (a fault counted against Glorfindel) is never read, said once; the watch's directory holds
    the reports it pulled, of either."""
    for w in ("annatar", "gothmog", "glorfindel"):
        L.dir_of(w, root).mkdir(parents=True)
    forged = root / "annatar" / "f1.json"
    forged.write_text(json.dumps(_report("gothmog", "fault", "f1") | {"metrics": {
        "injector": "gothmog", "kind": "fault", "fault_start": "2026-11-01T10:00:00+00:00"}}))
    (root / "annatar" / "a1.json").write_text(json.dumps(_report(rid="a1")))           # before C1: Annatar's
    (root / "glorfindel" / "g1.json").write_text(json.dumps({"run_id": "g1", "metrics": {
        "injector": "gothmog", "kind": "fault", "fault_start": "2026-11-01T10:00:00+00:00"}}))
    assert L.report_refusal(forged, json.loads(forged.read_text()))
    runs = run_report.read_reports(L.run_reports(root))
    assert sorted(r["run_id"] for r in runs) == ["a1", "g1"]
    run_report.read_reports(L.run_reports(root))
    assert capsys.readouterr().out.count("f1.json") == 1


def test_the_analysis_of_a_campaign_goes_to_the_watchs_directory(root):
    assert L.campaign_output(root / "annatar" / "campaigns" / "C1") == root / "glorfindel" / "campaigns" / "C1"
    assert L.campaign_output(root / "glorfindel" / "campaigns" / "C1") == root / "glorfindel" / "campaigns" / "C1"
    assert L.campaign_output(root / "copy" / "C1") == root / "copy" / "C1"     # named by hand


def test_the_writer_of_a_path(root):
    assert L.writer_of(root / "annatar" / "x.json") == "annatar"
    assert L.writer_of(root / "glorfindel" / "orodruin" / "requests" / "r.json") == "glorfindel"
    assert L.writer_of(root / "glorfindel" / "campaigns" / "annatar" / "runs" / "x.json") == "glorfindel"
    assert L.writer_of(root / "x.json") == ""


# ── The migration of the former layout ──────────────────────────────────────────────────

def _flat_poste(root):
    """The former layout of a workstation: every writer flat in runs/."""
    root.mkdir(parents=True)
    (root / "20261101T100000Z_signals.jsonl").write_text("{}\n")
    (root / "20261101T100000Z.json").write_text(json.dumps(_report("annatar", rid="20261101T100000Z")))
    (root / "gothmog-1.json").write_text(json.dumps(_report("gothmog", "fault", "gothmog-1")))
    (root / "old.json").write_text(json.dumps(_report(rid="old")))                    # before C1
    (root / "watch-x_debug.jsonl").write_text("{}\n")
    (root / "manual_actions.jsonl").write_text("{}\n")
    (root / "gothmog").mkdir()
    (root / "gothmog" / "gothmog-1_signals.jsonl").write_text("{}\n")
    (root / "exercises").mkdir()
    (root / "exercises" / "20261101T100000Z.json").write_text(json.dumps({"run_id": "x", "injector": "annatar"}))
    (root / "exercises" / "gothmog-1.json").write_text(json.dumps({"run_id": "g", "injector": "gothmog"}))
    c = root / "campaigns" / "C1"
    (c / "runs").mkdir(parents=True)
    (c / "manifest.json").write_text("{}")
    (c / "runs" / "r1.json").write_text("{}")
    (c / "report.md").write_text("# r\n")
    (c / "replay.json").write_text("{}")
    (root / "notes.txt").write_text("mine")
    (root / "weird.json").write_text("[1, 2]")


def test_the_migration_moves_each_file_to_its_writer_and_leaves_the_rest_said(root):
    _flat_poste(root)
    said: list[str] = []
    moved, left = L.migrate(root, say=said.append)
    rel = sorted(str(p.relative_to(root)) for p in root.rglob("*") if p.is_file())
    assert rel == sorted([
        "annatar/20261101T100000Z_signals.jsonl", "annatar/20261101T100000Z.json", "annatar/old.json",
        "gothmog/gothmog-1.json", "gothmog/gothmog-1_signals.jsonl",
        "glorfindel/watch-x_debug.jsonl", "console/manual_actions.jsonl",
        "annatar/exercises/20261101T100000Z.json", "gothmog/exercises/gothmog-1.json",
        "annatar/campaigns/C1/manifest.json", "annatar/campaigns/C1/runs/r1.json",
        "glorfindel/campaigns/C1/report.md", "glorfindel/campaigns/C1/replay.json",
        "notes.txt", "weird.json"])
    assert sorted(str(p.relative_to(root)) for p, _ in left) == ["notes.txt", "weird.json"]
    assert len(said) == 2 and all("jamais lu" in m and "rien n'est effacé" in m for m in said)
    assert all(L.dir_of(w, root).is_dir() for w in L.WRITERS)
    assert [str(p.relative_to(root)) for p, _ in L.survey(root)] == ["notes.txt", "weird.json"]
    assert L.migrate(root, say=lambda m: None)[0] == 0                  # run again: nothing more


def test_the_migration_on_h0_gives_the_pull_to_the_watch(root):
    """M3235, M3236: on H0 everything flat but the operator's gestures was the watch's — its
    pulled reports (their marker), its pulled windows (channel_created), its pulled campaigns
    (.pulled), its copy of Orodruin's statuses (contract.json)."""
    root.mkdir(parents=True)
    (root / ".pulled-runs").mkdir()
    (root / ".pulled-runs" / "r9").touch()
    (root / "r9.json").write_text(json.dumps(_report("annatar", rid="r9")))
    (root / "exercises").mkdir()
    (root / "exercises" / "r9.json").write_text(json.dumps({"run_id": "r9", "injector": "annatar",
                                                            "channel_created": "2026-11-01T10:00:00+00:00"}))
    c = root / "campaigns" / "C2"
    c.mkdir(parents=True)
    (c / ".pulled").touch()
    (c / "manifest.json").write_text("{}")
    (c / "report.md").write_text("# r\n")
    (root / "orodruin" / "requests").mkdir(parents=True)
    (root / "orodruin" / "contract.json").write_text("{}")
    (root / "orodruin" / "requests" / "r-1.json").write_text("{}")
    moved, left = L.migrate(root, say=lambda m: None)
    assert left == []
    for rel in ("glorfindel/r9.json", "glorfindel/.pulled-runs/r9", "glorfindel/exercises/r9.json",
                "glorfindel/campaigns/C2/manifest.json", "glorfindel/campaigns/C2/.pulled",
                "glorfindel/campaigns/C2/report.md", "glorfindel/orodruin/contract.json",
                "glorfindel/orodruin/requests/r-1.json"):
        assert (root / rel).exists(), rel
    assert (root / "orodruin").is_dir() and not any((root / "orodruin").iterdir())


def test_the_migration_on_orodruin_keeps_its_directory(root):
    """And makes the injectors' host's directories only: no watch there, no local verdicts."""
    (root / "orodruin" / "requests").mkdir(parents=True)
    (root / "orodruin" / "audit.jsonl").write_text("{}\n")
    (root / "orodruin" / "requests" / "played.jsonl").write_text("{}\n")
    assert L.main(["migrate", str(root), "--orodruin"]) == 0
    assert (root / "orodruin" / "audit.jsonl").is_file() and not (root / "glorfindel").exists()
    assert sorted(p.name for p in root.iterdir()) == ["annatar", "gothmog", "orodruin"]


def test_the_migration_never_writes_over_what_is_there(root):
    """M3234: a file of the former layout whose writer already has one by that name: both kept,
    the old one left and said — never one lost."""
    (root / "glorfindel").mkdir(parents=True)
    (root / "glorfindel" / "watch-x_debug.jsonl").write_text("new\n")
    (root / "watch-x_debug.jsonl").write_text("old\n")
    said: list[str] = []
    moved, left = L.migrate(root, say=said.append)
    assert (root / "glorfindel" / "watch-x_debug.jsonl").read_text() == "new\n"
    assert (root / "watch-x_debug.jsonl").read_text() == "old\n"
    assert [p.name for p, _ in left] == ["watch-x_debug.jsonl"] and "existe déjà" in said[0]


def test_the_migration_never_follows_a_link(root, tmp_path):
    root.mkdir(parents=True)
    (tmp_path / "elsewhere").mkdir()
    (root / "campaigns").symlink_to(tmp_path / "elsewhere")
    moved, left = L.migrate(root, say=lambda m: None)
    assert [(p.name, why) for p, why in left] == [("campaigns", "un lien, jamais suivi")]


def test_the_command_line(root, capsys):
    _flat_poste(root)
    assert L.main(["survey", str(root)]) == 1
    assert L.main(["migrate", str(root)]) == 0
    assert "2 laissé(s)" in capsys.readouterr().out
    assert L.main([]) == 2



# ── The relecture of SEC18: links, kinds, collisions ────────────────────────────────────

def test_a_writers_directory_that_is_a_link_stops_the_migration_before_anything_moves(root, tmp_path):
    """M3330: runs/annatar pointing elsewhere — a mount would give its writer the link's target.
    Nothing is moved, nothing made through it, the command fails and says the gesture."""
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    root.mkdir()
    (root / "annatar").symlink_to(elsewhere)
    (root / "x_signals.jsonl").write_text("{}\n")
    with pytest.raises(L.Unsafe):
        L.migrate(root, say=lambda m: None)
    assert L.main(["migrate", str(root)]) == 3
    assert list(elsewhere.iterdir()) == [] and (root / "x_signals.jsonl").is_file()
    assert L.unsafe(root) == [root / "annatar"]


def test_a_move_never_crosses_a_link_below_a_writers_directory(root, tmp_path):
    """M3331: runs/annatar/campaigns a link: a campaign is never moved through it."""
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (root / "annatar").mkdir(parents=True)
    (root / "annatar" / "campaigns").symlink_to(elsewhere)
    (root / "campaigns" / "C1").mkdir(parents=True)
    (root / "campaigns" / "C1" / "manifest.json").write_text("{}")
    moved, left = L.migrate(root, say=lambda m: None)
    assert list(elsewhere.iterdir()) == [] and (root / "campaigns" / "C1" / "manifest.json").is_file()
    assert any("jamais traversé" in why for _, why in left)


class _Credential:
    def get_token(self, *scopes):
        from types import SimpleNamespace
        return SimpleNamespace(token="t")


@pytest.mark.parametrize("sub", ["glorfindel/campaigns", "glorfindel/exercises", "glorfindel/orodruin",
                                 "verdicts/detections"])
def test_a_link_among_the_blues_known_subdirectories_stops_everything(root, tmp_path, sub):
    """M3342: a link where the watch writes (the pull, the reports, the local verdicts) — the
    migration stops before anything moves, and the watch's writes never go through it."""
    from eregion_core import exercise_channel, watch_channel as wc
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (root / sub).parent.mkdir(parents=True)
    (root / sub).symlink_to(elsewhere)
    (root / "x_signals.jsonl").write_text("{}\n")
    assert L.unsafe(root) == [root / sub]
    with pytest.raises(L.Unsafe):
        L.migrate(root, say=lambda m: None)
    if sub == "verdicts/detections":
        doc = {"run_id": "R1", "technique": "T1136.001", "verdict": "detected",
               "detected_at": "2026-11-03T10:00:00+00:00", "rule": "r", "latency_s": 1.0,
               "target": "/subscriptions/s/resourcegroups/rg/providers/microsoft.compute/virtualmachines/v"}
        with pytest.raises(ValueError, match="jamais traversé"):
            wc.write_local(root / "verdicts", "detections/R1/a.json", doc)
    if sub == "glorfindel/exercises":
        with pytest.raises(RuntimeError, match="jamais traversé"):
            exercise_channel.pull(root / sub, channel="https://account.blob.core.windows.net/exercises",
                                  credential=_Credential(), get=lambda *a, **k: None)
    assert list(elsewhere.iterdir()) == []


def test_a_link_deep_in_the_former_layout_is_left_and_said(root, tmp_path):
    """M3339: below the top too, what is no regular file is never followed nor moved."""
    target = tmp_path / "secret"
    target.write_text("kept")
    c = root / "campaigns" / "C1"
    c.mkdir(parents=True)
    (c / "manifest.json").symlink_to(target)
    (c / "scenario.yaml").write_text("x")
    moved, left = L.migrate(root, say=lambda m: None)
    assert (root / "annatar" / "campaigns" / "C1" / "scenario.yaml").is_file()
    assert not os.path.lexists(root / "annatar" / "campaigns" / "C1" / "manifest.json")
    assert [p.name for p, _ in left] == ["manifest.json"] and target.read_text() == "kept"


def test_the_former_layout_pending_says_when_to_stop_the_services(root):
    root.mkdir()
    for w in L.WRITERS:
        (root / w).mkdir()
    assert L.pending(root) is False and L.main(["pending", str(root)]) == 1
    (root / "manual_actions.jsonl").write_text("{}\n")
    assert L.pending(root) is True and L.main(["pending", str(root)]) == 0


def test_a_report_in_annatars_directory_is_an_attack_and_in_gothmogs_a_fault(root):
    """M3336: Annatar's directory naming its injector but saying ``fault`` would count as a fault
    of Gothmog's — refused; likewise an attack in Gothmog's."""
    a, g = root / "annatar" / "x.json", root / "gothmog" / "y.json"
    assert L.report_refusal(a, {"metrics": {"injector": "annatar", "kind": "fault"}})
    assert L.report_refusal(g, {"metrics": {"injector": "gothmog", "kind": "technique"}})
    assert not L.report_refusal(a, {"metrics": {"injector": "annatar", "kind": "technique"}})
    # M3233: the injector it names, whatever its kind
    assert "un rapport de gothmog" in L.report_refusal(a, {"metrics": {"injector": "gothmog", "kind": "technique"}})
    assert not L.report_refusal(g, {"metrics": {"injector": "gothmog"}})


def test_a_window_in_an_injectors_directory_names_that_injector(root):
    """M3337: a window of Gothmog's (a fault) in Annatar's directory is never believed — said."""
    start = datetime.now(timezone.utc)
    exercise.open_window("g1", injector="gothmog", kind="fault", experiment="vm-shutdown",
                         targets=["/x/vm"], directory=root / "annatar" / "exercises")
    exercise.open_window("a1", injector="annatar", kind="technique", experiment="T1110.001",
                         targets=["/x/vm"], now=start)
    got = exercise.load_windows(seen=root.parent / "seen.json")
    assert [w["run_id"] for w in got] == ["a1"]
    assert L.window_refusal_of(root / "annatar" / "exercises" / "g1.json", {"injector": "gothmog", "kind": "fault"})
