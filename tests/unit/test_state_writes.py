"""SEC17 (#451): the state files another process reads are written at once.

The watch's heartbeat (read by the injectors' gate, the console, the CD of H0, a second watch),
a run's report in runs/ (read by the watch, the console, the analysis, Orodruin's publisher) and
the console's restores in progress (read by `/api/state` while a restore starts or ends) were
written in place: opened, truncated, then written — a reader between the two found the file
empty or cut. Each is now written beside it and renamed over it: the file a reader opens is never
opened for writing.

Seen through Python's audit hook (``open``): what the code opens for writing, never a mock of
the writer. No Azure call. Mutants M3207–M3210 (scripts/mutation_check.py) are measured here.
"""
from __future__ import annotations

import json
import os
import stat
import sys
from contextlib import contextmanager
from datetime import datetime, timezone

import pytest

_WRITE_FLAGS = os.O_WRONLY | os.O_RDWR | os.O_TRUNC | os.O_APPEND
_watching: list[str] = []
_seen: list[str] = []


def _hook(event, args):
    if event != "open" or not _watching:
        return
    path, mode, flags = (tuple(args) + (None, None, None))[:3]
    if isinstance(path, int) or path is None:
        return
    writes = (isinstance(mode, str) and any(c in mode for c in "wax+")) or \
        (isinstance(flags, int) and flags & _WRITE_FLAGS)
    if writes and os.path.abspath(os.fsdecode(path)) in _watching:
        _seen.append(os.fsdecode(path))


sys.addaudithook(_hook)        # once per process; inert outside `_never_opened_for_writing`


@contextmanager
def _never_opened_for_writing(path):
    _seen.clear()
    _watching.append(os.path.abspath(path))
    try:
        yield _seen
    finally:
        _watching.clear()


def _mode(path) -> int:
    return stat.S_IMODE(os.stat(path).st_mode)


# ── The watch's heartbeat ───────────────────────────────────────────────────────────────

def test_the_heartbeat_is_never_written_in_place(tmp_path):
    """M3207: the heartbeat opened in place — a reader between the truncation and the write
    saw an empty file (the gate: « never », the CD: no health)."""
    from glorfindel import cli
    hb = tmp_path / ".glorfindel" / "watch_heartbeat"
    first = datetime(2026, 11, 3, 10, 0, tzinfo=timezone.utc)
    cli._write_watch_heartbeat(hb, first)
    with _never_opened_for_writing(hb) as seen:
        later = datetime(2026, 11, 3, 10, 1, tzinfo=timezone.utc)
        cli._write_watch_heartbeat(hb, later)
    assert seen == []
    assert datetime.fromisoformat(hb.read_text()) == later
    assert [p.name for p in hb.parent.iterdir()] == ["watch_heartbeat"]     # no temp file left


def test_the_heartbeat_keeps_the_mode_it_always_had(tmp_path):
    """M3208: the heartbeat 0600 — the CD of H0 and the console no longer read it."""
    from glorfindel import cli
    hb = tmp_path / ".glorfindel" / "watch_heartbeat"
    cli._write_watch_heartbeat(hb, datetime.now(timezone.utc))
    assert _mode(hb) == 0o644


def test_a_heartbeat_that_fails_to_be_written_leaves_the_last_one_whole(tmp_path, monkeypatch):
    from glorfindel import cli
    from glorfindel.response import state
    hb = tmp_path / ".glorfindel" / "watch_heartbeat"
    first = datetime(2026, 11, 3, 10, 0, tzinfo=timezone.utc)
    cli._write_watch_heartbeat(hb, first)

    def full(*a, **k):
        raise OSError(28, "No space left on device")
    monkeypatch.setattr(state.os, "replace", full)
    with pytest.raises(OSError):
        cli._write_watch_heartbeat(hb, datetime.now(timezone.utc))
    assert datetime.fromisoformat(hb.read_text()) == first
    assert [p.name for p in hb.parent.iterdir()] == ["watch_heartbeat"]


def test_the_gate_reads_the_heartbeat_the_watch_writes(tmp_path, monkeypatch):
    """What the injectors' gate and `glorfindel status` read is what the watch wrote, whole."""
    import eregion_core.watch_gate as gate
    from glorfindel import cli
    monkeypatch.setenv("HOME", str(tmp_path))
    cli._write_watch_heartbeat(tmp_path / ".glorfindel" / "watch_heartbeat", datetime.now(timezone.utc))
    assert gate.fresh(gate.local_beat(), datetime.now(timezone.utc))


# ── A run's report in runs/ ─────────────────────────────────────────────────────────────

def _report(run_id: str = "20261103T100000Z", result: str = "detected"):
    from eregion_core.run_report import RunReport
    return RunReport(scenario="T1041", run_id=run_id, mitre="T1041", result=result,
                     metrics={"run_format": 1}, thresholds={}, checks={})


def test_a_run_s_report_is_never_written_in_place(tmp_path):
    """M3209: a report opened in place — the watch or the console read it empty or cut."""
    runs = tmp_path / "runs"
    _report(result="unknown").save(runs)
    target = runs / "20261103T100000Z.json"
    with _never_opened_for_writing(target) as seen:
        path = _report().save(runs)
    assert seen == [] and path == target
    assert json.loads(target.read_text())["result"] == "detected"
    assert _mode(target) == 0o644                     # read by the other processes, as before
    assert sorted(p.name for p in runs.iterdir()) == ["20261103T100000Z.json"]


def test_a_link_in_the_place_of_a_report_is_replaced_never_followed(tmp_path):
    runs = tmp_path / "runs"
    runs.mkdir()
    elsewhere = tmp_path / "elsewhere.json"
    elsewhere.write_text("kept", encoding="utf-8")
    (runs / "20261103T100000Z.json").symlink_to(elsewhere)
    _report().save(runs)
    assert elsewhere.read_text(encoding="utf-8") == "kept"
    assert not (runs / "20261103T100000Z.json").is_symlink()


# ── The console's restores in progress ──────────────────────────────────────────────────

def test_the_restores_in_progress_are_never_written_in_place(tmp_path):
    """M3210: the console's file of restores in progress opened in place — `/api/state` read it
    empty, and a restore starting then lost the others."""
    pytest.importorskip("fastapi")
    import eregion_console.api as api
    api._restore_start("vm-a", "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm-a")
    with _never_opened_for_writing(api._RESTORE_TRACKING) as seen:
        api._restore_start("vm-b", "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm-b")
        api._restore_done("vm-a")
    assert seen == []
    assert [r["vm_name"] for r in api._active_restores()] == ["vm-b"]
    assert _mode(api._RESTORE_TRACKING) == 0o600


def test_a_restore_done_for_a_vm_not_in_progress_writes_nothing(tmp_path):
    pytest.importorskip("fastapi")
    import eregion_console.api as api
    api._restore_done("vm-never")
    assert not api._RESTORE_TRACKING.exists()
    api._restore_start("vm-a", "rid-a")
    before = api._RESTORE_TRACKING.stat().st_mtime_ns
    api._restore_done("vm-never")
    assert api._RESTORE_TRACKING.stat().st_mtime_ns == before
    assert [r["vm_name"] for r in api._active_restores()] == ["vm-a"]
