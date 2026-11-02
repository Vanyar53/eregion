"""SEC8 (#414) — the runs/ channel read as an input the watch does not trust.

1. The watch reads in runs/ only regular files, opened without blocking and without following
   a link; anything else is refused, said once, never read. What one poll reads of a file is
   bounded in bytes and in lines, the rest left for the next poll; a line past the bound is
   refused and said. A refusal is said, never a stop of the watch.
2. The rate of a writer is bounded, and what an admitted line starts in the watch too: one
   search per VM and technique, a bounded number in all, a bounded queue per VM, a bounded
   number of VMs. Durations are finite and bounded. A technique the watch does not know (its
   catalog, its rules) is refused: no search, no call to the model.
3. The moment of a restore is never taken from the channel on a real incident: a line counts
   only for an exercise card tied to its run, never after the card's first detection;
   otherwise the earliest moment the defender recorded, and the prompt says so.
4. The workspace queried for a rule proposal is the one of Glorfindel's config; a line naming
   another is refused and said.

No Azure call, no model call. Every identifier is made up (repository public). Mutants
M2810–M2839 (scripts/mutation_check.py) are measured here.
"""
from __future__ import annotations

import errno
import json
import os
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from eregion_core import channel_reader
from glorfindel import signal_origin

from .test_signal_origin import _line, _run_watch

VM = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/web"
GUARD_S = 5.0          # a read that would block is unblocked after this, so a red test never hangs


def _guarded(fn, *args):
    """fn(*args) in a thread, given GUARD_S: (finished, result or exception)."""
    box: list = []

    def run():
        try:
            box.append(fn(*args))
        except BaseException as exc:      # noqa: BLE001 — the test reads it
            box.append(exc)
    t = threading.Thread(target=run, daemon=True)
    t.start()
    t.join(GUARD_S)
    return (not t.is_alive()), (box[0] if box else None)


def _unblock_fifo_until(path: Path, stop: threading.Event) -> None:
    """The guard of a FIFO: whoever opened it for reading, blocked, is released (a writer
    opens it, writes nothing, closes) — from GUARD_S on, until `stop`."""
    if stop.wait(GUARD_S):
        return
    while not stop.is_set():
        try:
            os.close(os.open(path, os.O_WRONLY | os.O_NONBLOCK))
        except OSError as exc:
            if exc.errno not in (errno.ENXIO, errno.ENOENT):
                return
        stop.wait(0.05)


def _lines(n: int, **over) -> bytes:
    return "".join(json.dumps(_line("attack_started", signal_id=f"r_{i}", **over)) + "\n"
                   for i in range(n)).encode()


# ── 1. A regular file only, a bounded read ─────────────────────────────────────────────

def test_a_fifo_is_refused_without_blocking(tmp_path):
    fifo = tmp_path / "x_signals.jsonl"
    os.mkfifo(fifo)
    stop = threading.Event()
    threading.Thread(target=_unblock_fifo_until, args=(fifo, stop), daemon=True).start()
    try:
        started = time.monotonic()
        finished, got = _guarded(channel_reader.read_lines, fifo, 0)
        assert finished and time.monotonic() - started < GUARD_S
        assert isinstance(got, channel_reader.Refused) and "tube" in str(got)
    finally:
        stop.set()


@pytest.mark.parametrize("target", ["outside", "/dev/zero"])
def test_a_link_is_never_followed(tmp_path, target):
    """A link to a file elsewhere (another file's lines), or to a device that never ends."""
    outside = tmp_path / "elsewhere.jsonl"
    outside.write_bytes(_lines(1))
    link = tmp_path / "runs" / "x_signals.jsonl"
    link.parent.mkdir()
    link.symlink_to(outside if target == "outside" else target)
    finished, got = _guarded(channel_reader.read_lines, link, 0)
    assert finished and isinstance(got, channel_reader.Refused) and "lien" in str(got)
    assert channel_reader.start_offset(link) == 0


def test_a_start_offset_never_blocks_nor_raises(tmp_path):
    fifo, broken = tmp_path / "a_signals.jsonl", tmp_path / "b_signals.jsonl"
    os.mkfifo(fifo)
    broken.symlink_to(tmp_path / "gone")
    regular = tmp_path / "c_signals.jsonl"
    regular.write_bytes(_lines(2))
    finished, got = _guarded(lambda: [channel_reader.start_offset(p) for p in (fifo, broken, regular)])
    assert finished and got == [0, 0, regular.stat().st_size]


@pytest.mark.parametrize("max_lines, max_bytes", [(50, 1 << 20), (10_000, 16 * 1024)],
                         ids=["the-lines-bound", "the-bytes-bound"])
def test_a_huge_file_is_read_a_bounded_slice_per_poll(tmp_path, monkeypatch, max_lines, max_bytes):
    """At most READ_LINES lines and READ_BYTES per poll — whichever comes first —; the rest at
    the next one, from the offset kept: every line read once, in order."""
    monkeypatch.setattr(channel_reader, "READ_LINES", max_lines)
    monkeypatch.setattr(channel_reader, "READ_BYTES", max_bytes)
    f = tmp_path / "x_signals.jsonl"
    f.write_bytes(_lines(400))
    seen, offset, polls = [], 0, 0
    while offset < f.stat().st_size:
        got = channel_reader.read_lines(f, offset)
        assert len(got.lines) <= max_lines and got.offset - offset <= max_bytes
        seen += got.lines
        offset, polls = got.offset, polls + 1
    assert [json.loads(x)["signal_id"] for x in seen] == [f"r_{i}" for i in range(400)]
    assert polls >= 2


def test_a_line_past_the_bound_is_refused_and_the_next_one_read(tmp_path, monkeypatch):
    monkeypatch.setattr(channel_reader, "LINE_BYTES", 1024)
    monkeypatch.setattr(channel_reader, "READ_BYTES", 4096)
    f = tmp_path / "x_signals.jsonl"
    f.write_bytes(b"x" * 10_000)                    # no end yet, already past the bound
    got = channel_reader.read_lines(f, 0)
    assert got.lines == [] and got.too_long == 1 and got.skipping
    with open(f, "ab") as fh:
        fh.write(b"y" * 3000 + b"\n" + _lines(1) + b"z" * 1500 + b"\n" + _lines(1))
    offset, skipping, lines, too_long = got.offset, got.skipping, [], 0
    while offset < f.stat().st_size:
        got = channel_reader.read_lines(f, offset, skipping)
        offset, skipping = got.offset, got.skipping
        lines += got.lines
        too_long += got.too_long
    assert [json.loads(x)["signal_id"] for x in lines] == ["r_0", "r_0"]
    assert too_long == 1                             # the 1500-byte line; the first was counted


def test_the_reader_says_a_refused_file_once(tmp_path):
    runs = tmp_path / "runs"
    runs.mkdir()
    os.mkfifo(runs / "a_signals.jsonl")
    said: list[tuple[str, str]] = []
    reader = channel_reader.ChannelReader(runs, lambda text, kind="refused": said.append((kind, text)))
    for _ in range(5):
        finished, _got = _guarded(reader.poll)
        assert finished
    refused = [t for k, t in said if k == "refused"]
    assert len(refused) == 1 and "a_signals.jsonl" in refused[0] and "tube" in refused[0]


def _reader(runs: Path, **budget):
    said: list[tuple[str, str]] = []
    reader = channel_reader.ChannelReader(
        runs, lambda text, kind="refused": said.append((kind, text)),
        budget=channel_reader.Budget(**budget) if budget else None)
    return reader, said


def _ids(got) -> list[str]:
    return [json.loads(line)["signal_id"] for _path, line in got]


def test_a_file_truncated_or_replaced_is_read_from_its_start(tmp_path):
    runs = tmp_path / "runs"
    runs.mkdir()
    f = runs / "a_signals.jsonl"
    f.write_bytes(_lines(3))
    reader, said = _reader(runs)
    assert _ids(reader.poll()) == ["r_0", "r_1", "r_2"]
    f.write_bytes(_lines(1, raw_signal={"x": 1}))                   # truncated, shorter: one new line
    assert _ids(reader.poll()) == ["r_0"]
    new = runs / "a_signals.jsonl.tmp"
    new.write_bytes(_lines(5))                                      # replaced: another inode, longer
    os.replace(new, f)
    assert _ids(reader.poll()) == [f"r_{i}" for i in range(5)]
    assert sum("relu depuis son début" in t for _k, t in said) == 2


def test_a_file_gone_is_forgotten(tmp_path):
    runs = tmp_path / "runs"
    runs.mkdir()
    f = runs / "a_signals.jsonl"
    f.write_bytes(_lines(2))
    reader, _said = _reader(runs)
    reader.poll()
    f.unlink()
    reader.poll()
    assert f not in reader.offsets


def test_a_poll_opens_a_bounded_number_of_files_each_in_turn(tmp_path, monkeypatch):
    """FILES_PER_POLL files with something new opened per poll; the others at the next ones —
    every file read, none twice."""
    monkeypatch.setattr(channel_reader, "FILES_PER_POLL", 3)
    runs = tmp_path / "runs"
    runs.mkdir()
    for i in range(10):
        (runs / f"f{i:02d}_signals.jsonl").write_text(json.dumps(_line("attack_started", signal_id=f"s{i}")) + "\n")
    reader, _said = _reader(runs)
    opened: list[str] = []
    real = channel_reader.open_regular
    monkeypatch.setattr(channel_reader, "open_regular", lambda p: opened.append(Path(p).name) or real(p))
    seen: list[str] = []
    for _ in range(4):
        before = len(opened)
        seen += _ids(reader.poll())
        assert len(opened) - before <= 3
    assert sorted(seen) == [f"s{i}" for i in range(10)]
    assert reader.poll() == [] and len(opened) == 10                # nothing new: nothing opened


def test_a_writer_whose_minute_is_spent_is_not_read(tmp_path, monkeypatch):
    """Its file is passed over without being read, counted in bytes; another file waiting only
    for the channel's minute is read later, nothing lost."""
    now = [0.0]
    runs = tmp_path / "runs"
    runs.mkdir()
    a, b = runs / "a_signals.jsonl", runs / "b_signals.jsonl"
    a.write_bytes(_lines(2))
    reader, _said = _reader(runs, per_writer=2, total=3, window_s=60, clock=lambda: now[0])
    assert len(reader.poll()) == 2
    with open(a, "ab") as fh:
        fh.write(_lines(500))
    reads: list[str] = []
    real = channel_reader.read_lines
    monkeypatch.setattr(channel_reader, "read_lines", lambda p, *x, **k: reads.append(Path(p).name) or real(p, *x, **k))
    assert reader.poll() == [] and reads == [] and reader.offsets[a] == a.stat().st_size
    assert reader.budget.report()["a_signals.jsonl"][1] == len(_lines(500))
    b.write_bytes(_lines(3))
    assert _ids(reader.poll()) == ["r_0"]                           # the channel's third line
    assert _ids(reader.poll()) == []                                # its minute spent: waits
    now[0] = 61.0
    assert _ids(reader.poll()) == ["r_1", "r_2"]                    # read later, nothing lost


def test_a_fifo_and_a_link_in_runs_never_stop_the_watch(tmp_path, monkeypatch):
    """A FIFO and a link in runs/ when the watch starts: the line an injector writes next is
    still decided, the two are refused, each said once — the watch never blocks on them."""
    t0 = time.time() - 60
    stop = threading.Event()

    def prepare(runs: Path) -> None:
        os.mkfifo(runs / "pipe_signals.jsonl")
        elsewhere = runs.parent / "elsewhere.jsonl"
        elsewhere.write_text(json.dumps(_line("detection_missed", signal_id="from-the-link")) + "\n")
        (runs / "link_signals.jsonl").symlink_to(elsewhere)
        threading.Thread(target=_unblock_fifo_until, args=(runs / "pipe_signals.jsonl", stop),
                         daemon=True).start()

    started = time.monotonic()
    try:
        responded, polled, out = _run_watch(
            tmp_path, monkeypatch, [_line("attack_started", raw_signal={"attack_time": t0})],
            expect=1, prepare=prepare)
    finally:
        stop.set()
    assert time.monotonic() - started < GUARD_S + 10
    assert [d["event"] for d in responded] == ["detection"], out
    assert not [d for d in responded if d.get("signal_id") == "from-the-link"]
    flat = " ".join(out.split())
    assert flat.count("pipe_signals.jsonl refusé") == 1 and "tube nommé" in flat
    assert flat.count("link_signals.jsonl refusé") == 1 and "lien" in flat
    assert signal_origin.refused_counts() == {}


# ── 2. A bounded rate, bounded effects, finite durations, known techniques ─────────────

def _vm(i: int) -> str:
    return f"/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm-{i:03d}"


def test_the_budget_lets_a_writer_through_its_rate_and_says_the_rest_once_a_minute():
    now = [0.0]
    budget = channel_reader.Budget(per_writer=3, total=5, window_s=60, clock=lambda: now[0])
    assert [budget.take("a") for _ in range(5)] == [True, True, True, False, False]
    assert [budget.take("b") for _ in range(3)] == [True, True, False]      # the channel's 5
    assert budget.report() == {"a": (2, 0), "b": (1, 0)}
    budget.take("a")
    assert budget.report() == {}                     # said a minute ago: kept for the next
    now[0] = 61.0
    assert budget.take("a") is True                  # a new minute
    assert budget.report() == {"a": (1, 0)}


def test_a_burst_in_runs_is_cut_at_the_writers_rate_and_said_in_one_line(tmp_path, monkeypatch):
    """A file of 3 × PER_WRITER_PER_MIN lines: PER_WRITER_PER_MIN are decided, the rest not
    admitted — passed over unread —, said in one line and counted once, never one per line."""
    n = channel_reader.PER_WRITER_PER_MIN
    lines = [_line("detection_missed", signal_id=f"m{i}", resource_id=_vm(i)) for i in range(3 * n)]
    responded, _polled, out = _run_watch(tmp_path, monkeypatch, lines, expect=n)
    assert len(responded) == n, out
    flat = " ".join(out.split())
    assert flat.count("Canal runs/ :") == 1 and "octet(s) non lus" in flat
    assert flat.count("Signal refusé") == 0
    assert signal_origin.refused_counts() == {"(débit)": 1}


def test_the_lines_waiting_for_one_vm_are_bounded(tmp_path, monkeypatch):
    """A decision takes time: the channel's lines for one VM wait at most CHANNEL_QUEUED_PER_VM;
    the next ones are refused and said, never queued without end."""
    monkeypatch.setattr(channel_reader, "CHANNEL_QUEUED_PER_VM", 3)
    lines = [_line("detection_missed", signal_id=f"m{i}") for i in range(7)]
    responded, _polled, out = _run_watch(tmp_path, monkeypatch, lines, expect=3, slow_respond=0.3)
    assert len(responded) == 3, out
    assert " ".join(out.split()).count("lignes du canal attendent déjà pour cette VM") == 4
    assert signal_origin.refused_counts() == {"detection_missed": 4}


def test_one_search_per_vm_and_technique_and_a_bounded_number_of_them(tmp_path, monkeypatch):
    """A thread per line no more: the same search twice is refused while it runs, and at most
    CHANNEL_POLLS run at once."""
    monkeypatch.setattr(channel_reader, "CHANNEL_POLLS", 2)
    t0 = time.time() - 60
    raw = {"attack_time": t0}
    lines = ([_line("attack_started", signal_id=f"a{i}", raw_signal=raw) for i in range(3)]
             + [_line("attack_started", signal_id=f"b{i}", resource_id=_vm(i), raw_signal=raw) for i in range(3)])
    responded, polled, out = _run_watch(tmp_path, monkeypatch, lines, expect=2, slow_poll=1.0)
    assert len(polled) == 2, out
    flat = " ".join(out.split())
    assert flat.count("une recherche de cette technique sur cette VM est déjà en cours") == 2
    assert flat.count("recherches du canal déjà en cours") == 2


def test_the_vms_the_channel_names_are_bounded(tmp_path, monkeypatch):
    monkeypatch.setattr(channel_reader, "CHANNEL_VMS", 4)
    lines = [_line("detection_missed", signal_id=f"m{i}", resource_id=_vm(i)) for i in range(6)]
    responded, _polled, out = _run_watch(tmp_path, monkeypatch, lines, expect=4)
    assert len(responded) == 4, out
    assert " ".join(out.split()).count("le canal nomme déjà 4 VM") == 2


@pytest.mark.parametrize("value", [float("inf"), float("-inf"), float("nan"), 10 ** 400, -5, 0, True, "300",
                                   None, 3601])
def test_a_timeout_is_finite_and_bounded(value):
    line = _line("attack_started", raw_signal={"attack_time": time.time() - 60, "detection_timeout_s": value})
    adm = signal_origin.admit(line)
    assert adm.signal is None and "detection_timeout_s" in adm.refused
    missed = _line("detection_missed", context={"run_id": "r1", "detection_timeout_s": value})
    assert signal_origin.admit(missed).signal is None


def test_infinity_written_as_json_is_refused_and_the_scenarios_bounds_pass():
    """json reads `Infinity` and `NaN` as floats: refused. A scenario's own values — a
    timeout of minutes, the SLA's default of 9999 s — pass."""
    raw = '{"attack_time": %f, "detection_timeout_s": Infinity}' % (time.time() - 60)
    assert signal_origin.admit(_line("attack_started", raw_signal=json.loads(raw))).signal is None
    raw = '{"attack_time": %f, "detection_timeout_s": 300, "detection_max_s": NaN}' % (time.time() - 60)
    assert signal_origin.admit(_line("attack_started", raw_signal=json.loads(raw))).signal is None
    ok = signal_origin.admit(_line("attack_started", raw_signal={
        "attack_time": time.time() - 60, "detection_timeout_s": 480, "detection_max_s": 9999}))
    assert ok.signal is not None, ok.refused


def test_the_search_refuses_an_endless_timeout_before_any_query(monkeypatch):
    """`respond` reads a file the operator names, not runs/: its attack_started is bounded the
    same, before a detector is even made."""
    from glorfindel import agent
    made = []
    monkeypatch.setattr("glorfindel.detectors.detector_for", lambda *a, **k: made.append(a))
    sig = _line("attack_started", raw_signal={"attack_time": time.time() - 60,
                                              "detection_timeout_s": float("inf")})
    with pytest.raises(ValueError, match="detection_timeout_s"):
        agent.resolve_attack_started(sig)
    assert made == []


def test_the_known_techniques_are_the_catalogs_and_the_rules():
    from glorfindel.detection_authoring import load_catalog
    known = signal_origin.known_techniques()
    assert set(load_catalog()) <= known
    assert {"T1486", "T1136.001", "T1562.007"} <= known      # the catalog's, a rule's only
    assert "T9999.999" not in known


@pytest.mark.parametrize("event", ["attack_started", "detection_missed"])
def test_a_line_naming_an_unknown_technique_is_refused(event):
    line = _line(event, ttp="T9999.999", raw_signal={"attack_time": time.time() - 60})
    adm = signal_origin.admit(line)
    assert adm.signal is None and "inconnue" in adm.refused
    assert signal_origin.admit(_line(event, ttp=["T1486"])).signal is None


def test_an_unknown_technique_in_runs_reaches_neither_the_search_nor_the_model(tmp_path, monkeypatch):
    """No decision (the model's call) and no search for a technique the watch does not know —
    whatever the event; the refusal is said and counted."""
    lines = [_line("attack_started", ttp="T9999.999", raw_signal={"attack_time": time.time() - 60}),
             _line("detection_missed", ttp="T9999.998"),
             _line("detection_missed", signal_id="known")]
    responded, polled, out = _run_watch(tmp_path, monkeypatch, lines, expect=1)
    assert [d["signal_id"] for d in responded] == ["known"] and polled == []
    assert " ".join(out.split()).count("inconnue de la watch") == 2
    assert signal_origin.refused_counts() == {"attack_started": 1, "detection_missed": 1}


# ── 3. The moment of a restore is never the channel's on a real incident ───────────────

def _iso(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()


def _attack_line(at: float, run_id: str) -> dict:
    return _line("attack_started", signal_id=f"{run_id}_attack_started",
                 raw_signal={"attack_time": at}, context={"run_id": run_id, "scenario": "s"})


def _incident(tmp_path, monkeypatch):
    """A real incident: first detected 90 min ago, the VM isolated an hour later (human_only, the
    operator came late) — and a line in runs/ dated just before the isolation."""
    now = time.time()
    first, isolated = now - 5400, now - 1800
    monkeypatch.setattr("glorfindel.actions._load_isolation_state", lambda rid: {"isolated_at": _iso(isolated)})
    runs = tmp_path / "runs"
    runs.mkdir(exist_ok=True)
    (runs / "20261102T100000Z_signals.jsonl").write_text(json.dumps(_attack_line(isolated - 60, "20261102T100000Z")) + "\n")
    return first, isolated, runs


def test_a_real_incident_s_restore_never_takes_the_channel_s_moment(tmp_path, monkeypatch):
    from glorfindel import restore_plan
    first, _isolated, runs = _incident(tmp_path, monkeypatch)
    card = {"first_seen": _iso(first), "source": "real"}
    got = restore_plan.proposed_moment(VM, card, runs_dir=runs)
    assert got["source"] == "card" and got["before"] == _iso(first)
    assert "incident réel" in got["why"] and "le plus ancien des moments sûrs" in got["why"]
    assert restore_plan.proposed_moment(VM, {"first_seen": _iso(first)}, runs_dir=runs)["before"] == _iso(first)
    # A line dated before the first detection gives nothing either: the channel never names
    # the moment of a real incident, earlier or later.
    with open(runs / "20261102T100000Z_signals.jsonl", "a") as f:
        f.write(json.dumps(_attack_line(first - 600, "20261102T100000Z")) + "\n")
    assert restore_plan.proposed_moment(VM, card, runs_dir=runs)["before"] == _iso(first)


def test_an_exercise_s_moment_is_its_run_s_and_never_after_its_first_detection(tmp_path, monkeypatch):
    from glorfindel import restore_plan
    first, isolated, runs = _incident(tmp_path, monkeypatch)
    other = {"first_seen": _iso(first), "source": "exercise", "exercise_run": "20261102T090000Z"}
    got = restore_plan.proposed_moment(VM, other, runs_dir=runs)               # another run's line
    assert got["before"] == _iso(first) and "aucune ligne attack_started du run 20261102T090000Z" in got["why"]
    late = {**other, "exercise_run": "20261102T100000Z"}                      # its run, after the card
    assert restore_plan.proposed_moment(VM, late, runs_dir=runs)["before"] == _iso(first)
    (runs / "20261102T100000Z_signals.jsonl").write_text(
        json.dumps(_attack_line(first - 600, "20261102T100000Z")) + "\n")
    got = restore_plan.proposed_moment(VM, late, runs_dir=runs)
    assert got["source"] == "exercise" and got["before"] == _iso(first - 600)
    # The same line, before the first detection, is still no moment for another run's card.
    assert restore_plan.proposed_moment(VM, other, runs_dir=runs)["before"] == _iso(first)


def test_the_restore_command_takes_the_card_s_moment_not_the_channel_s(tmp_path, monkeypatch):
    """`glorfindel restore` without --before, on the real incident: the card's first detection
    — the line of runs/ dated after it is never the point's bound."""
    from click.testing import CliRunner

    from glorfindel import cli, escalations
    first, isolated, _runs = _incident(tmp_path, monkeypatch)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(cli, "_backup_vault_from_config", lambda v: ("rsv-example", "rg-backup", "stexample"))
    monkeypatch.setattr("glorfindel.actions.AzureConnector", lambda dry_run=False: SimpleNamespace(dry_run=dry_run))
    monkeypatch.setattr(cli, "_record_manual_action", lambda *a, **k: None)
    started: list = []

    def start_restore(resource_id, connector, vault, before, **kw):
        started.append(before)
        return {"job_id": "j", "restore_job_name": "rj", "recovery_point_time": "x"}
    monkeypatch.setattr("glorfindel.jobs.start_restore", start_restore)
    other = VM.replace("/web", "/web-02")
    escalations.record("rule-y-0123abcd", other, "restore_from_backup", "destructive_action", "r", ttp="T1486")
    out = CliRunner().invoke(cli.cli, ["restore", VM, "--yes"], terminal_width=200)
    # No card of this VM — another VM's says nothing of it: asked.
    assert out.exit_code != 0 and started == [] and "aucune carte" in " ".join(out.output.split())
    escalations.record("rule-x-0123abcd", VM, "restore_from_backup", "destructive_action", "r", ttp="T1486")
    store = [json.loads(x) for x in escalations._STORE.read_text().splitlines()]
    for e in store:
        if e["resource_id"] == VM:
            e["first_seen"] = _iso(first)
    escalations._STORE.write_text("\n".join(json.dumps(e) for e in store) + "\n")
    out = CliRunner().invoke(cli.cli, ["restore", VM, "--yes"], terminal_width=200)
    assert out.exit_code == 0, out.output
    assert started == [_iso(first)] and "incident réel" in " ".join(out.output.split())


def _pending_card(rid: str, action: str, first: float, **kw) -> str:
    from glorfindel import escalations
    esc_id = escalations.record(f"rule-{action}-0123abcd", rid, action, "destructive_action", "r",
                                ttp="T1486", **kw)
    store = [json.loads(x) for x in escalations._STORE.read_text().splitlines()]
    for e in store:
        if e["id"] == esc_id:
            e["first_seen"] = _iso(first)
    escalations._STORE.write_text("\n".join(json.dumps(e) for e in store) + "\n")
    return esc_id


def test_the_restore_command_takes_the_vm_s_first_detected_card(tmp_path, monkeypatch):
    """Several pending cards on the VM: the one first detected, whatever it holds — not the
    restore card, written later: the earliest moment the defender recorded."""
    from glorfindel import restore_plan
    monkeypatch.setattr("glorfindel.actions._load_isolation_state", lambda rid: None)
    now = time.time()
    _pending_card(VM, "restore_from_backup", now - 1800)
    first = _pending_card(VM, "isolate_vm", now - 5400)
    _pending_card(VM.replace("/web", "/web-02"), "isolate_vm", now - 9000)       # another VM's
    assert restore_plan.card_of(VM)["id"] == first
    assert restore_plan.proposed_moment(VM, restore_plan.card_of(VM))["before"] == _iso(now - 5400)


def test_runs_not_read_is_said_as_not_read(monkeypatch):
    """The bot, short of time, does not read runs/: the field says « non lu », never that no
    line was admitted."""
    from glorfindel import restore_plan
    monkeypatch.setattr("glorfindel.actions._load_isolation_state", lambda rid: None)
    drill = {"first_seen": _iso(time.time() - 600), "source": "exercise", "exercise_run": "20261102T100000Z"}
    why = restore_plan.proposed_moment(VM, drill, read_runs=False)["why"]
    assert "non lu" in why and "aucune ligne" not in why


# ── 4. The workspace queried is the config's ────────────────────────────────────────────

def _config(monkeypatch, *workspaces: str) -> None:
    cfg = SimpleNamespace(monitoring_backends=[SimpleNamespace(name=f"law-{i}", type="azure_monitor", workspace_id=w)
                                               for i, w in enumerate(workspaces)])
    monkeypatch.setattr("glorfindel.config.load_glorfindel_config", lambda *a, **k: cfg)


def test_a_detection_missed_naming_another_workspace_is_refused(monkeypatch):
    _config(monkeypatch, "11111111-aaaa-4bbb-8ccc-000000000001")
    missed = lambda ws: _line("detection_missed", context={"run_id": "r1", "workspace_id": ws})  # noqa: E731
    refused = signal_origin.admit(missed("22222222-aaaa-4bbb-8ccc-000000000002"))
    assert refused.signal is None and "config de Glorfindel" in refused.refused
    assert signal_origin.admit(missed("11111111-AAAA-4bbb-8ccc-000000000001")).signal is not None
    assert signal_origin.admit(missed("")).signal is not None
    assert signal_origin.admit(missed(["x"])).signal is None


@pytest.mark.parametrize("named, queried", [
    ("22222222-aaaa-4bbb-8ccc-000000000002", None),                                   # another: none
    ("", "11111111-aaaa-4bbb-8ccc-000000000001"),                                     # none named: the config's
    ("11111111-AAAA-4bbb-8ccc-000000000001", "11111111-aaaa-4bbb-8ccc-000000000001"),  # the config's, as it writes it
])
def test_a_rule_proposal_queries_the_config_s_workspace_only(monkeypatch, named, queried):
    """`respond` too (a file the operator names): the workspace getschema reads is the
    config's, never the one the signal names."""
    from glorfindel import agent
    _config(monkeypatch, "11111111-aaaa-4bbb-8ccc-000000000001")
    asked: list[str] = []
    authored: list[dict] = []
    monkeypatch.setattr(agent, "_find_rule_for_ttp", lambda *a, **k: None)
    monkeypatch.setattr("glorfindel.detection_rules.rulepoller_recently_matched", lambda *a, **k: False)
    monkeypatch.setattr("glorfindel.detectors.detector_for",
                        lambda source, workspace_id="": asked.append(workspace_id) or object())
    monkeypatch.setattr(agent, "author_rule", lambda **kw: authored.append(kw) or {
        "name": "r", "query": "q", "confidence": 0.1, "rationale": "", "source": "azure_monitor"})
    state = {"signal": {"event": "detection_missed", "ttp": "T1136.001", "resource_id": VM, "raw_signal": {},
                        "context": {"run_id": "r1", "workspace_id": named, "detection_timeout_s": 300}},
             "past_cycles": [], "incident": None, "dry_run": False, "proposal_id": ""}
    monkeypatch.setattr("glorfindel.proposed_rules.record", lambda *a, **k: "p1", raising=False)
    try:
        agent.propose_detection_rule(state, model="m")
    except Exception:          # what follows the authoring is not this test's
        pass
    assert asked == ([queried] if queried else [])
    assert authored and authored[0]["workspace_id"] == (queried or "")


# ── SEC15: the end of a file, for the console's feed and the TUI ─────────────────────────────

def test_the_end_of_a_file_is_read_bounded_ended_lines_only(tmp_path, monkeypatch):
    """`tail_lines`: at most READ_BYTES from the end, the line that bound cuts dropped, a line not
    ended left out, a line past LINE_BYTES refused, at most `max_lines` kept."""
    monkeypatch.setattr(channel_reader, "LINE_BYTES", 200)
    f = tmp_path / "x_signals.jsonl"
    f.write_bytes(b"".join(b'{"i": %d}\n' % i for i in range(1000)) + b"x" * 300 + b"\n" + b'{"i": "half')
    got = channel_reader.tail_lines(f, max_bytes=2048, max_lines=50)
    assert len(got) == 50 and got[-1] == '{"i": 999}' and all(json.loads(x) for x in got)
    whole = channel_reader.tail_lines(f, max_bytes=1 << 20, max_lines=10_000)
    assert len(whole) == 1000 and whole[0] == '{"i": 0}'        # the over-long line refused


def test_the_tui_never_reads_a_name_of_runs_as_markup(tmp_path, monkeypatch):
    """A name of runs/ is written by another container: the TUI shows it as text, never as Rich
    markup (SEC15, review)."""
    from glorfindel import tui
    monkeypatch.chdir(tmp_path)
    runs = tmp_path / "runs"
    runs.mkdir()
    (runs / "[bold]x_signals.jsonl").write_bytes(_lines(1))
    (runs / "[bold]x_debug.jsonl").symlink_to(tmp_path / "elsewhere")
    got = tui._load_feed()
    assert got[0] == "[yellow]⚠ \\[bold]x_debug.jsonl : un lien, jamais suivi — jamais lu[/yellow]"
    assert "\\[bold]x" in str(tui._feed_renderable(got, tui._current_run_label()).title)


def test_the_end_of_a_file_keeps_a_whole_line_its_bound_falls_on(tmp_path):
    """The bound falls exactly at a line's start: that line is whole, kept — one byte before or
    after it, the line it cuts is dropped (SEC15, review)."""
    f = tmp_path / "x_signals.jsonl"
    f.write_bytes(b"".join(b'{"i": %03d}\n' % i for i in range(100)))      # 11 bytes a line
    assert channel_reader.tail_lines(f, max_bytes=11 * 5)[0] == '{"i": 095}'
    assert len(channel_reader.tail_lines(f, max_bytes=11 * 5)) == 5
    assert channel_reader.tail_lines(f, max_bytes=11 * 5 - 1)[0] == '{"i": 096}'
    assert channel_reader.tail_lines(f, max_bytes=11 * 5 + 1)[0] == '{"i": 095}'
    assert len(channel_reader.tail_lines(f, max_bytes=11 * 100)) == 100


@pytest.mark.parametrize("make", ["fifo", "link-to-zero", "link-elsewhere"])
def test_the_end_of_a_file_never_blocks_nor_follows_a_link(tmp_path, make):
    f = tmp_path / "x_signals.jsonl"
    stop = threading.Event()
    if make == "fifo":
        os.mkfifo(f)
        threading.Thread(target=_unblock_fifo_until, args=(f, stop), daemon=True).start()
    elif make == "link-to-zero":
        f.symlink_to("/dev/zero")
    else:
        (tmp_path / "elsewhere").write_bytes(_lines(3))
        f.symlink_to(tmp_path / "elsewhere")
    try:
        finished, got = _guarded(channel_reader.tail_lines, f)
        assert finished and isinstance(got, channel_reader.Refused)
    finally:
        stop.set()


def test_the_tui_feed_reads_runs_as_the_watch_never_blocking(tmp_path, monkeypatch):
    """The TUI's feed: the newest regular run's lines; a link, newer, never a candidate; a pipe of
    that run said, never read — within the guard."""
    from glorfindel import tui
    monkeypatch.chdir(tmp_path)
    runs = tmp_path / "runs"
    runs.mkdir()
    (runs / "r1_signals.jsonl").write_bytes(_lines(3))
    fifo = runs / "r1_debug.jsonl"
    os.mkfifo(fifo)
    (tmp_path / "elsewhere").write_bytes(_lines(5))
    (runs / "z_signals.jsonl").symlink_to(tmp_path / "elsewhere")     # newer, never a candidate
    os.utime(runs / "r1_signals.jsonl", (time.time() - 60, time.time() - 60))
    stop = threading.Event()
    threading.Thread(target=_unblock_fifo_until, args=(fifo, stop), daemon=True).start()
    try:
        finished, got = _guarded(tui._load_feed)
        assert finished and isinstance(got, list), got
        assert got[0] == "[yellow]⚠ r1_debug.jsonl : un tube nommé — jamais lu[/yellow]"
        assert sum("attack_started" in line for line in got) == 3 and len(got) == 4
    finally:
        stop.set()


# ── SEC16 (#438): one reader for every component, and the writes into runs/ held as its reads ──

def _drain_fifo_after(path: Path, stop: threading.Event) -> None:
    """Whoever opened the pipe for writing, blocked, is released once the test is over — a reader
    opens it, reads nothing, closes — until none waited for 2 s: a red test fails at its guard,
    never hangs, nor does its process at its exit."""
    stop.wait()
    quiet = time.monotonic()
    while time.monotonic() - quiet < 2.0:
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
            os.close(fd)
            quiet = time.monotonic()
        except OSError:
            pass
        time.sleep(0.05)


@pytest.mark.parametrize("place", ["absent", "regular", "link", "dangling-link", "fifo", "fifo-read", "dir"])
def test_a_line_is_appended_to_a_regular_file_only_never_through_a_link_never_blocking(tmp_path, place):
    """``append_line``: created when absent, appended whole to a regular file; a link in its place
    refused, nothing written where it points (an existing file unchanged, a missing one never
    created); a pipe refused at once — whether someone reads it or not — nothing written in it."""
    f = tmp_path / "manual_actions.jsonl"
    elsewhere = tmp_path / "elsewhere.jsonl"
    stop = threading.Event()
    reader = None
    if place == "regular":
        f.write_text('{"a": 1}\n')
    elif place == "link":
        elsewhere.write_text("kept\n")
        f.symlink_to(elsewhere)
    elif place == "dangling-link":
        f.symlink_to(elsewhere)
    elif place == "dir":
        f.mkdir()
    elif place.startswith("fifo"):
        os.mkfifo(f)
        threading.Thread(target=_drain_fifo_after, args=(f, stop), daemon=True).start()
        if place == "fifo-read":
            reader = os.open(f, os.O_RDONLY | os.O_NONBLOCK)
    try:
        finished, got = _guarded(channel_reader.append_line, f, '{"b": 2}')
        assert finished, "the write blocked"
        if place in ("absent", "regular"):
            assert got is None
            assert f.read_text() == ('{"a": 1}\n' if place == "regular" else "") + '{"b": 2}\n'
        else:
            assert isinstance(got, channel_reader.Refused), got
            assert str(got) == {"link": "un lien, jamais suivi", "dangling-link": "un lien, jamais suivi",
                                "fifo": "un tube nommé", "fifo-read": "un tube nommé", "dir": "un répertoire"}[place]
            assert (elsewhere.read_text() == "kept\n") if place == "link" else not elsewhere.exists()
            if reader is not None:
                assert os.read(reader, 100) == b""                 # nothing written in it
    finally:
        if reader is not None:
            os.close(reader)
        stop.set()


@pytest.mark.parametrize("place", ["absent", "link", "fifo", "dir"])
def test_a_lock_of_runs_is_a_regular_file_never_through_a_link(tmp_path, place):
    """``open_lock`` (a campaign's report, its triage): created when absent; a link, a pipe or a
    directory in its place refused — never opened, never created where a link points."""
    f, elsewhere = tmp_path / ".report.lock", tmp_path / "elsewhere"
    if place == "link":
        f.symlink_to(elsewhere)
    elif place == "fifo":
        os.mkfifo(f)
    elif place == "dir":
        f.mkdir()
    if place == "absent":
        os.close(channel_reader.open_lock(f))
        assert f.is_file()
        return
    with pytest.raises(channel_reader.Refused) as refused:
        channel_reader.open_lock(f)
    assert str(refused.value) == {"link": "un lien, jamais suivi", "fifo": "un tube nommé",
                                  "dir": "un répertoire"}[place]
    assert not elsewhere.exists()


def test_a_whole_file_written_replaces_a_link_never_follows_it(tmp_path):
    """``write_file`` (a campaign's report, its notes): a link in its place is replaced by the
    file, never followed — what it pointed to is unchanged."""
    elsewhere = tmp_path / "elsewhere.md"
    elsewhere.write_text("kept")
    f = tmp_path / "report.md"
    f.symlink_to(elsewhere)
    channel_reader.write_file(f, "# report\n")
    assert not f.is_symlink() and f.read_text() == "# report\n" and elsewhere.read_text() == "kept"
    assert [p.name for p in tmp_path.iterdir() if p.name.startswith(".report.md.")] == []


def test_a_whole_file_read_is_bounded_and_its_status_never_through_a_link(tmp_path):
    f = tmp_path / "x.json"
    f.write_text(json.dumps({"pad": "x" * 64}))
    assert channel_reader.read_json(f) == {"pad": "x" * 64}
    with pytest.raises(channel_reader.Refused, match="plus de 32 octets"):
        channel_reader.read_file(f, 32)
    (tmp_path / "l.json").symlink_to(f)
    with pytest.raises(channel_reader.Refused, match="un lien, jamais suivi"):
        channel_reader.lstat_regular(tmp_path / "l.json")
    assert channel_reader.lstat_regular(f).st_size == f.stat().st_size


@pytest.mark.parametrize("trap", ["link", "fifo", "dir", "disk-full"])
def test_the_watch_debug_line_never_through_a_link_never_blocking_the_cycle_goes_on(tmp_path, monkeypatch,
                                                                                     capsys, trap):
    """The watch's line of a cycle (``_write_debug_record``): a link, a pipe or a directory in its
    place, or the write failing (a disk full) — refused or failed, nothing written elsewhere, the
    cycle never cut (OV1, BL1: a cycle that acted is no failed cycle), said once in the watch's
    log, never at every cycle."""
    from glorfindel import agent
    monkeypatch.chdir(tmp_path)
    (tmp_path / "runs").mkdir()
    f = tmp_path / "runs" / "r1_debug.jsonl"
    elsewhere = tmp_path / "elsewhere.jsonl"
    stop = threading.Event()
    if trap == "link":
        elsewhere.write_text("kept\n")
        f.symlink_to(elsewhere)
    elif trap == "dir":
        f.mkdir()
    elif trap == "disk-full":
        def full(path, line, mode=0o644):
            raise OSError(errno.ENOSPC, "No space left on device")
        monkeypatch.setattr(channel_reader, "append_line", full)
    else:
        os.mkfifo(f)
        threading.Thread(target=_drain_fifo_after, args=(f, stop), daemon=True).start()
    state = {"signal": {"event": "detection", "ttp": "T1110.001", "resource_id": "/x/vm-a",
                        "context": {"run_id": "r1"}}, "action": "snapshot"}
    try:
        for _ in range(2):
            finished, got = _guarded(agent._write_debug_record, state)
            assert finished, "the cycle's line blocked the watch"
            assert got is None, got                                  # never raised: the cycle goes on
        assert trap != "link" or elsewhere.read_text() == "kept\n"
        out = " ".join(capsys.readouterr().out.split())
        assert out.count("debug non écrit") == 1 and "r1_debug.jsonl" in out
        assert {"link": "un lien, jamais suivi", "fifo": "un tube nommé", "dir": "un répertoire",
                "disk-full": "No space left on device"}[trap] in out
    finally:
        stop.set()


@pytest.mark.parametrize("trap", ["link", "fifo", "dir"])
def test_the_clis_manual_action_never_through_a_link_never_blocking(tmp_path, monkeypatch, capsys, trap):
    """The CLI's note of an operator's action (runs/manual_actions.jsonl): a link or a pipe in its
    place — refused, nothing written elsewhere, never blocking; the action stands, the refusal
    said once."""
    from glorfindel import cli
    monkeypatch.chdir(tmp_path)
    (tmp_path / "runs").mkdir()
    f = tmp_path / "runs" / "manual_actions.jsonl"
    elsewhere = tmp_path / "elsewhere.jsonl"
    stop = threading.Event()
    if trap == "link":
        f.symlink_to(elsewhere)
    elif trap == "dir":
        f.mkdir()
    else:
        os.mkfifo(f)
        threading.Thread(target=_drain_fifo_after, args=(f, stop), daemon=True).start()
    try:
        for _ in range(2):
            finished, got = _guarded(cli._record_manual_action, "release_isolation", "/x/vm-a", {"ok": True})
            assert finished and got is None, got
        assert not elsewhere.exists()
        out = " ".join(capsys.readouterr().out.split())       # the terminal's width aside
        assert out.count("l'action n'y est pas notée") == 1
    finally:
        stop.set()
