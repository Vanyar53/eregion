"""SEC8 (#414) — the runs/ channel read as an input the watch does not trust.

1. The watch reads in runs/ only regular files, opened without blocking and without following
   a link; anything else is refused, said once, never read. What one poll reads of a file is
   bounded in bytes and in lines, the rest left for the next poll; a line past the bound is
   refused and said. A refusal is said, never a stop of the watch.

No Azure call, no model call. Every identifier is made up (repository public). Mutants
M2810–M2839 (scripts/mutation_check.py) are measured here.
"""
from __future__ import annotations

import errno
import json
import os
import threading
import time
from pathlib import Path

import pytest

from glorfindel import channel_reader, signal_origin

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


def test_a_huge_file_is_read_a_bounded_slice_per_poll(tmp_path, monkeypatch):
    """At most READ_LINES lines and READ_BYTES per poll; the rest at the next one, from the
    offset kept — every line read once, in order."""
    monkeypatch.setattr(channel_reader, "READ_LINES", 50)
    monkeypatch.setattr(channel_reader, "READ_BYTES", 16 * 1024)
    f = tmp_path / "x_signals.jsonl"
    f.write_bytes(_lines(400))
    got = channel_reader.read_lines(f, 0)
    assert len(got.lines) <= 50 and got.offset <= 16 * 1024
    seen, offset, polls = list(got.lines), got.offset, 1
    while offset < f.stat().st_size:
        got = channel_reader.read_lines(f, offset)
        assert len(got.lines) <= 50 and got.offset - offset <= 16 * 1024
        seen += got.lines
        offset, polls = got.offset, polls + 1
    assert [json.loads(x)["signal_id"] for x in seen] == [f"r_{i}" for i in range(400)]
    assert polls >= 400 // 50


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
