"""How the watch reads the runs/ channel (SEC8, #414): as an input it does not trust.

runs/ is written by other containers than the watch (the injectors, the console's CLI). The
watch's loop reads it between the reassertion, the TTL checks and the heartbeat: a read that
blocks, or that does not end, stops all of them. So:

- **a regular file only.** Each `*_signals.jsonl` is opened without blocking and without
  following a link (`O_NONBLOCK | O_NOFOLLOW`), then `fstat`: anything but a regular file — a
  link, a pipe, a device, a socket — is refused, said once (not at every poll), and never read;
- **a bounded read.** At most READ_BYTES and READ_LINES per file per poll; the rest waits for
  the next poll, from the offset kept. A line longer than LINE_BYTES is refused, said, and
  skipped to its end;
- **a bounded rate.** At most PER_WRITER_PER_MIN lines admitted per file (a run writes one
  file) and CHANNEL_PER_MIN for the whole channel, per minute; the surplus is refused and said
  in one line, at most once a minute (`Budget`), never one card per line.

The lines read are then admitted, or refused, by `glorfindel/signal_origin.py`.
"""
from __future__ import annotations

import errno
import os
import stat
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

# What one poll reads of one file. An injector's run writes a few lines of a few hundred bytes.
READ_BYTES = 256 * 1024
READ_LINES = 200
LINE_BYTES = 64 * 1024
# The lines admitted per minute: per file, and for the channel as a whole.
PER_WRITER_PER_MIN = 30
CHANNEL_PER_MIN = 120
WINDOW_S = 60.0

_FLAGS = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)


class Refused(OSError):
    """This entry of runs/ is not a regular file: never read (an OSError: whoever reads a file
    of runs/ and skips one it cannot read skips this one too)."""


def _kind(mode: int) -> str:
    for test, name in ((stat.S_ISFIFO, "un tube nommé"), (stat.S_ISCHR, "un périphérique"),
                       (stat.S_ISBLK, "un périphérique"), (stat.S_ISSOCK, "une socket"),
                       (stat.S_ISDIR, "un répertoire"), (stat.S_ISLNK, "un lien")):
        if test(mode):
            return name
    return "pas un fichier ordinaire"


def open_regular(path) -> int:
    """A descriptor on `path`, a regular file of runs/ — or Refused (a link, a pipe, a device,
    a socket, a directory). Never blocks, never follows a link. OSError when it is gone."""
    try:
        fd = os.open(path, _FLAGS)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise Refused("un lien, jamais suivi") from None
        if exc.errno in (errno.ENXIO, errno.EOPNOTSUPP):     # a socket
            raise Refused("une socket") from None
        raise
    try:
        mode = os.fstat(fd).st_mode
    except OSError:
        os.close(fd)
        raise
    if not stat.S_ISREG(mode):
        os.close(fd)
        raise Refused(_kind(mode))
    return fd


def start_offset(path) -> int:
    """Where the watch starts reading a file that was there before it: its end, for a regular
    file (lstat: a link is not followed); 0 otherwise — the reader then refuses it, and says so."""
    try:
        st = os.lstat(path)
    except OSError:
        return 0
    return st.st_size if stat.S_ISREG(st.st_mode) else 0


@dataclass
class Read:
    """One poll of one file: the complete lines read, where the next poll starts, whether it
    is still inside a line refused for its length, and how many such lines were refused."""
    lines: list[str] = field(default_factory=list)
    offset: int = 0
    skipping: bool = False
    too_long: int = 0


def read_lines(path, offset: int, skipping: bool = False) -> Read:
    """The complete lines of `path` from `offset`: at most READ_BYTES, READ_LINES. A line not
    ended yet (written from another container) is left for the next poll; one past LINE_BYTES
    is refused and skipped to its end (`skipping` carries that over to the next poll).
    Raises Refused (not a regular file) or OSError."""
    fd = open_regular(path)
    with os.fdopen(fd, "rb") as f:
        f.seek(offset)
        data = f.read(READ_BYTES)
    out = Read(offset=offset, skipping=skipping)
    pos = 0
    if skipping:
        nl = data.find(b"\n")
        if nl < 0:
            out.offset = offset + len(data)
            return out
        pos, out.skipping = nl + 1, False
    while len(out.lines) < READ_LINES:
        nl = data.find(b"\n", pos)
        if nl < 0:
            if len(data) - pos > LINE_BYTES:      # no end in sight, already past the bound
                out.too_long += 1
                out.skipping = True
                pos = len(data)
            break
        if nl - pos > LINE_BYTES:
            out.too_long += 1
        else:
            out.lines.append(data[pos:nl].decode("utf-8", errors="replace"))
        pos = nl + 1
    out.offset = offset + pos
    return out


class Budget:
    """The lines of the channel admitted per minute: `per_writer` per file, `total` for all.
    `take` says whether one more line passes; `report` gives the refused ones, at most once
    per window (one line in the log for a flood, never one per line). Thread-safe."""

    def __init__(self, per_writer: int = PER_WRITER_PER_MIN, total: int = CHANNEL_PER_MIN,
                 window_s: float = WINDOW_S, clock=time.monotonic):
        self.per_writer, self.total, self.window_s, self.clock = per_writer, total, window_s, clock
        self._lock = threading.Lock()
        self._start = clock()
        self._by: dict[str, int] = {}
        self._all = 0
        self._refused: dict[str, int] = {}
        self._said_at: float | None = None

    def take(self, writer: str) -> bool:
        with self._lock:
            now = self.clock()
            if now - self._start >= self.window_s:
                self._start, self._by, self._all = now, {}, 0
            if self._all >= self.total or self._by.get(writer, 0) >= self.per_writer:
                self._refused[writer] = self._refused.get(writer, 0) + 1
                return False
            self._by[writer] = self._by.get(writer, 0) + 1
            self._all += 1
            return True

    def report(self) -> dict[str, int]:
        """The lines refused since the last report, by file — {} when there are none, or when
        the last report is less than a window old (they are kept for the next one)."""
        with self._lock:
            if not self._refused:
                return {}
            now = self.clock()
            if self._said_at is not None and now - self._said_at < self.window_s:
                return {}
            self._said_at = now
            out, self._refused = self._refused, {}
            return out


class ChannelReader:
    """The watch's offsets in runs/*_signals.jsonl, and what it already said of each file.
    `poll` gives the lines read, as (file, line), within the budget; `say(text, kind)`
    receives what there is to say — kind "new" (a new run's file) or "refused"."""

    def __init__(self, runs_dir, say, *, budget: Budget | None = None):
        self.runs_dir = Path(runs_dir)
        self.say = say
        self.budget = budget or Budget()
        self.offsets: dict[Path, int] = {}
        self._skipping: dict[Path, bool] = {}
        self._refused: dict[Path, str] = {}

    def track_existing(self) -> None:
        """The files there at start: read from their end (only new lines are processed)."""
        for path in self.runs_dir.glob("*_signals.jsonl"):
            self.offsets[path] = start_offset(path)

    def _refuse(self, path: Path, why: str) -> None:
        if self._refused.get(path) != why:         # said once, not at every poll
            self._refused[path] = why
            self.say(f"{path.name} refusé : {why} — jamais lu (SEC8)", "refused")

    def poll(self) -> list[tuple[Path, str]]:
        for path in sorted(self.runs_dir.glob("*_signals.jsonl")):
            if path not in self.offsets:
                self.offsets[path] = 0          # new file — read from beginning
                self.say(f"New run: {path.name}", "new")
        out: list[tuple[str, str]] = []
        for path in list(self.offsets):
            try:
                got = read_lines(path, self.offsets[path], self._skipping.get(path, False))
            except Refused as exc:
                self._refuse(path, str(exc))
                continue
            except FileNotFoundError:
                continue
            except OSError as exc:
                self._refuse(path, f"illisible ({type(exc).__name__})")
                continue
            self._refused.pop(path, None)
            self.offsets[path], self._skipping[path] = got.offset, got.skipping
            if got.too_long:
                self.say(f"{path.name} : {got.too_long} ligne(s) de plus de {LINE_BYTES // 1024} Kio "
                         "refusée(s) — rien n'est décidé (SEC8)", "refused")
            out += [(path, line) for line in got.lines
                    if line.strip() and self.budget.take(path.name)]
        return out
