"""How Eregion reads the runs/ channel (SEC8, #414): as an input it does not trust — one reader
for every component (SEC16, #438): the watch, the console (eregion_console/runs_reader.py), the
analysis (a campaign's report and page). And how every writer writes there: a regular file only,
never through a link, never blocking (``append_line``, ``write_file``) — each in its own
directory, ``runs/<writer>/`` (SEC18, eregion_core/runs_layout.py), the others read-only to it.

runs/ is written by other containers than the watch (the injectors, the console's CLI). The
watch's loop reads it between the reassertion, the TTL checks and the heartbeat: a read that
blocks, or that does not end, stops all of them. So:

- **a regular file only.** Each `*_signals.jsonl` is opened without blocking and without
  following a link (`O_NONBLOCK | O_NOFOLLOW`), then `fstat`: anything but a regular file — a
  link, a pipe, a device, a socket — is refused, said once (not at every poll), and never read;
- **a bounded read.** At most READ_BYTES and READ_LINES per file per poll, FILES_PER_POLL files
  opened per poll (those with something new, in turn); the rest waits for the next poll, from
  the offset kept. A file replaced (another inode) or truncated is read again from its start; a
  file gone is forgotten. A line longer than LINE_BYTES is refused, said, and skipped to its end;
- **a bounded rate.** At most PER_WRITER_PER_MIN lines admitted per file (a run writes one
  file) and CHANNEL_PER_MIN for the whole channel, per minute: a poll reads no more lines than
  that room. A file whose writer has spent its minute is not read: what it holds is passed over,
  not admitted, counted in bytes and said in one line, at most once a minute (`Budget`), never
  one card per line. A file waiting only for the channel's minute is read later, nothing lost;
- **bounded effects.** What the lines admitted start in the watch is bounded too: CHANNEL_POLLS
  searches in flight (one per VM and technique), CHANNEL_QUEUED_PER_VM lines waiting per VM,
  CHANNEL_VMS VMs named; beyond, a line is refused and said (glorfindel/cli.py).

The lines read are then admitted, or refused, by `glorfindel/signal_origin.py`.
"""
from __future__ import annotations

import contextlib
import errno
import json
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
# The files one poll opens — those with something new; the others wait for the next poll, in turn.
FILES_PER_POLL = 32
# The lines admitted per minute: per file, and for the channel as a whole.
PER_WRITER_PER_MIN = 30
CHANNEL_PER_MIN = 120
WINDOW_S = 60.0
# What the channel's lines may start in the watch (glorfindel/cli.py, `_channel_room`): the
# searches in flight (one per VM and technique), its lines waiting per VM, the VMs it names.
CHANNEL_POLLS = 16
CHANNEL_QUEUED_PER_VM = 8
CHANNEL_VMS = 64

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
    return _start(path)[0]


def _start(path) -> tuple[int, int | None]:
    """(start_offset, the file's inode — None when it is no regular file)."""
    try:
        st = os.lstat(path)
    except OSError:
        return 0, None
    return (st.st_size, st.st_ino) if stat.S_ISREG(st.st_mode) else (0, None)


@dataclass
class Read:
    """One poll of one file: the complete lines read, where the next poll starts, whether it
    is still inside a line refused for its length, and how many such lines were refused."""
    lines: list[str] = field(default_factory=list)
    offset: int = 0
    skipping: bool = False
    too_long: int = 0
    ino: int | None = None
    restarted: bool = False


def read_lines(path, offset: int, skipping: bool = False, ino: int | None = None,
               max_lines: int | None = None) -> Read:
    """The complete lines of `path` from `offset`: at most READ_BYTES, READ_LINES. A line not
    ended yet (written from another container) is left for the next poll; one past LINE_BYTES
    is refused and skipped to its end (`skipping` carries that over to the next poll). A file
    that is not the one read before (`ino`) or shorter than `offset` — replaced, truncated — is
    read from its start (`restarted`). `max_lines`: fewer lines this time (the rate's room),
    the rest left in place. Raises Refused (not a regular file) or OSError."""
    fd = open_regular(path)
    with os.fdopen(fd, "rb") as f:
        st = os.fstat(f.fileno())
        restarted = (ino is not None and st.st_ino != ino) or st.st_size < offset
        if restarted:
            offset, skipping = 0, False
        f.seek(offset)
        data = f.read(READ_BYTES)
    out = Read(offset=offset, skipping=skipping, ino=st.st_ino, restarted=restarted)
    pos = 0
    if skipping:
        nl = data.find(b"\n")
        if nl < 0:
            out.offset = offset + len(data)
            return out
        pos, out.skipping = nl + 1, False
    while len(out.lines) < READ_LINES:
        if max_lines is not None and len(out.lines) >= max_lines:
            break
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


def tail_lines(path, max_bytes: int = READ_BYTES, max_lines: int = READ_LINES) -> list[str]:
    """The last complete lines of `path`, a regular file of runs/ (`open_regular`: never blocks,
    never follows a link) — for a reader that shows what was written lately (the console's live
    feed, the TUI), never the whole file: at most `max_bytes` read from its end, the first line
    cut by that bound dropped, a line past LINE_BYTES refused, at most `max_lines` kept, the last
    one only when it is ended. Raises Refused (not a regular file) or OSError (SEC15)."""
    fd = open_regular(path)
    with os.fdopen(fd, "rb") as f:
        size = os.fstat(f.fileno()).st_size
        start = max(0, size - max_bytes)
        # From the byte before the bound: a newline there, the bound falls at a line's start, and
        # that line is whole — the first newline is that one.
        f.seek(max(0, start - 1))
        data = f.read(max_bytes + (1 if start > 0 else 0))
    if start > 0:
        nl = data.find(b"\n")
        data = data[nl + 1:] if nl >= 0 else b""
    ended = data.split(b"\n")[:-1]        # what follows the last newline is not ended yet
    return [line.decode("utf-8", errors="replace") for line in ended if len(line) <= LINE_BYTES][-max_lines:]


# A whole file read at once (``read_file``): a watch's debug file, the operator's manual actions —
# a few hundred kilobytes over weeks; a report, a window, a manifest, a status — a few kilobytes.
FILE_BYTES = 16 * 1024 * 1024
DOC_BYTES = 1024 * 1024


def read_file(path, max_bytes: int = FILE_BYTES) -> bytes:
    """The whole of a regular file of runs/ (``open_regular``: never blocks, never follows a link),
    at most ``max_bytes`` — a file larger is refused, never cut and read as if it were whole.
    Raises Refused, or OSError (gone)."""
    fd = open_regular(path)
    with os.fdopen(fd, "rb") as f:
        data = f.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise Refused(f"plus de {max_bytes} octets")
    return data


def read_text(path, max_bytes: int = FILE_BYTES) -> str:
    """``read_file``, as UTF-8 (UnicodeDecodeError when it is not)."""
    return read_file(path, max_bytes).decode("utf-8")


def read_json(path, max_bytes: int = DOC_BYTES):
    """A JSON document of runs/, read by ``read_file`` — ValueError when it is not JSON."""
    return json.loads(read_text(path, max_bytes))


def lstat_regular(path) -> os.stat_result:
    """The lstat of a regular file of runs/ — its age, its size — never through a link: anything
    else is Refused, in the words ``open_regular`` uses; OSError when it is gone."""
    st = os.lstat(path)
    if not stat.S_ISREG(st.st_mode):
        raise Refused("un lien, jamais suivi" if stat.S_ISLNK(st.st_mode) else _kind(st.st_mode))
    return st


_APPEND = (os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_NONBLOCK", 0)
           | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))


def append_line(path, line: str, mode: int = 0o644, *, sync: bool = False) -> None:
    """Append one whole line to a regular file of runs/, created when absent (SEC16): never
    through a link, never blocking — a pipe without a reader refuses at once —, anything but a
    regular file refused (Refused), its line written whole in one write (``O_APPEND``).
    ``sync``: on disk before it returns (Orodruin's journal, its registry — SEC18)."""
    try:
        fd = os.open(path, _APPEND, mode)
    except OSError as exc:
        _refuse_open(path, exc)
        raise
    try:
        mode_ = os.fstat(fd).st_mode
        if not stat.S_ISREG(mode_):
            raise Refused(_kind(mode_))
        data = (line.rstrip("\n") + "\n").encode("utf-8")
        while data:
            data = data[os.write(fd, data):]
        if sync:
            os.fsync(fd)
    finally:
        os.close(fd)


def _refuse_open(path, exc: OSError) -> None:
    """An open for writing that failed on what is in the file's place: Refused, in the words a
    read would use — a link, a directory, a pipe no one reads, a socket. Any other failure:
    nothing raised here (the caller raises it)."""
    if exc.errno == errno.ELOOP:
        raise Refused("un lien, jamais suivi") from None
    if exc.errno == errno.EISDIR:
        raise Refused("un répertoire") from None
    if exc.errno in (errno.ENXIO, errno.EOPNOTSUPP):     # a pipe no one reads, a socket
        try:
            kind = _kind(os.lstat(path).st_mode)
        except OSError:
            kind = "pas un fichier ordinaire"
        raise Refused(kind) from None


_LOCK = (os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
         | getattr(os, "O_CLOEXEC", 0))


def open_lock(path, mode: int = 0o644) -> int:
    """A descriptor on a lock of runs/ (a campaign's report, its triage), created when absent: a
    regular file only (``fstat``), never through a link, never blocking — anything else is Refused
    (SEC16)."""
    try:
        fd = os.open(path, _LOCK, mode)
    except OSError as exc:
        _refuse_open(path, exc)
        raise
    try:
        kind = os.fstat(fd).st_mode
    except OSError:
        os.close(fd)
        raise
    if not stat.S_ISREG(kind):
        os.close(fd)
        raise Refused(_kind(kind))
    return fd

_said_writes: dict[str, str] = {}


def say_once(path, why: str) -> bool:
    """True the first time this process meets ``path`` refused for ``why`` (again when ``why``
    changes), whatever name it is written by: a refused write said once, never at every one."""
    key = os.path.abspath(path)
    if _said_writes.get(key) == why:
        return False
    _said_writes[key] = why
    return True


def why_not_written(exc: OSError) -> str:
    """What a write into runs/ met, said: a refusal in its own words, else the error (a disk full,
    a directory missing)."""
    return str(exc) if isinstance(exc, Refused) else f"{type(exc).__name__}: {exc.strerror or exc}"


def write_file(path, text: str, mode: int = 0o644, *, sync: bool = False) -> None:
    """Write a whole file of runs/ (a campaign's report, its notes) at once: in a new file beside
    it (``mkstemp``: created, never opened through a link), then renamed over it — a link in its
    place is replaced, never followed (SEC16). Raises OSError.

    ``sync`` (FS1b, the watch's registers of the action queue): the file fsync'd before it is
    renamed, then its directory — written once this returns, a crash of the host included."""
    import tempfile
    path = Path(path)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
            if sync:
                f.flush()
                os.fsync(f.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise
    if sync:
        dfd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)


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
        self._passed: dict[str, int] = {}
        self._said_at: float | None = None

    def _roll(self) -> None:
        now = self.clock()
        if now - self._start >= self.window_s:
            self._start, self._by, self._all = now, {}, 0

    def room(self, writer: str) -> tuple[int, int]:
        """(lines `writer` may still have admitted this minute, lines the channel may)."""
        with self._lock:
            self._roll()
            return self.per_writer - self._by.get(writer, 0), self.total - self._all

    def pass_over(self, writer: str, nbytes: int) -> None:
        """`nbytes` of `writer` not read: its minute is spent (said with the refused lines)."""
        with self._lock:
            self._passed[writer] = self._passed.get(writer, 0) + nbytes

    def take(self, writer: str) -> bool:
        with self._lock:
            self._roll()
            if self._all >= self.total or self._by.get(writer, 0) >= self.per_writer:
                self._refused[writer] = self._refused.get(writer, 0) + 1
                return False
            self._by[writer] = self._by.get(writer, 0) + 1
            self._all += 1
            return True

    def report(self) -> dict[str, tuple[int, int]]:
        """What was not admitted since the last report, by file: (lines refused, bytes passed
        over) — {} when there is nothing, or when the last report is less than a window old
        (it is kept for the next one)."""
        with self._lock:
            if not self._refused and not self._passed:
                return {}
            now = self.clock()
            if self._said_at is not None and now - self._said_at < self.window_s:
                return {}
            self._said_at = now
            out = {w: (self._refused.get(w, 0), self._passed.get(w, 0))
                   for w in {*self._refused, *self._passed}}
            self._refused, self._passed = {}, {}
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
        self._ino: dict[Path, int | None] = {}
        self._cursor = 0

    def track_existing(self) -> None:
        """The files there at start: read from their end (only new lines are processed)."""
        for path in self.runs_dir.glob("*_signals.jsonl"):
            self.offsets[path], self._ino[path] = _start(path)

    def _forget(self, path: Path) -> None:
        for kept in (self.offsets, self._skipping, self._refused, self._ino):
            kept.pop(path, None)

    def _pass_over(self, path: Path, size: int) -> None:
        """The writer's minute is spent: what the file holds is not read — passed over to its
        end, counted; a line cut there is skipped to its end at the next read."""
        try:
            fd = open_regular(path)
        except OSError:
            return
        try:
            ends_a_line = size == 0 or os.pread(fd, 1, size - 1) == b"\n"
        finally:
            os.close(fd)
        self.budget.pass_over(path.name, size - self.offsets[path])
        self.offsets[path], self._skipping[path] = size, not ends_a_line

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
        paths = list(self.offsets)
        start = self._cursor % len(paths) if paths else 0
        opened = 0
        for i, path in enumerate(paths[start:] + paths[:start]):
            try:
                st = os.lstat(path)
            except FileNotFoundError:
                self._forget(path)              # gone: forgotten, a new file of this name read whole
                continue
            except OSError:
                st = None
            regular = st is not None and stat.S_ISREG(st.st_mode)
            if regular and st.st_ino == self._ino.get(path) and st.st_size == self.offsets[path]:
                continue                        # nothing new: not opened
            if not regular and path in self._refused:
                continue                        # refused already, and said
            if opened >= FILES_PER_POLL:
                self._cursor = start + i        # the next poll starts here
                break
            writer_left, channel_left = self.budget.room(path.name)
            if channel_left <= 0:
                continue                        # the channel's minute is spent: read later
            opened += 1
            if writer_left <= 0 and regular and st.st_ino == self._ino.get(path) \
                    and st.st_size > self.offsets[path]:
                self._pass_over(path, st.st_size)
                continue
            try:
                got = read_lines(path, self.offsets[path], self._skipping.get(path, False),
                                 ino=self._ino.get(path), max_lines=min(writer_left, channel_left))
            except Refused as exc:
                self._refuse(path, str(exc))
                continue
            except FileNotFoundError:
                self._forget(path)
                continue
            except OSError as exc:
                self._refuse(path, f"illisible ({type(exc).__name__})")
                continue
            self._refused.pop(path, None)
            self.offsets[path], self._skipping[path], self._ino[path] = got.offset, got.skipping, got.ino
            if got.restarted:
                self.say(f"{path.name} : remplacé ou tronqué — relu depuis son début (SEC8)", "new")
            if got.too_long:
                self.say(f"{path.name} : {got.too_long} ligne(s) de plus de {LINE_BYTES // 1024} Kio "
                         "refusée(s) — rien n'est décidé (SEC8)", "refused")
            out += [(path, line) for line in got.lines
                    if line.strip() and self.budget.take(path.name)]
            if self.budget.room(path.name)[0] <= 0 and regular and got.offset < st.st_size:
                self._pass_over(path, st.st_size)   # its minute spent now: the rest not admitted
        return out
