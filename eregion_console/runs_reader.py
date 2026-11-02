"""How the console reads runs/ (SEC15, #425): as the watch reads it (eregion_core/channel_reader.py).

runs/ is written by other containers than the console — the injectors, the CLI, the watch, the
pulls of the exercise channel. Every read of it here:

- **a regular file only**, opened without blocking and without following a link
  (``channel_reader.open_regular``): a link, a named pipe, a device, a socket is refused,
  never read;
- **a bounded read**: at most ``MAX_BYTES`` (a JSON report or a window, ``JSON_MAX_BYTES``); a
  file larger is refused, never cut and read as if it were whole. The feed and the TUI read only
  the end of their files (``tail``, ``channel_reader.tail_lines``);
- **said once**: a file refused is said once in the console's log, with why — never at every
  read (``say_refused``).

Whatever is refused reads as absent (None, []): the pages say what they hold, the file is never
taken for its contents. No route reads here on the event loop: a heavy read goes through a
thread (``asyncio.to_thread``)."""
from __future__ import annotations

import json
import os
import stat

from eregion_core import channel_reader

# A watch's debug file, the manual actions; a run report, an exercise window, a status, a
# manifest — the bounds of the one reader (SEC16, eregion_core/channel_reader.py).
MAX_BYTES = channel_reader.FILE_BYTES
JSON_MAX_BYTES = channel_reader.DOC_BYTES

_said: dict[str, str] = {}
# A link, as ``channel_reader.open_regular`` refuses it.
LINK = "un lien, jamais suivi"


def say_refused(path, why: str) -> None:
    """A file of runs/ refused: said once in the console's log (again only if why changes) —
    once whatever the name it is read by (``runs/x.json`` or its absolute path)."""
    key = os.path.abspath(path)
    if _said.get(key) != why:
        _said[key] = why
        print(f"  ⚠ console: {shown(path)} — {why} : jamais lu (runs/ se lit comme la watch le lit)", flush=True)


def shown(path) -> str:
    """A name of runs/ as the log shows it: its control characters escaped (``\\x1b``) — another
    container writes it, and it never writes into the console's log."""
    return "".join(c if c.isprintable() else f"\\x{ord(c):02x}" if ord(c) < 0x100 else f"\\u{ord(c):04x}"
                   for c in str(path))


def _read(path, max_bytes: int) -> tuple[bytes | None, str]:
    """The file's bytes and '' — or None and why it is not read ('' when it is not there)."""
    try:
        return channel_reader.read_file(path, max_bytes), ""
    except channel_reader.Refused as exc:
        say_refused(path, str(exc))
        return None, str(exc)
    except FileNotFoundError:
        return None, ""
    except OSError as exc:
        return None, exc.strerror or type(exc).__name__


def read_bytes(path, max_bytes: int = MAX_BYTES) -> bytes | None:
    """The file's bytes — None when it is refused (not a regular file, or larger than
    ``max_bytes``: said once) or gone."""
    return _read(path, max_bytes)[0]


def read_text(path, max_bytes: int = MAX_BYTES) -> str | None:
    data = read_bytes(path, max_bytes)
    return None if data is None else data.decode("utf-8", errors="replace")


def read_json(path, max_bytes: int = JSON_MAX_BYTES):
    """The file's JSON — None when it is refused, gone, or not JSON."""
    return json_and_why(path, max_bytes)[0]


def json_and_why(path, max_bytes: int = JSON_MAX_BYTES) -> tuple[object, str]:
    """The file's JSON and '' — or None and why it is not read ('' when it is not there): where
    a page must tell a file refused from a file absent (Orodruin's status of a request)."""
    data, why = _read(path, max_bytes)
    if data is None:
        return None, why
    try:
        return json.loads(data.decode("utf-8", errors="replace")), ""
    except ValueError:
        return None, "pas du JSON"


def lines(path, max_bytes: int = MAX_BYTES) -> list[str]:
    text = read_text(path, max_bytes)
    return [] if text is None else text.splitlines()


def tail(path) -> list[str]:
    """The last lines of a file of runs/ (``channel_reader.tail_lines``) — [] when it is refused
    (said once) or gone: the feed and the TUI show what was written lately, never the whole."""
    try:
        return channel_reader.tail_lines(path)
    except channel_reader.Refused as exc:
        say_refused(path, str(exc))
    except OSError:
        pass
    return []


def regular(path) -> os.stat_result | None:
    """The file's lstat when it is a regular file — None otherwise: a link is never followed, a
    pipe or a device has no age nor size to give, and it is said once, in the words
    ``read_bytes`` would say it — from the lstat alone, nothing opened."""
    try:
        st = os.lstat(path)
    except OSError:
        return None
    if stat.S_ISREG(st.st_mode):
        return st
    say_refused(path, LINK if stat.S_ISLNK(st.st_mode) else channel_reader._kind(st.st_mode))
    return None
