"""DEP2 (#590): one package raised alone in the locks, and kept there by the next `make lock`.

`make lock` resolves everything at LOCK_DATE (`--exclude-newer`), and keeps what each lock already
pins. A fix published after that date (oauthlib 4.0.1, 31/10, for GHSA-3jp2-3mrg-2vxc) is out of
reach: moving LOCK_DATE for it rewrites the header of every lock, those that do not hold the package
too. `make lock UPGRADE_PACKAGE=oauthlib` raises that package alone, to the newest release before
UPGRADE_DATE (`--upgrade-package`, `--exclude-newer-package <name>=<date>`), and only in the locks
that pin it: the others are written again byte for byte.

uv writes `--exclude-newer-package` into the header of the lock, never `--upgrade-package`. The next
`make lock` at the same LOCK_DATE without that flag took the package back down (measured, uv 0.13.6:
oauthlib 4.0.1 → 4.0.0, silently). So each lock's own exceptions are passed again, as long as they
postdate LOCK_DATE; one that does not would cap the package below LOCK_DATE, and is dropped.

    python3 scripts/lock_flags.py flags requirements/dev.txt --lock-date 2026-10-26 \\
        [--upgrade oauthlib[,name…] --upgrade-date 2026-11-05]     # the flags for this lock, one line
    python3 scripts/lock_flags.py held oauthlib[,name…] requirements/*.txt   # exit 2: pinned nowhere
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_EXCEPTION = re.compile(r"--exclude-newer-package ([A-Za-z0-9][A-Za-z0-9._-]*)=(\d{4}-\d{2}-\d{2})T00:00:00Z")
_PINNED = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==")


def canonical(name: str) -> str:
    """The package's name as uv writes it in a lock (PEP 503)."""
    return re.sub(r"[-_.]+", "-", name).lower()


def _names(arg: str) -> list[str]:
    names = [n for n in (x.strip() for x in arg.split(",")) if n]
    bad = [n for n in names if not _NAME.match(n)]
    if bad or not names:
        raise SystemExit(f"lock_flags: nom de paquet invalide : {arg!r}")
    return [canonical(n) for n in names]


def _date(arg: str) -> str:
    if not _DATE.match(arg):
        raise SystemExit(f"lock_flags: date invalide (AAAA-MM-JJ) : {arg!r}")
    return arg


def pinned(lock: Path) -> set[str]:
    """The packages the lock pins, whatever their markers."""
    if not lock.exists():
        return set()
    return {canonical(m.group(1)) for line in lock.read_text(encoding="utf-8").splitlines()
            if (m := _PINNED.match(line))}


def exceptions(lock: Path) -> dict[str, str]:
    """name → date of the `--exclude-newer-package` the lock's header records (its command)."""
    if not lock.exists():
        return {}
    header = lock.read_text(encoding="utf-8").splitlines()[:2]
    return {canonical(n): d for n, d in _EXCEPTION.findall(header[1] if len(header) > 1 else "")}


def flags(lock: Path, lock_date: str, upgrade: list[str] | None = None,
          upgrade_date: str | None = None) -> list[str]:
    """The flags `make lock` adds to the uv command that writes `lock`, after LOCK_FLAGS."""
    kept = {n: d for n, d in exceptions(lock).items() if d > lock_date}
    out: list[str] = []
    held = pinned(lock)
    for name in upgrade or []:
        if name not in held:
            continue                                   # this lock is written again byte for byte
        out += ["--upgrade-package", name]
        if upgrade_date and upgrade_date > lock_date:
            kept[name] = upgrade_date
    for name in sorted(kept):
        out += ["--exclude-newer-package", f"{name}={kept[name]}T00:00:00Z"]
    return out


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="lock_flags.py")
    sub = p.add_subparsers(dest="cmd", required=True)
    f = sub.add_parser("flags")
    f.add_argument("lock", type=Path)
    f.add_argument("--lock-date", required=True, type=_date)
    f.add_argument("--upgrade", type=_names)
    f.add_argument("--upgrade-date", type=_date)
    h = sub.add_parser("held")
    h.add_argument("names", type=_names)
    h.add_argument("locks", nargs="+", type=Path)
    a = p.parse_args(argv)
    if a.cmd == "flags":
        if a.upgrade and not a.upgrade_date:
            raise SystemExit("lock_flags: --upgrade sans --upgrade-date")
        print(" ".join(flags(a.lock, a.lock_date, a.upgrade, a.upgrade_date)))
        return 0
    everywhere = set().union(*(pinned(lock) for lock in a.locks))
    missing = [n for n in a.names if n not in everywhere]
    if missing:
        print(f"UPGRADE_PACKAGE : {', '.join(missing)} n'est dans aucun verrou "
              f"({', '.join(str(lock) for lock in a.locks)})", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
