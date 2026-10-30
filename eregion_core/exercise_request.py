"""Dagorlad, phase (b) (docs/design/console.md, §7): a request for Orodruin — what the console
writes, what the operator carries to Orodruin, what Orodruin judges again and runs.

A request carries an identifier and its time; for each wire, the experiment, the target and its
rank. Nothing else: no zone, no « destructive », no expected result, no mode of the target, no
name typed. Orodruin recomputes everything from what it reads (``eregion_core/exercise_runner.py``),
and Annatar and Gothmog stay blind to Glorfindel as Glorfindel is to them.

``read`` is the only way in: it refuses any field more, any field missing, a value of the wrong
kind — the same reader on the console's host, on the operator's machine and on Orodruin, so a
request forged on a compromised H0 cannot carry anything the reader would trust.

The names typed by the operator (a destructive technique's target, or one nobody declared
non-destructive: A0) never live in the request: the command that carries it
(``make orodruin-exercise``) asks for them on the operator's machine and writes them beside it,
in a file of their own (``read_typed``). A name the console kept would prove nothing: a request
forged on H0 would pass under the human gesture unseen.

Where the console writes a request: ``~/.eregion/console/requests/`` (``requests_dir``), its own
directory — never ``runs/`` nor ``~/.glorfindel/``, where the watch reads (« Glorfindel reste
aveugle »). D1: the shared core; the console, the operator's command and Orodruin read it, none
of them importing another.
"""
from __future__ import annotations

import json
import os
import re
import secrets
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from eregion_core.orodruin import CEILING_INJECTIONS

# The fields, and nothing else (« rien d'autre »).
FIELDS = ("id", "at", "wires")
WIRE_FIELDS = ("experiment", "target", "rank")
TYPED_FIELDS = ("request", "typed")
# Each wire is at least one injection: a request never holds more than Orodruin's ceiling.
MAX_WIRES = CEILING_INJECTIONS
# Bounded reads: a request is a few hundred bytes.
MAX_BYTES = 64 * 1024

REQUESTS_ENV = "EREGION_REQUESTS_DIR"
_ID = re.compile(r"^r-\d{8}T\d{6}Z-[0-9a-f]{6}$")
_EXPERIMENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_VM_ID = re.compile(r"^/subscriptions/[^/\s]+/resourceGroups/[^/\s]+/providers/"
                    r"Microsoft\.Compute/virtualMachines/[^/\s]+$", re.IGNORECASE)
# A VM name as Azure writes it (1–64: letters, digits, '-', '_', '.').
_VM_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


class RequestRefused(ValueError):
    """A request (or its names typed) that the one reader does not take: why, in a sentence."""


@dataclass(frozen=True)
class Wire:
    experiment: str
    target: str
    rank: int

    @property
    def target_name(self) -> str:
        return self.target.rstrip("/").rsplit("/", 1)[-1]


@dataclass(frozen=True)
class Request:
    id: str
    at: str
    wires: tuple[Wire, ...]

    def to_dict(self) -> dict:
        return {"id": self.id, "at": self.at,
                "wires": [{"experiment": w.experiment, "target": w.target, "rank": w.rank}
                          for w in self.wires]}


def valid_id(value) -> bool:
    return isinstance(value, str) and bool(_ID.match(value))


def _exact(doc, fields: tuple[str, ...], what: str) -> None:
    if not isinstance(doc, dict):
        raise RequestRefused(f"{what} is not a JSON object")
    extra = sorted(set(doc) - set(fields))
    if extra:
        raise RequestRefused(f"{what} carries a field it never holds: {', '.join(map(str, extra))}")
    missing = [f for f in fields if f not in doc]
    if missing:
        raise RequestRefused(f"{what} lacks {', '.join(missing)}")


def read(doc) -> Request:
    """The request, or ``RequestRefused``: exactly its fields, each of its kind — an id
    ``r-<UTC time>-<6 hex>``, an ISO time with its zone, 1 to MAX_WIRES wires, each exactly an
    experiment (a catalogue id), a VM's resource id and its rank, the ranks 1, 2, … in order,
    the same pair once."""
    _exact(doc, FIELDS, "the request")
    if not valid_id(doc["id"]):
        raise RequestRefused("its id is not r-<YYYYMMDDTHHMMSSZ>-<6 hex>")
    at = doc["at"]
    try:
        when = datetime.fromisoformat(at) if isinstance(at, str) else None
    except ValueError:
        when = None
    if when is None or when.tzinfo is None:
        raise RequestRefused("its time is not an ISO time with its zone")
    wires = doc["wires"]
    if not isinstance(wires, list) or not 1 <= len(wires) <= MAX_WIRES:
        raise RequestRefused(f"its wires are not a list of 1 to {MAX_WIRES}")
    out, seen = [], set()
    for i, w in enumerate(wires, 1):
        _exact(w, WIRE_FIELDS, f"wire {i}")
        e, t, rank = w["experiment"], w["target"], w["rank"]
        if not isinstance(e, str) or not _EXPERIMENT.match(e):
            raise RequestRefused(f"wire {i}: its experiment is not a catalogue id")
        if not isinstance(t, str) or not _VM_ID.match(t):
            raise RequestRefused(f"wire {i}: its target is not a VM's resource id")
        if isinstance(rank, bool) or not isinstance(rank, int) or rank != i:
            raise RequestRefused(f"wire {i}: its rank is not {i} (the wires run in their order)")
        key = (e, t.lower())
        if key in seen:
            raise RequestRefused(f"wire {i}: the same pair twice")
        seen.add(key)
        out.append(Wire(e, t, rank))
    return Request(doc["id"], at, tuple(out))


def new(pairs: list[tuple[str, str]], now: datetime | None = None) -> Request:
    """A request for these (experiment, target) pairs, ranked in their order — passed through
    ``read`` like any other."""
    now = now or datetime.now(timezone.utc)
    rid = f"r-{now.strftime('%Y%m%dT%H%M%SZ')}-{secrets.token_hex(3)}"
    return read({"id": rid, "at": now.isoformat(),
                 "wires": [{"experiment": e, "target": t, "rank": i}
                           for i, (e, t) in enumerate(pairs, 1)]})


def requests_dir() -> Path:
    """The console's own directory for requests: ``~/.eregion/console/requests`` (or
    ``EREGION_REQUESTS_DIR``) — never under ``runs/`` nor ``~/.glorfindel/``."""
    return Path(os.environ.get(REQUESTS_ENV) or Path.home() / ".eregion" / "console" / "requests")


def write(request: Request, directory: Path | None = None) -> Path:
    """Write a new request, mode 600, never over another (O_EXCL)."""
    directory = Path(directory or requests_dir())
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = directory / f"{request.id}.json"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(request.to_dict(), f, indent=2)
        f.write("\n")
    return path


def _load_json(path: Path, what: str):
    try:
        with open(path, "rb") as f:
            body = f.read(MAX_BYTES + 1)
    except OSError as e:
        raise RequestRefused(f"{what} unreadable: {e.strerror or e}") from None
    if len(body) > MAX_BYTES:
        raise RequestRefused(f"{what} larger than {MAX_BYTES} bytes")
    try:
        return json.loads(body)
    except ValueError:
        raise RequestRefused(f"{what} is not JSON") from None


def load(path: str | Path) -> Request:
    return read(_load_json(Path(path), "the request"))


def read_typed(doc, request: Request) -> dict[int, str]:
    """The names typed for a request, by rank: ``{"request": <its id>, "typed": {"<rank>":
    "<name>"}}``, exactly — a rank of this request, a VM's name."""
    _exact(doc, TYPED_FIELDS, "the names typed")
    if doc["request"] != request.id:
        raise RequestRefused("the names typed are another request's")
    typed = doc["typed"]
    if not isinstance(typed, dict):
        raise RequestRefused("the names typed are not an object")
    ranks = {w.rank for w in request.wires}
    out: dict[int, str] = {}
    for k, v in typed.items():
        if not (isinstance(k, str) and k.isdigit() and int(k) in ranks):
            raise RequestRefused(f"a name typed for a wire this request does not hold: {k!r}")
        if not isinstance(v, str) or not _VM_NAME.match(v):
            raise RequestRefused(f"the name typed for wire {k} is not a VM's name")
        out[int(k)] = v
    return out


def load_typed(path: str | Path | None, request: Request) -> dict[int, str]:
    """No file: nothing typed (a request without a wire that asks for a name)."""
    if path is None or not Path(path).exists():
        return {}
    return read_typed(_load_json(Path(path), "the names typed"), request)


# ── On the operator's machine: show the request, have the names typed ───────────────────

def asks_name(destructive: bool | None, kind: str) -> bool:
    """A technique destructive, or that nobody declared non-destructive (A0): its target's
    name is typed. The catalogue decides — never the request."""
    return kind == "technique" and destructive is not False


def confirm(request: Request, catalog: dict, *, ask=input, say=print) -> dict | None:
    """Show the request wire by wire, and have the operator type the name of each wire's
    target that asks for one. Returns the names typed (``read_typed``'s shape), or None when
    the operator stops or types another name: nothing is sent. The name is compared here to
    the target the request names, to fail early; Orodruin compares it to the name it reads."""
    say(f"Request {request.id}, written {request.at} — {len(request.wires)} wire(s), "
        "one after the other:")
    for w in request.wires:
        e = catalog.get(w.experiment)
        what = f"{e.kind} {e.id} {e.name}" if e else f"{w.experiment} (not in this catalogue)"
        flag = ""
        if e is None or asks_name(e.destructive, e.kind):
            flag = "  ← DESTRUCTIVE" if e is not None and e.destructive else "  ← name to type"
        say(f"  {w.rank:>2}. {what}  →  {w.target_name}  (group "
            f"{w.target.split('/')[4]}){flag}")
    typed: dict[str, str] = {}
    for w in request.wires:
        e = catalog.get(w.experiment)
        if e is not None and not asks_name(e.destructive, e.kind):
            continue
        got = ask(f"Wire {w.rank}: type the name of its target VM to run it: ").strip()
        if got != w.target_name:
            say(f"✗ wire {w.rank}: « {got} » is not its target — nothing is sent.")
            return None
        typed[str(w.rank)] = got
    answer = ask(f"Run these {len(request.wires)} wire(s) from Orodruin? [y/N] ").strip().lower()
    if answer not in ("y", "yes", "o", "oui"):
        say("Nothing sent.")
        return None
    return {"request": request.id, "typed": typed}


def main(argv: list[str] | None = None) -> int:
    """``python -m eregion_core.exercise_request confirm <request.json> <typed.json>`` (the
    operator's machine, ``make orodruin-exercise``); ``check-id <id>``."""
    import argparse

    ap = argparse.ArgumentParser(prog="python -m eregion_core.exercise_request")
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("confirm")
    c.add_argument("request")
    c.add_argument("typed")
    c.add_argument("--catalog", default=None)
    k = sub.add_parser("check-id")
    k.add_argument("id")
    args = ap.parse_args(argv)
    if args.cmd == "check-id":
        if valid_id(args.id):
            return 0
        print(f"✗ REQUEST={args.id!r}: not a request id (r-<YYYYMMDDTHHMMSSZ>-<6 hex>)", file=sys.stderr)
        return 1
    from eregion_core.exercise_plan import load_catalog
    try:
        request = load(args.request)
    except RequestRefused as e:
        print(f"✗ request refused: {e} — nothing is sent", file=sys.stderr)
        return 1
    typed = confirm(request, load_catalog(args.catalog))
    if typed is None:
        return 1
    fd = os.open(args.typed, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(typed, f)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
