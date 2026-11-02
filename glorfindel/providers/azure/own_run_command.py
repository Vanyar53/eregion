"""Glorfindel's own identity, watched (SID1, #409): a Run Command under its identity that is
not the session drain of an isolation it decided on that VM is a critical card.

Why. The response role (« Eregion Glorfindel Response ») holds
`Microsoft.Compute/virtualMachines/runCommand/action`: an isolation cuts the sessions already
open with `ss -K`, through Run Command (isolation.py, `drain_connections`) — a NSG does not cut
an established connection. On a host, that identity is one managed identity shared by the
watch, the console and the bot: a container taken over could run a command, as root, on any VM
the role reaches. Rather than take the right away (the isolation would leave sessions open),
the Activity Log is read for it: its use outside a drain is said, at once, to a human.

What is read. The shipped rule `run-command-by-glorfindel-outside-isolation` (azure_activity)
keeps every Run Command of the hour, one row per operation, with the time of its first line
(`Started`), and projects `WatchedCaller = "glorfindel"`: it watches Glorfindel's identity only
— another caller's row is dropped here (a client's own rule on Run Command, without that
column, keeps every caller). Glorfindel's row is dropped only when it is the drain of an
isolation Glorfindel recorded on that VM: the isolation state names the VM, and records the
time each drain was started (`drains_at`, isolation.py); the operation started within
[drain − DRAIN_BEFORE_S, drain + DRAIN_AFTER_S]; and that drain was not already taken by
another operation — one drain, one Run Command. Else the row is kept and marked
`GlorfindelRunCommand` with the reason, critical:
  - `no_isolation`: no isolation of Glorfindel is recorded on that VM;
  - `outside_drain`: an isolation is recorded, but no drain at that time (or its drain already
    matched another operation);
  - `state_unreadable`: the isolation states, or that VM's, can't be read (A0: never dropped on
    an unknown);
  - `time_unreadable`: the operation's time can't be read;
  - `identity_unknown`: Glorfindel's identity could not be read — under a rule that watches it
    only, no row can be told Glorfindel's or not: each one is kept (A0).

Decided by the code (`_control_plane_decision`, glorfindel/agent.py), like every AL1 row: no
model, no action, never one click — the VM named is not what is compromised first: the host
of Glorfindel may be. The drains seen are kept RECORDED_TTL_S after the state is gone (a
release within minutes, the row later); a restart forgets them, and a drain that ran before
it, seen after, is a card.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone

RUN_COMMAND = "microsoft.compute/virtualmachines/runcommand/action"
# The drain's time is taken just before its call: the operation's first line comes after it
# — DRAIN_BEFORE_S is for the clocks of the host and of Azure. Its last line, when the first
# is missing, comes at most 300 s later (the drain waits that long, `result(timeout=300)`).
DRAIN_BEFORE_S = 120.0
DRAIN_AFTER_S = 300.0 + DRAIN_BEFORE_S
# The column a rule projects to watch Glorfindel's identity only, and its value.
SCOPE_COLUMN = "WatchedCaller"
SCOPE_GLORFINDEL = "glorfindel"
# The column the kept row gains: why it is a card.
MARK = "GlorfindelRunCommand"
# How many drains an isolation state keeps (a VM isolated again and again).
DRAINS_KEPT = 20

REASONS = {
    "no_isolation": "aucune isolation de Glorfindel n'est enregistrée sur cette VM",
    "outside_drain": ("une isolation est enregistrée sur cette VM, mais aucune coupure des sessions "
                      "à cette heure (ou sa coupure correspond déjà à une autre commande)"),
    "state_unreadable": "l'état d'isolation est illisible : la commande ne peut être rattachée à une isolation",
    "time_unreadable": "l'heure de l'opération est illisible : elle ne peut être rattachée à une isolation",
    "identity_unknown": ("l'identité de Glorfindel n'a pas pu être lue : rien ne peut être écarté "
                         "comme sa propre coupure des sessions"),
}

_FRACTION = re.compile(r"(\.\d{6})\d+")


def epoch(value) -> float | None:
    """A time read from a row or a state (ISO 8601, a datetime), in seconds; None if unreadable.
    Log Analytics writes seven digits of a second: Python reads six."""
    if isinstance(value, datetime):
        dt = value
    elif isinstance(value, str) and value.strip():
        try:
            dt = datetime.fromisoformat(_FRACTION.sub(r"\1", value.strip().replace("Z", "+00:00")))
        except ValueError:
            return None
    else:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()


def is_run_command(op: str) -> bool:
    return op == RUN_COMMAND


def watches_glorfindel_only(row: dict) -> bool:
    return str(row.get(SCOPE_COLUMN) or "").strip().lower() == SCOPE_GLORFINDEL


def started(row: dict) -> float | None:
    """When the operation started: its first line (`Started`), else the row's time."""
    for col in ("Started", "TimeGenerated"):
        if (at := epoch(row.get(col))) is not None:
            return at
    return None


def operation_key(row: dict) -> str:
    """What makes an operation one: its CorrelationId (its lines Start, Success share it)."""
    return str(row.get("CorrelationId") or f"{row.get('_ResourceId')}@{row.get('TimeGenerated')}")


def recorded_drains(state: dict) -> list[float]:
    """The drains an isolation state records, as times (an unreadable one left out)."""
    raw = state.get("drains_at")
    times = raw if isinstance(raw, list) else []
    return [t for t in (epoch(x) for x in times) if t is not None]


@dataclass
class DrainBook:
    """The drains Glorfindel ran: by VM id (lowercase), their times; the VMs with an isolation
    state read now (`isolated`; None: the states could not be read); and which operation took
    each drain (`taken`, kept across polls by the detector)."""
    times: dict[str, list[float]] = field(default_factory=dict)
    isolated: frozenset[str] | None = frozenset()
    taken: dict[tuple[str, float], str] = field(default_factory=dict)


def read_book() -> DrainBook:
    """The drains the active isolation states record, now."""
    try:
        from glorfindel.response.state import active_isolations
        states = active_isolations()
    except Exception:
        return DrainBook(isolated=None)
    times: dict[str, list[float]] = {}
    for st in states:
        rid = str(st.get("resource_id") or "").rstrip("/").lower()
        if rid:
            times.setdefault(rid, []).extend(recorded_drains(st))
    return DrainBook(times=times, isolated=frozenset(times))


def _state_unreadable(rid: str) -> bool:
    try:
        from glorfindel.response.state import _isolation_unreadable
        return _isolation_unreadable(rid)
    except Exception:
        return True


def attach(row: dict, rid: str, book: DrainBook) -> str | None:
    """None: the row is the drain of an isolation Glorfindel recorded on this VM (that drain is
    then taken by it); else why it is not."""
    at = started(row)
    if at is None:
        return "time_unreadable"
    key = operation_key(row)
    for t in sorted(book.times.get(rid, [])):
        if t - DRAIN_BEFORE_S <= at <= t + DRAIN_AFTER_S and book.taken.get((rid, t), key) == key:
            book.taken[(rid, t)] = key
            return None
    if book.isolated is None or _state_unreadable(rid):
        return "state_unreadable"
    if rid not in book.isolated:
        return "no_isolation"
    return "outside_drain"


def mark(row: dict, op: str, rid: str, known: bool, mine: bool, book) -> str | None:
    """For one row: "" — not a Run Command of this module (another operation; another caller
    under a client's rule); None — dropped (Glorfindel's drain, or another caller under a rule
    that watches Glorfindel only); else the reason it is a card. `book` is called once, when
    needed (a DrainBook, or a function that returns one)."""
    if not is_run_command(op):
        return ""
    only = watches_glorfindel_only(row)
    if not known:
        return "identity_unknown" if only else ""
    if not mine:
        return None if only else ""
    return attach(row, rid.rstrip("/").lower(), book() if callable(book) else book)


def describe(row: dict) -> tuple[str, list[str]]:
    """What the card says, and the steps for a human."""
    reason = str(row.get(MARK) or "")
    vm = str(row.get("_ResourceId") or row.get("ResourceId") or "?").rstrip("/").rsplit("/", 1)[-1]
    who = ("l'identité de Glorfindel" if reason != "identity_unknown"
           else "une identité (celle de Glorfindel n'a pu être lue)")
    what = (f" {who[0].upper()}{who[1:]} a lancé une commande sur {vm} par Run Command hors d'une "
            f"isolation qu'il a décidée : {REASONS.get(reason, reason)}. Ce n'est pas d'abord la VM "
            "qui est en cause : l'hôte de Glorfindel l'est peut-être (son identité est partagée par la "
            "watch, la console et le bot). Aucune action sur la VM. Glorfindel lance aussi Run Command "
            "avant un `glorfindel restore` (la dernière commande neutralisée) : si un restore de cette "
            "VM a été lancé à cette heure sous cette identité, c'est lui.")
    steps = [
        f"Lire ce que la commande a lancé sur {vm} (le modèle de la VM, `az vm run-command`, ou le "
        "journal de l'agent : /var/log/azure/run-command-handler/handler.log).",
        "Vérifier l'hôte de Glorfindel : ses conteneurs, leurs journaux, qui y a eu accès.",
        "Si la commande n'est pas expliquée : retirer à l'identité de Glorfindel le droit "
        "runCommand le temps de l'enquête, et renouveler ses identifiants.",
    ]
    return what, steps
