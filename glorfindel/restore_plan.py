"""A restore asks for its moment (SEC4c, #275): the recovery point restored is the newest one
from before the attack began, and the operator says when that was.

`proposed_moment` fills the field the console, the bot and the TUI show: for an exercise card,
the moment the runs/ channel gives for this VM and this run (its attack_started,
`signal_origin.attack_moment`), never after the card's first detection; else — a real incident,
or no such line — the earliest of the moments the defender itself recorded: the card's first
detection, the VM's isolation. The attack began before, the operator can go back. A line of
runs/ never gives the moment of a real incident (SEC8): whoever writes runs/ would otherwise
choose the point restored.
`points_before` lists, read only, the recovery points from before that moment. The command
then runs with `--before` (`restore_args`). Nothing here writes.
"""
from __future__ import annotations

from datetime import datetime, timezone


# A moment ahead of now is no attack's start: refused, beyond this margin (clocks drift).
FUTURE_MARGIN_S = 300


def parse_moment(text, now: float | None = None) -> str:
    """`text` as an ISO 8601 moment in UTC (no offset: UTC). Raises ValueError when it is not
    one — a year at the edge of the calendar too (`astimezone` overflows) — or when it is
    ahead of now by more than FUTURE_MARGIN_S: a restore « before » the future is a restore
    of the newest point, which the moment is there to avoid."""
    import time
    if not isinstance(text, str) or not text.strip():
        raise ValueError("aucun moment donné")
    try:
        dt = datetime.fromisoformat(text.strip().replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        dt = dt.astimezone(timezone.utc)
        epoch = dt.timestamp()
    except (ValueError, OverflowError, OSError):
        raise ValueError(f"{text[:60]!r} : pas un instant ISO 8601 "
                         "(ex. 2026-05-24T13:44:00+00:00)") from None
    now = time.time() if now is None else now
    if epoch > now + FUTURE_MARGIN_S:
        raise ValueError(f"{dt.isoformat()} est dans le futur : un instant avant le début de "
                         "l'attaque est passé")
    return dt.isoformat()


def moment_warning(resource_id: str, before: str) -> str:
    """What to say of a moment after the VM's isolation (not refused: said), or ""."""
    isolated_at, text = isolation_time(resource_id)
    try:
        after = isolated_at is not None and datetime.fromisoformat(before).timestamp() > isolated_at
    except (ValueError, OverflowError, OSError):
        return ""
    return (f"ce moment est postérieur à l'isolation de la VM ({text}) : l'attaque a commencé "
            "avant, un point pris entre les deux l'a peut-être déjà" if after else "")


def isolation_time(resource_id: str) -> tuple[float | None, str]:
    """(epoch, ISO text) of the VM's isolation in the state, or (None, "")."""
    try:
        from glorfindel.actions import _load_isolation_state
        iso = _load_isolation_state(resource_id) or {}
    except Exception:
        iso = {}
    text = str(iso.get("isolated_at") or "")
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00")).timestamp(), text
    except (TypeError, ValueError, OverflowError):
        return None, ""


def exercise_moment(resource_id: str, runs_dir="runs", run_id: str = "",
                    not_after: float | None = None) -> tuple[str, str]:
    """(ISO moment, why) from the attack_started of this VM and of run `run_id` the runs/
    channel admits — bounded by the VM's isolation when it is isolated, and by `not_after` (the
    card's first detection) — or ("", ""). No run: ("", "") — the channel is read for an
    exercise card only (SEC8)."""
    from glorfindel.signal_origin import attack_moment
    if not run_id:
        return "", ""
    isolated_at, _ = isolation_time(resource_id)
    found = attack_moment(resource_id, runs_dir=runs_dir, isolated_at=isolated_at,
                          run_id=run_id, not_after=not_after)
    if not found:
        return "", ""
    at, source = found
    return (datetime.fromtimestamp(at, tz=timezone.utc).isoformat(),
            f"début de l'exercice sur cette VM : attack_started de runs/{source}, avant la "
            "première détection de la carte")


def card_run(esc: dict | None) -> str:
    """The exercise run a card is tied to (B2: a window of that run covered its VM) — "" for a
    real card, or one that says nothing."""
    esc = esc or {}
    return str(esc.get("exercise_run") or "") if esc.get("source") == "exercise" else ""


def _first_seen(esc: dict) -> float:
    """A card's first detection, as an epoch — +inf when it says none (sorted last)."""
    try:
        return datetime.fromisoformat(parse_moment(str(esc.get("first_seen") or esc.get("timestamp") or ""))).timestamp()
    except ValueError:
        return float("inf")


def card_of(resource_id: str) -> dict | None:
    """The card a restore of this VM answers, among its pending ones: the one first detected,
    whatever it holds — its first detection is the earliest moment the defender recorded for
    the VM, safer than the restore card's own (written later) — or None. For `glorfindel
    restore` without --before."""
    from glorfindel import escalations
    want = str(resource_id or "").rstrip("/").lower()
    try:
        cards = [e for e in escalations.pending()
                 if str(e.get("resource_id") or "").rstrip("/").lower() == want]
    except Exception:            # an unreadable store: no card, the operator gives the moment
        return None
    return min(cards, key=_first_seen) if cards else None


def proposed_moment(resource_id: str, esc: dict | None = None, runs_dir="runs",
                    read_runs: bool = True) -> dict:
    """What the restore field is filled with: {"before", "source", "why"}.

    source "exercise": an exercise card, and the runs/ channel says when its run's attack on
    this VM began — never after the card's first detection; "card": the earliest of what the
    defender recorded — the card's first detection, or the VM's isolation when it came first
    (the card is written after the isolation and the autonomous snapshot) —, the attack began
    before, go back if needed; "": nothing says when — the operator gives it. A real card never
    reads runs/ (SEC8), and the why says so. `read_runs=False`: runs/ is not read (the bot,
    short of time) — and the why says « non lu », never « no line »."""
    first = str((esc or {}).get("first_seen") or (esc or {}).get("timestamp") or "")
    try:
        before = parse_moment(first)
    except ValueError:
        before = ""
    run = card_run(esc)
    if read_runs and run and before:
        found, why = exercise_moment(resource_id, runs_dir=runs_dir, run_id=run,
                                     not_after=datetime.fromisoformat(before).timestamp())
        if found:
            return {"before": found, "source": "exercise", "why": why}
    note = ((f" ; aucune ligne attack_started du run {run} admise avant elle" if read_runs else
             f" ; runs/ non lu pour le run {run} (le temps a manqué)") if run else
            " ; incident réel : aucune ligne de runs/ n'en donne le moment") if esc else ""
    isolated_at, isolated = isolation_time(resource_id)
    if before and isolated_at is not None and isolated_at < datetime.fromisoformat(before).timestamp():
        return {"before": datetime.fromtimestamp(isolated_at, tz=timezone.utc).isoformat(), "source": "card",
                "why": (f"le plus ancien des moments sûrs : isolation de la VM ({isolated}), avant la "
                        "première détection de la carte — l'attaque a commencé avant, reculer si "
                        "elle a commencé plus tôt" + note)}
    if before:
        return {"before": before, "source": "card",
                "why": ("le plus ancien des moments sûrs : première détection de la carte — "
                        "l'attaque a commencé avant, reculer si elle a commencé plus tôt" + note)}
    return {"before": "", "source": "",
            "why": "moment de l'attaque inconnu : le donner"
                   + (f" (VM isolée depuis {isolated}, l'attaque a commencé avant)" if isolated else "")}


def points_before(resource_id: str, before: str, connector=None) -> list[dict]:
    """The VM's recovery points from before `before`, newest first, read only:
    [{"name", "time", "vault_tier"}] — the first one is what the restore takes (the vault
    tier preferred, as the connector does). Raises when the vault can't be read."""
    from glorfindel.config import NO_VAULT_MSG, resolve_backup_vault
    vault, vault_rg, _ = resolve_backup_vault(None)
    if not vault:
        raise RuntimeError(NO_VAULT_MSG)
    if connector is None:
        from glorfindel.actions import AzureConnector
        connector = AzureConnector(dry_run=False)
    limit = datetime.fromisoformat(parse_moment(before))
    points = [p for p in connector.list_recovery_points(resource_id, vault=vault, vault_rg=vault_rg)
              if datetime.fromisoformat(p["time"]) < limit]
    points.sort(key=lambda p: p["time"], reverse=True)
    # A point taken after the isolation was taken during the incident: said beside it.
    isolated_at, _ = isolation_time(resource_id)
    for p in points:
        p["during_incident"] = (isolated_at is not None
                                and datetime.fromisoformat(p["time"]).timestamp() > isolated_at)
    vaulted = [p for p in points if p.get("vault_tier")]
    if vaulted:          # the one the restore takes, first
        points.remove(vaulted[0])
        points.insert(0, vaulted[0])
    return points


def restore_args(resource_id: str, before: str) -> list[str]:
    """The `glorfindel` arguments of a restore before that moment."""
    return ["restore", resource_id, "--yes", "--before", parse_moment(before)]


def failure_text(returncode: int, output: str) -> str:
    """What a refused or failed restore said, for a card: its last lines."""
    lines = [ln for ln in str(output or "").splitlines() if ln.strip()]
    tail = " ".join(ln.strip() for ln in lines[-4:]) or f"code {returncode}"
    return tail[-600:]
