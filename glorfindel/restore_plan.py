"""A restore asks for its moment (SEC4c, #275): the recovery point restored is the newest one
from before the attack began, and the operator says when that was.

`proposed_moment` fills the field the console, the bot and the TUI show: the moment the
runs/ channel gives for this VM (an exercise's attack_started, `signal_origin.attack_moment`),
else the card's first detection — the attack began before it, the operator can go back.
`points_before` lists, read only, the recovery points from before that moment. The command
then runs with `--before` (`restore_args`). Nothing here writes.
"""
from __future__ import annotations

from datetime import datetime, timezone


def parse_moment(text) -> str:
    """`text` as an ISO 8601 moment in UTC (no offset: UTC). Raises ValueError otherwise."""
    if not isinstance(text, str) or not text.strip():
        raise ValueError("aucun moment donné")
    try:
        dt = datetime.fromisoformat(text.strip().replace("Z", "+00:00"))
    except ValueError:
        raise ValueError(f"{text[:60]!r} : pas un instant ISO 8601 "
                         "(ex. 2026-05-24T13:44:00+00:00)") from None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat()


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


def exercise_moment(resource_id: str, runs_dir="runs") -> tuple[str, str]:
    """(ISO moment, why) from the attack_started of this VM the runs/ channel admits — bounded
    by the VM's isolation when it is isolated — or ("", "")."""
    from glorfindel.signal_origin import attack_moment
    isolated_at, _ = isolation_time(resource_id)
    found = attack_moment(resource_id, runs_dir=runs_dir, isolated_at=isolated_at)
    if not found:
        return "", ""
    at, source = found
    return (datetime.fromtimestamp(at, tz=timezone.utc).isoformat(),
            f"début de l'attaque sur cette VM : attack_started de runs/{source}")


def proposed_moment(resource_id: str, esc: dict | None = None, runs_dir="runs") -> dict:
    """What the restore field is filled with: {"before", "source", "why"}.

    source "exercise": the runs/ channel says when the attack began (an exercise);
    "card": the card's first detection — the attack began before, go back if needed;
    "": nothing says when — the operator gives it."""
    before, why = exercise_moment(resource_id, runs_dir=runs_dir)
    if before:
        return {"before": before, "source": "exercise", "why": why}
    first = str((esc or {}).get("first_seen") or (esc or {}).get("timestamp") or "")
    try:
        before = parse_moment(first)
    except ValueError:
        before = ""
    if before:
        return {"before": before, "source": "card",
                "why": ("première détection de la carte : l'attaque a commencé avant — "
                        "reculer si elle a commencé plus tôt")}
    _, isolated = isolation_time(resource_id)
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
