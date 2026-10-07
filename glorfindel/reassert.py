"""Reassert active isolations and blocks whose rules disappeared from Azure.

A rule Glorfindel placed can vanish without Glorfindel: a `terraform apply` on an NSG
with inline rules deletes every rule absent from the code, and a person can remove one
in the portal. The local state then says ISOLATED / BLOCKED while nothing is enforced.

Every minute (GLORFINDEL_REASSERT_INTERVAL_S) the watch re-reads Azure for every
recorded isolation and block — Glorfindel must know the real state at time T, and only
the few isolated/blocked VMs are read. A check that holds records `verified_at`.
- rules all present → nothing to do;
- rules missing, first time → put them back once (outside `human_only`) and alert;
- rules missing again after that → alert only. Two removals look deliberate (a person,
  or a pipeline that will keep deleting them): Glorfindel does not fight it.

Only MISSING rules trigger this. A bypass (an allow before the deny) or an unreadable
rule list is not fixed by re-applying; verification already reports those.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone

log = logging.getLogger(__name__)


def _missing(verification: dict) -> bool:
    return verification.get("verified") is False and bool(
        verification.get("uncovered_nics") or verification.get("missing_rules"))


def _alert(signal_id: str, **kwargs) -> None:
    """Record a reassert alert as a NEW card. The escalation store merges a re-fire into
    the pending card of the same action/resource/type and keeps its text: the second
    removal ("no longer isolated, not re-applied") was folded into the first card, which
    still said "re-applied once", and no notification went out (validation, 06/10)."""
    from glorfindel import escalations
    for e in escalations.pending():
        if e.get("signal_id") == signal_id:
            escalations.resolve(e["id"])
    escalations.record(signal_id=signal_id, escalation_type="verification_failed", **kwargs)


def _who_changed(connector, iso: dict) -> str:
    """Who wrote the VM's NICs lately (activity log, best effort) — the alert says it."""
    nics = {p.get("nic_id") for p in iso.get("placements") or [] if p.get("nic_id")}
    lines = []
    for nic in sorted(nics):
        try:
            lines += connector.recent_changes(nic) or []
        except Exception:
            pass
    return (" Dernières écritures sur la carte (journal d'activité) : " + " ; ".join(lines) + ".") if lines else ""


def _mark_alerted(vm: str, now: str) -> None:
    from glorfindel.actions import _load_isolation_state, _save_isolation_state
    state = _load_isolation_state(vm)
    if state is not None:
        _save_isolation_state(vm, {**state, "drift_alerted_at": now})


def _mode(autonomy, vm_name: str, ref: str = "") -> str:
    """The EFFECTIVE mode: a VM configured autonomous but held by its readiness (L6)
    gets an alert, not a re-application."""
    try:
        if autonomy is None:
            return "human_only"
        from glorfindel.readiness import effective_mode
        return effective_mode(ref or vm_name, autonomy.resolve(vm_name))[0]
    except Exception:
        return "human_only"


def reassert_active(connector, autonomy=None) -> list[dict]:
    """Check every active isolation and block; re-apply missing rules once.

    Returns one record per isolation/block whose rules were missing:
    {"kind", "vm", "ip"?, "outcome": "reapplied" | "escalated" | "failed", "detail"}.
    """
    from glorfindel.actions import active_blocks, active_isolations, _vm_lock

    report: list[dict] = []
    for snapshot in active_isolations():
        # Under the VM's lock, from a fresh read: a release running in the War Room or
        # the CLI finishes first, and its cleared state then says there is nothing to
        # reassert. Without it, a release seen halfway was put back (third review, T2).
        # State is read by resource id: two VMs may share a name.
        try:
            with _vm_lock(snapshot["vm_name"], timeout=_LOCK_WAIT_S):
                _reassert_isolation(connector, autonomy, snapshot["vm_name"], report,
                                    ref=snapshot["resource_id"])
        except TimeoutError:
            continue          # a write is running on this VM: next pass
    for snapshot in active_blocks():
        if not snapshot.get("resource_id"):
            continue
        try:
            with _vm_lock(snapshot["vm_name"], timeout=_LOCK_WAIT_S):
                _reassert_block(connector, autonomy, snapshot["vm_name"], snapshot.get("ip", ""), report,
                                ref=snapshot["resource_id"])
        except TimeoutError:
            continue
    return report


_LOCK_WAIT_S = 30
_STALE_MARKER_S = 1800


def _held_by_an_operation(state: dict, failed_key: str, running_key: str) -> bool:
    """Partial, half-failed or in-progress work belongs to whoever started it."""
    return bool(state.get("partial") or state.get(failed_key) or state.get(running_key))


def _stale(marker: str | None) -> bool:
    """An intent marker older than 30 min: the release/unblock was cut off (War Room
    timeout, crash) and nobody is finishing it (fourth review, Q10)."""
    if not marker:
        return False
    try:
        return (datetime.now(timezone.utc) - datetime.fromisoformat(marker)).total_seconds() > _STALE_MARKER_S
    except ValueError:
        return True


def _reassert_isolation(connector, autonomy, vm: str, report: list[dict], ref: str = "") -> None:
    from glorfindel.actions import _load_isolation_state, _save_isolation_state

    now = datetime.now(timezone.utc).isoformat()
    state = _load_isolation_state(ref or vm)
    if not state or not state.get("resource_id"):
        return                # released meanwhile
    iso = {**state, "vm_name": vm}
    rid = iso["resource_id"]
    if _stale(iso.get("releasing_at")) and not iso.get("stale_alerted_at"):
        reason = (f"La levée de l'isolation de {vm} a été interrompue (commencée le "
                  f"{iso['releasing_at']}, jamais terminée) : des cartes peuvent être levées et "
                  f"d'autres encore isolées. Relancer `glorfindel release {rid} --yes`, ou "
                  "ré-isoler si la levée n'était pas voulue.")
        _alert(f"reassert-{vm}", resource_id=rid, action="isolate_vm", reason=reason)
        _save_isolation_state(ref or vm, {**state, "stale_alerted_at": now})
        report.append({"kind": "isolation", "vm": vm, "outcome": "escalated", "detail": reason})
        return
    if _held_by_an_operation(iso, "release_failed", "releasing_at"):
        return                # a release is running, or left NICs for the operator
    try:
        verification = connector.verify_isolation(rid)
    except Exception as exc:                                   # VM gone, API down
        log.warning("reassert: isolation of %s not checked (%s)", vm, exc)
        return
    if verification.get("verified") is True:
        state = _load_isolation_state(ref or vm)
        if state is not None:
            # Back in place: a later disappearance is a new episode, alerted again.
            state.pop("drift_alerted_at", None)
            _save_isolation_state(ref or vm, {**state, "verified_at": now})
        return
    if not _missing(verification):
        return
    if iso.get("drift_alerted_at"):
        # Already alerted for this disappearance: one alert per episode. Re-alerting
        # every minute flooded the webhook and undid every acknowledgement
        # (validation run, 2026-10-06).
        return
    who = _who_changed(connector, iso)
    if iso.get("reasserted_at") or _mode(autonomy, vm, ref) == "human_only":
        reason = (
            f"L'isolation de {vm} a disparu d'Azure (règles ou NSG de quarantaine retirés)"
            + (" une deuxième fois (déjà reposée le " + iso["reasserted_at"] + ")"
               if iso.get("reasserted_at") else "")
            + " — la VM n'est plus isolée. Retrait délibéré, `terraform apply`, "
            "redéploiement Bicep/ARM de la carte ? Glorfindel ne les repose pas : "
            f"`glorfindel release {rid} --yes` si la levée est voulue, sinon ré-isoler."
            + who
        )
        _alert(f"reassert-{vm}", resource_id=rid, action="isolate_vm", reason=reason)
        _mark_alerted(ref or vm, now)
        report.append({"kind": "isolation", "vm": vm, "outcome": "escalated", "detail": reason})
        return
    try:
        connector.isolate_vm(rid)
        state = _load_isolation_state(ref or vm) or {}
        # Keep the original isolation time (TTL); record the re-application.
        _save_isolation_state(ref or vm, {**state, "isolated_at": iso.get("isolated_at", state.get("isolated_at")),
                                   "reasserted_at": now})
        reason = (f"L'isolation de {vm} avait disparu d'Azure (modification hors "
                  "Glorfindel) : reposée une fois. Si elle disparaît encore, "
                  "Glorfindel alertera sans la reposer." + who)
        outcome = "reapplied"
    except Exception as exc:
        reason = f"L'isolation de {vm} a disparu d'Azure ; la reposer a échoué : {exc}"
        outcome = "failed"
        _mark_alerted(ref or vm, now)        # no retry-and-alert every minute
    _alert(f"reassert-{vm}", resource_id=rid, action="isolate_vm", reason=reason)
    report.append({"kind": "isolation", "vm": vm, "outcome": outcome, "detail": reason})


def _reassert_block(connector, autonomy, vm: str, ip: str, report: list[dict], ref: str = "") -> None:
    from glorfindel.actions import _load_block_entries, _update_block_entry

    now = datetime.now(timezone.utc).isoformat()
    b = next((e for e in _load_block_entries(ref or vm) if e.get("ip") == ip), None)
    if not b:
        return                # unblocked meanwhile
    rid = b.get("resource_id", "")
    if not rid or not ip:
        return
    if _stale(b.get("unblocking_at")) and not b.get("stale_alerted_at"):
        reason = (f"Le déblocage de {ip} sur {vm} a été interrompu (commencé le "
                  f"{b['unblocking_at']}) : des règles peuvent rester. Relancer "
                  f"`glorfindel unblock {ip} {rid} --yes`, ou re-bloquer.")
        _alert(f"reassert-{vm}-{ip}", resource_id=rid, action="block_suspicious_ip",
               reason=reason, action_params={"ip": ip})
        _update_block_entry(ref or vm, ip, stale_alerted_at=now)
        report.append({"kind": "block", "vm": vm, "ip": ip, "outcome": "escalated", "detail": reason})
        return
    if _held_by_an_operation(b, "unblock_failed", "unblocking_at"):
        return
    try:
        verification = connector.verify_block_ip(ip, rid)
    except Exception as exc:
        log.warning("reassert: block of %s on %s not checked (%s)", ip, vm, exc)
        return
    if verification.get("verified") is True:
        _update_block_entry(ref or vm, ip, verified_at=now, drift_alerted_at=None)
        return
    if not _missing(verification):
        return
    if b.get("drift_alerted_at"):
        return                      # one alert per disappearance (see isolations)
    if b.get("reasserted_at") or _mode(autonomy, vm, ref) == "human_only":
        reason = (f"Le blocage de {ip} sur {vm} a disparu d'Azure"
                  + (" une deuxième fois" if b.get("reasserted_at") else "")
                  + " — l'IP n'est plus bloquée. Glorfindel ne le repose pas : "
                  f"`glorfindel unblock {ip} {rid} --yes` si c'est voulu, sinon re-bloquer.")
        _alert(f"reassert-{vm}-{ip}", resource_id=rid, action="block_suspicious_ip",
               reason=reason, action_params={"ip": ip})
        _update_block_entry(ref or vm, ip, drift_alerted_at=now)
        report.append({"kind": "block", "vm": vm, "ip": ip, "outcome": "escalated", "detail": reason})
        return
    try:
        connector.block_suspicious_ip(
            ip, rid, scope="vm" if b.get("scoped", True) else "subnet",
            threat_port=b.get("threat_port"))
        _update_block_entry(ref or vm, ip, reasserted_at=now)
        reason = (f"Le blocage de {ip} sur {vm} avait disparu d'Azure : reposé une fois. "
                  "S'il disparaît encore, Glorfindel alertera sans le reposer.")
        outcome = "reapplied"
    except Exception as exc:
        reason = f"Le blocage de {ip} sur {vm} a disparu d'Azure ; le reposer a échoué : {exc}"
        outcome = "failed"
        _update_block_entry(ref or vm, ip, drift_alerted_at=now)
    _alert(f"reassert-{vm}-{ip}", resource_id=rid, action="block_suspicious_ip",
           reason=reason, action_params={"ip": ip})
    report.append({"kind": "block", "vm": vm, "ip": ip, "outcome": outcome, "detail": reason})



def ttl_alerts(ttl_h: float, now: datetime | None = None) -> list[dict]:
    """Isolations older than the TTL: ONE escalation each, never a release.

    The watch used to release every isolation older than GLORFINDEL_ISOLATION_TTL_H
    (4 h): no human, no autonomy mode, no release precondition — a ransomware VM
    waiting for its restore went back on the network (fourth review, Q1). The TTL now
    asks a human: release (`glorfindel release`) or keep it isolated."""
    from glorfindel import escalations
    from glorfindel.actions import _load_isolation_state, _save_isolation_state, _vm_lock, active_isolations

    now = now or datetime.now(timezone.utc)
    out: list[dict] = []
    for iso in active_isolations():
        rid, since = iso.get("resource_id", ""), iso.get("isolated_at", "")
        if not rid or not since or iso.get("ttl_alerted_at"):
            continue
        try:
            age_h = (now - datetime.fromisoformat(since)).total_seconds() / 3600
        except ValueError:
            continue
        if age_h < ttl_h:
            continue
        vm = iso["vm_name"]
        try:
            with _vm_lock(vm, timeout=5):
                state = _load_isolation_state(rid)
                if not state or state.get("ttl_alerted_at"):
                    continue
                escalations.record(
                    signal_id=f"ttl-{iso.get('state_key', vm)}", resource_id=rid,
                    action="review_isolation", escalation_type="ttl_exceeded",
                    reason=(f"{vm} est isolée depuis {age_h:.1f} h (TTL {ttl_h:g} h). Glorfindel ne "
                            "lève pas une isolation seul : vérifier la VM, puis "
                            f"`glorfindel release {rid} --yes` si elle est saine, ou la garder "
                            "isolée (restore en attente, investigation)."),
                    suggested_steps=["Vérifier l'état de la VM (restore terminé ? intégrité ?).",
                                     f"Lever : glorfindel release {rid} --yes",
                                     "Ou garder l'isolation et acquitter cette carte."])
                _save_isolation_state(rid, {**state, "ttl_alerted_at": now.isoformat()})
                out.append({"vm": vm, "age_h": age_h})
        except TimeoutError:
            continue                 # a write in progress: next pass
    return out
