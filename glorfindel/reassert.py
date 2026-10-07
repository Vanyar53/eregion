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


def _mode(autonomy, vm_name: str) -> str:
    """The EFFECTIVE mode: a VM configured autonomous but held by its readiness (L6)
    gets an alert, not a re-application."""
    try:
        if autonomy is None:
            return "human_only"
        from glorfindel.readiness import effective_mode
        return effective_mode(vm_name, autonomy.resolve(vm_name))[0]
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
        with _vm_lock(snapshot["vm_name"]):
            _reassert_isolation(connector, autonomy, snapshot["vm_name"], report)
    for snapshot in active_blocks():
        with _vm_lock(snapshot["vm_name"]):
            _reassert_block(connector, autonomy, snapshot["vm_name"], snapshot.get("ip", ""), report)
    return report


def _held_by_an_operation(state: dict, failed_key: str, running_key: str) -> bool:
    """Partial, half-failed or in-progress work belongs to whoever started it."""
    return bool(state.get("partial") or state.get(failed_key) or state.get(running_key))


def _reassert_isolation(connector, autonomy, vm: str, report: list[dict]) -> None:
    from glorfindel.actions import _load_isolation_state, _save_isolation_state

    now = datetime.now(timezone.utc).isoformat()
    state = _load_isolation_state(vm)
    if not state or not state.get("resource_id"):
        return                # released meanwhile
    iso = {**state, "vm_name": vm}
    rid = iso["resource_id"]
    if _held_by_an_operation(iso, "release_failed", "releasing_at"):
        return                # a release is running, or left NICs for the operator
    try:
        verification = connector.verify_isolation(rid)
    except Exception as exc:                                   # VM gone, API down
        log.warning("reassert: isolation of %s not checked (%s)", vm, exc)
        return
    if verification.get("verified") is True:
        state = _load_isolation_state(vm)
        if state is not None:
            # Back in place: a later disappearance is a new episode, alerted again.
            state.pop("drift_alerted_at", None)
            _save_isolation_state(vm, {**state, "verified_at": now})
        return
    if not _missing(verification):
        return
    if iso.get("drift_alerted_at"):
        # Already alerted for this disappearance: one alert per episode. Re-alerting
        # every minute flooded the webhook and undid every acknowledgement
        # (validation run, 2026-10-06).
        return
    who = _who_changed(connector, iso)
    if iso.get("reasserted_at") or _mode(autonomy, vm) == "human_only":
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
        _mark_alerted(vm, now)
        report.append({"kind": "isolation", "vm": vm, "outcome": "escalated", "detail": reason})
        return
    try:
        connector.isolate_vm(rid)
        state = _load_isolation_state(vm) or {}
        # Keep the original isolation time (TTL); record the re-application.
        _save_isolation_state(vm, {**state, "isolated_at": iso.get("isolated_at", state.get("isolated_at")),
                                   "reasserted_at": now})
        reason = (f"L'isolation de {vm} avait disparu d'Azure (modification hors "
                  "Glorfindel) : reposée une fois. Si elle disparaît encore, "
                  "Glorfindel alertera sans la reposer." + who)
        outcome = "reapplied"
    except Exception as exc:
        reason = f"L'isolation de {vm} a disparu d'Azure ; la reposer a échoué : {exc}"
        outcome = "failed"
        _mark_alerted(vm, now)        # no retry-and-alert every minute
    _alert(f"reassert-{vm}", resource_id=rid, action="isolate_vm", reason=reason)
    report.append({"kind": "isolation", "vm": vm, "outcome": outcome, "detail": reason})


def _reassert_block(connector, autonomy, vm: str, ip: str, report: list[dict]) -> None:
    from glorfindel.actions import _load_block_entries, _update_block_entry

    now = datetime.now(timezone.utc).isoformat()
    b = next((e for e in _load_block_entries(vm) if e.get("ip") == ip), None)
    if not b:
        return                # unblocked meanwhile
    rid = b.get("resource_id", "")
    if not rid or not ip or _held_by_an_operation(b, "unblock_failed", "unblocking_at"):
        return
    try:
        verification = connector.verify_block_ip(ip, rid)
    except Exception as exc:
        log.warning("reassert: block of %s on %s not checked (%s)", ip, vm, exc)
        return
    if verification.get("verified") is True:
        _update_block_entry(vm, ip, verified_at=now, drift_alerted_at=None)
        return
    if not _missing(verification):
        return
    if b.get("drift_alerted_at"):
        return                      # one alert per disappearance (see isolations)
    if b.get("reasserted_at") or _mode(autonomy, vm) == "human_only":
        reason = (f"Le blocage de {ip} sur {vm} a disparu d'Azure"
                  + (" une deuxième fois" if b.get("reasserted_at") else "")
                  + " — l'IP n'est plus bloquée. Glorfindel ne le repose pas : "
                  f"`glorfindel unblock {ip} {rid} --yes` si c'est voulu, sinon re-bloquer.")
        _alert(f"reassert-{vm}-{ip}", resource_id=rid, action="block_suspicious_ip",
               reason=reason, action_params={"ip": ip})
        _update_block_entry(vm, ip, drift_alerted_at=now)
        report.append({"kind": "block", "vm": vm, "ip": ip, "outcome": "escalated", "detail": reason})
        return
    try:
        connector.block_suspicious_ip(
            ip, rid, scope="vm" if b.get("scoped", True) else "subnet",
            threat_port=b.get("threat_port"))
        _update_block_entry(vm, ip, reasserted_at=now)
        reason = (f"Le blocage de {ip} sur {vm} avait disparu d'Azure : reposé une fois. "
                  "S'il disparaît encore, Glorfindel alertera sans le reposer.")
        outcome = "reapplied"
    except Exception as exc:
        reason = f"Le blocage de {ip} sur {vm} a disparu d'Azure ; le reposer a échoué : {exc}"
        outcome = "failed"
        _update_block_entry(vm, ip, drift_alerted_at=now)
    _alert(f"reassert-{vm}-{ip}", resource_id=rid, action="block_suspicious_ip",
           reason=reason, action_params={"ip": ip})
    report.append({"kind": "block", "vm": vm, "ip": ip, "outcome": outcome, "detail": reason})

