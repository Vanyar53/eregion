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

Only MISSING rules are put back. A bypass (an allow before the deny) is said, once per
change, never fixed (reassert_cards, V-16); an unreadable rule list, neither.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from glorfindel.reassert_cards import (
    drift_over, drift_said, episode, new_pass, say_bypass, say_left, say_unreadable_states,
)
from glorfindel.reassert_quarantine import _report_altered_quarantines

log = logging.getLogger(__name__)


def _missing(verification: dict) -> bool:
    """Rules gone: the check fails on them — or holds only thanks to the quarantine while
    the block's own rules are gone (`held_missing`, A0)."""
    return (verification.get("verified") is False and bool(
        verification.get("uncovered_nics") or verification.get("missing_rules"))) or bool(
        verification.get("verified") is True and verification.get("held_missing"))


def _alert_id(vm: str, rid: str, ip: str = "") -> str:
    """One card per VM (and IP), keyed by the resource id too: keyed by name, an alert
    about `web` in one group closed the card of its homonym in another, which then stayed
    "already alerted" with no card at all (A0, invariant machine)."""
    from glorfindel.actions import _rid_hash
    return f"reassert-{vm}-{_rid_hash(rid)}" + (f"-{ip}" if ip else "")


def _alert(signal_id: str, **kwargs) -> None:
    """Record a reassert alert as a NEW card. The escalation store merges a re-fire into
    the pending card of the same action/resource/type and keeps its text: the second
    removal ("no longer isolated, not re-applied") was folded into the first card, which
    still said "re-applied once", and no notification went out (validation, 06/10).
    A card of the former name-only key is replaced too, when it is this VM's."""
    from glorfindel import escalations
    rid = (kwargs.get("resource_id") or "").rstrip("/").lower()
    ip = (kwargs.get("action_params") or {}).get("ip", "")
    vm = rid.rsplit("/", 1)[-1]
    legacy = f"reassert-{vm}" + (f"-{ip}" if ip else "")
    for e in escalations.pending():
        same_vm = (e.get("resource_id") or "").rstrip("/").lower() == rid
        if e.get("signal_id") == signal_id or (same_vm and (e.get("signal_id") or "").lower() == legacy):
            # Glorfindel's closure, with its note: never read as acknowledged (L2C, review).
            escalations.resolve(e["id"], note="Remplacée : une nouvelle alerte de réaffirmation la suit.")
    escalations.record(signal_id=signal_id, escalation_type="verification_failed", **kwargs)
    new_pass()


def _who_changed(connector, iso: dict) -> str:   # who wrote its NICs lately, best effort
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
        episode(vm, "", over=False)


def _mode(autonomy, vm_name: str, ref: str = "") -> str:
    """The EFFECTIVE mode: a VM held by its readiness (L6) gets an alert, not a re-application."""
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

    new_pass()
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
        except OSError as exc:
            # Its state not written (a full disk): the others are still read — a pass cut
            # off at the first VM never saw the next one held again (L2C, review).
            log.warning("reassert: %s not recorded (%s)", snapshot["vm_name"], exc)
    for snapshot in active_blocks():
        if not snapshot.get("resource_id"):
            continue
        try:
            with _vm_lock(snapshot["vm_name"], timeout=_LOCK_WAIT_S):
                _reassert_block(connector, autonomy, snapshot["vm_name"], snapshot.get("ip", ""), report,
                                ref=snapshot["resource_id"])
        except TimeoutError:
            continue
        except OSError as exc:
            log.warning("reassert: block on %s not recorded (%s)", snapshot["vm_name"], exc)
    _whatever_the_state(connector, autonomy, report)
    return report


def reassert_pass(connector, autonomy=None) -> list[dict]:
    """One pass of the watch's reassertion (every GLORFINDEL_REASSERT_INTERVAL_S): the
    recorded isolations and blocks when there are some — a cheap local read, no Azure
    call for them when there are none — then, whatever the local state says, our
    quarantine NSGs (I1F: the case they are read for is a state lost, and a card raised
    must close after the last release too) and the orphan rules (A3: a VM given a
    deleted VM's address is freed, or said, within the minute — discovery on or off)."""
    from glorfindel.actions import active_blocks, active_isolations
    new_pass()
    if active_isolations() or active_blocks():
        return reassert_active(connector, autonomy)
    report: list[dict] = []
    _whatever_the_state(connector, autonomy, report)
    return report


def _whatever_the_state(connector, autonomy, report: list[dict]) -> None:
    """The checks of every pass, after the isolations (which may have put a quarantine
    back): one listing of the NSGs for both, read after those writes. Listing failed →
    each lists for itself, and says it can't."""
    from glorfindel.orphans import sweep_orphan_rules
    say_unreadable_states(report)             # what it can't read, said (SEC4b)
    nsgs = None
    lister = getattr(connector, "nsg_listing", None)
    if lister is not None and getattr(connector, "dry_run", False) is not True:
        try:
            nsgs = lister()
            nsgs = nsgs if isinstance(nsgs, list) else None
        except Exception as exc:
            log.warning("reassert: NSGs not listed (%s)", exc)
    _report_altered_quarantines(connector, report, nsgs)
    sweep_orphan_rules(connector, autonomy, report, nsgs)


_LOCK_WAIT_S = 30
_STALE_MARKER_S = 1800


def _held_by_an_operation(state: dict, failed_key: str, running_key: str) -> bool:   # whoever started it
    return bool(state.get("partial") or state.get(failed_key) or state.get(running_key))


def _stale(marker: str | None) -> bool:
    """An intent marker older than 30 min: the release/unblock was cut off, nobody finishes it (Q10)."""
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
        _alert(_alert_id(vm, rid), resource_id=rid, action="isolate_vm", reason=reason)
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
    say_bypass(vm, rid, verification, report, ref=ref)
    if verification.get("verified") is True:
        state = _load_isolation_state(ref or vm)
        if state is not None:
            # Back in place: a later disappearance is a new episode, alerted again — also
            # when the mark can't be taken off (L2C, review).
            if state.get("drift_alerted_at"):
                episode(ref or vm, "", over=True)
            state.pop("drift_alerted_at", None)
            _save_isolation_state(ref or vm, {**state, "verified_at": now})
            episode(ref or vm, "", over=False)
        return
    if not _missing(verification):
        if verification.get("verified") is False and iso.get("drift_alerted_at"):
            drift_over(ref or vm)                # its rules back, an allow passes them (L2C, review)
        return
    if iso.get("drift_alerted_at") and drift_said(ref or vm, "", _alert_id(vm, rid)):
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
        _alert(_alert_id(vm, rid), resource_id=rid, action="isolate_vm", reason=reason)
        _mark_alerted(ref or vm, now)
        report.append({"kind": "isolation", "vm": vm, "outcome": "escalated", "detail": reason})
        return
    try:
        put = connector.isolate_vm(rid)
        state = _load_isolation_state(ref or vm) or {}
        # Keep the original isolation time (TTL); record the re-application.
        _save_isolation_state(ref or vm, {**state, "isolated_at": iso.get("isolated_at", state.get("isolated_at")),
                                   "reasserted_at": now})
        reason = (f"L'isolation de {vm} avait disparu d'Azure (modification hors "
                  "Glorfindel) : reposée une fois. Si elle disparaît encore, "
                  "Glorfindel alertera sans la reposer." + who
                  # I4B: what the rewrite left as it was, aimed at another VM — on the card.
                  + (f" {put['left_note']}" if isinstance(put, dict) and put.get("left_note") else ""))
        outcome = "reapplied"
    except Exception as exc:
        reason = f"L'isolation de {vm} a disparu d'Azure ; la reposer a échoué : {exc}"
        outcome = "failed"
    _alert(_alert_id(vm, rid), resource_id=rid, action="isolate_vm", reason=reason)
    if outcome == "failed":
        # No retry-and-alert every minute — marked AFTER the card exists (see blocks).
        _mark_alerted(ref or vm, now)
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
    say_left(vm, rid, ip, b, report, ref)     # what the block left, aimed at another VM (I4A)
    if _stale(b.get("unblocking_at")) and not b.get("stale_alerted_at"):
        reason = (f"Le déblocage de {ip} sur {vm} a été interrompu (commencé le "
                  f"{b['unblocking_at']}) : des règles peuvent rester. Relancer "
                  f"`glorfindel unblock {ip} {rid} --yes`, ou re-bloquer.")
        _alert(_alert_id(vm, rid, ip), resource_id=rid, action="block_suspicious_ip",
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
    say_bypass(vm, rid, verification, report, ip=ip, ref=ref)
    if verification.get("verified") is True and not verification.get("held_missing"):
        if b.get("drift_alerted_at"):
            episode(ref or vm, ip, over=True)           # the mark may fail to go (L2C, review)
        _update_block_entry(ref or vm, ip, verified_at=now, drift_alerted_at=None, uncovered_said=None)
        episode(ref or vm, ip, over=False)
        return
    if verification.get("uncovered_nics") and not verification.get("missing_rules"):
        # Never covered, not gone: a perimeter block alone on a VM with a NIC on another
        # subnet. Said once per set of NICs, nothing written — putting the perimeter back
        # covers nothing more (RB1, second review). Its own mark, never `drift_alerted_at`:
        # acknowledged, the card silenced the pair's later disappearance for ever (RB1,
        # third review). The pair whole again, a drift episode before is over.
        nics = sorted(verification["uncovered_nics"])
        if b.get("uncovered_said") != nics:
            reason = (f"Le blocage de périmètre de {ip} ne couvre pas {', '.join(nics)} de {vm} : non couverte(s) "
                      f"depuis le blocage (autre subnet), l'IP les atteint. Bloquer aussi la VM (scope vm) : "
                      f"`glorfindel block {ip} {rid}`.")
            _alert(_alert_id(vm, rid, ip), resource_id=rid, action="block_suspicious_ip",
                   reason=reason, action_params={"ip": ip})
            report.append({"kind": "block", "vm": vm, "ip": ip, "outcome": "escalated", "detail": reason})
        if b.get("uncovered_said") != nics or b.get("drift_alerted_at"):
            if b.get("drift_alerted_at"):
                episode(ref or vm, ip, over=True)
            _update_block_entry(ref or vm, ip, uncovered_said=nics, drift_alerted_at=None)
            episode(ref or vm, ip, over=False)
        return
    if not _missing(verification):
        if verification.get("verified") is False and b.get("drift_alerted_at"):
            drift_over(ref or vm, ip)            # its rules back, an allow passes them (L2C, review)
        return
    said = verification
    if (b.get("drift_alerted_at") and not _worse(b.get("drift_said"), _situation(verification))
            and drift_said(ref or vm, ip, _alert_id(vm, rid, ip))):
        # One alert per disappearance (see isolations) — but said again when it worsens: a
        # NIC held turned open or unknown, a rule more gone. Acknowledged, a card « reste
        # bloquée » silenced the perimeter's deletion that opened the VM (RB1, 4th review).
        return
    if b.get("reasserted_at") or _mode(autonomy, vm, ref) == "human_only":
        reason = (_block_drift(ip, vm, verification, again=bool(b.get("reasserted_at")))
                  + f" Glorfindel ne le repose pas : `glorfindel unblock {ip} {rid} --yes` si c'est voulu, "
                  "sinon re-bloquer.")
        _alert(_alert_id(vm, rid, ip), resource_id=rid, action="block_suspicious_ip",
               reason=reason, action_params={"ip": ip})
        _update_block_entry(ref or vm, ip, drift_alerted_at=now, drift_said=_situation(said))
        episode(ref or vm, ip, over=False)
        report.append({"kind": "block", "vm": vm, "ip": ip, "outcome": "escalated", "detail": reason})
        return
    # A merged entry (RB1): its perimeter AND its VM's placements, each put back — the
    # perimeter alone left a VM rule turned into an allow as it was.
    scopes = (["subnet", "vm"] if b.get("placements") else ["subnet"]) if b.get("scoped") is False else ["vm"]
    errors: list[str] = []
    for scope in scopes:
        try:
            connector.block_suspicious_ip(ip, rid, scope=scope, threat_port=b.get("threat_port"))
        except Exception as exc:
            errors.append(f"{exc}" if len(scopes) == 1 else f"{_SCOPE_WORDS[scope]} : {exc}")
    if len(errors) < len(scopes):
        _update_block_entry(ref or vm, ip, reasserted_at=now)
        # Said from Azure read again, never from the writes alone (A0): « reposé » only
        # for a block that holds whole.
        try:
            after = connector.verify_block_ip(ip, rid)
        except Exception as exc:
            after = {"verified": None, "error": f"relecture impossible : {exc}"}
        # A write that failed is never « reposé », whatever the reading says: an unreadable
        # perimeter read as whole, and the error was swallowed (RB1, review).
        if after.get("verified") is True and not after.get("held_missing") and not errors:
            reason = (f"Le blocage de {ip} sur {vm} avait disparu d'Azure : reposé une fois. "
                      "S'il disparaît encore, Glorfindel alertera sans le reposer.")
            outcome = "reapplied"
        else:
            say_bypass(vm, rid, after, report, ip=ip, ref=ref)
            said = after
            reason = (f"Le blocage de {ip} sur {vm} avait disparu d'Azure ; ses règles réécrites une fois"
                      + (f" (échec : {' ; '.join(errors)})" if errors else "")
                      + ", il ne tient pas en entier — " + _block_drift(ip, vm, after, said=True)
                      + f" Glorfindel ne les réécrit pas de nouveau : `glorfindel unblock {ip} {rid} --yes` si "
                      "c'est voulu, sinon re-bloquer.")
            outcome = "partial"
    else:
        reason = f"Le blocage de {ip} sur {vm} a disparu d'Azure ; le reposer a échoué : {' ; '.join(errors)}"
        outcome = "failed"
    _alert(_alert_id(vm, rid, ip), resource_id=rid, action="block_suspicious_ip",
           reason=reason, action_params={"ip": ip})
    if outcome != "reapplied":
        # "Already alerted" is written only once the card exists. Written before it, a
        # crash in between (or a full disk on the card) left the marker without the
        # card: every later pass returned on the marker, and the block stayed gone in
        # silence (L1F, invariant machine).
        _update_block_entry(ref or vm, ip, drift_alerted_at=now, drift_said=_situation(said))
        episode(ref or vm, ip, over=False)
    report.append({"kind": "block", "vm": vm, "ip": ip, "outcome": outcome, "detail": reason})


_SCOPE_WORDS = {"subnet": "règle de périmètre", "vm": "règles de la VM"}


def _situation(v: dict) -> dict:
    """What a block card said (RB1, 4th review): the rules gone, the NICs still held, open,
    unknown, whether the IP stayed blocked — kept in the entry to tell a worse one."""
    return {"gone": sorted({str(n) for n in (v.get("missing_rules") or []) + (v.get("held_missing") or [])}),
            "held": sorted(v.get("held_by_perimeter") or []), "open": sorted(v.get("open_nics") or []),
            "unsure": sorted(v.get("perimeter_unread") or []), "blocked": v.get("verified") is True}


def _worse(said, now: dict) -> bool:
    """Worse than what the card said: blocked no more, a rule more gone, a NIC more open or
    unknown. Better or the same: nothing said again. No record (an older entry): as before."""
    if not isinstance(said, dict):
        return False
    return bool((said.get("blocked") and not now["blocked"])
                or set(now["gone"]) - set(said.get("gone") or [])
                or set(now["open"]) - set(said.get("open") or [])
                or set(now["unsure"]) - set(said.get("unsure") or []) - set(said.get("open") or []))


def _block_drift(ip: str, vm: str, v: dict, again: bool = False, said: bool = False) -> str:
    """What a block's verification says is gone, and what still holds (RB1). Never « n'est
    plus bloquée » of an IP our perimeter (or the quarantine) still cuts off, nor of a NIC
    whose perimeter couldn't be read: that is said as unknown. `said`: the tail of a card
    whose head is already written (after a re-application)."""
    gone = [str(n) for n in (v.get("missing_rules") or v.get("held_missing") or [])]
    names = f" ({', '.join(gone)})" if gone else ""
    held, open_, unsure = (v.get("held_by_perimeter") or [], v.get("open_nics") or [],
                           v.get("perimeter_unread") or [])
    by = f" par la règle de périmètre {v.get('perimeter_rule')}" if held else ""
    twice = " une deuxième fois" if again else ""
    if v.get("verified") is True:
        where = f" sur {', '.join(held)}{by}" if held else ""
        if said:
            return (f"l'IP reste bloquée{where}, mais il manque toujours{names}." if gone else
                    "Azure le relit entier, mais une écriture a échoué : à vérifier.")
        return f"Le blocage de {ip} sur {vm} a disparu d'Azure en partie{twice}{names} — l'IP reste bloquée{where}."
    if v.get("verified") is None or (v.get("shadowed_by") and not gone):
        what = ("contourné : une règle d'autorisation d'un tiers passe avant (carte à part)"
                if v.get("shadowed_by") else f"non vérifiable ({v.get('error') or 'illisible'})")
        return (what + ".") if said else f"Le blocage de {ip} sur {vm} a disparu d'Azure{twice} — {what}."
    head = "" if said else f"Le blocage de {ip} sur {vm} a disparu d'Azure{twice}{names} — "
    if open_ or not unsure:
        tail = "l'IP n'est plus bloquée" + (f" sur {', '.join(open_)}" if open_ else "")
    else:
        tail = f"on ne sait pas si l'IP est encore bloquée sur {', '.join(unsure)}"
        unsure = []
    tail += f" ; elle l'est encore sur {', '.join(held)}{by}" if held else ""
    tail += (f" ; sur {', '.join(unsure)}, ses règles ont disparu et la règle de périmètre n'a pas pu être lue"
             if unsure else "")
    return head + tail + (f"{names}." if said else ".")


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
