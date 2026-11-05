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
change, never fixed (reassert_cards, V-16); an unreadable rule list, neither. A check that
raises is said on one card while it lasts, closed once it passes again (SEC13, V-16).
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from glorfindel.reassert_cards import (
    drift_baseline, drift_meet, drift_over, drift_said, episode, narrow_drift, new_pass, same_sid, say_bypass,
    say_left, say_unreadable_states, say_unverified, unrecorded, unverified_over, unverified_released,
)
from glorfindel.reassert_perimeters import put_back_perimeters
from glorfindel.reassert_quarantine import _report_altered_quarantines
from glorfindel.reassert_said import _block_drift, _situation, _worse, still_said

log = logging.getLogger(__name__)


def _missing(verification: dict) -> bool:
    """Rules gone: the check fails on them — or holds only thanks to the quarantine while
    the block's own rules are gone (`held_missing`, A0) — or fails on a bypass while some
    are gone too (`held_missing` next to `shadowed_by`: a merged perimeter's pair, I4C)."""
    return (verification.get("verified") is False and bool(
        verification.get("uncovered_nics") or verification.get("missing_rules")
        or verification.get("held_missing"))) or bool(
        verification.get("verified") is True and verification.get("held_missing"))


def _alert_id(vm: str, rid: str, ip: str = "") -> str:
    """One card per VM (and IP), keyed by the resource id too: keyed by name, an alert
    about `web` in one group closed the card of its homonym in another, which then stayed
    "already alerted" with no card at all (A0, invariant machine). The name in lowercase:
    Azure's names are case-insensitive, and the state of a VM taken up again by its lowercase
    id (Log Analytics' `_ResourceId`) names it so — the card said under its canonical name was
    neither closed nor read « said », the disappearance said again at every pass (I3C). The
    whole id, the IP too: an IPv6 written `2001:DB8::9` is the same block (I3C, review)."""
    from glorfindel.actions import _rid_hash
    return (f"reassert-{vm}-{_rid_hash(rid)}" + (f"-{ip}" if ip else "")).lower()


def _alert(signal_id: str, **kwargs) -> None:
    """Record a reassert alert as a NEW card. The escalation store merges a re-fire into
    the pending card of the same action/resource/type and keeps its text: the second
    removal ("no longer isolated, not re-applied") was folded into the first card, which
    still said "re-applied once", and no notification went out (validation, 06/10).
    A card of the former name-only key is replaced too, when it is this VM's — and one said
    under another case of its name (`same_sid`, I3C).

    Replaced in the write of the new card, never before it (L1A, #480): closed first, the new
    card refused (a full disk) left none — the mark kept from before read « said », and a
    pass that could not check the block again said nothing. Refused, the old card still
    waits, and the OSError reaches the pass: the mark is not written (L1F)."""
    from glorfindel import escalations
    rid = (kwargs.get("resource_id") or "").rstrip("/").lower()
    ip = (kwargs.get("action_params") or {}).get("ip", "")
    vm = rid.rsplit("/", 1)[-1]
    legacy = (f"reassert-{vm}" + (f"-{ip}" if ip else "")).lower()      # an IPv6 in capitals too (I3G)
    # Glorfindel's closure, with its note: never read as acknowledged (L2C, review).
    replaced = {e["id"]: "Remplacée : une nouvelle alerte de réaffirmation la suit." for e in escalations.pending()
                if same_sid(e.get("signal_id"), signal_id) or (
                    (e.get("resource_id") or "").rstrip("/").lower() == rid
                    and (e.get("signal_id") or "").lower() == legacy)}
    try:
        escalations.record(signal_id=signal_id, escalation_type="verification_failed", replaces=replaced, **kwargs)
    finally:
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


def _perimeters_first(blocks: list[dict]) -> list[dict]:
    """The blocks that hold a perimeter (an entry `scoped: False`, merged or not) before the
    VM blocks, each group in its own order. A perimeter put back covers every VM of its
    subnet: a VM block read before it, its rules rewritten, said « n'est plus bloquée » of
    NICs the perimeter cut off again a moment later in the same pass — a card false once
    the pass ended (L1Qr, seed 6). Read after, the VM block sees the pair as it is. The
    files' order (a directory listing) decided it before."""
    return sorted(blocks, key=lambda b: b.get("scoped") is not False)


def reassert_active(connector, autonomy=None) -> list[dict]:
    """Check every active isolation and block; re-apply missing rules once.

    Returns one record per isolation/block whose rules were missing:
    {"kind", "vm", "ip"?, "outcome": "reapplied" | "escalated" | "partial" | "failed", "detail"}.
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
            # Its state not written (a full disk): said, and the others still read — a pass
            # cut off at the first VM never saw the next one held again (L2C, review).
            report.append(unrecorded(snapshot["vm_name"], exc))
    blocks = _perimeters_first(active_blocks())
    # Two times (L1Qs): every perimeter pair to put back, first; then each entry read and finished.
    put_back = put_back_perimeters(connector, autonomy, blocks, report)
    for snapshot in blocks:
        if not snapshot.get("resource_id"):
            continue
        try:
            with _vm_lock(snapshot["vm_name"], timeout=_LOCK_WAIT_S):
                _reassert_block(connector, autonomy, snapshot["vm_name"], snapshot.get("ip", ""), report,
                                ref=snapshot["resource_id"], put_back=put_back)
        except TimeoutError:
            continue
        except OSError as exc:
            report.append(unrecorded(snapshot["vm_name"], exc, snapshot.get("ip", "")))
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
    unverified_released()                     # a check that raised, its VM released since (V-16)
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
    except Exception as exc:                                   # VM gone, API down: said once (V-16)
        say_unverified(vm, rid, exc, report)
        return
    if verification.get("verified") is not None:
        unverified_over(vm, rid)               # it answered: the check passes again
    elif verification.get("method") != "dry_run":     # « can't tell »: said, never « passes » (A0)
        say_unverified(vm, rid, verification.get("error") or "vérification non concluante", report)
    if iso.get("drift_alerted_at") and verification.get("verified") is not None and not _missing(verification):
        episode(ref or vm, "", over=True)        # back: a new episode next time, whatever write fails
    say_bypass(vm, rid, verification, report, ref=ref)
    if verification.get("verified") is True:
        state = _load_isolation_state(ref or vm)
        if state is not None:
            # Back in place: a later disappearance is a new episode, alerted again — also
            # when the mark can't be taken off, here or in say_bypass (L2C, review).
            state.pop("drift_alerted_at", None)
            _save_isolation_state(ref or vm, {**state, "verified_at": now})
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
        # I4B: what the rewrite left as it was, aimed at another VM — on the card.
        left = f" {put['left_note']}" if isinstance(put, dict) and put.get("left_note") else ""
        short = _isolation_said(put)
        if short:
            # Written, but the provider does not read it whole (RW2, #555): never « reposée », nothing
            # promised, and not marked put back — `reasserted_at` would keep it out of the passes.
            reason = (f"L'isolation de {vm} avait disparu d'Azure ; reposée, elle ne tient pas en entier : {short}. "
                      "Glorfindel ne la repose pas de nouveau : "
                      f"`glorfindel release {rid} --yes` si la levée est voulue, sinon ré-isoler." + who + left)
            outcome = "partial"
        else:
            state = _load_isolation_state(ref or vm) or {}
            # Keep the original isolation time (TTL); record the re-application.
            _save_isolation_state(ref or vm, {**state, "isolated_at": iso.get("isolated_at", state.get("isolated_at")),
                                       "reasserted_at": now})
            reason = (f"L'isolation de {vm} avait disparu d'Azure (modification hors "
                      "Glorfindel) : reposée une fois. Si elle disparaît encore, "
                      "Glorfindel alertera sans la reposer." + who + left)
            outcome = "reapplied"
    except Exception as exc:
        reason = f"L'isolation de {vm} a disparu d'Azure ; la reposer a échoué : {exc}"
        outcome = "failed"
    _alert(_alert_id(vm, rid), resource_id=rid, action="isolate_vm", reason=reason)
    if outcome in ("partial", "failed"):
        # No retry-and-alert every minute — marked AFTER the card exists (see blocks).
        _mark_alerted(ref or vm, now)
    report.append({"kind": "isolation", "vm": vm, "outcome": outcome, "detail": reason})


def _reassert_block(connector, autonomy, vm: str, ip: str, report: list[dict], ref: str = "",
                    put_back: dict | None = None) -> None:
    from glorfindel.actions import _load_block_entries, _update_block_entry

    now = datetime.now(timezone.utc).isoformat()
    b = next((e for e in _load_block_entries(ref or vm) if e.get("ip") == ip), None)
    if not b:
        return                # unblocked meanwhile
    rid = b.get("resource_id", "")
    if not rid or not ip:
        return
    # Its pair put back by the first time (L1Qs): read by it — the same first read here (the baseline, the
    # check's card, the bypass), then finished: its VM's rules, the re-read, the card.
    pair = (put_back or {}).get((rid.rstrip("/").lower(), ip)) if b.get("scoped") is False else None
    if pair is None and b.get("scoped") is False and b.get("partial") and b.get("partial_unsaid"):
        # Its pair written partial by a first time whose second never came (its lock held, the pass
        # cut off — RW2, #555): said now, from a read of now. Held by the provider's `partial` alone,
        # no pass read it again, its card never written. Nothing more written: the mode may have
        # changed since that pass (human_only), and the card says what the read finds.
        pair = {"error": None, "partial": b["partial_unsaid"], "read": None, "later": True}
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
    # Its `partial` mark written by the first time's own write of its pair (RW1): finished here, said.
    if _held_by_an_operation({**b, "partial": False} if (pair or {}).get("partial") else b,
                             "unblock_failed", "unblocking_at"):
        return
    try:
        verification = (pair["read"] if pair is not None and pair["read"] is not None
                        else connector.verify_block_ip(ip, rid))
    except Exception as exc:                                   # said once (V-16)
        say_unverified(vm, rid, exc, report, ip=ip)
        return
    said, now_is = verification, _situation(verification)
    baseline = drift_baseline(ref or vm, ip, b.get("drift_said"))
    worse = _worse(baseline, now_is)
    never_covered = bool(verification.get("uncovered_nics") and not verification.get("missing_rules"))
    if b.get("drift_alerted_at") and _missing(verification) and not never_covered:
        # Better than its card, here, before any write of the pass: what holds is the baseline — a
        # write refused below (a full disk) left it as the card said, and the rules gone again read
        # « not worse », in silence (L1Qs, the machine). Worse on one side: what got better (L1).
        narrow_drift(ref or vm, ip, drift_meet(baseline, now_is) if worse else now_is)
    if verification.get("verified") is not None:
        unverified_over(vm, rid, ip)
    elif verification.get("method") != "dry_run":
        say_unverified(vm, rid, verification.get("error") or "vérification non concluante", report, ip=ip)
    if b.get("drift_alerted_at") and verification.get("verified") is not None and not _missing(verification):
        episode(ref or vm, ip, over=True)        # back: a new episode next time, whatever write fails
    say_bypass(vm, rid, verification, report, ip=ip, ref=ref)
    if pair is not None:
        return _rewrite_block(connector, b, vm, rid, ip, report, ref, now, verification, pair)
    if verification.get("verified") is True and not verification.get("held_missing"):
        _update_block_entry(ref or vm, ip, verified_at=now, drift_alerted_at=None, uncovered_said=None)
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
        return
    if not _missing(verification):
        if verification.get("verified") is False and b.get("drift_alerted_at"):
            drift_over(ref or vm, ip)            # its rules back, an allow passes them (L2C, review)
        return
    if still_said(b, ref or vm, ip, _alert_id(vm, rid, ip), baseline, now_is):
        # One alert per disappearance (see isolations) — but said again when it worsens: a
        # NIC held turned open or unknown, a rule more gone. Acknowledged, a card « reste
        # bloquée » silenced the perimeter's deletion that opened the VM (RB1, 4th review).
        # Better since, pending or acknowledged: what still holds is the baseline (above) — a
        # rule back, gone again, is said (L1Q). Worse on one side, better on another: what got
        # better is the baseline before the card is written — its write refused (a full disk),
        # the next return to what was said still reads worse, and is said (L1, after SEC13).
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
    _rewrite_block(connector, b, vm, rid, ip, report, ref, now, said)


def _rewrite_block(connector, b: dict, vm: str, rid: str, ip: str, report: list[dict], ref: str, now: str,
                   said: dict, pair: dict | None = None) -> None:
    """Write the entry's rules, read them again, say it — `said`, the read that decided it. `pair`:
    its perimeter pair written by the first time (L1Qs), the write's error if any: its VM's rules
    alone left to write."""
    from glorfindel.actions import _update_block_entry
    # A merged entry (RB1): its perimeter AND its VM's placements, each put back — the
    # perimeter alone left a VM rule turned into an allow as it was.
    scopes = (["subnet", "vm"] if b.get("placements") else ["subnet"]) if b.get("scoped") is False else ["vm"]
    errors: list[str] = []

    short: list[str] = []         # written, but the provider said it does not hold whole (RW1)

    def failed(scope: str, exc, into: list[str] = errors) -> None:
        into.append(f"{exc}" if len(scopes) == 1 else f"{_SCOPE_WORDS[scope]} : {exc}")
    if pair is not None and pair["error"] is not None:
        failed("subnet", pair["error"])
    if pair is not None and pair.get("partial"):
        failed("subnet", pair["partial"], short)
    scopes = scopes[:1] if (pair or {}).get("later") else scopes      # a pair of an earlier pass: nothing written (RW2)
    for scope in scopes[1:] if pair is not None else scopes:
        try:
            put = connector.block_suspicious_ip(ip, rid, scope=scope, threat_port=b.get("threat_port"))
        except Exception as exc:
            failed(scope, exc)
            continue
        # Read as it is answered, raised or not (RW1, #513): AWS's `failed` wrote nothing.
        status, why = _write_said(put)
        if status:
            failed(scope, why, errors if status == "failed" else short)
    if len(errors) < len(scopes):
        # Written again: the episode ends in the write of `reasserted_at` (L1O, #507) — over first, in
        # memory, whatever that write does. Its marks kept, the card « reposé une fois » pending read
        # « already said »: gone again before the next pass, as it was read here, in silence — yet that
        # card says « s'il disparaît encore, Glorfindel alertera ». Not whole, its card opens a new one.
        episode(ref or vm, ip, over=True)
        _update_block_entry(ref or vm, ip, reasserted_at=now, drift_alerted_at=None, drift_said=None)
        # Said from Azure read again, never from the writes alone (A0): « reposé » only
        # for a block that holds whole.
        try:
            after = connector.verify_block_ip(ip, rid)
        except Exception as exc:
            after = {"verified": None, "error": f"relecture impossible : {exc}"}
        # A write that failed is never « reposé », whatever the reading says: an unreadable
        # perimeter read as whole, and the error was swallowed (RB1, review).
        reposed = False
        if after.get("verified") is True and not after.get("held_missing") and not errors:
            reposed = not short          # the provider's word: a write it said partial is never « reposé » (RW1)
        if reposed:
            reason = (f"Le blocage de {ip} sur {vm} avait disparu d'Azure : reposé une fois. "
                      "S'il disparaît encore, Glorfindel alertera sans le reposer.")
            outcome = "reapplied"
        else:
            say_bypass(vm, rid, after, report, ip=ip, ref=ref)
            said = after
            notes = ([f"échec : {' ; '.join(errors)}"] if errors else []) + (
                [f"en partie selon le fournisseur : {' ; '.join(short)}"] if short else [])
            reason = (f"Le blocage de {ip} sur {vm} avait disparu d'Azure ; ses règles réécrites une fois"
                      + (f" ({' ; '.join(notes)})" if notes else "")
                      + ", il ne tient pas en entier — " + _block_drift(ip, vm, after, said=True, partial=not errors)
                      + f" Glorfindel ne les réécrit pas de nouveau : `glorfindel unblock {ip} {rid} --yes` si "
                      "c'est voulu, sinon re-bloquer." + _held_partial(ref or vm, ip))
            outcome = "partial"
    else:
        reason = (f"Le blocage de {ip} sur {vm} a disparu d'Azure ; le reposer a échoué : {' ; '.join(errors)}"
                  + _held_partial(ref or vm, ip))
        outcome = "failed"
    _alert(_alert_id(vm, rid, ip), resource_id=rid, action="block_suspicious_ip",
           reason=reason, action_params={"ip": ip})
    if outcome != "reapplied":
        # "Already alerted" is written only once the card exists. Written before it, a
        # crash in between (or a full disk on the card) left the marker without the
        # card: every later pass returned on the marker, and the block stayed gone in
        # silence (L1F, invariant machine).
        _update_block_entry(ref or vm, ip, drift_alerted_at=now, drift_said=_situation(said))
        if b.get("partial_unsaid"):
            # The first time's mark of a partial pair (RW2), off once its card is said. Not taken off
            # (a crash, a full disk), the card is said again at the next pass: one card too many,
            # never the silence.
            _update_block_entry(ref or vm, ip, partial_unsaid=None)
        episode(ref or vm, ip, over=False)
    report.append({"kind": "block", "vm": vm, "ip": ip, "outcome": outcome, "detail": reason})


_SCOPE_WORDS = {"subnet": "règle de périmètre", "vm": "règles de la VM"}


def _write_said(put) -> tuple[str, str]:
    """What a block's write answered without raising (RW1, #513): (`failed` | `partial` | "", why).

    AWS answers `failed` when no ACL entry can be placed, `partial` when an entry does not hold at
    its read-back — neither raises. Read as written, a `failed` made the card say « ses règles
    réécrites une fois » of rules never written, and `reasserted_at` kept it from ever being tried
    again; a `partial` left its entry marked, out of every later pass, its card unsaid or promising
    « s'il disparaît encore, Glorfindel alertera ». Azure raises instead (PartialActionError); its
    `blocked_partial` — a perimeter written, NICs of another subnet not behind it — is left to the
    re-read, which says what holds."""
    status = put.get("status") if isinstance(put, dict) else None
    if status not in ("failed", "partial"):
        return "", ""
    why = " ; ".join(
        (f"{x['acl']} : {x.get('reason')}" if x.get("acl") else f"{x.get('reason')}")
        for x in put.get("bypass") or [] if isinstance(x, dict) and x.get("reason"))
    return status, why or str(put.get("error") or f"le fournisseur répond « {status} »")


def _isolation_said(put) -> str:
    """What an isolation's write answered without raising (RW2, #555): "" when it holds, else why not.

    AWS answers `isolated` whatever its read-back found, with `verified` False (an ENI off the
    quarantine group, the group altered) or None (unreadable), and `bypass` naming them. Azure
    answers no `verified` — each deny is confirmed as it is written, a NIC left raises
    (PartialActionError) — but an allow before its deny is answered in `bypass` (`shadowed_by`):
    written, passed by. Read as written, both made the card say « reposée une fois. Si elle disparaît
    encore, Glorfindel alertera » of an isolation that does not hold, and `reasserted_at` took it out
    of every later put-back. An answer that says nothing (no dict) is read as before."""
    if not isinstance(put, dict):
        return ""
    bypass = put.get("bypass") or []
    named = ", ".join(str(x) for x in bypass) if isinstance(bypass, (list, tuple)) else str(bypass).rstrip(". ")
    verified = put.get("verified", True)
    if verified is None:
        return f"le fournisseur n'a pas pu la relire ({named or 'vérification impossible'})"
    if verified is not True:
        return f"le fournisseur ne la relit pas entière ({named or 'non vérifiée'})"
    return named


def _held_partial(ref: str, ip: str) -> str:
    """Its entry marked `partial` by the provider's write: no pass reads it again (`_held_by_an_operation`)
    until it is blocked again whole or unblocked — said so, never « Glorfindel alertera » (RW1)."""
    from glorfindel.actions import _load_block_entries
    b = next((e for e in _load_block_entries(ref) if e.get("ip") == ip), None) or {}
    return (" Noté partiel par le fournisseur : la réaffirmation ne le relit plus avant un nouveau blocage "
            "entier ou un déblocage.") if b.get("partial") else ""


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
