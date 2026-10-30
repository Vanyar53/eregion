"""What the reassertion reads whatever the local state says: Glorfindel's quarantine NSGs
someone altered (I1F), said once per NSG and per change (moved from reassert.py, RB1).

A NIC whose state was lost sits in a quarantine nobody else checks: the pass reads every
quarantine NSG of the subscription, and a change that still holds NICs is a card — never a
write (without a state, nothing says which VM, nor its mode: I5).
"""
from __future__ import annotations

import logging

log = logging.getLogger("glorfindel.reassert")     # the pass's log, as before the split

_QUARANTINE_PREFIX = "reassert-quarantine-"
# Glorfindel's own closures carry a note (the console's « handled » list reads it); a card a
# human acknowledged carries none. Only the operator's word silences a change (L2Q, #331).
_CHANGED = "Le NSG de quarantaine a encore changé : une carte dit ce qu'il porte maintenant."
_SETTLED = "NSG de quarantaine entier de nouveau, vide, ou disparu de l'abonnement."
_SAID_ELSEWHERE: set[str] = set()     # cards' NSGs of another subscription, said (ISU, #264)


def _quarantine_alerts_path():
    """~/.glorfindel/quarantine_alerts.json: the change said — the `drift_alerted_at` of an NSG no state names."""
    from glorfindel import actions
    return actions._ISOLATION_STATE_DIR.parent / "quarantine_alerts.json"


def _load_quarantine_alerts() -> dict:
    import json
    try:
        data = json.loads(_quarantine_alerts_path().read_text())
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _save_quarantine_alerts(alerts: dict) -> None:
    import json
    from glorfindel import actions
    try:
        actions._atomic_write_text(_quarantine_alerts_path(), json.dumps(alerts, sort_keys=True))
    except Exception as exc:                  # said again at the next pass: noisier, not silent
        log.warning("reassert: quarantine alerts not recorded (%s)", exc)


def _report_altered_quarantines(connector, report: list[dict], nsgs: list | None = None) -> None:
    """Our quarantine NSG changed by someone, still holding NICs (I1F): said, one card
    per NSG and per change. The isolations are read from their state; a NIC whose state
    was lost (and its NSG's tags) sits in a quarantine nobody checked — a deny turned to
    Udp by hand opened it in silence. Not put back: without a state, nothing says which
    VM, nor its mode (I5). Run after the isolations, which may have put it back.

    A change said is not said again while it stands: the card stays, and once the
    operator acknowledges it, no new one comes (quarantine_alerts.json) — a new change
    of that NSG is a new card. A card closes, and its change is forgotten, once the NSG
    reads whole, holds nothing, or is gone from the subscription — read again by its id
    and not found, never only absent from the listing (I1S); never on an NSG read as
    unknown (configuration unreadable), unread, of another subscription, nor when the
    listing fails. Read again, our NSG is judged by its content, its tag or not.

    Acknowledged means the operator's word is the last on that change: the latest card of
    the NSG is this change's, closed without Glorfindel's note (`acknowledged`). The file
    alone is not enough (L2Q, #331): its write fails (a full disk) after another change was
    said, it keeps the former one, and once the diff comes back to it — a forensic access
    added then taken off, or the configuration unreadable — the NSG, still stripped, read
    « said » with no card left."""
    find = getattr(connector, "find_altered_quarantines", None)
    if find is None:
        return                                  # a provider without a quarantine NSG
    try:
        listing = find(nsgs=nsgs) if nsgs is not None else find()
    except Exception as exc:                # unread: every card stays as it is
        log.warning("reassert: quarantine NSGs not checked (%s)", exc)
        return
    if not isinstance(listing, list):
        return
    import hashlib
    from glorfindel import escalations
    from glorfindel.actions import _rid_hash

    def _key(rid) -> str:
        return (rid or "").rstrip("/").lower()

    seen = {_key(q.get("nsg_id")): q for q in listing}
    alerts = _load_quarantine_alerts()
    cards = [e for e in escalations.pending() if (e.get("signal_id") or "").startswith(_QUARANTINE_PREFIX)]
    # Absent from the listing is not gone (I1S, #231): a role removed on its group (a listing
    # that omits it without an error — a hypothesis, to measure on the bench), our tag taken
    # off. The NSG of a card (or of a change acknowledged) not listed is read again by its id,
    # before any card is touched: gone on a 404 only, anything else keeps the card. Of another
    # subscription: never read here, kept, said once (ISU, #264); a 403, at every pass.
    gone: set[str] = set()
    missing: dict[str, str] = {}
    for rid in [e.get("resource_id") or "" for e in cards] + list(alerts):
        if _key(rid) and _key(rid) not in seen:
            missing.setdefault(_key(rid), rid)
    cased = {_key(e.get("resource_id")): e.get("resource_id") for e in escalations.all_escalations()} \
        if any(rid == k for k, rid in missing.items()) else {}       # acknowledged alone: its name's case
    missing = {k: cased.get(k) or rid for k, rid in missing.items()}
    reread, outside = getattr(connector, "read_quarantine", None), getattr(connector, "outside_subscription", None)
    elsewhere = {k: w for k, rid in missing.items() if outside and isinstance(w := outside(rid), str) and w}
    for k in elsewhere.keys() - _SAID_ELSEWHERE:
        log.warning("reassert: quarantine NSG %s is in subscription %s, not the one Glorfindel reads: its "
                    "card kept, never read here (said once)", missing[k].rsplit("/", 1)[-1], elsewhere[k])
    _SAID_ELSEWHERE.intersection_update(elsewhere)
    _SAID_ELSEWHERE.update(elsewhere)
    for k, rid in ([(k, r) for k, r in missing.items() if k not in elsewhere] if reread is not None else ()):
        try:
            q = reread(rid)
        except Exception as exc:
            log.warning("reassert: quarantine NSG %s not read again (%s)", rid.rsplit("/", 1)[-1], exc)
            continue
        if q is None:
            gone.add(k)
        elif isinstance(q, dict):
            seen[k] = q
    altered: dict[str, tuple[str, dict]] = {}          # NSG → (signal id, as it reads)
    for k, q in seen.items():
        if q.get("status") == "altered" and q.get("nics"):
            change = hashlib.sha1("|".join(sorted(q.get("diff") or [])).lower().encode()).hexdigest()[:8]
            altered[k] = (f"{_QUARANTINE_PREFIX}{_rid_hash(q['nsg_id'])}-{change}", q)

    def settled(k: str) -> bool:
        """Read, and nothing to say: whole, holding nothing — or gone: read again by its
        id, not found. Unread is not settled."""
        if k in seen:
            return seen[k].get("status") != "unknown" and k not in altered
        return k in gone

    before = dict(alerts)
    said = set()
    for e in cards:
        sid = e.get("signal_id") or ""
        k = _key(e.get("resource_id"))
        if k in altered and altered[k][0] == sid:
            said.add(sid)
        elif k in altered or settled(k):
            # changed; whole again, holds nothing, gone — Glorfindel's closure, with its note
            escalations.resolve(e["id"], note=_CHANGED if k in altered else _SETTLED)
    for k in [k for k in alerts if settled(k)]:
        del alerts[k]
    history: list[dict] | None = None

    def acknowledged(k: str, signal_id: str) -> bool:
        """The latest card of this NSG is this change's, closed by the operator — not by
        Glorfindel, whose closures carry a note. Read only for a change the file says."""
        nonlocal history
        if history is None:
            history = [e for e in escalations.all_escalations()
                       if (e.get("signal_id") or "").startswith(_QUARANTINE_PREFIX)]
        last = next((e for e in reversed(history) if _key(e.get("resource_id")) == k), None)
        return (last is not None and last.get("signal_id") == signal_id
                and last.get("status") == "resolved" and not last.get("resolution"))

    for k, (signal_id, q) in altered.items():
        if signal_id in said or (alerts.get(k) == signal_id and acknowledged(k, signal_id)):
            continue                            # said: still pending, or acknowledged
        nsg_id = q.get("nsg_id") or ""
        name = nsg_id.rstrip("/").rsplit("/", 1)[-1]
        nics = ", ".join(n.rstrip("/").rsplit("/", 1)[-1] for n in q.get("nics") or [])
        reason = (f"Le NSG de quarantaine {name} ne porte plus les règles de Glorfindel "
                  f"({', '.join(q.get('diff') or [])}) — modifié hors Glorfindel, ou accès "
                  f"forensique changé dans la configuration : les cartes qu'il porte ({nics}) "
                  "peuvent ne plus être coupées de tout. Glorfindel ne le repose pas seul pour "
                  "des cartes dont il n'a pas l'état.")
        steps = [f"Vérifier les règles de {name} (glorfindel-quarantine-*) et qui les a changées "
                 "(journal d'activité).",
                 "Toute isolation dans la région les remet ; sinon les remettre à la main.",
                 f"Si l'incident est clos : lever les cartes qu'il porte ({nics}) — "
                 "`glorfindel release <vm> --yes`."]
        escalations.record(signal_id=signal_id, resource_id=nsg_id, action="restore_quarantine_nsg",
                           escalation_type="quarantine_altered", reason=reason, severity="high",
                           suggested_steps=steps)
        alerts[k] = signal_id
        report.append({"kind": "quarantine", "vm": name, "outcome": "escalated", "detail": reason})
    if alerts != before:
        _save_quarantine_alerts(alerts)
