"""The orphan rules (seventh review, U1; A3): a Glorfindel deny left by a NIC that no
longer exists, aimed at an address Azure has handed to another VM since — that VM is cut
off by a rule nobody owns.

Every minute, in the watch's reassertion pass (reassert.py), whatever discovery does:
one card per rule; then the rule is taken off, alone, when the connector found it
removable (it cuts a live VM behind its NSG, nothing says its NIC may still exist, the VM
it cuts is not one Glorfindel isolates or blocks) AND the VM it cuts runs in
`non_disruptive` or `full_auto` — taking off a rule of ours that cuts a VM by mistake
disrupts nothing. In `human_only` the card is all: no write, it says what to run (D-A,
27/10). A rule said is not said again while it stands (orphan_alerts.json): its card
stays, or, acknowledged, stays closed; it closes once the rule is no longer an orphan. A
card says what the rule cuts — every VM, its NIC —: once that changes (an address passed
to another VM or to nobody, a second VM cut later, the NSG no longer governing the VM),
the card is replaced, the rule said again for what it cuts now (U1O). What comes is said at
once; a VM leaving it stays named until the NIC that held the address proves it left (gone,
or read without it) — a partial NIC listing never lets go of a VM still cut.
"""
from __future__ import annotations

import contextlib
import json
import logging

log = logging.getLogger(__name__)

_LOCK_WAIT_S = 30
_ALONE = ("non_disruptive", "full_auto")


def _configured_mode(autonomy, name: str) -> str:
    """The mode the operator gave the VM. Not the readiness-held one (readiness.py): that
    hold asks whether Glorfindel can isolate and release the VM safely (a backup, its
    NSG reachable) — nothing a rule of ours taken off needs; and a VM that just got a
    deleted VM's address was never checked, so it would always be held. An unreadable
    configuration (autonomy None) is human_only: the card, no write."""
    try:
        return "human_only" if autonomy is None else autonomy.resolve(name)
    except Exception:
        return "human_only"


def _alerts_path():
    """Beside the isolation states (~/.glorfindel/orphan_alerts.json): the rules said,
    each with its card."""
    from glorfindel import actions
    return actions._ISOLATION_STATE_DIR.parent / "orphan_alerts.json"


def _load_alerts() -> dict:
    try:
        data = json.loads(_alerts_path().read_text())
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _save_alerts(alerts: dict) -> None:
    from glorfindel import actions
    try:
        actions._atomic_write_text(_alerts_path(), json.dumps(alerts, sort_keys=True))
    except Exception as exc:                  # said again at the next pass: noisier, not silent
        log.warning("orphans: alerts not recorded (%s)", exc)


# Beside the cards, in orphan_alerts.json: what each rule cut when its card was said (U1O).
_SAID = "_said"


def _entry(vm: str, h: dict | None = None) -> dict:
    return {"vm": vm.lower(), "nic": (h or {}).get("nic_id") or "", "ip": (h or {}).get("ip") or ""}


def _said_of(o: dict) -> list[dict]:
    """What a card says the rule cuts (U1O review), each with the NIC at the address: every
    VM it cuts (a NIC no VM holds: its NSG); none cut, the VM at its address — `~`, its NSG
    doesn't govern it —, or `~` the NSG when nobody holds it."""
    cut = o.get("cut", o["now_on"])
    if cut:
        return [_entry(h.get("vm_id") or o["nsg_id"], h) for h in cut]
    hit = (o["now_on"] or [None])[0]
    return [_entry("~" + (hit.get("vm_id") or o["nsg_id"]), hit) if hit else _entry("~" + o["nsg_id"])]


def _valid(said) -> list[dict] | None:
    """An entry of `_said` as read back: a list of VMs (names, or entries with their NIC);
    anything else is no entry — compared as before the review (second review, P8)."""
    if not isinstance(said, list) or not said:
        return None
    out = []
    for e in said:
        if isinstance(e, str):
            e = {"vm": e}
        if not (isinstance(e, dict) and isinstance(e.get("vm"), str)
                and all(isinstance(e.get(x, ""), str) for x in ("nic", "ip"))):
            return None
        out.append({"vm": e["vm"].lower(), "nic": e.get("nic", ""), "ip": e.get("ip", "")})
    return out


def _vms(said: list[dict], nsg: str) -> set[str]:
    return {e["vm"].lstrip("~") for e in said} - {nsg.lower()}


def _proven_left(connector, e: dict, o: dict) -> bool:
    """A VM a card named left the rule's addresses — proven by its NIC only (second review):
    gone (404), read without them, or off the VM (the VM deleted, its NIC kept). A NIC the
    listing missed, a 403, a 429 prove nothing. A card said before the review recorded no
    NIC: the VM gone, or its NICs, prove it."""
    vm = e["vm"].lstrip("~")
    try:
        if e.get("nic"):
            check = getattr(connector, "nic_left_addresses", None)
            return check is not None and check(e["nic"], o["ips"], vm) is True
        check = getattr(connector, "vm_left_addresses", None)
        return check is not None and check(vm, o["ips"]) is True
    except Exception:
        return False


def _with_kept(o: dict, kept: list[dict]) -> list[dict]:
    """What the card says the rule cuts: what it cuts now, and every VM it named that left
    unproven — never let go without a proof (second review)."""
    now = _said_of(o)
    return [e for e in now if e["vm"] != "~" + o["nsg_id"].lower()] + kept if kept else now


def _kept_text(kept: list[dict]) -> str:
    return "".join(f" Elle coupait aussi {_short(e['vm'].lstrip('~'))}"
                   + (f" (carte {_short(e['nic'])})" if e.get("nic") else "") + " : non relue depuis."
                   for e in kept)


def _moved(o: dict, was: str, said: list[dict]) -> str:
    """Why a card is replaced (U1O): the rule's address passed to another VM, to nobody, or
    the VMs it cuts changed."""
    cut, res = o.get("cut", o["now_on"]), _resource(o)
    vms = _vms(said, o["nsg_id"])
    if not vms:
        return f"Remplacée : {o['rule']} vise une adresse qu'aucune carte ne porte plus (U1O)."
    if not cut and len(said) == 1:
        return f"Remplacée : {o['rule']} vise l'adresse de {_short(res)}, que ce NSG ne gouverne plus (U1O)."
    if was not in vms:
        return f"Remplacée : {o['rule']} vise une adresse passée depuis à {_short(res)} (U1O)."
    unread = vms - {(h.get("vm_id") or "").lower() for h in cut}
    named = [_who(h) for h in cut] + [_short(e["vm"]) + (f" (carte {_short(e['nic'])})" if e["nic"] else "")
                                      for e in said if e["vm"].lstrip("~") in unread]
    return f"Remplacée : {o['rule']} coupe désormais {', '.join(named)} (U1O)."


def _short(ref: str) -> str:
    return (ref or "").rstrip("/").rsplit("/", 1)[-1]


def _who(h: dict) -> str:
    """What a rule cuts, said (U1O): the VM and its NIC — the NIC alone when no VM holds it."""
    vm, nic = _short(h.get("vm_id") or ""), _short(h.get("nic_id") or "")
    return f"{vm} (carte {nic})" if vm and nic else vm or nic


def _resource(o: dict) -> str:
    """What the card of an orphan rule is about: the VM it cuts (or would), else its NSG."""
    hit = (o.get("cut", o["now_on"]) or o["now_on"] or [None])[0]
    return (hit.get("vm_id") or o["nsg_id"]) if hit else o["nsg_id"]


def _names(text: str, o: dict) -> bool:
    """The card says the turned rule this kept deny waits behind (I5Q) — by the words that
    say it, not a substring: the perimeter's name begins every VM rule of its IP."""
    return f"notre règle {o['turned']['rule']} (".lower() in text.lower()


def _put_back(t: dict) -> str:
    from glorfindel.actions import _parse_nsg_resource_id
    rg, name = _parse_nsg_resource_id(t["nsg_id"])
    return (f"Remettre {t['rule']} en refus : az network nsg rule update -g {rg} --nsg-name {name} "
            f"-n {t['rule']} --access Deny")


def _remove(connector, orphan: dict, victims: list[str]) -> dict:
    """Under the lock of each VM it cuts: an isolation or a release of that VM runs
    first, and remove_orphan_rule reads the state again after it."""
    from glorfindel.actions import _vm_lock
    try:
        with contextlib.ExitStack() as stack:
            for vm in sorted(set(victims)):
                stack.enter_context(_vm_lock(vm, timeout=_LOCK_WAIT_S))
            out = connector.remove_orphan_rule(orphan)
    except TimeoutError as exc:
        return {"removed": False, "why": f"écriture en cours ({exc}) : au prochain passage", "busy": True}
    except Exception as exc:
        return {"removed": False, "why": str(exc)}
    return out if isinstance(out, dict) else {"removed": False, "why": str(out)}


def sweep_orphan_rules(connector, autonomy=None, report: list | None = None, nsgs=None) -> list[dict]:
    """One pass over the orphan rules. `nsgs`: the NSGs the watch's pass already listed.
    Never raises; returns `report`, with one record per rule taken off or said."""
    report = report if report is not None else []
    find = getattr(connector, "find_orphan_rules", None)
    if find is None or getattr(connector, "dry_run", False) is True:
        return report
    try:
        orphans = find(nsgs=nsgs) if nsgs is not None else find()
    except Exception as exc:                  # unread: every card stays as it is
        log.warning("orphans: not checked (%s)", exc)
        return report
    if not isinstance(orphans, list):
        return report
    try:
        _sweep(connector, autonomy, orphans, report)
    except Exception as exc:
        log.warning("orphans: pass failed (%s)", exc)
    return report


def _sweep(connector, autonomy, orphans: list[dict], report: list) -> None:
    from glorfindel import escalations
    from glorfindel.actions import _parse_nsg_resource_id

    can_write = getattr(connector, "read_only", False) is False
    alerts = _load_alerts()
    before = json.dumps(alerts, sort_keys=True)
    cut_said = alerts.pop(_SAID, None)
    cut_said = cut_said if isinstance(cut_said, dict) else {}
    current: set[str] = set()

    def _pending(card: str) -> bool:
        return any(e.get("id") == card for e in escalations.pending())

    # U1O: a card is about the VM the rule cut when it was said (the store merges by VM).
    # The address it aims at may pass to another VM since — its holder's IP changed, or
    # the holder deleted, and Azure hands the address to the next NIC: the card then says
    # a VM is cut that no longer is, and the one cut now is named by none. Replaced: a
    # pending card closed and every rule it spoke for said again; an acknowledged one stays
    # closed — it was about the other VM —, the rule said again for the one it cuts now.
    # Compared: every VM the card said the rule cuts (`cut_said`) — a second VM given another
    # of its addresses later is said too (the review). A VM leaving it with no other in its
    # place needs a proof: the listing may have left its NIC out, the card is then right.
    # Second review: a VM that left unproven stays named (`kept`), whatever came in its place
    # — what comes is said at once, what leaves only on a proof by its NIC.
    about = {e.get("id"): (e.get("resource_id") or "").lower() for e in escalations.all_escalations()}
    kept: dict[str, list[dict]] = {}
    for o in orphans:
        k = f"orphan-{o['nsg_id']}/{o['rule']}".lower()
        card = alerts.get(k)
        was = _valid(cut_said.get(k))
        if was is None and card in about and about[card] != _resource(o).lower():
            was = [_entry(about[card])]        # said before the review: by the card's VM alone
        if was is None:
            continue
        left = _vms(was, o["nsg_id"]) - _vms(_said_of(o), o["nsg_id"])
        unread = {v for v in left if not all(_proven_left(connector, e, o) for e in was
                                             if e["vm"].lstrip("~") == v)}
        if unread:
            kept[k] = [e for e in was if e["vm"].lstrip("~") in unread]
            gone = ", ".join(sorted(_short(v) for v in unread))
            log.warning("orphans: %s — %s missing from the NIC listing, unproven gone: still named",
                        o["rule"], gone)
            report.append({"kind": "orphan", "vm": gone, "outcome": "unread", "detail": (
                f"Règle {o['rule']} : {gone} reste nommée — la liste des cartes réseau ne la montre plus à "
                "cette adresse, et sa carte réseau ne prouve pas qu'elle l'a quittée (droits de lecture ?).")})
    for o in orphans:
        k = f"orphan-{o['nsg_id']}/{o['rule']}".lower()
        card = alerts.get(k)
        if card not in about:
            continue
        now = _with_kept(o, kept.get(k, []))
        was = _valid(cut_said.get(k))
        if was is None:
            if about[card] == _resource(o).lower():
                cut_said[k] = now
                continue
            was = [_entry(about[card])]
        if {e["vm"] for e in was} == {e["vm"] for e in now}:
            cut_said[k] = now
            continue
        spoke_for = [k]
        if _pending(card):
            escalations.resolve(card, note=_moved(o, about[card], now))
            spoke_for = [x for x, c in alerts.items() if c == card]
        for x in spoke_for:
            del alerts[x]

    # I5Q: a deny kept behind one of our rules turned into an allow is said with that rule,
    # never with its delete alone. The store merges the cards of a VM (its first reason
    # stays): the card of the VM's kept denies names every turned rule they wait behind.
    # A card said before — in human_only, before the turn, or for another rule of the VM —
    # that doesn't name them all is replaced: closed, and every rule it spoke for said
    # again below, the kept ones first.
    group: dict[str, list[dict]] = {}
    for o in orphans:
        if o.get("turned"):
            group.setdefault(_resource(o).lower(), []).append(o)
    # A kept deny not said yet merges into the VM's pending card too (the store keeps its
    # first reason): that card is read as well (the second review of I5Q).
    said = {e.get("id"): (e.get("reason") or "").lower() for e in escalations.all_escalations()}
    pending_of: dict[str, set] = {}
    for e in escalations.pending():
        if e.get("action") == "remove_orphan_rule":
            pending_of.setdefault((e.get("resource_id") or "").lower(), set()).add(e.get("id"))
    for o in orphans:
        if not o.get("turned"):
            continue
        res = _resource(o).lower()
        for card in ({alerts.get(f"orphan-{o['nsg_id']}/{o['rule']}".lower())} | pending_of.get(res, set())) - {None}:
            if not all(_names(said.get(card, ""), g) for g in group[res]):
                if _pending(card):
                    escalations.resolve(card, note=f"Remplacée : {o['rule']} est gardée derrière "
                                                   f"{o['turned']['rule']}, retournée en autorisation (I5Q).")
                for k in [k for k, c in alerts.items() if c == card]:
                    del alerts[k]
    orphans = sorted(orphans, key=lambda o: not o.get("turned"))

    for o in orphans:
        sid = f"orphan-{o['nsg_id']}/{o['rule']}"
        k = sid.lower()
        current.add(k)
        nsg_rg, nsg_name = _parse_nsg_resource_id(o["nsg_id"])
        # `cut`: the holders this NSG governs now. A connector that doesn't say counts
        # every holder as cut.
        cut = o.get("cut", o["now_on"])
        hit = (cut or o["now_on"] or [None])[0]
        victims = [_short(h.get("vm_id") or h.get("nic_id") or "") for h in cut]
        modes = {v: _configured_mode(autonomy, v) for v in victims}
        alone = (can_write and o.get("removable") is True and bool(modes)
                 and all(m in _ALONE for m in modes.values()))
        delete = f"az network nsg rule delete -g {nsg_rg} --nsg-name {nsg_name} -n {o['rule']}"
        out: dict = {}
        if alone:
            out = _remove(connector, o, victims)
            if out.get("busy"):
                continue                          # a write on that VM: the next pass
            if out.get("removed") is True:
                card = alerts.pop(k, None)
                note = f"Règle {o['rule']} retirée par Glorfindel (A3)."
                if card and _pending(card) and card not in alerts.values():   # shared: still said (I5Q)
                    escalations.resolve(card, note=note)
                    report.append({"kind": "orphan", "vm": victims[0], "outcome": "removed", "detail": note})
                    continue
        if k in alerts:
            continue                              # said: its card pending, or acknowledged
        if hit:
            reason = (f"Règle {o['rule']} ({nsg_name}) : laissée par une carte qui n'existe plus, elle "
                      f"vise {hit['ip']} — adresse de {_who(hit)} aujourd'hui, "
                      + ("qui est donc coupé(e)." if cut else
                         "que ce NSG ne gouverne pas : coupé(e) s'il passe derrière."))
            reason += "".join(f" Elle coupe aussi {h['ip']}, adresse de {_who(h)}." for h in cut[1:])
        else:
            reason = (f"Règle {o['rule']} ({nsg_name}) : laissée par une carte qui n'existe plus "
                      f"(vise {', '.join(o['ips']) or '*'}). Aucune carte ne porte cette adresse aujourd'hui.")
        reason += _kept_text(kept.get(k, []))
        steps = [delete]
        mates = group.get(_resource(o).lower(), []) if o.get("turned") else []
        if mates:
            steps = list(dict.fromkeys(_put_back(g["turned"]) for g in mates)) + [
                f"Ensuite seulement, la watch retire {', '.join(g['rule'] for g in mates)} à son passage "
                "suivant (mode non_disruptive) — jamais avant : la VM serait ouverte."]
        if out.get("removed") is True:
            reason += " Glorfindel l'a retirée."
        elif out:
            reason += f" Glorfindel n'a pas pu la retirer : {out.get('why') or 'échec'}."
        elif o.get("removable") is not True:
            reason += f" Gardée : {o.get('kept') or 'non retirable'}."
            reason += "".join(f" Gardée aussi, {g['rule']} : {g['kept']}." for g in mates if g is not o)
        elif not can_write:
            reason += " Droits en lecture seule : Glorfindel ne la retire pas."
        else:
            held = ", ".join(f"{v} ({m})" for v, m in modes.items() if m not in _ALONE)
            reason += (f" Mode {held} : Glorfindel ne la retire pas seul — la retirer "
                       f"(`{delete}`), ou donner à la VM le mode non_disruptive : la watch la "
                       "retire alors à son passage suivant.")
            steps.append(f"Ou donner à {victims[0]} le mode non_disruptive (autonomy.assets de "
                         "glorfindel-config.yaml, ou la console) : la watch retire la règle seule.")
        card = escalations.record(
            signal_id=sid,
            resource_id=_resource(o),
            action="remove_orphan_rule",
            escalation_type="orphan_rule",
            reason=reason,
            suggested_steps=steps,
            severity="high" if cut else "medium",
        )
        if out.get("removed") is True:
            # A card of another rule of that VM, still pending, took this one in (the
            # store merges by VM): it stays open for that rule.
            if card not in alerts.values():
                escalations.resolve(card, note=f"Règle {o['rule']} retirée par Glorfindel (A3).")
            report.append({"kind": "orphan", "vm": victims[0], "outcome": "removed", "detail": reason})
            continue
        if out:
            log.warning("orphans: rule %s not removed (%s)", o["rule"], out.get("why"))
        alerts[k] = card
        cut_said[k] = _with_kept(o, kept.get(k, []))
        report.append({"kind": "orphan", "vm": victims[0] if victims else nsg_name,
                       "outcome": "failed" if out else "escalated", "detail": reason})
    # A rule said that is no longer an orphan (gone, or its NIC is back): its card closes.
    # The store merges the cards of one VM: a card another standing rule shares stays.
    for k in [k for k in alerts if k not in current]:
        card = alerts.pop(k)
        if card not in alerts.values() and _pending(card):
            escalations.resolve(card, note="La règle n'est plus orpheline (retirée, ou sa carte est revenue).")
    cuts = {k: cut_said[k] for k in alerts if k in cut_said}
    doc = {**alerts, **({_SAID: cuts} if cuts else {})}
    if json.dumps(doc, sort_keys=True) != before:
        _save_alerts(doc)
