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
stays, or, acknowledged, stays closed; it closes once the rule is no longer an orphan.
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


def _short(ref: str) -> str:
    return (ref or "").rstrip("/").rsplit("/", 1)[-1]


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
    before = dict(alerts)
    current: set[str] = set()

    def _pending(card: str) -> bool:
        return any(e.get("id") == card for e in escalations.pending())

    # I5Q: a deny kept behind one of our rules turned into an allow is said with that rule,
    # never with its delete alone. A card said before — in human_only, before the turn, or
    # shared with another rule of the VM (the store merges by VM: its first reason stays) —
    # that doesn't name it is replaced: closed, and every rule it spoke for said again
    # below, the held ones first, so that the card the VM's rules share names the rule.
    said = {e.get("id"): (e.get("reason") or "").lower() for e in escalations.all_escalations()}
    for o in orphans:
        card = alerts.get(f"orphan-{o['nsg_id']}/{o['rule']}".lower())
        if o.get("turned") and card and o["turned"]["rule"].lower() not in said.get(card, ""):
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
            victim = _short(hit["vm_id"] or hit["nic_id"])
            reason = (f"Règle {o['rule']} ({nsg_name}) : laissée par une carte qui n'existe plus, elle "
                      f"vise {hit['ip']} — adresse de {victim} aujourd'hui, "
                      + ("qui est donc coupé(e)." if cut else
                         "que ce NSG ne gouverne pas : coupé(e) s'il passe derrière."))
        else:
            reason = (f"Règle {o['rule']} ({nsg_name}) : laissée par une carte qui n'existe plus "
                      f"(vise {', '.join(o['ips']) or '*'}). Aucune carte ne porte cette adresse aujourd'hui.")
        steps = [delete]
        if t := o.get("turned"):
            t_rg, t_name = _parse_nsg_resource_id(t["nsg_id"])
            steps = [f"Remettre {t['rule']} en refus : az network nsg rule update -g {t_rg} --nsg-name {t_name} "
                     f"-n {t['rule']} --access Deny",
                     f"Ensuite seulement, la watch retire {o['rule']} à son passage suivant (mode non_disruptive), "
                     f"ou : `{delete}` — jamais avant : la VM serait ouverte."]
        if out.get("removed") is True:
            reason += " Glorfindel l'a retirée."
        elif out:
            reason += f" Glorfindel n'a pas pu la retirer : {out.get('why') or 'échec'}."
        elif o.get("removable") is not True:
            reason += f" Gardée : {o.get('kept') or 'non retirable'}."
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
            resource_id=(hit["vm_id"] or o["nsg_id"]) if hit else o["nsg_id"],
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
        report.append({"kind": "orphan", "vm": victims[0] if victims else nsg_name,
                       "outcome": "failed" if out else "escalated", "detail": reason})
    # A rule said that is no longer an orphan (gone, or its NIC is back): its card closes.
    # The store merges the cards of one VM: a card another standing rule shares stays.
    for k in [k for k in alerts if k not in current]:
        card = alerts.pop(k)
        if card not in alerts.values() and _pending(card):
            escalations.resolve(card, note="La règle n'est plus orpheline (retirée, ou sa carte est revenue).")
    if alerts != before:
        _save_alerts(alerts)
