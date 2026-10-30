"""What the reassertion says without acting on it (SEC4b): an isolation or a block that an
allow of someone else's passes before (V-16), and a local state it can't read.

Neither is fixed by putting rules back. A bypass is a rule someone else wrote, evaluated
before our deny: Glorfindel never removes it (I2) — it says it, on a card of its own type,
once per change (not at every pass), and the card closes once the isolation or the block
holds again. A state file that can't be read may hold anything: the readers that would
conclude "nothing" from it stop (SEC3, SEC4b) — the card says which file, and why the
operations that need it wait.
"""
from __future__ import annotations

import hashlib
import logging

log = logging.getLogger(__name__)

BYPASS_TYPE = "bypassed"
_BYPASS_ACTION = "review_bypass"
_BYPASS_PREFIX = "reassert-bypass-"
STATE_TYPE = "state_unreadable"
_STATE_ACTION = "repair_local_state"
_STATE_PREFIX = "state-unreadable-"
_STATE_RESOURCE = "~/.glorfindel"


def _digest(parts) -> str:
    return hashlib.sha1("|".join(sorted(parts)).lower().encode()).hexdigest()[:8]


def _allow_key(f: dict) -> str:
    """One allow before our deny, as a change is told by: where, which, how."""
    return "/".join(str(f.get(k) or "") for k in ("nsg", "rule", "priority", "direction", "ports"))


def _describe(found: list[dict]) -> str:
    """As _describe_shadowing, whatever the verification left out of an entry."""
    return ", ".join(f"'{f.get('rule')}' (priorité {f.get('priority', '?')}, {f.get('direction', '?')}, "
                     f"ports {f.get('ports', '*')}" + (f", {f['nsg']}" if f.get("nsg") else "") + ")"
                     for f in found)


def _bypassing(verification: dict, ip: str) -> list[dict] | None:
    """The allows that pass before our deny, [] when it holds, None when that wasn't read
    (unknown, or rules missing: the drift card's case)."""
    if verification.get("verified") is True:
        return []
    found = verification.get("shadowed_by") if verification.get("verified") is False else None
    if not found or not isinstance(found, list):
        return None
    found = [f for f in found if isinstance(f, dict)]
    # A block: what lets the threat through (verify_block_ip's bypass); the rest is exposure.
    return [f for f in found if f.get("threat_port_open", True)] if ip else found


def say_bypass(vm: str, rid: str, verification: dict, report: list[dict], ip: str = "", ref: str = "") -> None:
    """The isolation (or, with `ip`, the block) of `vm` read as bypassed: one card, once
    per change — marked `bypass_said` in its state after the card exists (L1F) — never a
    write to Azure. Held again: the card closes, the mark goes."""
    from glorfindel import escalations
    from glorfindel.actions import (
        _load_block_entries, _load_isolation_state, _rid_hash, _save_isolation_state, _update_block_entry,
    )
    found = _bypassing(verification, ip)
    if found is None:
        return
    key = ref or vm
    if ip:
        entry = next((e for e in _load_block_entries(key) if e.get("ip") == ip), None)
        if entry is None:
            return
        mark = entry.get("bypass_said")

        def remember(sid):
            _update_block_entry(key, ip, bypass_said=sid)
    else:
        state = _load_isolation_state(key)
        if state is None:
            return
        mark = state.get("bypass_said")

        def remember(sid):
            fresh = _load_isolation_state(key)
            if fresh is not None:
                if sid is None:
                    fresh.pop("bypass_said", None)
                _save_isolation_state(key, {**fresh, **({"bypass_said": sid} if sid else {})})
    prefix = f"{_BYPASS_PREFIX}{'block' if ip else 'iso'}-{vm}-{_rid_hash(rid)}" + (f"-{ip}" if ip else "")
    cards = [e for e in escalations.pending() if (e.get("signal_id") or "").rsplit("-", 1)[0] == prefix]
    if not found:
        for e in cards:
            escalations.resolve(e["id"], note="Plus contourné : le deny de Glorfindel tient de nouveau.")
        if mark:
            remember(None)
        return
    sid = f"{prefix}-{_digest(_allow_key(f) for f in found)}"
    if mark == sid:
        return                                  # said: pending, or acknowledged
    for e in cards:
        if e.get("signal_id") != sid:
            escalations.resolve(e["id"], note="Contournement changé : une nouvelle carte le dit.")
    what = f"Le blocage de {ip} sur {vm}" if ip else f"L'isolation de {vm}"
    reason = (f"{what} est contourné{'' if ip else 'e'} : {_describe(found)} passe avant le deny "
              "de Glorfindel (NSG de la carte ou du sous-réseau). Remettre les règles n'y change rien ; "
              "Glorfindel ne retire jamais la règle d'un tiers.")
    steps = [f"Lire {', '.join(sorted({str(f.get('nsg') or '?') for f in found}))} : qui a posé "
             f"{', '.join(sorted({str(f.get('rule')) for f in found}))} (journal d'activité), et pourquoi.",
             "Si elle n'a pas lieu d'être : la retirer, ou lui donner une priorité au-delà de 999 "
             "(Glorfindel prend 100–999) ; la carte se ferme au passage suivant.",
             "Sinon : lever l'isolation ou le blocage, ou isoler autrement."]
    if not any(e.get("signal_id") == sid for e in cards):
        escalations.record(signal_id=sid, resource_id=rid, action=_BYPASS_ACTION, escalation_type=BYPASS_TYPE,
                           reason=reason, severity="high", suggested_steps=steps,
                           action_params={"ip": ip} if ip else None)
    remember(sid)
    report.append({"kind": "block" if ip else "isolation", "vm": vm, **({"ip": ip} if ip else {}),
                   "outcome": "bypassed", "detail": reason})


LEFT_TYPE = "rule_left"
_LEFT_ACTION = "review_left_rule"
_LEFT_PREFIX = "reassert-left-"


def say_left(vm: str, rid: str, ip: str, entry: dict, report: list[dict], ref: str = "") -> None:
    """A rule of this block left as it was by the block that wrote it (I4A): someone
    turned it into an allow, and it aims at an address that is no longer the VM's —
    another VM's now, or nobody knows. Rewritten, it changed that VM's flows; taken off,
    too. Said on one card per set of such rules, once (`left_said`, after the card),
    never a write."""
    from glorfindel import escalations
    from glorfindel.actions import _rid_hash, _update_block_entry
    left = [x for p in entry.get("placements") or [] for x in p.get("left") or [] if isinstance(x, dict)]
    if not left:
        return
    sid = f"{_LEFT_PREFIX}{vm}-{_rid_hash(rid)}-{ip}-" + _digest(f"{x.get('nsg')}/{x.get('rule')}" for x in left)
    if entry.get("left_said") == sid:
        return                                  # said: pending, or acknowledged
    what = " ; ".join(f"{x.get('rule')} ({x.get('nsg')}), "
                      + ("notre deny, qu'une règle à notre nom retournée attend derrière, "
                         if x.get("kind") == "deny" else "retournée en autorisation par un tiers, ")
                      + f"vise {x.get('to')}, qui est à {x.get('on')}" for x in left)
    reason = (f"Le blocage de {ip} sur {vm} a laissé telles quelles des règles à son nom qui visent une adresse "
              f"qui n'est plus celle de {vm} : {what}. Les réécrire ou les retirer changerait les flux de cette "
              f"autre VM ; le blocage de {vm} est posé sous un second nom.")
    steps = [f"Lire {', '.join(sorted({str(x.get('nsg')) for x in left}))} : qui a retourné "
             f"{', '.join(sorted({str(x.get('rule')) for x in left}))} (journal d'activité), et pourquoi.",
             "Si elle n'est plus voulue : la retirer à la main (az network nsg rule delete) ; "
             "si elle l'est, la remplacer par une règle du client, hors du nom de Glorfindel."]
    if not any(e.get("signal_id") == sid for e in escalations.pending()):
        escalations.record(signal_id=sid, resource_id=rid, action=_LEFT_ACTION, escalation_type=LEFT_TYPE,
                           reason=reason, severity="medium", suggested_steps=steps, action_params={"ip": ip})
    _update_block_entry(ref or vm, ip, left_said=sid)
    report.append({"kind": "block", "vm": vm, "ip": ip, "outcome": "escalated", "detail": reason})


def _alerts_path():
    """Beside the isolation states (~/.glorfindel/state_alerts.json): which set of
    unreadable state files was said."""
    from glorfindel import actions
    return actions._ISOLATION_STATE_DIR.parent / "state_alerts.json"


def _load_alerts() -> dict:
    import json
    try:
        data = json.loads(_alerts_path().read_text())
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _save_alerts(alerts: dict) -> None:
    import json
    from glorfindel import actions
    try:
        actions._atomic_write_text(_alerts_path(), json.dumps(alerts, sort_keys=True))
    except Exception as exc:                  # said again at the next pass: noisier, not silent
        log.warning("reassert: unreadable-state alert not recorded (%s)", exc)


def say_unreadable_states(report: list[dict]) -> None:
    """The local state files that can't be read, said on one card per set of files (once,
    acknowledged or not, while that set stands); closed once every file reads again."""
    from glorfindel import escalations
    from glorfindel import actions
    from glorfindel.actions import unreadable_states
    files = unreadable_states()
    sid = f"{_STATE_PREFIX}{_digest(files)}" if files else ""
    alerts = _load_alerts()
    cards = [e for e in escalations.pending() if (e.get("signal_id") or "").startswith(_STATE_PREFIX)]
    for e in cards:
        if e.get("signal_id") != sid:
            escalations.resolve(e["id"], note="État local lisible de nouveau, ou autres fichiers illisibles.")
    if not files:
        if alerts.pop("unreadable_states", None) is not None:
            _save_alerts(alerts)
        return
    if alerts.get("unreadable_states") == sid:
        return
    more = f" (+{len(files) - 5})" if len(files) > 5 else ""
    # What waits depends on which: a block file stops the orphan sweep only; an isolation
    # file, the release, the reset and verify_release of a NIC in quarantine or bare too.
    isolations = any(f.startswith(f"{actions._ISOLATION_STATE_DIR.name}/") for f in files)
    reason = (f"État local illisible : {', '.join(files[:5])}{more} — ce qu'il tient est inconnu. "
              "Tant qu'il l'est, la réaffirmation ne le vérifie pas et aucune règle orpheline n'est "
              "retirée" + (" ; la levée, le reset et la vérification d'une carte en quarantaine ou "
                           "sans NSG s'arrêtent : rien n'est retiré ni dit levé sur une inconnue. "
                           "Une isolation se fait quand même (son original inconnu n'est pas écrit)"
                           if isolations else "") + ".")
    aside = [f for f in files if f.startswith(f"{actions._ISOLATION_STATE_DIR.name}/{actions.ASIDE_DIR}/")]
    steps = (["Lire ces fichiers sous ~/.glorfindel/ : les réparer s'ils sont récupérables "
              "(la forme qu'écrit Glorfindel).",
              "Sinon les retirer à la main, puis relancer ce qui attendait ; `glorfindel reset "
              "--from-azure` relit Azure pour une VM dont l'état est perdu."]
             if len(aside) < len(files) else [])
    if aside:
        # Set aside when its VM's state was written since: never a state again, repaired or not.
        steps.append(f"Mis de côté ({', '.join(aside[:5])}) : un nouvel état de la VM a été écrit "
                     "depuis. Le lire, reporter à la main dans l'état courant ce qui y manque (un NSG "
                     "d'origine, un placement), puis le retirer — le réparer ne le remet pas en service.")
    if isolations:
        steps.append("Les VM isolées pendant ce temps dont une carte était sans NSG demanderont, à leur "
                     "levée, le tag glorfindel-orig-<hash> sur le NSG de quarantaine (« original "
                     "unknown » sur leur carte).")
    steps.append("La carte se ferme d'elle-même quand tout se lit de nouveau et que rien n'est mis de côté.")
    if not any(e.get("signal_id") == sid for e in cards):
        escalations.record(signal_id=sid, resource_id=_STATE_RESOURCE, action=_STATE_ACTION,
                           escalation_type=STATE_TYPE, reason=reason, severity="high", suggested_steps=steps)
    alerts["unreadable_states"] = sid
    _save_alerts(alerts)
    report.append({"kind": "state", "vm": "état local", "outcome": "escalated", "detail": reason})
