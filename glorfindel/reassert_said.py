"""What a block card of the reassertion says, from Azure's reading (out of reassert.py, I3P):
what is gone, and NIC by NIC what still holds — the perimeter included — what is open,
and what couldn't be read.
"""
from __future__ import annotations


def _block_drift(ip: str, vm: str, v: dict, again: bool = False, said: bool = False) -> str:
    """What a block's verification says is gone, and what still holds (RB1). Never « n'est
    plus bloquée » of an IP our perimeter (or the quarantine) still cuts off, nor of a NIC
    whose perimeter couldn't be read: that is said as unknown. `said`: the tail of a card
    whose head is already written (after a re-application).

    No NIC open nor unknown (I3P, #366): the IP is not said « plus bloquée » of the whole VM —
    where the perimeter holds, it « reste bloquée » (its own rules gone or passed by an
    allow, said beside it); NICs that couldn't be read — or whose own rules couldn't — it is
    not known, by name."""
    gone = [str(n) for n in (v.get("missing_rules") or v.get("held_missing") or [])]
    names = f" ({', '.join(gone)})" if gone else ""
    held, open_, unsure = (v.get("held_by_perimeter") or [], v.get("open_nics") or [],
                           v.get("perimeter_unread") or [])
    unknown = v.get("nics_unknown") or []        # their own rules unread: never left unsaid (I3P, review)
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
    if open_:
        tail = f"l'IP n'est plus bloquée sur {', '.join(open_)}"
    elif unsure or unknown:
        tail = f"on ne sait pas si l'IP est encore bloquée sur {', '.join(unsure + unknown)}"
        unsure, unknown = [], []
    elif held:
        tail = f"l'IP reste bloquée sur {', '.join(held)}{by}" + (
            ", ses propres règles contournées (carte à part)" if v.get("shadowed_by") else "")
        held = []
    elif v.get("nics_unread"):
        tail = f"on ne sait pas si l'IP est encore bloquée : cartes illisibles ({v['nics_unread']})"
    else:
        tail = "l'IP n'est plus bloquée"
    tail += f" ; elle l'est encore sur {', '.join(held)}{by}" if held else ""
    tail += (f" ; sur {', '.join(unsure)}, son blocage ne tient plus et la règle de périmètre n'a pas pu être lue"
             if unsure else "")
    tail += f" ; sur {', '.join(unknown)}, ses règles n'ont pas pu être lues" if unknown else ""
    return head + tail + (f"{names}." if said else ".")
