"""What a block card of the reassertion says, from Azure's reading (out of reassert.py, I3P):
what is gone, and NIC by NIC what still holds — the perimeter included — what is open,
and what couldn't be read.
"""
from __future__ import annotations


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
