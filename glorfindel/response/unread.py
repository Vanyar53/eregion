"""A VM's own isolation state that can't be read (I3U, #440): what it may still name — the
quarantine NSG a partial release left its NICs' rules on (`quarantines_left`, I3R), its
placements, an older version's record — is unknown, never "nothing" (A0). The release,
`reset --from-azure` and the release's verification say it and never claim done; the file
is kept as it is (SEC4b), for the operator to repair or remove, then the release runs again.
"""
from __future__ import annotations

from glorfindel.response import state as _state


def _own_unread(vm_ref: str, unverified: str, said=(), where=None) -> list[str]:
    """The failure to say when this VM's isolation state file is there and can't be read,
    else []. `unverified`: « levée non vérifiée », « reset non vérifié ». `where` (a text, or
    a callable read only then): where a partial release may have left its NICs' rules — the
    adapter's quarantine NSG. A failure that already names the file (a gone VM's, I7S; a
    NIC's StateUnreadable) stands for the rest, never for the warning: before removing the
    file, look THERE — not on the NSGs the NICs carry now, where nothing is found, the file
    goes, and the next release says `released` with the pair still there (I3U, review)."""
    if not _state._isolation_unreadable(vm_ref):
        return []
    name = f"{_state._ISOLATION_STATE_DIR.name}/{_state._state_file(_state._ISOLATION_STATE_DIR, vm_ref).name}"
    where = (where() if callable(where) else where) or "le NSG de quarantaine de leur région"
    warn = (f"avant de le retirer à la main, chercher les règles glorfindel-iso de ses cartes sur {where} "
            "(pas sur les NSG qu'elles portent maintenant)")
    if any(name in s for s in said):
        return [f"{name} : {warn}"]
    return [f"état local illisible ({name}) : ce qu'il nomme encore (un NSG de quarantaine quitté, des "
            f"placements) n'a pas été cherché, {unverified} — le réparer, ou, {warn}, puis relancer"]
