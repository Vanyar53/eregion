"""A VM's own isolation state that can't be read (I3U, #440): what it may still name — the
quarantine NSG a partial release left its NICs' rules on (`quarantines_left`, I3R), its
placements, an older version's record — is unknown, never "nothing" (A0). The release,
`reset --from-azure` and the release's verification say it and never claim done; the file
is kept as it is (SEC4b), for the operator to repair or remove, then the release runs again.
"""
from __future__ import annotations

from glorfindel.response import state as _state


def _own_unread(vm_ref: str, unverified: str, said=()) -> list[str]:
    """The failure to say when this VM's isolation state file is there and can't be read,
    else []. Said once: a failure that already names the file (a gone VM's, I7S; a NIC's
    StateUnreadable) stands for it. `unverified`: « levée non vérifiée », « reset non vérifié »."""
    if not _state._isolation_unreadable(vm_ref):
        return []
    name = f"{_state._ISOLATION_STATE_DIR.name}/{_state._state_file(_state._ISOLATION_STATE_DIR, vm_ref).name}"
    if any(name in s for s in said):
        return []
    return [f"état local illisible ({name}) : ce qu'il nomme encore (un NSG de quarantaine quitté, des "
            f"placements) n'a pas été cherché, {unverified} — le réparer"
            ", ou le retirer à la main après avoir cherché les règles glorfindel-iso de ses cartes, "
            "puis relancer"]
