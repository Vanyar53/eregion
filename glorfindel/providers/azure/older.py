"""The release of an older version's isolation by its record (I4E, #361): the single-NSG
state written before placements existed, or the same record a later isolation kept beside
its placements (`legacy`, glorfindel/response/legacy_state.py). Moved out of release.py,
which reaches 500 lines.
"""
from __future__ import annotations

from glorfindel.providers.azure.turned import _held_by_turned


class OlderIsolationMixin:
    """The older version's record undone (part of AzureConnector)."""

    def _own_nics(self, rg: str, vm_name: str) -> list[str]:
        """The VM's live NICs, for the guard (`mates`): a rule aimed at another NIC of the
        same VM is no other VM's. Unread: none — its own NICs count too, kept, said (A0)."""
        try:
            return [t0["nic_id"] for t0 in self._get_vm_nic_targets(rg, vm_name, allow_no_nsg=True)]
        except Exception:
            return []

    def _undo_older(self, older: dict, rg: str, vm_name: str, turned: dict) -> list[str]:
        """Take off the rules an older version's record names and put back the customer
        rules it moved, on the NSG it recorded — whatever that NSG's sharing now (its fixed
        names count only on a dedicated NSG for the sweep). Returns the failures; a rule
        the guard keeps (I4C) is one, said."""
        l_rg, l_name = older["nsg_rg"] or rg, older["nsg_name"]
        # Its deny-all may hold back one of our turned rules for a VM given this NSG and
        # an old address since: asked first, as every removal by name (I4C).
        mates = self._own_nics(rg, vm_name)
        failed: list[str] = []
        for name in older["rule_names"]:
            err = (_held_by_turned(self._network, turned, l_rg, l_name, name, "", mates)
                   or self._delete_rule(l_rg, l_name, name))
            if err:
                failed.append(err)
        left = self._restore_bumped(l_rg, l_name, older["bumped"])
        failed += [f"{l_rg}/{l_name}/{b['name']} (priorité non restaurée) : {b['error']}"
                   for b in left]
        return failed
