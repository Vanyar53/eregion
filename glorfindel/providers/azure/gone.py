"""A VM gone, and its NICs with it: what is left to know of them — the NICs its local records
name, a state of its that can't be read — and their rules looked for on every NSG of the
subscription (I7S, #303), for the release and the unblock (I5R) (moved from release.py, I3V).
"""
from __future__ import annotations

from glorfindel.providers.azure.nsg import _rule_name
from glorfindel.providers.azure.turned import _turned_guard
from glorfindel.providers.azure.sdk import _is_not_found
from glorfindel.response.ids import _parse_nsg_resource_id, _same_id
from glorfindel.response.policy import _ERR_MAX, _first_line
from glorfindel.response.state import _isolation_unreadable


# What the gone-VM helpers say, for the act they serve: the release, or the unblock (I5R).
_GONE_WORDS = {"isolation": ("levée", "l'isolation", "isolée"), "block": ("déblocage", "le blocage", "bloquée")}


class GoneVmMixin:
    """_known_nics, _gone_vm_unknown, _gone_nic_check, _gone_vm_rules (part of AzureConnector)."""

    @staticmethod
    def _known_nics(resource_id: str, state: dict) -> list[str]:
        """The NICs this VM's local records name: its isolation's placements, its
        blocks', those a failed release kept — what is left to know of them once the VM
        is gone (I7S, #303)."""
        from glorfindel.response.state import _load_block_entries
        blocks = _load_block_entries(resource_id)
        entries = [state, *(blocks if isinstance(blocks, list) else [])]
        ids = {(p.get("nic_id") or "").rstrip("/"): None for e in entries if isinstance(e, dict)
               for p in (e.get("placements") or []) if isinstance(p, dict)}
        kept = state.get("known_nics") if isinstance(state, dict) else None
        ids.update({n.rstrip("/"): None for n in (kept if isinstance(kept, list) else []) if isinstance(n, str)})
        return [n for n in ids if n]

    @staticmethod
    def _gone_vm_unknown(vm_ref: str, vm_name: str, act: str = "isolation") -> list[str]:
        """The VM gone, a state of its that can't be read (isolation or block) may name
        NICs the release can't look for: never `released`, the file kept (I7S, review —
        the release cleared the only file that named the NIC, its rules left). `act`:
        "block" for the unblock (I5R)."""
        from glorfindel.response.state import (_BLOCK_STATE_DIR, _ISOLATION_STATE_DIR, _state_file,
                                               unreadable_states)
        block = _state_file(_BLOCK_STATE_DIR, vm_ref)
        if _isolation_unreadable(vm_ref) or (
                block is not None and f"{_BLOCK_STATE_DIR.name}/{block.name}" in unreadable_states()):
            named = ", ".join(f"{d.name}/{f.name}" for d, f in (
                (_ISOLATION_STATE_DIR, _state_file(_ISOLATION_STATE_DIR, vm_ref)), (_BLOCK_STATE_DIR, block))
                if f is not None and f"{d.name}/{f.name}" in unreadable_states())
            return [f"{vm_name} supprimée, état illisible ({named}) : ses cartes inconnues, "
                    f"{_GONE_WORDS[act][0]} non vérifiée"]
        return []

    def _gone_nic_check(self, resource_id: str, vm_name: str, nid: str, act: str = "isolation") -> str | None:
        """Whether the rules named for this NIC of a gone VM may be looked for: None if
        so — the NIC gone too (a 404), detached, or on a VM of another name (the names
        carry `vm_name`). A NIC Azure kept (`az vm delete` and Terraform detach it by
        default) attached since to another VM of that name: its isolation has the same
        names — they stay, and that is said; as is a NIC that can't be read (I7S, review;
        A3's "Azure says 404", extended). `act`: "block" for the unblock — a block of
        that VM's has the same names too (I5R)."""
        from glorfindel.response.ids import _parse_nic_resource_id
        verb, held, state = _GONE_WORDS[act]
        short = nid.rsplit("/", 1)[-1]
        try:
            nic = self._network.network_interfaces.get(*_parse_nic_resource_id(nid))
        except Exception as exc:
            if _is_not_found(exc):
                return None
            return f"{vm_name} supprimée : carte {short} illisible ({_first_line(exc)[:_ERR_MAX]}), {verb} non vérifiée"
        holder = (getattr(getattr(nic, "virtual_machine", None), "id", None) or "").rstrip("/")
        if (not holder or holder.rsplit("/", 1)[-1].lower() != vm_name.lower()
                or (resource_id and _same_id(holder, resource_id))):
            return None
        return (f"{vm_name} supprimée : sa carte {short} est maintenant celle de {holder.split('/')[4]}/"
                f"{vm_name}, dont {held} porte les mêmes noms — laissés ; si elle n'est pas {state} "
                "(glorfindel status), ce sont ceux de la VM supprimée : à retirer à la main "
                "(az network nsg rule delete)")

    def _gone_vm_rules(self, resource_id: str, vm_name: str, nic_ids: list[str], stuck: set,
                       act: str = "isolation", prefix: str = "glorfindel-iso",
                       deleted: list | None = None) -> list[str]:
        """The VM is gone, and the NSGs its NICs carried with it out of sight: the rules
        named for its NICs (their hash: no other NIC's, _nic_owns) are looked for on every
        NSG of the subscription. One an isolation left there whose state was lost since
        (a crash, the state rewritten by a later isolation that went elsewhere) stayed
        on a shared NSG, aimed at an address Azure hands to the next VM — "released"
        (I7S, #303). A listing that fails is said: nothing found is not nothing there.
        Only the current hashed names: an older one (before L24, VM-suffixed) is shared
        by homonyms, and on a NSG that is not read through a NIC, nothing tells whose (I2).
        The unblock's too (I5R): `act` "block", `prefix` the block's, the rules it takes
        off added to `deleted`."""
        names: set[str] = set()
        failed: list[str] = []
        for nid in nic_ids:
            why = self._gone_nic_check(resource_id, vm_name, nid, act)
            if why:
                failed.append(why)
                continue
            names |= {n for b in self._placement_rule_bases(prefix, vm_name, nid.rsplit("/", 1)[-1], nid)
                      for n in (b, f"{b}-out")}
        if not names:
            return failed
        try:
            nsgs = list(self._network.network_security_groups.list_all())
            held_back = _turned_guard(self._network, nsgs)      # I5Q: a deny no turned rule waits behind
        except Exception as exc:
            return failed + [f"{vm_name} supprimée : les règles de ses cartes n'ont pas été cherchées sur les "
                             f"NSG de l'abonnement (liste illisible : {_first_line(exc)[:_ERR_MAX]}), "
                             f"{_GONE_WORDS[act][0]} non vérifiée"]
        for nsg in nsgs:
            n_rg, n_name = _parse_nsg_resource_id(nsg.id)
            for r in (getattr(nsg, "security_rules", None) or []):
                name = _rule_name(r)
                if name.lower() in names and (n_rg.lower(), n_name.lower(), name.lower()) not in stuck:
                    if why := held_back(nsg, r):
                        failed.append(f"{name} ({n_name}) gardée : {why}")
                        continue
                    err = self._delete_rule(n_rg, n_name, name)
                    if err:
                        failed.append(err)
                    elif deleted is not None:
                        deleted.append(name)
        return failed
