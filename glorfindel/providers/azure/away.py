"""The isolation rules of a NIC left bare, on an NSG it no longer carries (D80, #380) —
looked for by the release's sweep, which sees only the NSGs that govern a NIC now.
"""
from __future__ import annotations

from glorfindel.providers.azure.nsg import _rule_name
from glorfindel.providers.azure.turned import _held_by_turned, _turned_guard
from glorfindel.response.ids import _parse_nsg_resource_id
from glorfindel.response.policy import _ERR_MAX, _first_line


class AwayRulesMixin:
    """_away_rules (part of AzureConnector, called by the release's sweep)."""

    def _away_rules(self, vm_name: str, targets: list[dict], stuck: set, guard: dict, mates: list) -> list[str]:
        """A NIC of the VM with no NSG of its own (taken off by someone, its quarantine
        lifted to « none »): the NSG it carried is out of the sweep's sight, and a rule of
        its isolation kept there by an earlier release (I4C: a rule someone turned into an
        allow for another VM) was forgotten with the state — a later release said
        `released` (#380). Its rules, by the NIC's hash (no other NIC's, _nic_owns), are
        looked for on every NSG of the subscription, as for a gone VM (I7S): kept by the
        guard and said « gardée », or taken off. The NSGs already swept for that NIC (its
        subnet's) are skipped. A listing that fails is said: nothing found is not nothing
        there (A0)."""
        bare = [t0 for t0 in targets if not t0.get("quarantine") and not t0.get("own_nsg_id")]
        if not bare:
            return []
        names: dict[str, tuple[dict, set]] = {}
        for t0 in bare:
            seen = {(t["nsg_rg"].lower(), t["nsg_name"].lower()) for t in self._nic_nsg_views(t0)}
            for b in self._placement_rule_bases("glorfindel-iso", vm_name, t0["nic_short"], t0["nic_id"]):
                for n in (b, f"{b}-out"):
                    names[n.lower()] = (t0, seen)
        try:
            nsgs = (list(guard["nsgs"].values()) if "nsgs" in guard
                    else list(self._network.network_security_groups.list_all()))
        except Exception as exc:
            nics = ", ".join(t0["nic_short"] for t0 in bare)
            return [f"{nics} : carte sans NSG, ses règles d'isolation non cherchées sur les NSG de l'abonnement "
                    f"(liste illisible : {_first_line(exc)[:_ERR_MAX]}), levée non vérifiée"]
        failed: list[str] = []
        for nsg in nsgs:
            n_rg, n_name = _parse_nsg_resource_id(nsg.id)
            for r in (getattr(nsg, "security_rules", None) or []):
                name = _rule_name(r)
                t0, seen = names.get(name.lower(), (None, set()))
                if (t0 is None or (n_rg.lower(), n_name.lower()) in seen
                        or (n_rg.lower(), n_name.lower(), name.lower()) in stuck):
                    continue
                if "why" not in guard:
                    # The guard reads the listing just made, not a second one (D80's review).
                    # A failure here is left to it: it lists again and says what it can't read.
                    try:
                        why = _turned_guard(self._network, nsgs)
                        guard["nsgs"] = {tuple(x.lower() for x in _parse_nsg_resource_id(n.id)): n for n in nsgs}
                        guard["why"] = why
                    except Exception:
                        pass
                err = (_held_by_turned(self._network, guard, n_rg, n_name, name, t0["nic_id"], mates)
                       or self._delete_rule(n_rg, n_name, name))
                if err:
                    failed.append(err)
        return failed
