"""The rules of a NIC left bare, on an NSG it no longer carries (D80, #380) — looked for by
the release's sweep and by `reset --from-azure`, which see only the NSGs that govern a NIC now.
"""
from __future__ import annotations

import re

from glorfindel.providers.azure.nsg import _rule_name
from glorfindel.providers.azure.turned import _held_by_turned, _turned_guard
from glorfindel.response.ids import _parse_nsg_resource_id
from glorfindel.response.policy import _ERR_MAX, _first_line

# A block's name: its IP segment, then the VM, the NIC and its hash (sweep.py reads it alike).
_BLOCK_RE = re.compile(r"^glorfindel-block-\d{1,3}(?:-\d{1,3}){3}(?:-\d{1,2})?-(?P<rest>.+?)(?:-out)?$")


class AwayRulesMixin:
    """_away_rules, _away_split (part of AzureConnector)."""

    def _away_rules(self, vm_name: str, targets: list[dict], stuck: set, guard: dict, mates: list) -> list[str]:
        """The release's (_sweep_isolation): what _away_split keeps, said; the rest taken
        off — `stuck`, the placements whose undo just failed, not tried twice."""
        said, off = self._away_split(vm_name, targets, guard, mates,
                                     lambda k, name: (*k, name.lower()) in stuck)
        return said + [err for err in (self._delete_rule(*x) for x in off) if err]

    def _away_split(self, vm_name: str, targets: list[dict], guard: dict, mates: list, skip,
                    blocks: bool = False, unverified: str = "levée non vérifiée") -> tuple[list[str], list[tuple]]:
        """A NIC of the VM with no NSG of its own (taken off by someone, its quarantine
        lifted to « none »): the NSG it carried is out of the sweep's sight, and a rule of
        its isolation kept there by an earlier release (I4C: a rule someone turned into an
        allow for another VM) was forgotten with the state — a later release said
        `released`, a reset `swept_partial` without naming it (#380). Its rules, by the NIC's
        hash (no other NIC's, _nic_owns), are looked for on every NSG of the subscription,
        as for a gone VM (I7S); its blocks' too with `blocks` (the reset). Returns what the
        guard keeps, said « gardée », and the (rg, NSG, rule) to take off. Skipped: the NSGs
        that govern the NIC (swept for it already), and what `skip(nsg_key, name)` says.
        A listing that fails is said: nothing found is not nothing there (A0)."""
        bare = [t0 for t0 in targets if not t0.get("quarantine") and not t0.get("own_nsg_id")]
        if not bare:
            return [], []
        views = {t0["nic_id"]: {(t["nsg_rg"].lower(), t["nsg_name"].lower()) for t in self._nic_nsg_views(t0)}
                 for t0 in bare}
        names: dict[str, dict] = {}
        for t0 in bare:
            for b in self._placement_rule_bases("glorfindel-iso", vm_name, t0["nic_short"], t0["nic_id"]):
                names.update({n.lower(): t0 for n in (b, f"{b}-out")})
        try:
            nsgs = (list(guard["nsgs"].values()) if "nsgs" in guard
                    else list(self._network.network_security_groups.list_all()))
        except Exception as exc:
            nics = ", ".join(t0["nic_short"] for t0 in bare)
            return [f"{nics} : carte sans NSG, ses règles non cherchées sur les NSG de l'abonnement "
                    f"(liste illisible : {_first_line(exc)[:_ERR_MAX]}), {unverified}"], []
        said: list[str] = []
        off: list[tuple] = []
        for nsg in nsgs:
            n_rg, n_name = _parse_nsg_resource_id(nsg.id)
            k = (n_rg.lower(), n_name.lower())
            for r in (getattr(nsg, "security_rules", None) or []):
                name = _rule_name(r)
                t0 = names.get(name.lower())
                if t0 is None and blocks and (m := _BLOCK_RE.match(name)):
                    t0 = next((t for t in bare if name.lower() in {
                        n for b in self._placement_rule_bases(name[: m.start("rest") - 1], vm_name, t["nic_short"],
                                                              t["nic_id"]) for n in (b, f"{b}-out")}), None)
                if t0 is None or k in views[t0["nic_id"]] or skip(k, name):
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
                why = _held_by_turned(self._network, guard, n_rg, n_name, name, t0["nic_id"], mates)
                (said.append(why) if why else off.append((n_rg, n_name, name)))
        return said, off
