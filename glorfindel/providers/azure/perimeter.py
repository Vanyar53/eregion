"""The perimeter block an entry carries next to its VM's own block (RB1): a `block` and
a `block_perimeter` of one IP share one entry (`scoped: false`). Where it covers a NIC
whose own rules are gone, the IP is still blocked there; an entry lost, the one no other
VM's entry records may have been the gone VM's.
"""
from __future__ import annotations


class PerimeterMixin:
    """The merged perimeter block (part of AzureConnector)."""

    @staticmethod
    def _merged_perimeter(entry: dict) -> tuple[str, str, str] | None:
        """(rg, NSG, rule) of the perimeter block an entry carries next to its VM's
        placements — a `block` and a `block_perimeter` of one IP share one entry
        (`scoped: false`, RB1). None for any other entry."""
        if entry.get("scoped") is not False or not entry.get("nsg") or not entry.get("rule") or "/" not in entry["nsg"]:
            return None
        rg, name = entry["nsg"].split("/", 1)
        if any((p.get("nsg_rg"), p.get("nsg_name"), p.get("rule")) == (rg, name, entry["rule"])
               for p in entry.get("placements") or []):
            return None
        return rg, name, entry["rule"]

    def _perimeter_holds(self, cache: dict, t0: dict | None, ip: str, port) -> str:
        """'holds' | 'no' | 'unknown': a perimeter block of `ip` cuts it off this NIC — the
        entry's own or another VM's of the same subnet (one rule for the whole subnet, its
        name the IP alone): on an NSG that governs the NIC now, both rules present and
        whole, no allow before them letting the threat through. One holds: it holds."""
        if t0 is None:
            return "no"
        rule, out = self._block_rule_prefix(ip), "no"
        ips = t0.get("private_ips") or None
        for v in self._nic_nsg_views(t0):
            st, _ = self._block_pair_state(cache, v["nsg_rg"], v["nsg_name"], rule, ip, None)
            if st == "present":
                found = self._shadowed_deny(cache, v["nsg_rg"], v["nsg_name"], rule, inbound_src=[ip],
                                            inbound_dst=ips, outbound_src=ips, outbound_dst=[ip], port=port)
                if found is not None and not self._threat_open(found):
                    return "holds"
                st = "unknown" if found is None else st
            out = "unknown" if st == "unknown" else out
        return out

    @staticmethod
    def _perimeters_recorded(ip: str, but: str) -> set[tuple[str, str]]:
        """(rg, NSG) of the perimeter blocks of `ip` another VM's entry records — theirs."""
        from glorfindel.response.state import active_blocks
        return {tuple(e["nsg"].lower().split("/", 1)) for e in active_blocks()
                if e.get("ip") == ip and e.get("scoped") is False and "/" in (e.get("nsg") or "")
                and (e.get("resource_id") or "").rstrip("/").lower() != but.rstrip("/").lower()}
