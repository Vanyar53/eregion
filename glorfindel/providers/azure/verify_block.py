"""verify_block_ip: a block read on Azure by content, NIC by NIC, behind the quarantine
and the perimeter too (split out of unblock.py, I4B: moved without change).
"""
from __future__ import annotations

from glorfindel.providers.azure.nsg import (_deny_blocks, _deny_slot, _describe_shadowing, _rule_name,
                                            _shadowing_rules)
from glorfindel.response.ids import _parse_vm_resource_id
from glorfindel.response.policy import _ERR_MAX, _first_line
from glorfindel.response.state import _load_block_entries


class VerifyBlockMixin:
    """Verifying IP blocks (part of AzureConnector)."""

    def verify_block_ip(self, ip: str, resource_id: str) -> dict:
        """Confirm the block is in place: the inbound AND the outbound rule of every
        placement. Checking only the inbound one let a missing `-out` rule (egress /
        C2 / exfil path still open) pass as verified."""
        if self.dry_run:
            return {"verified": True, "method": "dry_run"}
        if not ip:
            return {"verified": False, "method": "nsg_check", "error": "no IP provided"}

        self._ensure_clients()
        rg, vm_name = _parse_vm_resource_id(resource_id)
        entry = next((e for e in _load_block_entries(resource_id) if e.get("ip") == ip), None)

        # Multi-NIC VM block: every NIC must be blocked — by ONE of its placements, both
        # rules present and the threat not let through. A re-block can leave an earlier,
        # bypassed placement next to a sound one: all of them used to have to hold, and
        # the sound block read as bypassed (L24, blocks in the invariant machine).
        # Against the NICs as they are NOW: a NIC whose IP changed since the block was
        # checked against the old one and read as blocked — the new address open (L26).
        if entry and entry.get("placements"):
            port = entry.get("threat_port")
            # Unreadable NICs: a missing rule still fails the check; a block that looks
            # whole can't be confirmed against addresses that weren't read.
            current: dict | None = None
            targets: dict = {}
            nics_unread = ""
            try:
                targets = {t0["nic_id"].rstrip("/").lower(): t0
                           for t0 in self._get_vm_nic_targets(rg, vm_name, allow_no_nsg=True)}
                current = {n: t0.get("private_ips") or [] for n, t0 in targets.items()}
            except Exception as exc:
                nics_unread = _first_line(exc)[:_ERR_MAX]
            groups: dict = {}
            for p in entry["placements"]:
                nic = (p.get("nic_id") or "").rstrip("/").lower()
                if current is not None and nic and nic not in current:
                    continue                         # no longer one of the VM's NICs
                groups.setdefault(nic or tuple(p.get("ips") or []), []).append(p)
            missing, unread, bypass, exposure, unknown = [], [], [], [], []
            held_missing: list[str] = []
            cache: dict = {}
            # A perimeter block (RB1) — in the same entry, or another VM's on the subnet: a
            # NIC whose own rules are gone is still blocked where it covers it — "no longer
            # blocked" was said of an IP it still cut off. `open_nics`: what nothing of ours
            # blocks any more.
            perimeter = self._merged_perimeter(entry)
            held_by, open_nics, unsure = [], [], []

            def _lost(t0, names: list[str]) -> None:
                short = t0["nic_short"] if t0 else ""
                holds = self._perimeter_holds(cache, t0, ip, port)
                if holds == "holds":
                    held_missing.extend(names)
                    held_by.append(short)
                    return
                missing.extend(names)
                if short:
                    (unsure if holds == "unknown" else open_nics).append(short)
            if current is not None and any(p.get("nic_id") for p in entry["placements"]):
                for n in [n for n in current if n not in groups]:       # a NIC added since
                    if not self._left_to_perimeter(cache, perimeter, targets.get(n), ip, port):
                        _lost(targets.get(n), [n.rsplit("/", 1)[-1]])
            for nic, ps in groups.items():
                # Only an NSG that governs the NIC NOW blocks anything: in quarantine, the
                # NIC's own NSG — where the block lies — is off it until the release. The
                # quarantine then blocks everything, as long as it is intact; emptied, the
                # attacker went through while the block's rules read as present (L26).
                t0 = targets.get(nic) if isinstance(nic, str) else None
                if t0 is not None:
                    governing = {(v["nsg_rg"].lower(), v["nsg_name"].lower()) for v in self._nic_nsg_views(t0)}
                    off = [p for p in ps if (p["nsg_rg"].lower(), p["nsg_name"].lower()) not in governing]
                    ps = [p for p in ps if p not in off]
                    if t0.get("quarantine"):
                        q = self._quarantine_blocks(t0["quarantine"], ip, cache)
                        if q == "blocks":
                            # Blocked now, by the quarantine. The block's own rules may
                            # be gone (a `terraform apply`): said, so the reassertion puts
                            # them back or alerts BEFORE the release opens the NIC (A0).
                            own_ips = (current or {}).get(nic) or None
                            for p in ps + off:
                                st, names = self._block_pair_state(cache, p["nsg_rg"], p["nsg_name"],
                                                                   p["rule"], ip, own_ips or p.get("ips") or None)
                                if st in ("absent", "altered"):
                                    held_missing += names
                            continue
                        if q == "unknown" and not ps:
                            unread.append(f'{t0["nic_short"]}: {t0["quarantine"]["nsg_name"]}')
                            continue
                    if not ps:
                        _lost(t0, [f'{p["rule"]} ({p["nsg_name"]} ne gouverne plus {t0["nic_short"]})' for p in off])
                        continue
                now = current.get(nic) if current is not None and isinstance(nic, str) else None
                ips_of = {id(p): now if now is not None else (p.get("ips") or None) for p in ps}
                nic_missing, nic_unread, nic_bypass, nic_unknown, nic_half = [], [], [], [], []
                for p in ps:
                    st, names = self._block_pair_state(cache, p["nsg_rg"], p["nsg_name"], p["rule"],
                                                       ip, ips_of[id(p)] or None)
                    if st in ("absent", "altered"):          # altered: put back like missing
                        nic_missing += names
                        # What is left of the pair, an allow before it (L1C, #369): gone AND
                        # bypassed, both said — the bypass was never read, never carded.
                        half = self._half_bypassed(cache, p, ip, ips_of[id(p)] or None, port)
                        nic_bypass += [f for f in half if f not in nic_bypass]
                        nic_half += names if half else []
                        continue
                    if st == "unknown":
                        nic_unread += names
                        continue
                    found = self._shadowed_deny(
                        cache, p["nsg_rg"], p["nsg_name"], p["rule"],
                        inbound_src=[ip], inbound_dst=ips_of[id(p)] or None,
                        outbound_src=ips_of[id(p)] or None, outbound_dst=[ip], port=port)
                    if found is None:
                        nic_unknown.append(f'{p["nsg_rg"]}/{p["nsg_name"]}')
                    elif self._threat_open(found):
                        nic_bypass += [f for f in found if f not in nic_bypass]
                    else:
                        exposure += found
                        break                       # this NIC is blocked
                else:
                    if nic_bypass:
                        bypass += [f for f in nic_bypass if f not in bypass]
                        if nic_half:
                            # Everything gone on the NIC, not only the half pair's: another
                            # placement wholly gone was dropped — the card said less (review).
                            _lost(t0, nic_missing)
                    elif nic_unread or nic_unknown:
                        unread += nic_unread
                        unknown += [u for u in nic_unknown if u not in unknown]
                    else:
                        _lost(t0, nic_missing)
            if perimeter:                   # its own pair: gone, put back like the VM's rules
                st, names = self._block_pair_state(cache, *perimeter, ip, None)
                if st in ("absent", "altered"):
                    (missing if missing else held_missing).extend(names)
                elif st == "unknown":            # never read as there (RB1, review)
                    unread += [f"{n} ({perimeter[1]})" for n in names]
            said = {**({"held_by_perimeter": held_by, "perimeter_rule": self._block_rule_prefix(ip)} if held_by else {}),
                    **({"perimeter_unread": unsure} if unsure else {})}
            if missing:
                # A bypass goes with what is gone (L1C, #369): dropped, no bypass card was
                # ever written while a rule of the VM was missing (L1).
                return {"verified": False, "method": "nsg_check", "missing_rules": missing,
                        "open_nics": open_nics, **said, **({"shadowed_by": bypass} if bypass else {}),
                        "error": f"rules missing: {', '.join(missing)}"
                                 + (f" ; contourné : {_describe_shadowing(bypass)}" if bypass else "")}
            if bypass:
                # What is gone goes with the bypass (I4C): the merged perimeter's pair lifted
                # by another VM's unblock, the VM's own rules there but bypassed — the bypass
                # alone was said, the pair's disappearance dropped, and the reassertion,
                # finding nothing missing, neither put it back nor said so (L1).
                return {**self._block_bypassed(ip, bypass), **({"held_missing": held_missing} if held_missing else {})}
            if unread:
                return {"verified": None, "method": "nsg_check", "unreadable_rules": unread,
                        "error": "blocage non vérifiable : règles illisibles (" + ", ".join(unread) + ")"}
            if unknown:
                return self._precedence_unknown(unknown, nics_covered=len(groups))
            if nics_unread:
                return {"verified": None, "method": "nsg_check",
                        "error": f"blocage non vérifiable : cartes illisibles ({nics_unread})"}
            # Threat port blocked; other ports the attacker still reaches are reported.
            return {"verified": True, "method": "nsg_check", "nics_covered": len(groups),
                    **({"exposure": exposure} if exposure else {}),
                    **({"held_missing": held_missing} if held_missing else {}), **said}

        # Perimeter (subnet) block, or legacy single-rule entry: check the recorded pair.
        if entry and entry.get("nsg") and entry.get("rule"):
            nsg_rg, nsg_name = entry["nsg"].split("/", 1)
            pair_cache: dict = {}
            st, names = self._block_pair_state(pair_cache, nsg_rg, nsg_name, entry["rule"], ip, None)
            missing = names if st in ("absent", "altered") else []
            if st == "unknown":
                return {"verified": None, "method": "nsg_check", "unreadable_rules": names,
                        "error": "blocage non vérifiable : règles illisibles"}
            if not missing:
                # A perimeter block has no destination scope: any VM behind the NSG.
                shadowed, unknown = self._precedence([
                    (nsg_rg, nsg_name, entry["rule"],
                     {"inbound_src": [ip], "inbound_dst": None, "outbound_src": None,
                      "outbound_dst": [ip], "port": entry.get("threat_port")})
                ])
                if self._threat_open(shadowed):
                    return self._block_bypassed(ip, shadowed)
                if unknown:
                    return self._precedence_unknown(unknown, rule=entry["rule"])
                if entry.get("scoped") is False:     # the VM's NICs it doesn't cover (RB1, review)
                    try:
                        off = [t["nic_short"] for t in self._off_perimeter(rg, vm_name, nsg_rg, nsg_name)]
                    except Exception as exc:
                        return {"verified": None, "method": "nsg_check",
                                "error": f"blocage non vérifiable : cartes illisibles ({_first_line(exc)[:_ERR_MAX]})"}
                    if off:
                        return {"verified": False, "method": "nsg_check", "uncovered_nics": off, "open_nics": off,
                                "error": f"le périmètre ne couvre pas {', '.join(off)} (autre subnet)"}
                return {"verified": True, "method": "nsg_check", "rule": entry["rule"],
                        **({"exposure": shadowed} if shadowed else {})}
            # What is left of the pair, an allow before it (L1R): said with what is gone, as
            # for a VM's block (L1C) — this path read the pair « missing » alone.
            half = self._half_bypassed(pair_cache, {"nsg_rg": nsg_rg, "nsg_name": nsg_name, "rule": entry["rule"]},
                                       ip, None, entry.get("threat_port"))
            return {"verified": False, "method": "nsg_check", "missing_rules": missing,
                    **({"shadowed_by": half} if half else {}),
                    "error": f"rules missing: {', '.join(missing)}"
                             + (f" ; contourné : {_describe_shadowing(half)}" if half else "")}

        # No state — recompute per-NIC names (multi-NIC) and check coverage.
        prefix = self._block_rule_prefix(ip)
        targets = self._get_vm_nic_targets(rg, vm_name)
        uncovered = []
        found: dict[str, tuple] = {}
        pair_cache: dict = {}
        for t0 in targets:
            bases = (*self._placement_rule_bases(prefix, vm_name, t0["nic_short"], t0["nic_id"]),
                     self._legacy_rule_base(prefix, vm_name, t0["nic_short"], t0["nic_id"]))
            present = [(t, base) for t in self._nic_nsg_views(t0) for base in bases
                       if self._rules_present(t["nsg_rg"], t["nsg_name"], [base, f"{base}-out"])]
            # The pair that blocks the NIC as it is now first (I4A): two denies of the
            # attacker for its current addresses — a pair left by an earlier address, or one
            # turned into an allow, read first, hid a bypass of the one that does.
            hit = next((h for h in present if self._block_pair_state(
                pair_cache, h[0]["nsg_rg"], h[0]["nsg_name"], h[1], ip, t0["private_ips"] or None)[0] == "present"),
                present[0] if present else None)
            if hit:
                found[t0["nic_id"]] = (hit[0]["nsg_rg"], hit[0]["nsg_name"], hit[1])
            else:
                uncovered.append(t0["nic_short"])
        if uncovered:
            return {"verified": False, "method": "nsg_check", "uncovered_nics": uncovered,
                    "error": f"NIC(s) not covered: {', '.join(uncovered)}"}
        shadowed, unknown = self._precedence([
            (*found[t["nic_id"]],
             {"inbound_src": [ip], "inbound_dst": t["private_ips"] or None,
              "outbound_src": t["private_ips"] or None, "outbound_dst": [ip]})
            for t in targets
        ])
        if shadowed:
            return self._block_bypassed(ip, shadowed)
        if unknown:
            return self._precedence_unknown(unknown, nics_covered=len(targets))
        return {"verified": True, "method": "nsg_check", "nics_covered": len(targets)}

    def _block_pair_state(self, cache: dict, nsg_rg: str, nsg_name: str, rule: str, ip: str,
                          ips: list[str] | None) -> tuple[str, list[str]]:
        """('present' | 'absent' | 'altered' | 'unknown', rule names concerned) for a
        block's rule pair, read from the NSG's listing by content (S2)."""
        names = [rule, f"{rule}-out"]
        rules = self._list_rules(cache, nsg_rg, nsg_name)
        if rules is None:
            return "unknown", names
        by_name = {_rule_name(r).lower(): r for r in rules}
        found = [by_name.get(n.lower()) for n in names]
        missing = [n for n, r in zip(names, found) if r is None]
        if missing:
            return "absent", missing
        altered = [n for n, r, d in zip(names, found, ("inbound", "outbound")) if not _deny_blocks(r, d, ip, ips)]
        return ("altered", altered) if altered else ("present", [])

    def _half_bypassed(self, cache: dict, p: dict, ip: str, ips: list[str] | None, port) -> list[dict]:
        """A pair gone or altered: each of its denies still there — a block of `ip`, or
        altered — passed by an allow before it that lets the threat through; [] otherwise
        (L1C, #369). Only a deny that still blocked was read: the inbound one narrowed to
        another port, the allow before it was never read (L1R, #381)."""
        rules = self._list_rules(cache, p["nsg_rg"], p["nsg_name"]) or []
        by_name = {_rule_name(r).lower(): r for r in rules}
        prio = {}
        for direction, name in (("inbound", p["rule"]), ("outbound", f'{p["rule"]}-out')):
            slot = _deny_slot(by_name.get(name.lower()), direction)
            if slot is not None:
                prio[direction] = slot
        found = [{**f, "nsg": f'{p["nsg_rg"]}/{p["nsg_name"]}'} for f in _shadowing_rules(
            rules, prio, inbound_src=[ip], inbound_dst=ips, outbound_src=ips, outbound_dst=[ip], port=port)] if prio else []
        return found if self._threat_open(found) else []

    @staticmethod
    def _threat_open(shadowed: list[dict]) -> bool:
        """An allow before the deny lets the threat itself through (not just another
        port). Entries without the flag (no known threat port) count as open."""
        return any(x.get("threat_port_open", True) for x in shadowed)

    @staticmethod
    def _block_bypassed(ip: str, shadowed: list[dict]) -> dict:
        bypass = [x for x in shadowed if x.get("threat_port_open", True)]
        return {
            "verified": False, "method": "nsg_check", "shadowed_by": shadowed,
            "error": f"blocage de {ip} contourné : " + _describe_shadowing(bypass)
                     + " passe avant le deny de Glorfindel",
        }
