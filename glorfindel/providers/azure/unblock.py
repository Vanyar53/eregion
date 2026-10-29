"""verify_block_ip and unblock_ip, including behind the quarantine (moved from
actions.py, A1).
"""
from __future__ import annotations

from glorfindel.providers.azure.nsg import (
    _deny_applies,
    _deny_blocks,
    _describe_shadowing,
    _ip_scoped,
    _nic_owns,
    _rule_name,
)
from glorfindel.providers.azure.quarantine import OriginalUnknown
from glorfindel.providers.azure.sdk import _is_not_found
from glorfindel.response.ids import _parse_nsg_resource_id, _parse_vm_resource_id
from glorfindel.response.policy import _ERR_MAX, _first_line
from glorfindel.response.state import (
    _clear_block_state,
    _held_in_quarantine,
    _load_block_entries,
    _recorded_original,
    _UNKNOWN,
    _update_block_entry,
)


class UnblockMixin:
    """Verifying and lifting IP blocks (part of AzureConnector)."""

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
            if current is not None and any(p.get("nic_id") for p in entry["placements"]):
                missing += [n.rsplit("/", 1)[-1] for n in current if n not in groups]   # a NIC added since
            cache: dict = {}
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
                        missing += [f'{p["rule"]} ({p["nsg_name"]} ne gouverne plus {t0["nic_short"]})' for p in off]
                        continue
                now = current.get(nic) if current is not None and isinstance(nic, str) else None
                ips_of = {id(p): now if now is not None else (p.get("ips") or None) for p in ps}
                nic_missing, nic_unread, nic_bypass, nic_unknown = [], [], [], []
                for p in ps:
                    st, names = self._block_pair_state(cache, p["nsg_rg"], p["nsg_name"], p["rule"],
                                                       ip, ips_of[id(p)] or None)
                    if st in ("absent", "altered"):          # altered: put back like missing
                        nic_missing += names
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
                        nic_bypass += found
                    else:
                        exposure += found
                        break                       # this NIC is blocked
                else:
                    if nic_bypass:
                        bypass += nic_bypass
                    elif nic_unread or nic_unknown:
                        unread += nic_unread
                        unknown += [u for u in nic_unknown if u not in unknown]
                    else:
                        missing += nic_missing
            if missing:
                return {"verified": False, "method": "nsg_check", "missing_rules": missing,
                        "error": f"rules missing: {', '.join(missing)}"}
            if bypass:
                return self._block_bypassed(ip, bypass)
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
                    **({"held_missing": held_missing} if held_missing else {})}

        # Perimeter (subnet) block, or legacy single-rule entry: check the recorded pair.
        if entry and entry.get("nsg") and entry.get("rule"):
            nsg_rg, nsg_name = entry["nsg"].split("/", 1)
            st, names = self._block_pair_state({}, nsg_rg, nsg_name, entry["rule"], ip, None)
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
                return {"verified": True, "method": "nsg_check", "rule": entry["rule"],
                        **({"exposure": shadowed} if shadowed else {})}
            return {"verified": False, "method": "nsg_check", "missing_rules": missing,
                    "error": f"rules missing: {', '.join(missing)}"}

        # No state — recompute per-NIC names (multi-NIC) and check coverage.
        prefix = self._block_rule_prefix(ip)
        targets = self._get_vm_nic_targets(rg, vm_name)
        uncovered = []
        found: dict[str, tuple] = {}
        for t0 in targets:
            bases = (self._placement_rule_base(prefix, vm_name, t0["nic_short"], t0["nic_id"]),
                     self._legacy_rule_base(prefix, vm_name, t0["nic_short"], t0["nic_id"]))
            hit = next(((t, base) for t in self._nic_nsg_views(t0) for base in bases
                        if self._rules_present(t["nsg_rg"], t["nsg_name"], [base, f"{base}-out"])), None)
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

    def unblock_ip(self, ip: str, resource_id: str) -> dict:
        """Remove every rule of a block. Delete failures are reported, not swallowed: a
        rule that could not be removed still blocks the IP, so its entry stays in state
        and the status is `unblock_partial`."""
        if self.dry_run:
            return {"status": "dry_run", "action": "unblock_ip", "ip": ip}
        if not ip:
            raise ValueError("unblock_ip: no IP address provided")

        self._guard_write("unblock_ip")
        self._ensure_clients()
        rg, vm_name = _parse_vm_resource_id(resource_id)
        entry = next((e for e in _load_block_entries(resource_id) if e.get("ip") == ip), None)
        if entry:
            # Intent first (see release_isolation): an unblock cut off midway is not a
            # block "removed outside Glorfindel" for the reassertion to put back.
            from datetime import datetime, timezone
            _update_block_entry(resource_id, ip, unblocking_at=datetime.now(timezone.utc).isoformat())
        deleted: list[str] = []
        failed: list[str] = []

        def _del(p_rg: str, p_name: str, rule: str) -> None:
            for nm in (rule, f"{rule}-out"):
                err = self._delete_rule(p_rg, p_name, nm)
                if err:
                    failed.append(err)
                else:
                    deleted.append(nm)

        # 1) Every per-NIC placement recorded at block time (multi-NIC VM block).
        for p in (entry or {}).get("placements", []):
            _del(p["nsg_rg"], p["nsg_name"], p["rule"])

        # 2) The recorded single rule (perimeter / legacy entry). A VM-scoped entry also
        # mirrors its first placement in nsg/rule: skip it then (deleted in step 1 — the
        # bench run listed every rule twice).
        if entry and entry.get("nsg") and entry.get("rule"):
            r_rg, r_name = entry["nsg"].split("/", 1)
            done = {(p["nsg_rg"], p["nsg_name"], p["rule"]) for p in entry.get("placements", [])}
            if (r_rg, r_name, entry["rule"]) not in done:
                _del(r_rg, r_name, entry["rule"])

        # 3) Then every NIC, state or not: a crash between Azure and the state file left
        # rules no entry knows — and the legacy lookup (primary NIC, old names) counted
        # a delete of a rule that wasn't there as done, so `unblocked` was said while
        # the rules stayed (L24, blocks in the invariant machine).
        s_deleted, s_failed = self._sweep_block(rg, vm_name, ip)
        deleted += [d for d in s_deleted if d not in deleted]
        failed += s_failed

        if failed:
            # Keep the entry: the rules that are still there keep blocking the IP, and a
            # retry of unblock / reset must still find them.
            _update_block_entry(resource_id, ip, unblock_failed=failed)
            return {
                "status": "unblock_partial", "ip": ip,
                "deleted_rules": deleted, "failed": failed,
            }
        _clear_block_state(resource_id, ip)
        return {
            "status": "unblocked" if deleted else "not_found",
            "ip": ip,
            "deleted_rules": deleted,
        }

    def _block_names_for_target(self, ip: str, vm_name: str, t: dict) -> set[str]:
        """Every rule name a VM-scoped block of `ip` can have left on this NIC's NSG:
        per-NIC (current, before the NIC hash), legacy VM-suffixed, and the plain name
        only on an NSG that governs this VM alone (on a shared one it is a perimeter
        block, an operator's decision covering every VM)."""
        prefix = self._block_rule_prefix(ip)
        bases = [self._placement_rule_base(prefix, vm_name, t["nic_short"], t["nic_id"]),
                 self._legacy_rule_base(prefix, vm_name, t["nic_short"], t["nic_id"]),
                 self._block_rule_name(ip, vm_name, "subnet")]
        if not _ip_scoped(t):
            bases.append(prefix)
        return {n.lower() for b in bases for n in (b, f"{b}-out")}

    def _sweep_block(self, rg: str, vm_name: str, ip: str) -> tuple[list[str], list[str]]:
        """(deleted, failed): the block rules of `ip` still on any NSG of this VM's NICs —
        named for it and applying to the NIC's addresses. Only rules that existed are
        counted as deleted; an unreadable NIC or rule list is a failure."""
        try:
            targets = self._get_vm_nic_targets(rg, vm_name, allow_no_nsg=True)
        except Exception as exc:
            if _is_not_found(exc):
                return [], []
            return [], [f"cartes de {vm_name} illisibles, déblocage non vérifié : {_first_line(exc)[:_ERR_MAX]}"]
        deleted: list[str] = []
        failed: list[str] = []
        cache: dict = {}
        for t0 in targets:
            if t0.get("subnet_unreadable"):
                failed.append(f'{t0["nic_short"]} : NSG du subnet illisible, déblocage non vérifié')
            views = self._nic_nsg_views(t0)
            try:
                original = self._original_away(t0, rg)
            except Exception as exc:
                failed.append(f'{t0["nic_short"]} : NSG d\'origine inconnu, déblocage non vérifié '
                              f"({_first_line(exc)[:_ERR_MAX]})")
                original = None
            if original:
                o_rg, o_name = _parse_nsg_resource_id(original)
                views = views + [{**t0, "nsg_rg": o_rg, "nsg_name": o_name, "scope": "nic", "ip_scoped": True}]
            for t in views:
                rules = self._list_rules(cache, t["nsg_rg"], t["nsg_name"])
                if rules is None:
                    failed.append(f'{t["nsg_rg"]}/{t["nsg_name"]} : règles illisibles, déblocage non vérifié')
                    continue
                names = self._block_names_for_target(ip, vm_name, t)
                base = self._placement_rule_base(self._block_rule_prefix(ip), vm_name, t["nic_short"], t["nic_id"])
                for r in rules:
                    name = _rule_name(r)
                    if _nic_owns(r, {base, f"{base}-out"}, names, t.get("private_ips") or None):
                        err = self._delete_rule(t["nsg_rg"], t["nsg_name"], name)
                        (failed if err else deleted).append(err or name)
                failed += self._unattributable_plain_block(ip, t, rules)
        return deleted, failed

    def _original_away(self, t0: dict, vm_rg: str) -> str | None:
        """The NIC's own NSG when it is off the NIC — where a block lies, out of sight
        until the release puts it back: unblocked meanwhile, `not_found` was answered and
        the IP was blocked again at the release. In our quarantine (L27), or left with no
        NSG at all, our quarantine taken off by hand (U3F, #293: a block cut off before
        its state, then isolated and left bare — the sweep only looked behind a
        quarantine). None: nothing away. Unknown RAISES — never "none" on a guess."""
        nic_id, q = t0["nic_id"], t0.get("quarantine")
        if not q and t0.get("own_nsg_id"):
            return None                          # its own NSG is on it: in its views
        original = _recorded_original(nic_id)
        if isinstance(original, str):
            return original                      # the state's NSG wins over the tag
        if q:
            # The state's "none" yields to our tag when it names an NSG, as at the
            # release: another host's isolation wrote X there, the block lies on X, and
            # `not_found` was answered (I8S, ISU #264).
            return self._original_from_tags(q, nic_id) if original is _UNKNOWN else self._tag_over_none(q, nic_id)
        # Bare: our tag on the region's quarantine NSG, as the release reads it (U2).
        tagged, q_bare = self._bare_nic_original(t0, vm_rg)
        if q_bare is not None:
            return tagged
        if original is _UNKNOWN and _held_in_quarantine(nic_id):
            raise OriginalUnknown("carte sans NSG, ni l'état local ni le tag ne le disent")
        return None

    def _unattributable_plain_block(self, ip: str, t: dict, rules: list) -> list[str]:
        """An older version's block under the IP's name alone, cutting this NIC off, on
        its own NSG whose sharing can't be read: this VM's, or another's away from it —
        unknown (I4S). Left, and said: it used to be left in silence, `not_found` answered
        while the IP stayed blocked. On a subnet's NSG the name is a perimeter block — and
        on a NIC's NSG that is its subnet's too, it may be one: said so (ISU, #264)."""
        if not (t.get("sharing_unknown") and t.get("scope") == "nic"):
            return []
        plain = {self._block_rule_prefix(ip).lower(), f"{self._block_rule_prefix(ip)}-out".lower()}
        what = "d'une ancienne version ou de périmètre" if t.get("subnet_nsg_too") else "d'une ancienne version"
        return [f'{t["nic_short"]}:{_rule_name(r)} (NSG {t["nsg_name"]} au partage illisible : blocage '
                f"{what}, VM inconnue) : laissée"
                for r in rules if _rule_name(r).lower() in plain and _deny_applies(r, t.get("private_ips") or None)]
