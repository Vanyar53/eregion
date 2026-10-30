"""block_suspicious_ip: one deny pair per NIC (scope vm), or a perimeter rule on the
subnet NSG (scope subnet) (moved from actions.py, A1).
"""
from __future__ import annotations

from glorfindel.providers.azure.nsg import (
    _describe_shadowing,
    _ip_scoped,
    _pair_priorities,
    _prefixes,
    _report_block_shadowing,
    _rule_name,
    _scope_to_nic,
    _shadowing_rules,
)
from glorfindel.providers.azure.sdk import _enum_text
from glorfindel.response.ids import _parse_vm_resource_id
from glorfindel.response.policy import _first_line, PartialActionError, blockable_ip
from glorfindel.response.state import _clear_block_state, _load_block_entries, _save_block_state


class BlockMixin:
    """IP blocks (part of AzureConnector)."""

    def block_suspicious_ip(
        self, ip: str, resource_id: str, scope: str = "vm", replace: bool = False,
        threat_port: int | None = None,
    ) -> dict:
        """Block a suspicious IP.

        scope="vm" (default, autonomous): the rule only affects THIS VM — on a shared
          subnet NSG it is addressed to the VM's private IP; on a NIC NSG it's any/any
          (the NSG already covers only this VM).
        scope="subnet" (deliberate, operator opt-in): one perimeter rule on the SUBNET
          NSG, attacker→any → blocks the IP for EVERY VM on the subnet (incl. future
          ones). scoped=False → War Room shows the ⚠ subnet-wide chip.
        replace=True (promote VM→subnet): apply the subnet rule FIRST, then drop the
          now-redundant VM-scoped rule for this IP. Create-then-delete → no protection
          gap (if the subnet rule fails to apply, the VM rule is left intact).
        threat_port: the port the attack targets, when known (22 for SSH brute force).
          An ALLOW before the deny only defeats the block if it opens that port; other
          ports left reachable are reported as exposure, not as a bypass.
        """
        if self.dry_run:
            return {"status": "dry_run", "action": "block_ip", "ip": ip, "scope": scope}
        if not ip:
            raise ValueError("block_suspicious_ip: no IP address provided")
        # `*`, a CIDR or a service tag would cut far more; a never-block address, never (SEC2).
        blockable_ip(ip)

        self._guard_write("block_suspicious_ip")
        self._ensure_clients()
        rg, vm_name = _parse_vm_resource_id(resource_id)

        if scope == "subnet":
            return self._block_ip_subnet(ip, resource_id, rg, vm_name, replace, threat_port)
        return self._block_ip_vm(ip, resource_id, rg, vm_name, threat_port)

    def _plan_block(self, t: dict, ip: str, nsg_rg: str, nsg_name: str, ip_scoped: bool,
                    assigned: dict, threat_port: int | None, pairs: list[tuple[str, str]],
                    holders: dict, shared: bool) -> dict:
        """Priorities a block deny pair would take on this NSG (`own`: its two names — a
        rewrite keeps their place or moves them up, see _pair_priorities), and the allows
        before it. The pair is the first of `pairs` none of whose rules aims at another
        VM (_left_on_others, I4A); `left`: those rules, kept as they are; `drop`: the other
        pairs' rules present, taken off once the deny is written. `shared`: the NSG governs
        other NICs (a subnet's, or a NIC's NSG another NIC joined)."""
        nsg_key = f"{nsg_rg}/{nsg_name}"
        existing = list(self._network.security_rules.list(nsg_rg, nsg_name))
        by_name = {_rule_name(r).lower(): r for r in existing}
        left: list[dict] = []
        own = None
        for pair in pairs:
            kept = [x for n in pair if n.lower() in by_name
                    for x in self._left_on_others(by_name[n.lower()], t, shared, nsg_key, holders, pairs)]
            if not kept:
                own = own or pair
            left += kept
        if own is None:
            raise RuntimeError(
                f"NIC {t['nic_short']} : les noms de son blocage sur {nsg_name} sont pris par des règles "
                "qui visent d'autres VM — rien n'est écrit par-dessus. "
                + _describe_left(left))
        taken = {x["rule"].lower() for x in left}
        drop = [n for pair in pairs if pair != own for n in pair if n.lower() in by_name and n.lower() not in taken]
        priority = _pair_priorities(existing, *own, 200, 10, assigned.get(nsg_key, set()))
        vm_ips = t["private_ips"] or None
        shadowed = _shadowing_rules(existing, priority, inbound_src=[ip], inbound_dst=vm_ips,
                                    outbound_src=vm_ips, outbound_dst=[ip], port=threat_port)
        return {"nsg_key": nsg_key, "priority": priority, "ip_scoped": ip_scoped,
                "shadowed": shadowed, "own": own, "left": left, "drop": drop,
                "bypassed": [x for x in shadowed if x.get("threat_port_open", True)]}

    def _left_on_others(self, rule, t: dict, shared: bool, nsg_key: str, holders: dict,
                        pairs: list[tuple[str, str]]) -> list[dict]:
        """A rule of this NIC's block that rewritten (or taken off) would change another
        VM's flows (I4A), aimed at an address that is no longer the NIC's — another VM's
        now, or nobody knows (A0) — or at any address, on an NSG others share:
        - one someone turned into an allow: rewritten, that VM was cut off (seed 8675, the
          old address handed to a new VM);
        - our deny, while a rule of this NIC's turned into an allow waits behind it for
          that address, on an NSG of the NIC (_turned_behind): lifted, it let that allow
          open that VM (seed 42 at 2 000). Otherwise our deny is never one: rewritten, it
          only gives back what it cut.
        Nobody's address: rewritten as before."""
        deny = _enum_text(getattr(rule, "access", "")) == "deny"
        direction = _enum_text(getattr(rule, "direction", ""))
        side = "destination" if direction == "inbound" else "source"
        mine = {a.lower() for a in t["private_ips"] or []}
        out = []
        for addr in _prefixes(rule, side) or ("*",):
            if addr in mine or (deny and not self._turned_behind(t, direction, addr, holders, pairs)):
                continue
            if addr in ("*", "any", "0.0.0.0/0"):
                on = "toutes les cartes derrière ce NSG" if shared else None
            else:
                on = self._address_holder(addr, t["nic_id"], holders)
            if on:
                out.append({"nsg": nsg_key, "rule": _rule_name(rule), "to": addr, "on": on,
                            "kind": "deny" if deny else "turned"})
        return out

    def _turned_behind(self, t: dict, direction: str, addr: str, holders: dict,
                       pairs: list[tuple[str, str]]) -> bool:
        """A rule of this NIC's block (by its names), on an NSG of the NIC, turned into an
        allow for `addr` in this direction (or any address). The NSGs unreadable: unknown,
        read as yes — keeping our deny never opens anything (A0). Listed once per NIC."""
        key = ("turned", t["nic_id"])
        if key not in holders:
            names = {n.lower() for pair in pairs for n in pair}
            found: set | None = set()
            try:
                for v in self._nic_nsg_views(t):
                    for r in self._network.security_rules.list(v["nsg_rg"], v["nsg_name"]):
                        if _rule_name(r).lower() in names and _enum_text(getattr(r, "access", "")) != "deny":
                            d = _enum_text(getattr(r, "direction", ""))
                            found |= {(d, a) for a in _prefixes(r, "destination" if d == "inbound" else "source")
                                      or ("*",)}
            except Exception:
                found = None
            holders[key] = found
        found = holders[key]
        if found is None:
            return True
        return bool({(direction, addr), (direction, "*")} & found) or (
            addr in ("*", "any", "0.0.0.0/0") and any(d == direction for d, _ in found))

    def _address_holder(self, addr: str, nic_id: str, holders: dict) -> str | None:
        """Who holds this address now, this NIC aside: VM names; None for nobody; an
        unknown said as such, never as nobody (A0). The NICs listed once per block."""
        if "map" not in holders:
            try:
                found: dict[str, set] = {}
                for nic in self._network.network_interfaces.list_all():
                    if nic.id.rstrip("/").lower() == nic_id.rstrip("/").lower():
                        continue
                    vm = getattr(getattr(nic, "virtual_machine", None), "id", None) or nic.id
                    for c in nic.ip_configurations or []:
                        if a := getattr(c, "private_ip_address", None):
                            found.setdefault(a.lower(), set()).add(vm.rstrip("/").rsplit("/", 1)[-1])
                holders["map"] = found
            except Exception as exc:
                holders["map"], holders["error"] = None, _first_line(exc)
        if holders["map"] is None:
            return f"inconnu (cartes illisibles : {holders['error']})"
        if "/" in addr or not addr[:1].isdigit():
            return "inconnu (une plage ou une étiquette, pas une adresse)"
        return ", ".join(sorted(holders["map"].get(addr, ()))) or None

    def _block_ip_vm(self, ip: str, resource_id: str, rg: str, vm_name: str,
                     threat_port: int | None = None) -> dict:
        """VM-scoped block (autonomous default) — deny the attacker IP on EVERY NIC so a
        secondary NIC doesn't leave the attacker a path. One rule pair per NIC:
        any↔attacker on an NSG that governs this VM alone, attacker↔(all the NIC's IPs)
        on an NSG shared with other NICs (subnet NSG or shared NIC-level NSG).

        Partial failure: rules already placed stay and are recorded (`partial: true`),
        then PartialActionError is raised — same contract as isolate_vm."""
        prefix = self._block_rule_prefix(ip)
        targets = self._get_vm_nic_targets(rg, vm_name)
        placements: list[dict] = []
        assigned: dict[str, set] = {}
        holders: dict = {}
        for t in targets:
            nsg_rg, nsg_name, scope_t = t["nsg_rg"], t["nsg_name"], t["scope"]
            nsg_key = f"{nsg_rg}/{nsg_name}"
            pairs = [(b, f"{b}-out") for b in self._placement_rule_bases(prefix, vm_name, t["nic_short"], t["nic_id"])]
            base = pairs[0][0]
            placement = {
                "nic_id": t["nic_id"], "nsg_rg": nsg_rg, "nsg_name": nsg_name, "scope": scope_t,
                "shared_nsg": bool(t.get("shared_nsg", False)),
                "ips": t["private_ips"], "rule": base,
            }
            applied: list[str] = []
            try:
                # Same placement rule as the isolation: no customer rule moved; when an
                # allow before the deny lets the THREAT through on this NSG, the NIC's
                # other NSG (its subnet's) holds the deny instead.
                plan = self._plan_block(t, ip, nsg_rg, nsg_name, _scope_to_nic(t), assigned, threat_port,
                                        pairs, holders, _ip_scoped(t))
                alt = t.get("alt_nsg")
                if plan["bypassed"] and alt:
                    alt_plan = self._plan_block(t, ip, alt["nsg_rg"], alt["nsg_name"], True,
                                                assigned, threat_port, pairs, holders, True)
                    if not alt_plan["bypassed"]:
                        placement.update({
                            "nsg_rg": alt["nsg_rg"], "nsg_name": alt["nsg_name"],
                            "scope": "subnet", "shared_nsg": False,
                            "moved_from": {"nsg": nsg_key, "because": plan["bypassed"]},
                        })
                        nsg_rg, nsg_name, nsg_key = alt["nsg_rg"], alt["nsg_name"], alt_plan["nsg_key"]
                        plan = alt_plan
                priority = plan["priority"]
                in_name, out_name = plan["own"]
                placement["rule"] = in_name
                if plan["ip_scoped"]:
                    ips = t["private_ips"]
                    if not ips:
                        # Same guard as isolate_vm: an empty destination list would make
                        # a rule that matches nothing (or is rejected) — never "blocked".
                        raise RuntimeError(
                            f"NIC {t['nic_short']} has no private IP — cannot scope the "
                            "block on its shared NSG"
                        )
                    self._put_deny_rule(nsg_rg, nsg_name, in_name, "Inbound", priority["inbound"],
                                        src=ip, dsts=ips)
                    applied.append(in_name)
                    self._put_deny_rule(nsg_rg, nsg_name, out_name, "Outbound", priority["outbound"],
                                        srcs=ips, dst=ip)
                    applied.append(out_name)
                else:
                    self._put_deny_rule(nsg_rg, nsg_name, in_name, "Inbound", priority["inbound"],
                                        src=ip, dst="*")
                    applied.append(in_name)
                    self._put_deny_rule(nsg_rg, nsg_name, out_name, "Outbound", priority["outbound"],
                                        src="*", dst=ip)
                    applied.append(out_name)
                placement["shadowed_by"] = plan["shadowed"]
                if plan["left"]:
                    placement["left"] = plan["left"]
                # The other pair's rules: ours, aimed at no other VM — the deny now holds.
                for nm in plan["drop"]:
                    if err := self._delete_rule(nsg_rg, nsg_name, nm):
                        placement.setdefault("drop_failed", []).append(err)
            except Exception as exc:
                kept = placements + ([placement] if applied else [])
                if not kept:
                    raise
                first = kept[0]
                _save_block_state(
                    vm_name, ip, resource_id,
                    nsg=f'{first["nsg_rg"]}/{first["nsg_name"]}', nsg_scope=first["scope"],
                    rule=first["rule"], scoped=True, placements=kept, partial=True,
                    threat_port=threat_port,
                )
                failed_nic = t["nic_short"]
                raise PartialActionError(
                    f"Blocage partiel de {ip} sur {vm_name} : {len(placements)}/{len(targets)} "
                    f"NIC(s) couverte(s), échec sur {failed_nic} ({_first_line(exc)}). "
                    "Les règles déjà posées restent en place et sont enregistrées — "
                    f"`glorfindel unblock {ip} <resource_id>` pour les retirer.",
                    cause=exc, covered=[p["rule"] for p in placements], failed_nic=failed_nic,
                ) from exc
            assigned.setdefault(nsg_key, set()).update(priority.values())
            placements.append(placement)

        first = placements[0]
        _save_block_state(
            vm_name, ip, resource_id,
            nsg=f'{first["nsg_rg"]}/{first["nsg_name"]}', nsg_scope=first["scope"],
            rule=first["rule"], scoped=True, placements=placements, threat_port=threat_port,
        )
        out = {
            "status": "blocked", "ip": ip, "scoped": True, "resource_id": resource_id,
            "nics_covered": len(placements),
            "nsg": f'{first["nsg_rg"]}/{first["nsg_name"]}',
            "nsg_scope": first["scope"], "rule": first["rule"],
            "placements": [
                {"nsg": f'{p["nsg_rg"]}/{p["nsg_name"]}', "scope": p["scope"],
                 **({"moved_from": p["moved_from"]["nsg"]} if p.get("moved_from") else {})}
                for p in placements
            ],
        }
        if any(_ip_scoped(p) or p["shared_nsg"] for p in placements):
            out["note"] = (
                "shared NSG involved (subnet or several NICs) — block scoped to this VM's "
                "private IP(s) (attacker still reaches other VMs until they detect it)."
            )
        moved = [p for p in placements if p.get("moved_from")]
        if moved:
            out["note"] = (
                "deny placed on the subnet NSG, scoped to this VM's IP(s): on "
                + ", ".join(p["moved_from"]["nsg"] for p in moved)
                + " an allow is evaluated before it ("
                + _describe_shadowing([s for p in moved for s in p["moved_from"]["because"]])
                + ")."
            )
        left = [x for p in placements for x in p.get("left", [])]
        if left:
            out["left_rules"] = left
            out["note"] = (out.get("note", "") + " " + _describe_left(left)).strip()
        _report_block_shadowing(out, ip, [s for p in placements for s in p.get("shadowed_by", [])])
        return out

    def _block_ip_subnet(
        self, ip: str, resource_id: str, rg: str, vm_name: str, replace: bool,
        threat_port: int | None = None,
    ) -> dict:
        """Perimeter block — one any rule on the SUBNET NSG (covers all VMs on the
        subnet + future). replace=True promotes a prior VM-scoped block: create the
        subnet rule first, then drop the prior per-NIC rules (no protection gap) — of the
        NICs behind it only. It lies on the primary NIC's subnet: a NIC on another subnet
        keeps its own block, and one nothing blocks is named (`uncovered_nics`, status
        `blocked_partial`) — it was `blocked` while that NIC stayed open, and a promotion
        took its block off (RB1, review)."""
        nic_id = self._get_primary_nic_id(rg, vm_name)
        nsg_rg, nsg_name = self._get_subnet_nsg(nic_id)
        rule_name = self._block_rule_name(ip, vm_name, scope="vm")  # shared (no VM suffix)
        try:
            off = self._off_perimeter(rg, vm_name, nsg_rg, nsg_name)
            off_ids, unread = {t["nic_id"].rstrip("/").lower() for t in off}, ""
        except Exception as exc:              # unknown: no NIC's own block taken off
            off, off_ids, unread = [], None, _first_line(exc)

        existing = list(self._network.security_rules.list(nsg_rg, nsg_name))
        # Put back by the reassertion, it keeps its place (see _pair_priorities).
        priority = _pair_priorities(existing, rule_name, f"{rule_name}-out", 200, 10)
        self._put_deny_rule(nsg_rg, nsg_name, rule_name, "Inbound", priority["inbound"], src=ip, dst="*")
        self._put_deny_rule(nsg_rg, nsg_name, f"{rule_name}-out", "Outbound", priority["outbound"],
                            src="*", dst=ip)

        promoted_from = None
        if replace:
            # Subnet rule now in place → drop the prior VM-scoped rules of the NICs behind it.
            prev = next((e for e in _load_block_entries(resource_id) if e.get("ip") == ip), None)
            dropped, kept = [], []
            for pl in (prev or {}).get("placements", []):
                if off_ids is None or (pl.get("nic_id") or "").rstrip("/").lower() in off_ids:
                    kept.append(pl)               # not behind the perimeter (or unknown): kept
                    continue
                for nm in (pl["rule"], f'{pl["rule"]}-out'):
                    try:
                        self._network.security_rules.begin_delete(pl["nsg_rg"], pl["nsg_name"], nm).result()
                    except Exception:
                        pass
                dropped.append(pl["rule"])
            # Legacy single-rule entry (no placements)
            if prev and prev.get("rule") and not prev.get("placements") and prev["rule"] != rule_name:
                old_rg, old_name = (prev.get("nsg") or f"{nsg_rg}/{nsg_name}").split("/", 1)
                for nm in (prev["rule"], f'{prev["rule"]}-out'):
                    try:
                        self._network.security_rules.begin_delete(old_rg, old_name, nm).result()
                    except Exception:
                        pass
                dropped.append(prev["rule"])
            if prev:
                _clear_block_state(resource_id, ip)
            promoted_from = dropped or None

        _save_block_state(
            vm_name, ip, resource_id,
            nsg=f"{nsg_rg}/{nsg_name}", nsg_scope="subnet", rule=rule_name, scoped=False,
            placements=kept if replace else None, threat_port=threat_port,
        )
        # A NIC off the perimeter's subnet is blocked only by its own block — as Azure reads
        # it, never as the state remembers it (a partial one, rules gone since).
        uncovered = [t["nic_short"] for t in off]
        if uncovered:
            try:
                check = self.verify_block_ip(ip, resource_id)
            except Exception as exc:
                check = {"verified": None, "error": _first_line(exc)}
            if check.get("verified") is True:
                uncovered = []
            elif check.get("verified") is False:
                open_ = {*(check.get("open_nics") or []), *(check.get("uncovered_nics") or []),
                         *(check.get("perimeter_unread") or [])}
                uncovered = [n for n in uncovered if n in open_] if open_ else uncovered
            else:
                unread = unread or check.get("error") or "illisible"
        # Same precedence report as the VM-scoped block (verify fails on it as well).
        shadowed = _shadowing_rules(
            existing, priority, inbound_src=[ip], inbound_dst=None,
            outbound_src=None, outbound_dst=[ip], port=threat_port)
        out = {
            "status": "blocked", "ip": ip, "nsg": f"{nsg_rg}/{nsg_name}",
            "nsg_scope": "subnet", "scoped": False, "rule": rule_name,
            "resource_id": resource_id,
            "note": (
                f"NSG {nsg_rg}/{nsg_name} — perimeter block: this IP is denied for ALL "
                "VMs on the subnet (and future ones)."
            ),
        }
        if promoted_from:
            out["promoted_from"] = promoted_from
        if uncovered or unread:
            out["status"] = "blocked_partial"
            out["uncovered_nics" if uncovered else "nics_unread"] = uncovered or unread
            out["note"] += (f" Not behind it, on another subnet: {', '.join(uncovered)} — {ip} still reaches "
                            "them; block the VM too (scope vm) to cut them off." if uncovered else
                            f" {vm_name}'s NICs unreadable ({unread}): what the perimeter covers of it is unverified.")
        _report_block_shadowing(out, ip, shadowed)
        return out

    def _block_rule_prefix(self, ip: str) -> str:
        return f"glorfindel-block-{ip.replace('.', '-').replace('/', '-')}"


def _describe_left(left: list[dict]) -> str:
    """What a block left as it was (I4A), and how to take it off."""
    return "Laissée(s) telle(s) quelle(s) : " + " ; ".join(
        f"{x['rule']} ({x['nsg']}), " + (
            f"notre deny sur {x['to']}, plus une adresse de la VM bloquée : {x['on']} — une règle à notre nom "
            "passée en autorisation par un tiers l'attend derrière, le retirer ouvrirait cette VM ; "
            if x.get("kind") == "deny" else
            f"règle du blocage retournée en autorisation par un tiers, vise {x['to']} — plus une adresse de la VM "
            f"bloquée : {x['on']}. La réécrire changerait les flux de cette VM ; ")
        + f"à retirer à la main si elle n'est plus voulue (az network nsg rule delete -g {x['nsg'].split('/', 1)[0]} "
        f"--nsg-name {x['nsg'].split('/', 1)[-1]} -n {x['rule']})" for x in left) + "."
