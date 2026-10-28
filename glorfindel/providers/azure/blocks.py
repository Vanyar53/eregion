"""block_suspicious_ip: one deny pair per NIC (scope vm), or a perimeter rule on the
subnet NSG (scope subnet) (moved from actions.py, A1).
"""
from __future__ import annotations

from glorfindel.providers.azure.nsg import (
    _describe_shadowing,
    _ip_scoped,
    _report_block_shadowing,
    _scope_to_nic,
    _shadowing_rules,
)
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
                    assigned: dict, threat_port: int | None) -> dict:
        """Priority a block deny would take on this NSG, and the allows before it."""
        nsg_key = f"{nsg_rg}/{nsg_name}"
        existing = list(self._network.security_rules.list(nsg_rg, nsg_name))
        used = {r.priority for r in existing} | assigned.get(nsg_key, set())
        priority = next(p for p in range(200, 4000, 10) if p not in used)
        vm_ips = t["private_ips"] or None
        shadowed = _shadowing_rules(existing, priority, inbound_src=[ip], inbound_dst=vm_ips,
                                    outbound_src=vm_ips, outbound_dst=[ip], port=threat_port)
        return {"nsg_key": nsg_key, "priority": priority, "ip_scoped": ip_scoped,
                "shadowed": shadowed,
                "bypassed": [x for x in shadowed if x.get("threat_port_open", True)]}

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
        for t in targets:
            nsg_rg, nsg_name, scope_t = t["nsg_rg"], t["nsg_name"], t["scope"]
            nsg_key = f"{nsg_rg}/{nsg_name}"
            base = self._placement_rule_base(prefix, vm_name, t["nic_short"], t["nic_id"])
            in_name, out_name = base, f"{base}-out"
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
                plan = self._plan_block(t, ip, nsg_rg, nsg_name, _scope_to_nic(t), assigned, threat_port)
                alt = t.get("alt_nsg")
                if plan["bypassed"] and alt:
                    alt_plan = self._plan_block(t, ip, alt["nsg_rg"], alt["nsg_name"], True,
                                                assigned, threat_port)
                    if not alt_plan["bypassed"]:
                        placement.update({
                            "nsg_rg": alt["nsg_rg"], "nsg_name": alt["nsg_name"],
                            "scope": "subnet", "shared_nsg": False,
                            "moved_from": {"nsg": nsg_key, "because": plan["bypassed"]},
                        })
                        nsg_rg, nsg_name, nsg_key = alt["nsg_rg"], alt["nsg_name"], alt_plan["nsg_key"]
                        plan = alt_plan
                priority = plan["priority"]
                if plan["ip_scoped"]:
                    ips = t["private_ips"]
                    if not ips:
                        # Same guard as isolate_vm: an empty destination list would make
                        # a rule that matches nothing (or is rejected) — never "blocked".
                        raise RuntimeError(
                            f"NIC {t['nic_short']} has no private IP — cannot scope the "
                            "block on its shared NSG"
                        )
                    self._put_deny_rule(nsg_rg, nsg_name, in_name, "Inbound", priority, src=ip, dsts=ips)
                    applied.append(in_name)
                    self._put_deny_rule(nsg_rg, nsg_name, out_name, "Outbound", priority, srcs=ips, dst=ip)
                    applied.append(out_name)
                else:
                    self._put_deny_rule(nsg_rg, nsg_name, in_name, "Inbound", priority, src=ip, dst="*")
                    applied.append(in_name)
                    self._put_deny_rule(nsg_rg, nsg_name, out_name, "Outbound", priority, src="*", dst=ip)
                    applied.append(out_name)
                placement["shadowed_by"] = plan["shadowed"]
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
            assigned.setdefault(nsg_key, set()).add(priority)
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
        _report_block_shadowing(out, ip, [s for p in placements for s in p.get("shadowed_by", [])])
        return out

    def _block_ip_subnet(
        self, ip: str, resource_id: str, rg: str, vm_name: str, replace: bool,
        threat_port: int | None = None,
    ) -> dict:
        """Perimeter block — one any rule on the SUBNET NSG (covers all VMs on the
        subnet + future). replace=True promotes a prior VM-scoped block: create the
        subnet rule first, then drop the prior per-NIC rules (no protection gap)."""
        nic_id = self._get_primary_nic_id(rg, vm_name)
        nsg_rg, nsg_name = self._get_subnet_nsg(nic_id)
        rule_name = self._block_rule_name(ip, vm_name, scope="vm")  # shared (no VM suffix)

        existing = list(self._network.security_rules.list(nsg_rg, nsg_name))
        used = {r.priority for r in existing}
        priority = next(p for p in range(200, 4000, 10) if p not in used)
        self._put_deny_rule(nsg_rg, nsg_name, rule_name, "Inbound", priority, src=ip, dst="*")
        self._put_deny_rule(nsg_rg, nsg_name, f"{rule_name}-out", "Outbound", priority, src="*", dst=ip)

        promoted_from = None
        if replace:
            # Subnet rule now in place → drop the prior VM-scoped rules (every NIC).
            prev = next((e for e in _load_block_entries(resource_id) if e.get("ip") == ip), None)
            dropped = []
            for pl in (prev or {}).get("placements", []):
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
            threat_port=threat_port,
        )
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
        _report_block_shadowing(out, ip, shadowed)
        return out

    def _block_rule_prefix(self, ip: str) -> str:
        return f"glorfindel-block-{ip.replace('.', '-').replace('/', '-')}"
