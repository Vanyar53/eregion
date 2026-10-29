"""Read-only questions to Azure: the rights an identity holds (readiness), private IP
owners, OS type, recent writes, NSG access and precedence, the NSG inventory, compute
access (moved from actions.py, A1).
"""
from __future__ import annotations

import os

from glorfindel.providers.azure.nsg import _shadowing_rules
from glorfindel.providers.azure.quarantine import _is_quarantine_nsg
from glorfindel.providers.azure.sdk import _enum_text, _is_iam_error
from glorfindel.response.ids import _parse_nic_resource_id, _parse_nsg_resource_id, _parse_vm_resource_id
from glorfindel.response.policy import _ERR_MAX, _first_line


class ReadersMixin:
    """Read-only questions: rights, inventory, audit (part of AzureConnector)."""

    # What the JIT isolation, the drain and the fallback rules need — checked without
    # writing anything, through Azure's permissions API (L6 readiness).
    REQUIRED_ACTIONS = (
        ("isolate_vm", "Microsoft.Network/networkInterfaces/write"),
        ("isolate_vm", "Microsoft.Network/virtualNetworks/subnets/join/action"),
        ("isolate_vm", "Microsoft.Network/networkSecurityGroups/write"),
        ("isolate_vm", "Microsoft.Network/networkSecurityGroups/join/action"),
        ("isolate_vm", "Microsoft.Compute/virtualMachines/runCommand/action"),
        ("release_isolation", "Microsoft.Network/networkSecurityGroups/join/action"),
        ("block_suspicious_ip", "Microsoft.Network/networkSecurityGroups/securityRules/write"),
        ("block_suspicious_ip", "Microsoft.Network/networkSecurityGroups/securityRules/delete"),
    )

    # What the response never needs, and the restore does (SEC7, V-17): the watch's identity
    # holding one of them on the VM's group could deallocate or restore on its own.
    BEYOND_RESPONSE = (
        "Microsoft.Compute/virtualMachines/deallocate/action",
        "Microsoft.RecoveryServices/Vaults/backupFabrics/protectionContainers/protectedItems/recoveryPoints/restore/action",
    )

    def _permission_scopes(self, rg: str, vm_name: str) -> dict[str, tuple[str, set]]:
        """Resource group → the (used_by, action) pairs needed THERE (third review, T12).
        Only the VM's and the quarantine's groups were read: a NIC, a VNet or the
        customer's NSG in another group (a central network group is common) failed the
        swap (LinkedAuthorizationFailed on subnets/join) or the release, while the
        readiness said "ready"."""
        scopes: dict[str, tuple[str, set]] = {}

        def need(group: str, used_by: str, action: str) -> None:
            if group:
                scopes.setdefault(group.lower(), (group, set()))[1].add((used_by, action))

        _, q_rg = self._quarantine_settings()
        need(rg, "isolate_vm", "Microsoft.Compute/virtualMachines/runCommand/action")
        for action in ("Microsoft.Network/networkSecurityGroups/write",
                       "Microsoft.Network/networkSecurityGroups/join/action"):
            need(q_rg or rg, "isolate_vm", action)
        for t in self._get_vm_nic_targets(rg, vm_name, allow_no_nsg=True):
            nic_rg, nic_name = _parse_nic_resource_id(t["nic_id"])
            need(nic_rg, "isolate_vm", "Microsoft.Network/networkInterfaces/write")
            try:
                nic = self._network.network_interfaces.get(nic_rg, nic_name)
                for ipc in getattr(nic, "ip_configurations", None) or []:
                    sub_id = getattr(getattr(ipc, "subnet", None), "id", "") or ""
                    if "/resourcegroups/" in sub_id.lower():
                        need(_parse_vm_resource_id(sub_id)[0], "isolate_vm",
                             "Microsoft.Network/virtualNetworks/subnets/join/action")
            except Exception:
                pass
            if t.get("own_nsg_id"):        # release puts the customer's NSG back
                need(_parse_nsg_resource_id(t["own_nsg_id"])[0], "release_isolation",
                     "Microsoft.Network/networkSecurityGroups/join/action")
            for v in self._nic_nsg_views(t):
                for action in ("Microsoft.Network/networkSecurityGroups/securityRules/write",
                               "Microsoft.Network/networkSecurityGroups/securityRules/delete"):
                    need(v["nsg_rg"], "block_suspicious_ip", action)
        return scopes

    def check_permissions(self, resource_id: str) -> dict:
        """Which of REQUIRED_ACTIONS Glorfindel's identity holds, each on the resource
        group where it applies (NICs, VNet, quarantine NSG, customer NSG, rule NSGs,
        VM) — read from `Microsoft.Authorization/permissions` (all pages), nothing
        written. Deny assignments, locks and PIM are not evaluated (the API doesn't
        return them)."""
        if self.dry_run:
            return {"ok": True, "missing": [], "dry_run": True}
        import fnmatch
        import requests
        try:
            self._ensure_clients()
            rg, vm_name = _parse_vm_resource_id(resource_id)
            scopes = self._permission_scopes(rg, vm_name)
            token = self._credential.get_token("https://management.azure.com/.default").token
            missing: list[dict] = []
            beyond: list[str] = []
            for scope_rg, needed in scopes.values():
                url = (f"https://management.azure.com/subscriptions/{self._subscription_id}"
                       f"/resourceGroups/{scope_rg}/providers/Microsoft.Authorization/permissions")
                params: dict | None = {"api-version": "2022-04-01"}
                perms: list = []
                while url:                     # nextLink: a long role list spans pages
                    r = requests.get(url, headers={"Authorization": f"Bearer {token}"},
                                     params=params, timeout=20)
                    if not r.ok:
                        return {"ok": False, "error": f"{scope_rg}: HTTP {r.status_code} {r.text[:200]}"}
                    body = r.json()
                    perms += body.get("value") or []
                    url, params = body.get("nextLink"), None

                def allowed(action: str) -> bool:
                    a = action.lower()
                    return any(
                        any(fnmatch.fnmatch(a, x.lower()) for x in (p.get("actions") or []))
                        and not any(fnmatch.fnmatch(a, x.lower()) for x in (p.get("notActions") or []))
                        for p in perms
                    )
                for used_by, action in sorted(needed):
                    if not allowed(action):
                        missing.append({"scope": scope_rg, "action": action, "used_by": used_by})
                if scope_rg.lower() == rg.lower():
                    beyond = [a for a in self.BEYOND_RESPONSE if allowed(a)]
            return {"ok": True, "missing": missing, "scopes": [g for g, _ in scopes.values()],
                    "beyond": beyond}
        except Exception as e:
            return {"ok": False, "error": _first_line(e)[:_ERR_MAX]}

    def private_ip_owners(self) -> dict[str, str]:
        """Private IP → VM resource id, for every NIC of the subscription (one paged
        call). The RulePoller attributes a call made FROM a VM (a storage PutBlob, T1041)
        to that VM by its address — such rows name no VM otherwise. Read-only.

        Two VNets can reuse an address (10.0.0.4 in each): an IP held by several VMs is
        left out — the row it appears on stays unattributed, never a guess. The last VM
        listed used to win, and an exfiltration could be pinned on the wrong VM (L21)."""
        if self.dry_run:
            return {}
        self._ensure_clients()
        holders: dict[str, dict[str, str]] = {}          # ip → {lower id: id}
        for nic in self._network.network_interfaces.list_all():
            vm = getattr(getattr(nic, "virtual_machine", None), "id", None)
            if not vm:
                continue
            for ipc in getattr(nic, "ip_configurations", None) or []:
                ip = getattr(ipc, "private_ip_address", None)
                if ip:
                    holders.setdefault(ip, {})[vm.rstrip("/").lower()] = vm
        return {ip: next(iter(vms.values())) for ip, vms in holders.items() if len(vms) == 1}

    def vm_os(self, resource_id: str) -> str:
        """"linux" / "windows" (lowercase os type of the OS disk), "" if unknown."""
        if self.dry_run:
            return ""
        self._ensure_clients()
        rg, vm_name = _parse_vm_resource_id(resource_id)
        vm = self._compute.virtual_machines.get(rg, vm_name)
        return _enum_text(getattr(getattr(vm.storage_profile, "os_disk", None), "os_type", ""))

    def recent_changes(self, resource_uri: str, minutes: int = 60) -> list[str]:
        """Who wrote this resource lately, from the Azure activity log (best effort, a
        few minutes behind). Explains an alert — never used to detect: Azure itself is
        re-read for that."""
        if self.dry_run:
            return []
        try:
            import requests
            from datetime import datetime, timedelta, timezone
            self._ensure_clients()
            since = (datetime.now(timezone.utc) - timedelta(minutes=minutes)).strftime("%Y-%m-%dT%H:%M:%SZ")
            token = self._credential.get_token("https://management.azure.com/.default").token
            url = (f"https://management.azure.com/subscriptions/{self._subscription_id}"
                   "/providers/Microsoft.Insights/eventtypes/management/values")
            r = requests.get(url, headers={"Authorization": f"Bearer {token}"}, timeout=20, params={
                "api-version": "2015-04-01",
                "$filter": f"eventTimestamp ge '{since}' and resourceUri eq '{resource_uri}'",
                "$select": "caller,operationName,eventTimestamp,status",
            })
            out = []
            # Glorfindel's own writes are not the answer to "who changed it".
            own = {os.environ.get(k, "").lower() for k in ("AZURE_CLIENT_ID", "GLORFINDEL_AZURE_CLIENT_ID")} - {""}
            for e in (r.json().get("value") or []) if r.ok else []:
                op = (e.get("operationName") or {}).get("localizedValue") or (e.get("operationName") or {}).get("value", "")
                st = (e.get("status") or {}).get("value", "")
                # One line per write: the activity log has Started/Accepted AND Succeeded.
                if st != "Succeeded" or str(e.get("caller", "")).lower() in own:
                    continue
                out.append(f'{str(e.get("eventTimestamp", ""))[11:19]} {e.get("caller", "?")} — {op}')
            return sorted(set(out))[-5:]
        except Exception:
            return []

    # ── Audit / readiness checks ───────────────────────────────────────────────

    def check_nsg_access(self, resource_id: str) -> dict:
        """Verify NSG read access — proxy for isolate_vm / block_suspicious_ip readiness.

        Enumerates EVERY NIC's governing NSG (`nsgs`), so the War Room shows the full
        multi-NIC NSG picture at rest (not just the primary NIC). `nsg`/`scope` mirror
        the first NIC for back-compat.
        """
        if self.dry_run:
            return {"ok": True, "nsg": "dry_run"}
        try:
            self._ensure_clients()
            rg, vm_name = _parse_vm_resource_id(resource_id)
            targets = self._get_vm_nic_targets(rg, vm_name)
            nsgs = [
                {
                    "nsg": f'{t["nsg_rg"]}/{t["nsg_name"]}',
                    "nsg_scope": t["scope"],
                    "nic_id": t["nic_id"],
                    "ips": t["private_ips"],
                }
                for t in targets
            ]
            first = targets[0]
            # rule count on the primary NIC's NSG (cheap signal that we can read it)
            rules = list(self._network.security_rules.list(first["nsg_rg"], first["nsg_name"]))
            return {
                "ok": True,
                "nsg": f'{first["nsg_rg"]}/{first["nsg_name"]}',
                "scope": first["scope"],
                "rules": len(rules),
                "nsgs": nsgs,
                "precedence": self._precedence_issues(targets),
            }
        except Exception as e:
            return {"ok": False, "iam": _is_iam_error(str(e)), "error": str(e)}

    def _precedence_issues(self, targets: list[dict]) -> list[dict]:
        """ALLOW rules that would be evaluated BEFORE the deny Glorfindel would place —
        found at rest, before any incident (audit readiness).

        Isolation: on every NSG — since L3 the deny takes the first free priority from
        100, so a customer rule at 100 on a dedicated NSG comes first too (this check
        still assumed "a dedicated NSG gets 100"). Block: the deny starts at 200 on every
        NSG, and the attacker is unknown yet, so any allow that admits SOME internet
        source to the VM counts (bench: allow-ssh at 100).
        """
        issues: list[dict] = []
        cache: dict = {}
        for t in targets:
            rules = self._list_rules(cache, t["nsg_rg"], t["nsg_name"])
            where = {"nsg": f'{t["nsg_rg"]}/{t["nsg_name"]}', "nic": t["nic_short"]}
            if rules is None:
                issues.append({**where, "unreadable": True})
                continue
            used = {r.priority for r in rules if isinstance(getattr(r, "priority", None), int)}
            ips = t["private_ips"] or None
            iso = next((p for p in range(self.ISOLATION_PRIORITY, 4000) if p not in used), None)
            if iso is not None:
                issues += [{**s, **where, "action": "isolate_vm"} for s in _shadowing_rules(
                    rules, iso, inbound_src=None, inbound_dst=ips,
                    outbound_src=ips, outbound_dst=None)]
            blk = next((p for p in range(200, 4000, 10) if p not in used), None)
            if blk is not None:
                issues += [{**s, **where, "action": "block_suspicious_ip"} for s in _shadowing_rules(
                    rules, blk, inbound_src="public", inbound_dst=ips,
                    outbound_src=ips, outbound_dst="public")]
        return issues

    def list_nsgs(self) -> list[dict]:
        """Enumerate ALL NSGs as resources — the true network-control inventory.

        The per-VM audit (check_nsg_access) UNDER-counts the inventory: it reports one
        NSG per NIC and so misses (1) a subnet NSG when the NIC also has its own NSG
        (a NIC is governed by BOTH), (2) an NSG on an AKS subnet (the cluster isn't
        audited as a VM), (3) NSGs of powered-off / evicted VMs. Listing NSG resources
        directly gives the complete set, each with its associations (subnets/NICs), its
        rule count, and whether it carries a Glorfindel restriction (a `glorfindel-*`
        rule = an active isolation/block).

        Each NSG also carries `vms` — the resource_ids of the VMs it governs (NIC-level
        OR subnet-level), resolved from one network-interfaces enumeration. The War Room
        uses it to (a) flag NSGs whose VMs aren't monitored (not in the LAW = a coverage
        blind spot) and (b) glow the associated VM card(s) on hover. Read-only.
        """
        if self.dry_run:
            return []
        self._ensure_clients()

        # NIC → VM and subnet → {VMs} maps, so each NSG can be attributed to the VMs it
        # governs (NIC association OR subnet association). One list_all over NICs — best
        # effort: if it fails, NSGs are still listed, just without `vms`.
        nic_to_vm: dict[str, str] = {}
        subnet_to_vms: dict[str, set] = {}
        try:
            for nic in self._network.network_interfaces.list_all():
                vm_id = getattr(getattr(nic, "virtual_machine", None), "id", None)
                if not vm_id:
                    continue
                nic_to_vm[nic.id.lower()] = vm_id
                for cfg in (nic.ip_configurations or []):
                    sub = getattr(getattr(cfg, "subnet", None), "id", None)
                    if sub:
                        subnet_to_vms.setdefault(sub.lower(), set()).add(vm_id)
        except Exception:
            pass

        out: list[dict] = []
        for nsg in self._network.network_security_groups.list_all():
            rg, name = _parse_nsg_resource_id(nsg.id)
            rules = list(nsg.security_rules or [])
            glor = [r for r in rules if (getattr(r, "name", "") or "").startswith("glorfindel-")]
            nic_ids = [n.id for n in (nsg.network_interfaces or [])]
            subnet_ids = [s.id for s in (nsg.subnets or [])]
            vms: set = set()
            for nid in nic_ids:
                vm = nic_to_vm.get(nid.lower())
                if vm:
                    vms.add(vm)
            for sid in subnet_ids:
                vms |= subnet_to_vms.get(sid.lower(), set())
            # The quarantine NSG carries Glorfindel's rules by construction: on standby
            # (attached to nothing) it restricts nothing — it did read as "restricted".
            quarantine = _is_quarantine_nsg(name)
            attached = bool(nic_ids or subnet_ids)
            out.append({
                "nsg": f"{rg}/{name}",
                "id": nsg.id,
                # Associations: a subnet-level NSG has subnets[], a NIC-level NSG has
                # network_interfaces[]. A shared NSG can have both / several.
                "subnets": subnet_ids,
                "nics": nic_ids,
                "vms": sorted(vms),                # VM resource_ids this NSG governs
                "rules": len(rules),
                "restricted": bool(glor) and (attached or not quarantine),  # an active Glorfindel rule
                "glorfindel_rules": len(glor),
                "quarantine": quarantine,
            })
        return out

    def check_compute_access(self, resource_id: str) -> dict:
        """Verify VM + disk read access — snapshot readiness."""
        if self.dry_run:
            return {"ok": True, "dry_run": True}
        try:
            self._ensure_clients()
            rg, vm_name = _parse_vm_resource_id(resource_id)
            vm = self._compute.virtual_machines.get(rg, vm_name)
            disks = []
            if vm.storage_profile.os_disk.managed_disk:
                disks.append(vm.storage_profile.os_disk.managed_disk.id.split("/")[-1])
            disks += [
                d.managed_disk.id.split("/")[-1]
                for d in vm.storage_profile.data_disks
                if d.managed_disk
            ]
            return {"ok": True, "vm": vm_name, "disks": disks}
        except Exception as e:
            return {"ok": False, "iam": _is_iam_error(str(e)), "error": str(e)}


def _turned_allows(nsgs) -> list[tuple[str, set, str, str, list]]:
    """Our rules, by their names, that someone turned into an allow (I5Q, #327): for
    each, its NSG, the subnets that NSG governs, the side of the NIC it protects
    ("destination" inbound, "source" outbound), its name, its addresses on that side."""
    out = []
    for nsg in nsgs:
        subnets = {s.id.rstrip("/").lower() for s in (getattr(nsg, "subnets", None) or []) if getattr(s, "id", None)}
        for r in (getattr(nsg, "security_rules", None) or []):
            name = getattr(r, "name", "") or ""
            if (not name.lower().startswith(("glorfindel-iso-", "glorfindel-block-"))
                    or _enum_text(getattr(r, "access", "")) != "allow"):
                continue
            side = "destination" if _enum_text(getattr(r, "direction", "")) == "inbound" else "source"
            single = getattr(r, f"{side}_address_prefix", None)
            values = ([single] if single else []) + list(getattr(r, f"{side}_address_prefixes", None) or [])
            out.append((nsg.id.rstrip("/").lower(), subnets, side, name, values))
    return out


def _takes_in(values: list, ip: str) -> bool:
    """An address field that takes `ip` in: empty, `*`, the address, a prefix holding
    it — or a tag, read as taking it in (the safe side: the deny stays)."""
    import ipaddress
    for v in [v for v in values if v] or ["*"]:
        if v == "*":
            return True
        try:
            if ipaddress.ip_address(ip) in ipaddress.ip_network(v, strict=False):
                return True
        except ValueError:
            return True                       # a tag (VirtualNetwork…): the safe side
    return False


def _behind_turned(cut: list[dict], side: str, turned: list, nic_nsg: dict, nic_subnets: dict) -> str:
    """Why a deny of a NIC that no longer exists, cutting these NICs off, stays (I5Q,
    #327): one of our rules someone turned into an allow, on the same side, aimed at the
    address of a NIC it cuts, on an NSG that governs that NIC — its own, or its subnet's.
    Taking the deny off would let through what that allow lets pass, which our block
    closes otherwise: the attacker reached a VM given a deleted VM's address and NSG,
    its subnet's perimeter block standing behind the turned rule. The deny stays and is
    said; once the operator puts the turned rule back, or removes it, the watch takes the
    deny off at its next pass. "": none."""
    for h in cut:
        nid = (h.get("nic_id") or "").rstrip("/").lower()
        for nsg_key, subnets, t_side, name, values in turned:
            governs = nic_nsg.get(nid) == nsg_key or bool(nic_subnets.get(nid, set()) & subnets)
            if governs and t_side == side and _takes_in(values, h["ip"]):
                return (f"notre règle {name} ({nsg_key.rsplit('/', 1)[-1]}), retournée en autorisation par "
                        f"quelqu'un, vise {h['ip']} : retirer ce refus laisserait passer ce qu'elle ouvre "
                        "— la remettre en refus, ou la retirer ; la watch retire alors celle-ci")
    return ""


def _turned_guard(network, nsgs: list):
    """The same guard for the writes that take off a deleted VM's denies by their names
    — its release, its unblock (I7S, I5R): a deny that holds back one of our rules turned
    into an allow, for the live NIC that holds its address now, stays (I5Q). Returns
    `why(nsg, rule) -> str` ("" to take it off). The NICs are listed only when a rule
    is turned; a listing that fails raises — nothing found is not nothing there."""
    turned = _turned_allows(nsgs)
    if not turned:
        return lambda nsg, rule, own="": ""
    nic_nsg: dict[str, str] = {}
    nic_subnets: dict[str, set] = {}
    holders: dict[str, str] = {}
    for nic in network.network_interfaces.list_all():
        nid = nic.id.rstrip("/").lower()
        nic_nsg[nid] = (getattr(getattr(nic, "network_security_group", None), "id", None) or "").rstrip("/").lower()
        for cfg in (nic.ip_configurations or []):
            if ip := getattr(cfg, "private_ip_address", None):
                holders[ip] = nid
            if subnet := getattr(getattr(cfg, "subnet", None), "id", None):
                nic_subnets.setdefault(nid, set()).add(subnet.rstrip("/").lower())

    def why(nsg, rule, own: str = "") -> str:
        # `own`: the NIC the rule was written for; holding the address, nothing waits.
        if _enum_text(getattr(rule, "access", "")) != "deny":
            return ""
        side = "destination" if _enum_text(getattr(rule, "direction", "")) == "inbound" else "source"
        single = getattr(rule, f"{side}_address_prefix", None)
        ips = [v for v in ([single] if single else []) + list(getattr(rule, f"{side}_address_prefixes", None) or [])
               if v and v != "*"]
        k = nsg.id.rstrip("/").lower()
        subnets = {s.id.rstrip("/").lower() for s in (getattr(nsg, "subnets", None) or []) if getattr(s, "id", None)}
        cut = [{"ip": ip, "nic_id": holders[ip]} for ip in ips
               if ip in holders and holders[ip] != own.rstrip("/").lower()
               and (nic_nsg.get(holders[ip]) == k or nic_subnets.get(holders[ip], set()) & subnets)]
        return _behind_turned(cut, side, turned, nic_nsg, nic_subnets)
    return why


def _held_by_turned(network, cache: dict, nsg_rg: str, nsg_name: str, name: str, nic_id: str) -> str:
    """Why a rule a release's placement names stays (I5Q): a live NIC other than its own
    holds the address it denies now (its NIC gone), and one of our rules someone turned
    into an allow waits behind it (_turned_guard). The NSGs listed once per release
    (`cache`); unreadable, the rule stays — nothing found is not nothing there. "": take
    it off."""
    try:
        if "why" not in cache:
            nsgs = list(network.network_security_groups.list_all())
            cache["nsgs"] = {tuple(x.lower() for x in _parse_nsg_resource_id(n.id)): n for n in nsgs}
            cache["why"] = _turned_guard(network, nsgs)
        nsg = cache["nsgs"].get((nsg_rg.lower(), nsg_name.lower()))
        rule = next((r for r in (getattr(nsg, "security_rules", None) or [])
                     if (getattr(r, "name", "") or "").lower() == name.lower()), None)
        why = cache["why"](nsg, rule, nic_id) if rule is not None else ""
    except Exception as exc:
        why = f"NSG de l'abonnement illisibles, aucune règle retournée exclue ({_first_line(exc)[:_ERR_MAX]})"
    return f"{nsg_rg}/{nsg_name}/{name} gardée : {why}" if why else ""
