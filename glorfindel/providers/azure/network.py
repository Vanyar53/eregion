"""NICs and NSGs as Glorfindel reads and writes them: a VM's NIC targets, rule writes
and deletes, rule names, NSG sharing (moved from actions.py, A1).
"""
from __future__ import annotations

import re

from glorfindel.providers.azure.nsg import _nic_hash, _rule_name
from glorfindel.providers.azure.quarantine import _is_quarantine_nsg
from glorfindel.providers.azure.sdk import _is_not_found
from glorfindel.response.ids import _parse_nic_resource_id, _parse_nsg_resource_id, _same_id
from glorfindel.response.policy import _ERR_MAX, _first_line

# A VM block's name before the VM was in it: the attacker's address alone (an older
# version's, on an NSG it took for the VM's own; on a subnet's, a perimeter block).
_PLAIN_BLOCK = re.compile(r"^glorfindel-block-\d{1,3}(?:-\d{1,3}){3}(?:-\d{1,2})?(?:-out)?$")


def _fixed_name(name: str, isolation_name: str) -> bool:
    """A rule name with no VM in it — an older version's isolation or block: whose it
    is depends on whose NSG it is (_isolation_pairs, _block_names_for_target)."""
    low = (name or "").lower()
    return low in (isolation_name.lower(), f"{isolation_name}-out".lower()) or bool(_PLAIN_BLOCK.match(low))


class NetworkMixin:
    """Reads and writes on NICs and NSGs (part of AzureConnector)."""

    def _put_deny_rule(
        self, nsg_rg: str, nsg_name: str, name: str, direction: str, priority: int,
        *, src=None, srcs=None, dst=None, dsts=None,
    ) -> None:
        """Create/update a Deny security rule. Use srcs/dsts (lists, augmented rule) to
        cover several IPs in one rule; src/dst for a single prefix like '*'."""
        from azure.mgmt.network.models import SecurityRule
        kwargs = dict(
            name=name, protocol="*",
            source_port_range="*", destination_port_range="*",
            access="Deny", priority=priority, direction=direction,
        )
        if srcs is not None:
            kwargs["source_address_prefixes"] = srcs
        else:
            kwargs["source_address_prefix"] = src
        if dsts is not None:
            kwargs["destination_address_prefixes"] = dsts
        else:
            kwargs["destination_address_prefix"] = dst
        self._network.security_rules.begin_create_or_update(
            nsg_rg, nsg_name, name, SecurityRule(**kwargs)
        ).result()

    def _delete_rule(self, nsg_rg: str, nsg_name: str, rule_name: str) -> str | None:
        """Delete one security rule. None on success or if it was already gone; else a
        short description of the failure (the rule may still be in place)."""
        try:
            self._network.security_rules.begin_delete(nsg_rg, nsg_name, rule_name).result()
            return None
        except Exception as e:
            if _is_not_found(e):
                return None
            return f"{nsg_rg}/{nsg_name}/{rule_name}: {_first_line(e)[:_ERR_MAX]}"

    def _restore_bumped(self, nsg_rg: str, nsg_name: str, bumped: list[dict]) -> list[dict]:
        """Put customer rules back on their original priority. Returns the ones that
        could not be restored (kept in state so a later release can retry)."""
        left: list[dict] = []
        for info in bumped:
            try:
                r = self._network.security_rules.get(nsg_rg, nsg_name, info["name"])
                r.priority = info["original_priority"]
                self._network.security_rules.begin_create_or_update(nsg_rg, nsg_name, r.name, r).result()
            except Exception as e:
                if _is_not_found(e):
                    continue  # its owner deleted it meanwhile — nothing to put back
                left.append({**info, "error": _first_line(e)[:_ERR_MAX]})
        return left

    def _list_rules(self, cache: dict, nsg_rg: str, nsg_name: str) -> list | None:
        """Security rules of an NSG, listed once per verification. None if unreadable:
        an empty list would read as "nothing precedes our deny" (fail open). An NSG that
        no longer exists (404) has no rules: empty — a block on an NSG the customer
        deleted read as "unreadable" forever, never as gone (A0, L1)."""
        key = (nsg_rg, nsg_name)
        if key not in cache:
            try:
                cache[key] = list(self._network.security_rules.list(nsg_rg, nsg_name))
            except Exception as exc:
                cache[key] = [] if _is_not_found(exc) else None
        return cache[key]

    def _rule_state(self, nsg_rg: str, nsg_name: str, name: str) -> str:
        """'present' | 'absent' | 'unknown' (the read itself failed)."""
        try:
            self._network.security_rules.get(nsg_rg, nsg_name, name)
            return "present"
        except Exception as e:
            return "absent" if _is_not_found(e) else "unknown"

    def _rules_present(self, nsg_rg: str, nsg_name: str, names: list[str]) -> bool:
        """True if all named rules exist on the NSG."""
        return self._rules_state(nsg_rg, nsg_name, names) == "present"

    def _rules_state(self, nsg_rg: str, nsg_name: str, names: list[str]) -> str:
        """'present' (all there) | 'absent' (one is definitely gone) | 'unknown' (a read
        failed). A read error used to count as "missing": the reassertion then put back
        an isolation that was still in place, and alerted that it had been removed."""
        states = [self._rule_state(nsg_rg, nsg_name, n) for n in names]
        if "absent" in states:
            return "absent"
        return "unknown" if "unknown" in states else "present"

    def _get_primary_nic_id(self, rg: str, vm_name: str) -> str:
        vm = self._compute.virtual_machines.get(rg, vm_name)
        nics = vm.network_profile.network_interfaces
        primary = next((n for n in nics if n.primary), nics[0])
        return primary.id

    def _get_vm_nic_targets(self, rg: str, vm_name: str, allow_no_nsg: bool = False) -> list[dict]:
        """Every NIC of the VM with its governing NSG + all private IPs.

        Isolation must cover EVERY NIC: a VM with 2 NICs each behind its own NSG is
        only half-isolated if we touch the primary alone (the real bug). Each target
        becomes one placement — deny any/any on a NIC-level NSG (scope 'nic') or deny
        scoped to ALL the NIC's private IPs on a shared subnet NSG (scope 'subnet').

        Glorfindel's own quarantine NSG (L4) is not the NIC's NSG: a NIC carrying it is
        described as it is without it (`nic_has_nsg` False, its subnet's NSG as the
        governing one) and the quarantine NSG is reported apart (`quarantine`) — a block
        must not land in an NSG that leaves with the isolation.

        allow_no_nsg: a NIC with no NSG at all (neither its own nor its subnet's) is
        returned with scope 'none' instead of raising — isolation can still attach the
        quarantine NSG to it.
        """
        vm = self._compute.virtual_machines.get(rg, vm_name)
        targets: list[dict] = []
        for ref in vm.network_profile.network_interfaces:
            nic_id = ref.id
            nic_rg, nic_name = _parse_nic_resource_id(nic_id)
            nic = self._network.network_interfaces.get(nic_rg, nic_name)
            own_id = getattr(getattr(nic, "network_security_group", None), "id", None)
            quarantine = None
            if own_id and _is_quarantine_nsg(own_id) and self._managed_by_glorfindel(own_id):
                q_rg, q_name = _parse_nsg_resource_id(own_id)
                quarantine = {"nsg_rg": q_rg, "nsg_name": q_name, "nsg_id": own_id}
                own_id = None
            try:
                subnet_nsg, subnet_unreadable = self._subnet_nsg_of(nic), False
            except Exception:
                # Unknown, not "none": every reader that would conclude from its absence
                # (release, verify_release, verify_isolation, reset) checks this flag.
                subnet_nsg, subnet_unreadable = None, True
            alt_nsg = None
            if own_id:
                nsg_rg, nsg_name = _parse_nsg_resource_id(own_id)
                scope = "nic"
                if subnet_nsg and subnet_nsg != (nsg_rg, nsg_name):
                    alt_nsg = {"nsg_rg": subnet_nsg[0], "nsg_name": subnet_nsg[1]}
            elif subnet_nsg:
                (nsg_rg, nsg_name), scope = subnet_nsg, "subnet"
            elif allow_no_nsg:
                nsg_rg, nsg_name, scope = None, None, "none"
            else:
                raise RuntimeError(f"NIC {nic_name} and its subnet have no NSG — cannot isolate VM")
            sharing = self._nsg_sharing(nsg_rg, nsg_name) if scope == "nic" else False
            shared = sharing is not False
            ips = [getattr(c, "private_ip_address", None) for c in (getattr(nic, "ip_configurations", None) or [])]
            targets.append({
                "nic_id": nic_id,
                "nic_short": nic_id.rstrip("/").split("/")[-1],
                "nsg_rg": nsg_rg,
                "nsg_name": nsg_name,
                "scope": scope,
                # A NIC-level NSG attached to other NICs (or to a subnet as well) is as
                # shared as a subnet NSG: any/any there would cut off every VM behind it.
                "shared_nsg": shared,
                # Unreadable: placed as shared (safe), but an older version's fixed-name
                # rule there can't be told apart — see _unattributable_fixed.
                **({"sharing_unknown": True} if sharing is None else {}),
                "ip_scoped": scope in ("subnet", "none") or shared,
                "private_ips": [ip for ip in ips if ip],
                # The subnet's NSG when the NIC also has its own: the other place a deny
                # holds (traffic must pass both).
                "alt_nsg": alt_nsg,
                "nic_has_nsg": bool(own_id),
                "own_nsg_id": own_id,
                "subnet_unreadable": subnet_unreadable,
                # Its own NSG is its subnet's too: a plain-named block there may be a
                # perimeter block — said so when it is left (ISU, #264).
                **({"subnet_nsg_too": True} if own_id and subnet_nsg and tuple(
                    x.lower() for x in subnet_nsg) == (nsg_rg.lower(), nsg_name.lower()) else {}),
                "quarantine": quarantine,
                "location": getattr(nic, "location", None),
            })
        return targets

    def _subnet_nsg_of(self, nic) -> tuple[str, str] | None:
        """(rg, name) of the NSG on the NIC's subnet, or None when the subnet has none.
        A failed read RAISES: it used to read as "no NSG", and a release without state,
        hit by a 429 there, swept nothing and said released (L24)."""
        try:
            subnet_id = nic.ip_configurations[0].subnet.id
            parts = subnet_id.split("/")
            sub_rg = parts[parts.index("resourceGroups") + 1]
            vnet = parts[parts.index("virtualNetworks") + 1]
        except Exception:
            return None                       # no IP configuration or subnet to read
        subnet = self._network.subnets.get(sub_rg, vnet, parts[-1])
        if subnet.network_security_group is None:
            return None
        return _parse_nsg_resource_id(subnet.network_security_group.id)

    def _set_nic_nsg(self, nic_id: str, nsg_id: str | None, expect: str | None = None) -> bool:
        """Attach `nsg_id` to the NIC (None: detach). With `expect`, only when the NIC
        currently carries that NSG (never touch an NSG that isn't ours). Returns True
        if the NIC was changed."""
        from azure.mgmt.network.models import NetworkSecurityGroup
        nic_rg, nic_name = _parse_nic_resource_id(nic_id)
        nic = self._network.network_interfaces.get(nic_rg, nic_name)
        current = getattr(getattr(nic, "network_security_group", None), "id", None)
        if expect is not None and not _same_id(current or "", expect):
            return False
        nic.network_security_group = NetworkSecurityGroup(id=nsg_id) if nsg_id else None
        self._network.network_interfaces.begin_create_or_update(nic_rg, nic_name, nic).result()
        return True

    def _nsg_is_shared(self, nsg_rg: str, nsg_name: str) -> bool:
        """True if this NSG governs more than one NIC, or a subnet too.

        Azure lets one NSG be attached to several NICs and subnets at once (the common
        "one NSG per tier" layout). Treating such an NSG as "this VM only" put an
        any/any deny on it: an autonomous isolation then cut off every VM sharing it.
        Unreadable association → shared: the IP-scoped placement only ever touches the
        target's own IPs, so it is the safe default.
        """
        return self._nsg_sharing(nsg_rg, nsg_name) is not False

    def _nsg_sharing(self, nsg_rg: str, nsg_name: str, away_nic: str | None = None) -> bool | None:
        """True / False, or None when the NSG's associations can't be read.

        away_nic: a NIC that belongs behind this NSG but isn't attached right now (in
        quarantine, or bare): it counts as one of the NSG's. Counted only from what is
        attached, the NSG of a NIC away read as governing one NIC — another VM's — and
        the reset took an older version's fixed-name isolation of that VM for its own
        (I4F, #235). Another VM's NIC away from it counts too (_tied_while_away, I4S)."""
        try:
            nsg = self._network.network_security_groups.get(nsg_rg, nsg_name)
        except Exception:
            return None
        nics = list(getattr(nsg, "network_interfaces", None) or [])
        subnets = list(getattr(nsg, "subnets", None) or [])
        if away_nic and not any(_same_id(getattr(n, "id", "") or "", away_nic) for n in nics):
            nics.append(away_nic)
        if len(nics) < 2 and not subnets:
            away = self._tied_while_away(nsg, [n if isinstance(n, str) else getattr(n, "id", "") or "" for n in nics])
            if away is not False:
                return away                   # another VM's NIC away from it (I4S), or unknown
        return len(nics) > 1 or len(subnets) > 0

    def _tied_while_away(self, nsg, counted: list[str]) -> bool | None:
        """True when a NIC not in `counted` belongs behind this NSG while it is away from
        it — in our quarantine, or left bare —: our tag on the quarantine NSG names this
        NSG as its original, or, its tag lost, the local state does. None when that can't
        be read — a listing, or a local state (SEC4b): unknown, the fixed names are left and said (_unattributable_fixed).

        Counted from what is attached, the NSG of a VM away in quarantine read as the
        new VM's alone there, and its reset took the older version's isolation of the
        other VM for its own (I4S, #239; I4F was the NIC of the reset itself). Read only
        when the NSG holds a fixed name (an older version's, no VM in it): only then does
        it matter whose NSG this is — every rule placed since is scoped to its NIC."""
        if not any(_fixed_name(_rule_name(r), self.ISOLATION_RULE_NAME)
                   for r in (getattr(nsg, "security_rules", None) or [])):
            return False
        from glorfindel.response.state import _unreadable_isolations, active_isolations
        nsg_id = getattr(nsg, "id", "") or ""
        mine = {self._orig_tag(n) for n in counted if n}

        def names_this(original) -> bool:
            return isinstance(original, str) and _same_id(original, nsg_id)

        try:
            listing = list(self._network.network_security_groups.list_all())
        except Exception:
            return None
        tied: set[str] = set()                # NICs (by their tag's key) whose original is this NSG
        held: set[str] = set()                # NICs in our quarantine now
        for q in listing:
            tags = getattr(q, "tags", None) or {}
            if not _is_quarantine_nsg(getattr(q, "id", "") or "") or tags.get("managed-by") != "glorfindel":
                continue
            held |= {self._orig_tag(n.id) for n in (getattr(q, "network_interfaces", None) or [])
                     if getattr(n, "id", None)}
            tied |= {tag for tag, value in tags.items() if tag.startswith("glorfindel-orig-") and names_this(value)}
        # The local state says it too — the tag lost, it still does.
        tied |= {self._orig_tag(p["nic_id"]) for iso in active_isolations() for p in iso.get("placements") or []
                 if p.get("kind") == "quarantine" and p.get("nic_id") and names_this(p.get("original_nsg_id"))}
        tied -= mine
        if tied & held:
            return True
        if _unreadable_isolations():
            return None                       # a state that can't be read may tie one (SEC4b)
        if not tied:
            return False
        # Tied to this NSG, not in our quarantine: left bare (our NSG taken off it, the
        # tag kept until its original is back), or a stale record — a NIC gone since, or
        # given back an NSG outside Glorfindel. Only the bare one is away.
        try:
            for n in self._network.network_interfaces.list_all():
                now = getattr(getattr(n, "network_security_group", None), "id", None)
                if self._orig_tag(n.id) in tied and (now is None or _is_quarantine_nsg(now)):
                    return True
        except Exception:
            return None
        return False

    def _get_nic_private_ips(self, nic_id: str) -> list[str]:
        """All private IPs across a NIC's ipConfigurations (a NIC can have several).

        An NSG applies to the whole NIC, not per ipConfig, so a subnet-scoped deny must
        address every private IP of the NIC or a secondary IP stays reachable.
        """
        nic_rg, nic_name = _parse_nic_resource_id(nic_id)
        nic = self._network.network_interfaces.get(nic_rg, nic_name)
        ips = [
            getattr(c, "private_ip_address", None)
            for c in (nic.ip_configurations or [])
        ]
        return [ip for ip in ips if ip]

    def _block_rule_name(self, ip: str, vm_name: str, scope: str) -> str:
        """Base name for a block rule. VM-suffixed on a shared subnet NSG so blocks
        scoped to different VMs (same attacker IP) don't collide."""
        base = f"glorfindel-block-{ip.replace('.', '-').replace('/', '-')}"
        return f"{base}-{vm_name}" if scope == "subnet" else base

    def _placement_rule_base(self, prefix: str, vm_name: str, nic_short: str, nic_id: str) -> str:
        """A rule-name base unique per NIC, within Azure's 80-char limit (with '-out').

        Unique by the hash of the NIC's id, not only by names: two VMs named alike in
        two resource groups, with NICs named alike, behind one NSG (a hub subnet, a
        "tier" NSG) got the same name — isolating one rewrote the other's rule, and the
        other's verification found it by name (L24). Lowercase: the canonical id and
        Log Analytics' lowercase one give one name."""
        base = f"{prefix}-{vm_name}-{nic_short}-{_nic_hash(nic_id, 6)}"
        if len(base) + 4 > 80:
            room = max(80 - 4 - len(prefix) - 2 - 8, 1)
            base = f"{prefix}-{vm_name[:room]}-{_nic_hash(nic_id, 8)}"
        return base.lower()

    def _placement_rule_bases(self, prefix: str, vm_name: str, nic_short: str, nic_id: str) -> tuple[str, str]:
        """The NIC's rule-name base, then its second (I4A): a block is written under the
        second only when its first pair is held by a rule someone turned into an allow,
        aimed at an address that is no longer the NIC's — another VM's now, or nobody
        knows: rewritten, it changed that VM's flows. Same mark at the end (the NIC's
        hash): whatever reads our rules by it reads both."""
        base = self._placement_rule_base(prefix, vm_name, nic_short, nic_id)
        head, mark = base.rsplit("-", 1)
        return base, f"{head[:80 - 4 - 3 - len(mark)]}-b-{mark}"

    @staticmethod
    def _legacy_rule_base(prefix: str, vm_name: str, nic_short: str, nic_id: str) -> str:
        """The name before the NIC hash (isolations and blocks placed before L24)."""
        base = f"{prefix}-{vm_name}-{nic_short}"
        if len(base) + 4 > 80:
            import hashlib
            base = f"{prefix}-{vm_name[:40]}-{hashlib.sha1(nic_id.encode()).hexdigest()[:8]}"
        return base

    def _get_nic_nsg(self, nic_id: str) -> tuple[str, str, str]:
        """Resolve the NSG governing a NIC. Returns (rg, name, scope).

        scope is "nic" (NSG attached to the NIC — rule affects only this VM) or
        "subnet" (fallback: NSG on the subnet — ⚠ rule affects EVERY VM on the
        subnet, not just this one). Callers acting on the NSG (isolate/block) must
        surface "subnet" so the blast radius is visible — a subnet-level deny-all
        isolates the whole subnet, not the single VM.
        """
        nic_rg, nic_name = _parse_nic_resource_id(nic_id)
        nic = self._network.network_interfaces.get(nic_rg, nic_name)

        # NIC-level NSG (preferred — scoped to this VM)
        if nic.network_security_group is not None:
            rg, name = _parse_nsg_resource_id(nic.network_security_group.id)
            return rg, name, "nic"

        # Fallback: subnet-level NSG (shared — affects all VMs on the subnet)
        subnet_id = nic.ip_configurations[0].subnet.id
        # /subscriptions/.../virtualNetworks/<vnet>/subnets/<subnet>
        parts = subnet_id.split("/")
        sub_rg = parts[parts.index("resourceGroups") + 1]
        vnet = parts[parts.index("virtualNetworks") + 1]
        subnet_name = parts[-1]
        subnet = self._network.subnets.get(sub_rg, vnet, subnet_name)
        if subnet.network_security_group is None:
            raise RuntimeError(f"NIC {nic_name} and its subnet have no NSG — cannot isolate VM")
        rg, name = _parse_nsg_resource_id(subnet.network_security_group.id)
        return rg, name, "subnet"

    def _get_subnet_nsg(self, nic_id: str) -> tuple[str, str]:
        """Resolve the NSG on the NIC's SUBNET (always the subnet's, ignoring any NIC
        NSG). Used for a deliberate subnet-wide block. Raises if the subnet has no NSG
        (then a subnet-wide block isn't possible without per-NIC propagation)."""
        nic_rg, nic_name = _parse_nic_resource_id(nic_id)
        nic = self._network.network_interfaces.get(nic_rg, nic_name)
        subnet_id = nic.ip_configurations[0].subnet.id
        parts = subnet_id.split("/")
        sub_rg = parts[parts.index("resourceGroups") + 1]
        vnet = parts[parts.index("virtualNetworks") + 1]
        subnet_name = parts[-1]
        subnet = self._network.subnets.get(sub_rg, vnet, subnet_name)
        if subnet.network_security_group is None:
            raise RuntimeError(
                f"Subnet {subnet_name} has no NSG — subnet-wide block not available "
                "(NSGs are per-NIC; would require propagating to each NIC)."
            )
        return _parse_nsg_resource_id(subnet.network_security_group.id)

    def _nic_nsg_id(self, nic_id: str) -> str | None:
        nic_rg, nic_name = _parse_nic_resource_id(nic_id)
        nic = self._network.network_interfaces.get(nic_rg, nic_name)
        return getattr(getattr(nic, "network_security_group", None), "id", None)

    def _nic_gone(self, nic_id: str) -> bool:
        """True only when the NIC itself no longer exists (deleted with its VM)."""
        try:
            self._nic_nsg_id(nic_id)
            return False
        except Exception as e:
            return _is_not_found(e)

    @staticmethod
    def _nic_nsg_views(t: dict) -> list[dict]:
        """The NIC as seen from each NSG that governs it: its own (or its subnet's when it
        has none), plus its subnet's NSG when it has both. An isolation or a block may
        sit on either — the second one when the first had an ALLOW before our deny."""
        views = [t] if t.get("nsg_name") else []
        alt = t.get("alt_nsg")
        if alt:
            views.append({**t, "nsg_rg": alt["nsg_rg"], "nsg_name": alt["nsg_name"],
                          "scope": "subnet", "shared_nsg": False, "ip_scoped": True})
        return views
