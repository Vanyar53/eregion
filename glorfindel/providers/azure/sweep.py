"""`glorfindel reset`'s sweep of a VM's rules, and the orphan rules no NIC owns any
more (moved from actions.py, A1).
"""
from __future__ import annotations

from glorfindel.providers.azure.nsg import _nic_hash, _nic_owns, _rule_name
from glorfindel.providers.azure.sdk import _enum_text
from glorfindel.response.ids import _parse_vm_resource_id, _same_id
from glorfindel.response.policy import _ERR_MAX, _first_line
from glorfindel.response.state import (
    _clear_block_state,
    _clear_isolation_state,
    _held_in_quarantine,
    _load_block_entries,
    _load_isolation_state,
    _recorded_original,
    _save_isolation_state,
    _UNKNOWN,
    _update_block_entry,
)


class SweepMixin:
    """Reset and orphan rules (part of AzureConnector)."""

    def sweep_vm_rules(self, resource_id: str, dry_run: bool = False) -> dict:
        """Azure as the source of truth: remove every glorfindel-* rule that belongs to
        THIS VM on the NSGs of its NICs, with or without local state.

        Ownership comes from the deterministic rule names: the per-(VM, NIC) isolation
        and block names (readable or hashed form) and the legacy VM-suffixed ones; the
        legacy fixed isolation names only on an NSG governing this VM alone. The IP
        segment of a block name anchors the match, so `web` never matches `app-web`.
        Kept: perimeter (subnet-wide) blocks — an operator decision covering every VM —
        and every non-glorfindel rule. Customer rules bumped by an isolation can't be
        put back without state: reported, not guessed.
        """
        if not dry_run:
            self._guard_write("reset")
            # Intent first, as release_isolation and unblock_ip do: a reset cut off midway
            # (a crash, a timeout) is a release under way, not an isolation "removed
            # outside Glorfindel" for the reassertion to put back (A0, I9).
            from datetime import datetime, timezone
            now = datetime.now(timezone.utc).isoformat()
            state = _load_isolation_state(resource_id)
            if state:
                _save_isolation_state(resource_id, {**state, "releasing_at": now})
            for e in _load_block_entries(resource_id):
                if e.get("ip"):
                    _update_block_entry(resource_id, e["ip"], unblocking_at=now)
        self._ensure_clients()
        import hashlib
        import re
        rg, vm_name = _parse_vm_resource_id(resource_id)
        block_re = re.compile(r"^glorfindel-block-\d{1,3}(?:-\d{1,3}){3}(?:-\d{1,2})?-(?P<rest>.+?)(?:-out)?$")
        to_delete: list[tuple[str, str, str]] = []
        kept: list[str] = []
        unreadable: list[str] = []
        seen: set = set()
        targets = self._get_vm_nic_targets(rg, vm_name, allow_no_nsg=True)
        own_state = _load_isolation_state(resource_id) or {}
        legacy_named: dict[tuple, set] = {}
        if "placements" not in own_state and own_state.get("nsg_name"):
            legacy_named[((own_state.get("nsg_rg") or rg).lower(), own_state["nsg_name"].lower())] = {
                n.lower() for n in own_state.get("rule_names", [])}
        quarantined = [t0 for t0 in targets if t0.get("quarantine")]
        unreadable += [f'{t0["nic_short"]}: NSG du subnet illisible' for t0 in targets if t0.get("subnet_unreadable")]
        originals: dict[str, str | None] = {}
        views = [v for t0 in targets for v in self._nic_nsg_views(t0)]
        failed_early: list[str] = []
        for t0 in quarantined:
            try:
                # The local state first, when there is one, then our tag — as the release
                # does. From the tag only, a reset with the state in hand stopped on an
                # original it knew (L27).
                original = _recorded_original(t0["nic_id"])
                if original is _UNKNOWN:
                    original = self._original_from_tags(t0["quarantine"], t0["nic_id"])
                originals[t0["nic_id"]] = original
            except Exception as exc:
                unreadable.append(f'{t0["nic_short"]}: NSG d\'origine illisible ({_first_line(exc)[:_ERR_MAX]})')
                continue
            if original:
                # Hidden behind the quarantine: its own NSG, where an earlier fallback
                # may have left rules (L24).
                views.append(self._original_view(t0, original))
        # A NIC left bare after our NSG was taken off it: its original comes back below
        # (state first, then our tag — as the release does, L27/L28). Its rules are swept
        # too: an older version's isolation there stayed, and the VM, "swept", was still
        # cut off (A0). From the tag only, a lost tag made the reset skip the NIC, say
        # `swept` and clear the state that knew it (A0, seed 3).
        bare: dict = {}
        for t0 in targets:
            if t0.get("quarantine") or t0.get("own_nsg_id"):
                continue
            recorded = _recorded_original(t0["nic_id"])
            try:
                original, q_bare = self._bare_nic_original(t0, rg)
            except Exception as exc:
                if recorded is _UNKNOWN:
                    failed_early.append(f'{t0["nic_short"]}: tag d\'origine illisible ({_first_line(exc)[:_ERR_MAX]})')
                    continue
                original, q_bare = _UNKNOWN, None
            if recorded is not _UNKNOWN:
                original = recorded
            elif q_bare is None:
                if _held_in_quarantine(t0["nic_id"]):
                    # In quarantine for our state, its original unknown there and no tag:
                    # skipped, the reset said `swept` and cleared the state — the NIC
                    # left bare, an old isolation on its own NSG unrecorded (I8F).
                    failed_early.append(f'{t0["nic_short"]}: carte sans NSG, NSG d\'origine inconnu '
                                        "(ni l'état local ni le tag ne le disent) : la remettre à la main")
                continue
            bare[t0["nic_id"]] = (original, q_bare)
            if original:
                views.append(self._original_view(t0, original))
        for t in views:
            nsg_key = (t["nsg_rg"].lower(), t["nsg_name"].lower())
            h = hashlib.sha1(t["nic_id"].encode()).hexdigest()[:8]
            iso_names = {n.lower() for n in self._isolation_names_for_target(vm_name, t)}
            iso_base = self._placement_rule_base("glorfindel-iso", vm_name, t["nic_short"], t["nic_id"])
            rules = self._list_rules({}, t["nsg_rg"], t["nsg_name"])
            if rules is None:
                # Unreadable: nothing found is not nothing there — keep the local state.
                unreadable.append(f'{t["nsg_rg"]}/{t["nsg_name"]}: règles illisibles')
                continue
            # An older version's state names its rules (as the release reads them); an
            # unowned one of its fixed names can't be attributed — not "swept" (A0).
            unreadable += [u for u in self._unattributable_fixed(t, rules) if u not in unreadable]
            for r in rules:
                name = _rule_name(r)
                if not name.startswith("glorfindel-") or (nsg_key, name.lower()) in seen:
                    continue
                if name.lower() in legacy_named.get(nsg_key, set()):
                    seen.add((nsg_key, name.lower()))
                    to_delete.append((t["nsg_rg"], t["nsg_name"], name))
                    continue
                m = block_re.match(name)
                if m:
                    prefix = name[: m.start("rest") - 1]
                    hashed = self._placement_rule_base(prefix, vm_name, t["nic_short"], t["nic_id"])
                    owned = {f"{prefix}-{x}".lower() for x in (
                        vm_name, f"{vm_name}-{t['nic_short']}", f"{vm_name[:40]}-{h}")}
                    owned = {n for b in owned for n in (b, f"{b}-out")}
                else:
                    hashed, owned = iso_base, iso_names
                # Named for this VM is not enough: a homonym behind the same NSG has the
                # same legacy names — only a rule that applies to THIS NIC goes (L24),
                # unless its name carries this NIC's hash (_nic_owns). A rule of the VM's
                # other NIC waits for that NIC's pass (it used to be marked seen here,
                # and skipped there).
                if _nic_owns(r, {hashed, f"{hashed}-out"}, owned, t.get("private_ips") or None):
                    seen.add((nsg_key, name.lower()))
                    to_delete.append((t["nsg_rg"], t["nsg_name"], name))
                elif m is None and name.startswith("glorfindel-block-"):
                    seen.add((nsg_key, name.lower()))
                    kept.append(f'{t["nsg_rg"]}/{t["nsg_name"]}/{name}')   # perimeter block
        deleted, failed = [], list(unreadable)
        for t0 in quarantined:
            q = t0["quarantine"]
            if t0["nic_id"] not in originals:
                continue                       # original unreadable: the NIC stays in quarantine
            original = originals[t0["nic_id"]]
            label = (f'{t0["nic_short"]}: retirer {q["nsg_name"]}'
                     + (f' (remettre {original.rstrip("/").split("/")[-1]})' if original else ""))
            if dry_run:
                deleted.append(label)
                continue
            try:
                self._unquarantine(t0["nic_id"], q, original)
                deleted.append(label)
            except Exception as exc:
                failed.append(f"{label} : {_first_line(exc)[:_ERR_MAX]}")
        failed += failed_early
        for t0 in targets:
            # A NIC left bare after our NSG was taken off it: our tag says what it
            # carried (seventh review, U2) — or the state (see above).
            if t0["nic_id"] not in bare:
                continue
            original, q_bare = bare[t0["nic_id"]]
            label = (f'{t0["nic_short"]}: carte sans NSG'
                     + (f', remettre {original.rstrip("/").split("/")[-1]}' if original else ""))
            if dry_run:
                deleted.append(label)
                continue
            try:
                if original:
                    self._set_nic_nsg(t0["nic_id"], original)
                    if not _same_id(self._nic_nsg_id(t0["nic_id"]) or "", original):
                        raise RuntimeError("NSG d'origine non remis")
                if q_bare is not None:
                    self._forget_original(q_bare, t0["nic_id"])
                deleted.append(label)
            except Exception as exc:
                failed.append(f"{label} : {_first_line(exc)[:_ERR_MAX]}")
        for nsg_rg, nsg_name, name in to_delete:
            if dry_run:
                deleted.append(f"{nsg_rg}/{nsg_name}/{name}")
                continue
            err = self._delete_rule(nsg_rg, nsg_name, name)
            (failed if err else deleted).append(err or f"{nsg_rg}/{nsg_name}/{name}")
        if not dry_run and not failed:
            _clear_isolation_state(resource_id)
            for entry in _load_block_entries(resource_id):
                _clear_block_state(resource_id, entry.get("ip", ""))
        elif not dry_run:
            # Part of it is gone from Azure, part is unknown: the state is kept, marked as
            # a failed release / unblock — the reassertion leaves that to the operator. Left
            # unmarked, it read "removed outside Glorfindel" and put back what the operator
            # had just asked to remove (L27).
            state = _load_isolation_state(resource_id)
            if state:
                _save_isolation_state(resource_id, {**state, "release_failed": failed})
            for entry in _load_block_entries(resource_id):
                _update_block_entry(resource_id, entry.get("ip", ""), unblock_failed=failed)
        return {
            "status": "dry_run" if dry_run else ("swept_partial" if failed else "swept"),
            "deleted": deleted, "failed": failed, "kept_perimeter": kept,
            "note": "Règles client décalées par une isolation : non restaurées sans état local.",
        }

    def find_orphan_rules(self) -> list[dict]:
        """Glorfindel denies left by a NIC that no longer exists (seventh review, U1).

        A release can't find the rules of a deleted VM without its state: nothing says
        which NSGs to look at. On a shared NSG they stay, aimed at an IP Azure hands to
        the next NIC — which is then cut off. Our names end with the hash of the NIC's id:
        a rule whose hash matches no NIC of the subscription is an orphan. Each one comes
        with the NIC (and VM) that now holds an address it targets, if any. Older names
        (before the hash) can't be told apart and are not reported. Raises if the NICs
        or NSGs can't be listed — no orphan is not the same as unknown."""
        if self.dry_run:
            return []
        self._ensure_clients()
        marks: set[str] = set()
        holders: dict[str, tuple[str, str]] = {}
        for nic in self._network.network_interfaces.list_all():
            nid = nic.id.rstrip("/").lower()
            marks |= {_nic_hash(nid, 6), _nic_hash(nid, 8)}
            vm_id = getattr(getattr(nic, "virtual_machine", None), "id", None) or ""
            for cfg in (nic.ip_configurations or []):
                ip = getattr(cfg, "private_ip_address", None)
                if ip:
                    holders[ip] = (nic.id, vm_id)
        orphans: list[dict] = []
        for nsg in self._network.network_security_groups.list_all():
            for r in (nsg.security_rules or []):
                name = _rule_name(r).lower()
                if (not name.startswith(("glorfindel-iso-", "glorfindel-block-"))
                        or _enum_text(getattr(r, "access", "")) != "deny"):
                    continue
                mark = (name[:-4] if name.endswith("-out") else name).rsplit("-", 1)[-1]
                if len(mark) not in (6, 8) or any(c not in "0123456789abcdef" for c in mark) or mark in marks:
                    continue
                side = "destination" if _enum_text(getattr(r, "direction", "")) == "inbound" else "source"
                single = getattr(r, f"{side}_address_prefix", None)
                ips = [v for v in ([single] if single else []) + list(getattr(r, f"{side}_address_prefixes", None) or [])
                       if v and v != "*"]
                now_on = [{"ip": ip, "nic_id": holders[ip][0], "vm_id": holders[ip][1]}
                          for ip in ips if ip in holders]
                orphans.append({"nsg_id": nsg.id, "rule": _rule_name(r), "ips": ips, "now_on": now_on})
        return orphans
