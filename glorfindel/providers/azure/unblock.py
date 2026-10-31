"""unblock_ip, including behind the quarantine (moved from actions.py, A1;
verify_block_ip in verify_block.py since I4B).
"""
from __future__ import annotations

from glorfindel.providers.azure.nsg import (
    _deny_applies,
    _ip_scoped,
    _nic_hash,
    _nic_owns,
    _rule_name,
)
from glorfindel.providers.azure.quarantine import OriginalUnknown
from glorfindel.providers.azure.sdk import _is_not_found
from glorfindel.providers.azure.turned import _aims_elsewhere, _held_by_turned
from glorfindel.response.ids import _parse_nsg_resource_id, _parse_vm_resource_id
from glorfindel.response.policy import _ERR_MAX, _first_line
from glorfindel.response.state import (
    _clear_block_state,
    _held_in_quarantine,
    _load_block_entries,
    _load_isolation_state,
    _recorded_original,
    _UNKNOWN,
    _update_block_entry,
)


def _placement_key(p: dict) -> tuple[str, str, str]:
    """A block placement's (resource group, NSG, rule), case-insensitive as ARM names are."""
    return (str(p.get("nsg_rg", "")).lower(), str(p.get("nsg_name", "")).lower(), str(p.get("rule", "")).lower())


class UnblockMixin:
    """Lifting IP blocks (part of AzureConnector)."""

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
        # I4B: a rule of ours that, taken off, would change another VM's flows stays, said
        # (_held_by_turned) — one turned into an allow that opens the VM given an old
        # address, a deny that holds back such a rule. The NSGs listed once.
        guard: dict = {}
        mates = [x.get("nic_id", "") for x in (entry or {}).get("placements", [])]
        gone: set = set()          # the placements whose two rules are off Azure now (U7D)

        def _del(p_rg: str, p_name: str, rule: str, nic_id: str = "") -> bool:
            done = True
            for nm in (rule, f"{rule}-out"):
                err = (_held_by_turned(self._network, guard, p_rg, p_name, nm, nic_id, mates)
                       or self._delete_rule(p_rg, p_name, nm))
                if err:
                    failed.extend([err] if err not in failed else [])
                    done = False
                else:
                    deleted.append(nm)
            return done

        # 1) Every per-NIC placement recorded at block time (multi-NIC VM block).
        for p in (entry or {}).get("placements", []):
            if _del(p["nsg_rg"], p["nsg_name"], p["rule"], p.get("nic_id", "")):
                gone.add(_placement_key(p))

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
        s_deleted, s_failed = self._sweep_block(rg, vm_name, ip, resource_id, guard, mates)
        deleted += [d for d in s_deleted if d not in deleted]
        failed += [f for f in s_failed if f not in failed]

        if failed:
            # Keep the entry: the rules that are still there keep blocking the IP, and a
            # retry of unblock / reset must still find them. Not the placements whose two
            # rules this unblock took off (U7D): kept, a block written whole since merged
            # them back in, and their absence read as a disappearance — a false card, put
            # back outside human_only.
            now = next((e for e in _load_block_entries(resource_id) if e.get("ip") == ip), None) or {}
            kept = [p for p in now.get("placements") or [] if _placement_key(p) not in gone]
            _update_block_entry(resource_id, ip, unblock_failed=failed,
                                **({"placements": kept} if gone and now.get("placements") else {}))
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
        bases = [*self._placement_rule_bases(prefix, vm_name, t["nic_short"], t["nic_id"]),
                 self._legacy_rule_base(prefix, vm_name, t["nic_short"], t["nic_id"]),
                 self._block_rule_name(ip, vm_name, "subnet")]
        if not _ip_scoped(t):
            bases.append(prefix)
        return {n.lower() for b in bases for n in (b, f"{b}-out")}

    def _sweep_block(self, rg: str, vm_name: str, ip: str, resource_id: str = "",
                     guard: dict | None = None, named=()) -> tuple[list[str], list[str]]:
        """(deleted, failed): the block rules of `ip` still on any NSG of this VM's NICs —
        named for it and applying to the NIC's addresses. Only rules that existed are
        counted as deleted; an unreadable NIC or rule list is a failure. The VM gone:
        _gone_vm_blocks. One aimed elsewhere than the VM's addresses asks the guard first
        (I4B, `guard`: its cache). `named`: the NICs the block's entry places."""
        try:
            targets = self._get_vm_nic_targets(rg, vm_name, allow_no_nsg=True)
        except Exception as exc:
            if _is_not_found(exc):
                return self._gone_vm_blocks(resource_id, vm_name, ip)
            return [], [f"cartes de {vm_name} illisibles, déblocage non vérifié : {_first_line(exc)[:_ERR_MAX]}"]
        deleted: list[str] = []
        failed: list[str] = []
        cache: dict = {}
        guard = {} if guard is None else guard
        own_ips = [a for t0 in targets for a in t0.get("private_ips") or []]
        mates = [t0["nic_id"] for t0 in targets]
        unplaced: list[str] = []
        seen: set = set()
        known = {n.rstrip("/").lower() for n in named if n}
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
            else:
                if original is None and not t0.get("own_nsg_id") and t0["nic_id"].rstrip("/").lower() not in known:
                    unplaced.append(t0)
            if original:
                o_rg, o_name = _parse_nsg_resource_id(original)
                views = views + [{**t0, "nsg_rg": o_rg, "nsg_name": o_name, "scope": "nic", "ip_scoped": True}]
            for t in views:
                rules = self._list_rules(cache, t["nsg_rg"], t["nsg_name"])
                if rules is None:
                    failed.append(f'{t["nsg_rg"]}/{t["nsg_name"]} : règles illisibles, déblocage non vérifié')
                    continue
                names = self._block_names_for_target(ip, vm_name, t)
                hashed = {n for b in self._placement_rule_bases(self._block_rule_prefix(ip), vm_name,
                                                                t["nic_short"], t["nic_id"]) for n in (b, f"{b}-out")}
                for r in rules:
                    name = _rule_name(r)
                    if _nic_owns(r, hashed, names, t.get("private_ips") or None):
                        seen.add((t["nsg_rg"].lower(), t["nsg_name"].lower(), name.lower()))
                        err = (_aims_elsewhere(r, own_ips) and _held_by_turned(
                            self._network, guard, t["nsg_rg"], t["nsg_name"], name, t0["nic_id"], mates)
                               or self._delete_rule(t["nsg_rg"], t["nsg_name"], name))
                        (failed if err else deleted).append(err or name)
                failed += self._unattributable_plain_block(ip, t, rules)
        if unplaced:
            failed += self._unplaced_blocks(vm_name, ip, unplaced, seen, guard, mates, deleted)
        return deleted, failed

    def _unplaced_blocks(self, vm_name: str, ip: str, nics: list[dict], seen: set, guard: dict, mates: list,
                         deleted: list) -> list[str]:
        """NICs with no NSG of their own whose NSG nothing records — taken off by someone, no
        entry placing them: their block lies out of their views' sight, and `not_found` was
        said while it stood on the NSG they carried (the CI's macOS run, I4B). Their names
        carry their hash, no other NIC's: looked for on every NSG of the subscription, as a
        deleted VM's are (I7S, I5R), each asked about first (_held_by_turned). `seen`: what
        the views already took off or kept. A listing that fails is said. The failures."""
        prefix = self._block_rule_prefix(ip)
        owner = {n.lower(): t0["nic_id"] for t0 in nics
                 for b in self._placement_rule_bases(prefix, vm_name, t0["nic_short"], t0["nic_id"])
                 for n in (b, f"{b}-out")}
        try:
            nsgs = list(self._network.network_security_groups.list_all())
        except Exception as exc:
            return [f'{", ".join(t0["nic_short"] for t0 in nics)} : sans NSG connu, son blocage non cherché sur les '
                    f"NSG de l'abonnement (liste illisible : {_first_line(exc)[:_ERR_MAX]}), déblocage non vérifié"]
        failed: list[str] = []
        for nsg in nsgs:
            n_rg, n_name = _parse_nsg_resource_id(nsg.id)
            for r in getattr(nsg, "security_rules", None) or []:
                name = _rule_name(r)
                if name.lower() not in owner or (n_rg.lower(), n_name.lower(), name.lower()) in seen:
                    continue
                err = (_held_by_turned(self._network, guard, n_rg, n_name, name, owner[name.lower()], mates)
                       or self._delete_rule(n_rg, n_name, name))
                (failed if err else deleted).append(err or name)
        return failed

    def _gone_vm_blocks(self, resource_id: str, vm_name: str, ip: str) -> tuple[list[str], list[str]]:
        """(deleted, failed) for a VM gone, its NICs with it: nothing to sweep NIC by NIC.
        It answered `not_found` without looking (`return [], []`), while a block whose
        entry was lost — a crash before it was written, or written over since — stayed on
        a shared NSG, aimed at an address Azure hands to the next VM (I5R, the unblock's
        side of I7S). The release's way (release.py): the NICs the local records name
        (`_known_nics`: the block's placements, the isolation's), their block rules looked
        for on every NSG of the subscription and taken off (`_gone_vm_rules`) — a NIC kept
        and attached since to another VM of that name is left, and said
        (`_gone_nic_check`); a state that can't be read is said (`_gone_vm_unknown`). Then
        what those don't see: _unnamed_blocks."""
        known = self._known_nics(resource_id, _load_isolation_state(resource_id) or {})
        lost = not any(e.get("ip") == ip for e in _load_block_entries(resource_id))
        deleted: list[str] = []
        failed = self._gone_vm_unknown(resource_id or vm_name, vm_name, "block")
        failed += self._gone_vm_rules(resource_id, vm_name, known, set(), "block",
                                      self._block_rule_prefix(ip), deleted)
        failed += self._unnamed_blocks(vm_name, ip, known, resource_id if lost else None)
        return deleted, failed

    def _unnamed_blocks(self, vm_name: str, ip: str, known: list[str], lost: str | None = None) -> list[str]:
        """A rule of the block named for this gone VM, whose NIC no record names (the entry
        lost, no isolation) and no NIC on Azure carries: it can't be told from a deleted
        homonym's — left, and said; never `not_found` (I5R). A listing that fails is said.
        `lost`: the VM's id when its entry is lost too — then a perimeter block of the IP
        (its plain name) that no other VM's entry records may have been its own: left (it
        covers a whole subnet), and said (RB1). Each says how to take it off, and that the
        unblock says it again while it stays: taken off, the next unblock is done."""
        prefix = self._block_rule_prefix(ip).lower()
        mine = f"{prefix}-{vm_name}".lower()
        try:
            nsgs = list(self._network.network_security_groups.list_all())
            nics = list(self._network.network_interfaces.list_all())
        except Exception as exc:
            return [f"{vm_name} supprimée : NSG ou cartes de l'abonnement illisibles "
                    f"({_first_line(exc)[:_ERR_MAX]}), déblocage non vérifié"]
        marks = {_nic_hash(n, size) for n in [*known, *(getattr(c, "id", None) or "" for c in nics)] if n
                 for size in (6, 8)}
        tied = self._perimeters_recorded(ip, lost) if lost else set()
        said: list[str] = []
        for nsg in nsgs:
            n_rg, n_name = _parse_nsg_resource_id(nsg.id)
            for r in getattr(nsg, "security_rules", None) or []:
                name = _rule_name(r).lower()
                how = (f" : laissée — à retirer à la main{{}} : az network nsg rule delete -g {n_rg} "
                       f"--nsg-name {n_name} -n {_rule_name(r)} ; le déblocage la redira tant qu'elle reste")
                if name == mine or (name.startswith(f"{mine}-")
                                    and name.removesuffix("-out").rsplit("-", 1)[-1] not in marks):
                    said.append(f"{n_name}:{_rule_name(r)} (nommée pour une VM {vm_name} supprimée, carte que "
                                "rien ne nomme plus)" + how.format(" si aucune VM vivante de ce nom ne bloque "
                                                                   f"{ip} (glorfindel status)"))
                elif lost and name.removesuffix("-out") == prefix and (n_rg.lower(), n_name.lower()) not in tied:
                    said.append(f"{n_name}:{_rule_name(r)} (règle de périmètre, ou d'une ancienne version : bloque "
                                f"{ip} pour tout un subnet ou une carte ; "
                                f"l'entrée de {vm_name} perdue, elle peut avoir été la sienne)"
                                + how.format(" si ce blocage n'est plus voulu"))
        return said

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
