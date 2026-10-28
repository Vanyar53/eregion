"""release_isolation: undo every placement, then sweep each NIC for what the state
doesn't know (moved from actions.py, A1).
"""
from __future__ import annotations

from glorfindel.providers.azure.nsg import _deny_applies, _deny_isolates, _ip_scoped, _nic_owns, _rule_name
from glorfindel.providers.azure.quarantine import OriginalUnknown, _is_quarantine_nsg
from glorfindel.providers.azure.sdk import _is_not_found
from glorfindel.response.ids import _parse_nsg_resource_id, _parse_vm_resource_id, _same_id
from glorfindel.response.policy import _ERR_MAX, _first_line
from glorfindel.response.state import (
    _clear_isolation_state,
    _legacy_claimed,
    _load_isolation_state,
    _recorded_original,
    _save_isolation_state,
    _UNKNOWN,
)


class ReleaseMixin:
    """release_isolation and the isolation names it looks for (part of AzureConnector)."""

    def _isolation_pairs(self, vm_name: str, t: dict) -> list[tuple[str, str]]:
        """Every (inbound, outbound) rule-name pair an isolation of this VM can have left
        on this NIC's NSG: the per-NIC names (current, then before the NIC hash), the
        legacy VM-suffixed names, and the legacy FIXED names on an NSG that governs this
        VM alone — on a shared NSG they could belong to another VM's isolation. A name
        is never proof on its own: see _isolating_pair / _iso_rules_on."""
        bases = [self._placement_rule_base("glorfindel-iso", vm_name, t["nic_short"], t["nic_id"]),
                 self._legacy_rule_base("glorfindel-iso", vm_name, t["nic_short"], t["nic_id"]),
                 f"{self.ISOLATION_RULE_NAME}-{vm_name}"]
        if not _ip_scoped(t):
            bases.append(self.ISOLATION_RULE_NAME)
        return [(b, f"{b}-out") for b in bases]

    def _isolation_names_for_target(self, vm_name: str, t: dict) -> list[str]:
        return [n for pair in self._isolation_pairs(vm_name, t) for n in pair]

    def _isolating_pair(self, vm_name: str, t: dict, rules: list) -> str | None:
        """The inbound rule name of an isolation of this NIC found in `rules` (the NSG's
        listing): both directions present, each a deny that cuts all of the NIC's
        traffic. None if no pair holds."""
        by_name = {_rule_name(r).lower(): r for r in rules}
        ips = t.get("private_ips") or []
        for in_name, out_name in self._isolation_pairs(vm_name, t):
            r_in, r_out = by_name.get(in_name.lower()), by_name.get(out_name.lower())
            if (r_in is not None and r_out is not None
                    and _deny_isolates(r_in, "inbound", ips) and _deny_isolates(r_out, "outbound", ips)):
                return _rule_name(r_in)
        return None

    def _iso_rules_on(self, vm_name: str, t: dict, rules: list) -> list:
        """The isolation rules of THIS NIC in `rules` (the NSG's listing): see _nic_owns.
        Names compare without case — Azure's do."""
        names = {n.lower() for n in self._isolation_names_for_target(vm_name, t)}
        base = self._placement_rule_base("glorfindel-iso", vm_name, t["nic_short"], t["nic_id"])
        ips = t.get("private_ips") or None
        return [r for r in rules if _nic_owns(r, {base, f"{base}-out"}, names, ips)]

    def _original_view(self, t0: dict, original: str) -> dict:
        """The NIC as seen from its original NSG (away while in quarantine, or not yet put
        back on a bare NIC), placed as that NSG really is: fixed legacy names count only on
        an NSG that governs one VM — this NIC, away, counted among its NICs (I4F)."""
        o_rg, o_name = _parse_nsg_resource_id(original)
        sharing = self._nsg_sharing(o_rg, o_name, away_nic=t0["nic_id"])
        return {**t0, "nsg_rg": o_rg, "nsg_name": o_name, "scope": "nic", "ip_scoped": sharing is not False,
                "shared_nsg": sharing is not False, **({"sharing_unknown": True} if sharing is None else {})}

    def _unattributable_fixed(self, t: dict, rules: list) -> list[str]:
        """An older version's fixed-name isolation (no VM in its name) that cuts this NIC
        off, on an NSG that isn't its own — shared since, a subnet's, or whose sharing
        can't be read — and that no older single-NSG state names: whose it is can't be
        told. It used to be ignored: the VM was "released" while cut off (A0)."""
        if not (t.get("sharing_unknown") or _ip_scoped(t)):
            return []
        fixed = {self.ISOLATION_RULE_NAME.lower(), f"{self.ISOLATION_RULE_NAME}-out".lower()}
        how = "au partage illisible" if t.get("sharing_unknown") else "partagé"
        return [f'{t["nic_short"]}:{_rule_name(r)} (NSG {t["nsg_name"]} {how} : isolation d\'une ancienne '
                "version, VM inconnue)"
                for r in rules if _rule_name(r).lower() in fixed and _deny_applies(r, t.get("private_ips") or None)
                and not _legacy_claimed(t["nsg_rg"], t["nsg_name"], _rule_name(r))]

    def _tag_over_none(self, q: dict, nic_id: str) -> str | None:
        """The original of a NIC whose local state says it had no NSG: our tag, when it
        names one (I8S). Two hosts keep separate states: the first isolated the NIC bare
        ("none"), its customer gave it an NSG since, the second isolated it and wrote that
        NSG in the tag — the first's release followed its own "none" and left the NIC
        without its NSG. No tag, or our NSG gone: the state's "none" stands. A tag that
        can't be read RAISES: it may name the original, and the release deletes it."""
        try:
            return self._original_from_tags(q, nic_id)
        except OriginalUnknown:
            return None
        except Exception as exc:
            if _is_not_found(exc):
                return None
            raise

    def release_isolation(self, resource_id: str) -> dict:
        """Remove every isolation rule of the VM and restore bumped customer rules.

        Failures are no longer swallowed: a rule that could not be deleted keeps the VM
        cut off, so the state is kept for those placements, and the status says
        `release_partial` with the failing rules. `released` means every delete succeeded
        (or the rule was already gone).

        The recorded placements are undone first, then every current NIC is swept for
        what the state doesn't know (_sweep_isolation) — with no state at all (lost,
        corrupt, never written) that sweep is the whole release.
        """
        if self.dry_run:
            return {"status": "dry_run", "action": "release_isolation", "resource_id": resource_id}

        self._guard_write("release_isolation")
        self._ensure_clients()
        rg, vm_name = _parse_vm_resource_id(resource_id)
        state = _load_isolation_state(resource_id) or {}
        if state:
            # The intent is recorded before Azure is touched: a release cut off midway
            # (War Room timeout, crash) leaves NICs half released — the reassertion
            # must not read that as "removed outside Glorfindel" and isolate again.
            from datetime import datetime, timezone
            _save_isolation_state(resource_id, {**state, "releasing_at": datetime.now(timezone.utc).isoformat()})

        failed: list[str] = []
        remaining: list[dict] = []
        if state.get("placements"):
            # Multi-NIC: undo each placement on its own NSG. Delete our denies first —
            # a customer rule can only go back to priority 100 once ours is gone.
            for p in state["placements"]:
                if p.get("kind") == "quarantine":
                    # Put the NIC's own NSG back (or none) — only if it still carries
                    # OURS; our NSG keeps its deny rules for the next VM.
                    # The state's original wins (None = the NIC had no NSG); the tag
                    # is read only when the state doesn't say. Unknown original, or
                    # an original that didn't come back → the NIC stays in quarantine.
                    try:
                        now = self._nic_nsg_id(p["nic_id"])
                        if now and not _same_id(now, p["nsg_id"]):
                            # Another NSG is on the NIC (a redeploy put the customer's
                            # back): nothing to restore, the original is not needed.
                            # Asked first, an unknown original failed this release
                            # forever (L26).
                            self._forget_original(p, p["nic_id"])
                            continue
                        original = (p["original_nsg_id"] if "original_nsg_id" in p
                                    else self._original_from_tags(p, p["nic_id"]))
                        if original is None and "original_nsg_id" in p:
                            original = self._tag_over_none(p, p["nic_id"])
                        if now is None:
                            # Detached from our NSG and left with none: the release
                            # moved on, deleted the tag, and the NIC kept no NSG while
                            # verify_release agreed (seventh review, U2). Put the
                            # original back; the tag goes only once it is on.
                            if original:
                                self._set_nic_nsg(p["nic_id"], original, expect=None)
                                back = self._nic_nsg_id(p["nic_id"])
                                if not _same_id(back or "", original):
                                    raise RuntimeError(
                                        f"NSG d'origine non remis sur {p['nic_id'].rsplit('/', 1)[-1]} "
                                        f"(carte sans NSG, détachée de la quarantaine hors de Glorfindel)")
                            self._forget_original(p, p["nic_id"])
                            continue
                        self._unquarantine(p["nic_id"], p, original)
                    except Exception as exc:
                        if not self._nic_gone(p["nic_id"]):
                            failed.append(f'{p["nic_id"].split("/")[-1]}: NSG de quarantaine '
                                          f"non détaché : {_first_line(exc)[:_ERR_MAX]}")
                            remaining.append(p)
                    continue
                p_rg, p_name = p["nsg_rg"], p["nsg_name"]
                p_failed = [
                    err for err in (
                        self._delete_rule(p_rg, p_name, name)
                        for name in (p.get("rule_in"), p.get("rule_out")) if name
                    ) if err
                ]
                left = self._restore_bumped(p_rg, p_name, p.get("bumped", []))
                p_failed += [f"{p_rg}/{p_name}/{b['name']} (priorité non restaurée) : {b['error']}"
                             for b in left]
                if p_failed:
                    failed += p_failed
                    # Keep the placement for a retry: its rule names (deleting an absent
                    # rule is a no-op) and only the bumps still to put back.
                    remaining.append({**p, "bumped": left})
        elif "placements" not in state and state.get("nsg_name") and not _is_quarantine_nsg(state["nsg_name"]):
            # Legacy single-NSG state: recorded rule names + bumps live on the recorded NSG.
            # Only a state written before placements existed: a partial release leaves
            # `placements: []` next to the flat fields kept for /api/state, which name the
            # FIRST placement — the shared quarantine NSG and its deny rules. Read as a
            # legacy state, the next release deleted them: every VM in quarantine in the
            # region was open again (L26, invariant machine).
            l_rg, l_name = state.get("nsg_rg", rg), state["nsg_name"]
            for name in state.get("rule_names", []):
                err = self._delete_rule(l_rg, l_name, name)
                if err:
                    failed.append(err)
            left = self._restore_bumped(l_rg, l_name, state.get("bumped", []))
            failed += [f"{l_rg}/{l_name}/{b['name']} (priorité non restaurée) : {b['error']}"
                       for b in left]

        # Then what the state doesn't know, state or not: a crash between Azure and the
        # state file, an answer lost after Azure applied a write, a placement replaced
        # by a re-isolation. `released` used to mean "what the state listed is undone"
        # while a NIC stayed cut off (L24).
        failed += self._sweep_isolation(rg, vm_name, remaining)

        if failed:
            from datetime import datetime, timezone
            _save_isolation_state(resource_id, {
                **state,
                "resource_id": state.get("resource_id") or resource_id,
                "isolated_at": state.get("isolated_at") or datetime.now(timezone.utc).isoformat(),
                "placements": remaining if state.get("placements") else state.get("placements", []),
                "release_failed": failed,
            })
            return {"status": "release_partial", "resource_id": resource_id, "failed": failed}

        _clear_isolation_state(resource_id)
        return {"status": "released", "resource_id": resource_id}

    def _sweep_isolation(self, rg: str, vm_name: str, remaining: list[dict]) -> list[str]:
        """Remove every isolation of this VM still on Azure: our quarantine NSG on its
        NICs (original from the state, else from our tag), and on each NSG that governs
        a NIC, the rules of THAT NIC — named for it and applying to its addresses, so a
        homonym's rules on the same NSG stay. `remaining`: placements whose undo just
        failed (not tried twice). Returns the failures; an unreadable NIC or rule list
        is one — nothing found is not nothing there."""
        try:
            targets = self._get_vm_nic_targets(rg, vm_name, allow_no_nsg=True)
        except Exception as exc:
            if _is_not_found(exc):
                return []                     # the VM is gone, and its NICs with it
            return [f"cartes de {vm_name} illisibles, levée non vérifiée : {_first_line(exc)[:_ERR_MAX]}"]
        held = {p["nic_id"].rstrip("/").lower() for p in remaining if p.get("kind") == "quarantine"}
        stuck = {(p["nsg_rg"].lower(), p["nsg_name"].lower(), n.lower())
                 for p in remaining if p.get("kind") != "quarantine"
                 for n in (p.get("rule_in"), p.get("rule_out")) if n}
        failed: list[str] = []
        cache: dict = {}
        restored = False
        for t0 in targets:
            q = t0.get("quarantine")
            if q and t0["nic_id"].rstrip("/").lower() not in held:
                try:
                    original = _recorded_original(t0["nic_id"])
                    if original is _UNKNOWN:
                        original = self._original_from_tags(q, t0["nic_id"])
                    elif original is None:
                        original = self._tag_over_none(q, t0["nic_id"])
                    self._unquarantine(t0["nic_id"], q, original)
                    restored = True
                except Exception as exc:
                    failed.append(f'{t0["nic_short"]}: NSG de quarantaine non retiré : '
                                  f"{_first_line(exc)[:_ERR_MAX]}")
            elif not q and not t0.get("own_nsg_id") and t0["nic_id"].rstrip("/").lower() not in held:
                # Bare: taken off our NSG and left with none, the state lost or never
                # written. Our tag still says what it carried (seventh review, U2).
                try:
                    original, q_bare = self._bare_nic_original(t0, rg)
                    if q_bare is not None:
                        if original:
                            self._set_nic_nsg(t0["nic_id"], original)
                            if not _same_id(self._nic_nsg_id(t0["nic_id"]) or "", original):
                                raise RuntimeError("NSG d'origine non remis (carte sans NSG)")
                            restored = True
                        self._forget_original(q_bare, t0["nic_id"])
                except Exception as exc:
                    failed.append(f'{t0["nic_short"]}: carte sans NSG, NSG d\'origine non remis : '
                                  f"{_first_line(exc)[:_ERR_MAX]}")
        if restored:
            # A NIC in quarantine doesn't show its own NSG: the rules an earlier fallback
            # left there were out of sight until it came back (L24).
            try:
                targets = self._get_vm_nic_targets(rg, vm_name, allow_no_nsg=True)
            except Exception as exc:
                return failed + [f"cartes de {vm_name} illisibles, levée non vérifiée : "
                                 f"{_first_line(exc)[:_ERR_MAX]}"]
        for t0 in targets:
            if t0.get("subnet_unreadable"):
                failed.append(f'{t0["nic_short"]} : NSG du subnet illisible, levée non vérifiée')
            for t in self._nic_nsg_views(t0):
                rules = self._list_rules(cache, t["nsg_rg"], t["nsg_name"])
                if rules is None:
                    failed.append(f'{t["nsg_rg"]}/{t["nsg_name"]} : règles illisibles, levée non vérifiée')
                    continue
                for r in self._iso_rules_on(vm_name, t, rules):
                    if (t["nsg_rg"].lower(), t["nsg_name"].lower(), _rule_name(r).lower()) in stuck:
                        continue
                    err = self._delete_rule(t["nsg_rg"], t["nsg_name"], _rule_name(r))
                    if err:
                        failed.append(err)
                failed += [f"{u} : laissée" for u in self._unattributable_fixed(t, rules)]
        return failed
