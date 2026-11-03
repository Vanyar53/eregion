"""The rules of a NIC on an NSG it no longer carries — left bare (D80, #380), looked for by
the release's sweep and by `reset --from-azure`, which see only the NSGs that govern a NIC now;
or out of our quarantine NSG with the release (I3R, #431).
"""
from __future__ import annotations

import re

from glorfindel.providers.azure.nsg import _rule_name
from glorfindel.providers.azure.turned import _aims_elsewhere, _held_by_turned, _turned_guard
from glorfindel.providers.azure.quarantine import QUARANTINE_NSG_PREFIX
from glorfindel.response.ids import _parse_nsg_resource_id, _parse_vm_resource_id
from glorfindel.response.policy import _ERR_MAX, _first_line
from glorfindel.response.unread import _own_unread

# A block's name: its IP segment, then the VM, the NIC and its hash (sweep.py reads it alike).
_BLOCK_RE = re.compile(r"^glorfindel-block-\d{1,3}(?:-\d{1,3}){3}(?:-\d{1,2})?-(?P<rest>.+?)(?:-out)?$")


class AwayRulesMixin:
    """_away_rules, _away_split, _left_quarantine_rules (part of AzureConnector)."""

    def _unread(self, resource_id: str, unverified: str, said=()) -> list[str]:
        """_own_unread (I3U): this VM's isolation state unreadable, said — with where to look
        before removing it, our quarantine NSG of its region (_quarantine_hint)."""
        return _own_unread(resource_id, unverified, said, lambda: self._quarantine_hint(resource_id))

    def _quarantine_hint(self, resource_id: str) -> str:
        """Where a partial release may have left a NIC's rules, its state unreadable since (I3U,
        review): our quarantine NSG of the VM's region (`nsg-glorfindel-quarantine-<région>`), in
        the configured group, else the VM's — the NSGs its NICs carry now are not it. Read only
        then; a region that can't be read is said as such."""
        rg, vm_name = _parse_vm_resource_id(resource_id)
        try:
            regions = sorted({(t0.get("location") or "").lower() for t0 in
                              self._get_vm_nic_targets(rg, vm_name, allow_no_nsg=True)} - {""})
        except Exception:
            regions = []
        try:
            q_rg = self._quarantine_settings()[1] or rg
        except Exception:
            q_rg = f"{rg}, ou celui de la configuration"
        names = " ou ".join(f"{QUARANTINE_NSG_PREFIX}-{r}" for r in regions) or f"{QUARANTINE_NSG_PREFIX}-<région>"
        return f"{names} (groupe {q_rg})"

    @staticmethod
    def _quarantines_left(state: dict) -> dict:
        """NIC id (lowercase) → (rg, name) of the quarantine NSG it leaves with this release (or
        left before, a redeploy): the one a quarantine placement of the state isolated it by,
        and those a partial release left unswept (`quarantines_left`: its placement undone
        meanwhile, or no state at all — the retry looks there again, I3R's review)."""
        kept = state.get("quarantines_left") if isinstance(state, dict) else None
        left = {k.rstrip("/").lower(): (v[0], v[1]) for k, v in (kept.items() if isinstance(kept, dict) else ())
                if isinstance(k, str) and isinstance(v, (list, tuple)) and len(v) == 2
                and all(isinstance(x, str) and x for x in v)}
        placements = state.get("placements") if isinstance(state, dict) else None
        left.update({p["nic_id"].rstrip("/").lower(): (p["nsg_rg"], p["nsg_name"])
                     for p in (placements if isinstance(placements, list) else ()) if isinstance(p, dict)
                     and p.get("kind") == "quarantine" and p.get("nic_id") and p.get("nsg_rg") and p.get("nsg_name")})
        return left

    def _left_quarantine_rules(self, vm_name: str, targets: list[dict], left: dict, guard: dict,
                               mates: list, own_ips: list, cache: dict, stuck: set, keep: dict) -> list[str]:
        """The release's (_sweep_isolation): a NIC that left our quarantine NSG (`left`, NIC →
        the NSG) may have rules of its own there — an isolation written while that NSG had lost
        our tag, placed on it as on any NSG the NIC carried. Off it, the NIC no longer sees it:
        the release put its NSG back and said `released`, the rules left (I3R, #431). Looked
        for there as on an NSG that governs the NIC — its hash, or an older name aimed at its
        addresses, the guard asked for one aimed elsewhere. A NIC still in it is skipped (its
        undo failed: they may be all that cuts it off), and a bare one (_away_rules looks
        for its rules on every NSG, this one included: said once). A NIC whose search there
        fails or keeps a rule goes into `keep` (NIC → the NSG), for the partial state: off the
        quarantine NSG now, its retry would no longer know to look there. `stuck`: the
        placements whose undo just failed — not tried, nor said, twice."""
        failed: list[str] = []
        for t0 in targets:
            q = left.get(t0["nic_id"].rstrip("/").lower())
            if q is None or not (t0.get("own_nsg_id") or t0.get("quarantine")):
                continue
            now = [(t["nsg_rg"], t["nsg_name"]) for t in self._nic_nsg_views(t0)] + (
                [(t0["quarantine"]["nsg_rg"], t0["quarantine"]["nsg_name"])] if t0.get("quarantine") else [])
            if (q[0].lower(), q[1].lower()) in {(a.lower(), b.lower()) for a, b in now}:
                continue
            before = len(failed)
            rules = self._list_rules(cache, *q)
            if rules is None:
                failed.append(f"{q[0]}/{q[1]} : règles illisibles, levée non vérifiée")
                rules = []
            view = {**t0, "nsg_rg": q[0], "nsg_name": q[1], "scope": "nic", "shared_nsg": True, "ip_scoped": True}
            for r in self._iso_rules_on(vm_name, view, rules):
                name = _rule_name(r)
                if (q[0].lower(), q[1].lower(), name.lower()) in stuck:
                    continue
                err = (_aims_elsewhere(r, own_ips) and _held_by_turned(
                    self._network, guard, q[0], q[1], name, t0["nic_id"], mates) or self._delete_rule(q[0], q[1], name))
                if err:
                    failed.append(err)
            if len(failed) > before:
                keep[t0["nic_id"].rstrip("/")] = list(q)
        return failed

    def _out_of_sight_seen(self, vm_name: str, targets: list[dict], state: dict,
                           cache: dict) -> tuple[list[str], list[str]]:
        """verify_release's: the rules of a NIC on an NSG the release still looks at but the NIC
        no longer carries (_out_of_sight_views), found as the release finds them — a bare NIC's
        too, nothing is taken off here. After a partial release, `glorfindel release` read
        « verified », cleared the state and said « state cleared », the pair left on the
        quarantine NSG and the only file that said where to look gone (I3V, #450). Returns
        (still there, unreadable)."""
        still: list[str] = []
        unknown: list[str] = []
        for view in self._out_of_sight_views(targets, state):
            where = f'{view["nsg_name"]}, groupe {view["nsg_rg"]} : {view["out_of_sight"]}'
            rules = self._list_rules(cache, view["nsg_rg"], view["nsg_name"])
            if rules is None:
                unknown.append(f'{view["nic_short"]}:{where}')
                continue
            still += [f'{view["nic_short"]}:{_rule_name(r)} (sur {where})'
                      for r in self._iso_rules_on(vm_name, view, rules)]
        return still, unknown

    def _out_of_sight_views(self, targets: list[dict], state: dict) -> list[dict]:
        """Each NIC seen from an NSG the release looks at that the NIC no longer carries — the
        quarantine NSG it left (_quarantines_left: a partial release's `quarantines_left`, a
        quarantine placement of the state), or the NSG a placement by rules of the state names
        (the isolation written on the quarantine NSG while it had lost our tag, seed 67's) —,
        as an NSG shared with other VMs (its older names count only aimed at its addresses),
        for verify_release and `reset --from-azure` (I3V). Not one that still governs it: in it
        still (said as such), or among the NSGs it carries (looked at with them)."""
        left = self._quarantines_left(state)
        rows = state.get("placements") if isinstance(state, dict) else None
        placed = [p for p in (rows if isinstance(rows, list) else ()) if isinstance(p, dict)
                  and p.get("kind") != "quarantine" and p.get("nic_id") and p.get("nsg_rg") and p.get("nsg_name")]
        views: list[dict] = []
        for t0 in targets:
            nid = t0["nic_id"].rstrip("/").lower()
            seen = {(t["nsg_rg"].lower(), t["nsg_name"].lower()) for t in self._nic_nsg_views(t0)} | (
                {(t0["quarantine"]["nsg_rg"].lower(), t0["quarantine"]["nsg_name"].lower())}
                if t0.get("quarantine") else set())
            wanted = ([(*left[nid], "NSG de quarantaine quitté")] if nid in left else []) + [
                (p["nsg_rg"], p["nsg_name"], "NSG d'un placement de l'état, que la carte ne porte plus")
                for p in placed if p["nic_id"].rstrip("/").lower() == nid]
            for q_rg, q_name, why in wanted:
                if (q_rg.lower(), q_name.lower()) not in seen:
                    seen.add((q_rg.lower(), q_name.lower()))
                    views.append({**t0, "nsg_rg": q_rg, "nsg_name": q_name, "scope": "nic", "shared_nsg": True,
                                  "ip_scoped": True, "out_of_sight": why})
        return views

    def _away_rules(self, vm_name: str, targets: list[dict], stuck: set, guard: dict, mates: list) -> list[str]:
        """The release's (_sweep_isolation): what _away_split keeps, said; the rest taken
        off — `stuck`, the placements whose undo just failed, not tried twice."""
        said, off = self._away_split(vm_name, targets, guard, mates,
                                     lambda k, name: (*k, name.lower()) in stuck)
        return said + [err for err in (self._delete_rule(*x) for x in off) if err]

    def _away_split(self, vm_name: str, targets: list[dict], guard: dict, mates: list, skip,
                    blocks: bool = False, unverified: str = "levée non vérifiée") -> tuple[list[str], list[tuple]]:
        """A NIC of the VM with no NSG of its own (taken off by someone, its quarantine
        lifted to « none »): the NSG it carried is out of the sweep's sight, and a rule of
        its isolation kept there by an earlier release (I4C: a rule someone turned into an
        allow for another VM) was forgotten with the state — a later release said
        `released`, a reset `swept_partial` without naming it (#380). Its rules, by the NIC's
        hash (no other NIC's, _nic_owns), are looked for on every NSG of the subscription,
        as for a gone VM (I7S); its blocks' too with `blocks` (the reset). Returns what the
        guard keeps, said « gardée », and the (rg, NSG, rule) to take off. Skipped: the NSGs
        that govern the NIC (swept for it already), and what `skip(nsg_key, name)` says.
        A listing that fails is said: nothing found is not nothing there (A0)."""
        bare = [t0 for t0 in targets if not t0.get("quarantine") and not t0.get("own_nsg_id")]
        if not bare:
            return [], []
        views = {t0["nic_id"]: {(t["nsg_rg"].lower(), t["nsg_name"].lower()) for t in self._nic_nsg_views(t0)}
                 for t0 in bare}
        names: dict[str, dict] = {}
        for t0 in bare:
            for b in self._placement_rule_bases("glorfindel-iso", vm_name, t0["nic_short"], t0["nic_id"]):
                names.update({n.lower(): t0 for n in (b, f"{b}-out")})
        try:
            nsgs = (list(guard["nsgs"].values()) if "nsgs" in guard
                    else list(self._network.network_security_groups.list_all()))
        except Exception as exc:
            nics = ", ".join(t0["nic_short"] for t0 in bare)
            return [f"{nics} : carte sans NSG, ses règles non cherchées sur les NSG de l'abonnement "
                    f"(liste illisible : {_first_line(exc)[:_ERR_MAX]}), {unverified}"], []
        said: list[str] = []
        off: list[tuple] = []
        for nsg in nsgs:
            n_rg, n_name = _parse_nsg_resource_id(nsg.id)
            k = (n_rg.lower(), n_name.lower())
            for r in (getattr(nsg, "security_rules", None) or []):
                name = _rule_name(r)
                t0 = names.get(name.lower())
                if t0 is None and blocks and (m := _BLOCK_RE.match(name)):
                    t0 = next((t for t in bare if name.lower() in {
                        n for b in self._placement_rule_bases(name[: m.start("rest") - 1], vm_name, t["nic_short"],
                                                              t["nic_id"]) for n in (b, f"{b}-out")}), None)
                if t0 is None or k in views[t0["nic_id"]] or skip(k, name):
                    continue
                if "why" not in guard:
                    # The guard reads the listing just made, not a second one (D80's review).
                    # A failure here is left to it: it lists again and says what it can't read.
                    try:
                        why = _turned_guard(self._network, nsgs)
                        guard["nsgs"] = {tuple(x.lower() for x in _parse_nsg_resource_id(n.id)): n for n in nsgs}
                        guard["why"] = why
                    except Exception:
                        pass
                why = _held_by_turned(self._network, guard, n_rg, n_name, name, t0["nic_id"], mates)
                (said.append(why) if why else off.append((n_rg, n_name, name)))
        return said, off
