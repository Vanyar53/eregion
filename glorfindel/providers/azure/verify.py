"""verify_isolation and verify_release: read by content, and the precedence of every
allow before our deny (moved from actions.py, A1).
"""
from __future__ import annotations

from glorfindel.providers.azure.nsg import _describe_shadowing, _rule_name, _shadowing_rules
from glorfindel.providers.azure.quarantine import _is_quarantine_nsg, PLATFORM_OPEN_NOTE
from glorfindel.response.ids import _parse_vm_resource_id
from glorfindel.response.legacy_state import _older_record
from glorfindel.response.policy import _ERR_MAX, _first_line
from glorfindel.response.state import _held_in_quarantine, _load_isolation_state, _UNKNOWN, StateUnreadable


class VerifyMixin:
    """The isolation's verifications (part of AzureConnector)."""

    def verify_isolation(self, resource_id: str) -> dict:
        if self.dry_run:
            return {"verified": True, "method": "dry_run"}

        self._ensure_clients()
        rg, vm_name = _parse_vm_resource_id(resource_id)
        targets = self._get_vm_nic_targets(rg, vm_name, allow_no_nsg=True)

        # Isolation holds only if EVERY NIC carries a deny pair — a single uncovered NIC
        # is the multi-NIC gap (looks ISOLATED but traffic still flows on the other NIC).
        uncovered: list[str] = []
        unreadable: list[str] = []
        altered: list[str] = []          # our quarantine NSG changed (Q6)
        held: set[str] = set()           # NICs our quarantine NSG holds — nothing to compare
        found: dict[str, list[tuple]] = {}     # nic_id → [(nsg_rg, nsg_name, inbound deny name)]
        cache: dict = {}
        for t0 in targets:
            unknown = bool(t0.get("subnet_unreadable"))
            hits: list[tuple] = []
            # Glorfindel's quarantine NSG on the NIC (L4): holds if its rules are exactly
            # ours — read by content (Q6). Nothing customer runs before them.
            q = t0.get("quarantine")
            if q:
                st, diff = self._quarantine_state(q, cache)
                if st == "ok":
                    held.add(t0["nic_id"])
                    found[t0["nic_id"]] = []
                    continue
                if st == "altered":
                    altered.append(f'{t0["nic_short"]} ({q["nsg_name"]} : {", ".join(diff)})')
                unknown = unknown or st == "unknown"
            # The deny may sit on the NIC's own NSG and/or on its subnet's (placed there
            # when an ALLOW preceded it on the first): traffic crosses both, one deny that
            # isn't bypassed holds — every one is kept for the precedence check below (the
            # first found used to decide alone, a bypassed leftover over a sound one: L24).
            # Read from the NSG's listing, by content: a homonym's rule of the same name,
            # scoped to its own addresses, isolates nothing here.
            for t in self._nic_nsg_views(t0):
                rules = self._list_rules(cache, t["nsg_rg"], t["nsg_name"])
                if rules is None:
                    unknown = True
                    continue
                hit = self._isolating_pair(vm_name, t, rules)
                if hit:
                    hits.append((t["nsg_rg"], t["nsg_name"], hit))
            if hits:
                found[t0["nic_id"]] = hits
            elif q and t0["nic_short"] in {a.split(" ", 1)[0] for a in altered}:
                # Our quarantine NSG tampered with: put back by the reassertion, which
                # re-applies an isolation that is "missing".
                uncovered.append(t0["nic_short"])
            else:
                # Not found: missing for sure, or only unreadable (no claim either way).
                (unreadable if unknown else uncovered).append(t0["nic_short"])

        if uncovered:
            return {"verified": False, "method": "nsg_check", "uncovered_nics": uncovered,
                    **({"quarantine_altered": altered,
                        "error": "NSG de quarantaine modifié : " + " ; ".join(altered)} if altered else {}),
                    **({"unreadable_nics": unreadable} if unreadable else {})}
        if unreadable:
            return {"verified": None, "method": "nsg_check", "unreadable_nics": unreadable,
                    "error": "isolation non vérifiable : règles illisibles sur "
                             + ", ".join(unreadable)}

        # Present is not effective: an ALLOW evaluated before the deny still passes its
        # traffic (the bench's allow-ssh at 100 kept SSH open on every "isolated" VM).
        # Every NSG is checked now — a deny no longer forces priority 100 by moving the
        # customer's rules. The check uses the name actually found (a legacy-named
        # isolation used to pass it by finding nothing to compare), on the listing the
        # deny was read from.
        shadowed: list[dict] = []
        unknown: list[str] = []
        for t in targets:
            scope = {"inbound_src": None, "inbound_dst": t["private_ips"] or None,
                     "outbound_src": t["private_ips"] or None, "outbound_dst": None}
            nic_shadowed: list[dict] = []
            nic_unknown: list[str] = []
            for nsg_rg, nsg_name, rule in found[t["nic_id"]]:
                res = self._shadowed_deny(cache, nsg_rg, nsg_name, rule, **scope)
                if res == []:
                    break                              # one deny holds for this NIC
                if res is None:
                    nic_unknown.append(f"{nsg_rg}/{nsg_name}")
                else:
                    nic_shadowed += res
            else:
                if nic_unknown:
                    unknown += [u for u in nic_unknown if u not in unknown]
                else:
                    shadowed += nic_shadowed
        if shadowed:
            return {
                "verified": False, "method": "nsg_check", "shadowed_by": shadowed,
                "error": "isolation contournée : " + _describe_shadowing(shadowed)
                         + " passe avant le deny de Glorfindel",
            }
        if unknown:
            return self._precedence_unknown(unknown, nics_covered=len(targets))
        # Isolated by rules (the quarantine was refused): said, not hidden (Q15).
        platform_open = [t["nic_short"] for t in targets if t["nic_id"] not in held]
        return {"verified": True, "method": "nsg_check", "nics_covered": len(targets),
                **({"platform_open": platform_open, "note": PLATFORM_OPEN_NOTE} if platform_open else {})}

    def _shadowed_deny(
        self, cache: dict, nsg_rg: str, nsg_name: str, rule_name: str, **scope,
    ) -> list[dict] | None:
        """ALLOW rules evaluated before OUR deny `rule_name` on this NSG (see
        _shadowing_rules). None when that can't be established: the NSG's rules are
        unreadable, or our rule (present per `get`) is missing from the listing."""
        rules = self._list_rules(cache, nsg_rg, nsg_name)
        if rules is None:
            return None
        by_name = {_rule_name(r).lower(): r for r in rules}
        prio = getattr(by_name.get(rule_name.lower()), "priority", None)
        if not isinstance(prio, int):
            return None
        # Each direction against its own deny: the outbound one moved behind a customer
        # allow (priority 4000, by hand) read as holding — the inbound one's priority
        # was used for both (A0).
        out = getattr(by_name.get(f"{rule_name}-out".lower()), "priority", None)
        found = _shadowing_rules(rules, {"inbound": prio, "outbound": out if isinstance(out, int) else prio},
                                 **scope)
        return [{**f, "nsg": f"{nsg_rg}/{nsg_name}"} for f in found]

    def _precedence(self, checks: list[tuple]) -> tuple[list[dict], list[str]]:
        """Run _shadowed_deny over (nsg_rg, nsg_name, rule_name, scope) checks.
        Returns (shadowing allows, NSGs whose precedence could not be established)."""
        cache: dict = {}
        shadowed: list[dict] = []
        unknown: list[str] = []
        for nsg_rg, nsg_name, rule_name, scope in checks:
            found = self._shadowed_deny(cache, nsg_rg, nsg_name, rule_name, **scope)
            if found is None:
                if f"{nsg_rg}/{nsg_name}" not in unknown:
                    unknown.append(f"{nsg_rg}/{nsg_name}")
            else:
                shadowed += found
        return shadowed, unknown

    @staticmethod
    def _precedence_unknown(unknown: list[str], **extra) -> dict:
        """Rules present but their precedence unreadable: no claim either way."""
        return {
            "verified": None, "method": "nsg_check", "precedence_unknown": unknown, **extra,
            "error": "préséance non vérifiable (règles illisibles sur "
                     + ", ".join(unknown) + ") : les règles sont posées, rien ne garantit "
                     "qu'aucune allow ne passe avant",
        }

    def verify_release(self, resource_id: str) -> dict:
        """Confirm that NO NIC still carries an isolation rule of this VM.

        The previous check was `not verify_isolation()`, i.e. "at least one NIC is
        uncovered". A release that failed on one NIC (or on one direction of a single
        NIC) therefore passed as verified while that NIC stayed cut off. A rule whose
        presence can't be read counts as still there: no success claim on an unknown.
        """
        if self.dry_run:
            return {"verified": True, "method": "dry_run"}

        self._ensure_clients()
        rg, vm_name = _parse_vm_resource_id(resource_id)
        still: list[str] = []
        unknown: list[str] = []
        untraced: list[str] = []         # bare, held in our quarantine, its original unknown
        targets = self._get_vm_nic_targets(rg, vm_name, allow_no_nsg=True)
        still += [f'{t0["nic_short"]}:{t0["quarantine"]["nsg_name"]} (NSG de quarantaine attaché)'
                  for t0 in targets if t0.get("quarantine")]
        # A NIC taken off our NSG and left with none is not released: its own NSG — in
        # the state, or still in our tag — is not back (seventh review, U2).
        state = _load_isolation_state(resource_id) or {}
        recorded = {(p.get("nic_id") or "").rstrip("/").lower(): p
                    for p in state.get("placements") or []
                    if p.get("kind") == "quarantine"}
        for t0 in targets:
            if t0.get("quarantine") or t0.get("own_nsg_id"):
                continue
            p = recorded.get(t0["nic_id"].rstrip("/").lower())
            original = p["original_nsg_id"] if p and "original_nsg_id" in p else _UNKNOWN
            # The state's "none" too: our tag may name the NSG the NIC got since —
            # another host's isolation (I8S).
            if original is _UNKNOWN or original is None:
                try:
                    tagged = self._bare_nic_original(t0, rg)[0]
                except Exception as exc:
                    unknown.append(f'{t0["nic_short"]} : tag d\'origine illisible ({_first_line(exc)[:_ERR_MAX]})')
                    continue
                if original is _UNKNOWN or tagged is not _UNKNOWN:
                    original = tagged
            try:
                held = original is _UNKNOWN and _held_in_quarantine(t0["nic_id"])
            except StateUnreadable as exc:
                # A state that can't be read may hold it in quarantine: read as bare by
                # design, it said released on an unknown (SEC4b).
                unknown.append(f'{t0["nic_short"]} : sans NSG, {_first_line(exc)[:_ERR_MAX]}')
                continue
            if held:
                # In quarantine for our state, its original unknown there (state and
                # tags lost before a re-isolation, Q7) and no tag: someone left it bare.
                # Bare is not its design for all we know — read as released, an old
                # isolation stayed on its own NSG while this said verified (I3F, #287).
                untraced.append(f'{t0["nic_short"]} : sans NSG, NSG d\'origine inconnu '
                                "(ni l'état local ni le tag ne le disent)")
                continue
            if original and original is not _UNKNOWN:
                still.append(f'{t0["nic_short"]} : sans NSG, '
                             f'{original.rstrip("/").rsplit("/", 1)[-1]} non remis')
        cache: dict = {}
        unknown += [f'{t0["nic_short"]}:NSG du subnet' for t0 in targets if t0.get("subnet_unreadable")]
        for t in (v for t0 in targets for v in self._nic_nsg_views(t0)):
            rules = self._list_rules(cache, t["nsg_rg"], t["nsg_name"])
            if rules is None:
                unknown.append(f'{t["nic_short"]}:{t["nsg_name"]}')
                continue
            still += [f'{t["nic_short"]}:{_rule_name(r)}' for r in self._iso_rules_on(vm_name, t, rules)]
            unknown += self._unattributable_fixed(t, rules)
        # An older version's single-NSG record names its rules — its state, or kept by a
        # later isolation (I4E): there, whatever the NSG's sharing now (its fixed names only
        # count on a dedicated NSG) — the release deletes them by that record, the
        # verification must look for them too (A0).
        older = _older_record(state)
        if older and not _is_quarantine_nsg(older["nsg_name"]):
            l_rg, l_name = older["nsg_rg"] or rg, older["nsg_name"]
            rules = self._list_rules(cache, l_rg, l_name)
            names = {n.lower() for n in older["rule_names"]}
            if rules is None:
                unknown.append(f"{l_name} (état ancien)")
            else:
                still += [f"{l_name}:{_rule_name(r)} (état ancien)" for r in rules
                          if _rule_name(r).lower() in names and f"{l_name}:{_rule_name(r)}" not in still]
        if still or unknown or untraced:
            detail = ", ".join(still + untraced + [f"{u} (lecture impossible)" for u in unknown])
            return {"verified": False, "method": "nsg_check",
                    "still_isolated": still, "unreadable": unknown,
                    **({"original_unknown": untraced} if untraced else {}),
                    "error": f"isolation toujours présente : {detail}"}
        return {"verified": True, "method": "nsg_check"}
