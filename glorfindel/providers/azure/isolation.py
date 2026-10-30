"""isolate_vm: every NIC by the quarantine NSG, else by deny rules (the fallback);
partial isolations recorded; sessions cut through Run Command (moved from
actions.py, A1).
"""
from __future__ import annotations

import re

from glorfindel.providers.azure.nsg import (
    _allows_passed_by_its_replacement,
    _describe_shadowing,
    _pair_priorities,
    _scope_to_nic,
    _shadowing_rules,
)
from glorfindel.providers.azure.quarantine import _remember_quarantine_outcome, PLATFORM_OPEN_NOTE
from glorfindel.providers.azure.sdk import _enum_text
from glorfindel.providers.azure.turned import _aims_elsewhere, _held_by_turned
from glorfindel.response.ids import _parse_vm_resource_id
from glorfindel.response.policy import _ERR_MAX, _first_line, original_unknown_nics, PartialActionError
from glorfindel.response.state import (
    _load_isolation_state,
    _merge_isolation_placements,
    _previous_placements,
    _save_isolation_state,
)


class IsolationMixin:
    """isolate_vm and the session drain (part of AzureConnector)."""

    def isolate_vm(self, resource_id: str) -> dict:
        """Deny all traffic on EVERY NIC of the VM (fully reversible).

        A VM can have several NICs, each behind its own NSG (or its subnet's NSG).
        Isolating only the primary NIC leaves the others open. So we place one deny
        pair per NIC: any/any on an NSG that governs this VM alone (priority 100,
        bumping conflicts), or scoped to all the NIC's private IPs on an NSG shared with
        other NICs — a subnet NSG or a shared NIC-level NSG (free priority, no bump →
        other VMs untouched). State records every placement for release.

        Partial failure: if a later NIC fails, the denies already in place stay (partial
        containment beats none), are recorded in state with `partial: true`, and a
        PartialActionError is raised. A failure before anything landed raises the
        original error and writes no state (nothing to undo).
        """
        if self.dry_run:
            return {"status": "dry_run", "action": "isolate_vm", "resource_id": resource_id}

        self._guard_write("isolate_vm")
        self._ensure_clients()
        rg, vm_name = _parse_vm_resource_id(resource_id)
        targets = self._get_vm_nic_targets(rg, vm_name, allow_no_nsg=True)
        quarantine_on, _ = self._quarantine_settings()

        placements: list[dict] = []
        assigned: dict[str, set] = {}  # nsg_key → priorities used during THIS call
        guard: dict = {}               # I4B: what a rewrite would change for another VM, read once
        mates = [t["nic_id"] for t in targets]
        for t in targets:
            # L4: a NIC with no NSG of its own gets Glorfindel's quarantine NSG — nothing
            # of the customer's touched, nothing evaluated before its deny, untouched by a
            # `terraform apply` (the NIC resource keeps an NSG it doesn't manage). Falls
            # back to the subnet NSG's rules if attaching is refused (Azure Policy, IAM).
            quarantine_error = ""
            if t.get("quarantine") or (quarantine_on and "nic_has_nsg" in t):
                try:
                    placements.append(self._quarantine_placement(t, rg))
                    continue
                except Exception as exc:
                    if not t.get("nsg_name"):
                        failed = {"nic_id": t["nic_id"], "applied": [], "bumped": []}
                        partial = self._record_partial_isolation(
                            vm_name, resource_id, placements, failed, exc, total=len(targets))
                        if partial is None:
                            raise
                        raise partial from exc
                    quarantine_error = _first_line(exc)[:_ERR_MAX]
            if not t.get("nsg_name"):
                raise RuntimeError(
                    f"NIC {t['nic_short']} has no NSG and the quarantine NSG is disabled — "
                    "cannot isolate (enable `isolation.quarantine_nsg` or add an NSG)")
            nsg_rg, nsg_name, scope = t["nsg_rg"], t["nsg_name"], t["scope"]
            nsg_key = f"{nsg_rg}/{nsg_name}"
            pairs = [(b, f"{b}-out") for b in
                     self._placement_rule_bases("glorfindel-iso", vm_name, t["nic_short"], t["nic_id"])]
            in_name, out_name = pairs[0]
            placement = {
                "nic_id": t["nic_id"], "nsg_rg": nsg_rg, "nsg_name": nsg_name,
                "scope": scope, "shared_nsg": bool(t.get("shared_nsg", False)),
                "ips": t["private_ips"], "priority": None,
                "rule_in": in_name, "rule_out": out_name,
                "bumped": [],    # customer rules moved off priority 100 (restored on release)
                "applied": [],   # deny rules confirmed by Azure
            }
            if quarantine_error:
                placement["quarantine_error"] = quarantine_error
            try:
                # Never move a customer rule (a `terraform apply` puts it back, or fails
                # on the priority we took): the deny takes the first free priority. An
                # ALLOW evaluated before it would let its traffic through — then use the
                # NIC's other NSG if it has one: traffic must pass both, a deny in either
                # holds. Plan both before writing anything.
                plan = self._plan_isolation(t, nsg_rg, nsg_name, _scope_to_nic(t), assigned, pairs, guard, mates)
                alt = t.get("alt_nsg")
                if plan["shadowed"] and alt:
                    alt_plan = self._plan_isolation(t, alt["nsg_rg"], alt["nsg_name"], True, assigned, pairs,
                                                    guard, mates)
                    if not alt_plan["shadowed"]:
                        placement.update({
                            "nsg_rg": alt["nsg_rg"], "nsg_name": alt["nsg_name"],
                            "scope": "subnet", "shared_nsg": False,
                            "moved_from": {"nsg": nsg_key, "because": plan["shadowed"]},
                        })
                        nsg_rg, nsg_name, nsg_key = alt["nsg_rg"], alt["nsg_name"], alt_plan["nsg_key"]
                        plan = alt_plan
                priority = plan["priority"]
                placement["priority"] = priority["inbound"]
                in_name, out_name = plan["own"]
                placement.update({"rule_in": in_name, "rule_out": out_name})
                ips = t["private_ips"]
                if plan["ip_scoped"]:
                    if not ips:
                        raise RuntimeError(
                            f"NIC {t['nic_short']} has no private IP — cannot scope isolation "
                            "on its shared NSG"
                        )
                    self._put_deny_rule(nsg_rg, nsg_name, in_name, "Inbound", priority["inbound"], src="*", dsts=ips)
                    placement["applied"].append(in_name)
                    self._put_deny_rule(nsg_rg, nsg_name, out_name, "Outbound", priority["outbound"], srcs=ips, dst="*")
                    placement["applied"].append(out_name)
                else:
                    # NSG governing this VM only: any/any affects nobody else.
                    self._put_deny_rule(nsg_rg, nsg_name, in_name, "Inbound", priority["inbound"], src="*", dst="*")
                    placement["applied"].append(in_name)
                    self._put_deny_rule(nsg_rg, nsg_name, out_name, "Outbound", priority["outbound"], src="*", dst="*")
                    placement["applied"].append(out_name)
                # Still recorded when no alternative was clean: verify escalates on it.
                placement["shadowed_by"] = plan["shadowed"]
                if plan["left"]:
                    placement["left"] = plan["left"]
                # The other pair's rules: ours, aimed at no other VM — the deny now holds (I4B).
                for nm in plan["drop"]:
                    if err := self._delete_rule(nsg_rg, nsg_name, nm):
                        placement.setdefault("left", []).append(
                            {"nsg": f"{nsg_rg}/{nsg_name}", "rule": nm, "why": f"{nsg_rg}/{nsg_name}/{nm} n'a pas pu être retirée : {err}"})
            except Exception as exc:
                partial = self._record_partial_isolation(
                    vm_name, resource_id, placements, placement, exc, total=len(targets))
                if partial is None:
                    raise
                raise partial from exc

            assigned.setdefault(nsg_key, set()).update(priority.values())
            placements.append(placement)

        # Persist state ONLY after every deny rule is confirmed on Azure (a 403 mid-way
        # must not leave an orphan "ISOLATED" state). placements[] drives release/verify;
        # the flat nsg/nsg_scope/rule_names fields keep /api/state + legacy paths working.
        from datetime import datetime, timezone
        first = placements[0]
        merged = _merge_isolation_placements(_previous_placements(resource_id), placements)
        # In our quarantine, its original unknown (Q7, or beside a state that can't be
        # read): its release will ask for the tag — said now, not first then (SEC4b).
        unknown = original_unknown_nics(merged)
        _save_isolation_state(resource_id, {
            "resource_id": resource_id,
            "isolated_at": datetime.now(timezone.utc).isoformat(),
            "scoped": True,
            "placements": merged,
            "nsg_rg": first["nsg_rg"], "nsg_name": first["nsg_name"], "nsg_scope": first["scope"],
            "rule_names": [p["rule_in"] for p in placements] + [p["rule_out"] for p in placements],
            **({"original_unknown": unknown} if unknown else {}),
        })

        out = {
            "status": "isolated",
            "resource_id": resource_id,
            "scoped": True,
            "nics_covered": len(placements),
            "placements": [
                {"nsg": f'{p["nsg_rg"]}/{p["nsg_name"]}', "scope": p["scope"],
                 **({"moved_from": p["moved_from"]["nsg"]} if p.get("moved_from") else {})}
                for p in placements
            ],
            # Back-compat summary (first placement)
            "nsg": f'{first["nsg_rg"]}/{first["nsg_name"]}',
            "nsg_scope": first["scope"],
            "rule": first["rule_in"],
            **({"original_unknown": unknown,
                "original_note": "NSG d'origine inconnu pour " + ", ".join(unknown) + " : la levée "
                "demandera le tag glorfindel-orig-<hash> sur le NSG de quarantaine (=<id du NSG> ou "
                "=none)"} if unknown else {}),
        }
        if any(p["scope"] == "subnet" for p in placements):
            out["note"] = (
                "subnet-level NSG involved — isolation scoped to this VM's private IP(s) "
                "only (no impact on other VMs on the subnet)."
            )
        if any(p["shared_nsg"] for p in placements):
            out["note"] = (
                "NSG shared with other NICs involved — isolation scoped to this VM's "
                "private IP(s) only (no impact on the other VMs behind that NSG)."
            )
        left = [x for p in placements for x in p.get("left", [])]
        if left:
            out["left_rules"] = left
            out["left_note"] = _describe_iso_left(left)
        if any(p.get("kind") == "quarantine" for p in placements):
            out["note"] = (
                "Glorfindel's quarantine NSG on the NIC(s) for the time of the isolation — "
                "the customer's own NSG (if any) is left untouched and goes back on release."
            )
        refused = [p["quarantine_error"] for p in placements if p.get("quarantine_error")]
        if refused:
            out["quarantine_refused"] = refused
        _remember_quarantine_outcome(resource_id, refused, placements)
        by_rules = [p["nic_id"].rstrip("/").rsplit("/", 1)[-1] for p in placements if p.get("kind") != "quarantine"]
        if by_rules:
            out["platform_open"] = by_rules           # Q15: said, not hidden
            out["platform_note"] = PLATFORM_OPEN_NOTE
        shadowed = [s for p in placements for s in p.get("shadowed_by", [])]
        if shadowed:
            out["shadowed_by"] = shadowed
            out["bypass"] = (
                "Isolation contournée : " + _describe_shadowing(shadowed)
                + " passe avant le deny de Glorfindel."
            )
        # The rules only stop NEW connections: measured 2026-10-05, an attacker's SSH
        # session (17 min), an idle one (11 min) and an outbound download all survived
        # the isolation. Cut them from inside, now that nothing can reconnect.
        out["drain"] = self.drain_connections(resource_id)
        # Kept with the isolation: `list` and the War Room must show that sessions were
        # left open, not only the response of the call (validation run, 2026-10-05).
        try:
            _, _vm = _parse_vm_resource_id(resource_id)
            state = _load_isolation_state(resource_id)
            if state is not None:
                _save_isolation_state(resource_id, {**state, "drain": out["drain"]})
        except Exception:
            pass
        return out

    # Connections a drain must never cut: loopback (local services) and the Azure
    # platform addresses the VM agent, Run Command and IMDS depend on.
    _DRAIN_FILTER = (
        "( not dst 127.0.0.0/8 and not dst [::1] "
        "and not dst 168.63.129.16 and not dst 169.254.169.254 )"
    )

    def drain_connections(self, resource_id: str) -> dict:
        """Kill the VM's established TCP connections through Run Command (`ss -K`).

        Run Command still works on an isolated VM (platform address, not filtered by
        NSGs) and `ss -K` cut every session in the bench test. Linux only: on Windows
        the outcome says the sessions were not cut. Never raises — the isolation rules
        are in place either way; the outcome tells whether open sessions survive.
        """
        if self.dry_run:
            return {"status": "dry_run"}
        try:
            from azure.mgmt.compute.models import RunCommandInput
            rg, vm_name = _parse_vm_resource_id(resource_id)
            vm = self._compute.virtual_machines.get(rg, vm_name)
            os_type = _enum_text(getattr(getattr(vm.storage_profile, "os_disk", None), "os_type", "") or "")
            if "windows" in os_type.lower():
                return {"status": "unsupported",
                        "note": "Windows : les sessions déjà ouvertes ne sont pas coupées."}
            # The count must fail loudly: `ss … | wc -l` printed 0 when `ss` was missing
            # or refused -H — "nothing left" on an unknown.
            import shlex
            flt = self._DRAIN_FILTER
            # Investigation sessions survive — only what the forensic allow lets in: TCP
            # from the source to a forensic port of the VM, i.e. the session's LOCAL port
            # (sixth review, S8). Any other session with that host — another port, or one the
            # VM opened towards it — is cut like the rest. Validated networks and ports only
            # (Q5): the raw value went into this shell command as is.
            ports = self._forensic_ports()
            local = " or ".join(f"sport = :{int(port)}" for port in ports)
            for cidr in (self._forensic_sources() if ports else []):
                flt = flt[:-1] + f"and not ( dst {cidr} and ( {local} ) ) )"
            flt = shlex.quote(flt)
            script = [
                f"ss -K state established {flt} >/dev/null 2>&1",
                f"if out=$(ss -Htn state established {flt} 2>/dev/null); "
                f"then echo \"glorfindel-drain-remaining=$(printf '%s\\n' \"$out\" | grep -c .)\"; "
                f"else echo glorfindel-drain-remaining=error; fi",
            ]
            res = self._compute.virtual_machines.begin_run_command(
                rg, vm_name, RunCommandInput(command_id="RunShellScript", script=script),
            ).result(timeout=300)   # an unresponsive VM agent must not hold the watch worker
            text = " ".join(str(getattr(v, "message", "") or "") for v in (getattr(res, "value", None) or []))
            if "glorfindel-drain-remaining=error" in text:
                return {"status": "failed",
                        "error": "sessions restantes non comptées (`ss` absent ou en erreur)"}
            m = re.search(r"glorfindel-drain-remaining=(\d+)", text)
            if m is None:
                return {"status": "failed", "error": "sortie de Run Command illisible"}
            remaining = int(m.group(1))
            if remaining:
                return {"status": "partial", "remaining": remaining,
                        "error": f"{remaining} connexion(s) encore établie(s) après ss -K"}
            return {"status": "drained"}
        except Exception as e:
            return {"status": "failed", "error": _first_line(e)[:_ERR_MAX]}

    def _record_partial_isolation(
        self, vm_name: str, resource_id: str, done: list[dict], failed: dict,
        exc: BaseException, *, total: int,
    ) -> PartialActionError | None:
        """Persist what a failed isolation left on Azure; build the error to raise.

        Returns None when nothing landed (no state written — the caller re-raises the
        original error, exactly as before). Otherwise writes a `partial` state covering
        every rule still in place, so release / reset can find and remove them.
        """
        # A customer rule moved off priority 100 for a deny that never landed protects
        # nothing: put it back now. If that fails too, keep it in state for release.
        if failed["bumped"] and not failed["applied"]:
            failed["bumped"] = self._restore_bumped(
                failed["nsg_rg"], failed["nsg_name"], failed["bumped"])
        kept = done + ([failed] if failed["applied"] or failed["bumped"] else [])
        if not kept:
            return None

        from datetime import datetime, timezone
        failed_nic = failed["nic_id"].rstrip("/").split("/")[-1]
        covered = [p["nic_id"].rstrip("/").split("/")[-1] for p in done]
        first = kept[0]
        _save_isolation_state(resource_id, {
            "resource_id": resource_id,
            "isolated_at": datetime.now(timezone.utc).isoformat(),
            "scoped": True,
            "partial": True,
            "failed_nic": failed_nic,
            "error": _first_line(exc)[:300],
            # A re-isolation that fails on NIC 2 still leaves NIC 2's earlier isolation
            # on Azure: it stays recorded (L24 — the state used to forget it).
            "placements": _merge_isolation_placements(_previous_placements(resource_id), kept),
            "nsg_rg": first["nsg_rg"], "nsg_name": first["nsg_name"], "nsg_scope": first["scope"],
            "rule_names": [p["rule_in"] for p in kept] + [p["rule_out"] for p in kept],
        })
        return PartialActionError(
            f"Isolation partielle de {vm_name} : {len(done)}/{total} NIC(s) couverte(s), "
            f"échec sur {failed_nic} ({_first_line(exc)}). Les règles déjà posées restent "
            "en place et sont enregistrées — `glorfindel reset` pour les retirer.",
            cause=exc, covered=covered, failed_nic=failed_nic,
        )

    def _plan_isolation(self, t: dict, nsg_rg: str, nsg_name: str, ip_scoped: bool,
                        assigned: dict, pairs: list[tuple[str, str]], guard: dict, mates: list) -> dict:
        """Priority an isolation deny would take on this NSG, and the customer ALLOW
        rules that would be evaluated before it (nothing written). `own`: our rule
        names — a re-application keeps their place or moves them up, never down
        (_pair_priorities): the first of `pairs` (the NIC's name, then its second, I4B)
        none of whose rules present would change another VM's flows, rewritten — one of
        ours turned into an allow that opens the VM given the NIC's old address, or our
        deny there a turned rule waits behind (_held_by_turned: the unblock's, the
        release's guard). Those stay as they are (`left`, said); the other pair's rules
        present go once the deny holds (`drop`) — but a deny of theirs before an allow the
        new one comes after (I4D, seed 1618): taken off, that allow opened the VM; it stays,
        said in `left`. Both pairs held: this NIC fails."""
        nsg_key = f"{nsg_rg}/{nsg_name}"
        existing = list(self._network.security_rules.list(nsg_rg, nsg_name))
        by_name = {(getattr(r, "name", "") or "").lower(): r for r in existing}
        left: list[dict] = []
        own = None
        for pair in pairs:
            held = [{"nsg": nsg_key, "rule": n, "why": why} for n in pair if n.lower() in by_name
                    and _aims_elsewhere(by_name[n.lower()], t["private_ips"])
                    and (why := _held_by_turned(self._network, guard, nsg_rg, nsg_name, n, t["nic_id"], mates))]
            own = own or (pair if not held else None)
            left += held
        if own is None:
            raise RuntimeError(f"NIC {t['nic_short']} : les noms de son isolation sur {nsg_name} sont pris par des "
                               "règles qui changeraient les flux d'une autre VM — rien n'est écrit par-dessus. "
                               + _describe_iso_left(left))
        taken = {x["rule"].lower() for x in left}
        drop = [n for pair in pairs if pair != own for n in pair if n.lower() in by_name and n.lower() not in taken]
        priority = _pair_priorities(existing, *own, self.ISOLATION_PRIORITY, 1, assigned.get(nsg_key, set()))
        # I4D: a deny of the other pair before an allow its replacement comes after stays.
        for n in list(drop):
            if passed := _allows_passed_by_its_replacement(existing, by_name[n.lower()], priority):
                drop.remove(n)
                left.append({"nsg": nsg_key, "rule": n, "why": (
                    f"{nsg_key}/{n}, notre deny, passe avant {', '.join(passed)} ; la règle qui la remplace "
                    f"passe après (priorité {priority[_enum_text(by_name[n.lower()].direction)]}) : la retirer "
                    f"ouvrirait {t['nic_short']}")})
        ips = t["private_ips"] or None
        shadowed = _shadowing_rules(existing, priority, inbound_src=None, inbound_dst=ips,
                                    outbound_src=ips, outbound_dst=None)
        return {"nsg_key": nsg_key, "priority": priority, "ip_scoped": ip_scoped,
                "shadowed": shadowed, "own": own, "left": left, "drop": drop}


def _describe_iso_left(left: list[dict]) -> str:
    """What an isolation left as it was (I4B), and why."""
    return "Laissée(s) telle(s) quelle(s) : " + " ; ".join(f"{x['why']}" for x in left) + "."
