"""Glorfindel's quarantine NSG (L4): attached to a NIC for the time of its isolation,
the NIC's own NSG recorded in state and as a tag; its content checked against what it
must hold (moved from actions.py, A1).
"""
from __future__ import annotations

import os

from glorfindel.providers.azure.nsg import _rule_name, _rule_signature
from glorfindel.providers.azure.sdk import _enum_text, _is_not_found
from glorfindel.response.ids import _parse_nsg_resource_id, _same_id
from glorfindel.response.locks import _quarantine_lock
from glorfindel.response.state import _held_in_quarantine, _recorded_original, _UNKNOWN


# Lot L4 — Glorfindel's own quarantine NSG, attached to a NIC that has none of its own.
QUARANTINE_NSG_PREFIX = "nsg-glorfindel-quarantine"
QUARANTINE_RULE_IN = "glorfindel-quarantine-deny-in"
QUARANTINE_RULE_OUT = "glorfindel-quarantine-deny-out"
# NSGs don't filter the platform addresses (168.63.129.16 DNS, 169.254.169.254 IMDS)
# unless a rule names their service tags: an "isolated" VM still resolved names through
# Azure DNS (a tunnel) and fetched managed-identity tokens from IMDS (measured on the
# bench, 2026-10-07). The VM agent (Run Command, used to cut sessions) talks to the
# WireServer, which these tags don't cover.
QUARANTINE_PLATFORM_RULES = (
    ("glorfindel-quarantine-deny-dns", 110, "AzurePlatformDNS"),
    ("glorfindel-quarantine-deny-imds", 111, "AzurePlatformIMDS"),
)
QUARANTINE_FORENSIC_RULE = "glorfindel-quarantine-forensic-in"
# The rules fallback can't deny them for one VM: Azure refuses a rule to these service
# tags unless its source is "*" (InvalidDNSExfilSourceTag, measured on the bench
# 2026-10-08, DNS and IMDS alike) — on a shared NSG that would cut every VM behind it.
# The fallback says they stay reachable (fourth review, Q15); only the quarantine NSG,
# attached to the isolated NIC alone, denies them.
# Not on a NIC NSG that looks dedicated either (decision 19/10, docs/azure.md): a "*"
# rule reaches every NIC on that NSG, now or later — a NIC away in quarantine (L24) or one
# attached during the isolation would lose DNS/IMDS. Don't add it.
PLATFORM_OPEN_NOTE = ("DNS et IMDS d'Azure encore joignables : le repli par règles ne peut "
                      "pas les refuser à une seule VM (Azure exige la source « * »)")


def _remember_quarantine_outcome(resource_id: str, refused: list, placements: list) -> None:
    """Tell the readiness gate what the isolation met (sixth review, S7): a quarantine
    swap refused at execution — an Azure Policy, a right the permissions read can't see —
    becomes a reserve of the VM; an isolation that put the quarantine on every NIC clears
    it. Best effort: never in the way of an isolation."""
    try:
        from glorfindel import readiness
        if refused:
            readiness.record_quarantine_refusal(resource_id, refused)
        elif placements and all(p.get("kind") == "quarantine" for p in placements):
            readiness.clear_quarantine_refusal(resource_id)
    except Exception:
        pass


def _is_quarantine_nsg(nsg_id_or_name: str) -> bool:
    name = (nsg_id_or_name or "").rstrip("/").split("/")[-1].lower()
    return name.startswith(QUARANTINE_NSG_PREFIX)


# Our quarantine denies: deny-all at 100, Azure's DNS and IMDS at 110 / 111.
_QUARANTINE_LAST_DENY = 111


def _opens_quarantine(rule) -> bool:
    """A rule in our quarantine NSG that could let traffic through: an allow evaluated
    before our last deny. A deny, or an allow after them, changes nothing."""
    prio = getattr(rule, "priority", None)
    return (_enum_text(getattr(rule, "access", "")) == "allow"
            and (not isinstance(prio, int) or prio <= _QUARANTINE_LAST_DENY))


class OriginalUnknown(RuntimeError):
    """The NSG a NIC carried before its quarantine is not known: neither the state nor
    the quarantine NSG's tag says. The NIC stays in quarantine — putting "no NSG" back
    on a guess left NICs without their NSG (fourth review, Q7)."""


class QuarantineMixin:
    """The quarantine NSG: placement, original NSG, content (part of AzureConnector)."""

    def _quarantine_placement(self, t: dict, default_rg: str) -> dict:
        """Put the quarantine NSG on this NIC (JIT); the placement to record.

        A NIC with no NSG gets ours attached (L4). A NIC with its own NSG gets ours IN
        PLACE of it, for the time of the isolation: the customer's NSG and its rules are
        left untouched, and go back on release. Measured on the bench (2026-10-06,
        azurerm 4.81.0): `terraform plan` sees no change and `apply` reverts nothing —
        the NIC resource doesn't hold its NSG, the association only checks that the NIC
        has one. Only a forced replacement of the association, or a Bicep/ARM redeploy
        of the NIC, puts the customer's NSG back (L5 notices). The original is recorded
        in state and, before the swap, as a tag on our NSG — Azure keeps the answer even
        if the local state is lost."""
        current = t.get("quarantine")
        # The NIC already carries one of Glorfindel's quarantine NSGs — whichever: a
        # changed `quarantine_rg`, a config unreadable then read again, another region
        # setting. It is a RE-application on THAT NSG. Taken for a first placement, the
        # NIC's "own" NSG read as none, "none" was recorded, the old placement that knew
        # the real original was replaced, and the release left the NIC without its NSG
        # while verify_release said verified (sixth review, S1).
        q = (self._ensure_quarantine_nsg(t.get("location"), default_rg, at=current) if current
             else self._ensure_quarantine_nsg(t.get("location"), default_rg))
        if current:
            # The state knows the original; the tag is the fallback. Neither says →
            # unknown, never recorded as "none" (the placement then carries no
            # original, and the release keeps the NIC in quarantine rather than guess).
            original = _recorded_original(t["nic_id"])
            if original is _UNKNOWN:
                try:
                    original = self._original_from_tags(q, t["nic_id"])
                except OriginalUnknown:
                    original = _UNKNOWN
        else:
            original = t.get("own_nsg_id") or None
            if original is None:
                # A bare NIC may have been in our quarantine before, and left bare by
                # someone else: what was recorded then (state, or our tag) still stands.
                # Re-isolating it recorded "none" over it, and the release then left it
                # with no NSG (seventh review, U2).
                recorded = prior = _recorded_original(t["nic_id"])
                unread = False
                if prior is _UNKNOWN or prior is None:
                    try:
                        prior = self._bare_nic_original(t, default_rg)[0]
                    except Exception:
                        # Our tag unreadable (a 429): what it says is unknown. Read as
                        # "none", it was written over the tag — a valid original lost
                        # with the state, the NIC released bare (I8F). The state's own
                        # explicit "none" still holds.
                        prior, unread = _UNKNOWN, True
                if prior and prior is not _UNKNOWN:
                    original = prior
                elif unread and recorded is _UNKNOWN:
                    original = _UNKNOWN
                elif recorded is _UNKNOWN and prior is _UNKNOWN and _held_in_quarantine(t["nic_id"]):
                    # Our state has it in quarantine, its original unknown (state and
                    # tags lost before a re-isolation), and someone left it bare: the
                    # bare NIC is theirs, not its design. Recorded "none", the release
                    # left it with no NSG and said released — an old isolation still on
                    # its own NSG, and nothing recorded it any more (I8F).
                    original = _UNKNOWN
            # Recorded even when the NIC had no NSG: "none" said explicitly, so a tag
            # that is missing means unknown (Q7), not "put no NSG back". An unknown is
            # left unwritten: the missing tag says it.
            if original is not _UNKNOWN:
                self._record_original(q, t["nic_id"], original)
            # The swap only happens if the NIC still carries what was read: its return
            # was ignored, and a NIC changed in between was reported isolated (S1).
            if not self._set_nic_nsg(t["nic_id"], q["nsg_id"], expect=t.get("own_nsg_id") or ""):
                raise RuntimeError(f"{t['nic_short']} changed since it was read — quarantine NSG "
                                   "not attached")
            # Read back, as the release does: another host's write right after ours (a
            # pipeline, another watch — our lock is per host) left the NIC elsewhere, and
            # it was reported isolated (A0). Unreadable: the swap was accepted, the
            # verification decides.
            try:
                now = self._nic_nsg_id(t["nic_id"])
            except Exception:
                now = q["nsg_id"]
            if not _same_id(now or "", q["nsg_id"]):
                raise RuntimeError(f"{t['nic_short']} changed right after the swap "
                                   f"({(now or 'no NSG').rsplit('/', 1)[-1]}) — not isolated by quarantine")
        return {
            "nic_id": t["nic_id"], "kind": "quarantine", "scope": "quarantine",
            "nsg_rg": q["nsg_rg"], "nsg_name": q["nsg_name"], "nsg_id": q["nsg_id"],
            **({} if original is _UNKNOWN else {"original_nsg_id": original}),
            "shared_nsg": False, "ips": t["private_ips"], "priority": 100,
            "rule_in": QUARANTINE_RULE_IN, "rule_out": QUARANTINE_RULE_OUT,
            "bumped": [], "applied": ["nic-attach"], "shadowed_by": [],
        }

    @staticmethod
    def _orig_tag(nic_id: str) -> str:
        import hashlib
        return "glorfindel-orig-" + hashlib.sha1(nic_id.rstrip("/").lower().encode()).hexdigest()[:12]

    def _quarantine_tags(self, q: dict) -> dict:
        nsg = self._network.network_security_groups.get(q["nsg_rg"], q["nsg_name"])
        return dict(getattr(nsg, "tags", None) or {})

    def _write_quarantine_tags(self, q: dict, tags: dict) -> None:
        from azure.mgmt.network.models import TagsObject
        self._network.network_security_groups.update_tags(q["nsg_rg"], q["nsg_name"], TagsObject(tags=tags))

    _NO_ORIGINAL = "none"

    def _record_original(self, q: dict, nic_id: str, original_id: str | None) -> None:
        """NIC → its own NSG (or "none"), kept as a tag on our quarantine NSG (not on
        the NIC: a `terraform apply` rewrites the NIC's tags — measured).

        The quarantine NSG is shared by every isolation in the region: the tags are
        rewritten whole, so two isolations at once (N VMs on one rule, the War Room next
        to the watch) erased each other's tag. Read-modify-write under a lock, then read
        back: a tag that didn't land raises, and the NIC is not swapped."""
        key = self._orig_tag(nic_id)
        value = original_id or self._NO_ORIGINAL
        with _quarantine_lock(q["nsg_id"]):
            tags = self._quarantine_tags(q)
            tags[key] = value
            self._write_quarantine_tags(q, tags)
            if self._quarantine_tags(q).get(key) != value:
                raise RuntimeError(f"original NSG of {nic_id.rsplit('/', 1)[-1]} not recorded "
                                   "on the quarantine NSG (tag overwritten)")

    def _original_from_tags(self, q: dict, nic_id: str) -> str | None:
        """The NIC's original NSG from our tag; None if the tag says the NIC had none.
        A read error RAISES (it used to read as "no original", and the release left the
        NIC with no NSG while verify_release said verified), and so does a MISSING tag
        (OriginalUnknown): written for every NIC since the fourth review (Q7), its
        absence is an unknown — a lost write, a hand edit — not "none"."""
        key = self._orig_tag(nic_id)
        value = self._quarantine_tags(q).get(key)
        if not value:
            raise OriginalUnknown(
                f"NSG d'origine de {nic_id.rstrip('/').rsplit('/', 1)[-1]} inconnu : ni l'état local "
                f"ni le tag {key} de {q['nsg_name']} ne le disent. La carte reste en quarantaine — "
                f"poser le tag ({key}=<id du NSG> ou {key}={self._NO_ORIGINAL}) puis relancer la levée.")
        return None if value == self._NO_ORIGINAL else value

    def _forget_original(self, q: dict, nic_id: str) -> None:
        try:
            with _quarantine_lock(q["nsg_id"]):
                tags = self._quarantine_tags(q)
                if tags.pop(self._orig_tag(nic_id), None) is not None:
                    self._write_quarantine_tags(q, tags)
        except Exception:
            pass     # a stale tag is harmless: it is only read for a NIC carrying our NSG

    def _managed_by_glorfindel(self, nsg_id: str) -> bool:
        """A customer NSG whose name happens to start like ours is not ours: a stateless
        release would have detached it (third review, details). Our quarantine NSGs carry
        `managed-by: glorfindel`. Unreadable → treated as ours: the release then needs
        our tags to proceed, and fails safely rather than detach anything."""
        try:
            nsg_rg, nsg_name = _parse_nsg_resource_id(nsg_id)
            tags = getattr(self._network.network_security_groups.get(nsg_rg, nsg_name), "tags", None) or {}
            return tags.get("managed-by") == "glorfindel"
        except Exception:
            return True

    def _unquarantine(self, nic_id: str, q: dict, original: str | None) -> None:
        """Put the NIC's own NSG back (or none), only if it still carries OURS, then read
        the NIC back: release is done when the ORIGINAL is on it, not when ours is gone
        (verify_release only checks the latter)."""
        if self._set_nic_nsg(nic_id, original, expect=q["nsg_id"]):
            now = self._nic_nsg_id(nic_id)
            if not _same_id(now or "", original or ""):
                raise RuntimeError(
                    f"NSG d'origine non remis sur {nic_id.rsplit('/', 1)[-1]} : la carte porte "
                    f"{(now or 'aucun NSG').rsplit('/', 1)[-1]} au lieu de "
                    f"{(original or 'aucun NSG').rsplit('/', 1)[-1]}")
        self._forget_original(q, nic_id)

    def _bare_nic_original(self, t0: dict, vm_rg: str):
        """A NIC with no NSG at all that was in our quarantine: someone took our NSG off
        and left it bare (seventh review, U2). Our tag still says what it carried — it
        goes only once the original is back. (original or None, the quarantine NSG) when
        a tag is found, (_UNKNOWN, None) otherwise. Looked up on the region's quarantine
        NSG, in the configured group and in the VM's."""
        if t0.get("quarantine") or t0.get("own_nsg_id"):
            return _UNKNOWN, None
        name = f"{QUARANTINE_NSG_PREFIX}-{(t0.get('location') or 'unknown').lower()}"
        groups = [vm_rg]
        try:
            cfg_rg = self._quarantine_settings()[1]
            if cfg_rg:
                groups.insert(0, cfg_rg)
        except Exception:
            pass
        tag = self._orig_tag(t0["nic_id"])

        def found(nsg):
            tags = getattr(nsg, "tags", None) or {}
            value = tags.get(tag) if tags.get("managed-by") == "glorfindel" else None
            if not value:
                return None
            q_rg, q_name = _parse_nsg_resource_id(nsg.id)
            return (None if value == self._NO_ORIGINAL else value), {"nsg_rg": q_rg, "nsg_name": q_name, "nsg_id": nsg.id}

        for q_rg in dict.fromkeys(g.lower() for g in groups):
            try:
                hit = found(self._network.network_security_groups.get(q_rg, name))
            except Exception as exc:
                if _is_not_found(exc):
                    continue
                raise
            if hit:
                return hit
        # The quarantine group may have changed since (or the config can't be read):
        # every quarantine NSG of ours in the subscription, by its name and our tag.
        for nsg in self._network.network_security_groups.list_all():
            if (getattr(nsg, "name", "") or "").lower() == name:
                hit = found(nsg)
                if hit:
                    return hit
        return _UNKNOWN, None

    # ── L4: Glorfindel's quarantine NSG ─────────────────────────────────────────

    def _quarantine_settings(self) -> tuple[bool, str]:
        """(enabled, resource group) from glorfindel-config.yaml `isolation:` — enabled
        by default; GLORFINDEL_QUARANTINE_NSG=0 turns it off."""
        if os.environ.get("GLORFINDEL_QUARANTINE_NSG", "").strip() in ("0", "false", "no"):
            return False, ""
        # An unreadable config RAISES (ConfigError): the defaults used to stand in for
        # it — another quarantine group, `quarantine_nsg: false` ignored — and a
        # re-isolation then recorded "no NSG" as the NIC's original (sixth review, S1).
        from glorfindel.config import load_glorfindel_config
        iso = load_glorfindel_config().isolation
        return bool(iso.quarantine_nsg), iso.quarantine_rg or ""

    def _ensure_quarantine_nsg(self, location: str, default_rg: str, at: dict | None = None) -> dict:
        """Get or create Glorfindel's quarantine NSG for this region: deny-all in and
        out at priority 100, deny to Azure's DNS and IMDS (not filtered otherwise), and
        the operator's forensic sources allowed in (`isolation.forensic_sources`), placed
        before the deny. One per region (a NIC only takes an NSG of its own region and
        subscription), created on first need; an older one gets the missing rules."""
        from azure.mgmt.network.models import NetworkSecurityGroup
        if at:                                  # the quarantine NSG a NIC already carries
            q_rg, name = at["nsg_rg"], at["nsg_name"]
        else:
            _, cfg_rg = self._quarantine_settings()
            q_rg = cfg_rg or default_rg
            name = f"{QUARANTINE_NSG_PREFIX}-{(location or 'unknown').lower()}"
        wanted = self._quarantine_wanted()
        # One creator at a time (Q7): two isolations in the region both read "not found"
        # and both created it — the second creation rewrote the tags, erasing the
        # original NSG the first had just recorded.
        with _quarantine_lock(f"{q_rg}/{name}"):
            try:
                nsg = self._network.network_security_groups.get(q_rg, name)
            except Exception as exc:
                if not _is_not_found(exc):
                    raise
                nsg = self._network.network_security_groups.begin_create_or_update(q_rg, name, NetworkSecurityGroup(
                    location=location,
                    tags={"managed-by": "glorfindel", "purpose": "incident-quarantine"},
                    security_rules=list(wanted.values()),
                )).result()
        # Never adopt an NSG that only has our name (Q6): our rules would land in a
        # customer's NSG, and its own rules would be removed below.
        if (getattr(nsg, "tags", None) or {}).get("managed-by") != "glorfindel":
            raise RuntimeError(f"NSG {q_rg}/{name} exists without the managed-by=glorfindel tag — "
                               "not Glorfindel's quarantine NSG, not adopted")
        rules = {_rule_name(r).lower(): r for r in (getattr(nsg, "security_rules", None) or [])}
        for rule_name, rule in wanted.items():
            current = rules.get(rule_name.lower())
            # Missing, or changed — turned into an allow, moved, narrowed (Q6), or the
            # forensic sources changed in the config: put it back as it must be.
            if current is None or _rule_signature(current) != _rule_signature(rule):
                self._network.security_rules.begin_create_or_update(q_rg, name, rule_name, rule).result()
        # A rule that isn't ours goes only if it could let traffic through before our
        # denies — an allow ahead of them (an allow added by hand, the forensic rule the
        # config no longer wants). A policy's deny (DINE / Modify) is left alone: removed
        # at every isolation, put back by the policy, it read as "removed a second time"
        # (sixth review, S6).
        for low, current in rules.items():
            if low not in {w.lower() for w in wanted} and _opens_quarantine(current):
                self._network.security_rules.begin_delete(q_rg, name, _rule_name(current)).result()
        return {"nsg_rg": q_rg, "nsg_name": name, "nsg_id": nsg.id}

    def _quarantine_wanted(self, with_forensic: bool = True) -> dict:
        """The rules Glorfindel's quarantine NSG carries, by name: deny-all in and out at
        100, deny to Azure's DNS and IMDS (not filtered otherwise), and the validated
        forensic sources allowed in before the deny, on their ports only (Q5)."""
        from azure.mgmt.network.models import SecurityRule

        def _deny(rule_name: str, direction: str) -> SecurityRule:
            return SecurityRule(
                name=rule_name, priority=100, direction=direction, access="Deny",
                protocol="*", source_address_prefix="*", destination_address_prefix="*",
                source_port_range="*", destination_port_range="*",
                description="Glorfindel — incident quarantine (attached only while a VM is isolated)",
            )
        wanted = {QUARANTINE_RULE_IN: _deny(QUARANTINE_RULE_IN, "Inbound"),
                  QUARANTINE_RULE_OUT: _deny(QUARANTINE_RULE_OUT, "Outbound")}
        for rule_name, priority, tag in QUARANTINE_PLATFORM_RULES:
            wanted[rule_name] = SecurityRule(
                name=rule_name, priority=priority, direction="Outbound", access="Deny",
                protocol="*", source_address_prefix="*", destination_address_prefix=tag,
                source_port_range="*", destination_port_range="*",
                description=f"Glorfindel — quarantine: {tag} is not filtered by a deny-all")
        if not with_forensic:
            return wanted                    # the denies only: they don't depend on the config
        forensic, ports = self._forensic_sources(), self._forensic_ports()
        if forensic and ports:
            wanted[QUARANTINE_FORENSIC_RULE] = SecurityRule(
                name=QUARANTINE_FORENSIC_RULE, priority=90, direction="Inbound", access="Allow",
                protocol="Tcp", source_address_prefixes=forensic, destination_address_prefix="*",
                source_port_range="*", destination_port_ranges=[str(p) for p in ports],
                description="Glorfindel — quarantine: investigation access (isolation.forensic_sources)")
        return wanted

    def _quarantine_blocks(self, q: dict, ip: str, cache: dict) -> str:
        """'blocks' | 'open' | 'unknown': does our quarantine NSG, intact, cut `ip` off
        from the NIC? It denies everything but the operator's forensic sources."""
        import ipaddress
        try:
            st, _ = self._quarantine_state(q, cache)
            if st != "ok":
                return "unknown" if st == "unknown" else "open"
            addr = ipaddress.ip_address(ip)
            if any(addr in ipaddress.ip_network(s, strict=False) for s in self._forensic_sources()):
                return "open"
            return "blocks"
        except Exception:
            return "unknown"

    def _quarantine_state(self, q: dict, cache: dict) -> tuple[str, list[str]]:
        """('ok' | 'altered' | 'unknown', what differs) — our quarantine NSG read by its
        content, not by the names of its rules (Q6)."""
        rules = self._list_rules(cache, q["nsg_rg"], q["nsg_name"])
        if rules is None:
            return "unknown", []
        by_name = {_rule_name(r).lower(): r for r in rules}
        from glorfindel.config import ConfigError
        try:
            wanted = self._quarantine_wanted()
            forensic_known = True
        except ConfigError:
            # The forensic allow comes from the config; our denies don't. An emptied
            # quarantine NSG went unseen while the config couldn't be read (seventh
            # review, U4): check the denies, and say the rest is unknown.
            wanted = self._quarantine_wanted(with_forensic=False)
            forensic_known = False
        diff = [n for n, w in wanted.items()
                if n.lower() not in by_name or _rule_signature(by_name[n.lower()]) != _rule_signature(w)]
        if not forensic_known and not diff:
            return "unknown", ["config illisible : accès forensique non vérifiable"]
        diff += [_rule_name(r) for low, r in by_name.items()
                 if low not in {w.lower() for w in wanted} and _opens_quarantine(r)]
        return ("altered" if diff else "ok"), diff

    def find_altered_quarantines(self, nsgs: list | None = None) -> list[dict]:
        """Glorfindel's quarantine NSGs as they read now, with the NICs they hold (I1F).
        The reassertion reads each isolation from its state: a NIC whose state was lost
        stays in a quarantine nobody checked — its deny turned to Udp by hand, the VM was
        reachable on TCP again, in silence.

        [{"nsg_id", "nics", "status": "altered" | "ok" | "unknown", "diff"}] — every
        quarantine NSG of the subscription, each read by content as verify_isolation
        reads it (Q6); "unknown" when the configuration can't be read and our denies
        hold (the forensic access can't be checked). An NSG that only has our name is not
        ours. The whole subscription, always: listed in `quarantine_rg` only, an NSG made
        in another group before the setting changed went unseen (I1F, second review).
        Raises if the NSGs can't be listed: none altered is not unknown. `nsgs`: the
        NSGs the watch's pass already listed (shared with the orphan sweep, A3)."""
        if self.dry_run:
            return []
        self._ensure_clients()
        out: list[dict] = []
        for nsg in (self._network.network_security_groups.list_all() if nsgs is None else nsgs):
            nsg_id = getattr(nsg, "id", "") or ""
            if (not _is_quarantine_nsg(nsg_id)
                    or (getattr(nsg, "tags", None) or {}).get("managed-by") != "glorfindel"):
                continue
            nics = [n.id for n in (getattr(nsg, "network_interfaces", None) or []) if getattr(n, "id", None)]
            q_rg, q_name = _parse_nsg_resource_id(nsg_id)
            cache = {(q_rg, q_name): list(getattr(nsg, "security_rules", None) or [])}
            st, diff = self._quarantine_state({"nsg_rg": q_rg, "nsg_name": q_name}, cache)
            out.append({"nsg_id": nsg_id, "nics": nics, "status": st, "diff": diff})
        return out

    def _forensic_sources(self) -> list[str]:
        """isolation.forensic_sources as validate_forensic_sources keeps them (Q5). An
        unreadable config raises (S1) — no source is guessed."""
        from glorfindel.config import load_glorfindel_config, validate_forensic_sources
        return validate_forensic_sources(load_glorfindel_config().isolation.forensic_sources)[0]

    def _forensic_ports(self) -> list[int]:
        from glorfindel.config import load_glorfindel_config
        return list(load_glorfindel_config().isolation.forensic_ports)
