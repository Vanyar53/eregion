"""IP blocks on AWS (MC1): deny entries in the network ACL of each subnet of the instance.

A security group only allows, and an ACL entry names one side only (H5): a block on AWS
cuts the attacker off from the whole subnet, never from one instance — and says so
(`scope: subnet`). An ACL entry has no name nor description: only the local state says it
is Glorfindel's, so the state is written BEFORE the entries (intent first), and an entry is
removed only while it still says what Glorfindel wrote and no other recorded block holds it.
"""
from __future__ import annotations

import contextlib
import ipaddress
from datetime import datetime, timezone

from glorfindel.providers.aws.client import is_not_found, parse_instance_arn
from glorfindel.response import locks as _locks
from glorfindel.response import state as _state
from glorfindel.response.policy import _ERR_MAX, _first_line

_LAST = 32766                      # H5: the highest number an entry may take


def _covers(cidr: str | None, ip: str) -> bool:
    try:
        return bool(cidr) and ipaddress.ip_address(ip) in ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False


def _entries(acl: dict, egress: bool) -> list[dict]:
    return sorted((e for e in acl.get("Entries") or [] if bool(e.get("Egress")) == egress),
                  key=lambda e: int(e.get("RuleNumber", 0)))


def _entry(acl: dict, egress: bool, number) -> dict | None:
    return next((e for e in _entries(acl, egress) if int(e.get("RuleNumber", 0)) == number), None)


def _all_traffic(e: dict) -> bool:
    return str(e.get("Protocol", "")) == "-1" and not e.get("PortRange")


def _is_our_deny(e: dict | None, cidr: str) -> bool:
    """Exactly what Glorfindel writes: deny, every protocol, the attacker's /32."""
    return bool(e) and str(e.get("RuleAction", "")).lower() == "deny" and _all_traffic(e) \
        and e.get("CidrBlock") == cidr


def _first_allow(acl: dict, egress: bool, ip: str) -> int:
    """The number of the first entry that lets some traffic of `ip` through; past the last
    number when none does."""
    for e in _entries(acl, egress):
        if str(e.get("RuleAction", "")).lower() == "allow" and _covers(e.get("CidrBlock"), ip):
            return int(e["RuleNumber"])
    return _LAST + 1


def cut(acl: dict, egress: bool, ip: str) -> bool:
    """Is every protocol of `ip` refused in this direction? The first entry covering it
    that is an allow says no, a deny of everything says yes; the `*` entry denies."""
    for e in _entries(acl, egress):
        if not _covers(e.get("CidrBlock"), ip):
            continue
        if str(e.get("RuleAction", "")).lower() == "allow":
            return False
        if _all_traffic(e):
            return True
    return True


def _free_number(acl: dict, egress: bool, below: int) -> int | None:
    """The highest free number below `below` (closest to the customer's own entries)."""
    used = {int(e["RuleNumber"]) for e in _entries(acl, egress)}
    return next((n for n in range(min(below, _LAST + 1) - 1, 0, -1) if n not in used), None)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class BlockMixin:
    """block_suspicious_ip, unblock_ip, verify_block_ip (part of AwsConnector)."""

    @staticmethod
    def _cidr(ip: str) -> str:
        addr = ipaddress.ip_address(ip)
        if addr.version != 4:
            raise ValueError(f"{ip} : IPv6 n'est pas traité sur AWS (MC1)")
        return f"{addr}/32"

    @contextlib.contextmanager
    def _acl_locks(self, acl_ids):
        """One writer at a time per ACL (it is shared by every instance of its subnets),
        taken in a fixed order."""
        with contextlib.ExitStack() as stack:
            for acl_id in sorted(set(acl_ids)):
                stack.enter_context(_locks._quarantine_lock(f"aws/acl/{acl_id}"))
            yield

    def _instance_acls(self, iid: str) -> dict[str, list[str]]:
        """ACL id → the instance's subnets it governs."""
        acls: dict[str, list[str]] = {}
        for e in self._instance_enis(iid):
            if e["subnet"] and e["subnet"] not in {s for v in acls.values() for s in v}:
                acls.setdefault(self._acl_of(e["subnet"])["NetworkAclId"], []).append(e["subnet"])
        return acls

    @staticmethod
    def _held_numbers(ip: str, acl_id: str, but_rid: str = "") -> set[tuple[bool, int]]:
        """(egress, number) of the entries the recorded blocks of `ip` hold on this ACL —
        but those of `but_rid`."""
        held = set()
        for b in _state.active_blocks():
            if b.get("ip") != ip or (but_rid and (b.get("resource_id") or "").lower() == but_rid.lower()):
                continue
            for p in b.get("placements") or []:
                if p.get("acl_id") == acl_id:
                    held |= {(False, p.get("rule_in")), (True, p.get("rule_out"))}
        return held

    def block_suspicious_ip(self, ip: str, resource_id: str, scope: str = "vm", replace: bool = False,
                            threat_port: int | None = None) -> dict:
        """Deny `ip` (every protocol, both directions) in the ACL of each subnet of the
        instance, before the first entry that lets it through. `scope` is read but a
        block is always subnet-wide on AWS; `replace` has nothing to replace."""
        if self.dry_run:
            return {"status": "dry_run", "action": "block_suspicious_ip", "ip": ip, "resource_id": resource_id}
        self._guard_write("block_suspicious_ip")
        cidr = self._cidr(ip)
        _, _, iid = parse_instance_arn(resource_id)
        acls = self._instance_acls(iid)
        placements, bypass, creates = [], [], []
        with self._acl_locks(acls):
            for acl_id in sorted(acls):
                acl = self._acl(acl_id)
                if acl is None:
                    bypass.append({"acl": acl_id, "reason": "ACL introuvable"})
                    continue
                held = self._held_numbers(ip, acl_id)
                numbers = {}
                for egress in (False, True):
                    # An entry another block recorded, intact, and still ahead of every allow
                    # of the attacker — one the customer passed since is not reused.
                    first = _first_allow(acl, egress, ip)
                    reuse = next((n for eg, n in sorted(held, key=lambda x: (x[0], x[1] or 0))
                                  if eg == egress and n and n < first
                                  and _is_our_deny(_entry(acl, egress, n), cidr)), None)
                    if reuse is not None:
                        numbers[egress] = (reuse, False)
                    else:
                        n = _free_number(acl, egress, first)
                        numbers[egress] = (n, True) if n is not None else None
                if None in numbers.values():
                    bypass.append({"acl": acl_id, "reason": "aucun numéro libre avant l'entrée qui laisse passer "
                                   f"{ip} : rien n'est posé sur cette ACL"})
                    continue
                (n_in, new_in), (n_out, new_out) = numbers[False], numbers[True]
                placements.append({"nsg_rg": "aws-acl", "nsg_name": acl_id, "rule": f"{n_in}/{n_out}",
                                   "acl_id": acl_id, "subnets": acls[acl_id], "rule_in": n_in, "rule_out": n_out,
                                   "cidr": cidr})
                creates += [(acl_id, n, eg) for eg, n, new in ((False, n_in, new_in), (True, n_out, new_out)) if new]
            if not placements:
                return {"status": "failed", "action": "block_suspicious_ip", "ip": ip, "resource_id": resource_id,
                        "scope": "subnet", "bypass": bypass}
            first = placements[0]
            record = dict(nsg=first["acl_id"], nsg_scope="subnet", rule=first["rule"], scoped=False,
                          placements=placements, threat_port=threat_port)
            # Intent first: once created, nothing but this record says an entry is ours.
            _state._save_block_state(iid, ip, resource_id, partial=True, **record)
            for acl_id, n, egress in creates:
                self._ec2.create_network_acl_entry(NetworkAclId=acl_id, RuleNumber=n, Protocol="-1",
                                                   RuleAction="deny", Egress=egress, CidrBlock=cidr)
            # Read back: the attacker refused every protocol, both ways, on each ACL.
            for p in placements:
                try:
                    acl = self._acl(p["acl_id"])
                    held_back = acl is not None and cut(acl, False, ip) and cut(acl, True, ip)
                except Exception:
                    held_back = False
                if not held_back:
                    bypass.append({"acl": p["acl_id"], "reason": f"{ip} n'est pas refusé partout sur cette ACL "
                                   "à la relecture"})
            _state._save_block_state(iid, ip, resource_id, partial=bool(bypass), **record)
        return {"status": "partial" if bypass else "blocked", "action": "block_suspicious_ip", "ip": ip,
                "resource_id": resource_id, "scope": "subnet", "scope_requested": scope,
                "placements": placements, "bypass": bypass,
                "note": "sur AWS, un blocage vaut pour tout le sous-réseau (ACL réseau)"}

    def unblock_ip(self, ip: str, resource_id: str) -> dict:
        """Remove the entries this instance's block recorded — those that still say what
        Glorfindel wrote, and that no other recorded block of `ip` holds."""
        if self.dry_run:
            return {"status": "dry_run", "action": "unblock_ip", "ip": ip, "resource_id": resource_id}
        self._guard_write("unblock_ip")
        cidr = self._cidr(ip)
        parse_instance_arn(resource_id)
        entry = next((e for e in _state._load_block_entries(resource_id) if e.get("ip") == ip), None)
        if entry is None:
            return {"status": "not_found", "action": "unblock_ip", "ip": ip, "resource_id": resource_id,
                    "note": "aucun blocage noté : une entrée d'ACL n'a pas de nom, rien ne dit lesquelles "
                            "sont à Glorfindel"}
        _state._update_block_entry(resource_id, ip, unblocking_at=_now())
        placements = [p for p in entry.get("placements") or [] if p.get("acl_id")]
        failed, kept = [], []
        with self._acl_locks(p["acl_id"] for p in placements):
            for p in placements:
                acl_id = p["acl_id"]
                try:
                    acl = self._acl(acl_id)
                    if acl is None:
                        continue                                 # the ACL is gone, its entries with it
                    held = self._held_numbers(ip, acl_id, but_rid=resource_id)
                    for egress, n in ((False, p.get("rule_in")), (True, p.get("rule_out"))):
                        if not n:
                            continue
                        if (egress, n) in held:
                            kept.append(f"{acl_id}/{n}")
                            continue
                        if not _is_our_deny(_entry(acl, egress, n), cidr):
                            continue             # gone, or no longer what Glorfindel wrote: not ours
                        try:
                            self._ec2.delete_network_acl_entry(NetworkAclId=acl_id, RuleNumber=n, Egress=egress)
                        except Exception as exc:
                            if not is_not_found(exc):
                                raise
                except Exception as exc:
                    failed.append({"acl": acl_id, "error": _first_line(exc)[:_ERR_MAX]})
        if failed:
            _state._update_block_entry(resource_id, ip, unblocking_at=None,
                                       unblock_failed="; ".join(f"{f['acl']}: {f['error']}" for f in failed))
            return {"status": "partial", "action": "unblock_ip", "ip": ip, "resource_id": resource_id,
                    "failed": failed}
        _state._clear_block_state(resource_id, ip)
        return {"status": "unblocked", "action": "unblock_ip", "ip": ip, "resource_id": resource_id,
                "kept_for_other_blocks": sorted(set(kept))}

    def verify_block_ip(self, ip: str, resource_id: str) -> dict:
        """True when, on the ACL of each subnet of the instance, the entries this block
        recorded are there as written, and `ip` is refused every protocol both ways."""
        if self.dry_run:
            return {"verified": None, "method": "dry_run"}
        cidr = self._cidr(ip)
        _, _, iid = parse_instance_arn(resource_id)
        entry = next((e for e in _state._load_block_entries(resource_id) if e.get("ip") == ip), None) or {}
        try:
            acls = self._instance_acls(iid)
        except Exception as exc:
            return {"verified": None, "method": "network_acl",
                    "reason": "instance introuvable" if is_not_found(exc) else _first_line(exc)[:_ERR_MAX]}
        missing, bypass, unknown = [], [], []
        for acl_id in sorted(acls):
            try:
                acl = self._acl(acl_id)
            except Exception:
                unknown.append(acl_id)
                continue
            if acl is None:
                unknown.append(acl_id)
                continue
            mine = [p for p in entry.get("placements") or [] if p.get("acl_id") == acl_id]
            if not any(_is_our_deny(_entry(acl, False, p.get("rule_in")), cidr)
                       and _is_our_deny(_entry(acl, True, p.get("rule_out")), cidr) for p in mine):
                missing.append(acl_id)
            elif not (cut(acl, False, ip) and cut(acl, True, ip)):
                bypass.append(acl_id)
        verified = False if (missing or bypass) else (None if unknown else True)
        return {"verified": verified, "method": "network_acl", "scope": "subnet",
                "missing_rules": missing, "bypass": bypass, "unknown": unknown}
