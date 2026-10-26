"""Glorfindel's quarantine security group, one per VPC (MC1): no rule out, and in only the
operator's forensic sources; it REPLACES the groups of an ENI for the time of an isolation.
The original groups are recorded in the local state and, before the swap, as a tag on the
quarantine group — AWS keeps the answer if the state is lost.

Unlike Azure (an NSG's tags are rewritten whole), create_tags merges by key (H7): two
isolations at once can't erase each other's tag.
"""
from __future__ import annotations

import os

from glorfindel.providers.aws.client import error_code, tags_of
from glorfindel.response import locks as _locks
from glorfindel.response import state as _state

QUARANTINE_SG_NAME = "glorfindel-quarantine"
MANAGED_TAGS = {"managed-by": "glorfindel", "purpose": "incident-quarantine"}
ORIG_TAG = "glorfindel-orig-"
PLATFORM_OPEN_NOTE = ("DNS d'Amazon et IMDS encore joignables : ni un groupe de sécurité ni une ACL "
                      "réseau ne les filtrent (H6, docs/design/monde-aws.md)")
_UNKNOWN = _state._UNKNOWN


def sg_rules(perms) -> list[dict]:
    """IpPermissions → one rule per source (CIDR or group), comparable as dicts."""
    out = []
    for p in perms or []:
        proto = {"6": "tcp", "17": "udp"}.get(str(p.get("IpProtocol", "-1")).lower(),
                                              str(p.get("IpProtocol", "-1")).lower())
        base = {"proto": proto, "from": None if proto == "-1" else p.get("FromPort"),
                "to": None if proto == "-1" else p.get("ToPort")}
        out += [{**base, "cidr": r.get("CidrIp"), "group": None} for r in p.get("IpRanges") or []]
        out += [{**base, "cidr": None, "group": g.get("GroupId")} for g in p.get("UserIdGroupPairs") or []]
    return out


def sg_perm(rule: dict) -> dict:
    p = {"IpProtocol": rule["proto"]}
    if rule["from"] is not None:
        p["FromPort"], p["ToPort"] = rule["from"], rule["to"]
    if rule["cidr"]:
        p["IpRanges"] = [{"CidrIp": rule["cidr"]}]
    else:
        p["UserIdGroupPairs"] = [{"GroupId": rule["group"]}]
    return p


class OriginalUnknown(RuntimeError):
    """The groups an ENI carried before its quarantine are not known: neither the state nor
    the quarantine group's tag says. The ENI stays in quarantine (Q7)."""


class QuarantineMixin:
    """The quarantine security group (part of AwsConnector)."""

    def _quarantine_enabled(self) -> bool:
        """`isolation.quarantine_nsg` (« the quarantine group » on AWS): on by default;
        GLORFINDEL_QUARANTINE_NSG=0 turns it off. An unreadable config RAISES (S1)."""
        if os.environ.get("GLORFINDEL_QUARANTINE_NSG", "").strip() in ("0", "false", "no"):
            return False
        from glorfindel.config import load_glorfindel_config
        return bool(load_glorfindel_config().isolation.quarantine_nsg)

    def _forensic_rules(self) -> list[dict]:
        """The ingress the quarantine group holds: TCP `forensic_ports` from each validated
        `forensic_sources` (Q5). An unreadable config raises: no source is guessed."""
        from glorfindel.config import load_glorfindel_config, validate_forensic_sources
        iso = load_glorfindel_config().isolation
        sources = validate_forensic_sources(iso.forensic_sources)[0]
        return [{"proto": "tcp", "from": p, "to": p, "cidr": s, "group": None}
                for s in sources if ":" not in s for p in iso.forensic_ports]

    @staticmethod
    def _is_ours(sg: dict | None) -> bool:
        return bool(sg) and sg.get("GroupName") == QUARANTINE_SG_NAME and \
            tags_of(sg).get("managed-by") == "glorfindel"

    def _quarantine_sg(self, vpc: str) -> dict | None:
        """The VPC's quarantine group, if it exists and is ours — one with our name and
        without our tag is a customer's, never ours (Q6)."""
        sg = self._sg_named(vpc, QUARANTINE_SG_NAME)
        return sg if self._is_ours(sg) else None

    def _ensure_quarantine_sg(self, vpc: str) -> dict:
        """Get or create the VPC's quarantine group, and put its content back as it must
        be: no egress (a new group allows everything out, H3), ingress only the forensic
        rules. One creator at a time per VPC."""
        wanted = self._forensic_rules()
        with _locks._quarantine_lock(f"aws/{vpc}/{QUARANTINE_SG_NAME}"):
            sg = self._sg_named(vpc, QUARANTINE_SG_NAME)
            if sg is None:
                try:
                    gid = self._ec2.create_security_group(
                        GroupName=QUARANTINE_SG_NAME, VpcId=vpc,
                        Description="Glorfindel - incident quarantine (carried only while an instance is isolated)",
                        TagSpecifications=[{"ResourceType": "security-group",
                                            "Tags": [{"Key": k, "Value": v} for k, v in MANAGED_TAGS.items()]}],
                    )["GroupId"]
                except Exception as exc:
                    if error_code(exc) != "InvalidGroup.Duplicate":       # another host created it
                        raise
                    gid = None
                sg = self._sg(gid) if gid else self._sg_named(vpc, QUARANTINE_SG_NAME)
                if sg is None:
                    raise RuntimeError(f"groupe de quarantaine de {vpc} créé, mais introuvable à la relecture")
            if not self._is_ours(sg):
                raise RuntimeError(f"{sg['GroupId']} s'appelle {QUARANTINE_SG_NAME} sans le tag managed-by=glorfindel "
                                   "— ce n'est pas le groupe de quarantaine de Glorfindel, il n'est pas adopté")
            gid = sg["GroupId"]
            changed = False
            egress = sg_rules(sg.get("IpPermissionsEgress"))
            if egress:
                self._ec2.revoke_security_group_egress(GroupId=gid, IpPermissions=[sg_perm(r) for r in egress])
                changed = True
            ingress = sg_rules(sg.get("IpPermissions"))
            extra = [r for r in ingress if r not in wanted]
            if extra:
                self._ec2.revoke_security_group_ingress(GroupId=gid, IpPermissions=[sg_perm(r) for r in extra])
                changed = True
            missing = [r for r in wanted if r not in ingress]
            if missing:
                self._ec2.authorize_security_group_ingress(GroupId=gid, IpPermissions=[sg_perm(r) for r in missing])
                changed = True
            return self._sg(gid) if changed else sg

    def _quarantine_content(self, sg: dict) -> tuple[str, list[str]]:
        """('ok' | 'altered' | 'unknown', what differs) — read by content. A missing
        forensic allow opens nothing: not an alteration."""
        from glorfindel.config import ConfigError
        diff = [f"sortie {r.get('cidr') or r.get('group')}" for r in sg_rules(sg.get("IpPermissionsEgress"))]
        ingress = sg_rules(sg.get("IpPermissions"))
        try:
            wanted = self._forensic_rules()
        except ConfigError:
            if diff:
                return "altered", diff
            return ("unknown", ["config illisible : accès forensique non vérifiable"]) if ingress else ("ok", [])
        diff += [f"entrée {r.get('cidr') or r.get('group')}" for r in ingress if r not in wanted]
        return ("altered" if diff else "ok"), diff

    # ── the original groups ──────────────────────────────────────────────────────

    @staticmethod
    def _orig_key(eni_id: str) -> str:
        return ORIG_TAG + eni_id

    def _record_original(self, sg_id: str, eni_id: str, groups: list[str]) -> None:
        """ENI → its groups, as a tag on the quarantine group, read back: a tag that didn't
        land raises, and the ENI is not swapped."""
        key, value = self._orig_key(eni_id), ",".join(groups)
        self._ec2.create_tags(Resources=[sg_id], Tags=[{"Key": key, "Value": value}])
        if tags_of(self._sg(sg_id) or {}).get(key) != value:
            raise RuntimeError(f"groupes d'origine de {eni_id} non notés sur {sg_id}")

    def _original_from_tag(self, sg: dict | None, eni_id: str) -> list[str] | None:
        value = tags_of(sg or {}).get(self._orig_key(eni_id))
        return [g for g in value.split(",") if g] if value else None

    def _forget_original(self, sg_id: str, eni_id: str) -> None:
        try:
            self._ec2.delete_tags(Resources=[sg_id], Tags=[{"Key": self._orig_key(eni_id)}])
        except Exception:
            pass      # a stale tag is harmless: it is read for an ENI in quarantine, or put back

    @staticmethod
    def _recorded_original(eni_id: str, state: dict | None = None):
        """The original groups the local state records for this ENI — in `state`, or in
        any isolation recorded — else _UNKNOWN."""
        for iso in ([state] if state is not None else _state.active_isolations()):
            for p in (iso or {}).get("placements") or []:
                if p.get("kind") == "quarantine" and p.get("nic_id") == eni_id and p.get("original_groups"):
                    return list(p["original_groups"])
        return _UNKNOWN

    def _prior_original(self, eni_id: str, sg: dict | None, state: dict | None = None):
        rec = self._recorded_original(eni_id, state)
        if rec is not _UNKNOWN:
            return rec
        tag = self._original_from_tag(sg, eni_id)
        return tag if tag else _UNKNOWN
