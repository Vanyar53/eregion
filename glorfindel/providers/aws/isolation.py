"""isolate_vm, release_isolation and their verifications on AWS (MC1): every ENI of the
instance by the quarantine security group of its VPC — there is no isolation by rules on
AWS (a security group only allows; a network ACL would cut the whole subnet).
"""
from __future__ import annotations

from datetime import datetime, timezone

from glorfindel.providers.aws.client import is_not_found, parse_instance_arn
from glorfindel.providers.aws.network import same_groups
from glorfindel.providers.aws.quarantine import _UNKNOWN, PLATFORM_OPEN_NOTE, OriginalUnknown
from glorfindel.response import state as _state
from glorfindel.response.policy import _ERR_MAX, PartialActionError, _first_line

# What a re-isolation keeps of the state it replaces: dates and alerts, never the marks
# of an operation that is over (a release that failed or ran, a partial isolation).
_KEPT = ("isolated_at", "reasserted_at", "drift_alerted_at", "ttl_alerted_at")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class IsolationMixin:
    """isolate_vm, release_isolation, verify_isolation, verify_release (part of AwsConnector)."""

    def isolate_vm(self, resource_id: str) -> dict:
        """Every ENI of the instance gets the quarantine group of its VPC in place of its
        groups (fully reversible). A later ENI that fails leaves the earlier ones in
        quarantine (partial containment beats none), recorded with `partial: true`, and
        raises PartialActionError; a failure before anything landed writes no state."""
        if self.dry_run:
            return {"status": "dry_run", "action": "isolate_vm", "resource_id": resource_id}
        self._guard_write("isolate_vm")
        _, _, iid = parse_instance_arn(resource_id)
        # Before any write, and raising when the config can't be read (S1, I10).
        if not self._quarantine_enabled():
            raise RuntimeError(
                "AWS : isolation impossible sans le groupe de quarantaine (isolation.quarantine_nsg "
                "désactivé) — un groupe de sécurité ne refuse rien et une ACL réseau couperait tout le "
                "sous-réseau : il n'y a pas de repli par règles")
        self._forensic_rules()
        enis = self._instance_enis(iid)
        previous = _state._load_isolation_state(resource_id) or {}
        placements: list[dict] = []
        for e in enis:
            try:
                placements.append(self._quarantine_eni(e))
            except Exception as exc:
                if not placements and not previous.get("placements"):
                    raise
                merged = _state._merge_isolation_placements(previous.get("placements") or [], placements)
                _state._save_isolation_state(resource_id, {
                    "resource_id": resource_id, "provider": "aws", "placements": merged,
                    "isolated_at": previous.get("isolated_at") or _now(),
                    "partial": True, "partial_error": _first_line(exc)[:_ERR_MAX]})
                raise PartialActionError(
                    f"isolation partielle de {iid} : {e['eni']} non mise en quarantaine ({_first_line(exc)})",
                    cause=exc, covered=[p["nic_id"] for p in placements], failed_nic=e["eni"]) from exc
        state = {k: previous[k] for k in _KEPT if previous.get(k)}
        state.update({"resource_id": resource_id, "provider": "aws",
                      "placements": _state._merge_isolation_placements(previous.get("placements") or [], placements),
                      "isolated_at": previous.get("isolated_at") or _now()})
        _state._save_isolation_state(resource_id, state)
        try:
            check = self._check_isolation(self._instance_enis(iid))      # as it is now
        except Exception:
            check = {"verified": None, "uncovered_nics": [], "missing_rules": []}
        bypass = check["uncovered_nics"] + check["missing_rules"] + (
            ["vérification impossible"] if check["verified"] is None else [])
        return {"status": "isolated", "action": "isolate_vm", "resource_id": resource_id,
                "method": "quarantine_sg", "placements": placements, "verified": check["verified"],
                "bypass": bypass, "platform_open": [e["eni"] for e in enis],
                "platform_open_note": PLATFORM_OPEN_NOTE,
                "drain": {"status": "unavailable", "reason": "pas de coupure de sessions sur AWS (MC1) : "
                          "une connexion suivie survit au changement de groupes (H10)"}}

    def _quarantine_eni(self, e: dict) -> dict:
        """Put the quarantine group on this ENI; the placement to record."""
        q = self._ensure_quarantine_sg(e["vpc"])
        qid, eni, cur = q["GroupId"], e["eni"], list(e["groups"])
        prior = self._prior_original(eni, q)
        if qid in cur:
            # Already ours (a re-isolation, the reassertion): its original stays what the
            # state or the tag says — never what it carries now. Other groups next to ours
            # (someone added one) come off.
            original = prior
            if same_groups(cur, [qid]):
                if original is not _UNKNOWN and self._original_from_tag(q, eni) is None:
                    try:
                        self._record_original(qid, eni, original)
                    except Exception:
                        pass        # the state still has it
                return self._placement(e, qid, original)
        else:
            default = self._default_sg(e["vpc"])
            # Someone took it out of our quarantine onto `default` (the analog of a NIC left
            # bare): what was recorded then still stands (U2).
            if prior is not _UNKNOWN and default and same_groups(cur, [default]) and not same_groups(prior, cur):
                original = prior
            else:
                original = cur
        if original is not _UNKNOWN:
            self._record_original(qid, eni, original)
        if not self._set_groups(eni, [qid], expect=cur):
            raise RuntimeError(f"{eni} a changé depuis sa lecture — groupe de quarantaine non posé")
        # Read back: another host's write right after ours (A0). Unreadable: the change
        # was accepted, the verification decides.
        try:
            now = self._eni_groups(eni)
        except Exception:
            now = [qid]
        if not same_groups(now, [qid]):
            raise RuntimeError(f"{eni} a changé juste après l'échange ({','.join(now)}) — pas en quarantaine")
        return self._placement(e, qid, original)

    @staticmethod
    def _placement(e: dict, qid: str, original) -> dict:
        return {"nic_id": e["eni"], "kind": "quarantine", "scope": "quarantine", "vpc": e["vpc"],
                "quarantine_sg": qid, "ips": list(e["ips"]), "applied": ["eni-groups"],
                **({} if original is _UNKNOWN else {"original_groups": list(original)})}

    # ── release ────────────────────────────────────────────────────────────────

    def release_isolation(self, resource_id: str) -> dict:
        """Give every ENI in quarantine its original groups back (the state's; else the
        tag's), only while it still carries ours, and read it back. An original unknown,
        or one of its groups deleted since, keeps the ENI in quarantine, said."""
        if self.dry_run:
            return {"status": "dry_run", "action": "release_isolation", "resource_id": resource_id}
        self._guard_write("release_isolation")
        _, _, iid = parse_instance_arn(resource_id)
        state = _state._load_isolation_state(resource_id)
        try:
            enis = self._instance_enis(iid)
        except Exception as exc:
            if not is_not_found(exc):
                raise
            # The instance is gone, its ENIs with it: nothing carries our group any more.
            for p in (state or {}).get("placements") or []:
                if p.get("quarantine_sg"):
                    self._forget_original(p["quarantine_sg"], p["nic_id"])
            _state._clear_isolation_state(resource_id)
            return {"status": "released", "action": "release_isolation", "resource_id": resource_id,
                    "note": "instance supprimée"}
        if state is not None:
            # The intent first: the reassertion must not put back what a release takes off (I9).
            _state._save_isolation_state(resource_id, {**state, "releasing_at": _now()})
        released, failed, keep = [], [], []
        for e in enis:
            try:
                outcome = self._release_eni(e, state)
            except Exception as exc:
                failed.append({"nic": e["eni"], "error": _first_line(exc)[:_ERR_MAX]})
                keep.append(self._kept_placement(e, state))
                continue
            if outcome:
                released.append(outcome)
        if failed:
            _state._save_isolation_state(resource_id, {
                "resource_id": resource_id, "provider": "aws", "placements": keep,
                "isolated_at": (state or {}).get("isolated_at") or _now(),
                "release_failed": "; ".join(f"{f['nic']}: {f['error']}" for f in failed)[:_ERR_MAX]})
            return {"status": "partial" if released else "failed", "action": "release_isolation",
                    "resource_id": resource_id, "released": released, "failed": failed}
        _state._clear_isolation_state(resource_id)
        return {"status": "released", "action": "release_isolation", "resource_id": resource_id,
                "released": released}

    def _kept_placement(self, e: dict, state: dict | None) -> dict:
        try:
            q = self._quarantine_sg(e["vpc"])
        except Exception:
            q = None
        original = self._prior_original(e["eni"], q, state or {})
        return self._placement(e, q["GroupId"] if q else "", original)

    def _release_eni(self, e: dict, state: dict | None) -> str:
        """The ENI back to its original; its id when something was done, "" otherwise.
        Raises when it must stay in quarantine."""
        eni, cur = e["eni"], list(e["groups"])
        q = self._quarantine_sg(e["vpc"])
        qid = q["GroupId"] if q else None
        rec = self._recorded_original(eni, state) if state is not None else _UNKNOWN
        tag = self._original_from_tag(q, eni)
        if qid is None or qid not in cur:
            default = self._default_sg(e["vpc"])
            prior = rec if rec is not _UNKNOWN else tag
            if prior and default and same_groups(cur, [default]) and not same_groups(prior, cur):
                # Taken out of our quarantine onto `default` by someone: its original back.
                self._put_back(eni, prior, cur)
                if qid:
                    self._forget_original(qid, eni)
                return eni
            if qid and tag is not None:
                self._forget_original(qid, eni)
            return ""
        original = self._usable_original(eni, [rec, tag], e["vpc"], q)
        self._put_back(eni, original, cur)
        self._forget_original(qid, eni)
        return eni

    def _usable_original(self, eni: str, candidates: list, vpc: str, q: dict) -> list[str]:
        """The first known original whose groups all still exist in the VPC: the state's,
        else the tag's — the operator's answer when a group was deleted and recreated (a
        new id, H4)."""
        known = [c for c in candidates if c and c is not _UNKNOWN]
        key = self._orig_key(eni)
        if not known:
            raise OriginalUnknown(
                f"groupes d'origine de {eni} inconnus : ni l'état local ni le tag {key} de {q['GroupId']} ne "
                f"les disent. L'ENI reste en quarantaine — poser le tag {key}=<sg-…,sg-…> puis relancer la levée.")
        for groups in known:
            if all((sg := self._sg(g)) is not None and sg.get("VpcId") == vpc for g in groups):
                return list(groups)
        raise RuntimeError(
            f"un groupe d'origine de {eni} ({','.join(known[0])}) n'existe plus. L'ENI reste en quarantaine — "
            f"recréer le groupe, poser le tag {key}=<ses groupes> sur {q['GroupId']}, puis relancer la levée.")

    def _put_back(self, eni: str, original: list[str], cur: list[str]) -> None:
        if not self._set_groups(eni, original, expect=cur):
            raise RuntimeError(f"{eni} a changé depuis sa lecture — groupes d'origine non remis")
        now = self._eni_groups(eni)
        if not same_groups(now, original):
            raise RuntimeError(f"groupes d'origine non remis sur {eni} : elle porte {','.join(now)} au lieu de "
                               f"{','.join(original)}")

    # ── verifications ──────────────────────────────────────────────────────────

    def verify_isolation(self, resource_id: str) -> dict:
        """True only when every ENI carries the quarantine group of its VPC alone, and
        that group is intact (read by content). A read that fails gives None, never True."""
        if self.dry_run:
            return {"verified": None, "method": "dry_run"}
        _, _, iid = parse_instance_arn(resource_id)
        try:
            enis = self._instance_enis(iid)
        except Exception as exc:
            return {"verified": None, "method": "quarantine_sg", "uncovered_nics": [], "missing_rules": [],
                    "reason": "instance introuvable" if is_not_found(exc) else _first_line(exc)[:_ERR_MAX]}
        return self._check_isolation(enis)

    def _check_isolation(self, enis: list[dict]) -> dict:
        uncovered, altered, unknown, cache = [], [], [], {}
        for e in enis:
            try:
                if e["vpc"] not in cache:
                    cache[e["vpc"]] = self._quarantine_sg(e["vpc"])
                q = cache[e["vpc"]]
                if q is None or not same_groups(e["groups"], [q["GroupId"]]):
                    uncovered.append(e["eni"])
                    continue
                st, diff = self._quarantine_content(q)
                if st == "altered":
                    altered += [f"{q['GroupId']}: {d}" for d in diff]
                elif st == "unknown":
                    unknown.append(e["eni"])
            except Exception:
                unknown.append(e["eni"])
        verified = False if (uncovered or altered) else (None if unknown else True)
        return {"verified": verified, "method": "quarantine_sg", "uncovered_nics": uncovered,
                "missing_rules": sorted(set(altered)), "unknown": unknown,
                "platform_open": [e["eni"] for e in enis], "platform_open_note": PLATFORM_OPEN_NOTE,
                "nics": len(enis)}

    def verify_release(self, resource_id: str) -> dict:
        """True only when no ENI carries a quarantine group, and every ENI whose original is
        known (state, tag) carries it."""
        if self.dry_run:
            return {"verified": None, "method": "dry_run"}
        _, _, iid = parse_instance_arn(resource_id)
        state = _state._load_isolation_state(resource_id)
        try:
            enis = self._instance_enis(iid)
            pending = []
            for e in enis:
                q = self._quarantine_sg(e["vpc"])
                if q is not None and q["GroupId"] in e["groups"]:
                    pending.append(e["eni"])
                    continue
                rec = self._recorded_original(e["eni"], state) if state is not None else _UNKNOWN
                prior = rec if rec is not _UNKNOWN else self._original_from_tag(q, e["eni"])
                if prior and not same_groups(prior, e["groups"]):
                    pending.append(e["eni"])
        except Exception as exc:
            return {"verified": None, "method": "quarantine_sg",
                    "reason": "instance introuvable" if is_not_found(exc) else _first_line(exc)[:_ERR_MAX]}
        return {"verified": not pending, "method": "quarantine_sg", "still_isolated": pending}
