"""An older version's isolation record: the single-NSG state written before placements
existed (#8, 06/19) — its NSG, its fixed rule names, the customer rules it moved — and the
same record kept beside the placements of a later isolation of that VM (I4E, #361).

A new isolation wrote its state over the old one: the record was lost, and on an NSG shared
since, nothing tied the old deny-all to its VM any more — « VM inconnue : laissée », every
release after `release_partial`, the VM cut off for ever. Kept now under `legacy`, it is read
wherever the old state was: the release and the reset take its rules off, the verification
looks for them, `_legacy_claimed` ties them to their VM, the Activity Log's reader counts
them as ours.
"""
from __future__ import annotations

import json

from glorfindel.response import state as _state


def _older_record(state) -> dict | None:
    """The older version's record this state holds: the state itself when it has no
    `placements` (written before they existed), or its `legacy` field (kept by a later
    isolation, I4E). None if it holds none."""
    if not isinstance(state, dict):
        return None
    rec = state if "placements" not in state else state.get("legacy")
    if not isinstance(rec, dict) or not rec.get("nsg_name"):
        return None
    return {"nsg_rg": rec.get("nsg_rg"), "nsg_name": rec["nsg_name"],
            "rule_names": [n for n in rec.get("rule_names") or [] if isinstance(n, str)],
            "bumped": list(rec.get("bumped") or [])}


def _kept_legacy(previous, rg: str) -> dict:
    """What a new isolation keeps of the state it writes over: the older version's record,
    under `legacy` (I4E) — its rules are still on Azure until a release takes them off."""
    rec = _older_record(previous)
    return {"legacy": {**rec, "nsg_rg": rec["nsg_rg"] or rg}} if rec else {}


def _legacy_claimed(nsg_rg: str, nsg_name: str, rule: str) -> bool:
    """An older version's single-NSG record names this rule — a state of its own, or kept
    by a later isolation (I4E): it has an owner, whose release deletes it by that record."""
    directory = _state._ISOLATION_STATE_DIR
    if not directory.exists():
        return False
    for f in directory.glob("*.json"):
        try:
            rec = _older_record(json.loads(f.read_text()))
        except Exception:
            continue
        if (rec is not None
                and rec["nsg_name"].lower() == nsg_name.lower()
                and (rec["nsg_rg"] or "").lower() == (nsg_rg or "").lower()
                and rule.lower() in {n.lower() for n in rec["rule_names"]}):
            return True
    return False
