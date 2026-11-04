"""The first of the reassertion's two times for the blocks (L1Qs, #424): every perimeter pair to be
put back, of every entry that holds one, is put back before any VM block is read or written.

A perimeter block covers every VM of its subnet. Read in one go, entry after entry, a block —
another VM's, or an entry holding a perimeter of its own on another subnet — read before a pair it
lies behind was put back said « n'est plus bloquée » of NICs that pair cut off again a moment later
in the same pass: a card false once the pass ended. Sorting the perimeters first (L1Qr) held while
a single entry held a perimeter; two of them, on two subnets, a VM with a NIC behind each, wait for
each other, and no order suits both. So: the pairs first, all of them; then each entry is read
again and finished — its VM's rules, its re-read, its card — in the second time (`reassert`).

Only what the second time would write is written here, decided the same way (`_to_write`): the
entry held by no operation, its rules gone, not already said for this disappearance, outside
human_only, never put back before. The rest — the cards, the marks — is the second time's.
"""
from __future__ import annotations

import logging
from datetime import timezone

log = logging.getLogger(__name__)


def _to_write(b: dict, verification: dict, autonomy, vm: str, rid: str, ip: str, ref: str) -> bool:
    """The entry's rules are written by this pass, the second time would decide from `verification`:
    held whole, never covered, nothing gone, a disappearance already said and no worse, in
    human_only, or put back once before — nothing written."""
    from glorfindel import reassert as r
    from glorfindel.reassert_cards import drift_baseline
    from glorfindel.reassert_said import still_said
    if verification.get("verified") is True and not verification.get("held_missing"):
        return False
    if verification.get("uncovered_nics") and not verification.get("missing_rules"):
        return False
    if not r._missing(verification):
        return False
    if still_said(b, ref or vm, ip, r._alert_id(vm, rid, ip), drift_baseline(ref or vm, ip, b.get("drift_said")),
                  r._situation(verification)):
        return False
    return not (b.get("reasserted_at") or r._mode(autonomy, vm, ref) == "human_only")


def put_back_perimeters(connector, autonomy, blocks: list[dict], report: list[dict]) -> dict:
    """The perimeter pairs of the entries that hold one (`scoped: False`, merged or not), put back
    where the second time would put them back: {(resource id, IP): {"error": the write's, or None;
    "read": the check that decided it — what the card compares a later drift with}}.
    An entry whose lock is held, or whose check raises, is left to the second time."""
    from glorfindel import reassert as r
    from glorfindel.actions import _load_block_entries, _update_block_entry, _vm_lock
    from glorfindel.reassert_cards import episode, unrecorded

    done: dict = {}
    for snapshot in blocks:
        if snapshot.get("scoped") is not False or not snapshot.get("resource_id"):
            continue
        vm, ip, ref = snapshot["vm_name"], snapshot.get("ip", ""), snapshot["resource_id"]
        try:
            with _vm_lock(vm, timeout=r._LOCK_WAIT_S):
                b = next((e for e in _load_block_entries(ref) if e.get("ip") == ip), None)
                rid = (b or {}).get("resource_id", "")
                if (not b or not rid or not ip or b.get("scoped") is not False
                        or r._held_by_an_operation(b, "unblock_failed", "unblocking_at")):
                    continue
                try:
                    verification = connector.verify_block_ip(ip, rid)
                except Exception:
                    continue                        # said by the second time (V-16)
                if not _to_write(b, verification, autonomy, vm, rid, ip, ref):
                    continue
                try:
                    connector.block_suspicious_ip(ip, rid, scope="subnet", threat_port=b.get("threat_port"))
                    err = None
                except Exception as exc:
                    err = f"{exc}"
                done[(rid.rstrip("/").lower(), ip)] = {"error": err, "read": verification}
                if err is None:
                    # Written: marked at once, as the second time would — a pass cut off between
                    # the two times never puts it back a second time as a first. Its episode ends in
                    # the same write, over in memory first (L1O, #507, as `_rewrite_block`): the second
                    # time skipped (its lock held), the marks kept, a pair gone again read « already
                    # said » behind the acknowledged card, whatever the connector writes of the entry.
                    episode(ref, ip, over=True)
                    _update_block_entry(ref, ip, reasserted_at=r.datetime.now(timezone.utc).isoformat(),
                                        drift_alerted_at=None, drift_said=None)
        except TimeoutError:
            continue
        except OSError as exc:
            report.append(unrecorded(vm, exc, ip))
    return done
