"""RW1 (#513): the reassertion of a block reads the status its write returns, raised or not.

On AWS, `block_suspicious_ip` answers `{"status": "failed"}` without raising when no ACL entry can
be placed, and `{"status": "partial"}` when an entry does not hold at its read-back (MC1). Read as
written, a `failed` made the card say « ses règles réécrites une fois » of rules never written and
marked the entry put back (`reasserted_at`): never tried again. A `partial` marked the entry
`partial` — held by an operation, out of every later pass — and its card was never written; on the
second time's own path it said « s'il disparaît encore, Glorfindel alertera ». Measured on the AWS
world of MC1 (tests/unit/fake_aws.py), then on a connector shaped like Azure's.
"""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from glorfindel import actions, config, escalations, readiness
from glorfindel.actions import _load_block_entries, _save_block_state
from glorfindel.config import AutonomyConfig
from glorfindel.providers.aws import blocks as aws_blocks
from glorfindel.providers.aws.connector import AwsConnector
from glorfindel.reassert import _write_said, reassert_active

from .fake_aws import ACCOUNT, ATTACKER, REGION, FakeAws, acl_entry, arn

_ACT = AutonomyConfig(default="non_disruptive")
_WEB = arn("i-web1")


@pytest.fixture
def aws(tmp_path, monkeypatch):
    """i-web1 on subnet-app, its ACL allowing everything at 100; the attacker blocked (deny at 99)."""
    monkeypatch.setattr(actions, "_ISOLATION_STATE_DIR", tmp_path / "isolation")
    monkeypatch.setattr(actions, "_BLOCK_STATE_DIR", tmp_path / "blocks")
    cfg = tmp_path / "glorfindel-config.yaml"
    cfg.write_text("isolation:\n  quarantine_nsg: true\n")
    monkeypatch.setattr(config, "_DEFAULT_PATHS", [cfg])
    f = FakeAws()
    f.add_vpc("vpc-a", "10.0.0.0/16")
    f.add_acl("vpc-a", "acl-app", [acl_entry(100, False, "allow", "0.0.0.0/0"),
                                   acl_entry(100, True, "allow", "0.0.0.0/0")])
    f.add_subnet("vpc-a", "subnet-app", "10.0.0.0/24", "acl-app")
    f.add_instance("i-web1", [{"id": "eni-web1", "subnet": "subnet-app", "ips": ["10.0.0.4"], "groups": []}])
    c = AwsConnector(ec2=f, account=ACCOUNT, region=REGION, read_only=False)
    readiness.record_assessment(readiness._verdict("i-web1", []), _WEB)      # its mode is its mode (L6)
    assert c.block_suspicious_ip(ATTACKER, _WEB)["status"] == "blocked"
    assert c.verify_block_ip(ATTACKER, _WEB)["verified"] is True
    return f, c


def _ours_deleted(f: FakeAws) -> None:
    """A `terraform apply` on the ACL: every entry absent from the code goes — ours."""
    acl = f.acls["acl-app"]["entries"]
    for k in [k for k, e in acl.items() if e["action"] == "deny"]:
        del acl[k]


def _cards() -> list[dict]:
    return [e for e in escalations.pending() if e["signal_id"].startswith("reassert-")]


def test_aws_failed_is_a_failure_never_rules_rewritten_and_tried_again_later(aws):
    """No number left before the customer's allow (moved to 1): AWS writes nothing and answers
    `failed`. The card says the put-back failed; the entry is not marked put back."""
    f, c = aws
    _ours_deleted(f)
    acl = f.acls["acl-app"]["entries"]
    for egress in (False, True):
        del acl[(egress, 100)]
        acl[(egress, 1)] = acl_entry(1, egress, "allow", "0.0.0.0/0")
    written = len(f.journal)
    report = reassert_active(c, _ACT)
    assert [r["outcome"] for r in report] == ["failed"], report
    (card,) = _cards()
    assert "le reposer a échoué" in card["reason"] and "aucun numéro libre" in card["reason"]
    assert "réécrites une fois" not in card["reason"] and "reposé une fois" not in card["reason"]
    (b,) = _load_block_entries(_WEB)
    assert not b.get("reasserted_at"), "a write that wrote nothing marked the block put back: never tried again"
    assert b.get("drift_alerted_at")                    # said once, like a write that raises
    assert f.journal[written:] == []                    # nothing written, as AWS said


def test_aws_partial_reread_whole_is_said_and_never_promises_an_alert(aws, monkeypatch):
    """The read-back of each write does not hold (an allow seen a moment, an ACL unreadable): AWS
    answers `partial` and marks the entry — no pass reads it again. Re-read after, it is whole.
    The card says it does not hold whole and that it is no longer read, never « Glorfindel
    alertera »; the next pass, the entry held, says nothing more."""
    f, c = aws
    _ours_deleted(f)
    real_cut, real_block, inside = aws_blocks.cut, c.block_suspicious_ip, []
    monkeypatch.setattr(aws_blocks, "cut", lambda acl, egress, ip: False if inside else real_cut(acl, egress, ip))

    def blind_read_back(*a, **k):
        inside.append(1)
        try:
            return real_block(*a, **k)
        finally:
            inside.pop()
    c.block_suspicious_ip = blind_read_back
    report = reassert_active(c, _ACT)
    assert c.verify_block_ip(ATTACKER, _WEB)["verified"] is True        # whole, read again
    assert [r["outcome"] for r in report] == ["partial"], f"a partial write said nothing: {report}"
    (card,) = _cards()
    assert card["reason"] == report[0]["detail"]
    assert "il ne tient pas en entier" in card["reason"] and "en partie selon le fournisseur" in card["reason"]
    assert "ne le relit plus" in card["reason"]
    assert "alertera" not in card["reason"] and "reposé une fois" not in card["reason"]
    (b,) = _load_block_entries(_WEB)
    assert b.get("partial") and b.get("drift_alerted_at")
    assert reassert_active(c, _ACT) == []                 # held by its mark, as the card says


def test_aws_whole_put_back_is_still_reposed_once(aws):
    """The boundary: a write AWS answers `blocked` is put back once, as before."""
    f, c = aws
    _ours_deleted(f)
    report = reassert_active(c, _ACT)
    assert [r["outcome"] for r in report] == ["reapplied"]
    assert "reposé une fois" in _cards()[0]["reason"]
    assert c.verify_block_ip(ATTACKER, _WEB)["verified"] is True


# ── the second time's own path: an entry scoped to its VM (shaped like Azure's) ─────────────────

_RID = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm"
_IP = "203.0.113.9"


@pytest.fixture
def vm_block():
    readiness.record_assessment(readiness._verdict("vm", []), _RID)
    _save_block_state("vm", _IP, _RID, nsg="rg/nsg", nsg_scope="nic", rule="glorfindel-block-x",
                      scoped=True, placements=[{"nsg_rg": "rg", "nsg_name": "nsg", "rule": "glorfindel-block-x"}])
    c = MagicMock()
    c.verify_block_ip.return_value = {"verified": False, "missing_rules": ["glorfindel-block-x"]}
    return c


def _answers(c, out: dict, whole: bool = True) -> None:
    def write(*a, **k):
        if whole:
            c.verify_block_ip.return_value = {"verified": True}
        return out
    c.block_suspicious_ip.side_effect = write


def test_failed_without_raising_is_a_failure(vm_block):
    c = vm_block
    _answers(c, {"status": "failed", "error": "refusé"}, whole=False)
    report = reassert_active(c, _ACT)
    assert [r["outcome"] for r in report] == ["failed"]
    assert "le reposer a échoué : refusé" in report[0]["detail"]
    (b,) = _load_block_entries(_RID)
    assert not b.get("reasserted_at")


def test_partial_reread_whole_is_not_reposed(vm_block):
    c = vm_block
    _answers(c, {"status": "partial", "bypass": [{"nic": "nic-b", "reason": "non relu"}]})
    report = reassert_active(c, _ACT)
    assert [r["outcome"] for r in report] == ["partial"]
    assert "en partie selon le fournisseur : non relu" in report[0]["detail"]
    assert "alertera" not in report[0]["detail"]


def test_azure_blocked_partial_is_left_to_the_reread(vm_block):
    """Azure's `blocked_partial` (a perimeter written, NICs of another subnet not behind it) is no
    write that failed: the re-read decides, whole here — put back once."""
    c = vm_block
    _answers(c, {"status": "blocked_partial", "uncovered_nics": ["nic-b"]})
    assert [r["outcome"] for r in reassert_active(c, _ACT)] == ["reapplied"]


def test_what_a_write_said():
    assert _write_said({"status": "blocked"}) == ("", "")
    assert _write_said(None) == ("", "")
    assert _write_said({"status": "failed", "bypass": [{"acl": "acl-1", "reason": "aucun numéro libre"}]}) == (
        "failed", "acl-1 : aucun numéro libre")
    assert _write_said({"status": "partial"}) == ("partial", "le fournisseur répond « partial »")
