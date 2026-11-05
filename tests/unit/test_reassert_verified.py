"""RW2 (#555): the reassertion of an isolation reads what its write answered — `verified`, `bypass`.

On AWS (MC1), `isolate_vm` answers `isolated` whatever its read-back found: `verified` False (an ENI
off the quarantine group after the swap) or None (unreadable), the ENIs named in `bypass`. On Azure,
each deny is confirmed as it is written and a NIC left raises (PartialActionError), but a deny written
behind an allow is answered `isolated` too, with `bypass`. Read as written, both made the card say
« reposée une fois. Si elle disparaît encore, Glorfindel alertera » of an isolation that does not
hold, and `reasserted_at` took it out of every later put-back.

And RW1's follow-ups (#558): a pair the first time wrote partial, its second time never come (its
lock held, the pass cut off), stayed out of every pass without a card; the card of a write the
provider said partial said « une écriture a échoué »; Azure's PartialActionError on a put-back gets
`_held_partial`'s sentence. Measured on the AWS world (tests/unit/fake_aws.py) and the in-memory
Azure (tests/unit/fake_azure.py): no cloud call, no model call.
"""
from __future__ import annotations

from contextlib import contextmanager
from unittest.mock import MagicMock

import pytest
from azure.core.exceptions import HttpResponseError

from glorfindel import actions, config, escalations, readiness
from glorfindel.actions import (
    AzureConnector, _load_block_entries, _load_isolation_state, _save_block_state, active_blocks,
)
from glorfindel.config import AutonomyConfig
from glorfindel.providers.aws import blocks as aws_blocks
from glorfindel.providers.aws.connector import AwsConnector
from glorfindel.reassert import _isolation_said, reassert_active
from glorfindel.reassert_perimeters import put_back_perimeters
from glorfindel.reassert_said import _block_drift

from .fake_aws import ACCOUNT, ATTACKER, REGION, FakeAws, acl_entry, arn, sg_rule
from .fake_azure import FakeAzure, _error, open_flows, vm_id
from .test_invariants import _rule

_ACT = AutonomyConfig(default="non_disruptive")
_WEB = arn("i-web1")


def _cards(action: str | None = None) -> list[dict]:
    return [e for e in escalations.pending() if e["signal_id"].startswith("reassert-")
            and (action is None or e.get("action") == action)]


# ── AWS: the isolation's read-back ─────────────────────────────────────────────────────────────

@pytest.fixture
def aws(tmp_path, monkeypatch):
    """i-web1 on subnet-app with its own group; isolated (the quarantine group, verified)."""
    monkeypatch.setattr(actions, "_ISOLATION_STATE_DIR", tmp_path / "isolation")
    monkeypatch.setattr(actions, "_BLOCK_STATE_DIR", tmp_path / "blocks")
    cfg = tmp_path / "glorfindel-config.yaml"
    cfg.write_text("isolation:\n  quarantine_nsg: true\n")
    monkeypatch.setattr(config, "_DEFAULT_PATHS", [cfg])
    f = FakeAws()
    f.add_vpc("vpc-a", "10.0.0.0/16")
    f.add_sg("vpc-a", "sg-web", "web", ingress=[sg_rule(cidr="0.0.0.0/0")], egress=[sg_rule(cidr="0.0.0.0/0")])
    f.add_acl("vpc-a", "acl-app", [acl_entry(100, False, "allow", "0.0.0.0/0"),
                                   acl_entry(100, True, "allow", "0.0.0.0/0")])
    f.add_subnet("vpc-a", "subnet-app", "10.0.0.0/24", "acl-app")
    f.add_instance("i-web1", [{"id": "eni-web1", "subnet": "subnet-app", "ips": ["10.0.0.4"], "groups": ["sg-web"]}])
    c = AwsConnector(ec2=f, account=ACCOUNT, region=REGION, read_only=False)
    readiness.record_assessment(readiness._verdict("i-web1", []), _WEB)      # its mode is its mode (L6)
    assert c.isolate_vm(_WEB)["verified"] is True
    return f, c


def _terraform_apply(f: FakeAws) -> None:
    """The ENI's groups put back as the code says (H11): the isolation is gone."""
    e = f.enis["eni-web1"]
    e["groups"] = list(e["design_groups"])


def _swapped_back_at_the_check(f: FakeAws) -> None:
    """Another host puts the ENI's groups back right after Glorfindel's swap — after its own read-back
    of the ENI, before the check reads the instance (A0): `isolated`, `verified` False."""
    armed = []

    def chaos(op, phase, write):
        if op == "eni.write" and phase == "after":
            armed.append(1)
        elif op == "instance.describe" and phase == "before" and armed:
            armed.clear()
            _terraform_apply(f)
    f.chaos = chaos


def test_aws_isolation_put_back_unverified_is_not_reposed_nor_marked(aws):
    """The swap lands, the check reads the ENI off quarantine: AWS answers `isolated`, `verified`
    False. The card says it does not hold, names the ENI, promises nothing; `reasserted_at` not set.
    The next pass, the same disappearance, says nothing more (one card per episode)."""
    f, c = aws
    _terraform_apply(f)
    _swapped_back_at_the_check(f)
    report = reassert_active(c, _ACT)
    assert [r["outcome"] for r in report] == ["partial"], report
    (card,) = _cards("isolate_vm")
    assert card["reason"] == report[0]["detail"]
    assert "ne tient pas en entier" in card["reason"] and "ne la relit pas entière (eni-web1)" in card["reason"]
    assert "reposée une fois" not in card["reason"] and "alertera" not in card["reason"]
    state = _load_isolation_state(_WEB)
    assert not state.get("reasserted_at"), "an isolation that does not hold, marked put back: never tried again"
    assert state.get("drift_alerted_at")
    assert c.verify_isolation(_WEB)["verified"] is False                  # as the card says
    f.chaos = lambda *a: None
    written = len(f.journal)
    assert reassert_active(c, _ACT) == [] and len(_cards("isolate_vm")) == 1
    assert f.journal[written:] == []


def test_aws_isolation_put_back_unreadable_is_said_so(aws, monkeypatch):
    """The read-back can't read the quarantine group: `verified` None, « vérification impossible »."""
    f, c = aws
    _terraform_apply(f)
    real_isolate, real_content, inside = c.isolate_vm, c._quarantine_content, []
    monkeypatch.setattr(c, "_quarantine_content", lambda q: ("unknown", []) if inside else real_content(q))

    def blind(rid):
        inside.append(1)
        try:
            return real_isolate(rid)
        finally:
            inside.pop()
    c.isolate_vm = blind
    report = reassert_active(c, _ACT)
    assert [r["outcome"] for r in report] == ["partial"], report
    assert "n'a pas pu la relire (vérification impossible)" in report[0]["detail"]
    assert "alertera" not in report[0]["detail"]
    assert not _load_isolation_state(_WEB).get("reasserted_at")
    # The episode over once it reads whole: verified, its mark off.
    assert reassert_active(c, _ACT) == []
    state = _load_isolation_state(_WEB)
    assert state.get("verified_at") and not state.get("drift_alerted_at")


def test_aws_isolation_put_back_whole_is_still_reposed_once(aws):
    """The boundary: verified, nothing in `bypass` — put back once, as before."""
    f, c = aws
    _terraform_apply(f)
    report = reassert_active(c, _ACT)
    assert [r["outcome"] for r in report] == ["reapplied"]
    assert "reposée une fois" in report[0]["detail"]
    assert _load_isolation_state(_WEB).get("reasserted_at")


# ── Azure: a deny written behind an allow ──────────────────────────────────────────────────────

_AZ_WEB = vm_id("rg-app1", "web")


def _azure(monkeypatch, nics: int = 1, allow: bool = False):
    """web, each NIC on its own NSG (`nsg-web-<i>`), isolation by rules (no quarantine); `allow`: the
    customer's allow-ssh at 100, before any deny of ours."""
    monkeypatch.setenv("GLORFINDEL_QUARANTINE_NSG", "0")
    f = FakeAzure()
    subnet = f.add_subnet("rg-net", "vnet-hub", "app", None)
    allow_ssh = _rule("allow-ssh", 100, dict(access="Allow", direction="Inbound", source_address_prefix="*",
                                             destination_address_prefix="*", destination_port_range="22"))
    nsgs = [f.add_nsg("rg-app1", f"nsg-web-{i}", [allow_ssh] if allow else []) for i in range(nics)]
    f.add_vm("rg-app1", "web", [{"rg": "rg-app1", "name": f"web-nic-{i}", "ips": [f"10.0.0.{4 + i}"],
                                 "subnet": subnet, "nsg": nsgs[i]} for i in range(nics)])
    c = AzureConnector(dry_run=False, read_only=False)
    c._network, c._compute = f.network, f.compute
    c._subscription_id = "s"
    c.recent_changes = lambda *a, **k: []
    c.drain_connections = lambda rid: {"status": "unsupported"}
    readiness.record_assessment(readiness._verdict("web", []), _AZ_WEB)
    return f, c, nsgs


def _ours_gone(f: FakeAzure, prefix: str) -> None:
    """A `terraform apply` on NSGs with inline rules: every rule of ours goes."""
    for n in f.nsgs.values():
        for name in [k for k in n["rules"] if k.startswith(prefix)]:
            del n["rules"][name]


def test_azure_isolation_put_back_behind_an_allow_is_not_reposed(monkeypatch):
    """The Azure side of the hole: the deny written again lands after the customer's allow-ssh
    (`bypass`, nothing raised). Before, « reposée une fois » and `reasserted_at`; the SSH flow
    still open. Now: a put-back that does not hold, said with the provider's words."""
    f, c, _ = _azure(monkeypatch, allow=True)
    out = c.isolate_vm(_AZ_WEB)
    assert out["status"] == "isolated" and out.get("bypass") and "verified" not in out, out
    _ours_gone(f, "glorfindel-iso")
    report = reassert_active(c, _ACT)
    iso = [r for r in report if r["kind"] == "isolation"]
    assert [r["outcome"] for r in iso] == ["partial"], report
    (card,) = _cards("isolate_vm")
    assert "ne tient pas en entier : Isolation contournée" in card["reason"] and "allow-ssh" in card["reason"]
    assert "reposée une fois" not in card["reason"] and "alertera" not in card["reason"]
    state = _load_isolation_state(_AZ_WEB)
    assert not state.get("reasserted_at") and state.get("drift_alerted_at")
    flows = open_flows({"nsgs": f.nsgs, "nics": f.nics, "subnets": f.subnets, "vms": f.vms}, _AZ_WEB)
    assert any(fl[2] == "in" and fl[4] == 22 for fl in flows), "the card says it does not hold: SSH is open"


def test_azure_isolation_put_back_whole_is_reposed_once(monkeypatch):
    f, c, _ = _azure(monkeypatch)
    assert not c.isolate_vm(_AZ_WEB).get("bypass")
    _ours_gone(f, "glorfindel-iso")
    report = reassert_active(c, _ACT)
    assert [r["outcome"] for r in report] == ["reapplied"], report
    assert _load_isolation_state(_AZ_WEB).get("reasserted_at")


def test_azure_partial_block_put_back_says_it_is_no_longer_read(monkeypatch):
    """RW1's follow-up: web's VM block on two NICs, both pairs gone; written again, the second NIC's
    write refused (403): Azure keeps the first, marks the entry `partial` and raises
    PartialActionError. The card says the put-back failed and that no pass reads the entry again —
    `_held_partial`'s sentence —, never « Glorfindel alertera »; the next pass says nothing."""
    f, c, _ = _azure(monkeypatch, nics=2)
    assert c.block_suspicious_ip(ATTACKER, _AZ_WEB, scope="vm")["status"] == "blocked"
    _ours_gone(f, "glorfindel-block")
    writes = []

    def chaos(op, phase, write):
        if op == "rule.write" and phase == "before":
            writes.append(1)
            if len(writes) == 3:                       # the second NIC's first rule
                raise _error(HttpResponseError, 403, "(AuthorizationFailed) rule.write: refused")
    f.chaos = chaos
    report = reassert_active(c, _ACT)
    assert [r["outcome"] for r in report] == ["failed"], report
    (card,) = _cards("block_suspicious_ip")
    assert "le reposer a échoué : Blocage partiel" in card["reason"]
    assert card["reason"].endswith("Noté partiel par le fournisseur : la réaffirmation ne le relit plus avant un "
                                   "nouveau blocage entier ou un déblocage."), card["reason"]
    assert "alertera" not in card["reason"]
    (b,) = _load_block_entries(_AZ_WEB)
    assert b.get("partial") and b.get("drift_alerted_at") and not b.get("reasserted_at")
    f.chaos = lambda *a: None
    assert reassert_active(c, _ACT) == []                 # held by its mark, as the card says


# ── RW1's follow-ups on AWS: a pair the first time wrote partial ───────────────────────────────

@pytest.fixture
def aws_block(tmp_path, monkeypatch):
    """i-web1 on subnet-app, its ACL allowing everything at 100; the attacker blocked, then our
    entries stripped by a `terraform apply` on the ACL. The read-back of each write blinded."""
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
    readiness.record_assessment(readiness._verdict("i-web1", []), _WEB)
    assert c.block_suspicious_ip(ATTACKER, _WEB)["status"] == "blocked"
    acl = f.acls["acl-app"]["entries"]
    for k in [k for k, e in acl.items() if e["action"] == "deny"]:
        del acl[k]
    blind = []
    real_cut = aws_blocks.cut
    monkeypatch.setattr(aws_blocks, "cut", lambda acl, egress, ip: False if blind else real_cut(acl, egress, ip))
    return f, c, blind


def _first_time_only(c, blind: list) -> list[dict]:
    """The first time alone, its write read back blind (`partial`): the pass cut off after it."""
    report: list[dict] = []
    blind.append(1)
    try:
        put_back = put_back_perimeters(c, _ACT, active_blocks(), report)
    finally:
        blind.clear()
    assert put_back and next(iter(put_back.values()))["partial"], put_back
    return report


def _said_partial(card: dict) -> None:
    assert "en partie selon le fournisseur" in card["reason"] and "il ne tient pas en entier" in card["reason"]
    assert "le fournisseur l'a dit partiel : à vérifier" in card["reason"], card["reason"]
    assert "une écriture a échoué" not in card["reason"] and "alertera" not in card["reason"]


def test_a_partial_pair_of_a_pass_cut_off_after_the_first_time_is_said_the_next_pass(aws_block):
    """The pass cut off between the two times: the provider's `partial` held the entry out of every
    later pass, its card never written. The first time's own mark (`partial_unsaid`) lets the next
    pass's second time say it — from a read of now, nothing written — then the mark goes, with the
    card. Still marked `partial` by the provider, its card says no pass reads it again."""
    f, c, blind = aws_block
    assert _first_time_only(c, blind) == []
    (b,) = _load_block_entries(_WEB)
    assert b.get("partial") and b.get("partial_unsaid") and b.get("reasserted_at")
    assert _cards() == []
    written = len(f.journal)
    report = reassert_active(c, _ACT)
    assert [r["outcome"] for r in report] == ["partial"], f"a pair written partial, never said: {report}"
    assert f.journal[written:] == []
    (card,) = _cards("block_suspicious_ip")
    _said_partial(card)
    assert "ne le relit plus" in card["reason"]
    (b,) = _load_block_entries(_WEB)
    assert not b.get("partial_unsaid") and b.get("drift_alerted_at") and b.get("partial")
    assert reassert_active(c, _ACT) == [] and len(_cards()) == 1      # said once


def test_a_partial_pair_said_a_pass_later_writes_nothing_in_human_only(aws_block):
    """The VM put in human_only between the two passes (I5): the card is said, nothing is written."""
    f, c, blind = aws_block
    _first_time_only(c, blind)
    written = len(f.journal)
    report = reassert_active(c, AutonomyConfig(default="human_only"))
    assert [r["outcome"] for r in report] == ["partial"], report
    assert f.journal[written:] == [], "the reassertion wrote in human_only"
    _said_partial(_cards("block_suspicious_ip")[0])


def test_a_partial_pair_whose_second_time_found_its_lock_held_is_said_the_next_pass(aws_block, monkeypatch):
    """The same, its second time skipped: the VM's lock held more than 30 s (a release, the console)."""
    f, c, blind = aws_block
    real_lock, calls = actions._vm_lock, []

    @contextmanager
    def busy_second(name, timeout=None):
        if timeout is not None:                 # the reassertion's (the connector's own waits)
            calls.append(name)
            if len(calls) == 2:
                raise TimeoutError(name)
        with real_lock(name, timeout=timeout):
            yield
    monkeypatch.setattr(actions, "_vm_lock", busy_second)
    blind.append(1)
    try:
        assert reassert_active(c, _ACT) == []                     # the first time wrote, the second waited
    finally:
        blind.clear()
    assert _cards() == [] and _load_block_entries(_WEB)[0].get("partial_unsaid")
    report = reassert_active(c, _ACT)
    assert [r["outcome"] for r in report] == ["partial"], report
    _said_partial(_cards("block_suspicious_ip")[0])


def test_a_partial_pair_said_in_its_own_pass_takes_its_mark_off(aws_block):
    """Both times in one pass: the card said at once, the first time's mark gone with it."""
    f, c, blind = aws_block
    blind.append(1)
    try:
        report = reassert_active(c, _ACT)
    finally:
        blind.clear()
    assert [r["outcome"] for r in report] == ["partial"], report
    (b,) = _load_block_entries(_WEB)
    assert not b.get("partial_unsaid")


def test_a_mark_without_the_providers_partial_holds_nothing(aws_block):
    """The first time's mark is read only while the provider's `partial` holds the entry out of the
    passes: without it, the entry is read as any other — in human_only, its disappearance said, never
    a pair « réécrite » of a stale reason."""
    f, c, _ = aws_block
    b = _load_block_entries(_WEB)[0]
    actions._update_block_entry(_WEB, ATTACKER, partial=False, partial_unsaid="acl-app : non relu")
    assert b.get("partial") is False
    report = reassert_active(c, AutonomyConfig(default="human_only"))
    assert [r["outcome"] for r in report] == ["escalated"], report
    assert "non relu" not in report[0]["detail"] and "réécrites" not in report[0]["detail"]


def test_a_block_written_whole_takes_the_first_times_mark_off():
    """A block written whole supersedes the first time's mark (`_save_block_state`): its card is
    about a write that is over. Written partial, the mark stays."""
    rid = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm"
    _save_block_state("vm", "203.0.113.9", rid, scoped=False, partial=True)
    actions._update_block_entry(rid, "203.0.113.9", partial_unsaid="x")
    _save_block_state("vm", "203.0.113.9", rid, scoped=False, partial=True)
    assert _load_block_entries(rid)[0].get("partial_unsaid") == "x"
    _save_block_state("vm", "203.0.113.9", rid, scoped=False)
    assert "partial_unsaid" not in _load_block_entries(rid)[0]


# ── the card of a write the provider said partial ──────────────────────────────────────────────

def test_a_partial_write_reread_whole_is_said_partial_never_a_write_failed():
    whole = {"verified": True}
    assert _block_drift("ip", "vm", whole, said=True, partial=True) == (
        "Azure le relit entier, mais le fournisseur l'a dit partiel : à vérifier.")
    assert _block_drift("ip", "vm", whole, said=True) == "Azure le relit entier, mais une écriture a échoué : à vérifier."


def test_a_vm_block_written_partial_reread_whole_says_partial():
    """The second time's own path (an entry scoped to its VM): the write answered `partial`, the
    re-read whole — no write failed."""
    rid = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm"
    readiness.record_assessment(readiness._verdict("vm", []), rid)
    _save_block_state("vm", "203.0.113.9", rid, nsg="rg/nsg", nsg_scope="nic", rule="glorfindel-block-x",
                      scoped=True, placements=[{"nsg_rg": "rg", "nsg_name": "nsg", "rule": "glorfindel-block-x"}])
    c = MagicMock()
    c.verify_block_ip.return_value = {"verified": False, "missing_rules": ["glorfindel-block-x"]}

    def write(*a, **k):
        c.verify_block_ip.return_value = {"verified": True}
        return {"status": "partial", "bypass": [{"nic": "nic-b", "reason": "non relu"}]}
    c.block_suspicious_ip.side_effect = write
    (r,) = reassert_active(c, _ACT)
    assert "le fournisseur l'a dit partiel : à vérifier" in r["detail"] and "une écriture a échoué" not in r["detail"]


# ── what an isolation's write answered ──────────────────────────────────────────────────────────

def test_what_an_isolation_write_said():
    assert _isolation_said({"status": "isolated", "verified": True, "bypass": []}) == ""
    assert _isolation_said({"status": "isolated"}) == ""                 # Azure, nothing passed by
    assert _isolation_said(None) == "" and _isolation_said(MagicMock()) == ""
    assert _isolation_said({"verified": False, "bypass": ["eni-1", "eni-2"]}) == (
        "le fournisseur ne la relit pas entière (eni-1, eni-2)")
    assert _isolation_said({"verified": False}) == "le fournisseur ne la relit pas entière (non vérifiée)"
    assert _isolation_said({"verified": None, "bypass": []}) == (
        "le fournisseur n'a pas pu la relire (vérification impossible)")
    assert _isolation_said({"status": "isolated", "bypass": "Isolation contournée : 'allow-x' passe avant."}) == (
        "Isolation contournée : 'allow-x' passe avant")
