"""The AWS adapter (MC1), case by case, on the simulated world (tests/unit/fake_aws.py).

The invariants on AWS (test_invariants_aws.py) draw sequences; these are the cases written
by hand: a round trip, the refusals, what AWS declares. No AWS call: the EC2 client is
the fake's.
"""
from __future__ import annotations

import pytest

from glorfindel import actions, config
from glorfindel.providers import CloudConnector, capabilities_of
from glorfindel.providers.aws.client import error_code, is_not_found, parse_instance_arn
from glorfindel.providers.aws.connector import AwsConnector, WrongAccountError
from glorfindel.providers.interface import NETWORK_QUARANTINE, NETWORK_RULES, RESTORE_POINT, SESSION_DRAIN
from glorfindel.response.policy import PartialActionError, WrongSubscriptionError

from .fake_aws import ACCOUNT, ATTACKER, INTERNET, REGION, FakeAws, acl_entry, arn, open_flows, sg_rule


@pytest.fixture
def world(tmp_path, monkeypatch):
    monkeypatch.setattr(actions, "_ISOLATION_STATE_DIR", tmp_path / "isolation")
    monkeypatch.setattr(actions, "_BLOCK_STATE_DIR", tmp_path / "blocks")
    cfg = tmp_path / "glorfindel-config.yaml"
    cfg.write_text("isolation:\n  quarantine_nsg: true\n")
    monkeypatch.setattr(config, "_DEFAULT_PATHS", [cfg])
    monkeypatch.delenv("GLORFINDEL_QUARANTINE_NSG", raising=False)
    f = FakeAws()
    f.add_vpc("vpc-a", "10.0.0.0/16")
    f.add_acl("vpc-a", "acl-app", [acl_entry(100, False, "allow", "0.0.0.0/0"),
                                   acl_entry(100, True, "allow", "0.0.0.0/0")])
    f.add_subnet("vpc-a", "subnet-app", "10.0.0.0/24", "acl-app")
    f.add_subnet("vpc-a", "subnet-data", "10.0.1.0/24", "acl-default-vpc-a")
    f.add_sg("vpc-a", "sg-web", "web", ingress=[sg_rule("tcp", 22, "0.0.0.0/0"), sg_rule("tcp", 443, "0.0.0.0/0")],
             egress=[sg_rule(cidr="0.0.0.0/0")])
    f.add_instance("i-web1", [{"id": "eni-web1", "subnet": "subnet-app", "ips": ["10.0.0.4"], "groups": ["sg-web"]}])
    f.add_instance("i-db", [{"id": "eni-db0", "subnet": "subnet-app", "ips": ["10.0.0.6"], "groups": ["sg-web"]},
                            {"id": "eni-db1", "subnet": "subnet-data", "ips": ["10.0.1.7", "10.0.1.8"],
                             "groups": ["sg-web", "sg-default-vpc-a"]}])
    c = AwsConnector(ec2=f, account=ACCOUNT, region=REGION, read_only=False)
    return f, c, cfg


def test_isolate_then_release_comes_back_to_the_design(world):
    f, c, _ = world
    design = open_flows(f.snapshot(), "i-db")
    out = c.isolate_vm(arn("i-db"))
    assert out["status"] == "isolated" and not out["bypass"] and out["verified"] is True
    # Only Amazon's DNS and IMDS stay open — no SG nor ACL filters them (H6), and it is said.
    assert {(fl[0], fl[3]) for fl in open_flows(f.world(), "i-db")} <= {
        (e, p) for e in ("eni-db0", "eni-db1") for p in ("169.254.169.253", "169.254.169.254")}
    assert set(out["platform_open"]) == {"eni-db0", "eni-db1"}
    assert c.verify_isolation(arn("i-db"))["verified"] is True
    assert c.verify_release(arn("i-db"))["verified"] is False
    assert f.enis["eni-db1"]["groups"] != ["sg-web", "sg-default-vpc-a"]
    assert c.release_isolation(arn("i-db"))["status"] == "released"
    assert f.enis["eni-db1"]["groups"] == ["sg-web", "sg-default-vpc-a"]
    assert open_flows(f.world(), "i-db") == design
    assert c.verify_release(arn("i-db"))["verified"] is True
    assert actions._load_isolation_state(arn("i-db")) is None


def test_the_original_survives_a_lost_state_through_the_tag(world):
    f, c, _ = world
    c.isolate_vm(arn("i-web1"))
    for p in actions._ISOLATION_STATE_DIR.glob("*.json"):
        p.unlink()
    assert c.release_isolation(arn("i-web1"))["status"] == "released"
    assert f.enis["eni-web1"]["groups"] == ["sg-web"]


def test_an_unknown_original_keeps_the_eni_in_quarantine_and_says_which_tag(world):
    f, c, _ = world
    c.isolate_vm(arn("i-web1"))
    for p in actions._ISOLATION_STATE_DIR.glob("*.json"):
        p.unlink()
    q = next(s for s in f.sgs.values() if s["name"] == "glorfindel-quarantine")
    q["tags"].pop("glorfindel-orig-eni-web1")
    out = c.release_isolation(arn("i-web1"))
    assert out["status"] == "failed" and "glorfindel-orig-eni-web1" in out["failed"][0]["error"]
    assert f.enis["eni-web1"]["groups"] == [q["id"]]
    assert actions._load_isolation_state(arn("i-web1"))["release_failed"]
    q["tags"]["glorfindel-orig-eni-web1"] = "sg-web"            # the operator answers
    assert c.release_isolation(arn("i-web1"))["status"] == "released"
    assert f.enis["eni-web1"]["groups"] == ["sg-web"]


def test_a_deleted_original_group_is_given_by_the_operator_by_the_tag(world):
    """A group recreated has a new id (H4): the state's original can't be put back, the
    tag the operator sets is."""
    f, c, _ = world
    c.isolate_vm(arn("i-web1"))
    f.enis["eni-db0"]["groups"] = ["sg-default-vpc-a"]
    f.enis["eni-db1"]["groups"] = ["sg-default-vpc-a"]
    assert f.delete_sg("sg-web")
    out = c.release_isolation(arn("i-web1"))
    assert out["status"] == "failed" and "n'existe plus" in out["failed"][0]["error"]
    f.add_sg("vpc-a", "sg-web2", "web")
    q = next(s for s in f.sgs.values() if s["name"] == "glorfindel-quarantine")
    q["tags"]["glorfindel-orig-eni-web1"] = "sg-web2"
    assert c.release_isolation(arn("i-web1"))["status"] == "released"
    assert f.enis["eni-web1"]["groups"] == ["sg-web2"]


def test_no_isolation_without_the_quarantine_group_nor_with_an_unreadable_config(world):
    f, c, cfg = world
    before = f.snapshot()
    cfg.write_text("isolation:\n  quarantine_nsg: false\n")
    with pytest.raises(RuntimeError, match="pas de repli par règles"):
        c.isolate_vm(arn("i-web1"))
    cfg.write_text("isolation: [quarantine_nsg: true\n")
    with pytest.raises(Exception):
        c.isolate_vm(arn("i-web1"))
    assert f.snapshot() == before and not f.journal


def test_a_policy_on_one_eni_leaves_a_partial_isolation_recorded(world):
    f, c, _ = world
    f.enis["eni-db1"]["policy"] = True
    with pytest.raises(PartialActionError):
        c.isolate_vm(arn("i-db"))
    st = actions._load_isolation_state(arn("i-db"))
    assert st["partial"] and [p["nic_id"] for p in st["placements"]] == ["eni-db0"]
    f.enis["eni-db1"]["policy"] = False
    assert c.release_isolation(arn("i-db"))["status"] == "released"
    assert f.enis["eni-db0"]["groups"] == ["sg-web"]


def test_a_customer_group_named_like_the_quarantine_is_never_adopted(world):
    f, c, _ = world
    f.add_sg("vpc-a", "sg-lookalike", "glorfindel-quarantine", ingress=[sg_rule(cidr="0.0.0.0/0")])
    with pytest.raises(RuntimeError, match="n'est pas adopté"):
        c.isolate_vm(arn("i-web1"))
    assert f.enis["eni-web1"]["groups"] == ["sg-web"]
    assert c.verify_isolation(arn("i-web1"))["verified"] is False


def test_a_block_is_subnet_wide_placed_before_the_customer_allow_and_shared(world):
    f, c, _ = world
    out = c.block_suspicious_ip(ATTACKER, arn("i-web1"), scope="vm")
    assert out["status"] == "blocked" and out["scope"] == "subnet"
    assert {k for k in f.acls["acl-app"]["entries"]} == {(False, 100), (True, 100), (False, 99), (True, 99)}
    assert not [fl for fl in open_flows(f.world(), "i-web1") if fl[3] == ATTACKER]
    assert c.verify_block_ip(ATTACKER, arn("i-web1"))["verified"] is True
    # The db's first ENI shares the ACL: its block reuses the entries; the second ENI's
    # subnet gets its own.
    assert c.block_suspicious_ip(ATTACKER, arn("i-db"))["status"] == "blocked"
    assert len(f.acls["acl-app"]["entries"]) == 4 and (False, 99) in f.acls["acl-default-vpc-a"]["entries"]
    # Unblocking one keeps what the other holds.
    out = c.unblock_ip(ATTACKER, arn("i-web1"))
    assert out["status"] == "unblocked" and out["kept_for_other_blocks"]
    assert c.verify_block_ip(ATTACKER, arn("i-db"))["verified"] is True
    assert c.unblock_ip(ATTACKER, arn("i-db"))["status"] == "unblocked"
    assert set(f.acls["acl-app"]["entries"]) == {(False, 100), (True, 100)}
    assert all(j["authored"] for j in f.journal if j["op"] == "acl.delete")


def test_no_free_number_before_the_allow_places_nothing_and_says_it(world):
    f, c, _ = world
    f.acls["acl-app"]["entries"][(False, 1)] = acl_entry(1, False, "allow", "0.0.0.0/0")
    out = c.block_suspicious_ip(ATTACKER, arn("i-web1"))
    assert out["status"] == "failed" and out["bypass"]
    assert not [j for j in f.journal if j["op"] == "acl.create"]
    assert c.unblock_ip(ATTACKER, arn("i-web1"))["status"] == "not_found"


def test_an_entry_someone_changed_is_not_removed(world):
    f, c, _ = world
    c.block_suspicious_ip(ATTACKER, arn("i-web1"))
    f.acls["acl-app"]["entries"][(False, 99)]["action"] = "allow"
    v = c.verify_block_ip(ATTACKER, arn("i-web1"))
    assert v["verified"] is False and v["missing_rules"] == ["acl-app"]
    assert c.unblock_ip(ATTACKER, arn("i-web1"))["status"] == "unblocked"
    assert (False, 99) in f.acls["acl-app"]["entries"] and (True, 99) not in f.acls["acl-app"]["entries"]


@pytest.mark.parametrize("rid", [
    arn("i-web1", account="444455556666"), arn("i-web1", region="eu-central-1"), "i-web1",
    "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/web"])
def test_another_account_another_region_or_no_arn_is_refused(world, rid):
    f, c, _ = world
    for call in (lambda: c.isolate_vm(rid), lambda: c.release_isolation(rid), lambda: c.verify_isolation(rid),
                 lambda: c.verify_release(rid), lambda: c.block_suspicious_ip(ATTACKER, rid),
                 lambda: c.unblock_ip(ATTACKER, rid), lambda: c.verify_block_ip(ATTACKER, rid)):
        with pytest.raises(WrongAccountError):
            call()
    assert issubclass(WrongAccountError, WrongSubscriptionError) and not f.journal


def test_what_aws_declares():
    caps = capabilities_of(AwsConnector(read_only=False))
    assert caps.provider == "aws" and issubclass(AwsConnector, CloudConnector)
    assert caps.get(NETWORK_QUARANTINE).actions == ("isolate_vm", "release_isolation")
    # No isolation by rules on AWS, no session cut, no restore point (MC1).
    assert "isolate_vm" not in caps.get(NETWORK_RULES).actions
    assert caps.get(SESSION_DRAIN) is None and caps.get(RESTORE_POINT) is None
    assert all(r.startswith("ec2:") for c in caps.capabilities for r in c.rights)


def test_without_a_client_nothing_is_attempted():
    c = AwsConnector(account=ACCOUNT, region=REGION, read_only=False)
    with pytest.raises(RuntimeError, match="MC2"):
        c.isolate_vm(arn("i-web1"))
    with pytest.raises(NotImplementedError):
        c.snapshot(arn("i-web1"))


def test_read_only_and_dry_run(world):
    f, _, _ = world
    with pytest.raises(PermissionError):
        AwsConnector(ec2=f, account=ACCOUNT, region=REGION, read_only=True).isolate_vm(arn("i-web1"))
    dry = AwsConnector(ec2=f, account=ACCOUNT, region=REGION, dry_run=True, read_only=False)
    assert dry.isolate_vm(arn("i-web1"))["status"] == "dry_run" and not f.journal


def test_errors_and_arns_are_read_without_the_sdk():
    from .fake_aws import ClientError, throttled
    assert error_code(throttled("x")) == "RequestLimitExceeded" and not is_not_found(throttled("x"))
    assert is_not_found(ClientError("InvalidInstanceID.NotFound", "gone"))
    assert parse_instance_arn(arn("i-0abc")) == (REGION, ACCOUNT, "i-0abc")
    with pytest.raises(ValueError):
        parse_instance_arn("arn:aws:ec2:eu-west-3:111122223333:volume/vol-1")


def test_the_fake_evaluates_an_acl_without_state(world):
    """The answer of an allowed flow is a flow of its own through an ACL (H5): an ACL that
    lets SSH in but no ephemeral port out keeps the session from answering."""
    f, _, _ = world
    f.acls["acl-app"]["entries"] = {(False, 100): acl_entry(100, False, "allow", "0.0.0.0/0", "tcp", 22),
                                    (True, 100): acl_entry(100, True, "allow", "0.0.0.0/0", "tcp", 443)}
    flows = {(fl[2], fl[3], fl[4]) for fl in open_flows(f.world(), "i-web1")}
    assert ("in", INTERNET, 22) not in flows
    f.acls["acl-app"]["entries"][(True, 110)] = acl_entry(110, True, "allow", "0.0.0.0/0", "tcp", 1024, 65535)
    assert ("in", INTERNET, 22) in {(fl[2], fl[3], fl[4]) for fl in open_flows(f.world(), "i-web1")}
