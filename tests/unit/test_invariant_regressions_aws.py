"""Sequences the invariant machine on AWS found failing (MC1, test_invariants_aws.py),
replayed as fixed examples on every push. A rule's draws are given in the order it makes
them — `_draw` takes the instance, then the fault.
"""
from __future__ import annotations

import pytest

from .test_invariant_regressions import Script
from .test_invariants import invariant_env
from .test_invariants_aws import _ENIS, AwsIsolationMachine


def _net(**over):
    """Every subnet on its VPC's default ACL, no rule of the customer's, the quarantine off."""
    plain = {"ingress": [], "egress": []}
    return {"web": plain, "own": {e: plain for e in _ENIS}, "default_extra": False,
            "groups": {e: [] for e in _ENIS}, "policy": {e: False for e in _ENIS},
            "acl": {"subnet-app": "default", "subnet-data": "default", "subnet-edge": "default"},
            "acl_rules": {"shared": [], "own-data": [], "own-edge": []}, "windows": None,
            "config": {"quarantine": False, "rg": "", "forensic": [], "readable": True}, **over}


def _check(m: AwsIsolationMachine):
    """Every invariant of the machine, as Hypothesis runs them after a step."""
    m.writes_only_its_own()
    m.never_more_open_than_designed()
    m.customer_configuration_untouched()
    m.every_entry_of_glorfindel_is_recorded()
    m.every_claim_is_true()
    m.one_vm_one_state_file()


def _run(monkeypatch, net, *steps, then=None):
    invariant_env(monkeypatch)
    m = AwsIsolationMachine()
    try:
        m.build(net)
        _check(m)
        for rule, *draws in steps:
            getattr(m, rule)(**({"data": Script(*draws)} if draws else {}))
            _check(m)
        if then:
            then(m)
    finally:
        m.teardown()


_ACL = "acl-default-vpc-a"
# AWS1 (#334): our block on i-web1 (its inbound deny at 99, under the default ACL's allow
# at 100), the inbound one turned into an allow by someone, the operator takes it off and
# the unblock the outbound one: number 99 is free on AWS again. The customer takes it.
_NUMBER_TAKEN_AGAIN = (
    ("block", "i-web1", None, 22, "vm"),
    ("tamper_with_our_entry", (_ACL, False, 99), "allow"),
    ("recover",),
    ("customer_adds_acl_entry", _ACL, "in-all", 99),
)


def test_an_entry_of_the_customer_at_a_number_glorfindel_once_held_is_the_customers(monkeypatch):
    """The fake keeps what Glorfindel wrote at (ACL, direction, number) after someone
    turned it around and the operator removed it — nothing deleted it through the API.
    The I2 oracle left out of the customer's entries any entry at such a key: the
    customer's own entry at the number freed, in the design, was missing from what the
    test read — « customer entries changed » on a world as the customer wrote it. Neither
    the fake (a free number is taken, as AWS does) nor the adapter (the unblock deletes
    only an entry still as it wrote it) was wrong. The oracle leaves out an entry by its
    content now: Glorfindel's as it wrote it, or what someone turned it into."""
    def then(m):
        assert m.fake.acls[_ACL]["entries"][(False, 99)]["action"] == "allow"
        assert (_ACL, False, 99) in m.fake.authored            # the stale record, kept
    _run(monkeypatch, _net(), *_NUMBER_TAKEN_AGAIN, then=then)


@pytest.mark.parametrize("change", ["deny", "gone"])
def test_the_oracle_sees_a_change_of_the_customers_entry_at_that_number(monkeypatch, change):
    """The other side of the same key: excluded by its key, the customer's entry at a
    number Glorfindel once held was out of I2's sight — turned into a deny, or deleted,
    by anyone but the customer, nothing said it. By content, I2 sees it (A0: the oracle
    refuses more, never less)."""
    def then(m):
        entries = m.fake.acls[_ACL]["entries"]
        if change == "deny":
            entries[(False, 99)] = dict(entries[(False, 99)], action="deny")
        else:
            del entries[(False, 99)]
        try:
            with pytest.raises(AssertionError, match="I2: customer entries of acl-default-vpc-a changed"):
                m.customer_configuration_untouched()
        finally:
            m.design["acls"][_ACL]["entries"].pop((False, 99))   # the teardown judges what is left
            entries.pop((False, 99), None)
    _run(monkeypatch, _net(), *_NUMBER_TAKEN_AGAIN, then=then)
