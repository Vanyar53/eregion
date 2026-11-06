"""AL1c (#597): a card of the control plane or of an identity is filed on what it is about —
never on a VM it has nothing to do with.

Measured on the bench by ID1 (05 and 06/11): six cards filed on vm-celebrimbor-bree, the first VM
online, none of them about it — two NSG rule writes on the shared NSG, a snapshot of gondolin's
data disk (gondolin offline) and its download access, a Reader role on the bench's group, and three
events of Entra ID on the test application and its principal. Their rows, forged here as the
shipped rules project them (no real id: a zero subscription, the bench's names already in the
repository), go through the real RulePoller, the real graph and the real store; Azure's answers
(the VMs an NSG covers, a disk's VM, a snapshot's source) are a fake topology. What is held:
  - an NSG rule: on the NSG, with the VMs it covers that the discovery knows, an offline one too;
  - a snapshot, a download access: on the VM of the source disk when Azure still says it, else on
    the group — the row names the snapshot only, and the card says so;
  - a role on the group: on the group; on the subscription: on the control plane;
  - the three events of Entra: on the identity (the application, the principal), never a VM;
  - an unknown resource: on its group, or the control plane when the row names none;
  - nothing else changes: no model, no action, no incident on a VM, nothing in the memory, never
    merged; the data plane keeps its anchor;
  - the Discord card names its target, says what could not be read, and no longer repeats its
    paragraph under « Pourquoi rien n'est exécuté »; one thread for the identities.
Mutants M4270–M4279 (scripts/mutants/AL1c.py).
"""
from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from glorfindel import card_target
from glorfindel.card_target import UNREAD, Topology
from glorfindel.detection_rules import RulePoller, load_config
from .test_activity_logs import SHIPPED, _cfg, _graph, _initial, _llm

SUB = "/subscriptions/00000000-0000-0000-0000-000000000000"
GROUP = f"{SUB}/resourceGroups/rg-celebrimbor"
PROV = f"{GROUP}/providers"
BREE = f"{PROV}/Microsoft.Compute/virtualMachines/vm-celebrimbor-bree"
GONDOLIN = f"{PROV}/Microsoft.Compute/virtualMachines/vm-celebrimbor-gondolin"
NSG = f"{PROV}/Microsoft.Network/networkSecurityGroups/nsg-celebrimbor"
SUBNET = f"{PROV}/Microsoft.Network/virtualNetworks/vnet-celebrimbor/subnets/default"
DISK = f"{PROV}/Microsoft.Compute/disks/disk-celebrimbor-gondolin-data"
SNAP = f"{PROV}/Microsoft.Compute/snapshots/snap-gondolin-data"
ROLE = f"{GROUP}/providers/Microsoft.Authorization/roleAssignments/11111111-2222-3333-4444-555555555555"
APP_OID = "00000000-0000-0000-0000-0000000000c1"
SP_OID = "00000000-0000-0000-0000-0000000000c2"
ADMIN_OID = "00000000-0000-0000-0000-0000000000b1"

NSG_OP = "MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/SECURITYRULES/WRITE"
SNAP_OP = "MICROSOFT.COMPUTE/SNAPSHOTS/WRITE"
SNAP_ACCESS_OP = "MICROSOFT.COMPUTE/SNAPSHOTS/BEGINGETACCESS/ACTION"
DISK_ACCESS_OP = "MICROSOFT.COMPUTE/DISKS/BEGINGETACCESS/ACTION"
ROLE_OP = "MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE"


def _low(rid: str) -> str:
    return rid.lower()


# What Azure answers (ReadersMixin.control_topology): every id lowercase.
AZURE = {
    "nsg_vms": {_low(NSG): [_low(BREE), _low(GONDOLIN)]},
    "disk_vm": {_low(DISK): _low(GONDOLIN)},
    "snapshot_source": {_low(SNAP): _low(DISK)},
}


def _activity(op, rid, corr="c-1", group="rg-celebrimbor", **extra):
    """A row as the shipped Activity Log rules project it."""
    row = {"TimeGenerated": "2026-11-05T10:00:00Z", "OperationNameValue": op,
           "ActivityStatusValue": "Success", "Caller": "operator@example.org",
           "CallerIpAddress": "203.0.113.7", "CallerAppId": "", "CallerObjectId": ADMIN_OID,
           "_ResourceId": rid, "ResourceGroup": group, "CorrelationId": corr}
    row.update(extra)
    return row


def _entra(kind, corr="c-e"):
    """A row as the shipped Entra ID rules project it — on the bench's test application."""
    row = {"TimeGenerated": "2026-11-06T08:00:00Z", "EntraKind": kind, "Result": "success",
           "CorrelationId": corr, "ActorName": "operator@example.org", "ActorId": ADMIN_OID,
           "ActorAppId": "", "ActorIp": "203.0.113.7"}
    if kind == "credential":
        row.update(EntraOperation="Update application – Certificates and secrets management ",
                   TargetName="eregion-bench-test", TargetId=APP_OID, TargetType="Application",
                   CredentialAdded="[]")
    elif kind == "consent":
        row.update(EntraOperation="Consent to application", TargetName="eregion-bench-test",
                   TargetId=SP_OID, TargetType="ServicePrincipal", Permissions="User.Read")
    elif kind == "signin":
        row.update(EntraOperation="Service principal sign-in", ActorName="eregion-bench-test",
                   ActorId=SP_OID, ActorAppId=APP_OID, ActorIp="198.51.100.23",
                   TargetName="Microsoft Graph", SignIns=1, BaselineSignIns=40, BaselineDays=5)
    row["EventId"] = f"{corr}|{row.get('TargetId') or row.get('ActorId')}"
    return row


class _Workspace:
    """The rule's query, answered with forged rows (the adapter's filtering is AL1's, tested there)."""

    def __init__(self, rows):
        self.rows = rows

    def run_query(self, query, timespan=None):
        return list(self.rows)


class _Registry:
    def __init__(self, *rids):
        self.assets = [SimpleNamespace(name=r.rsplit("/", 1)[-1], resource_id=r) for r in rids]

    def for_backend(self, _name):
        return self.assets


def _shipped(name):
    return next(r for r in load_config(SHIPPED, glorfindel_cfg=_cfg(), client_layer=False).rules
                if r.name == name)


def _poll(rule_name, rows, azure=AZURE, vms=(BREE, GONDOLIN), fresh=True, owners=None):
    """One poll of a shipped rule over forged rows, BREE first online and GONDOLIN offline —
    the discovery keeps both (an offline VM stays a valid target)."""
    rule = _shipped(rule_name)
    sent: list = []
    topology = Topology(lambda: azure) if azure is not None else None
    p = RulePoller([rule], sent.append, topology=topology, ip_owners=owners)
    if fresh:
        p._status = {}                       # each poll of a test reads its rows anew
    p._detector = lambda _rule: _Workspace(rows)
    p._registry = _Registry(*vms)
    p.poll_once(rule)
    p.stop()
    return sent


# ── the control plane: filed on what the row names ────────────────────────────

def test_an_nsg_rule_is_filed_on_the_nsg_and_shown_on_every_vm_it_covers():
    sent = _poll("nsg-change-outside-glorfindel",
                 [_activity(NSG_OP, f"{NSG}/securityRules/allow-ssh-admin")])
    assert len(sent) == 1
    sig = sent[0]
    t = sig["context"]["target"]
    assert sig["resource_id"] == NSG and sig["resource_type"] == "nsg"
    assert t["kind"] == "nsg" and t["name"] == "nsg-celebrimbor" and t["via"] == "règle allow-ssh-admin"
    # Both VMs it covers, gondolin offline included — never one of them alone, never bree as an anchor.
    assert sorted(t["vm_names"]) == ["vm-celebrimbor-bree", "vm-celebrimbor-gondolin"]
    assert sorted(t["vms"]) == sorted([BREE, GONDOLIN])
    assert sig["context"]["attribution"] == "unattributed" and "candidates" not in sig["context"]
    assert sig["context"]["asset_name"] == "nsg-celebrimbor"


def test_an_nsg_whose_coverage_azure_did_not_answer_is_still_the_nsg_and_says_so():
    azure = {**AZURE, "nsg_vms": None}
    t = _poll("nsg-change-outside-glorfindel", [_activity(NSG_OP, NSG)], azure=azure)[0]["context"]["target"]
    assert t["kind"] == "nsg" and t["vms"] == [] and "n'ont pas pu être lues" in t["limit"]
    # No topology at all (a dry run): the NSG still, its VMs not said.
    t = _poll("nsg-change-outside-glorfindel", [_activity(NSG_OP, NSG)], azure=None)[0]["context"]["target"]
    assert t["kind"] == "nsg" and t["vms"] == [] and t["limit"]
    # A VM it covers that the discovery does not know: counted, never named as if watched.
    azure = {**AZURE, "nsg_vms": {_low(NSG): [_low(BREE), f"{SUB}/x/virtualmachines/elsewhere"]}}
    t = _poll("nsg-change-outside-glorfindel", [_activity(NSG_OP, NSG)], azure=azure)[0]["context"]["target"]
    assert t["vm_names"] == ["vm-celebrimbor-bree"]
    assert "1 VM lue(s) sur Azure que la règle ne surveille pas (absente de la découverte, exclue de la règle, ou d'un autre backend)" in t["limit"]
    # An NSG the listing does not hold: never « gone » on that alone — the watch reads what its
    # rights let it list (on H0, `Reader` on the bench's group): it says both (review, AL1c).
    azure = {**AZURE, "nsg_vms": {}}
    t = _poll("nsg-change-outside-glorfindel", [_activity(NSG_OP, NSG)], azure=azure)[0]["context"]["target"]
    assert t["kind"] == "nsg" and t["vms"] == [] and "hors des droits de la watch" in t["limit"]
    # An NSG read with no VM the watch could read under it: what was read, never « covers none ».
    azure = {**AZURE, "nsg_vms": {_low(NSG): []}}
    t = _poll("nsg-change-outside-glorfindel", [_activity(NSG_OP, NSG)], azure=azure)[0]["context"]["target"]
    assert "n'a été lue sous ce NSG" in t["limit"] and "ne couvre aucune" not in t["limit"]


def test_a_snapshot_is_filed_on_the_vm_of_its_source_disk_and_says_the_row_names_none():
    sent = _poll("snapshot-by-unexpected-caller",
                 [_activity(SNAP_OP, SNAP, corr="c-s"), _activity(SNAP_ACCESS_OP, SNAP, corr="c-a")])
    assert len(sent) == 2
    for sig in sent:
        t = sig["context"]["target"]
        # gondolin — offline — and never bree, the first VM online.
        assert sig["resource_id"] == GONDOLIN and t["kind"] == "vm"
        assert t["name"] == "vm-celebrimbor-gondolin" and "snap-gondolin-data" in t["via"]
        assert "disk-celebrimbor-gondolin-data" in t["via"]
        assert "ne nomme pas le disque source" in t["limit"]
        # Filed on the VM, still not attributed to it: no incident there, no window read.
        assert sig["context"]["attribution"] == "unattributed"


def test_a_snapshot_azure_no_longer_holds_is_filed_on_its_group():
    azure = {**AZURE, "snapshot_source": {}}
    sig = _poll("snapshot-by-unexpected-caller", [_activity(SNAP_OP, SNAP)], azure=azure)[0]
    t = sig["context"]["target"]
    assert sig["resource_id"] == GROUP and t["kind"] == "resource_group" and t["name"] == "rg-celebrimbor"
    assert "ne nomme pas le disque source" in t["limit"] and "hors des droits de la watch" in t["limit"]
    assert "supprimé depuis" not in t["limit"]            # deleted, or out of the watch's reach
    azure = {**AZURE, "snapshot_source": None}
    t = _poll("snapshot-by-unexpected-caller", [_activity(SNAP_OP, SNAP)], azure=azure)[0]["context"]["target"]
    assert t["kind"] == "resource_group" and "n'ont pas pu être lus" in t["limit"]


def test_a_download_access_to_a_disk_is_filed_on_its_vm():
    sig = _poll("snapshot-by-unexpected-caller", [_activity(DISK_ACCESS_OP, DISK)])[0]
    t = sig["context"]["target"]
    assert sig["resource_id"] == GONDOLIN and t["kind"] == "vm" and t["via"] == "disque disk-celebrimbor-gondolin-data"
    # A disk of a VM the discovery does not know: its group, said.
    azure = {**AZURE, "disk_vm": {_low(DISK): f"{SUB}/x/virtualmachines/elsewhere"}}
    t = _poll("snapshot-by-unexpected-caller", [_activity(DISK_ACCESS_OP, DISK)], azure=azure)[0]["context"]["target"]
    assert t["kind"] == "resource_group" and card_target._UNWATCHED in t["limit"]
    azure = {**AZURE, "disk_vm": {_low(DISK): ""}}
    t = _poll("snapshot-by-unexpected-caller", [_activity(DISK_ACCESS_OP, DISK)], azure=azure)[0]["context"]["target"]
    assert t["kind"] == "resource_group" and "attaché à aucune VM" in t["limit"]
    azure = {**AZURE, "disk_vm": {}}
    t = _poll("snapshot-by-unexpected-caller", [_activity(DISK_ACCESS_OP, DISK)], azure=azure)[0]["context"]["target"]
    assert t["kind"] == "resource_group" and "hors des droits de la watch" in t["limit"]


def test_a_role_is_filed_on_its_scope():
    sig = _poll("role-assignment-write", [_activity(ROLE_OP, ROLE)])[0]
    t = sig["context"]["target"]
    assert sig["resource_id"] == GROUP and t["kind"] == "resource_group" and t["name"] == "rg-celebrimbor"
    assert "portée rg-celebrimbor" in t["via"]
    # On the VM itself: that VM's, attributed (AL1, unchanged).
    on_vm = f"{GONDOLIN}/providers/Microsoft.Authorization/roleAssignments/abc"
    sig = _poll("role-assignment-write", [_activity(ROLE_OP, on_vm)])[0]
    assert sig["resource_id"] == GONDOLIN and sig["context"]["attribution"] == "asset"
    assert sig["context"]["target"]["kind"] == "vm"
    # On the subscription: the control plane as a whole.
    on_sub = f"{SUB}/providers/Microsoft.Authorization/roleAssignments/abc"
    sig = _poll("role-assignment-write", [_activity(ROLE_OP, on_sub, group="")])[0]
    assert sig["resource_id"] == card_target.CONTROL_PLANE_ID
    assert sig["context"]["target"]["kind"] == "control_plane" and sig["context"]["target"]["limit"]


BREE_IP = "10.10.1.4"


def _bree_owns_its_ip():
    return {BREE_IP: _low(BREE)}


def test_a_write_made_from_a_watched_vm_is_filed_on_what_it_writes_the_vm_named_as_the_caller():
    """The RulePoller routes a row by the address that made the call (`CallerIpAddress`, T1041):
    an NSG written from bree was filed on bree, the NSG unsaid. The VM that made the call is the
    caller, named in `via`, never the target; the card stays unattributed (second review, AL1c)."""
    row = _activity(NSG_OP, f"{NSG}/securityRules/allow-ssh-admin", CallerIpAddress=BREE_IP)
    sig = _poll("nsg-change-outside-glorfindel", [row], owners=_bree_owns_its_ip)[0]
    t = sig["context"]["target"]
    assert sig["resource_id"] == NSG and t["kind"] == "nsg" and sig["resource_type"] == "nsg"
    assert t["via"] == "règle allow-ssh-admin, appel depuis vm-celebrimbor-bree"
    assert sorted(t["vm_names"]) == ["vm-celebrimbor-bree", "vm-celebrimbor-gondolin"]
    assert sig["context"]["attribution"] == "unattributed" and sig["context"]["asset_name"] == "nsg-celebrimbor"
    # A disk read from bree — gondolin's, then bree's own: on the disk's VM, never attributed to
    # it — the row names the disk, not the VM.
    for vm, name in ((GONDOLIN, "vm-celebrimbor-gondolin"), (BREE, "vm-celebrimbor-bree")):
        azure = {**AZURE, "disk_vm": {_low(DISK): _low(vm)}}
        sig = _poll("snapshot-by-unexpected-caller", [_activity(DISK_ACCESS_OP, DISK, CallerIpAddress=BREE_IP)],
                    azure=azure, owners=_bree_owns_its_ip)[0]
        t = sig["context"]["target"]
        assert sig["resource_id"] == vm and t["kind"] == "vm" and t["name"] == name
        assert t["via"] == "disque disk-celebrimbor-gondolin-data, appel depuis vm-celebrimbor-bree"
        assert sig["context"]["attribution"] == "unattributed"
    # A role on gondolin, written from bree: the row names gondolin — its card, attributed (AL1).
    on_vm = f"{GONDOLIN}/providers/Microsoft.Authorization/roleAssignments/abc"
    sig = _poll("role-assignment-write", [_activity(ROLE_OP, on_vm, CallerIpAddress=BREE_IP)],
                owners=_bree_owns_its_ip)[0]
    assert sig["resource_id"] == GONDOLIN and sig["context"]["attribution"] == "asset"
    assert sig["context"]["target"] == {"kind": "vm", "id": GONDOLIN, "name": "vm-celebrimbor-gondolin"}
    # What names a VM: the row's own resource, or one of its sub-resources — never the caller's.
    assert card_target.names_vm({"_ResourceId": on_vm.upper()}, GONDOLIN)
    assert not card_target.names_vm({"_ResourceId": on_vm}, BREE)
    assert not card_target.names_vm({"_ResourceId": NSG, "CallerIpAddress": BREE_IP}, BREE)
    assert not card_target.names_vm({"_ResourceId": f"{GONDOLIN}-old"}, GONDOLIN)


def test_a_rule_of_the_control_plane_or_of_an_identity_speaks_with_no_vm_watched():
    """No VM watched — every VM excluded from the rule, or the discovery still empty just after
    a start — is no reason to leave a card of the control plane or of an identity unsaid: it is
    filed on what it names (review, AL1c). The data plane, it, has nothing to anchor on."""
    sent = _poll("nsg-change-outside-glorfindel", [_activity(NSG_OP, NSG)], vms=())
    assert len(sent) == 1 and sent[0]["resource_id"] == NSG
    t = sent[0]["context"]["target"]
    # The two VMs Azure reads under it, unknown to an empty discovery: counted, never named.
    assert t["kind"] == "nsg" and t["vms"] == [] and "2 VM lue(s) sur Azure" in t["limit"]
    sent = _poll("entra-credential-added", [_entra("credential")], vms=())
    assert len(sent) == 1 and sent[0]["resource_id"] == f"entra:application:{APP_OID}"
    assert sent[0]["context"]["target"]["kind"] == "identity"
    # A disk, a snapshot: the VM of the source disk is not in an empty discovery — the group,
    # said (docs/glorfindel.md: just after a start, or for a VM evicted after 8 h offline).
    for row in (_activity(DISK_ACCESS_OP, DISK), _activity(SNAP_OP, SNAP)):
        sig = _poll("snapshot-by-unexpected-caller", [row], vms=())[0]
        t = sig["context"]["target"]
        assert sig["resource_id"] == GROUP and t["kind"] == "resource_group"
        assert "disk-celebrimbor-gondolin-data" in t["via"] and card_target._UNWATCHED in t["limit"]
    # A row that names a VM the rule does not watch is still dropped (AL1, unchanged).
    on_vm = f"{GONDOLIN}/providers/Microsoft.Authorization/roleAssignments/abc"
    assert _poll("role-assignment-write", [_activity(ROLE_OP, on_vm)], vms=()) == []
    # The data plane: no VM, no anchor, no card.
    rule = _shipped("ssh-brute-force")
    sent = []
    p = RulePoller([rule], sent.append, topology=Topology(lambda: AZURE))
    p._status = {}
    p._detector = lambda _rule: _Workspace([{"IPAddress": "203.0.113.9", "FailedAttempts": 40}])
    p._registry = _Registry()
    p.poll_once(rule)
    p.stop()
    assert sent == []


def test_an_unknown_resource_is_filed_on_its_group_or_on_the_control_plane():
    t = card_target.control_target(_activity("MICROSOFT.STORAGE/STORAGEACCOUNTS/WRITE",
                                              f"{PROV}/Microsoft.Storage/storageAccounts/stbench"))
    assert t["kind"] == "resource_group" and t["id"] == GROUP and t["via"] == "stbench"
    t = card_target.control_target(_activity("MICROSOFT.X/Y/WRITE", f"{SUB}/providers/Microsoft.X/y/z", group=""))
    assert t["kind"] == "control_plane" and "groupe" in t["limit"]
    t = card_target.control_target({"OmittedOperations": [{}, {}]})
    assert t["kind"] == "control_plane" and "synthèse" in t["limit"]


# ── an identity: filed on the identity, never a VM ────────────────────────────

@pytest.mark.parametrize("kind,rule,oid,itype", [
    ("credential", "entra-credential-added", APP_OID, "Application"),
    ("consent", "entra-app-consent", SP_OID, "ServicePrincipal"),
    ("signin", "entra-sp-unusual-signin", SP_OID, "ServicePrincipal"),
])
def test_an_identity_card_is_filed_on_the_identity(monkeypatch, kind, rule, oid, itype):
    sent = _poll(rule, [_entra(kind)])
    assert len(sent) == 1
    sig = sent[0]
    t = sig["context"]["target"]
    assert t["kind"] == "identity" and t["identity_type"] == itype and t["object_id"] == oid
    assert sig["resource_id"] == f"entra:{itype.lower()}:{oid}" and sig["resource_type"] == "identity"
    assert "virtualmachines" not in sig["resource_id"].lower()
    # Its name is the application's (chosen by whoever registers it): on the card, never the id.
    assert t["name"] == "eregion-bench-test" and sig["context"]["asset_name"] == sig["resource_id"]
    assert sig["context"]["plane"] == "identity" and sig["context"]["attribution"] == "unattributed"


def test_an_identity_row_without_its_object_id_is_said():
    row = _entra("credential")
    row["TargetId"] = "app-billing'; drop"            # never an id: not one in the pseudo id
    t = card_target.identity_target(row)
    assert t["id"] == "entra:application:unread" and t["object_id"] == "" and t["limit"]


# ── nothing else changes ──────────────────────────────────────────────────────

def test_the_data_plane_keeps_its_anchor():
    """A data-plane row that names no VM is still anchored on one watched VM (L11, unchanged)."""
    rule = _shipped("ssh-brute-force")
    sent: list = []
    p = RulePoller([rule], sent.append, topology=Topology(lambda: AZURE))
    p._detector = lambda _rule: _Workspace([{"IPAddress": "203.0.113.9", "FailedAttempts": 40}])
    p._registry = _Registry(BREE, GONDOLIN)
    p.poll_once(rule)
    p.stop()
    assert sent and sent[0]["resource_id"] == BREE and "target" not in sent[0]["context"]
    assert sent[0]["context"]["attribution"] == "unattributed" and sent[0]["resource_type"] == "vm"


def test_a_target_that_raises_never_loses_the_card(monkeypatch):
    def boom(*_a, **_k):
        raise RuntimeError("no")
    monkeypatch.setattr(card_target, "of_row", boom)
    sig = _poll("nsg-change-outside-glorfindel", [_activity(NSG_OP, NSG)])[0]
    assert sig["context"]["target"]["kind"] == "control_plane" and sig["resource_id"] != BREE


@pytest.mark.parametrize("rule,rows", [
    ("nsg-change-outside-glorfindel", [_activity(NSG_OP, NSG)]),
    ("role-assignment-write", [_activity(ROLE_OP, ROLE)]),
    ("entra-credential-added", [_entra("credential")]),
])
def test_no_model_no_action_no_incident_no_memory_never_merged(tmp_path, monkeypatch, rule, rows):
    """The garantees of AL1 and C2, on a card filed on its target: the model never asked, nothing
    run, no incident opened or fed on any VM, nothing in the memory; the card holds its target;
    two operations on one NSG are two cards."""
    from glorfindel import escalations
    from glorfindel.incidents import IncidentRegistry
    from glorfindel.memory import CycleMemory
    sent = _poll(rule, rows)
    sent += _poll(rule, [dict(r, CorrelationId="c-2", EventId="c-2|x") for r in rows])
    assert len(sent) == 2
    incidents = IncidentRegistry(path=tmp_path / "incidents.jsonl")
    memory = CycleMemory(path=tmp_path / "cycles")
    connector = MagicMock(dry_run=False)
    with patch("litellm.completion", return_value=_llm("isolate_vm")) as llm:
        for sig in sent:
            final = _graph(tmp_path, monkeypatch, connector, memory=memory,
                           incidents=incidents).invoke(_initial(sig))
            assert final["incident"] is None and final["action"] == ""
    llm.assert_not_called()
    for name in ("isolate_vm", "block_suspicious_ip", "snapshot", "release_isolation"):
        getattr(connector, name).assert_not_called()
    assert incidents.get_active(BREE) is None and incidents.get_active(GONDOLIN) is None
    assert memory.count() == 0
    cards = escalations.pending()
    assert len(cards) == 2                                  # never merged
    for card, sig in zip(cards, sent):
        assert card["resource_id"] == sig["resource_id"] != BREE
        assert card["target"] == sig["context"]["target"]
        assert card["escalation_type"] in ("control_plane_change", "identity_change")
    # TO JUDGE shows it, its target with it.
    judged = {c["id"]: c for c in escalations.to_judge()}
    assert all(judged[c["id"]]["target"] == c["target"] for c in cards)


def test_the_watch_queues_a_card_by_its_plane_never_behind_an_unrelated_vm():
    from glorfindel.cli import _queue_of
    nsg = _poll("nsg-change-outside-glorfindel", [_activity(NSG_OP, NSG)])[0]
    ident = card_target.identity_target(_entra("credential"))
    assert _queue_of(nsg) == "plane:control"
    assert _queue_of({"resource_id": ident["id"], "context": {"plane": "identity", "target": ident}}) == "plane:identity"
    # A card filed on a VM (a disk's): that VM's queue; a data-plane signal: its VM's.
    disk = _poll("snapshot-by-unexpected-caller", [_activity(DISK_ACCESS_OP, DISK)])[0]
    assert _queue_of(disk) == GONDOLIN
    assert _queue_of({"resource_id": BREE, "context": {}}) == BREE


# ── the topology ──────────────────────────────────────────────────────────────

def test_the_topology_is_cached_read_again_on_a_miss_and_says_what_it_could_not_read(monkeypatch):
    import glorfindel.card_target as ct
    now = [1000.0]
    monkeypatch.setattr(ct.time, "time", lambda: now[0])
    calls = []

    def source():
        calls.append(1)
        if len(calls) == 1:
            raise RuntimeError("throttled")
        return {"nsg_vms": {"a": ["vm"]}, "disk_vm": None, "snapshot_source": {}}
    topo = Topology(source)
    assert topo.lookup("nsg_vms", "A") is UNREAD and len(calls) == 1     # never « none there »
    now[0] += ct._MISS_REFRESH_S
    assert topo.lookup("nsg_vms", "a") == ["vm"] and len(calls) == 2
    assert topo.lookup("disk_vm", "d") is UNREAD
    assert topo.lookup("nsg_vms", "a") == ["vm"] and len(calls) == 2     # cached
    assert topo.lookup("snapshot_source", "s") is None and len(calls) == 2
    now[0] += ct._MISS_REFRESH_S
    topo.lookup("snapshot_source", "s")                                  # a miss, a minute later
    assert len(calls) == 3


def test_the_azure_reader_lists_each_section_on_its_own_read_only():
    from glorfindel.providers.azure.readers import ReadersMixin
    nic = SimpleNamespace(id=f"{PROV}/Microsoft.Network/networkInterfaces/nic-bree",
                          virtual_machine=SimpleNamespace(id=BREE),
                          ip_configurations=[SimpleNamespace(subnet=SimpleNamespace(id=SUBNET))])
    nic2 = SimpleNamespace(id=f"{PROV}/Microsoft.Network/networkInterfaces/nic-gondolin",
                           virtual_machine=SimpleNamespace(id=GONDOLIN), ip_configurations=[])
    nsg = SimpleNamespace(id=NSG, network_interfaces=[SimpleNamespace(id=nic2.id)],
                          subnets=[SimpleNamespace(id=SUBNET)])
    conn = SimpleNamespace(dry_run=False, _ensure_clients=lambda: None)
    conn._network = SimpleNamespace(network_interfaces=SimpleNamespace(list_all=lambda: [nic, nic2]),
                                    network_security_groups=SimpleNamespace(list_all=lambda: [nsg]))

    def no_snapshots():
        raise RuntimeError("403")
    conn._compute = SimpleNamespace(
        disks=SimpleNamespace(list=lambda: [SimpleNamespace(id=DISK, managed_by=GONDOLIN)]),
        snapshots=SimpleNamespace(list=no_snapshots))
    out = ReadersMixin.control_topology(conn)
    assert out["nsg_vms"] == {_low(NSG): sorted([_low(BREE), _low(GONDOLIN)])}
    assert out["disk_vm"] == {_low(DISK): _low(GONDOLIN)}
    assert out["snapshot_source"] is None                    # unread, never « no snapshot »
    assert ReadersMixin.control_topology(SimpleNamespace(dry_run=True)) == {}


# ── the Discord card ──────────────────────────────────────────────────────────

def _card(sig, explanation="Plan de contrôle : une opération sur nsg-celebrimbor."):
    reason = (f"{explanation} Sévérité : haute. Détection seule : aucune action autonome sur le "
              "plan de contrôle — décision déterministe, sans appel au modèle ; revue humaine.")
    return {"id": "e1", "action": "", "escalation_type": "control_plane_change",
            "resource_id": sig["resource_id"], "target": sig["context"]["target"], "ttp": "T1562.007",
            "severity": "high", "rule_name": "nsg-change-outside-glorfindel",
            "explanation": explanation, "reason": reason, "suggested_steps": ["Vérifier."]}


def test_the_discord_card_names_its_target_and_says_its_paragraph_once():
    pytest.importorskip("discord")
    from glorfindel.bot import _embed_body
    sig = _poll("nsg-change-outside-glorfindel", [_activity(NSG_OP, f"{NSG}/securityRules/allow-ssh-admin")])[0]
    card = _card(sig)
    description, fields = _embed_body(card)
    by = dict((n, v) for n, v, _ in fields)
    assert "NSG `nsg-celebrimbor`" in by["Ressource visée"]
    assert "`vm-celebrimbor-bree`" in by["Ressource visée"] and "`vm-celebrimbor-gondolin`" in by["Ressource visée"]
    assert "Ressource" not in by                              # never « vm-celebrimbor-bree » alone
    # The paragraph once: the description holds it, the field under it says only why nothing runs.
    assert "Plan de contrôle" in description
    why = by["Pourquoi rien n'est exécuté"]
    assert "Plan de contrôle : une opération" not in why and "Détection seule" in why
    # An identity: named, its object id with it; a limit said.
    ident = card_target.identity_target(_entra("credential"))
    _, fields = _embed_body({**card, "escalation_type": "identity_change", "resource_id": ident["id"],
                             "target": ident})
    by = dict((n, v) for n, v, _ in fields)
    assert by["Identité visée"].startswith("Application `eregion-bench-test`") and APP_OID in by["Identité visée"]
    sig = _poll("snapshot-by-unexpected-caller", [_activity(SNAP_OP, SNAP)], azure={**AZURE, "snapshot_source": {}})[0]
    _, fields = _embed_body(_card(sig))
    by = dict((n, v) for n, v, _ in fields)
    assert by["Ressource visée"].startswith("groupe de ressources `rg-celebrimbor`")
    assert "ne nomme pas le disque source" in by["Limite"]


def test_the_discord_card_names_eight_vms_an_nsg_covers_and_counts_the_rest():
    """An NSG over a whole subnet: the field stays readable (Discord cuts a field at 1024), eight
    VMs named, the rest counted (review, AL1c)."""
    pytest.importorskip("discord")
    from glorfindel.bot import _embed_body
    vms = [f"{PROV}/Microsoft.Compute/virtualMachines/vm-{i:02d}" for i in range(10)]
    azure = {**AZURE, "nsg_vms": {_low(NSG): [_low(v) for v in vms]}}
    sig = _poll("nsg-change-outside-glorfindel", [_activity(NSG_OP, NSG)], azure=azure, vms=vms)[0]
    assert len(sig["context"]["target"]["vm_names"]) == 10      # the card keeps them all
    shown = dict((n, v) for n, v, _ in _embed_body(_card(sig))[1])["Ressource visée"]
    assert all(f"`vm-{i:02d}`" in shown for i in range(8))
    assert "`vm-08`" not in shown and "`vm-09`" not in shown
    assert shown.endswith(" et 2 autre(s)")
    # Long names: the field stays under Discord's 1024, or the whole embed is refused.
    long = {"kind": "nsg", "id": NSG, "name": "n" * 300, "via": "v" * 300, "vm_names": ["x" * 300] * 10}
    shown = dict((n, v) for n, v, _ in _embed_body({**_card(sig), "target": long})[1])["Ressource visée"]
    assert len(shown) == 1024 and shown.startswith("NSG `" + "n" * 120)


def test_a_card_filed_before_al1c_says_it_may_not_be_about_its_vm():
    pytest.importorskip("discord")
    from glorfindel.bot import _embed_body
    old = {"id": "e0", "action": "", "escalation_type": "identity_change", "resource_id": BREE,
           "explanation": "x", "reason": "x y"}
    by = dict((n, v) for n, v, _ in _embed_body(old)[1])
    # Filed on the first VM online — or on the VM itself (a role on it, a signal of `respond`):
    # the card cannot tell which, and never says « not about it » (review, AL1c).
    assert "la détection peut ne pas la viser" in by["Ressource"]
    assert "ne la vise pas" not in by["Ressource"]
    data = {**old, "escalation_type": "low_confidence", "action": "isolate_vm"}
    assert dict((n, v) for n, v, _ in _embed_body(data)[1])["Ressource"] == "`vm-celebrimbor-bree`"


def test_the_names_on_the_discord_card_are_escaped():
    pytest.importorskip("discord")
    from glorfindel.bot import _embed_body
    ident = card_target.identity_target({**_entra("credential"), "TargetName": "**@everyone** [x](http://e)"})
    _, fields = _embed_body({"id": "e", "action": "", "escalation_type": "identity_change",
                             "resource_id": ident["id"], "target": ident, "explanation": "", "reason": ""})
    shown = dict((n, v) for n, v, _ in fields)["Identité visée"]
    assert "@everyone" not in shown and "`" + "**@​everyone** [x](http://e)" + "`" in shown


def test_every_identity_card_shares_one_thread_and_a_resource_card_its_own():
    pytest.importorskip("discord")
    from glorfindel.bot import _thread_key, _thread_name
    a = card_target.identity_target(_entra("credential"))
    b = card_target.identity_target(_entra("consent"))
    assert _thread_key({"resource_id": a["id"]}) == _thread_key({"resource_id": b["id"]}) == "entra:identities"
    assert _thread_name("entra:identities") == "Entra ID — identités"
    assert _thread_key({"resource_id": NSG}) == NSG and _thread_name(NSG) == "nsg-celebrimbor"
    # A card from before AL1c stays in the thread of the VM it was posted in.
    assert _thread_key({"resource_id": BREE, "escalation_type": "identity_change"}) == BREE


# ── the console ───────────────────────────────────────────────────────────────

def test_the_console_files_an_identity_card_on_its_own_tile_and_an_nsg_card_on_the_vms_it_covers():
    """The page (glorfindel.js): an identity card on the identities' tile, never a VM's; a card
    about an NSG on the NSG and on each VM it covers; a group, the control plane, their own tile;
    the note says what the card is about. Read in the page's text: no browser in the suite."""
    from pathlib import Path
    js = (Path(__file__).resolve().parents[2] / "eregion_console/static/glorfindel.js").read_text()
    def body(head):
        return js.split(head, 1)[1].split("\n}\n", 1)[0]
    on_tile = body("function _onTile(e, r) {")
    assert "if (r.kind === 'identity') return _isIdentityCard(e);" in on_tile
    assert "if (_isIdentityCard(e)) return false;" in on_tile
    assert "_coversVm(e, r.resource_id)" in on_tile
    assert "const myEscs      = vmEscs.filter(e => _onTile(e, resource));" in js
    assert "🎯 about ${kind}${named}${via}${covers}" in js
    # A tile of its own — the identities', a group's, the control plane's — is named with a « : »,
    # which no VM's name holds, and holds its cards only: never one tile with a VM named
    # « control-plane » or like the group (review, AL1c).
    own = body("function _ownTile(e) {")
    assert "const _IDENTITY_TILE = 'entra:identities';" in js
    assert "if (t.kind === 'identity') return _IDENTITY_TILE;" in own
    assert "if (t.kind === 'resource_group') return 'group:' + String(e.resource_id || '').toLowerCase();" in own
    assert "if (t.kind === 'control_plane') return 'plane:control';" in own
    assert "if (own || r.kind) return own === r.vm_name;" in on_tile
    assert on_tile.index("if (own || r.kind)") < on_tile.index("e.resource_id.split('/').pop() === r.vm_name")
    infra = body("function renderInfra() {")
    assert "const own = _ownTile(e);" in infra and "resourceMap.set(own," in infra
    # The card opens its tile's cards, the topology draws to that tile.
    assert "const vmName = _ownTile(e) || e.resource_id.split('/').pop();" in js
    assert "const vm    = _ownTile(e) || e.resource_id.split('/').pop();" in js


def test_the_console_names_eight_vms_an_nsg_covers_and_says_a_card_filed_before_may_not_be_about_its_vm():
    """The note of a card (glorfindel.js `_targetNote`): the VMs an NSG covers named up to eight,
    the rest counted, as Discord does; a card of the control plane or of an identity filed before
    AL1c says it may not be about its VM (on the first VM online, or on the VM itself), on the card
    and in TO JUDGE (review, AL1c). Read in the page's text: no browser in the suite."""
    from pathlib import Path
    js = (Path(__file__).resolve().parents[2] / "eregion_console/static/glorfindel.js").read_text()
    note = js.split("function _targetNote(e, vmName) {", 1)[1].split("\n}\n", 1)[0]
    assert "const _VMS_SHOWN = 8;" in js
    assert "const more = vms.length > _VMS_SHOWN ? ` and ${vms.length - _VMS_SHOWN} more` : '';" in note
    assert "vms.slice(0, _VMS_SHOWN).map(v => _attr(v)).join(', ')}${more}" in note
    assert "⚓ filed on ${_attr(vmName)}, may not be about it</div>" in note
    assert ", not about it" not in note
    assert "const _FILED_BEFORE = 'Filed before AL1c, without its target: the detection may not be about this VM';" in js
    assert "title=\"${_attr(_FILED_BEFORE)}\"" in note
    assert "_DETECTION_ONLY.has(c.escalation_type) ? _FILED_BEFORE :" in js


def test_record_keeps_the_target():
    from glorfindel import escalations
    t = card_target.identity_target(_entra("credential"))
    eid = escalations.record(signal_id="s", resource_id=t["id"], action="", escalation_type="identity_change",
                             reason="r", target=t)
    card = next(e for e in escalations.pending() if e["id"] == eid)
    assert card["target"] == t
    assert json.loads(json.dumps(card))["target"]["kind"] == "identity"
