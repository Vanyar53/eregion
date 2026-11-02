"""SEC8 (#414) — every ARM call that carries a token is built from the parts read of an id.

An id a window names, a listing returns or an experiment targets is never pasted after
``https://management.azure.com`` as it was received: a VM's URL is rebuilt from its
subscription, group and name (``eregion_core.held.vm_parts``), anything else must be a path
under ARM (``safe_path``, ``arm_relative``), and a listing's next page outside ARM is refused.
Refused before the token is even asked for. A property: whatever the text, the host is ARM's.

No Azure call. Every identifier is made up (repository public). Mutants M2810–M2839.
"""
from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock
from urllib.parse import urlsplit

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from eregion_core import held, inscription

SUB = "00000000-0000-0000-0000-0000000000cc"
VM = f"/subscriptions/{SUB}/resourceGroups/rg-example/providers/Microsoft.Compute/virtualMachines/vm-example-01"
ARM_HOST = "management.azure.com"


def _ok(body=None):
    return MagicMock(ok=True, status_code=200, json=MagicMock(return_value=body or {"tags": {}}))


class _Recorder:
    """A fake requests.get and credential: what was asked, with which token."""

    def __init__(self):
        self.urls: list[str] = []
        self.tokens = 0

    def get(self, url, headers=None, params=None, timeout=None):
        self.urls.append(url)
        return _ok()

    def credential(self):
        rec = self

        class _Cred:
            def get_token(self, scope):
                rec.tokens += 1
                return SimpleNamespace(token="t")
        return _Cred()


@pytest.mark.parametrize("rid", [VM, VM.lower(), VM + "/", VM.replace("resourceGroups", "resourcegroups")])
def test_a_vm_id_gives_its_parts(rid):
    assert held.vm_parts(rid) == (SUB, "rg-example", "vm-example-01")
    assert held.vm_path(rid).lower() == VM.lower()


@pytest.mark.parametrize("rid", [
    "@other-host.example" + VM,                      # before the path: another host
    ":8443" + VM, "." + VM, "//other-host.example" + VM,
    VM + "?x=1", VM + "#x", VM + "/extensions/x", VM.replace("vm-example-01", "vm%2F01"),
    VM.replace("vm-example-01", ".."), VM.replace("rg-example", "rg@x"),
    VM.replace("vm-example-01", "vm​01"), VM.replace("vm-example-01", "vm 01"),
    f"/subscriptions/{SUB}/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/st",
    "", None, 3,
])
def test_an_id_not_exactly_a_vms_is_refused(rid):
    with pytest.raises(ValueError):
        held.vm_parts(rid)


def test_the_enrollment_read_builds_its_urls_from_the_parts():
    rec = _Recorder()
    reader = inscription.TagEnrollment(credential=rec.credential(), get=rec.get)
    reader.tags(VM)
    assert rec.urls == [f"https://{ARM_HOST}/subscriptions/{SUB}/resourceGroups/rg-example",
                        f"https://{ARM_HOST}{VM}"]


@pytest.mark.parametrize("prefix", ["@other-host.example", ":443@other-host.example", ".other-host.example"])
def test_an_id_that_would_change_the_host_is_refused_before_any_token(prefix):
    rec = _Recorder()
    reader = inscription.TagEnrollment(credential=rec.credential(), get=rec.get)
    with pytest.raises(ValueError):
        reader.tags(prefix + VM)
    assert rec.urls == [] and rec.tokens == 0
    assert reader(prefix + VM) is False                   # not enrolled: the window marks nothing
    assert rec.urls == [] and rec.tokens == 0


@settings(max_examples=300, deadline=None)
@given(st.text(max_size=40), st.text(max_size=40))
def test_whatever_the_id_the_token_goes_to_arm_only(head, tail):
    """A property: an id with any text before or after a VM's — read, or refused, but every
    URL asked is ARM's, on the VM's own path."""
    rec = _Recorder()
    reader = inscription.TagEnrollment(credential=rec.credential(), get=rec.get)
    try:
        reader.tags(head + VM + tail)
    except ValueError:
        assert rec.urls == []
        return
    assert {urlsplit(u).hostname for u in rec.urls} == {ARM_HOST}
    assert all(urlsplit(u).username is None and not urlsplit(u).query for u in rec.urls)


@pytest.mark.parametrize("path", ["/providers/Microsoft.Authorization/roleDefinitions/r1",
                                  f"/subscriptions/{SUB}/providers/Microsoft.Authorization/roleDefinitions/r1"])
def test_a_path_under_arm_passes(path):
    assert held.arm_relative(path) == path


@pytest.mark.parametrize("path", ["@other-host.example/x", "other-host.example/x", "/x?y", "/x#y", "/x%2F",
                                  "/x/../y", "/x\\y", "/x y", "", None])
def test_a_path_not_under_arm_is_refused(path):
    with pytest.raises(ValueError):
        held.arm_relative(path)


def test_orodruin_never_reads_a_role_definition_elsewhere(monkeypatch):
    """The role definition ids come from the listing of the assignments: one that is not a path
    under ARM is not read (its rights unproven: outside), its URL never asked."""
    import base64
    import json

    from eregion_core import orodruin
    monkeypatch.setenv("AZURE_SUBSCRIPTION_ID", SUB)
    oid = base64.urlsafe_b64encode(json.dumps({"oid": "o"}).encode()).decode().rstrip("=")
    credential = MagicMock()
    credential.get_token.return_value.token = f"h.{oid}.s"
    asked: list[str] = []
    bench = orodruin.bench_scope(SUB, orodruin.DEFAULT_BENCH_RG)

    def get(url, headers, params, timeout):
        asked.append(url)
        if url.endswith("/roleAssignments"):
            return _ok({"value": [{"properties": {"scope": bench, "roleDefinitionId": "@other-host.example/r"}}]})
        return _ok({"value": []})

    orodruin.read_identity(credential=credential, get=get)
    assert asked and all(urlsplit(u).hostname == ARM_HOST for u in asked)
    assert not [u for u in asked if "other-host" in u]


def test_orodruin_never_follows_a_next_page_elsewhere(monkeypatch):
    import base64
    import json

    from eregion_core import orodruin
    monkeypatch.setenv("AZURE_SUBSCRIPTION_ID", SUB)
    oid = base64.urlsafe_b64encode(json.dumps({"oid": "o"}).encode()).decode().rstrip("=")
    credential = MagicMock()
    credential.get_token.return_value.token = f"h.{oid}.s"
    asked: list[str] = []

    def get(url, headers, params, timeout):
        asked.append(url)
        # One page elsewhere, then the end: a red test never loops.
        return _ok({"value": [], **({} if "other-host" in url else {"nextLink": "https://other-host.example/next"})})

    with pytest.raises(RuntimeError, match="outside Azure Resource Manager"):
        orodruin.read_identity(credential=credential, get=get)
    assert all(urlsplit(u).hostname == ARM_HOST for u in asked)


def test_gothmog_calls_arm_paths_only():
    """A VM id read from an experiment's targets: an ARM path, or no call."""
    from gothmog.engines.chaos_studio import ChaosStudio
    http = MagicMock()
    engine = ChaosStudio(credential=MagicMock(), http=http, subscription_id=SUB)
    with pytest.raises(ValueError):
        engine.vm("@other-host.example" + VM)
    assert not http.get.called and not http.post.called
    http.get.return_value = _ok({})
    engine.vm(VM)
    assert urlsplit(http.get.call_args[0][0]).hostname == ARM_HOST


def test_glorfindels_permission_check_never_follows_a_next_page_elsewhere(monkeypatch):
    from glorfindel.providers.azure.connector import AzureConnector
    conn = object.__new__(AzureConnector)
    conn.dry_run = False
    conn._subscription_id = SUB
    conn._credential = SimpleNamespace(get_token=lambda scope: SimpleNamespace(token="t"))
    conn._ensure_clients = lambda: None
    conn._permission_scopes = lambda rg, vm: {"rg": ("rg-example", {("isolate_vm", "Microsoft.Network/x")})}
    asked: list[str] = []

    def get(url, headers=None, params=None, timeout=None):
        asked.append(url)
        # One page elsewhere, then the end: a red test never loops.
        return _ok({"value": [], **({} if "other-host" in url else {"nextLink": "https://other-host.example/next"})})
    monkeypatch.setattr("requests.get", get)
    got = conn.check_permissions(VM)
    assert got["ok"] is False and "outside Azure Resource Manager" in got["error"]
    assert all(urlsplit(u).hostname == ARM_HOST for u in asked)
