"""MC0: no provider SDK outside its adapter, and each provider declares its capabilities.

The CI runs this file with the rest (.github/workflows/ci.yml, step « Provider
boundary » first, so a breach is named before the long tests). A provider SDK — azure,
boto3/botocore, google-cloud, googleapiclient — is imported only:
  - in glorfindel/, under glorfindel/providers/<provider>/ (Azure: the only adapter);
  - elsewhere, in the adapter file of its component (ADAPTERS);
  - or in a file of KNOWN_DEBT, a list that can only shrink: each entry says why.
Tests are out of scope: the fake Azure raises the SDK's own exceptions.
"""
from __future__ import annotations

import ast
import inspect
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]

# SDK root module → provider.
SDK_ROOTS = {"azure": "azure", "boto3": "aws", "botocore": "aws", "google.cloud": "gcp",
             "google.auth": "gcp", "googleapiclient": "gcp"}

# Outside glorfindel/: the one file through which a component reaches its cloud.
ADAPTERS = {
    "annatar/executors/azure_vm.py": "azure",          # Annatar's injector (Run Command)
    "annatar/collectors/azure_monitor.py": "azure",    # Annatar's detection watcher
    "gothmog/engines/chaos_studio.py": "azure",        # Gothmog's fault engine
    "infra/orodruin/kill.py": "azure",                 # Orodruin's emergency stop
}
# Not an adapter, and known: each takes an azure.identity credential for a REST call of
# the shared core. Shrink-only — the test fails when one no longer imports the SDK.
KNOWN_DEBT = {
    "eregion_core/inscription.py": "credential for the ARM tag read of the inscription",
    "eregion_core/exercise_channel.py": "credential for the exercise channel (Storage)",
    "eregion_core/orodruin.py": "credential for the contract check (role assignments)",
}
_SKIP_DIRS = {"tests", "node_modules", "__pycache__", "build", "dist", "venv", "site-packages"}


def _python_files():
    for p in sorted(ROOT.rglob("*.py")):
        parts = p.relative_to(ROOT).parts
        if any(part.startswith(".") or part in _SKIP_DIRS for part in parts[:-1]):
            continue
        yield p


def _sdk(module: str) -> str | None:
    for root, provider in SDK_ROOTS.items():
        if module == root or module.startswith(root + "."):
            return provider
    return None


def sdk_imports(source: str) -> list[tuple[int, str, str]]:
    """(line, module, provider) for each provider SDK the source imports — import
    statements, and importlib.import_module("<sdk>…") with a literal name."""
    found = []
    for node in ast.walk(ast.parse(source)):
        names: list[str] = []
        if isinstance(node, ast.Import):
            names = [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            names = [node.module]
        elif (isinstance(node, ast.Call) and getattr(node.func, "attr", getattr(node.func, "id", ""))
              in ("import_module", "__import__") and node.args
              and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str)):
            names = [node.args[0].value]
        for name in names:
            provider = _sdk(name)
            if provider:
                found.append((node.lineno, name, provider))
    return found


def allowed(rel: str, provider: str) -> bool:
    if rel.startswith("glorfindel/"):
        return rel.startswith(f"glorfindel/providers/{provider}/")
    return ADAPTERS.get(rel) == provider or rel in KNOWN_DEBT


def breaches() -> list[str]:
    out = []
    for p in _python_files():
        rel = p.relative_to(ROOT).as_posix()
        for line, module, provider in sdk_imports(p.read_text(encoding="utf-8")):
            if not allowed(rel, provider):
                out.append(f"{rel}:{line} imports {module} ({provider}) outside its adapter")
    return out


def test_no_provider_sdk_outside_its_adapter():
    assert breaches() == []


def test_the_scan_sees_what_it_must_refuse():
    """The scan itself: a planted import in glorfindel/ outside the adapter is found,
    under each form; the same import inside the adapter is allowed."""
    src = ("import azure.mgmt.network\nfrom azure.identity import X\nimport boto3\n"
           "import importlib\nimportlib.import_module('google.cloud.compute')\n")
    found = sdk_imports(src)
    assert [m for _, m, _ in found] == ["azure.mgmt.network", "azure.identity", "boto3",
                                        "google.cloud.compute"]
    assert not allowed("glorfindel/agent.py", "azure")
    assert not allowed("glorfindel/providers/aws/x.py", "azure")
    assert allowed("glorfindel/providers/azure/network.py", "azure")
    assert not allowed("annatar/runner/engine.py", "azure")
    assert sdk_imports("import azurely\nfrom .azure import x\n") == []
    files = {p.relative_to(ROOT).as_posix() for p in _python_files()}
    assert "glorfindel/agent.py" in files and "glorfindel/providers/azure/sdk.py" in files
    assert not any(f.startswith("tests/") for f in files)


# The ceiling of KNOWN_DEBT: a file added there would pass the boundary unseen.
_KNOWN_DEBT_CEILING = frozenset({
    "eregion_core/inscription.py", "eregion_core/exercise_channel.py", "eregion_core/orodruin.py"})


def test_the_known_debt_cannot_grow_and_no_shared_core_file_is_an_adapter():
    """KNOWN_DEBT stays within its ceiling of 26/10; ADAPTERS may grow (a new injector or
    engine is a new adapter) but never with a file of the shared core or of glorfindel/ —
    moving a debt entry there would hide it."""
    assert set(KNOWN_DEBT) <= _KNOWN_DEBT_CEILING
    assert not [a for a in ADAPTERS if a.startswith(("eregion_core/", "glorfindel/"))]


def test_the_known_debt_only_shrinks():
    """An entry whose file no longer imports the SDK goes: the list must say the truth."""
    for rel in KNOWN_DEBT:
        assert sdk_imports((ROOT / rel).read_text(encoding="utf-8")), f"{rel}: remove it from KNOWN_DEBT"
    for rel in ADAPTERS:
        assert sdk_imports((ROOT / rel).read_text(encoding="utf-8")), f"{rel}: no longer an adapter"


def test_glorfindel_calls_the_azure_rest_api_only_from_its_adapter():
    """Some Azure calls go through REST (permissions, activity log, backup): the endpoint
    is the provider's API as much as its SDK."""
    hits = [p.relative_to(ROOT).as_posix() for p in (ROOT / "glorfindel").rglob("*.py")
            if "management.azure.com" in p.read_text(encoding="utf-8")]
    assert hits and all(h.startswith("glorfindel/providers/azure/") for h in hits)


# ── Capabilities ─────────────────────────────────────────────────────────────

def test_azure_declares_what_check_permissions_reads():
    """The rights the readiness reads from the declaration are the ones the permissions
    read asks Azure about — one source drifting from the other would say « ready » on
    rights nobody checked."""
    from glorfindel.actions import AzureConnector
    from glorfindel.providers import capabilities_of
    caps = capabilities_of(AzureConnector(dry_run=True, read_only=False))
    declared = set().union(*(c.rights for c in caps.capabilities))
    assert declared == {a for _, a in AzureConnector.REQUIRED_ACTIONS}
    scopes_src = inspect.getsource(AzureConnector._permission_scopes)
    assert set(re.findall(r'"(Microsoft\.[A-Za-z./]+)"', scopes_src)) == declared


def test_every_connector_declares_its_capabilities():
    from glorfindel.providers import CloudConnector, capabilities_of
    from glorfindel.actions import AzureConnector

    assert capabilities_of(AzureConnector(dry_run=True, read_only=False)).provider == "azure"

    class Undeclared(AzureConnector):
        CAPABILITIES = None
    with pytest.raises(TypeError):
        capabilities_of(Undeclared(dry_run=True, read_only=False))
    assert issubclass(AzureConnector, CloudConnector)
    # A test double (no CloudConnector) reads as the only adapter.
    assert capabilities_of(object()).provider == "azure"


def test_a_spec_mock_and_an_instance_declaration_are_read():
    """A MagicMock(spec=AzureConnector) reports AzureConnector as its class: it reads as
    Azure, and the readiness runs on it; an instance that carries its own declaration is
    read before its class's."""
    from unittest.mock import MagicMock

    from glorfindel.actions import AzureConnector
    from glorfindel.providers import ProviderCapabilities, capabilities_of
    from glorfindel.readiness import assess

    mock = MagicMock(spec=AzureConnector)
    assert capabilities_of(mock).provider == "azure"
    mock.read_only, mock._subscription_id = False, None
    mock.check_permissions.return_value = {"ok": True, "missing": []}
    mock.check_nsg_access.return_value = {"ok": True, "precedence": []}
    mock.vm_os.return_value = "linux"
    assert assess(RID, mock)["verdict"] == "ready"

    own = ProviderCapabilities("other", ())
    conn = AzureConnector(dry_run=True, read_only=False)
    conn.CAPABILITIES = own
    assert capabilities_of(conn) is own


def _readiness_conn(caps, missing=()):
    """An AzureConnector whose class declares `caps`, its Azure reads answered here."""
    from glorfindel.actions import AzureConnector

    class Declared(AzureConnector):
        CAPABILITIES = caps
    c = Declared(dry_run=True, read_only=False)
    c.check_permissions = lambda rid: {"ok": True, "missing": [
        {"action": a, "scope": "rg", "used_by": "isolate_vm"} for a in missing]}
    c.check_nsg_access = lambda rid: {"ok": True, "precedence": []}
    c.vm_os = lambda rid: "linux"
    return c


RID = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm1"


def test_the_readiness_reads_the_declaration():
    """A provider that declares no session cut gets the reserve « no_drain » though no
    right is missing; one whose quarantine needs a right that is missing isolates by
    rules — the readiness knows no permission name of its own."""
    from glorfindel.providers.azure.capabilities import CAPABILITIES
    from glorfindel.providers.interface import (
        NETWORK_QUARANTINE, SESSION_DRAIN, Capability, ProviderCapabilities)
    from glorfindel.readiness import assess

    assert assess(RID, _readiness_conn(CAPABILITIES))["verdict"] == "ready"
    no_drain = ProviderCapabilities("other", tuple(c for c in CAPABILITIES.capabilities
                                                   if c.name != SESSION_DRAIN))
    assert "no_drain" in assess(RID, _readiness_conn(no_drain))["reserve_codes"]
    custom = ProviderCapabilities("other", tuple(
        Capability(NETWORK_QUARANTINE, c.actions, frozenset({"other/quarantine"}))
        if c.name == NETWORK_QUARANTINE else c for c in CAPABILITIES.capabilities))
    a = assess(RID, _readiness_conn(custom, missing=["other/quarantine"]))
    assert "rules_fallback" in a["reserve_codes"]
    assert "other/quarantine" in next(r["fix"] for r in a["reasons"] if r["code"] == "rules_fallback")
