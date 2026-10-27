"""A1: glorfindel/actions.py split by concern, its import path kept.

The split moved code without changing it (scripts/check_paragraphs.py finds every line
of the old file). What these tests hold: the façade still behaves as one module — a
name patched through it reaches every module that reads it (the hermetic conftest relies
on it) — and no module of the split grows back to thousands of lines.
"""
from __future__ import annotations

import importlib
from pathlib import Path

import glorfindel.actions as actions

ROOT = Path(__file__).resolve().parents[2]
SPLIT = [m.__name__ for m in actions._MODULES]


def _modules():
    return [importlib.import_module(name) for name in SPLIT]


def test_every_module_of_the_split_is_in_the_facade():
    """A module added to glorfindel/response or glorfindel/providers/azure without being
    listed in the façade would keep its names out of reach of `glorfindel.actions`."""
    on_disk = {
        ".".join(p.relative_to(ROOT).with_suffix("").parts)
        for d in ("glorfindel/response", "glorfindel/providers", "glorfindel/providers/azure")
        for p in (ROOT / d).glob("*.py") if p.name != "__init__.py"
    }
    on_disk.discard("glorfindel.providers.azure.monitor")     # the detector: not an action
    on_disk.discard("glorfindel.providers.azure.activity")    # the Activity Log's (AL1): neither
    assert on_disk == set(SPLIT)


def test_a_name_bound_in_several_modules_is_one_object():
    """The façade reads a name from the first module that binds it and writes it to all:
    that is one namespace only if every binding is the same object."""
    seen: dict[str, tuple[str, object]] = {}
    for module in _modules():
        for name, value in vars(module).items():
            if name.startswith("__"):
                continue
            if name in seen:
                first, obj = seen[name]
                assert obj is value, f"{name}: {first} and {module.__name__} bind different objects"
            else:
                seen[name] = (module.__name__, value)


def test_a_patch_through_the_facade_reaches_every_module_that_reads_it(monkeypatch, tmp_path):
    """conftest redirects the state through `glorfindel.actions`: the redirection must
    reach the state module AND the locks (their lock files live next to the state)."""
    binders = [m for m in _modules() if "_ISOLATION_STATE_DIR" in vars(m)]
    assert {m.__name__ for m in binders} >= {"glorfindel.response.state", "glorfindel.response.locks"}
    monkeypatch.setattr(actions, "_ISOLATION_STATE_DIR", tmp_path / "iso")
    assert all(m._ISOLATION_STATE_DIR == tmp_path / "iso" for m in binders)
    actions._save_isolation_state("/subscriptions/s/resourceGroups/rg/providers/x/vm1", {"resource_id": "r"})
    assert list((tmp_path / "iso").glob("*.json"))
    with actions._vm_lock("vm1"):
        pass
    assert list((tmp_path / "locks").glob("vm-*.lock"))

    calls = []
    monkeypatch.setattr(actions, "_save_block_state", lambda *a, **k: calls.append(a))
    blocks = importlib.import_module("glorfindel.providers.azure.blocks")
    assert blocks._save_block_state is actions._save_block_state


def test_a_value_a_module_changes_itself_reads_live(monkeypatch):
    """`warm_up_azure_sdk` sets its own module's `_warmed_up`: read through the façade,
    it must say so (a copy bound in the façade would stay False)."""
    monkeypatch.setattr(actions, "_warmed_up", False)
    monkeypatch.setattr(actions, "_WARM_UP_MODULES", ("json.decoder",))
    actions.warm_up_azure_sdk()
    assert actions._warmed_up is True


def test_the_mixins_of_azure_connector_share_no_name():
    """Each concern defines its own methods: a name defined twice would make the order of
    the bases decide which one runs."""
    owners: dict[str, str] = {}
    for base in actions.AzureConnector.__mro__[1:]:
        if base.__module__.startswith("glorfindel.providers.azure."):
            for name in vars(base):
                if not name.startswith("__"):
                    assert name not in owners, f"{name} in {owners.get(name)} and {base.__name__}"
                    owners[name] = base.__name__
    assert not actions.AzureConnector.__abstractmethods__


def test_no_module_of_the_split_beyond_a_few_hundred_lines():
    """The criterion of A1 (ROADMAP, septième passe): no file beyond a few hundred lines."""
    files = [ROOT / "glorfindel/actions.py"] + [
        p for d in ("glorfindel/response", "glorfindel/providers", "glorfindel/providers/azure")
        for p in (ROOT / d).glob("*.py")]
    too_long = {str(p.relative_to(ROOT)): n for p in files
                if (n := len(p.read_text().splitlines())) > 500}
    assert not too_long


def test_mock_patch_on_the_facade_fails_loudly_and_says_what_to_use(monkeypatch):
    """mock.patch deletes the name on exit, and the façade can't put an « original » back
    (under conftest it would be the real home): it refuses, naming monkeypatch.setattr
    and the module of origin."""
    from unittest import mock

    import pytest

    monkeypatch.setattr(actions, "_ERR_MAX", actions._ERR_MAX)   # restores after the test
    with pytest.raises(AttributeError, match=r"monkeypatch\.setattr.*glorfindel\.response\.policy\._ERR_MAX"):
        with mock.patch("glorfindel.actions._ERR_MAX", 1):
            pass
    # Patching the module of origin works, for that module only.
    policy = importlib.import_module("glorfindel.response.policy")
    with mock.patch("glorfindel.response.policy._ERR_MAX", 2):
        assert policy._ERR_MAX == 2
