"""Glorfindel's response actions — the import path everything uses (A1).

The code that lived here (4 394 lines) is split by concern, nothing changed in it:

  glorfindel/response/          the provider-neutral core
    policy.py                   which actions run alone, errors, verdicts
    ids.py                      resource ids
    state.py                    local state (~/.glorfindel/isolation, blocks)
    locks.py                    one writer per VM, per quarantine NSG
  glorfindel/providers/         the provider interface (MC0)
    interface.py                CloudConnector
  glorfindel/providers/azure/   the only adapter, and the only place the Azure SDK is imported
    connector.py                AzureConnector, the subscription guard, the VM lock on writes
    nsg.py                      reading security rules by content
    network.py                  NICs and NSGs: reads, rule writes, names
    quarantine.py               the quarantine NSG
    isolation.py, release.py, verify.py      isolation by quarantine or by rules
    blocks.py, unblock.py       IP blocks
    backup.py, restore.py       restore points
    sweep.py, readers.py        reset and orphans; rights, inventory, audit reads
    sdk.py                      SDK warm-up, error and enum helpers

`from glorfindel.actions import X` keeps working for every name that lived here: the CLI,
the War Room, the agent and the tests import from this path.

One namespace, as before the split. A name set here — a test's monkeypatch of
`_ISOLATION_STATE_DIR`, `_vm_lock`, `_save_block_state`… — is set in every module that
binds it, so the patch reaches all the code that reads it, as it did when that code was
one file. A name is read from the first module that binds it (they all bind the same
object, `tests/unit/test_provider_boundary.py`), live: a value a module changes itself
(`_warmed_up`) reads as changed.
"""
from __future__ import annotations

import importlib as _importlib
import sys as _sys
import types as _types

_MODULES = tuple(_importlib.import_module(name) for name in (
    "glorfindel.response.policy",
    "glorfindel.response.ids",
    "glorfindel.response.state",
    "glorfindel.response.locks",
    "glorfindel.providers.interface",
    "glorfindel.providers.azure.sdk",
    "glorfindel.providers.azure.nsg",
    "glorfindel.providers.azure.quarantine",
    "glorfindel.providers.azure.network",
    "glorfindel.providers.azure.isolation",
    "glorfindel.providers.azure.release",
    "glorfindel.providers.azure.verify",
    "glorfindel.providers.azure.blocks",
    "glorfindel.providers.azure.unblock",
    "glorfindel.providers.azure.backup",
    "glorfindel.providers.azure.restore",
    "glorfindel.providers.azure.sweep",
    "glorfindel.providers.azure.readers",
    "glorfindel.providers.azure.connector",
))


def _binders(name: str) -> list:
    return [] if name.startswith("__") else [m for m in _MODULES if name in vars(m)]


def __getattr__(name: str):
    for module in _binders(name):
        return vars(module)[name]
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__() -> list[str]:
    return sorted({n for m in _MODULES for n in vars(m) if not n.startswith("__")} | set(globals()))


class _OneNamespace(_types.ModuleType):
    """Writes reach every module of the split that binds the name (see the docstring)."""

    def __setattr__(self, name: str, value) -> None:
        binders = _binders(name)
        if not binders:
            super().__setattr__(name, value)
        for module in binders:
            setattr(module, name, value)

    def __delattr__(self, name: str) -> None:
        if _binders(name):
            raise AttributeError(
                f"{name} lives in {_binders(name)[0].__name__}: patch it with monkeypatch.setattr "
                "(this module forwards writes), not by deleting it")
        super().__delattr__(name)


_sys.modules[__name__].__class__ = _OneNamespace
