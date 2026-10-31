"""Is a VM held by Glorfindel now — isolated or in quarantine — as an injector reads it before it
acts (DG-b review, point 1): Orodruin before a wire of a Dagorlad request
(eregion_core/exercise_runner.py), Annatar's preflight (annatar/executors/azure_vm.py). One rule,
in the shared core, read the same on both sides (D1: neither imports the other, nor Glorfindel).

What holds a VM is a rule of Glorfindel's on a security group that governs it: the group of each of
its network interfaces, and the group of each subnet they sit in, wherever those live — read from
the VM's ``networkProfile``, never by listing the VM's resource group (an NSG lives where its owner
put it: ``nsg_rg``). Glorfindel names its rules:

- ``glorfindel-iso-<vm>-<nic>-<hash>`` and its ``-out`` pair, or the second form ``…-b-<hash>``
  (glorfindel/providers/azure/network.py ``_placement_rule_bases``, isolation.py);
- ``glorfindel-isolation-deny-all`` before L24 — the same prefix, ``glorfindel-iso``;
- ``glorfindel-quarantine-…`` on the quarantine NSG a NIC is moved onto.

A0: what cannot be read holds the VM — a wire waits, then is skipped; a run never goes on a VM it
cannot tell is free. A rule of Glorfindel's on a subnet's group holds every VM of the subnet,
another's isolation included: the safe direction.

Pure but for ``arm_get(path, api_version) -> dict``, the caller's read of Azure Resource Manager
with its own identity (Orodruin's needs ``networkInterfaces/read`` and
``virtualNetworks/subnets/read`` on the bench, infra/orodruin/main.tf).
"""
from __future__ import annotations

import re
from typing import Callable

HOLD_PREFIXES = ("glorfindel-iso", "glorfindel-quarantine-")
VM_API = "2024-07-01"
NET_API = "2023-09-01"
# A path of ARM as a resource id gives it: no query, no fragment, no escape (DG-b review, point 3).
_ARM_PATH = re.compile(r"/subscriptions/[^/?#%\s]+(?:/[^/?#%\s]+)+")


class Unreadable(RuntimeError):
    """What would say whether the VM is held cannot be read: it is held."""


def is_hold(rule_name: str) -> bool:
    return str(rule_name or "").lower().startswith(HOLD_PREFIXES)


def safe_path(path: str) -> str:
    """``path`` if it is an ARM resource path, else ValueError: no query, no fragment, no escape,
    no segment that walks the path (``.``, ``..``), no character a terminal or a log would not
    print as itself (a control, a bidirectional override, a zero-width one) — #358, after DG-b's
    second review. What is read is exactly the resource the id names."""
    if not isinstance(path, str) or not _ARM_PATH.fullmatch(path):
        raise ValueError(f"not an ARM resource path: {path!r}")
    if not path.isprintable():
        raise ValueError(f"an ARM resource path with a character not printable: {path!r}")
    if any(seg in (".", "..") for seg in path.split("/")):
        raise ValueError(f"an ARM resource path that walks its segments (. or ..): {path!r}")
    return path


def _id(obj) -> str:
    return str((obj or {}).get("id") or "") if isinstance(obj, dict) else ""


def governing_nsgs(resource_id: str, arm_get: Callable[[str, str], dict]) -> list[str]:
    """The ids of the security groups that govern the VM's traffic: each NIC's, each subnet's."""
    vm = arm_get(safe_path(resource_id), VM_API)
    nics = [_id(n) for n in ((vm.get("properties") or {}).get("networkProfile") or {}).get("networkInterfaces") or []]
    if not nics or not all(nics):
        raise Unreadable("the VM's network interfaces cannot be read")
    out: list[str] = []
    for nic_id in nics:
        nic = arm_get(safe_path(nic_id), NET_API)
        props = nic.get("properties") or {}
        if _id(props.get("networkSecurityGroup")):
            out.append(_id(props["networkSecurityGroup"]))
        for ipc in props.get("ipConfigurations") or []:
            subnet_id = _id((ipc.get("properties") or {}).get("subnet"))
            if not subnet_id:
                raise Unreadable(f"a configuration of {nic_id.rsplit('/', 1)[-1]} names no subnet")
            subnet = arm_get(safe_path(subnet_id), NET_API)
            sub_nsg = _id((subnet.get("properties") or {}).get("networkSecurityGroup"))
            if sub_nsg:
                out.append(sub_nsg)
    seen, unique = set(), []
    for n in out:
        if n.lower() not in seen:
            seen.add(n.lower())
            unique.append(n)
    return unique


def holding(resource_id: str, arm_get: Callable[[str, str], dict]) -> str:
    """Why Glorfindel holds the VM now — "" when nothing of it governs the VM. Anything that
    cannot be read: a reason too (A0)."""
    try:
        for nsg_id in governing_nsgs(resource_id, arm_get):
            nsg = arm_get(safe_path(nsg_id), NET_API)
            rules = [str(r.get("name") or "") for r in (nsg.get("properties") or {}).get("securityRules") or []
                     if isinstance(r, dict)]
            held = [r for r in rules if is_hold(r)]
            if held:
                return f"Glorfindel's {held[0]} in {nsg_id.rsplit('/', 1)[-1]}"
    except Exception as e:
        return f"its isolation unreadable: {e}"[:200]
    return ""
