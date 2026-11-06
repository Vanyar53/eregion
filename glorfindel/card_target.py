"""What a card of the control plane or of an identity is about (AL1c, #597) — never a VM it
has nothing to do with.

Until AL1c, a row of the Activity Log that named no VM, and every row of Entra ID's logs, was
filed on the first VM of the discovery (an anchor, ``vm-celebrimbor-bree`` on the bench): six
cards of ID1 sat on a VM none of them was about. The card is now filed on what the row names,
read in its ``_ResourceId`` and the type of the resource:

  - **an NSG, or one of its rules**: on the NSG — and shown on each VM it covers (by its subnet
    or its network interface), the VMs the discovery knows, an offline one included;
  - **a disk** (a download access): on the VM the disk is attached to, when the discovery knows
    it; **a snapshot** (its write, a download access): the row names the snapshot only, never
    its source disk — the source is read on Azure (the snapshot's ``creationData``) while the
    snapshot still exists, then the disk's VM; otherwise the group, the limit said;
  - **a role assignment**: on its scope — the VM when the scope is the VM (the RulePoller's own
    attribution), else the group;
  - **anything else**: on its resource group, or on « the control plane » when there is none.

An identity card (Entra ID) is filed on the identity — the application, the service principal,
the user the row is about (for a sign-in, the service principal that signed in) — never on a VM.

What the row and Azure could not say is written on the target (``limit``): never a guess.
Nothing here writes, nor reads Azure itself: the topology (`Topology`) is handed in, read by the
provider (``ReadersMixin.control_topology``), cached.
"""
from __future__ import annotations

import logging
import re
import threading
import time
from typing import Callable

logger = logging.getLogger("glorfindel.card_target")

CONTROL_PLANE_ID = "control-plane"
IDENTITY_PREFIX = "entra:"
# The kinds of target a card may have: a VM, an NSG, a resource group, the control plane as a
# whole, an identity.
KINDS = ("vm", "nsg", "resource_group", "control_plane", "identity")

_NSG_RE = re.compile(
    r"^(?P<nsg>.*?/providers/microsoft\.network/networksecuritygroups/(?P<name>[^/]+))"
    r"(?:/(?:default)?securityrules/(?P<rule>[^/]+))?/?$", re.IGNORECASE)
_DISK_RE = re.compile(r"^(?P<disk>.*?/providers/microsoft\.compute/disks/(?P<name>[^/]+))(?:/.*)?$",
                      re.IGNORECASE)
_SNAPSHOT_RE = re.compile(
    r"^(?P<snap>.*?/providers/microsoft\.compute/snapshots/(?P<name>[^/]+))(?:/.*)?$", re.IGNORECASE)
_ROLE_RE = re.compile(r"^(?P<scope>.*?)/providers/microsoft\.authorization/roleassignments/[^/]+/?$",
                      re.IGNORECASE)
_GROUP_RE = re.compile(r"^(?P<group>/subscriptions/(?P<sub>[^/]+)/resourcegroups/(?P<name>[^/]+))",
                       re.IGNORECASE)
_SUB_RE = re.compile(r"^/subscriptions/(?P<sub>[^/]+)", re.IGNORECASE)
_VM_RE = re.compile(r"/providers/microsoft\.compute/virtualmachines/[^/]+", re.IGNORECASE)
# What may stand in an identity's pseudo id: an object id (a GUID), never a name — a name is
# chosen by whoever registers the application.
_SAFE_ID = re.compile(r"^[A-Za-z0-9-]{1,64}$")
_SAFE_TYPE = re.compile(r"^[A-Za-z]{1,40}$")


# ── the topology: which VMs an NSG covers, which VM a disk is attached to, a snapshot's source ──

_TTL_S = 300.0
_MISS_REFRESH_S = 60.0
UNREAD = object()      # a section of the topology Azure did not answer
# What a listing that does not hold an id may mean: the watch reads only what its rights let it
# list (on H0, `Reader` on the bench's group), and a listing over the subscription is filtered by
# them — never « gone » on that alone (review, AL1c).
_GONE_OR_HIDDEN = "supprimé, ou hors des droits de la watch"


class Topology:
    """The provider's topology (``nsg_vms``, ``disk_vm``, ``snapshot_source``: lowercase ids),
    read at most every `_TTL_S`, and again on a miss at most every `_MISS_REFRESH_S` — a snapshot
    taken a minute ago is not in a listing of five minutes ago. A section that could not be read
    is None in the source's answer: `lookup` says UNREAD, never « nothing there »."""

    def __init__(self, source: Callable[[], dict]) -> None:
        self._source = source
        self._lock = threading.Lock()
        self._at = 0.0
        self._data: dict = {}

    def _read(self) -> None:
        try:
            data = self._source() or {}
        except Exception as exc:
            logger.warning("control-plane topology unreadable (%s) — keeping the last one", exc)
            data = None
        if isinstance(data, dict):
            self._data = data
        self._at = time.time()

    def lookup(self, section: str, key: str):
        """The value of `key` in `section` (lowercase) — None when Azure's listing does not hold
        it (gone, or out of reach) —, or UNREAD when the section could not be read."""
        key = (key or "").rstrip("/").lower()
        with self._lock:
            age = time.time() - self._at
            if not self._at or age >= _TTL_S:
                self._read()
            elif age >= _MISS_REFRESH_S and key not in (self._data.get(section) or {}):
                self._read()
            part = self._data.get(section)
        if part is None:
            return UNREAD
        return part.get(key)


def _lookup(topology, section: str, key: str):
    if topology is None:
        return UNREAD
    try:
        return topology.lookup(section, key)
    except Exception as exc:  # a target is never lost to a topology that raises
        logger.warning("control-plane topology: %s unreadable (%s)", section, exc)
        return UNREAD


# ── the targets ──

def _short(rid: str) -> str:
    return str(rid or "").rstrip("/").rsplit("/", 1)[-1]


def vm_target(rid: str, name: str = "", via: str = "", limit: str = "") -> dict:
    t = {"kind": "vm", "id": rid, "name": name or _short(rid)}
    if via:
        t["via"] = via
    if limit:
        t["limit"] = limit
    return t


def control_plane_target(limit: str = "") -> dict:
    t = {"kind": "control_plane", "id": CONTROL_PLANE_ID, "name": "plan de contrôle"}
    if limit:
        t["limit"] = limit
    return t


def _group_target(rid: str, row: dict, via: str = "", limit: str = "") -> dict:
    """The resource group of `rid` (or the row's ResourceGroup), else the control plane."""
    m = _GROUP_RE.match(rid or "")
    if m:
        gid, name = m.group("group"), m.group("name")
    else:
        name = str(row.get("ResourceGroup") or "").strip()
        sub = _SUB_RE.match(rid or "")
        if not name or "/" in name:
            return control_plane_target(limit=" ".join(filter(None, [
                limit, "La ligne ne nomme aucun groupe de ressources."])))
        gid = f"/subscriptions/{sub.group('sub')}/resourceGroups/{name}" if sub else f"resourceGroups/{name}"
    t = {"kind": "resource_group", "id": gid, "name": name}
    if via:
        t["via"] = via
    if limit:
        t["limit"] = limit
    return t


def _known(targets) -> dict[str, tuple[str, str]]:
    return {str(rid).rstrip("/").lower(): (rid, name) for rid, name in (targets or []) if rid}


def _nsg(m, row: dict, known: dict, topology) -> dict:
    """On the NSG, with the VMs it covers that the discovery knows (an offline one included):
    the console shows the card on each of them, one card."""
    nsg_id, name, rule = m.group("nsg"), m.group("name"), m.group("rule") or ""
    covered = _lookup(topology, "nsg_vms", nsg_id)
    t = {"kind": "nsg", "id": nsg_id, "name": name, "vms": [], "vm_names": []}
    if rule:
        t["via"] = f"règle {rule}"
    if covered is UNREAD:
        t["limit"] = "Les VM que ce NSG couvre n'ont pas pu être lues sur Azure."
        return t
    if covered is None:
        t["limit"] = (f"Ce NSG n'est pas dans la liste lue sur Azure ({_GONE_OR_HIDDEN}) : "
                      "les VM qu'il couvre ne sont pas dites.")
        return t
    unknown = 0
    for vm in sorted({str(v).rstrip("/").lower() for v in covered or []}):
        if vm in known:
            t["vms"].append(known[vm][0])
            t["vm_names"].append(known[vm][1])
        else:
            unknown += 1
    said = []
    if not t["vms"]:
        said.append("Aucune VM connue de la découverte n'a été lue sous ce NSG "
                    "(cartes réseau lisibles par la watch).")
    if unknown:
        said.append(f"Sous ce NSG, {unknown} VM lue(s) sur Azure que la découverte ne connaît pas.")
    if said:
        t["limit"] = " ".join(said)
    return t


def _disk_vm(disk_id: str, known: dict, topology):
    """(the VM of the disk known to the discovery, or None; what could not be said)."""
    vm = _lookup(topology, "disk_vm", disk_id)
    if vm is UNREAD:
        return None, "Le rattachement du disque à une VM n'a pas pu être lu sur Azure."
    if vm is None:
        return None, f"Le disque n'est pas dans la liste lue sur Azure ({_GONE_OR_HIDDEN})."
    vm = str(vm or "").rstrip("/").lower()
    if not vm:
        return None, "Le disque n'est attaché à aucune VM."
    if vm not in known:
        return None, f"Le disque est attaché à {_short(vm)}, que la découverte ne connaît pas."
    return known[vm], ""


def control_target(row: dict, targets=(), topology=None) -> dict:
    """The target of one Activity Log row that names no VM the RulePoller routed it to."""
    row = row if isinstance(row, dict) else {}
    if row.get("OmittedOperations"):
        return control_plane_target(
            limit="Carte de synthèse : chacune de ses opérations nomme sa propre ressource.")
    rid = str(row.get("_ResourceId") or row.get("ResourceId") or "").strip()
    known = _known(targets)
    m = _NSG_RE.match(rid)
    if m:
        return _nsg(m, row, known, topology)
    m = _DISK_RE.match(rid)
    if m:
        vm, limit = _disk_vm(m.group("disk"), known, topology)
        if vm:
            return vm_target(vm[0], vm[1], via=f"disque {m.group('name')}")
        return _group_target(rid, row, via=f"disque {m.group('name')}", limit=limit)
    m = _SNAPSHOT_RE.match(rid)
    if m:
        via = f"instantané {m.group('name')}"
        said = "La ligne ne nomme pas le disque source de l'instantané."
        src = _lookup(topology, "snapshot_source", m.group("snap"))
        if src is UNREAD or not src:
            return _group_target(rid, row, via=via, limit=said + (
                " Les instantanés n'ont pas pu être lus sur Azure." if src is UNREAD else
                f" L'instantané n'est pas dans la liste lue sur Azure ({_GONE_OR_HIDDEN}) : sa source "
                "n'a pas pu être lue."
                if src is None else " Azure ne donne pas sa source."))
        disk = _DISK_RE.match(str(src))
        if not disk:
            return _group_target(rid, row, via=via, limit=said + f" Sa source, {_short(src)}, n'est pas un disque.")
        vm, limit = _disk_vm(disk.group("disk"), known, topology)
        if vm:
            return vm_target(vm[0], vm[1], via=f"{via}, du disque {disk.group('name')}",
                             limit=said + " Sa source a été lue sur Azure.")
        return _group_target(rid, row, via=f"{via}, du disque {disk.group('name')}", limit=f"{said} {limit}")
    m = _ROLE_RE.match(rid)
    if m:
        scope = m.group("scope") or "/"
        via = f"attribution de rôle, portée {_short(scope) or '/'}"
        if _VM_RE.search(scope):
            # On a VM the RulePoller did not route the row to (not in the discovery): its group.
            return _group_target(scope, row, via=via, limit="La VM de la portée n'est pas dans la découverte.")
        if _GROUP_RE.match(scope):
            return _group_target(scope, row, via=via)
        return control_plane_target(limit="La portée de l'attribution n'est pas un groupe de ressources "
                                          "(l'abonnement, un groupe d'administration).")
    if _VM_RE.search(rid):
        # A VM the RulePoller did not route the row to: never filed on it as if it were known.
        return _group_target(rid, row, via=_short(rid),
                             limit="La VM nommée n'est pas dans la découverte.")
    return _group_target(rid, row, via=_short(rid) if rid else "")


def identity_target(row: dict) -> dict:
    """The identity an Entra ID row is about: its target (an application, a service principal,
    a user, a group), or for a sign-in the service principal that signed in. Its pseudo id
    carries the object id only, never a name."""
    row = row if isinstance(row, dict) else {}
    if row.get("OmittedOperations"):
        return {"kind": "identity", "id": f"{IDENTITY_PREFIX}several", "name": "plusieurs identités",
                "limit": "Carte de synthèse : chacune de ses opérations nomme sa propre identité."}
    signin = str(row.get("EntraKind") or "").strip().lower() == "signin"
    cols = ("ActorId", "ActorName", None) if signin else ("TargetId", "TargetName", "TargetType")
    oid = str(row.get(cols[0]) or "").strip()
    name = str(row.get(cols[1]) or "").strip()
    ttype = "ServicePrincipal" if signin else str(row.get(cols[2]) or "").strip()
    if not _SAFE_TYPE.match(ttype):
        ttype = "identity"
    t = {"kind": "identity", "identity_type": ttype, "name": name or oid or "?",
         "object_id": oid if _SAFE_ID.match(oid) else ""}
    t["id"] = f"{IDENTITY_PREFIX}{ttype.lower()}:{t['object_id'] or 'unread'}"
    if not t["object_id"]:
        t["limit"] = "La ligne ne donne pas l'identifiant de l'identité."
    return t


def of_row(row: dict, plane: str, tgt=None, targets=(), topology=None) -> dict:
    """The card's target for a row of the control plane or of an identity: the VM the RulePoller
    routed it to (`tgt`, the row names it), else what the row names."""
    if plane == "identity":
        return identity_target(row)
    if tgt is not None:
        return vm_target(tgt[0], tgt[1])
    return control_target(row, targets, topology)


def is_identity_id(rid: str) -> bool:
    return str(rid or "").startswith(IDENTITY_PREFIX)
