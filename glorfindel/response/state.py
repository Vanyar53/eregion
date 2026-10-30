"""Local state of the response: one file per VM under ~/.glorfindel/isolation and
~/.glorfindel/blocks, written atomically, keyed by name and resource id (moved from
actions.py, A1). Tests redirect both directories (conftest), through glorfindel.actions.
"""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

from glorfindel.response.ids import _same_id
from glorfindel.response.policy import _console


_ISOLATION_STATE_DIR = Path.home() / ".glorfindel" / "isolation"

_UNKNOWN = object()


class StateUnreadable(RuntimeError):
    """An isolation state can't be read: what it holds is unknown, never "nothing" (SEC4b)."""


def _unreadable_isolations() -> list[str]:
    """The isolation state files that can't be read (`unreadable_states`, isolations only)."""
    return [f for f in unreadable_states() if f.startswith(f"{_ISOLATION_STATE_DIR.name}/")]


def _raise_if_unreadable(what: str) -> None:
    unread = _unreadable_isolations()
    if unread:
        more = f" (+{len(unread) - 3})" if len(unread) > 3 else ""
        raise StateUnreadable(
            f"état local illisible ({', '.join(unread[:3])}{more}) : {what} — le réparer ou le "
            "retirer à la main, puis relancer")


def _quarantine_placements(nic_id: str) -> list[dict]:
    """This NIC's quarantine placements in every readable isolation state."""
    return [p for iso in active_isolations() for p in iso.get("placements") or []
            if p.get("kind") == "quarantine" and _same_id(p.get("nic_id") or "", nic_id)]


def _recorded_original(nic_id: str):
    """The original NSG recorded in local state for this NIC (None = it had none), or
    _UNKNOWN when no state records it. None readable records it while a state can't be
    read: StateUnreadable — that one may, and our tag read in its place could undo the
    original it records (SEC4b)."""
    for p in _quarantine_placements(nic_id):
        if "original_nsg_id" in p:
            return p["original_nsg_id"]
    _raise_if_unreadable(f"le NSG d'origine de {nic_id.rstrip('/').rsplit('/', 1)[-1]} y est peut-être")
    return _UNKNOWN


def _held_in_quarantine(nic_id: str) -> bool:
    """A local state records this NIC in our quarantine — its original known or not.
    Not known there (lost with the tags, Q7), it is an unknown: never "none" (I8F). None
    readable records it while a state can't be read: StateUnreadable, never "no" (SEC4b)."""
    if _quarantine_placements(nic_id):
        return True
    _raise_if_unreadable(f"{nic_id.rstrip('/').rsplit('/', 1)[-1]} y est peut-être en quarantaine")
    return False


def _recorded_or_unknown(nic_id: str):
    """For an isolation: unknown while a state can't be read — it never stops one (SEC4b);
    left unwritten, the release keeps the NIC in quarantine until it is known."""
    try:
        return _recorded_original(nic_id)
    except StateUnreadable:
        return _UNKNOWN


def _held_or_unreadable(nic_id: str) -> bool:
    """For an isolation: held in quarantine by a state, or a state can't be read (SEC4b)."""
    try:
        return _held_in_quarantine(nic_id)
    except StateUnreadable:
        return True


_BLOCK_STATE_DIR = Path.home() / ".glorfindel" / "blocks"


def _atomic_write_text(path: Path, text: str, mode: int = 0o600) -> None:
    """Write through a temp file + os.replace.

    A reader (War Room, a concurrent CLI, the watch) never sees a half-written state
    file, and a crash mid-write leaves the previous version intact instead of a
    truncated JSON that would break the next release.

    Readable by its owner only (SEC3, V-27): 0600, its directory made 0700 — the watch,
    the console, the bot and the CLI run as the operator; nothing else reads it. `mode`:
    what is written for others to read (the injectors' heartbeat), its directory 0755.
    """
    path.parent.mkdir(mode=0o755 if mode & 0o044 else 0o700, parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(text)
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _vm_ref(ref: str) -> tuple[str, str]:
    """(VM name, resource id) from a short name or a full resource id."""
    if "/" in (ref or ""):
        return ref.rstrip("/").split("/")[-1], ref
    return ref, ""


def _rid_hash(resource_id: str) -> str:
    import hashlib
    return hashlib.sha1(resource_id.rstrip("/").lower().encode()).hexdigest()[:8]


def _file_rid(f: Path) -> str:
    """The resource id a state file belongs to ("" if unreadable or not recorded)."""
    try:
        data = json.loads(f.read_text())
    except Exception:
        return ""
    if isinstance(data, list):
        data = data[0] if data else {}
    return str((data or {}).get("resource_id") or "").rstrip("/").lower()


def _hash_variants(directory: Path, rid: str) -> list[Path]:
    """Every `*--<hash>.json` of this resource id, whatever the case of its name part
    (the hash itself ignores case). Newest first."""
    if not directory.exists():
        return []
    files = [f for f in directory.glob(f"*--{_rid_hash(rid)}.json")
             if _file_rid(f) in ("", rid.rstrip("/").lower())]
    return sorted(files, key=lambda f: f.stat().st_mtime, reverse=True)


def _state_file(directory: Path, ref: str) -> Path | None:
    """The state file of a VM, keyed `<name in lowercase>--<hash of its resource id>.json`.

    Keyed by name only, two VMs with the same name in two resource groups shared one
    file (third review). The name part is lowercase (fourth review, Q9), and a file is
    found by its HASH whatever the case of its name — a mixed-case file of an earlier
    version stayed invisible to lowercase ids (fifth review, C2). A legacy `<name>.json`
    is used only when it belongs to that resource id; by name alone, an ambiguous name
    resolves to nothing."""
    name, rid = _vm_ref(ref)
    legacy = directory / f"{name}.json"
    if rid:
        target = directory / f"{name.lower()}--{_rid_hash(rid)}.json"
        if target.exists():
            return target
        variants = _hash_variants(directory, rid)
        if variants:
            return variants[0]
        if legacy.exists() and _file_rid(legacy) in ("", rid.rstrip("/").lower()):
            return legacy
        return None
    if legacy.exists():
        return legacy
    if not directory.exists():
        return None
    keyed = sorted({f for f in directory.glob("*--*.json")
                    if _file_rid(f).rsplit("/", 1)[-1] == name.lower()})
    return keyed[0] if len(keyed) == 1 else None


def _same_file(a: Path, b: Path) -> bool:
    try:
        return a.samefile(b)
    except OSError:
        return False


def _write_state(directory: Path, ref: str, rid: str, payload) -> None:
    """Write under the keyed name, then remove this VM's OTHER files (plain name, other
    cases of the name part). Never one that IS the target: on a case-insensitive file
    system (macOS, Windows, Docker Desktop mounts) `VM-Foo--h.json` and `vm-foo--h.json`
    are the same file — removing the "old" one deleted the state just written (fifth
    review, C1)."""
    name, ref_rid = _vm_ref(ref)
    rid = rid or ref_rid
    if not rid:
        _atomic_write_text(directory / f"{name}.json", json.dumps(payload))
        return
    target = directory / f"{name.lower()}--{_rid_hash(rid)}.json"
    olds = [old for old in [directory / f"{name}.json", *_hash_variants(directory, rid)]
            if old.name != target.name and old.exists() and not _same_file(old, target)
            and _file_rid(old) in ("", rid.rstrip("/").lower())]
    if olds and not target.exists():
        # Moved first (one atomic rename), then rewritten: a crash between writing the
        # new file and removing the old one left two — a lookup by name read the old
        # one (A0, an older version's state in the invariant machine).
        os.replace(olds.pop(0), target)
    _atomic_write_text(target, json.dumps(payload))
    for old in olds:
        old.unlink()


def _owner_only(directory: Path) -> None:
    """A state directory of an earlier version, and its files, made owner-only (0700 /
    0600, SEC3 V-27). One that isn't ours to change (root's, from the old image: `make
    fix-state-ownership`) is left as it is."""
    for path, mode in [(directory, 0o700), *((f, 0o600) for f in directory.glob("*.json"))]:
        try:
            os.chmod(path, mode)
        except OSError:
            pass


def migrate_state_files() -> int:
    """At start-up: every state file under its lowercase keyed name, one per VM (the
    newest wins). A mixed-case file left by #41's version, or a plain `<name>.json`,
    would otherwise stay invisible to lowercase ids — or come back to life once the
    lowercase file is cleared (fifth review, C2). Returns the files moved or removed."""
    changed = 0
    for directory in (_ISOLATION_STATE_DIR, _BLOCK_STATE_DIR):
        if not directory.exists():
            continue
        _owner_only(directory)
        seen: set[str] = set()
        for f in sorted(directory.glob("*.json"), key=lambda f: f.stat().st_mtime, reverse=True):
            rid = _file_rid(f)
            if not rid or rid in seen or not f.exists():
                continue
            seen.add(rid)
            name = rid.rsplit("/", 1)[-1]
            target = directory / f"{name.lower()}--{_rid_hash(rid)}.json"
            if f.name != target.name and not _same_file(f, target):
                _atomic_write_text(target, f.read_text())
                f.unlink()
                changed += 1
            for other in _hash_variants(directory, rid) + [directory / f"{name}.json"]:
                # Only a file that IS this VM's: the plain `<name>.json` of a homonym in
                # another group was deleted here, its isolation gone from the list, the
                # reassertion, the TTL and the War Room (sixth review, S3). A legacy file
                # without a recorded id stays: whose it is can't be told.
                if (other.exists() and other.name != target.name and not _same_file(other, target)
                        and _file_rid(other) == rid):
                    other.unlink()
                    changed += 1
    return changed


def _save_isolation_state(vm_ref: str, state: dict) -> None:
    rid = str(state.get("resource_id") or "")
    _set_aside_unreadable(rid or vm_ref)
    _write_state(_ISOLATION_STATE_DIR, vm_ref, rid, state)


ASIDE_DIR = "aside"


def _set_aside_unreadable(vm_ref: str) -> None:
    """This VM's unreadable state moved to `isolation/aside/` before a new one is written
    (SEC4b): never written over, never a state again (out of the states' `*.json`), listed
    by `unreadable_states` until the operator removes it."""
    if not _isolation_unreadable(vm_ref):
        return
    f = _state_file(_ISOLATION_STATE_DIR, vm_ref)
    (_ISOLATION_STATE_DIR / ASIDE_DIR).mkdir(mode=0o700, exist_ok=True)
    n, aside = 1, _ISOLATION_STATE_DIR / ASIDE_DIR / f.name
    while aside.exists():
        n += 1
        aside = _ISOLATION_STATE_DIR / ASIDE_DIR / f"{f.stem}-{n}.json"
    os.replace(f, aside)


def _load_isolation_state(vm_ref: str) -> dict | None:
    """The recorded isolation, or None if absent or unreadable.

    An unreadable file is reported, not raised: release_isolation then recomputes the
    rule names on every NIC (they are deterministic), so a corrupt file can no longer
    make an isolation impossible to lift from the CLI. A NIC in our quarantine waits for
    it: the original it may record is unknown (`_recorded_original`, SEC4b).
    """
    f = _state_file(_ISOLATION_STATE_DIR, vm_ref)
    if f is None:
        return None
    try:
        data = json.loads(f.read_text())
        if not _readable_shape(data, dict):
            raise ValueError("pas la forme d'un état d'isolation")
        return data
    except (OSError, ValueError) as e:
        _console.print(
            f"[yellow]État d'isolation illisible pour {_vm_ref(vm_ref)[0]} ({e}) — règles cherchées par leur "
            "nom sur chaque carte de la VM ; une carte en quarantaine, ou la VM supprimée (ses cartes "
            "inconnues), attend qu'il soit réparé ou retiré.[/yellow]"
        )
        return None


def _isolation_unreadable(vm_ref: str) -> bool:
    """This VM's isolation state file is there and can't be read (SEC4b)."""
    f = _state_file(_ISOLATION_STATE_DIR, vm_ref)
    return f is not None and f"{_ISOLATION_STATE_DIR.name}/{f.name}" in unreadable_states()


def _clear_isolation_state(vm_ref: str) -> None:
    f = _state_file(_ISOLATION_STATE_DIR, vm_ref)
    if f is not None and f.exists():
        f.unlink()


def unreadable_states() -> list[str]:
    """The isolation and block state files that can't be read: unparsable, an I/O error,
    or not the shape Glorfindel writes (an object per isolation, a list of entries per
    block file). What such a file holds is unknown — never "nothing": a reader that
    decides on the absence of a state (the orphan sweep) does nothing while one is listed
    (SEC3, N-06). `<directory>/<file>`, sorted."""
    out = []
    for directory, shape in ((_ISOLATION_STATE_DIR, dict), (_BLOCK_STATE_DIR, list)):
        if not directory.exists():
            continue
        for f in directory.glob("*.json"):
            try:
                data = json.loads(f.read_text())
            except (OSError, ValueError):
                data = None
            if not _readable_shape(data, shape):
                out.append(f"{directory.name}/{f.name}")
    # Set aside (SEC4b): listed while it exists, readable or not — to report by hand into
    # the current state, never a state of its own again.
    aside = _ISOLATION_STATE_DIR / ASIDE_DIR
    if aside.is_dir():
        out += [f"{_ISOLATION_STATE_DIR.name}/{ASIDE_DIR}/{f.name}" for f in aside.iterdir() if f.is_file()]
    return sorted(out)


def _readable_shape(data, shape) -> bool:
    """The shape Glorfindel writes: an object per isolation whose placements, when it has
    some, are a list of objects, beside its resource id — a non-empty string, written with
    every state since placements exist (#8, 06/19); only an older single-NSG state may
    lack it (SEC4b). A list of objects per block file."""
    if shape is list:
        return isinstance(data, list) and all(isinstance(e, dict) for e in data)
    if not isinstance(data, dict):
        return False
    if "placements" not in data:
        return True
    placements, rid = data["placements"], data.get("resource_id")
    return (isinstance(rid, str) and bool(rid.strip()) and isinstance(placements, list)
            and all(isinstance(p, dict) for p in placements))


def active_isolations() -> list[dict]:
    """Return all active isolation state files (VMs that Glorfindel has isolated). An
    unreadable one is left out — `unreadable_states` lists it, for the readers (SEC4b)."""
    result = []
    for f in _ISOLATION_STATE_DIR.glob("*.json"):
        try:
            state = json.loads(f.read_text())
        except (OSError, ValueError):
            continue
        rid = state.get("resource_id") if _readable_shape(state, dict) else None
        if rid and isinstance(rid, str):
            result.append({**state, "vm_name": rid.rstrip("/").rsplit("/", 1)[-1], "state_key": f.stem})
    return result


def _previous_placements(resource_id: str) -> list[dict]:
    return list((_load_isolation_state(resource_id) or {}).get("placements") or [])


def _isolation_placement_key(p: dict) -> tuple:
    if p.get("kind") == "quarantine":
        return ("quarantine", (p.get("nic_id") or "").rstrip("/").lower())
    return ("rules", (p.get("nsg_rg") or "").lower(), (p.get("nsg_name") or "").lower(),
            (p.get("rule_in") or "").lower())


def _merge_isolation_placements(old: list[dict], new: list[dict]) -> list[dict]:
    """A re-isolation's placements, plus the earlier ones it didn't redo: a deny left
    on another NSG, under an older name, or on a NIC the new attempt didn't reach is
    still on Azure — release must know it."""
    keys = {_isolation_placement_key(p) for p in new}
    return new + [p for p in old if _isolation_placement_key(p) not in keys]


def _merge_placements(old: list[dict], new: list[dict]) -> list[dict]:
    """Union of block placements, keyed by (NSG, rule) — a re-block after a partial
    failure must keep track of the rules of BOTH attempts."""
    seen = {(p.get("nsg_rg"), p.get("nsg_name"), p.get("rule")) for p in new}
    return new + [p for p in old if (p.get("nsg_rg"), p.get("nsg_name"), p.get("rule")) not in seen]


def _save_block_state(
    vm_name: str, ip: str, resource_id: str,
    nsg: str = "", nsg_scope: str = "", rule: str = "", scoped: bool = True,
    placements: list | None = None, partial: bool = False, threat_port: int | None = None,
) -> None:
    from datetime import datetime, timezone
    entries = _load_block_entries(resource_id or vm_name)
    prev = next((e for e in entries if e.get("ip") == ip), None)
    if prev is None:
        # Record the NSG + scope so the representation matches Azure reality:
        # nsg_scope="subnet" → rule lives on a shared subnet NSG, "nic" → on the VM NIC.
        # scoped=True → rule only affects THIS VM (NIC, or subnet+VM-IP addressing);
        # False would be a subnet-wide `any` rule → War Room shows the ⚠ blast-radius chip.
        # placements[] → one rule per NIC (multi-NIC VM block); nsg/rule mirror the first
        # placement for /api/state + legacy display.
        entries.append({
            "ip": ip, "resource_id": resource_id,
            "blocked_at": datetime.now(timezone.utc).isoformat(),
            "nsg": nsg, "nsg_scope": nsg_scope, "rule": rule, "scoped": scoped,
            "placements": placements or [],
            "partial": partial,
            "threat_port": threat_port,
        })
    else:
        # The IP already recorded (a retry, another scope): merged, every rule known to unblock.
        # Written whole, it supersedes a failed or cut-off unblock: its marks go (L1B, #355).
        if not scoped:
            prev.update(nsg=nsg, nsg_scope=nsg_scope, rule=rule, scoped=False)
        prev["placements"] = _merge_placements(prev.get("placements") or [], placements or [])
        prev["partial"] = partial
        for mark in () if partial else ("unblock_failed", "unblocking_at", "stale_alerted_at"):
            prev.pop(mark, None)
        if threat_port is not None:
            prev["threat_port"] = threat_port
    _write_state(_BLOCK_STATE_DIR, vm_name, resource_id, entries)


def _load_block_entries(vm_ref: str) -> list[dict]:
    """Return the recorded block entries for a VM (empty if none). `vm_ref`: a short
    name or a full resource id (see _state_file)."""
    f = _state_file(_BLOCK_STATE_DIR, vm_ref)
    if f is None:
        return []
    try:
        return json.loads(f.read_text())
    except Exception:
        return []


def _clear_block_state(vm_ref: str, ip: str) -> None:
    f = _state_file(_BLOCK_STATE_DIR, vm_ref)
    if f is None:
        return
    entries = [e for e in _load_block_entries(vm_ref) if e.get("ip") != ip]
    if entries:
        _atomic_write_text(f, json.dumps(entries))
    else:
        f.unlink()


def _update_block_entry(vm_ref: str, ip: str, **fields) -> None:
    """Annotate an existing block entry (e.g. the rules an unblock could not remove)."""
    f = _state_file(_BLOCK_STATE_DIR, vm_ref)
    if f is None:
        return
    entries = _load_block_entries(vm_ref)
    for e in entries:
        if e.get("ip") == ip:
            e.update(fields)
    if entries:
        _atomic_write_text(f, json.dumps(entries))


def active_blocks() -> list[dict]:
    """Return all active IP blocks per VM ({vm_name, resource_id, ip, blocked_at})."""
    result = []
    if not _BLOCK_STATE_DIR.exists():
        return result
    for f in _BLOCK_STATE_DIR.glob("*.json"):
        try:
            for entry in json.loads(f.read_text()):
                vm = (entry.get("resource_id") or "").rstrip("/").rsplit("/", 1)[-1] or f.stem
                result.append({**entry, "vm_name": vm, "state_key": f.stem})
        except Exception:
            pass
    return result
