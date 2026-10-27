"""The console's sections: which ones are active on this host, and why.

Glorfindel is the product: always active, even before it is configured — its page then says
what is missing. Annatar and Gothmog require it and are added to it (decision of 26/10): one
is active once this host holds one of its runs — an exercise window, a run report, a
campaign — else its tab is greyed and leads to what it would add. ``EREGION_CONSOLE_SECTIONS``
(``eregion console --sections``) fixes the active injectors instead: the listed ones are
active even without a run, the others greyed; Glorfindel cannot be removed.
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path

GLORFINDEL = "glorfindel"
INJECTORS = ("annatar", "gothmog")
SECTIONS = (
    {"id": GLORFINDEL, "label": "Glorfindel", "role": "what it detects and does on real traffic"},
    {"id": "annatar", "label": "Annatar", "role": "attacks run against Glorfindel"},
    {"id": "gothmog", "label": "Gothmog", "role": "faults run against Glorfindel and your infrastructure"},
)
ENV = "EREGION_CONSOLE_SECTIONS"
_TTL_S = 10.0
_cache: dict = {"at": 0.0, "key": None, "value": None}


def override() -> set[str] | None:
    """The injectors ``EREGION_CONSOLE_SECTIONS`` makes active, or None when it is unset or
    empty (detection then decides). ``glorfindel`` may be listed — it is always active. An
    unknown name raises ValueError: a section asked for and silently absent would hide a
    page the operator expects."""
    raw = os.environ.get(ENV, "").strip()
    if not raw:
        return None
    names = {n.strip().lower() for n in raw.split(",") if n.strip()}
    unknown = names - {GLORFINDEL, *INJECTORS}
    if unknown:
        raise ValueError(f"{ENV}: unknown section(s) {', '.join(sorted(unknown))} — "
                         f"choose among {', '.join(INJECTORS)} (glorfindel is always on)")
    return names - {GLORFINDEL}


def _json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def found_runs(runs: Path) -> dict[str, dict[str, int]]:
    """What this host holds of each injector: exercise windows (a purged window's tombstone
    names no injector and counts for none), run reports (Gothmog's say so in
    ``metrics.injector``; any other is Annatar's) and campaigns (Annatar's)."""
    from eregion_core.exercise import exercises_dir
    found = {i: {"windows": 0, "reports": 0, "campaigns": 0} for i in INJECTORS}
    directory = exercises_dir(runs)
    for path in directory.glob("*.json") if directory.is_dir() else []:
        w = _json(path)
        if isinstance(w, dict) and w.get("injector") in found:
            found[w["injector"]]["windows"] += 1
    for path in [*runs.glob("*.json"), *runs.glob("campaigns/*/runs/*.json")]:
        r = _json(path)
        if not isinstance(r, dict) or not isinstance(r.get("metrics"), dict):
            continue
        found["gothmog" if r["metrics"].get("injector") == "gothmog" else "annatar"]["reports"] += 1
    found["annatar"]["campaigns"] = sum(1 for _ in runs.glob("campaigns/*/manifest.json"))
    return found


def glorfindel_setup() -> dict:
    """Whether Glorfindel has started on this host: a configuration, a watch heartbeat."""
    from glorfindel.config import _DEFAULT_PATHS
    config = next((str(p) for p in _DEFAULT_PATHS if p.is_file()), "")
    heartbeat = (Path.home() / ".glorfindel" / "watch_heartbeat").is_file()
    return {"configured": bool(config or heartbeat), "config": config, "heartbeat": heartbeat}


def version() -> dict:
    """What this console runs: the reference H0 deployed (``EREGION_REF``, ``EREGION_REVISION``,
    passed by deploy.sh at the image's build), else the commit of the checkout it runs from
    (local), and the package's version. ``label`` is what the header shows: the tag when one
    was deployed, else the package's version and the short commit."""
    if _version_cache:
        return _version_cache
    import os
    from importlib.metadata import PackageNotFoundError, version as pkg_version
    try:
        package = pkg_version("eregion")
    except PackageNotFoundError:
        package = ""
    ref, revision = os.environ.get("EREGION_REF", ""), os.environ.get("EREGION_REVISION", "")
    source = "deployed" if revision else ""
    if not revision:
        revision = checkout_revision()
        source = "checkout" if revision else ""
    if ref and not ref.startswith("v"):
        ref = ""                       # a commit deployed: its short form says it already
    label = ref or (f"v{package}" if package else "") + (f" · {revision[:7]}" if revision else "")
    _version_cache.update(package=package, ref=ref, revision=revision, source=source,
                          label=label.strip(" ·") or "unknown version")
    return _version_cache


_version_cache: dict = {}


def checkout_revision() -> str:
    """The commit of the git checkout this console runs from (a local console), else ''."""
    import subprocess
    root = Path(__file__).resolve().parents[1]
    if not (root / ".git").exists():
        return ""
    try:
        return subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, capture_output=True,
                              text=True, timeout=3).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return ""


def status(runs: Path) -> dict:
    """Every section, active or greyed, and why — cached a few seconds: three pages poll it."""
    forced = override()
    key = (str(runs.resolve()), os.environ.get(ENV, ""))
    now = time.monotonic()
    if _cache["key"] == key and now - _cache["at"] < _TTL_S:
        return _cache["value"]
    found = found_runs(runs)
    sections = []
    for s in SECTIONS:
        if s["id"] == GLORFINDEL:
            sections.append({**s, "active": True, "always": True, "setup": glorfindel_setup()})
            continue
        held = found[s["id"]]
        has_runs = any(held.values())
        if forced is not None:
            active = s["id"] in forced
            why = "listed in --sections" if active else "not listed in --sections"
        else:
            active = has_runs
            why = "runs on this host" if active else "no run, window or campaign on this host"
        sections.append({**s, "active": active, "always": False, "found": held, "why": why})
    value = {"sections": sections, "override": sorted(forced) if forced is not None else None}
    _cache.update(at=now, key=key, value=value)
    return value
