"""The channel that carries exercise windows (B2) from the injectors' host (Orodruin) to a
watch on another host (Glorfindel hosted, H0) — O1, part C.

A blob container, reached by managed identity only (no shared key): Orodruin's identity
writes, the watch's identity reads. ``EREGION_EXERCISE_CHANNEL`` is the container's URL
(``https://<account>.blob.core.windows.net/exercises``); unset or empty, nothing is
published or pulled and the windows stay local, as before.

Both directions fail toward ``real``: a window that doesn't reach the watch leaves its
cycles labelled real — the label never lowers a guard (eregion_core/exercise.py). So a
failure here is reported, never raised into a run or a cycle.

The same container carries a finished campaign to H0, where its report is written (IA0,
#167; analysis/hosted_report.py): its manifest and the report of each of its runs, under
``campaigns/<campaign_id>/`` — nothing else, and no right more than the windows' (one
assignment, on this container: eregion_core/orodruin.py). The prefix keeps them out of the
windows: a run's window is ``<run_id>.json`` at the root, and a name with a ``/`` never
matches ``_SAFE_NAME``, so ``pull`` leaves the campaigns to ``pull_campaigns``.
"""
from __future__ import annotations

import os
import re
import threading
import time
import xml.etree.ElementTree as ET
from datetime import datetime
from email.utils import parsedate_to_datetime
from pathlib import Path

CHANNEL_ENV = "EREGION_EXERCISE_CHANNEL"
STORAGE = "https://storage.azure.com/.default"
API_VERSION = "2021-08-06"
# A blob becomes a local file: only a plain run_id name, never a path.
_SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*\.json$")
PULL_EVERY_S = 30.0
# A campaign's blobs: ``campaigns/<campaign_id>/manifest.json`` and
# ``campaigns/<campaign_id>/runs/<run_id>.json`` — each part a plain name, never a path.
CAMPAIGNS = "campaigns"
_SAFE_PART = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
_CAMPAIGN_BLOB = re.compile(
    r"^campaigns/(?P<cid>[A-Za-z0-9][A-Za-z0-9_.-]*)/"
    r"(?:manifest\.json|runs/(?P<rid>[A-Za-z0-9][A-Za-z0-9_.-]*)\.json)$")
# The files of a run that go to H0: its report only — never its _debug.jsonl (the watch's,
# written on H0) nor its _signals.jsonl.
_RUN_FILES = ("{run_id}.json",)
# Beside a manifest pulled from the channel: H0 writes the report of these campaigns only,
# never of a campaign of its own runs directory (analysis/hosted_report.py).
PULLED = ".pulled"

_last_pull = 0.0
_pull_lock = threading.Lock()
_credential = None


def channel_url() -> str:
    return (os.environ.get(CHANNEL_ENV) or "").strip().rstrip("/")


def auth_headers(credential) -> dict:
    """Storage, by managed identity — shared with the return channel (watch_channel.py)."""
    global _credential
    if credential is None:
        if _credential is None:
            from azure.identity import DefaultAzureCredential
            _credential = DefaultAzureCredential()
        credential = _credential
    return {"Authorization": f"Bearer {credential.get_token(STORAGE).token}",
            "x-ms-version": API_VERSION}


def publish(window: dict, *, channel: str | None = None, credential=None, put=None) -> bool:
    """Write the window as ``<run_id>.json``. False when no channel is configured."""
    import json
    import requests

    url = channel if channel is not None else channel_url()
    if not url:
        return False
    name = f"{window['run_id']}.json"
    if not _SAFE_NAME.match(name):
        raise ValueError(f"unsafe window name: {name!r}")
    headers = {**auth_headers(credential), "x-ms-blob-type": "BlockBlob",
               "Content-Type": "application/json"}
    r = (put or requests.put)(f"{url}/{name}", headers=headers,
                              data=json.dumps(window, indent=2).encode(), timeout=15)
    if not r.ok:
        raise RuntimeError(f"HTTP {r.status_code} publishing {name}")
    return True


def pull(directory: Path, *, channel: str | None = None, credential=None, get=None) -> int:
    """Copy into ``directory`` every window of the channel that is new or changed since the
    local copy, page after page of the listing. Returns how many were written."""
    import requests

    url = channel if channel is not None else channel_url()
    if not url:
        return 0
    get = get or requests.get
    headers = auth_headers(credential)
    directory.mkdir(parents=True, exist_ok=True)
    written = 0
    for blob in _blobs(get, url, headers):
        name = blob.findtext("Name") or ""
        if not _SAFE_NAME.match(name):  # a campaign's blob (a ``/``) or a path: never a window
            continue
        modified = blob.findtext("Properties/Last-Modified")
        local = directory / name
        if local.exists() and modified:
            remote_ts = parsedate_to_datetime(modified).timestamp()
            if remote_ts <= local.stat().st_mtime:
                continue
        body = get(f"{url}/{name}", headers=headers, timeout=15)
        if not body.ok:
            continue
        tmp = local.with_suffix(".json.tmp")
        tmp.write_bytes(body.content)
        tmp.replace(local)  # atomic: the watch never reads half a window
        written += 1
    return written


def pull_if_due(directory: Path, *, now: float | None = None) -> None:
    """``pull`` at most every PULL_EVERY_S — load_windows runs on every cycle, and on the
    return channel's thread (eregion_core/watch_channel.py): one pull at a time."""
    global _last_pull
    if not channel_url():
        return
    now = time.monotonic() if now is None else now
    if now - _last_pull < PULL_EVERY_S or not _pull_lock.acquire(blocking=False):
        return
    try:
        _last_pull = now
        pull(directory)
    except Exception as e:  # the local windows still count; the rest falls toward real
        print(f"[exercise-channel] pull failed at {datetime.now():%H:%M:%S}: {e}")
    finally:
        _pull_lock.release()


def pull_now(directory: Path, **kw) -> int:
    """``pull`` now, whatever PULL_EVERY_S, under the lock ``pull_if_due`` takes: two pulls
    never write the same window at once. For the campaign report, which needs the last
    window, closed just before its campaign ended (analysis/hosted_report.py)."""
    if not _pull_lock.acquire(timeout=60):
        raise RuntimeError("another pull of the windows is still running")
    try:
        return pull(directory, **kw)
    finally:
        _pull_lock.release()


# ── A finished campaign, carried to H0 (#167) ─────────────────────────────────────────

def safe_part(part: str) -> bool:
    """A plain name — never a path: what a campaign id or a run id read from a manifest (it
    may come from another host) must be before it names a file."""
    return bool(_SAFE_PART.match(part)) and ".." not in part


_safe_part = safe_part


def unpublished_runs(campaign_dir: Path, runs_dir: Path | None = None) -> list[str]:
    """The executed runs of the campaign whose report is not in ``runs_dir`` — H0 waits for
    each one before it writes the campaign's report, so it will not write it on its own
    (``campaign run --runs-dir X``: the runs' reports stay in ``runs/``, annatar/runner/report.py)."""
    import json

    cdir = Path(campaign_dir)
    runs = Path(runs_dir) if runs_dir is not None else cdir.parent.parent
    manifest = json.loads((cdir / "manifest.json").read_text(encoding="utf-8"))
    out = []
    for scenario in manifest.get("scenarios") or []:
        if not isinstance(scenario, dict) or scenario.get("status") != "executed":
            continue
        rid = str(scenario.get("run_id") or "")
        if rid and (not safe_part(rid) or not (runs / f"{rid}.json").is_file()):
            out.append(rid)
    return out


def campaign_blobs(campaign_dir: Path, runs_dir: Path | None = None) -> list[tuple[str, Path]]:
    """What a campaign carries to H0, as (blob name, local file): the report of each of its
    runs (``runs/<run_id>.json``, which holds ``attack_time``), then its manifest — last, so
    a watch that sees the manifest sees the runs too. Nothing else: not the runs' debug or
    signal files, not another run, not a file of the campaign directory (scenarios, report).
    A run_id that is not a plain name is left out; a campaign_id that is not raises."""
    import json

    cdir = Path(campaign_dir)
    runs = Path(runs_dir) if runs_dir is not None else cdir.parent.parent
    manifest = json.loads((cdir / "manifest.json").read_text(encoding="utf-8"))
    cid = str(manifest.get("campaign_id") or cdir.name)
    if not _safe_part(cid):
        raise ValueError(f"unsafe campaign id: {cid!r}")
    out: list[tuple[str, Path]] = []
    for scenario in manifest.get("scenarios") or []:
        rid = str((scenario or {}).get("run_id") or "")
        if not _safe_part(rid):
            continue
        for pattern in _RUN_FILES:
            name = pattern.format(run_id=rid)
            if (runs / name).is_file():
                out.append((f"{CAMPAIGNS}/{cid}/runs/{name}", runs / name))
    out.append((f"{CAMPAIGNS}/{cid}/manifest.json", cdir / "manifest.json"))
    return out


def publish_campaign(campaign_dir: Path, runs_dir: Path | None = None, *,
                     channel: str | None = None, credential=None,
                     put=None) -> tuple[str, list[str]]:
    """Write the campaign's blobs (``campaign_blobs``) to the channel: the campaign id they
    are published under (the manifest's, after which H0 names the campaign's directory and
    report) and the names written — ``("", [])`` when no channel is configured. A refused
    write raises to its caller, which reports it (annatar/cli.py): the campaign has run,
    its report can be written later."""
    import requests

    url = channel if channel is not None else channel_url()
    if not url:
        return "", []
    blobs = campaign_blobs(campaign_dir, runs_dir)
    cid = blobs[-1][0].split("/")[1]  # campaigns/<cid>/manifest.json, always the last
    headers = {**auth_headers(credential), "x-ms-blob-type": "BlockBlob",
               "Content-Type": "application/json"}
    written = []
    for name, path in blobs:
        r = (put or requests.put)(f"{url}/{name}", headers=headers, data=path.read_bytes(),
                                  timeout=15)
        if not r.ok:
            raise RuntimeError(f"HTTP {r.status_code} publishing {name}")
        written.append(name)
    return cid, written


def _blobs(get, url: str, headers: dict, prefix: str = ""):
    """Every blob of the channel (under ``prefix``, when one is given), page after page."""
    marker = ""
    while True:
        params = {"restype": "container", "comp": "list"}
        if prefix:
            params["prefix"] = prefix
        if marker:
            params["marker"] = marker
        r = get(url, headers=headers, params=params, timeout=15)
        if not r.ok:
            raise RuntimeError(f"HTTP {r.status_code} listing the channel")
        root = ET.fromstring(r.content)
        yield from root.iter("Blob")
        marker = (root.findtext("NextMarker") or "").strip()
        if not marker:
            return


def pull_campaigns(directory: Path, *, channel: str | None = None, credential=None,
                   get=None) -> tuple[int, set[str]]:
    """Copy the published campaigns into ``directory`` (``runs/campaigns`` on H0):
    ``<campaign_id>/runs/<run_id>.json``, then ``<campaign_id>/manifest.json``, each new or
    changed since the local copy, written whole (tmp, then replace). A blob of any other
    shape is skipped; the windows are never touched.

    The runs first, the manifests last, and a campaign's manifest only when every one of
    its runs came: a manifest here says its runs are here too (analysis/hosted_report.py
    reads a ``done`` manifest as « report due »). Beside each manifest, a ``PULLED`` marker:
    the hosted report writes only the campaigns that came this way, never one of a local run
    on the same runs directory. Returns how many files were written, and the campaigns whose
    pull failed (a run or the manifest refused) — not due at this pull."""
    import requests

    url = channel if channel is not None else channel_url()
    if not url:
        return 0, set()
    get = get or requests.get
    headers = auth_headers(credential)
    directory = Path(directory)
    runs, manifests = [], []
    for blob in _blobs(get, url, headers, f"{CAMPAIGNS}/"):
        name = blob.findtext("Name") or ""
        m = _CAMPAIGN_BLOB.match(name)
        if not m or not _safe_part(m["cid"]) or (m["rid"] is not None and not _safe_part(m["rid"])):
            continue
        (manifests if m["rid"] is None else runs).append((blob, name, m))
    written, failed = 0, set()
    for blob, name, m in runs + manifests:
        if m["rid"] is None and m["cid"] in failed:
            continue  # a run of it did not come: its manifest waits for the next pull
        local = directory / m["cid"] / ("manifest.json" if m["rid"] is None
                                        else f"runs/{m['rid']}.json")
        modified = blob.findtext("Properties/Last-Modified")
        if local.exists() and modified:
            if parsedate_to_datetime(modified).timestamp() <= local.stat().st_mtime:
                if m["rid"] is None:
                    (local.parent / PULLED).touch()
                continue
        body = get(f"{url}/{name}", headers=headers, timeout=15)
        if not body.ok:
            failed.add(m["cid"])
            continue
        local.parent.mkdir(parents=True, exist_ok=True)
        tmp = local.with_suffix(".json.tmp")
        tmp.write_bytes(body.content)
        tmp.replace(local)  # atomic: the report never reads half a manifest
        if m["rid"] is None:  # this campaign came from the channel: its report is H0's
            (local.parent / PULLED).touch()
        written += 1
    return written, failed
