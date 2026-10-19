"""The channel that carries exercise windows (B2) from the injectors' host (Orodruin) to a
watch on another host (Glorfindel hosted, H0) — O1, part C.

A blob container, reached by managed identity only (no shared key): Orodruin's identity
writes, the watch's identity reads. ``EREGION_EXERCISE_CHANNEL`` is the container's URL
(``https://<account>.blob.core.windows.net/exercises``); unset or empty, nothing is
published or pulled and the windows stay local, as before.

Both directions fail toward ``real``: a window that doesn't reach the watch leaves its
cycles labelled real — the label never lowers a guard (eregion_core/exercise.py). So a
failure here is reported, never raised into a run or a cycle.
"""
from __future__ import annotations

import os
import re
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

_last_pull = 0.0
_credential = None


def channel_url() -> str:
    return (os.environ.get(CHANNEL_ENV) or "").strip().rstrip("/")


def _headers(credential) -> dict:
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
    headers = {**_headers(credential), "x-ms-blob-type": "BlockBlob",
               "Content-Type": "application/json"}
    r = (put or requests.put)(f"{url}/{name}", headers=headers,
                              data=json.dumps(window, indent=2).encode(), timeout=15)
    if not r.ok:
        raise RuntimeError(f"HTTP {r.status_code} publishing {name}")
    return True


def pull(directory: Path, *, channel: str | None = None, credential=None, get=None) -> int:
    """Copy into ``directory`` every window of the channel that is new or changed since the
    local copy. Returns how many were written."""
    import requests

    url = channel if channel is not None else channel_url()
    if not url:
        return 0
    get = get or requests.get
    headers = _headers(credential)
    r = get(url, headers=headers, params={"restype": "container", "comp": "list"}, timeout=15)
    if not r.ok:
        raise RuntimeError(f"HTTP {r.status_code} listing the channel")
    directory.mkdir(parents=True, exist_ok=True)
    written = 0
    for blob in ET.fromstring(r.content).iter("Blob"):
        name = blob.findtext("Name") or ""
        if not _SAFE_NAME.match(name):
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
    """``pull`` at most every PULL_EVERY_S — load_windows runs on every cycle."""
    global _last_pull
    if not channel_url():
        return
    now = time.monotonic() if now is None else now
    if now - _last_pull < PULL_EVERY_S:
        return
    _last_pull = now
    try:
        pull(directory)
    except Exception as e:  # the local windows still count; the rest falls toward real
        print(f"[exercise-channel] pull failed at {datetime.now():%H:%M:%S}: {e}")
