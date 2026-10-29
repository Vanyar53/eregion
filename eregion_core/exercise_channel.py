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

And the report of a run launched alone (``annatar run``, ``gothmog run``, #193), so that its
verdict is seen on H0 too: ``runs/<run_id>.json``, under the same container and the same
assignment — a prefix again, which neither ``pull`` nor ``pull_campaigns`` takes. H0 pulls
it into its own ``runs/<run_id>.json`` (``pull_runs``), where the console of the atelier
reads it, once it has the shape H0 accepts (H-1), and never over a file it did not pull.

SEC5 holds the channel at its edges:
- a storage bearer token goes only to an Azure Storage blob endpoint — ``https://<account>``
  and one of ``BLOB_SUFFIXES`` (the public cloud, then the sovereign ones), port 443, no user
  in the URL; any other URL is refused before a token is asked for (N-15, ``url_refusal``);
- a pull reads what it is given within bounds (V-21): a blob at most ``MAX_BLOB_BYTES``, a
  listing page at most ``MAX_LISTING_BYTES``, at most ``MAX_BLOBS`` names listed and
  ``MAX_DOWNLOADS`` blobs downloaded per pull — read as a stream cut past the bound, never
  read whole and then checked; what goes past one is said, and left for the next pull or
  skipped, never written;
- a window pulled from the channel carries when its blob was created, as the listing says
  (``CREATED``, written over anything the window said of it, and kept from its first pull):
  the watch bounds the window by it, not by what the window declares (V-20,
  eregion_core/exercise.py);
- Orodruin's journal goes here too, under ``audit/`` (V-29, eregion_core/orodruin.py): an
  append blob per run, a prefix no pull takes.
"""
from __future__ import annotations

import os
import re
import threading
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from urllib.parse import urlsplit

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
# The report of a run launched alone: ``runs/<run_id>.json``, the run id a plain name.
RUNS = "runs"
_RUN_BLOB = re.compile(r"^runs/(?P<rid>[A-Za-z0-9][A-Za-z0-9_.-]*)\.json$")
# In H0's runs directory, one empty file per run report pulled from the channel: H0 writes
# again only those, never the report of a run of its own.
PULLED_RUNS = ".pulled-runs"

# SEC5 (N-15): the only hosts a storage bearer token is sent to — Azure Storage's blob
# endpoints: the public cloud, Azure China, Azure US Government.
BLOB_SUFFIXES = (".blob.core.windows.net", ".blob.core.chinacloudapi.cn",
                 ".blob.core.usgovcloudapi.net")
_ACCOUNT = re.compile(r"^[a-z0-9]{3,24}$")
# SEC5 (V-21): what one pull reads at most. A window, a run's report, a campaign's manifest
# are a few KiB; a listing page of Azure's 5 000 names, about 2 MiB.
MAX_BLOB_BYTES = 1024 * 1024
MAX_LISTING_BYTES = 8 * 1024 * 1024
MAX_BLOBS = 2000
MAX_DOWNLOADS = 200
_CHUNK = 64 * 1024
# SEC5 (V-20): in a window pulled from the channel, when its blob was created — the
# listing's word, never the window's (eregion_core/exercise.py reads it).
CREATED = "channel_created"
# SEC5 (V-29): Orodruin's journal, one append blob per run.
AUDIT = "audit"

_last_pull = 0.0
_pull_lock = threading.Lock()
_credential = None


class ChannelRefused(ValueError):
    """A channel URL a storage token must never be sent to (N-15)."""


class TooLarge(RuntimeError):
    """A blob or a listing past its bound (V-21): the rest of it is never read."""


def channel_url() -> str:
    return (os.environ.get(CHANNEL_ENV) or "").strip().rstrip("/")


def url_refusal(url: str) -> str:
    """Why a storage token must not go to ``url`` — "" when it is an Azure Storage blob
    endpoint: https, ``<account>`` then one of BLOB_SUFFIXES, port 443, no user (N-15)."""
    try:
        parts = urlsplit(url or "")
        port = parts.port
    except ValueError:
        return "not a URL"
    if parts.scheme != "https":
        return "not https"
    if parts.username is not None or parts.password is not None:
        return "a user in the URL"
    if port not in (None, 443):
        return f"port {port}, not 443"
    host = (parts.hostname or "").lower()
    for suffix in BLOB_SUFFIXES:
        if host.endswith(suffix) and _ACCOUNT.match(host[:-len(suffix)]):
            return ""
    return "not an Azure Storage blob endpoint (https://<account>.blob.core.windows.net)"


def check_url(url: str) -> str:
    """``url``, or ChannelRefused — before any token is asked for."""
    why = url_refusal(url)
    if why:
        host = urlsplit(url or "").hostname or "?"
        raise ChannelRefused(f"channel {host!r} refused, no token sent: {why}")
    return url


def _read(r, limit: int, what: str) -> bytes:
    """The body of ``r``, at most ``limit`` bytes. A real response is read as a stream and
    cut past the bound — never read whole, then checked (V-21); its Content-Length, when it
    says more, refuses it before a byte is read. A client passed in (a fake) gives its body."""
    import requests

    if isinstance(r, requests.Response):
        try:
            declared = int(r.headers.get("Content-Length") or -1)
        except ValueError:
            declared = -1
        if declared > limit:
            r.close()
            raise TooLarge(f"{what}: {declared} bytes, more than {limit}")
        out = bytearray()
        for chunk in r.iter_content(_CHUNK):
            out += chunk
            if len(out) > limit:
                r.close()
                raise TooLarge(f"{what}: more than {limit} bytes")
        return bytes(out)
    body = r.content
    if len(body) > limit:
        raise TooLarge(f"{what}: more than {limit} bytes")
    return body


def fetch(get, url: str, headers: dict, *, limit: int = MAX_BLOB_BYTES, params=None,
          what: str = "") -> tuple[object, bytes]:
    """GET ``url``: (the response, its body read within ``limit``) — b"" when it is not ok.
    Without a client passed in, requests streams it (``stream=True``)."""
    import requests

    if get is None:
        r = requests.get(url, headers=headers, params=params, timeout=15, stream=True)
    else:
        r = get(url, headers=headers, params=params, timeout=15)
    if not r.ok:
        return r, b""
    return r, _read(r, limit, what or url.rsplit("/", 1)[-1])


def auth_headers(credential, url: str) -> dict:
    """Storage, by managed identity — shared with the return channel (watch_channel.py). The
    token is asked for only once ``url`` is an Azure Storage blob endpoint (N-15)."""
    global _credential
    check_url(url)
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
    headers = {**auth_headers(credential, url), "x-ms-blob-type": "BlockBlob",
               "Content-Type": "application/json"}
    r = (put or requests.put)(f"{url}/{name}", headers=headers,
                              data=json.dumps(window, indent=2).encode(), timeout=15)
    if not r.ok:
        raise RuntimeError(f"HTTP {r.status_code} publishing {name}")
    return True


def _created(blob) -> str:
    """When the blob was created, as the listing says (``Creation-Time``) — else its
    ``Last-Modified``, never earlier — else now: the bound is only ever stricter (V-20)."""
    for field in ("Properties/Creation-Time", "Properties/Last-Modified"):
        value = blob.findtext(field)
        if value:
            try:
                return parsedate_to_datetime(value).astimezone(timezone.utc).isoformat()
            except (TypeError, ValueError):
                continue
    return datetime.now(timezone.utc).isoformat()


def _stamped(body: bytes, blob, local: Path) -> bytes:
    """The window as pulled, with ``CREATED`` set to when its blob was created — the value of
    its first pull, kept when the window comes again (closed), else the listing's (V-20). A
    body that is no JSON object is written as it came: the watch refuses it anyway."""
    import json

    try:
        window = json.loads(body)
    except ValueError:
        return body
    if not isinstance(window, dict):
        return body
    first = ""
    try:
        first = str(json.loads(local.read_text(encoding="utf-8")).get(CREATED) or "")
    except (OSError, ValueError, AttributeError):
        pass
    window[CREATED] = first or _created(blob)
    return json.dumps(window, indent=2).encode()


# A window, once pulled, may come again only closed (V-20): every field as it was, ``end`` from
# null to a date not before its start (``closed_by`` beside it, the kill's). Anything else —
# a target added, a start moved, its expiry pushed, ``end`` withdrawn or moved — is refused,
# the local copy kept. When it was refused, by blob: said once, not downloaded again.
_KEPT_AS_PULLED = {CREATED, "end", "closed_by"}
_refused_rewrites: dict[str, str] = {}


def rewrite_refusal(old, new) -> str:
    """Why a window pulled again may not replace its local copy — "" when it is its closure."""
    from eregion_core.exercise import _parse  # exercise imports this module lazily

    if not isinstance(old, dict) or not isinstance(new, dict):
        return "" if not isinstance(old, dict) else "not a JSON object"
    if old.get("purged_at"):
        return "purged here already"
    changed = sorted(k for k in (set(old) | set(new)) - _KEPT_AS_PULLED if old.get(k) != new.get(k))
    if changed:
        return f"rewritten after it was pulled: {', '.join(changed)} changed"
    if old.get("end") == new.get("end"):
        return ""
    start, end = _parse(old.get("start")), _parse(new.get("end"))
    if old.get("end") is None and end is not None and start is not None and end >= start:
        return ""
    return "its end withdrawn or moved after it was pulled"


def pull(directory: Path, *, channel: str | None = None, credential=None, get=None,
         say=print) -> int:
    """Copy into ``directory`` every window of the channel that is new or changed since the
    local copy, page after page of the listing — the container's root only (the windows; the
    prefixes are other pulls'), within the bounds of V-21. Each window carries when its blob
    was created (``CREATED``, V-20); one pulled already is replaced only by its closure
    (``rewrite_refusal``). Returns how many were written."""
    url = channel if channel is not None else channel_url()
    if not url:
        return 0
    headers = auth_headers(credential, url)
    directory.mkdir(parents=True, exist_ok=True)
    written = downloads = 0
    for blob in _blobs(get, url, headers, delimiter="/", say=say):
        name = blob.findtext("Name") or ""
        if not _SAFE_NAME.match(name):  # a campaign's blob (a ``/``) or a path: never a window
            continue
        modified = blob.findtext("Properties/Last-Modified")
        local = directory / name
        if local.exists() and modified:
            remote_ts = parsedate_to_datetime(modified).timestamp()
            if remote_ts <= local.stat().st_mtime:
                continue
        key = f"{directory}/{name}"
        if modified and _refused_rewrites.get(key) == modified:
            continue  # refused already, said already: not downloaded again
        if downloads >= MAX_DOWNLOADS:
            say(f"[exercise-channel] {MAX_DOWNLOADS} windows downloaded: the rest waits for "
                "the next pull")
            break
        downloads += 1
        try:
            r, body = fetch(get, f"{url}/{name}", headers, what=f"window {name}")
        except TooLarge as e:
            say(f"[exercise-channel] {e} — not pulled")
            continue
        if not r.ok:
            continue
        if local.exists():
            import json
            try:
                old = json.loads(local.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                old = None
            try:
                new = json.loads(body)
            except ValueError:
                new = None
            why = rewrite_refusal(old, new)
            if why:
                _refused_rewrites[key] = modified or ""
                say(f"[exercise-channel] window {name} refused, the copy pulled before kept: {why}")
                continue
        _refused_rewrites.pop(key, None)
        tmp = local.with_suffix(".json.tmp")
        tmp.write_bytes(_stamped(body, blob, local))
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
    headers = {**auth_headers(credential, url), "x-ms-blob-type": "BlockBlob",
               "Content-Type": "application/json"}
    written = []
    for name, path in blobs:
        r = (put or requests.put)(f"{url}/{name}", headers=headers, data=path.read_bytes(),
                                  timeout=15)
        if not r.ok:
            raise RuntimeError(f"HTTP {r.status_code} publishing {name}")
        written.append(name)
    return cid, written


# ── The report of a run launched alone, carried to H0 (#193) ──────────────────────────

def publish_run(run_id: str, runs_dir: Path | str = "runs", *, channel: str | None = None,
                credential=None, put=None) -> str:
    """Write the report of a run launched alone to the channel, as ``runs/<run_id>.json``:
    its report only, never its debug or signal files. The blob's name, or "" when no channel
    is configured or the run wrote no report. A refused write raises to its caller."""
    import requests

    url = channel if channel is not None else channel_url()
    if not url:
        return ""
    if not safe_part(run_id):
        raise ValueError(f"unsafe run id: {run_id!r}")
    path = Path(runs_dir) / f"{run_id}.json"
    if not path.is_file():
        return ""
    name = f"{RUNS}/{run_id}.json"
    headers = {**auth_headers(credential, url), "x-ms-blob-type": "BlockBlob",
               "Content-Type": "application/json"}
    r = (put or requests.put)(f"{url}/{name}", headers=headers, data=path.read_bytes(),
                              timeout=15)
    if not r.ok:
        raise RuntimeError(f"HTTP {r.status_code} publishing {name}")
    return name


def carry_run(run_id: str, runs_dir: Path | str = "runs") -> bool:
    """``publish_run`` at the end of a run (``annatar run``, ``gothmog run``), beside its
    closed window. A failure is said, never raised: the run is over, and its report stays
    on this host. True once published."""
    try:
        name = publish_run(run_id, runs_dir)
    except Exception as e:
        print(f"[exercise-channel] run report {run_id} not published: {e}")
        return False
    if name:
        print(f"[exercise-channel] run report published to H0: {name}")
    return bool(name)


def _blobs(get, url: str, headers: dict, prefix: str = "", *, delimiter: str = "",
           say=print):
    """Every blob of the channel (under ``prefix``, when one is given; not below a
    ``delimiter``), page after page — each page read within MAX_LISTING_BYTES, at most
    MAX_BLOBS names in all: past them, the listing stops and says so (V-21)."""
    marker, seen = "", 0
    while True:
        params = {"restype": "container", "comp": "list"}
        if prefix:
            params["prefix"] = prefix
        if delimiter:
            params["delimiter"] = delimiter
        if marker:
            params["marker"] = marker
        r, body = fetch(get, url, headers, limit=MAX_LISTING_BYTES, params=params,
                        what="a listing page of the channel")
        if not r.ok:
            raise RuntimeError(f"HTTP {r.status_code} listing the channel")
        root = ET.fromstring(body)
        for blob in root.iter("Blob"):
            if seen >= MAX_BLOBS:
                say(f"[exercise-channel] listing stopped at {MAX_BLOBS} blobs"
                    f"{' under ' + prefix if prefix else ''}: the rest is not pulled")
                return
            seen += 1
            yield blob
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

    url = channel if channel is not None else channel_url()
    if not url:
        return 0, set()
    headers = auth_headers(credential, url)
    directory = Path(directory)
    runs, manifests = [], []
    for blob in _blobs(get, url, headers, f"{CAMPAIGNS}/"):
        name = blob.findtext("Name") or ""
        m = _CAMPAIGN_BLOB.match(name)
        if not m or not _safe_part(m["cid"]) or (m["rid"] is not None and not _safe_part(m["rid"])):
            continue
        (manifests if m["rid"] is None else runs).append((blob, name, m))
    written, failed, downloads = 0, set(), 0
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
        if downloads >= MAX_DOWNLOADS:  # V-21: the rest waits; its manifest with it
            failed.add(m["cid"])
            continue
        downloads += 1
        try:
            r, body = fetch(get, f"{url}/{name}", headers, what=name)
        except TooLarge as e:
            print(f"[exercise-channel] {e} — not pulled")
            failed.add(m["cid"])
            continue
        if not r.ok:
            failed.add(m["cid"])
            continue
        local.parent.mkdir(parents=True, exist_ok=True)
        tmp = local.with_suffix(".json.tmp")
        tmp.write_bytes(body)
        tmp.replace(local)  # atomic: the report never reads half a manifest
        if m["rid"] is None:  # this campaign came from the channel: its report is H0's
            (local.parent / PULLED).touch()
        written += 1
    return written, failed


def pull_runs(directory: Path, *, refusal, channel: str | None = None, credential=None,
              get=None) -> tuple[int, dict[str, str]]:
    """Copy into ``directory`` (``runs`` on H0) the published report of each run launched
    alone, as ``<run_id>.json``, new or changed since the local copy, written whole (tmp,
    then replace). Each one is read against the shape H0 accepts first — ``refusal(report,
    run_id)`` says why not, "" when it does (analysis/campaign_schema.py
    ``run_report_refusal``, H-1) — and a refused one is not written. A local file without
    its ``PULLED_RUNS`` marker (a run of this host) is never written over. Returns how many
    were written, and why each one that was not, by run id; the windows and the campaigns
    are never touched."""
    import json

    url = channel if channel is not None else channel_url()
    if not url:
        return 0, {}
    headers = auth_headers(credential, url)
    directory = Path(directory)
    marks = directory / PULLED_RUNS
    written, skipped, downloads = 0, {}, 0
    for blob in _blobs(get, url, headers, f"{RUNS}/"):
        name = blob.findtext("Name") or ""
        m = _RUN_BLOB.match(name)
        if not m or not safe_part(m["rid"]):
            continue
        rid = m["rid"]
        local, mark = directory / f"{rid}.json", marks / rid
        if local.exists():
            if not mark.exists():
                skipped[rid] = "a report of this name is here already, not pulled: kept"
                continue
            modified = blob.findtext("Properties/Last-Modified")
            if modified and parsedate_to_datetime(modified).timestamp() <= local.stat().st_mtime:
                continue
        if downloads >= MAX_DOWNLOADS:
            skipped[rid] = f"not pulled yet: {MAX_DOWNLOADS} reports downloaded by this pull"
            continue
        downloads += 1
        try:
            r, content = fetch(get, f"{url}/{name}", headers, what=name)
        except TooLarge as e:
            skipped[rid] = f"refused: {e}"
            continue
        if not r.ok:
            skipped[rid] = f"HTTP {r.status_code} downloading it"
            continue
        try:
            report = json.loads(content)
        except ValueError:
            skipped[rid] = "refused: not JSON"
            continue
        why = refusal(report, rid)
        if why:
            skipped[rid] = f"refused: {why}"
            continue
        marks.mkdir(parents=True, exist_ok=True)
        mark.touch()  # the marker first: cut before the file, the next pull still writes it
        directory.mkdir(parents=True, exist_ok=True)
        tmp = local.with_suffix(".json.tmp")
        tmp.write_bytes(content)
        tmp.replace(local)  # atomic: the console never reads half a report
        written += 1
    return written, skipped
