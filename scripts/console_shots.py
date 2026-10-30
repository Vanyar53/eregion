#!/usr/bin/env python3
"""Dagorlad shown (DOC1, #365): the README's captures and loop, replayed from the sample data.

    python scripts/console_shots.py                  # docs/images/dagorlad/: board.png, runs.png, loop.webp
    python scripts/console_shots.py --video ~/dagorlad.mp4   # and the whole tour, outside the repository
    python scripts/console_shots.py --check          # which tools are here; renders nothing
    make console-shots [VIDEO=~/dagorlad.mp4]

**The sample data only.** The console is started on ``tests/fixtures/dagorlad_sample.json`` and
nothing else: a fictitious bench (the zero subscription, the bench's public names), written into
a throwaway directory that is the server's HOME and working directory — never ``~/.glorfindel``,
``runs/`` or a real bench. The script refuses (exit 2) another sample, a sample that carries an
identifier outside the allowed ones (``identifiers``), a video written inside the repository.
The server it starts refuses to run anywhere but in that directory, with an Azure variable in
its environment, or without the sample's mark (``serve_refusal``); it connects nowhere but the
loopback (``loopback_only``). No Azure call, no model, no H0.

**The tools are the workstation's**, never the CI's nor a dependency of the package: a Chromium
(``--chromium``, ``EREGION_CHROMIUM``, the PATH, or Playwright's cache: ``chrome-headless-shell``),
driven by the DevTools protocol with ``websockets`` (the console's extra brings it); ffmpeg for
the video only (``--ffmpeg``, ``EREGION_FFMPEG``, the PATH, or Playwright's): an mp4 when it
has libx264, else a WebM (VP9). Missing, the script says which and stops (exit 3). The images
are PNG and an animated WebP, encoded by Chromium itself and put together here — no image
library.

``docs/images/dagorlad/shots.json`` binds the images to the sample: the sample's sha256 and
each image's. ``tests/unit/test_console_shots.py`` checks it, with the sample's identifiers.
"""
from __future__ import annotations

import argparse
import base64
import glob
import hashlib
import ipaddress
import json
import os
import re
import secrets
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SAMPLE = REPO / "tests" / "fixtures" / "dagorlad_sample.json"
OUT = REPO / "docs" / "images" / "dagorlad"
MANIFEST = "shots.json"
MARK = ".dagorlad-sample"          # in the throwaway directory: the sample's sha256
ZERO_SUBSCRIPTION = "00000000-0000-0000-0000-000000000000"
WIDTH, HEIGHT = 1440, 900
BOARD_HEIGHT = 1100
LOOP_SCALE = 0.75
MAX_PNG = 300 * 1024
MAX_LOOP = 3 * 1024 * 1024

# ── What may be shown: the identifiers allowed ─────────────────────────────────────────────
# A subscription or a tenant is a GUID: only the zero one. An address: only the documentation's
# ranges (RFC 5737). A name of the bench: its public ones. A host: none but these.
GUID = re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")
IPV4 = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
DOC_NETS = tuple(ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"))
HOST = re.compile(r"\b(?:[a-z0-9-]+\.)+(?:com|net|org|io|dev|app|cloud|fr|eu|internal|local)\b", re.I)
ALLOWED_HOSTS = ("github.com", "vanyar53.github.io", "example.com", "example.org", "example.net")
BENCH_NAME = re.compile(r"(?:rg-celebrimbor[a-z0-9-]*|vm-celebrimbor-[a-z0-9-]+|vm-sentinel)")


def identifiers(text: str) -> list[str]:
    """What in ``text`` could name a real deployment: a GUID that is not the zero one, an IPv4
    address outside the documentation's ranges, a host name outside the allowed ones."""
    found = [g for g in GUID.findall(text) if g != ZERO_SUBSCRIPTION]
    for a in IPV4.findall(text):
        try:
            ip = ipaddress.ip_address(a)
        except ValueError:
            continue
        if not any(ip in n for n in DOC_NETS):
            found.append(a)
    found += [h for h in HOST.findall(text) if h.lower() not in ALLOWED_HOSTS]
    return found


def doc_refusal(doc) -> str:
    """Why this sample must not be rendered — "" when it may: the zero subscription, the
    bench's public names, no identifier anywhere in it."""
    if not isinstance(doc, dict) or not doc.get("sample"):
        return "not Dagorlad's sample (no « sample » field)"
    if doc.get("subscription") != ZERO_SUBSCRIPTION:
        return f"its subscription is not the zero GUID ({ZERO_SUBSCRIPTION})"
    names = [t.get(k) for t in doc.get("targets") or [] for k in ("name", "resource_group")]
    bad = [n for n in names if not (isinstance(n, str) and BENCH_NAME.fullmatch(n))]
    if bad:
        return f"a name outside the bench's public ones: {bad[0]!r}"
    found = identifiers(json.dumps(doc))
    if found:
        return f"an identifier outside the allowed ones: {found[0]!r}"
    return ""


def sample_refusal(path: Path) -> str:
    """The shipped sample, and nothing else."""
    try:
        if Path(path).resolve() != SAMPLE.resolve():
            return f"{path}: not the shipped sample ({SAMPLE.relative_to(REPO)}) — the script renders it only"
        doc = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return f"{path}: unreadable ({exc})"
    return doc_refusal(doc)


def sha256(path: Path) -> str:
    """The digest of a text file, its line ends as Git stores them (a checkout in CRLF reads
    the same)."""
    return hashlib.sha256(Path(path).read_bytes().replace(b"\r\n", b"\n")).hexdigest()


# ── The sample, written into a throwaway directory ─────────────────────────────────────────

def resource_id(doc: dict, target: dict) -> str:
    return (f"/subscriptions/{doc['subscription']}/resourceGroups/{target['resource_group']}"
            f"/providers/Microsoft.Compute/virtualMachines/{target['name']}")


def _iso(dt: datetime) -> str:
    return dt.isoformat()


def materialize(doc: dict, work: Path, now: datetime | None = None) -> dict:
    """The sample as the console reads it, its times counted back from ``now``: under
    ``work/home`` the watch's heartbeat and discovered assets; under ``work/cwd/runs`` the run
    reports, the watch's cycles, the exercise windows, Orodruin's contract. Returns where."""
    now = (now or datetime.now(timezone.utc)).replace(microsecond=0)
    home, cwd = work / "home", work / "cwd"
    runs = cwd / "runs"
    for d in (home / ".glorfindel", runs / "exercises", runs / "orodruin"):
        d.mkdir(parents=True, exist_ok=True)
    mark = sha256(SAMPLE) if SAMPLE.exists() else ""
    for d in (work, home, cwd):
        (d / MARK).write_text(mark, encoding="utf-8")
    (home / ".glorfindel" / "watch_heartbeat").write_text(_iso(now - timedelta(seconds=12)), encoding="utf-8")
    by_name = {t["name"]: t for t in doc["targets"]}
    assets = [{"name": t["name"], "resource_id": resource_id(doc, t), "monitoring_backend": doc["backend"],
               "last_seen": _iso(now - timedelta(seconds=t.get("seen_ago_s", 30))), "source": "heartbeat",
               "kind": "vm", "parent": "", "extra": {}} for t in doc["targets"]]
    (home / ".glorfindel" / "discovered_assets.json").write_text(json.dumps(assets, indent=2), encoding="utf-8")
    o = doc.get("orodruin")
    if o:
        (runs / "orodruin" / "contract.json").write_text(json.dumps(
            {"verdict": o["verdict"], "codes": o["codes"], "at": _iso(now - timedelta(seconds=o.get("ago_s", 0)))}),
            encoding="utf-8")
    cycles = []
    for r in doc.get("runs") or []:
        at = (now - timedelta(hours=r["ago_h"])).replace(microsecond=0)
        target = by_name[r["target"]]
        rid = resource_id(doc, target)
        fault = r["experiment"] == "vm-shutdown"
        run_id = ("gothmog-" if fault else "") + at.strftime("%Y%m%dT%H%M%SZ")
        if fault:
            end = at + timedelta(seconds=r.get("restore_s", 90) + 60)
            probes = [{"name": n, "ok": True, "observed": "ok", "expect": "ok"}
                      for n in ("vm-running", "guest-agent-ready", "heartbeat")]
            report = {"scenario": "vm-shutdown", "run_id": run_id, "mitre": "", "result": r["result"],
                      "metrics": {"run_format": 1, "kind": "fault", "injector": "gothmog",
                                  "experiment_id": "vm-shutdown", "fault_start": _iso(at), "fault_end": _iso(end),
                                  "targets": [rid], "time_to_restore_s": r.get("restore_s"),
                                  "before": {target["name"]: probes}, "after": {target["name"]: probes}},
                      "thresholds": {}, "checks": {"fault_started": "PASS", "steady_before": "PASS",
                                                   "steady_after": "PASS", "return_verified": "PASS"}}
        else:
            metrics = {"run_format": 1, "kind": "technique", "injector": "annatar",
                       "experiment_id": r["experiment"], "resource_id": rid, "attack_time": _iso(at),
                       "detection": r["detection"]}
            if r["detection"] == "detected":
                metrics["detection_latency_s"] = r["latency_s"]
            report = {"scenario": r["experiment"], "run_id": run_id, "mitre": r["experiment"],
                      "result": "PASS" if r["detection"] == "detected" else "FAIL",
                      "metrics": metrics, "thresholds": {}, "checks": {}}
            d = r.get("decision")
            if d and r["detection"] == "detected":
                seen = at + timedelta(seconds=r["latency_s"])
                cycles.append({
                    "timestamp": _iso(seen + timedelta(seconds=38)),
                    "signal": {"signal_id": f"rule-sample-{run_id}", "event": "detection", "ttp": r["experiment"],
                               "resource_id": rid, "timestamp": _iso(seen),
                               "context": {"rule_name": next((x["name"] for x in doc["rules"]
                                                              if x["ttp"] == r["experiment"]), ""),
                                           "attribution": "asset"}},
                    "reasoning": "sample", "confidence": d["confidence"], "action": d["action"],
                    "escalate": d["escalate"], "escalation_reason": "",
                    "outcome": {"status": "escalated" if d["escalate"] else "executed",
                                "executed": not d["escalate"]},
                    "resolved_autonomy_mode": "human_only"})
        (runs / f"{run_id}.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
        if r.get("window"):
            start = at - timedelta(seconds=20)
            end = at + timedelta(minutes=12)
            (runs / "exercises" / f"{run_id}.json").write_text(json.dumps({
                "run_id": run_id, "injector": "gothmog" if fault else "annatar",
                "kind": "fault" if fault else "technique",
                "experiment": r["experiment"], "targets": [rid.lower()], "start": _iso(start),
                "end": _iso(end), "expires": _iso(start + timedelta(hours=2)),
                **({} if fault else {"destructive": bool(r.get("destructive", False))})}), encoding="utf-8")
    with open(runs / "watch-sample_debug.jsonl", "w", encoding="utf-8") as f:
        for c in cycles:
            f.write(json.dumps(c) + "\n")
    return {"home": home, "cwd": cwd, "runs": runs}


# ── The server: the console, on the sample, in its throwaway directory ─────────────────────

def serve_refusal(work: Path, environ, home: Path, cwd: Path) -> str:
    """Why the console must not start here — "" when it may: its HOME and its working
    directory are the throwaway directory's, each with the sample's mark; no Azure variable in
    its environment (the console would read the bench with them)."""
    azure = sorted(k for k in environ if k.startswith(("AZURE_", "ARM_")))
    if azure:
        return f"an Azure variable in the environment: {azure[0]}"
    expected = sha256(SAMPLE)
    for what, d, want in (("HOME", home, work / "home"), ("working directory", cwd, work / "cwd")):
        if Path(d).resolve() != want.resolve():
            return f"its {what} is {d}, not the throwaway directory's"
        try:
            if (Path(d) / MARK).read_text(encoding="utf-8") != expected:
                return f"its {what} carries no mark of the sample"
        except OSError:
            return f"its {what} carries no mark of the sample"
    return ""


def loopback_only() -> None:
    """Every connection of this process to the loopback, or PermissionError: the console started
    on the sample reaches no cloud, no model, no host — even by a path the patches missed."""
    real_connect, real_connect_ex, real_getaddrinfo = (socket.socket.connect, socket.socket.connect_ex,
                                                      socket.getaddrinfo)

    def _local(address) -> bool:
        if not isinstance(address, tuple):   # a Unix socket
            return True
        host = str(address[0])
        if host == "localhost":
            return True
        try:
            return ipaddress.ip_address(host.split("%")[0]).is_loopback
        except ValueError:
            return False

    def connect(self, address):
        if not _local(address):
            raise PermissionError(f"console_shots: no connection off the loopback ({address[0]})")
        return real_connect(self, address)

    def connect_ex(self, address):
        if not _local(address):
            raise PermissionError(f"console_shots: no connection off the loopback ({address[0]})")
        return real_connect_ex(self, address)

    def getaddrinfo(host, *args, **kwargs):
        if host is not None and not _local((host, 0)):
            raise PermissionError(f"console_shots: no name resolved off the loopback ({host})")
        return real_getaddrinfo(host, *args, **kwargs)

    socket.socket.connect, socket.socket.connect_ex, socket.getaddrinfo = connect, connect_ex, getaddrinfo


def install(api, doc: dict, put=setattr) -> None:
    """The console's readers of the bench replaced by the sample: the VMs and their tags (as
    ``TagEnrollment`` reads them through Azure: its judgement, ``enrollment``, stays the code's
    own), the rules as the watch loads them, the watch's gate. ``put``: how each is replaced
    (a test passes ``monkeypatch.setattr``)."""
    from eregion_core import inscription, watch_gate
    vms = []
    for t in doc["targets"]:
        tags = {"eregion-target": doc["bench"], "eregion-zone": t["zone"]} if t.get("zone") else {}
        vms.append({"resource_id": resource_id(doc, t), "name": t["name"], "resource_group": t["resource_group"],
                    "rg_tags": {"eregion-target": doc["bench"]}, "tags": tags})
    by_id = {v["resource_id"].lower(): v for v in vms}
    rules = [{"name": r["name"], "ttp": r["ttp"], "enabled": r["enabled"], "backend": doc["backend"],
              "expected_latency_s": r["expected_latency_s"], "layer": "base"} for r in doc["rules"]]

    def tags(self, rid: str) -> tuple[dict, dict]:
        vm = by_id.get(str(rid).lower())
        if vm is None:
            raise LookupError("not in the sample")
        return dict(vm["rg_tags"]), dict(vm["tags"])

    put(inscription.TagEnrollment, "tags", tags)
    put(inscription.TagEnrollment, "vms", lambda self, subscription, **kw: [dict(v) for v in vms])
    put(api, "READ_TARGETS", lambda subscription: [dict(v) for v in vms])
    put(api, "_board_rules", lambda: rules)
    put(watch_gate, "refusal", lambda now=None: "")


def serve(work: Path, port: int) -> int:
    reason = serve_refusal(work, os.environ, Path.home(), Path.cwd())
    if reason:
        print(f"console_shots: refused — {reason}", file=sys.stderr)
        return 2
    loopback_only()
    sys.path.insert(0, str(REPO))
    import uvicorn

    import eregion_console.api as api
    install(api, json.loads(SAMPLE.read_text(encoding="utf-8")))
    uvicorn.run(api.app, host="127.0.0.1", port=port, log_level="warning")
    return 0


def package_version() -> str:
    """The version the header shows: the repository's, never the installed package's."""
    import tomllib
    return tomllib.loads((REPO / "pyproject.toml").read_text(encoding="utf-8"))["project"]["version"]


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def server_env(work: Path, token: str) -> dict[str, str]:
    """The console's environment, built from nothing: the throwaway HOME, the token, the
    sections — never the operator's (an Azure variable, a key of the model, a channel)."""
    return {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(work / "home"),
            "LANG": "C.UTF-8", "PYTHONPATH": str(REPO), "PYTHONDONTWRITEBYTECODE": "1",
            "EREGION_CONSOLE_TOKEN": token, "EREGION_CONSOLE_SECTIONS": "annatar,gothmog",
            "EREGION_BENCH": "celebrimbor", "EREGION_REF": f"v{package_version()}"}


def start_server(work: Path, token: str) -> tuple[subprocess.Popen, int]:
    port = _free_port()
    env = server_env(work, token)
    proc = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), "--serve", str(work), "--port", str(port)],
                            cwd=str(work / "cwd"), env=env)
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise SystemExit(f"console_shots: the console did not start (exit {proc.returncode})")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return proc, port
        except OSError:
            time.sleep(0.2)
    proc.kill()
    raise SystemExit("console_shots: the console did not answer in 30 s")


# ── The tools of the workstation ───────────────────────────────────────────────────────────

def find_chromium(given: str | None = None) -> str | None:
    for c in (given, os.environ.get("EREGION_CHROMIUM")):
        if c:
            return c if Path(c).is_file() else None
    for name in ("chrome-headless-shell", "chromium", "chromium-browser", "google-chrome", "chrome"):
        if found := shutil.which(name):
            return found
    cache = Path.home() / ".cache" / "ms-playwright"
    for pattern in ("chromium_headless_shell-*/chrome-headless-shell-linux64/chrome-headless-shell",
                    "chromium-*/chrome-linux*/chrome"):
        hits = sorted(glob.glob(str(cache / pattern)))
        if hits:
            return hits[-1]
    return None


def find_ffmpeg(given: str | None = None) -> str | None:
    for c in (given, os.environ.get("EREGION_FFMPEG")):
        if c:
            return c if Path(c).is_file() else None
    if found := shutil.which("ffmpeg"):
        return found
    hits = sorted(glob.glob(str(Path.home() / ".cache" / "ms-playwright" / "ffmpeg-*" / "ffmpeg-linux")))
    return hits[-1] if hits else None


def missing_tools(chromium: str | None, ffmpeg: str | None, video: bool) -> list[str]:
    out = []
    if not chromium:
        out.append("a Chromium: --chromium, EREGION_CHROMIUM, or `python -m playwright install "
                   "chromium-headless-shell` (Playwright's cache is searched)")
    try:
        import websockets.sync.client  # noqa: F401
    except ImportError:
        out.append("websockets (the console's extra: pip install -e '.[console]')")
    if video and not ffmpeg:
        out.append("ffmpeg, for the video: --ffmpeg, EREGION_FFMPEG, the PATH, or Playwright's "
                   "(`python -m playwright install ffmpeg`)")
    return out


# ── Chromium, by the DevTools protocol ─────────────────────────────────────────────────────

class Browser:
    """A headless Chromium on a throwaway profile, one page, driven by the DevTools protocol.
    It resolves no name but localhost: the page loads nothing from outside anyway (CSP)."""

    def __init__(self, chromium: str, profile: Path):
        from websockets.sync.client import connect
        self.proc = subprocess.Popen(
            [chromium, "--headless", "--remote-debugging-port=0", f"--user-data-dir={profile}",
             "--no-first-run", "--no-default-browser-check", "--disable-gpu", "--hide-scrollbars",
             "--mute-audio", "--disable-extensions", "--disable-background-networking", "--disable-sync",
             "--disable-component-update", "--force-color-profile=srgb", "--force-device-scale-factor=1",
             "--host-resolver-rules=MAP * ~NOTFOUND , EXCLUDE localhost , EXCLUDE 127.0.0.1",
             f"--window-size={WIDTH},{HEIGHT}", "about:blank"],
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        url, deadline = None, time.monotonic() + 30
        while time.monotonic() < deadline and url is None:
            line = self.proc.stderr.readline()
            if not line and self.proc.poll() is not None:
                break
            m = re.search(r"DevTools listening on (ws://\S+)", line)
            url = m.group(1) if m else None
        if url is None:
            self.proc.kill()
            raise SystemExit("console_shots: Chromium did not start (missing libraries? "
                             "run it alone with --version)")
        self._conn = connect(url, max_size=None, open_timeout=10)
        self.ws = self._conn.__enter__()
        self._id = 0
        self.errors: list[str] = []
        self.on_event = None
        target = self.call("Target.createTarget", url="about:blank")["targetId"]
        self.session = self.call("Target.attachToTarget", targetId=target, flatten=True)["sessionId"]
        self.send("Page.enable")
        self.send("Runtime.enable")
        self.send("Log.enable")
        self.viewport(WIDTH, HEIGHT)
        self.send("Emulation.setEmulatedMedia", features=[{"name": "prefers-color-scheme", "value": "dark"}])

    def viewport(self, width: int, height: int) -> None:
        self.size = (width, height)
        self.send("Emulation.setDeviceMetricsOverride", width=width, height=height, deviceScaleFactor=1, mobile=False)

    def call(self, method: str, session: str | None = None, **params) -> dict:
        self._id += 1
        msg = {"id": self._id, "method": method, "params": params}
        if session:
            msg["sessionId"] = session
        self.ws.send(json.dumps(msg))
        while True:
            m = json.loads(self.ws.recv(timeout=60))
            if m.get("id") == self._id:
                if "error" in m:
                    raise RuntimeError(f"{method}: {m['error']}")
                return m.get("result", {})
            self._seen(m)

    def _seen(self, m: dict) -> None:
        """An event: the page's errors kept (a JS exception, a violation of the CSP, an
        error logged), then the screencast's handler, if any."""
        if m.get("method") == "Runtime.exceptionThrown":
            self.errors.append(m["params"]["exceptionDetails"].get("text", "exception"))
        elif m.get("method") == "Log.entryAdded" and m["params"]["entry"].get("level") == "error":
            self.errors.append(m["params"]["entry"].get("text", "error"))
        if self.on_event:
            self.on_event(m)

    def send(self, method: str, **params) -> dict:
        return self.call(method, self.session, **params)

    def js(self, expression: str):
        r = self.send("Runtime.evaluate", expression=expression, returnByValue=True, awaitPromise=True)
        if r.get("exceptionDetails"):
            raise RuntimeError(f"page: {r['exceptionDetails'].get('text')} {expression[:80]}")
        return r.get("result", {}).get("value")

    def wait(self, expression: str, timeout: float = 20.0) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.js(f"!!({expression})"):
                return
            time.sleep(0.1)
        where = self.js("location.href + ' — ' + (typeof S !== 'undefined' ? JSON.stringify({err: S.err, board: !!S.board})"
                        " : 'no S') + ' — ' + (document.body ? document.body.innerText.slice(0, 200) : '')")
        raise SystemExit(f"console_shots: the page never showed `{expression}` ({where})")

    def go(self, url: str) -> None:
        self.send("Page.navigate", url=url)
        path = json.dumps(url.split("?")[0])
        self.wait(f"(location.origin + location.pathname) === {path} && document.readyState === 'complete'")

    def shot(self, fmt: str = "png", quality: int | None = None, scale: float = 1.0) -> bytes:
        params = {"format": fmt, "captureBeyondViewport": False}
        if quality is not None:
            params["quality"] = quality
        if scale != 1.0:
            params["clip"] = {"x": 0, "y": 0, "width": self.size[0], "height": self.size[1], "scale": scale}
        return base64.b64decode(self.send("Page.captureScreenshot", **params)["data"])

    def pump(self, seconds: float) -> None:
        """Time passes, the events (a screencast's frames) are handled meanwhile."""
        deadline = time.monotonic() + seconds
        while (left := deadline - time.monotonic()) > 0:
            try:
                m = json.loads(self.ws.recv(timeout=left))
            except TimeoutError:
                return
            self._seen(m)

    def close(self) -> None:
        try:
            self._conn.__exit__(None, None, None)
        finally:
            self.proc.kill()
            self.proc.wait(timeout=10)


# ── The gestures on Dagorlad's board ───────────────────────────────────────────────────────

# A pointer drawn on the page, for the loop and the video (a headless capture shows none).
_CURSOR = """(() => { let c = document.getElementById('shots-cursor');
  if (!c) { c = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    c.id = 'shots-cursor'; c.setAttribute('width', '22'); c.setAttribute('height', '22');
    c.innerHTML = '<path d="M2 2 L2 18 L7 13 L11 21 L14 19.5 L10 12 L17 12 Z" fill="#e6edf3" stroke="#0d1117" stroke-width="1.5"/>';
    Object.assign(c.style, {position: 'fixed', left: '0px', top: '0px', zIndex: 99999, pointerEvents: 'none'});
    document.body.appendChild(c); }
  c.style.left = (%f - 2) + 'px'; c.style.top = (%f - 2) + 'px'; return true; })()"""


def red_index(b: Browser, experiment: str) -> int:
    return b.js(f"S.board.reds.findIndex(r => r.id === {json.dumps(experiment)})")


def blue_index(b: Browser, name: str) -> int:
    return b.js(f"S.board.targets.findIndex(t => t.name === {json.dumps(name)})")


def center(b: Browser, selector: str) -> tuple[float, float]:
    r = b.js(f"(() => {{ const e = document.querySelector({json.dumps(selector)}); if (!e) return null;"
             " const r = e.getBoundingClientRect(); return [r.left + r.width / 2, r.top + r.height / 2]; })()")
    if r is None:
        raise SystemExit(f"console_shots: nothing at {selector}")
    return r[0], r[1]


def plan_settled(n: int) -> str:
    return f"S.plan && S.plan.wires && S.plan.wires.length === {n} && S.wires.length === {n}"


def open_board(b: Browser, base: str, token: str) -> None:
    b.go(f"{base}/dagorlad?token={token}")
    b.js("localStorage.clear(); true")
    b.go(f"{base}/dagorlad")
    b.wait("typeof S !== 'undefined' && S.board && S.board.reds.length > 0 && document.querySelector('#blue-0')")


def draw(b: Browser, pairs) -> None:
    """The wires, as the page draws them on a click: a red card, then a target."""
    for experiment, target in pairs:
        i, j = red_index(b, experiment), blue_index(b, target)
        if i < 0 or j < 0:
            raise SystemExit(f"console_shots: no card for {experiment} → {target}")
        b.js(f"ACTIONS.pick({i}); ACTIONS.aim({j}); S.picked = null; renderBoard(); true")
        b.wait(plan_settled(b.js("S.wires.length")))
    b.pump(0.4)


class Recorder:
    """The frames of the loop: each a WebP from Chromium, with how long it stays."""

    def __init__(self, b: Browser):
        self.b, self.frames = b, []

    def frame(self, ms: int) -> None:
        self.frames.append((self.b.shot("webp", quality=70, scale=LOOP_SCALE), ms))


def pointer(b: Browser, x: float, y: float, kind: str = "mouseMoved", rec: Recorder | None = None,
            ms: int = 0) -> None:
    b.js(_CURSOR % (x, y))
    params = {"type": kind, "x": x, "y": y, "button": "left" if kind != "mouseMoved" else "none",
              "buttons": 1 if kind in ("mousePressed",) else 0, "clickCount": 1 if kind != "mouseMoved" else 0}
    b.send("Input.dispatchMouseEvent", **params)
    if rec and ms:
        rec.frame(ms)


def glide(b: Browser, a, z, steps: int, rec: Recorder | None, ms: int, pressed: bool = False,
          dwell: float = 0.0) -> None:
    for k in range(1, steps + 1):
        t = k / steps
        t = t * t * (3 - 2 * t)
        x, y = a[0] + (z[0] - a[0]) * t, a[1] + (z[1] - a[1]) * t
        b.js(_CURSOR % (x, y))
        b.send("Input.dispatchMouseEvent", type="mouseMoved", x=x, y=y,
               button="left" if pressed else "none", buttons=1 if pressed else 0)
        if rec:
            rec.frame(ms)
        if dwell:
            b.pump(dwell)


def drag_wire(b: Browser, experiment: str, target: str, rec: Recorder | None, ms: int = 70,
              dwell: float = 0.0) -> None:
    i, j = red_index(b, experiment), blue_index(b, target)
    start = center(b, f"#red-{i} .handle")
    end = center(b, f"#blue-{j}")
    here = b.js("(() => { const c = document.getElementById('shots-cursor');"
                " return c ? [parseFloat(c.style.left) + 2, parseFloat(c.style.top) + 2] : null; })()")
    glide(b, here or (start[0] - 200, start[1] + 120), start, 6, rec, ms, dwell=dwell)
    n = b.js("S.wires.length")
    b.send("Input.dispatchMouseEvent", type="mousePressed", x=start[0], y=start[1], button="left",
           buttons=1, clickCount=1)
    glide(b, start, end, 10, rec, ms, pressed=True, dwell=dwell)
    b.send("Input.dispatchMouseEvent", type="mouseReleased", x=end[0], y=end[1], button="left",
           buttons=0, clickCount=1)
    b.wait(plan_settled(n + 1))
    b.pump(0.3)


def click(b: Browser, selector: str, rec: Recorder | None, ms: int = 70, dwell: float = 0.0) -> None:
    x, y = center(b, selector)
    here = b.js("(() => { const c = document.getElementById('shots-cursor');"
                " return c ? [parseFloat(c.style.left) + 2, parseFloat(c.style.top) + 2] : null; })()")
    glide(b, here or (x - 150, y - 80), (x, y), 7, rec, ms, dwell=dwell)
    b.send("Input.dispatchMouseEvent", type="mousePressed", x=x, y=y, button="left", buttons=1, clickCount=1)
    b.send("Input.dispatchMouseEvent", type="mouseReleased", x=x, y=y, button="left", buttons=0, clickCount=1)
    b.pump(0.4)


# ── The animated WebP, put together from Chromium's frames ─────────────────────────────────

def _chunks(data: bytes):
    if data[:4] != b"RIFF" or data[8:12] != b"WEBP":
        raise ValueError("not a WebP")
    pos = 12
    while pos + 8 <= len(data):
        tag, size = data[pos:pos + 4], struct.unpack("<I", data[pos + 4:pos + 8])[0]
        yield tag, data[pos + 8:pos + 8 + size]
        pos += 8 + size + (size & 1)


def _chunk(tag: bytes, body: bytes) -> bytes:
    return tag + struct.pack("<I", len(body)) + body + (b"\0" if len(body) & 1 else b"")


def _u24(n: int) -> bytes:
    return struct.pack("<I", n)[:3]


def animated_webp(frames: list[tuple[bytes, int]], width: int, height: int) -> bytes:
    """One animated WebP (looping) from still WebPs of the same size, each shown ``ms``."""
    alpha, body = False, b""
    for data, ms in frames:
        image = [(t, c) for t, c in _chunks(data) if t in (b"ALPH", b"VP8 ", b"VP8L")]
        alpha |= any(t == b"ALPH" for t, _ in image)
        anmf = (_u24(0) + _u24(0) + _u24(width - 1) + _u24(height - 1) + _u24(max(1, min(ms, 0xFFFFFF)))
                + bytes([0b10]) + b"".join(_chunk(t, c) for t, c in image))
        body += _chunk(b"ANMF", anmf)
    vp8x = bytes([0x02 | (0x10 if alpha else 0)]) + b"\0\0\0" + _u24(width - 1) + _u24(height - 1)
    payload = b"WEBP" + _chunk(b"VP8X", vp8x) + _chunk(b"ANIM", b"\0\0\0\0" + struct.pack("<H", 0)) + body
    return b"RIFF" + struct.pack("<I", len(payload)) + payload


# ── The three renderings ───────────────────────────────────────────────────────────────────

RUNS_READY = ("!document.querySelector('#ex-list .empty') && document.getElementById('cat-list').innerText"
              ".includes('T1110.001')")


def render_shots(b: Browser, base: str, token: str, doc: dict, out: Path) -> dict[str, bytes]:
    b.viewport(WIDTH, BOARD_HEIGHT)      # every red card in view, the fault's too
    open_board(b, base, token)
    draw(b, doc["board"])
    board = b.shot("png")
    b.viewport(WIDTH, HEIGHT)
    b.go(f"{base}/dagorlad?view=runs")
    b.wait(RUNS_READY)
    b.pump(1.0)
    runs = b.shot("png")
    return {"board.png": board, "runs.png": runs}


def render_loop(b: Browser, base: str, token: str, doc: dict) -> bytes:
    """10 to 15 s: a wire drawn and its verdict, a refused one taken off, a destructive one that
    asks for the name, the request and the command it gives."""
    open_board(b, base, token)
    rec = Recorder(b)
    (ok, refused, typed) = doc["loop"]
    pointer(b, 520, 640)
    rec.frame(900)
    drag_wire(b, *ok, rec)
    rec.frame(1900)
    drag_wire(b, *refused, rec)
    rec.frame(1800)
    k = b.js("S.wires.length - 1")
    click(b, f"#pills .pill:nth-child({k + 1}) .px", rec)
    rec.frame(500)
    drag_wire(b, *typed, rec)
    rec.frame(1700)
    click(b, "#plan button[data-on-click='request']", rec)
    b.wait("S.request && S.request.command")
    b.pump(0.3)
    rec.frame(3000)
    return animated_webp(rec.frames, round(WIDTH * LOOP_SCALE), round(HEIGHT * LOOP_SCALE))


def render_video(b: Browser, base: str, token: str, doc: dict, ffmpeg: str, path: Path, work: Path) -> Path:
    """The whole tour, as a screencast: the board, the wires and their verdicts, the request,
    « Stop all », the Runs view. An mp4 when ffmpeg has libx264, else a WebM."""
    frames: list[tuple[float, bytes]] = []

    def on_event(m):
        if m.get("method") == "Page.screencastFrame":
            p = m["params"]
            frames.append((p["metadata"]["timestamp"], base64.b64decode(p["data"])))
            b.ws.send(json.dumps({"id": 0, "sessionId": b.session, "method": "Page.screencastFrameAck",
                                  "params": {"sessionId": p["sessionId"]}}))

    b.viewport(WIDTH, BOARD_HEIGHT)
    open_board(b, base, token)
    b.on_event = on_event
    b.send("Page.startScreencast", format="jpeg", quality=85, maxWidth=WIDTH, maxHeight=BOARD_HEIGHT,
           everyNthFrame=1)
    pointer(b, 520, 640)
    b.pump(2.5)
    for pair in doc["board"]:
        drag_wire(b, *pair, None, dwell=0.06)
        b.pump(2.2)
    b.pump(2.0)
    click(b, "#plan button[data-on-click='stopAll']", None, dwell=0.05)
    b.pump(3.5)
    click(b, "#plan .request.stop button[data-on-click='stopAll']", None, dwell=0.05)
    b.pump(1.0)
    refused = [k for k, v in enumerate(b.js("S.plan.wires.map(v => v.code)")) if v]
    for k in reversed(refused):
        click(b, f"#plan tr:nth-child({k + 1}) button[data-on-click='unwire']", None, dwell=0.05)
        b.wait(plan_settled(b.js("S.wires.length")))
        b.pump(1.2)
    click(b, "#plan button[data-on-click='request']", None, dwell=0.05)
    b.wait("S.request && S.request.command")
    b.pump(4.5)
    click(b, "#views a[href='/dagorlad?view=runs']", None, dwell=0.05)
    b.wait(RUNS_READY)
    b.pump(3.0)
    click(b, "#ex-list .row-head[data-toggle]", None, dwell=0.05)     # the newest run, opened
    b.pump(3.5)
    click(b, "#cat-list [data-toggle]", None, dwell=0.05)             # the regressed row, opened
    b.pump(3.5)
    b.send("Page.stopScreencast")
    b.on_event = None
    if not frames:
        raise SystemExit("console_shots: the screencast gave no frame")
    fps, t0, t1 = 25, frames[0][0], frames[-1][0] + 1.0
    stream = work / "frames.mjpeg"
    with open(stream, "wb") as f:
        k, t = 0, t0
        while t < t1:
            while k + 1 < len(frames) and frames[k + 1][0] <= t:
                k += 1
            f.write(frames[k][1])
            t += 1 / fps
    encoders = subprocess.run([ffmpeg, "-hide_banner", "-encoders"], capture_output=True, text=True).stdout
    if "libx264" in encoders:
        path = path.with_suffix(".mp4")
        codec = ["-c:v", "libx264", "-pix_fmt", "yuv420p", "-crf", "24", "-preset", "slow", "-movflags", "+faststart"]
    else:
        path = path.with_suffix(".webm")
        codec = ["-c:v", "libvpx-vp9", "-b:v", "0", "-crf", "36", "-row-mt", "1"]
        print(f"console_shots: {ffmpeg} has no libx264 — the video is a WebM (VP9): {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run([ffmpeg, "-y", "-hide_banner", "-loglevel", "error", "-f", "image2pipe", "-framerate", str(fps),
                    "-c:v", "mjpeg", "-i", f"file:{stream}", "-vf", "scale=trunc(iw/2)*2:trunc(ih/2)*2",
                    *codec, str(path)], check=True)
    return path


# ── The command ────────────────────────────────────────────────────────────────────────────

def _inside_repo(path: Path) -> bool:
    p = path.expanduser().resolve()
    build = (REPO / "build").resolve()
    return (p == REPO or REPO in p.parents) and build not in p.parents


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--sample", type=Path, default=SAMPLE, help="the sample (only the shipped one is rendered)")
    ap.add_argument("--out", type=Path, default=OUT, help="where the images go")
    ap.add_argument("--video", type=Path, help="the whole tour: an mp4 (or a WebM), outside the repository")
    ap.add_argument("--chromium")
    ap.add_argument("--ffmpeg")
    ap.add_argument("--check", action="store_true", help="say which tools are here, render nothing")
    ap.add_argument("--no-images", action="store_true", help="the video only")
    ap.add_argument("--serve", type=Path, help=argparse.SUPPRESS)
    ap.add_argument("--port", type=int, default=0, help=argparse.SUPPRESS)
    args = ap.parse_args(argv)
    if args.serve:
        return serve(args.serve.resolve(), args.port)

    reason = sample_refusal(args.sample)
    if reason:
        print(f"console_shots: refused — {reason}", file=sys.stderr)
        return 2
    if args.video and _inside_repo(args.video):
        print(f"console_shots: refused — the video stays outside the repository ({args.video}); "
              "put it in your scratch directory, or build/ (ignored)", file=sys.stderr)
        return 2
    chromium, ffmpeg = find_chromium(args.chromium), find_ffmpeg(args.ffmpeg)
    missing = missing_tools(chromium, ffmpeg, bool(args.video))
    if args.check:
        print(f"chromium: {chromium or 'missing'}\nffmpeg:   {ffmpeg or 'missing'}")
        for m in missing:
            print(f"missing: {m}")
        return 3 if missing else 0
    if missing:
        for m in missing:
            print(f"console_shots: missing — {m}", file=sys.stderr)
        print("console_shots: nothing rendered; the CI never runs this script", file=sys.stderr)
        return 3

    doc = json.loads(SAMPLE.read_text(encoding="utf-8"))
    token = secrets.token_urlsafe(24)
    with tempfile.TemporaryDirectory(prefix="dagorlad-sample-") as tmp:
        work = Path(tmp)
        materialize(doc, work)
        server, port = start_server(work, token)
        base = f"http://127.0.0.1:{port}"
        browser = Browser(chromium, work / "chrome")
        try:
            if not args.no_images:
                out = args.out
                out.mkdir(parents=True, exist_ok=True)
                images = render_shots(browser, base, token, doc, out)
                images["loop.webp"] = render_loop(browser, base, token, doc)
                for name, data in images.items():
                    (out / name).write_bytes(data)
                    limit = MAX_LOOP if name.endswith(".webp") else MAX_PNG
                    flag = "" if len(data) <= limit else f"  OVER {limit // 1024} KB"
                    print(f"{out / name}  {len(data) / 1024:.0f} KB{flag}")
                manifest = {"rendered_by": "scripts/console_shots.py",
                            "sample": str(SAMPLE.relative_to(REPO)), "sample_sha256": sha256(SAMPLE),
                            "images": {n: hashlib.sha256(d).hexdigest() for n, d in sorted(images.items())}}
                (out / MANIFEST).write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
            if args.video:
                path = render_video(browser, base, token, doc, ffmpeg, args.video.expanduser(), work)
                print(f"{path}  {path.stat().st_size / 1024 / 1024:.1f} MB")
            print(f"page errors (JS, CSP): {len(browser.errors)}")
            for e in browser.errors[:10]:
                print(f"  {e[:200]}")
        finally:
            browser.close()
            server.terminate()
            try:
                server.wait(timeout=10)
            except subprocess.TimeoutExpired:
                server.kill()
    return 0


if __name__ == "__main__":
    sys.exit(main())
