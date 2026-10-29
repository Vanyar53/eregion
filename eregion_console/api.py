from __future__ import annotations

import asyncio
import hmac
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

try:
    from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
    from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
    from fastapi.staticfiles import StaticFiles
except ImportError as e:
    raise ImportError(
        "The Eregion console requires extra dependencies: pip install -e '.[console]' "
        "from the clone"
    ) from e

# No schema, no docs pages: what the console's routes are is not served to whoever asks (SEC1).
app = FastAPI(title="Eregion console", openapi_url=None, docs_url=None, redoc_url=None)


class AmbiguousVM(Exception):
    """A VM name the console sent matches several VMs (same name, two resource groups)."""


@app.exception_handler(AmbiguousVM)
async def _ambiguous_vm(_request, exc: AmbiguousVM):
    from fastapi.responses import JSONResponse
    return JSONResponse(status_code=409, content={"error": str(exc)})

# The session cookie (SEC1): a value derived from the token, never the token itself, under a
# name that carries the port the browser reached (`_cookie_name`) — a browser keeps one jar for
# every port of a host, and two consoles (a team's on 7008, the local one on 7007) would
# overwrite each other's. The former cookie, `glorfindel_warroom`, is no longer read.
_TOKEN_COOKIE = "eregion_console"
TOKEN_ENV = "EREGION_CONSOLE_TOKEN"
LEGACY_TOKEN_ENV = "GLORFINDEL_WARROOM_TOKEN"
# The names, besides the loopback ones, under which this console may be reached (SEC1):
# comma-separated, for an access through another name (a proxy, a host name of the network).
HOSTS_ENV = "EREGION_CONSOLE_HOSTS"
_LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})
# The token drawn at the first start without one (SEC1): the operator's own file, mode 600,
# beside Glorfindel's state (bind-mounted by compose: the same file on the host).
_TOKEN_FILE = Path.home() / ".glorfindel" / "console_token"
_local_token: dict = {"value": ""}
_SESSION_LABEL = b"eregion-console-session/v1"
# Methods that change something: their requests must come from the console's own pages (or a
# script with the token), carry a JSON object, and nothing else (SEC1).
_CHANGES = frozenset({"POST", "PUT", "PATCH", "DELETE"})
_MAX_BODY = 64 * 1024


def console_token() -> str:
    """The token the deployment sets: EREGION_CONSOLE_TOKEN when it is not empty, else its
    former name. Not empty, not merely set: docker compose passes `${VAR:-}`, so the new
    variable is always there, empty on a host whose host.env only has the old one (H0) — read
    as "set", it would drop the token there."""
    return os.environ.get(TOKEN_ENV, "") or os.environ.get(LEGACY_TOKEN_ENV, "")


def _token() -> str:
    """The token every request is checked against: the deployment's, else the one this host
    drew (`ensure_token`). Empty only when neither could be had: every request is refused."""
    return console_token() or _local_token["value"]


def ensure_token() -> tuple[str, str]:
    """The console's token and where it comes from: ``env`` (the deployment sets it — H0),
    ``file`` (drawn at an earlier start, read from ``_TOKEN_FILE``) or ``new`` (drawn now and
    written there, mode 600). There is no console without a token (SEC1). The file is read
    and written without following a symbolic link. OSError when it can be neither read nor
    written (a link included)."""
    token = console_token()
    if token:
        return token, "env"
    path = _TOKEN_FILE
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except FileNotFoundError:
        kept = ""
    else:
        with os.fdopen(fd, "r", encoding="utf-8") as fh:
            if os.fstat(fd).st_mode & 0o077:
                os.fchmod(fd, 0o600)
            kept = fh.read().strip()
    if kept:
        _local_token["value"] = kept
        return kept, "file"
    import secrets
    token = secrets.token_urlsafe(32)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(token + "\n")
    os.chmod(path, 0o600)
    _local_token["value"] = token
    return token, "new"


def _session(token: str) -> str:
    """The cookie's value: derived from the token (HMAC), so the cookie never carries the token
    — it opens the pages and nothing else (not a Bearer, not ?token=) — survives a restart,
    and changes with the token."""
    import hashlib
    return hmac.new(token.encode(), _SESSION_LABEL, hashlib.sha256).hexdigest()


def _cookie_name(host: str, scheme: str) -> str:
    """The session cookie's name for the port the browser reached (the Host's, else the
    scheme's default): one console's cookie never overwrites another's on the same host."""
    from urllib.parse import urlsplit
    try:
        port = urlsplit("//" + host).port
    except ValueError:
        port = None
    return f"{_TOKEN_COOKIE}_{port or (443 if scheme in ('https', 'wss') else 80)}"


def _host_name(netloc: str) -> str | None:
    """The host name of a Host header (or of an entry of EREGION_CONSOLE_HOSTS), lowercased,
    without its port; None when it is not a plain host[:port]."""
    if not netloc or any(c in netloc for c in "/?#@\\ \t,"):
        return None
    from urllib.parse import urlsplit
    try:
        parts = urlsplit("//" + netloc)
        parts.port                      # a port that is not a number raises
    except ValueError:
        return None
    return parts.hostname or None


def _allowed_host(host: str) -> bool:
    """A loopback name, or one EREGION_CONSOLE_HOSTS lists — whatever the port: a tunnel or a
    team's console publishes another port than the one the console listens on. The name is
    what is checked here; the port of a change's origin is checked by the Origin."""
    name = _host_name(host)
    if not name:
        return False
    extra = {_host_name(h.strip()) for h in os.environ.get(HOSTS_ENV, "").split(",") if h.strip()}
    return name in _LOOPBACK_HOSTS or name in extra - {None}


def _same_origin(origin: str, host: str) -> bool:
    """The Origin of a page of this console: its scheme, and exactly the Host it was asked under."""
    origin, host = origin.lower(), host.lower()
    return origin in (f"http://{host}", f"https://{host}")


class _TokenAuthMiddleware:
    """The console's boundary, for every route (pages, API, live feed).

    The console triggers real Azure actions (restore, release, approve & execute) and
    can switch an asset's autonomy mode: it answers its own pages, and scripts with its token.

    In order (SEC1): the Host is a loopback name or one EREGION_CONSOLE_HOSTS lists (403); a
    request that changes something (POST, PUT, PATCH, DELETE, the WebSocket) never comes from
    another origin (403); the token (`_token`: always one), as the session cookie
    (`_cookie_name`: derived from the token) or `Authorization: Bearer <token>`, or `?token=<token>` once
    on a GET, which sets the cookie (HttpOnly, SameSite=Strict, Secure over HTTPS) and
    redirects to the same URL without the token (401 otherwise: a token page for a browser);
    a browser's change carries its Origin (403); and a change carries a JSON object
    (`Content-Type: application/json`, 415 / 400). Pure ASGI so it also covers the WebSocket
    feed, which HTTP middlewares don't see.
    """

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return

        from starlette.requests import HTTPConnection
        conn = HTTPConnection(scope)
        ws = scope["type"] == "websocket"
        changes = ws or scope.get("method", "GET") in _CHANGES
        host = conn.headers.get("host", "")
        origin = conn.headers.get("origin")

        if not _allowed_host(host):
            await _refuse(scope, receive, send, 403,
                          f"Eregion console: unknown host name — list it in {HOSTS_ENV}.")
            return
        if changes and origin is not None and not _same_origin(origin, host):
            await _refuse(scope, receive, send, 403,
                          "Eregion console: a change from another origin is refused.")
            return

        token = _token()
        if not token:
            await _refuse(scope, receive, send, 503,
                          f"Eregion console: no token ({TOKEN_ENV}, or {_TOKEN_FILE} unreadable).")
            return

        def _ok(candidate: str | None, expected: str) -> bool:
            return bool(candidate) and hmac.compare_digest(candidate.encode(), expected.encode())

        bearer = conn.headers.get("authorization", "")
        bearer = bearer[7:] if bearer.lower().startswith("bearer ") else ""
        by_bearer = _ok(bearer, token)
        cookie = _cookie_name(host, scope.get("scheme", "http"))
        by_cookie = _ok(conn.cookies.get(cookie), _session(token))

        if not (by_bearer or by_cookie):
            if not ws and scope.get("method") in ("GET", "HEAD") and _ok(conn.query_params.get("token"), token):
                from urllib.parse import urlencode
                from starlette.responses import RedirectResponse
                query = urlencode([(k, v) for k, v in conn.query_params.multi_items() if k != "token"])
                # One leading slash: `//name` would send the browser to another host.
                target = "/" + conn.url.path.lstrip("/") + (f"?{query}" if query else "")
                resp = RedirectResponse(target, status_code=303)
                resp.set_cookie(cookie, _session(token), httponly=True, samesite="strict",
                                secure=scope.get("scheme") == "https")
                await resp(scope, receive, send)
                return
            if ws:
                await _refuse(scope, receive, send, 401, "")
                return
            if "text/html" in conn.headers.get("accept", ""):
                # A browser navigating here: a page that asks for the token (GET form →
                # ?token=… → cookie + redirect above), not a raw JSON error.
                from starlette.responses import HTMLResponse
                await HTMLResponse(_TOKEN_PAGE, status_code=401)(scope, receive, send)
                return
            await _refuse(scope, receive, send, 401,
                          f"Eregion console: open /?token=<{TOKEN_ENV}> once, or send "
                          "Authorization: Bearer <token>.")
            return

        if changes and not by_bearer and origin is None:
            # The cookie is a browser's, and a browser says where a change comes from.
            await _refuse(scope, receive, send, 403,
                          "Eregion console: a change without its origin is refused.")
            return
        if changes and not ws:
            receive = await _json_body(scope, receive, send)
            if receive is None:
                return
        await self.app(scope, receive, send)


async def _refuse(scope, receive, send, status: int, error: str) -> None:
    """A refusal: a JSON error, or, for the live feed, the WebSocket closed before it opens."""
    if scope["type"] == "websocket":
        await receive()  # websocket.connect
        await send({"type": "websocket.close", "code": 1008})
        return
    from starlette.responses import JSONResponse
    await JSONResponse({"error": error}, status_code=status)(scope, receive, send)


async def _json_body(scope, receive, send):
    """A change's body: a JSON object, `Content-Type: application/json`, at most _MAX_BODY.
    Read whole, then handed to the route as it came; None once refused (sent)."""
    from starlette.datastructures import Headers
    media = Headers(scope=scope).get("content-type", "").split(";")[0].strip().lower()
    if media != "application/json":
        await _refuse(scope, receive, send, 415,
                      "Eregion console: a change carries a JSON object (Content-Type: application/json).")
        return None
    chunks, size = [], 0
    while True:
        message = await receive()
        if message["type"] == "http.disconnect":
            return None
        chunk = message.get("body", b"")
        size += len(chunk)
        if size > _MAX_BODY:
            await _refuse(scope, receive, send, 413, "Eregion console: body too large.")
            return None
        chunks.append(chunk)
        if not message.get("more_body"):
            break
    body = b"".join(chunks)
    try:
        parsed = json.loads(body) if body else None
    except ValueError:
        parsed = None
    if not isinstance(parsed, dict):
        await _refuse(scope, receive, send, 400, "Eregion console: a change carries a JSON object.")
        return None
    replayed = False

    async def replay():
        nonlocal replayed
        if not replayed:
            replayed = True
            return {"type": "http.request", "body": body, "more_body": False}
        return await receive()
    return replay


_TOKEN_PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Eregion — token</title>
<style>
  :root { color-scheme: dark; }
  body { margin: 0; min-height: 100vh; display: grid; place-items: center; padding: 16px;
         background: #0d1117; color: #e6edf3;
         font: 14px/1.5 ui-monospace, "Cascadia Code", "SF Mono", Consolas, monospace; }
  form { display: grid; gap: 12px; width: min(100%, 26rem); padding: 24px;
         border: 1px solid #30363d; border-radius: 8px; background: #161b22; }
  h1 { margin: 0; font-size: 16px; }
  p { margin: 0; color: #7d8590; }
  input, button { font: inherit; padding: 8px 10px; border-radius: 6px; }
  input { background: #0d1117; color: #e6edf3; border: 1px solid #30363d; }
  input:focus-visible, button:focus-visible { outline: 2px solid #58a6ff; outline-offset: 2px; }
  button { background: #1f6feb; color: #fff; border: 0; cursor: pointer; }
</style></head><body>
<form method="get" action="">
  <h1>EREGION</h1>
  <p>This console can trigger Azure actions. Enter its token: the one set in
     <code>EREGION_CONSOLE_TOKEN</code> on the machine that hosts it, else the one the console
     drew at its first start, in <code>~/.glorfindel/console_token</code> there.</p>
  <label for="token">Token</label>
  <input id="token" name="token" type="password" autocomplete="current-password" required autofocus>
  <button type="submit">Open</button>
</form></body></html>"""


app.add_middleware(_TokenAuthMiddleware)

_STATIC = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=str(_STATIC)), name="static")
# The pages, served as files: one per section (/config is the Glorfindel page, opened on its
# configuration; /annatar and /gothmog share one page, filtered by the path).
_PAGES = {"/": "overview.html", "/glorfindel": "glorfindel.html", "/config": "glorfindel.html",
          "/annatar": "injector.html", "/gothmog": "injector.html"}


# Defence in depth for pages that show what other hosts wrote (manifests from Orodruin): never
# framed by another page (clickjacking on Approve & execute), never talking to another origin,
# no <base>, forms to this origin only (the token page) (#222). Scripts from this origin only, as
# files: no inline script, no on… handler, no javascript: URL, no eval — what an injection would
# write, refused even if escaping missed it (#257); no plugin either. Anything else from this
# origin only (SEC1): no image, font or stylesheet from elsewhere — styles may be inline (the
# pages' <style> and style="…", what the scripts write; a style runs no code).
_CSP = ("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self'; "
        "object-src 'none'; frame-ancestors 'none'; connect-src 'self'; base-uri 'none'; "
        "form-action 'self'")
# On every response too (SEC1): a file is what its type says, and no address of the console
# (a ?token= one included) leaves in a Referer.
_HEADERS = {"Content-Security-Policy": _CSP, "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer"}


@app.middleware("http")
async def _page_headers(request, call_next):
    """The CSP and the other headers on every response, the token page's and the boundary's
    refusals included (this middleware is the outermost). Pages and their scripts revalidate
    on every load (ETag): after a redeployment, a page left in the browser's cache showed the
    old console on H0 (#197)."""
    response = await call_next(request)
    if request.url.path in _PAGES or request.url.path.startswith("/static/"):
        response.headers["Cache-Control"] = "no-cache"
    response.headers.update(_HEADERS)
    return response


@app.on_event("startup")
async def _warm_up_azure() -> None:
    """Import the Azure SDK once, single-threaded, before any request thread.

    api.py runs Azure calls in threads outside audit.run (approve→isolate, snapshot,
    verify) via asyncio.to_thread; warming up here closes the concurrent-first-import
    race window for all of them (per Glorfindel 23c2f88). Idempotent + best-effort.
    """
    try:
        from glorfindel.actions import warm_up_azure_sdk
        await asyncio.to_thread(warm_up_azure_sdk)
    except Exception:
        pass


@app.on_event("startup")
async def _read_enrollment() -> None:
    """H-1: a window marks a VM only if that VM is enrolled, read by the reader itself. The
    watch sets that check at startup (glorfindel/cli.py); the console sets the same, with the
    same identity on H0, so the injectors' pages show Glorfindel's reading — without it, no
    window would mark anything here, and no run of a published campaign would be kept."""
    from eregion_core import exercise
    from eregion_core.inscription import TagEnrollment
    exercise.set_enrollment_check(TagEnrollment())


@app.on_event("startup")
async def _have_a_token() -> None:
    """The token, before the first request — also when the app is served without `serve`. The
    file unreadable: said, and every request is refused (no console without a token)."""
    try:
        ensure_token()
    except OSError as exc:
        print(f"  ✗ console token: {_TOKEN_FILE} unreadable ({exc}) — every request is refused; "
              f"set {TOKEN_ENV}.", flush=True)


@app.on_event("startup")
async def _say_which_token() -> None:
    """Both token variables set, with two values: the new one is the token — said once, so an
    operator who still types the old one knows why it is refused."""
    new, old = os.environ.get(TOKEN_ENV, ""), os.environ.get(LEGACY_TOKEN_ENV, "")
    if new and old and new != old:
        print(f"  ⚠ {TOKEN_ENV} and {LEGACY_TOKEN_ENV} differ: the console takes {TOKEN_ENV}.", flush=True)


def _page(name: str):
    async def page() -> FileResponse:
        return FileResponse(_STATIC / name)
    return page


for _path, _file in _PAGES.items():
    app.add_api_route(_path, _page(_file), methods=["GET"], include_in_schema=False)


def _with_query(path: str, request) -> str:
    q = request.url.query
    return path + (f"?{q}" if q else "")


@app.get("/atelier", include_in_schema=False)
async def atelier_moved(request: Request):
    """The atelier became the injectors' sections: its address leads to the overview."""
    return RedirectResponse(_with_query("/", request), status_code=308)


@app.get("/api/atelier/{rest:path}", include_in_schema=False)
async def atelier_api_moved(rest: str, request: Request):
    """The atelier's API lost its prefix (/api/atelier/exercises → /api/exercises), until 1.0:
    a page left in a browser's cache still reads."""
    return RedirectResponse(_with_query(f"/api/{rest}", request), status_code=308)


@app.get("/runs/{run_id}", include_in_schema=False)
async def run_page(run_id: str):
    """A run's page, in the section of its injector — what a card knows is the run id only."""
    from eregion_core.exercise_channel import safe_part
    if not safe_part(run_id):
        return JSONResponse({"error": "run id: a plain name"}, status_code=400)
    return RedirectResponse(f"/{_injector_of(run_id)}?run={quote(run_id)}", status_code=302)


def _injector_of(run_id: str) -> str:
    """Gothmog when its window or its report says so; Annatar otherwise (a purged window's
    tombstone names no injector; Annatar's reports do not name theirs)."""
    from eregion_core.exercise import exercises_dir
    for path in (exercises_dir(_RUNS) / f"{run_id}.json", _run_reports().get(run_id)):
        try:
            data = json.loads(path.read_text(encoding="utf-8")) if path else None
        except (OSError, ValueError):
            continue
        if not isinstance(data, dict):
            continue
        metrics = data.get("metrics") if isinstance(data.get("metrics"), dict) else {}
        if "gothmog" in (data.get("injector"), metrics.get("injector")):
            return "gothmog"
    return "annatar"


@app.get("/api/sections")
async def sections_status() -> dict:
    """Glorfindel, and each injector active or greyed on this host, and why
    (eregion_console/sections.py); and whether this console only reads (observe-only)."""
    from eregion_console import sections
    try:
        out = await asyncio.to_thread(sections.status, _RUNS)
    except ValueError as exc:
        return {"error": str(exc)}
    return {**out, "read_only": _read_only(), "version": sections.version()}


# What Glorfindel closed itself, with a note (A3: an orphan rule taken off alone — a write
# on Azure no open card says): shown on its tile for a day (Jonathan, 27/10). A card a human
# acknowledged carries no note.
_HANDLED_FOR_H = 24.0


def _handled(now: datetime) -> list[dict]:
    from glorfindel import escalations as esc_module
    out = []
    for e in esc_module.all_escalations():
        if e.get("status") != "resolved" or not e.get("resolution"):
            continue
        try:
            at = datetime.fromisoformat(e.get("resolved_at") or "")
        except (TypeError, ValueError):
            continue
        if at.tzinfo is None:
            at = at.replace(tzinfo=timezone.utc)
        if (now - at).total_seconds() <= _HANDLED_FOR_H * 3600:
            out.append({k: e.get(k, "") for k in
                        ("id", "resource_id", "escalation_type", "resolution", "resolved_at")})
    return out


@app.get("/api/state")
async def state() -> dict:
    from glorfindel import escalations as esc_module
    from glorfindel.actions import active_blocks, active_isolations

    now = datetime.now(timezone.utc)
    isolations = {i["resource_id"]: i for i in active_isolations()}
    blocks: dict[str, list] = {}
    for b in active_blocks():
        blocks.setdefault(b["resource_id"], []).append(b)

    resources = []
    for resource_id in sorted(set(isolations) | set(blocks)):
        vm_name = resource_id.split("/")[-1]
        states = []
        if resource_id in isolations:
            _iso = isolations[resource_id]
            states.append({
                "type": "isolated",
                "since": _iso.get("isolated_at", ""),
                "nsg_scope": _iso.get("nsg_scope", ""),  # "nic" | "subnet"
                "nsg": _iso.get("nsg_name", "") or _iso.get("nsg", ""),
                # placements[] = one deny placement per NIC (multi-NIC coverage). The UI
                # shows "N NICs" when >1 so the operator sees full coverage, not just one NSG.
                "placements": _iso.get("placements", []),
                **_state_flags(_iso.get("placements", [])),
                # partial: some NICs only (a placement failed) — or a release that could
                # not remove every rule. Never shown as a plain ISOLATED.
                "partial": bool(_iso.get("partial")),
                "failed_nic": _iso.get("failed_nic", ""),
                "release_failed": _iso.get("release_failed", []),
                # NICs isolated by rules only: Azure's DNS / IMDS still reachable (S7).
                "platform_open": _platform_open_nics(_iso.get("placements", [])),
                # Last time the watch re-read Azure and found the isolation in place.
                "verified_at": _iso.get("verified_at", ""),
                # Open sessions cut after the rules? (drain: drained|partial|failed|unsupported)
                "drain": _iso.get("drain") or {},
            })
        for b in blocks.get(resource_id, []):
            states.append({
                "type": "blocked",
                "ip": b["ip"],
                "since": b.get("blocked_at", ""),
                "nsg_scope": b.get("nsg_scope", ""),
                "nsg": b.get("nsg", ""),       # "rg/name" of the NSG holding the rule
                "rule": b.get("rule", ""),
                "scoped": b.get("scoped", True),  # False once promoted subnet-wide
                "placements": b.get("placements", []),  # one rule per NIC (multi-NIC block)
                **_state_flags(b.get("placements", [])),
                "partial": bool(b.get("partial")),
                "unblock_failed": b.get("unblock_failed", []),
                "verified_at": b.get("verified_at", ""),
            })
        resources.append({
            "resource_id": resource_id,
            "vm_name": vm_name,
            "states": states,
        })

    # Discovered assets — fresh read from disk (watch service may have updated the file)
    discovered: list[dict] = []
    try:
        from glorfindel.discovery import AssetRegistry
        discovered = AssetRegistry().to_dicts()
    except Exception:
        pass

    # Posture gaps (infrastructure readiness issues)
    posture_gaps: list[dict] = []
    try:
        from glorfindel.posture import PostureChecker
        from glorfindel.config import load_glorfindel_config
        _gcfg = load_glorfindel_config()
        _pc = PostureChecker(_gcfg, None, dry_run=True)
        posture_gaps = _pc.active_gaps()
    except Exception:
        pass

    pending_escalations = esc_module.pending()
    handled = _handled(now)

    # Autonomy modes — resolved for EVERY VM the UI can render (discovered assets,
    # isolated/blocked resources, and escalation targets). Resolving only discovered
    # assets left escalation-only cards (e.g. a mode_hold target) falling back to the
    # global default, so a per-asset override never showed in the card.
    autonomy_modes: dict[str, str] = {}
    autonomy_holds: dict[str, dict] = {}   # configured autonomous, held by readiness (L6)
    autonomy_default = "human_only"
    try:
        from glorfindel.config import load_glorfindel_config as _load_gcfg
        _acfg = _load_gcfg()
        autonomy_default = _acfg.autonomy.default
        _vm_names: set[str] = set()
        for _a in discovered:
            _n = _a.get("name") or _a.get("resource_id", "").split("/")[-1]
            if _n:
                _vm_names.add(_n)
        for _r in resources:
            if _r.get("vm_name"):
                _vm_names.add(_r["vm_name"])
        for _e in pending_escalations:
            _rid = _e.get("resource_id", "")
            if _rid:
                _vm_names.add(_rid.split("/")[-1])
        from glorfindel.readiness import effective_mode as _effective
        # The gate reads readiness by resource id: so must the display (fifth review,
        # C4 — by name, homonyms showed "human_only" while one acted alone).
        _rids: dict[str, set] = {}
        for _a in discovered:
            if _a.get("resource_id"):
                _rids.setdefault(_a.get("name") or _a["resource_id"].split("/")[-1], set()).add(_a["resource_id"])
        for _r in resources:
            if _r.get("vm_name") and _r.get("resource_id"):
                _rids.setdefault(_r["vm_name"], set()).add(_r["resource_id"])
        for _n in _vm_names:
            _conf = _acfg.autonomy.resolve(_n)
            _ids = sorted(_rids.get(_n, set()), key=str.lower)
            _ids = list({i.lower(): i for i in _ids}.values())
            if len(_ids) > 1:
                # Homonyms: show the MOST permissive effective mode, and say it is ambiguous.
                _modes = [_effective(i, _conf)[0] for i in _ids]
                autonomy_modes[_n] = "non_disruptive" if "non_disruptive" in _modes else "human_only"
                autonomy_holds[_n] = {"reason": "ambiguous", "codes": [], "configured": _conf,
                                      "message": f"{len(_ids)} VMs portent ce nom — modes : "
                                                 + ", ".join(_modes)}
                continue
            autonomy_modes[_n], _hold = _effective(_ids[0] if _ids else _n, _conf)
            if _hold:
                autonomy_holds[_n] = _hold
    except Exception:
        pass

    from glorfindel.config import read_only_requested
    read_only = read_only_requested()

    # Autonomy capability matrix — what runs alone vs is always gated (UI popover).
    # Constants are stable per Glorfindel; import from actions (single source).
    capability: dict = {}
    try:
        from glorfindel.actions import AUTONOMOUS_ACTIONS, HUMAN_APPROVAL_REQUIRED
        from glorfindel.config import confidence_threshold
        _allow: list = []
        try:
            _allow = list(_acfg.autonomy.allow_destructive)
        except Exception:
            pass
        capability = {
            "autonomous_actions": sorted(AUTONOMOUS_ACTIONS),
            "gated_actions": sorted(HUMAN_APPROVAL_REQUIRED),
            "allow_destructive": _allow,
            # The gate's own reading (G2): a malformed value holds every action — shown
            # as 100 %, never as the 70 % it no longer is (nor a NaN in the JSON).
            # Read from config, not the agent: the War Room never imports the agent
            # for it, and a failed import would drop the whole matrix (G2 review).
            "confidence_threshold": min(confidence_threshold(), 1.0),
        }
    except Exception:
        pass

    return {
        "resources": resources,
        "escalations": pending_escalations,
        "handled": handled,
        "restores": _active_restores(),
        "restore_failures": _restore_failures(),
        "discovered_assets": discovered,
        "posture_gaps": posture_gaps,
        "active_jobs": _all_jobs(),
        "autonomy_modes": autonomy_modes,
        "autonomy_holds": autonomy_holds,
        "autonomy_default": autonomy_default,
        "read_only": read_only,
        "capability": capability,
        "now": now.isoformat(),
    }


def _platform_open_nics(placements) -> list[str]:
    from glorfindel.actions import platform_open_nics
    return platform_open_nics(placements)


def _state_flags(placements: list) -> dict:
    """Per-state flags the cards need: a NIC-level NSG shared with other NICs (treated
    like a subnet NSG), and ALLOW rules recorded as evaluated before our deny."""
    found = [s for p in placements for s in (p.get("shadowed_by") or [])]
    return {
        "shared": any(p.get("shared_nsg") for p in placements),
        # Bypass = the threat itself gets through; exposure = other ports stay reachable
        # (a block whose threat port is known). Exposure must not light ⚠ bypassed.
        "shadowed": [s for s in found if s.get("threat_port_open", True)],
        "exposure": [s for s in found if not s.get("threat_port_open", True)],
        "moved": [p["moved_from"] for p in placements if p.get("moved_from")],
    }


@app.get("/api/watch/status")
async def watch_status() -> dict:
    """Heartbeat-based: watch writes ~/.glorfindel/watch_heartbeat every ~60s."""
    hb = Path.home() / ".glorfindel" / "watch_heartbeat"
    if not hb.exists():
        return {"status": "stopped"}
    try:
        ts = datetime.fromisoformat(hb.read_text().strip())
        age_s = (datetime.now(timezone.utc) - ts).total_seconds()
        if age_s < 90:
            return {
                "status": "running",
                "since": ts.isoformat(),
                "age_s": int(age_s),
            }
        return {"status": "stale", "age_s": int(age_s)}
    except Exception:
        return {"status": "unknown"}


def _mask(value: str) -> str:
    """An identifier as Config shows it: its first 8 and last 4 characters, '' when unset."""
    return f"{value[:8]}…{value[-4:]}" if value else ""


@app.get("/api/config")
async def config() -> dict:
    import os

    subscription = os.environ.get("AZURE_SUBSCRIPTION_ID", "")
    tenant = os.environ.get("AZURE_TENANT_ID", "")
    client_id = os.environ.get("AZURE_CLIENT_ID", "")

    # Load Glorfindel infra config (glorfindel-config.yaml)
    try:
        from glorfindel.config import load_glorfindel_config
        glorfindel_cfg = load_glorfindel_config()
        glorfindel_cfg_dict = {
            "monitoring_backends": [
                {"name": b.name, "type": b.type,
                 "discovery_enabled": b.discovery.enabled,
                 "discovery_interval_s": b.discovery.interval_s}
                for b in glorfindel_cfg.monitoring_backends
            ],
            "action_backends": [
                {"name": b.name, "type": b.type, "vault_name": b.vault_name}
                for b in glorfindel_cfg.action_backends
            ],
            "exceptions_count": len(glorfindel_cfg.exceptions),
        }
    except Exception:
        glorfindel_cfg_dict = {"monitoring_backends": [], "action_backends": [], "exceptions_count": 0}

    # Detection config (backends, assets, rules)
    rules_info: list[dict] = []
    known_resources: list[dict] = []
    backends_info: list[dict] = []
    assets_info: list[dict] = []
    detection_is_inert = False  # True if no rule can poll → detection fires nothing
    rules_path = _base_rules_path()
    if rules_path:
        try:
            from glorfindel.detection_rules import (
                _load_status,
                detection_inert,
                load_config,
            )
            cfg = load_config(rules_path, glorfindel_cfg=glorfindel_cfg)
            status = _load_status()
            detection_is_inert = detection_inert(cfg.rules)

            # Per-backend reachability from rule poll status. A backend whose rules are
            # erroring is unreachable (deleted LAW / IAM revoked / wrong GUID) — surfaced
            # so the War Room can red the DETECT node instead of showing it green while
            # detection is blind. Needs the detector to actually record last_error on a
            # failed query (it used to swallow failures as empty results).
            backend_state: dict[str, dict] = {}
            for rule in cfg.rules:
                bn = rule.monitoring_backend_name
                if not bn:
                    continue
                s = status.get(rule.name, {})
                st = backend_state.setdefault(bn, {"polled": False, "error": ""})
                if s.get("last_poll"):
                    st["polled"] = True
                if s.get("last_error") and not st["error"]:
                    st["error"] = s["last_error"]

            for b in cfg.backends:
                st = backend_state.get(b.name)
                if st is None:
                    reachable, backend_error = None, ""        # no rule bound yet
                elif st["error"]:
                    reachable, backend_error = False, st["error"]
                else:
                    reachable, backend_error = (True if st["polled"] else None), ""
                # No workspace id nor endpoint (SEC1): the page shows neither.
                backends_info.append({
                    "name": b.name,
                    "type": b.type,
                    "reachable": reachable,
                    "last_error": backend_error,
                })

            # Action backends (RSV, storage...) from glorfindel-config.yaml
            for b in glorfindel_cfg.action_backends:
                assets_info.append({
                    "name": b.name,
                    "type": b.type,
                    "resource_id": "",
                    "monitoring_backends": [],
                    "vault_name": b.vault_name,
                    "resource_group": b.resource_group,
                })

            for rule in cfg.rules:
                s = status.get(rule.name, {})
                rules_info.append({
                    "name": rule.name,
                    "ttp": rule.ttp,
                    "source": rule.source,
                    "description": rule.description,
                    "query": rule.query,
                    "interval_s": rule.interval_s,
                    "asset_name": rule.asset_name,
                    "monitoring_backend_name": rule.monitoring_backend_name,
                    "enabled": rule.enabled,
                    "last_poll": s.get("last_poll", ""),
                    "last_match": s.get("last_match", ""),
                    "last_error": s.get("last_error", ""),
                    "match_count": s.get("match_count", 0),
                })
        except Exception:
            pass

    from eregion_core.models import glorfindel_model
    llm_model = glorfindel_model()
    llm_provider = llm_model.split("/")[0] if "/" in llm_model else llm_model

    # Masked, as the page shows them (SEC1): enough to recognise a subscription or an
    # identity, never the identifiers themselves.
    return {
        "azure": {
            "subscription_id": _mask(subscription),
            "tenant_id": _mask(tenant),
            "client_id": _mask(client_id),
            "configured": bool(subscription and tenant and client_id),
        },
        "llm": {
            "model": llm_model,
            "provider": llm_provider,
            "base_url": os.environ.get("GLORFINDEL_LLM_BASE_URL", ""),
            # Where the model comes from — shown, never set here: changing who decides is a
            # deployment change (harness, end-to-end run), not a War Room setting.
            "source": "deployment" if os.environ.get("GLORFINDEL_LLM_MODEL") else "default",
        },
        "detection": {
            "rules": rules_info,
            "rules_file": str(rules_path) if rules_path else None,
            "inert": detection_is_inert,
        },
        "monitoring_backends": backends_info,
        "assets": assets_info,
        "known_resources": known_resources,
        "glorfindel_config": glorfindel_cfg_dict,
    }


@app.get("/api/feed/history")
async def feed_history() -> dict:
    return {"entries": _load_recent(40)}


@app.websocket("/api/feed")
async def feed_ws(ws: WebSocket) -> None:
    await ws.accept()

    positions: dict[str, int] = {}
    runs = Path("runs")

    def _init() -> None:
        if not runs.exists():
            return
        for pat in ("*_signals.jsonl", "*_debug.jsonl", "manual_actions.jsonl"):
            for f in runs.glob(pat):
                positions[str(f)] = f.stat().st_size

    _init()

    for entry in _load_recent(40):
        await ws.send_json(entry)

    try:
        while True:
            await asyncio.sleep(2)
            if not runs.exists():
                continue
            for pat, kind in (
                ("*_signals.jsonl", "signal"),
                ("*_debug.jsonl", "action"),
                ("manual_actions.jsonl", "action"),
            ):
                for f in runs.glob(pat):
                    key = str(f)
                    # Files not seen at _init() are new — read from start
                    prev = positions.get(key, 0)
                    cur = f.stat().st_size
                    if cur <= prev:
                        positions[key] = cur
                        continue
                    with open(f) as fh:
                        fh.seek(prev)
                        for raw in fh:
                            raw = raw.strip()
                            if not raw:
                                continue
                            try:
                                entry = _parse(json.loads(raw), kind)
                                await ws.send_json(entry)
                            except Exception:
                                pass
                        positions[key] = fh.tell()
    except WebSocketDisconnect:
        pass


_IAM_GAP_MSG = (
    "Permission denied — the service principal lacks the Azure role to perform this "
    "action (IAM gap, not the read-only flag). Grant the required role (e.g. Network "
    "Contributor on the NSG) or run the action via the CLI."
)


def _is_auth_gap(text: str) -> bool:
    low = (text or "").lower()
    return "authorizationfailed" in low or "does not have authorization" in low


def _friendly_azure_error(exc: Exception, action: str = "") -> dict:
    """Turn a raw Azure SDK error into a concise, actionable message for the UI.

    Detects the IAM capability gap (403 AuthorizationFailed): credentials flagged
    read-write but the SP can't perform the write — same gap the watch path surfaces
    as `write_blocked`. Otherwise keeps the first sentence, dropping the SDK's
    duplicated `Code:/Message:` tail.
    """
    raw = str(exc)
    if _is_auth_gap(raw):
        return {"error": _IAM_GAP_MSG, "capability_gap": True}
    first = raw.split(" Code:")[0].split("\n")[0].strip()
    return {"error": (first or raw)[:300]}


def _subprocess_result(result: "subprocess.CompletedProcess[str]") -> dict:
    """Normalise subprocess result — surfaces PermissionError / IAM gap from stderr."""
    stderr = result.stderr or ""
    permission_denied = "read-only" in stderr.lower() or "PermissionError" in stderr
    auth_gap = _is_auth_gap(stderr)
    out = {
        "stdout": result.stdout,
        "stderr": stderr,
        "ok": result.returncode == 0 and not permission_denied and not auth_gap,
    }
    if permission_denied:
        out.update({"permission_denied": True, "error": stderr.strip()})
    elif auth_gap:
        out.update({"capability_gap": True, "error": _IAM_GAP_MSG})
    return out


@app.post("/api/action/release/{vm_name}")
async def action_release(vm_name: str) -> dict:
    """Release isolation only — use after restore when the VM is clean."""
    resource_id = _find_resource_id(vm_name)
    if not resource_id:
        return {"error": f"No active isolation found for {vm_name}"}
    result = await asyncio.to_thread(
        subprocess.run,
        [_bin(), "release", resource_id, "--yes"],
        capture_output=True, text=True, timeout=600,   # a multi-NIC release takes minutes; cut midway = half released
    )
    return _subprocess_result(result)


@app.post("/api/action/revert/{vm_name}")
async def action_revert(vm_name: str) -> dict:
    """Full reset — release isolation + unblock all IPs."""
    resource_id = _find_resource_id(vm_name)
    if not resource_id:
        return {"error": f"No active actions found for {vm_name}"}
    result = await asyncio.to_thread(
        subprocess.run,
        [_bin(), "reset", resource_id, "--yes"],
        capture_output=True, text=True, timeout=600,   # a multi-NIC release takes minutes; cut midway = half released
    )
    return _subprocess_result(result)


def _all_jobs() -> list[dict]:
    try:
        from glorfindel.jobs import all_jobs
        return all_jobs()
    except Exception:
        return []


@app.get("/api/jobs/{vm_name}")
async def get_job_status(vm_name: str, refresh: bool = False) -> dict:
    """Return the active job for a VM. Pass ?refresh=true to poll Azure for status."""
    from glorfindel.jobs import get_job, refresh_job, save_job
    job = get_job(vm_name)
    if not job:
        return {}
    if refresh and job.get("status") == "InProgress":
        from glorfindel.actions import AzureConnector
        before = job.get("status")
        await asyncio.to_thread(refresh_job, job, AzureConnector(dry_run=False))
        if job.get("status") != before:
            await asyncio.to_thread(save_job, vm_name, job)
    return job


_CFG_READONLY_MSG = "Config file is read-only — edit glorfindel-config.yaml directly (or remount without :ro)"


def _resolve_vm(vm_name: str) -> str | None:
    """resource_id of a VM by name: detection rules first, then discovered assets."""
    rid = _find_resource_id(vm_name)
    if rid:
        return rid
    from glorfindel.discovery import AssetRegistry
    for asset in AssetRegistry().all():
        if asset.name == vm_name or asset.resource_id.split("/")[-1] == vm_name:
            return asset.resource_id
    return None


def _assess_vm(vm_name: str) -> dict:
    from glorfindel.actions import AzureConnector
    from glorfindel.readiness import assess
    rid = _resolve_vm(vm_name)
    if not rid:
        return {"error": f"resource_id not found for {vm_name}"}
    try:
        from glorfindel.config import load_glorfindel_config
        quarantine = load_glorfindel_config().isolation.quarantine_nsg
    except Exception:
        quarantine = True
    return assess(rid, AzureConnector(dry_run=False), quarantine_nsg=quarantine)


@app.get("/api/readiness/{vm_name}")
async def readiness(vm_name: str) -> dict:
    """Can Glorfindel act on this VM? Verdict (ready / reserve / not_ready) and reasons,
    computed from Azure without writing anything — what the activation screen shows."""
    return await asyncio.to_thread(_assess_vm, vm_name)


def _read_only() -> bool:
    # The connector's reading, not a stricter one of its own (G2): `on` or `TRUE` used to
    # leave the War Room's autonomy menus open on a read-only deployment.
    from glorfindel.config import read_only_requested
    return read_only_requested()


# Observe-only: Glorfindel decides, a human judges, nothing acts — the autonomy mode stays
# human_only. Changing it from the War Room would only produce write_blocked cards (and
# undid the human_only forced on the hosted VM, H0).
_READ_ONLY_MODE = ("observe-only (read-only credentials): the autonomy mode is locked to "
                   "human-only")


@app.post("/api/activate/{vm_name}")
async def activate(vm_name: str, body: dict | None = None) -> dict:
    """Switch a VM to autonomous response (non_disruptive). Recomputes the readiness
    verdict and refuses a VM that isn't ready, or one whose reserves were not all
    acknowledged (`acknowledged`: the reserve codes the operator was shown)."""
    if _read_only():
        return {"error": _READ_ONLY_MODE}
    from glorfindel.readiness import activation_refusal
    assessment = await asyncio.to_thread(_assess_vm, vm_name)
    if "error" in assessment:
        return assessment
    refusal = activation_refusal(assessment, (body or {}).get("acknowledged"))
    if refusal:
        return {"error": refusal, "readiness": assessment}
    try:
        from glorfindel.config import set_asset_mode
        path = await asyncio.to_thread(set_asset_mode, vm_name, "non_disruptive")
    except OSError:
        return {"error": _CFG_READONLY_MSG}
    except Exception as e:
        return {"error": str(e)}
    # What the operator was shown and accepted: the watch's gate reads it (a reserve
    # that appears later puts the VM back in human_only).
    from glorfindel import readiness as _rd
    rid = _resolve_vm(vm_name) or ""
    await asyncio.to_thread(_rd.record_assessment, assessment, rid)
    await asyncio.to_thread(_rd.acknowledge, rid or assessment["vm"], assessment["reserve_codes"], "war-room")
    await asyncio.to_thread(_rd.resolve_card, rid or assessment["vm"])
    return {"ok": True, "vm": vm_name, "mode": "non_disruptive", "path": str(path),
            "acknowledged": assessment["reserve_codes"]}


@app.post("/api/autonomy/{vm_name}")
async def set_autonomy_mode(vm_name: str, body: dict) -> dict:
    """Set the autonomy mode for an asset and persist to glorfindel-config.yaml.

    Switching TO autonomous response goes through the readiness check, like
    /api/activate: no VM leaves human_only without its reserves having been shown."""
    if _read_only():
        return {"error": _READ_ONLY_MODE}
    mode = body.get("mode", "")
    if mode == "non_disruptive":
        return await activate(vm_name, body)
    try:
        from glorfindel.config import set_asset_mode
        path = await asyncio.to_thread(set_asset_mode, vm_name, mode)
        if mode == "human_only":
            # Back to observation: a later activation shows the reserves again.
            from glorfindel import readiness as _rd
            await asyncio.to_thread(_rd.revoke, vm_name)
            await asyncio.to_thread(_rd.resolve_card, vm_name)
        return {"ok": True, "vm": vm_name, "mode": mode, "path": str(path)}
    except ValueError as e:
        return {"error": str(e)}
    except OSError:
        return {"error": _CFG_READONLY_MSG}
    except Exception as e:
        return {"error": str(e)}


@app.patch("/api/config/autonomy/default")
async def set_autonomy_default(body: dict) -> dict:
    """Set the global default autonomy mode and persist to glorfindel-config.yaml.

    Autonomous by default is safe for VMs created later: the watch checks each VM it
    discovers, and only a ready one acts alone (L6 gate); the others stay in human_only
    with a card asking to confirm their reserves."""
    if _read_only():
        return {"error": _READ_ONLY_MODE}
    mode = body.get("mode", "")
    try:
        from glorfindel.config import set_default_mode
        path = await asyncio.to_thread(set_default_mode, mode)
        out = {"ok": True, "mode": mode, "path": str(path)}
        if mode == "non_disruptive":
            out["note"] = ("Ready VMs act alone within a minute; VMs with reserves stay "
                           "in human-only and ask for confirmation.")
        return out
    except ValueError as e:
        return {"error": str(e)}
    except OSError:
        return {"error": _CFG_READONLY_MSG}
    except Exception as e:
        return {"error": str(e)}


def _verify_approved(connector, esc: dict, action: str, resource_id: str, result: dict,
                     ip: str = "") -> dict:
    """Verify an action approved from the War Room, as the agent verifies its own, and
    leave a trace in runs/ for the feed. The approve route used to execute without
    either (real run, 2026-10-05). A failed check becomes a verification_failed
    escalation — the approval itself resolved the mode_hold one."""
    from glorfindel import escalations as _esc
    from glorfindel.actions import isolation_verdict
    try:
        if action == "isolate_vm":
            verification = isolation_verdict(connector.verify_isolation(resource_id), result)
        elif action == "release_isolation":
            verification = connector.verify_release(resource_id)
        else:
            verification = connector.verify_block_ip(ip, resource_id)
    except Exception as e:
        verification = {"verified": None, "error": f"vérification impossible : {e}"}
    try:
        from glorfindel.cli import _record_manual_action
        _record_manual_action(action, resource_id, {
            **(result or {}), **verification, "approved_escalation": esc.get("id", "")})
    except Exception:
        pass
    # Not verified is not a success either (fourth review, Q11): a check that couldn't
    # conclude leaves a card too, as the agent's own cycle now does.
    if verification.get("verified") is not True:
        failed = verification.get("verified") is False
        _esc.record(
            signal_id=f"approve-{esc.get('id', '')}", resource_id=resource_id, action=action,
            escalation_type="verification_failed",
            reason=(f"Action '{action}' approuvée et exécutée, mais "
                    + ("la vérification a échoué : " if failed else "elle n'a pas pu être vérifiée : ")
                    + f"{verification.get('error', 'check failed' if failed else 'Azure illisible')}"),
            ttp=esc.get("ttp", ""), severity=esc.get("severity", ""),
        )
    return verification


# Escalation types whose held action a human may run in one click. Not
# unattributed_signal: its card is anchored on a VM the detection did NOT name —
# approving isolated that VM (fourth review, Q4).
_APPROVABLE_TYPES = {"mode_hold", "low_confidence", "uncharacterized_signal", "release_hold",
                     "telemetry_gap", "unstable_decision"}


def _approval_max_age_h() -> float:
    """GLORFINDEL_APPROVAL_MAX_AGE_H, 2 h when unset or malformed. `nan` and `inf` parsed:
    `age > nan` is never true, and a card of any age could be executed (G2) — both are
    2 h. Zero or negative stays as written: one-click approval closed on purpose
    (`_approval_refusal` refuses every card), never reopened to 2 h."""
    import math
    try:
        value = float(os.environ.get("GLORFINDEL_APPROVAL_MAX_AGE_H") or "2")
    except ValueError:
        return 2.0
    if math.isnan(value) or value == math.inf:
        return 2.0
    return value


def _approval_refusal(esc: dict, vm_name: str) -> str | None:
    """Why this card can't be executed in one click any more, or None."""
    from datetime import datetime, timezone
    etype = esc.get("escalation_type", "")
    if etype == "unattributed_signal":
        return ("Détection non attribuée : la carte est ancrée sur une VM que la détection "
                "ne nomme pas. Identifier la VM concernée, puis agir depuis la CLI.")
    if etype not in _APPROVABLE_TYPES:
        return f"Ce type de carte ({etype or '?'}) ne s'exécute pas en un clic."
    seen = esc.get("last_seen") or esc.get("timestamp") or ""
    try:
        seen_dt = datetime.fromisoformat(seen)
    except ValueError:
        return "Carte sans date lisible : relancer l'analyse plutôt que l'exécuter."
    max_age_h = _approval_max_age_h()
    if max_age_h <= 0:
        # Closed on purpose: no card of any age — a card dated a little ahead of this
        # clock included (`age > 0` let it through) — runs in one click.
        return ("Approbation en un clic fermée (GLORFINDEL_APPROVAL_MAX_AGE_H ≤ 0) : "
                "agir depuis la CLI.")
    age_h = (datetime.now(timezone.utc) - seen_dt).total_seconds() / 3600
    if age_h > max_age_h:
        return (f"Carte vieille de {age_h:.1f} h : l'état de la VM a pu changer (restore, levée). "
                "Acquitter et laisser la détection se reproduire, ou agir depuis la CLI.")
    try:
        from glorfindel import jobs as _jobs
        rec = json.loads((_jobs._RECOVERY_DIR / f"{vm_name}.json").read_text())
        if datetime.fromisoformat(rec["last_restore_at"]) > seen_dt:
            return ("Un restore a eu lieu après cette carte : l'exécuter agirait sur une VM "
                    "restaurée. Acquitter la carte.")
    except (OSError, ValueError, KeyError):
        pass
    return None


@app.post("/api/action/approve/{esc_id}")
async def action_approve(esc_id: str, ip: str = "", scope: str = "vm") -> dict:
    """One-click approve for mode_hold escalations — executes the recommended action and acks.

    `ip` (query param) lets the operator supply the target IP for block_suspicious_ip
    when the escalation doesn't carry it (e.g. recorded before action_params existed).
    `scope` ("vm"|"subnet", block_suspicious_ip only) is the operator's blast-radius
    choice at click time: "vm" (default, scoped to this VM's IP) or "subnet" (one
    any-rule on the subnet NSG → blocks the IP for every VM on the subnet).
    """
    from glorfindel import escalations as _esc
    esc = next((e for e in _esc.pending() if e["id"] == esc_id), None)
    if not esc:
        return {"error": f"Escalation {esc_id} not found or already resolved"}

    action = esc.get("action", "")
    resource_id = esc.get("resource_id", "")
    vm_name = resource_id.split("/")[-1]
    refusal = _approval_refusal(esc, vm_name)
    if refusal:
        return {"error": refusal}
    if action == "block_suspicious_ip" and ip:
        from glorfindel.actions import single_host_ip
        try:
            ip = single_host_ip(ip)
        except ValueError as e:
            return {"error": str(e)}

    try:
        from glorfindel.actions import AzureConnector
        connector = AzureConnector(dry_run=False)

        if action == "isolate_vm":
            result = await asyncio.to_thread(connector.isolate_vm, resource_id)
            _esc.resolve(esc_id)
            verification = await asyncio.to_thread(
                _verify_approved, connector, esc, action, resource_id, result)
            return {"ok": True, "action": action, "result": result, "verification": verification}

        elif action == "snapshot":
            resp = await action_snapshot(vm_name)
            if "error" not in resp:
                _esc.resolve(esc_id)
            return resp

        elif action == "release_isolation":
            resp = await action_release(vm_name)
            if resp.get("ok"):
                _esc.resolve(esc_id)
                # The CLI release checks only BEFORE removing the rules; confirm after,
                # as for an approved isolation (validation run, 2026-10-05).
                resp["verification"] = await asyncio.to_thread(
                    _verify_approved, connector, esc, action, resource_id, {"status": "released"})
            return resp

        elif action == "block_suspicious_ip":
            # Parameterised action — needs the IP. Prefer an operator-supplied IP (query
            # param), else read it from the escalation payload (`ip` or `action_params.ip`).
            block_ip = ip or esc.get("ip") or (esc.get("action_params") or {}).get("ip") or ""
            if block_ip:
                from glorfindel.actions import single_host_ip
                try:
                    block_ip = single_host_ip(block_ip)
                except ValueError as e:
                    return {"error": str(e)}
            if not block_ip:
                # Escalation carries no IP (e.g. recorded before action_params) — ask the
                # operator instead of refusing, so the current escalation is still actionable.
                return {"needs_ip": True, "error": (
                    "This escalation doesn't carry the IP — enter the IP to block, "
                    f"or run: glorfindel block <ip> {resource_id} --yes"
                )}
            block_scope = scope if scope in ("vm", "subnet") else "vm"
            threat_port = (esc.get("action_params") or {}).get("port")
            result = await asyncio.to_thread(
                connector.block_suspicious_ip, block_ip, resource_id, block_scope,
                False, threat_port)
            _esc.resolve(esc_id)
            verification = await asyncio.to_thread(
                _verify_approved, connector, esc, action, resource_id, result, block_ip)
            return {"ok": True, "action": action, "ip": block_ip,
                    "scope": block_scope, "result": result, "verification": verification}

        else:
            return {"error": f"Action '{action}' non supportée par la console — CLI : glorfindel respond {resource_id}"}

    except PermissionError as e:
        return {"error": str(e), "permission_denied": True}
    except Exception as e:
        return _friendly_azure_error(e, action)


@app.post("/api/action/block-promote/{vm_name}")
async def action_block_promote(vm_name: str) -> dict:
    """Extend an existing VM-scoped block to the whole subnet (all VMs).

    Reads the IP from the active block and re-blocks with scope="subnet", replace=True.
    The connector places the subnet-wide rule first, then removes the redundant VM rule
    (create-then-delete) → no protection window. Operator decision, never autonomous.
    """
    from glorfindel.actions import AzureConnector, active_blocks

    block = next(
        (b for b in active_blocks() if b["resource_id"].split("/")[-1] == vm_name),
        None,
    )
    if not block:
        return {"error": f"No active block found for {vm_name}"}
    ip = block.get("ip", "")
    rid = block["resource_id"]
    if not ip:
        return {"error": f"Active block for {vm_name} has no IP"}

    try:
        connector = AzureConnector(dry_run=False)
        result = await asyncio.to_thread(
            connector.block_suspicious_ip, ip, rid, "subnet", True)
        return {"ok": True, "ip": ip, "scope": "subnet", "result": result}
    except PermissionError as e:
        return {"error": str(e), "permission_denied": True}
    except Exception as e:
        return _friendly_azure_error(e, "block_suspicious_ip")


@app.post("/api/action/snapshot/{vm_name}")
async def action_snapshot(vm_name: str) -> dict:
    """Trigger an on-demand Azure Backup snapshot via jobs.py (visible to CLI + War Room)."""
    resource_id = _find_resource_id(vm_name)
    if not resource_id:
        return {"error": f"Resource ID not found for {vm_name}"}

    from glorfindel.config import NO_VAULT_MSG, resolve_backup_vault
    vault, vault_rg, _ = resolve_backup_vault()
    if not vault:
        return {"error": NO_VAULT_MSG}

    from glorfindel.actions import AzureConnector
    from glorfindel.jobs import start_snapshot as _start_snapshot

    def _start() -> dict:
        # vault_rg: a central vault lives in its own RG (not the VM's).
        return _start_snapshot(resource_id, AzureConnector(dry_run=False), vault, vault_rg=vault_rg)

    job = await asyncio.to_thread(_start)
    return {"status": "started", "job_id": job["job_id"], "resource_id": resource_id}


# Cards anchored on a VM the detection may not concern (AL1; an identity detection names no
# VM — C2): the same types as glorfindel/bot.py's and the page's (_ANCHORED_TYPES).
_ANCHORED_TYPES = {"control_plane_change", "identity_change", "unattributed_signal"}


def _restore_refusal(esc_id: str, vm_name: str) -> tuple[str | None, str]:
    """(why the console refuses this restore, or None; the card's resource id). A restore
    from the console is its card's (SEC1): pending, a restore, on this VM, and never an
    anchored one — as the page and the bot."""
    from glorfindel import escalations as _esc
    cli = "glorfindel restore <resource_id> --yes --before <ISO8601>"
    if not esc_id:
        return f"A restore from the console goes through its card — else the CLI: {cli}", ""
    esc = next((e for e in _esc.pending() if e.get("id") == esc_id), None)
    if not esc:
        return f"Escalation {esc_id} not found or already resolved", ""
    rid = esc.get("resource_id", "")
    if esc.get("escalation_type") in _ANCHORED_TYPES:
        return ("This card is anchored on a VM the detection does not name: no restore from "
                f"the console — identify the VM, then the CLI: {cli}"), rid
    if esc.get("action") != "restore_from_backup":
        return f"This card does not hold a restore — CLI: {cli}", rid
    if rid.rstrip("/").split("/")[-1] != vm_name:
        return f"This card is not {vm_name}'s", rid
    return None, rid


@app.get("/api/restore/plan/{vm_name}")
async def restore_plan_view(vm_name: str, escalation: str = "", before: str = "") -> dict:
    """What a card's restore asks (SEC4c), read only: the moment the field is filled with —
    the exercise's attack_started for this VM, else the card's first detection — and the
    recovery points from before the moment given (`before`, else that one)."""
    from glorfindel import escalations as _esc
    from glorfindel import restore_plan
    refusal, resource_id = _restore_refusal(escalation, vm_name)
    if refusal:
        return {"error": refusal}
    esc = next((e for e in _esc.pending() if e.get("id") == escalation), None)
    proposed = restore_plan.proposed_moment(resource_id, esc)
    try:
        moment = restore_plan.parse_moment(before) if before else proposed["before"]
    except ValueError as exc:
        return {**proposed, "resource_id": resource_id, "error": str(exc)}
    out = {**proposed, "resource_id": resource_id, "moment": moment, "points": [], "points_error": "",
           "warning": restore_plan.moment_warning(resource_id, moment) if moment else ""}
    if not moment:
        return out
    loop = asyncio.get_running_loop()
    try:
        out["points"] = await loop.run_in_executor(
            None, lambda: restore_plan.points_before(resource_id, moment))
    except Exception as exc:  # unreadable vault: said, the restore stays possible
        out["points_error"] = f"{type(exc).__name__}: {str(exc)[:300]}"
    return out


@app.post("/api/action/restore/{vm_name}")
async def action_restore(vm_name: str, body: dict) -> dict:
    """Azure Backup restore of the VM of a restore card (`{"escalation": <id>, "before":
    <ISO 8601>}`), in the background (`glorfindel restore --before`). The moment is asked
    (SEC4c): without it, refused — never the newest point."""
    esc_id = str(body.get("escalation") or "")
    refusal, resource_id = _restore_refusal(esc_id, vm_name)
    if refusal:
        return {"error": refusal}
    from glorfindel import restore_plan
    try:
        before = restore_plan.parse_moment(body.get("before"))
    except ValueError as exc:
        return {"error": f"The moment to restore before is required: {exc}"}
    _restore_start(vm_name, resource_id)
    asyncio.create_task(_bg_restore(resource_id, vm_name, before, esc_id))
    return {"status": "started", "resource_id": resource_id, "before": before}


@app.post("/api/action/ack/{esc_id}")
async def action_ack(esc_id: str) -> dict:
    from glorfindel import escalations as esc_module
    esc_module.resolve(esc_id)
    return {"ok": True}


@app.post("/api/escalations/{esc_id}/verdict")
async def set_verdict(esc_id: str, body: dict) -> dict:
    """The operator's judgement of a card: right / wrong / unsure (observation)."""
    from glorfindel import escalations as esc_module
    try:
        e = esc_module.set_verdict(esc_id, str((body or {}).get("verdict", "")), str((body or {}).get("note", "")))
    except (KeyError, ValueError) as exc:
        return {"error": str(exc).strip("'")}
    return {"ok": True, "verdict": e["verdict"]}


def _since_start(since: str):
    """'7d', '24h', '4w' → the datetime that far back; 'all' → None. Raises ValueError."""
    from datetime import datetime, timedelta, timezone
    if since == "all":
        return None
    units = {"h": "hours", "d": "days", "w": "weeks"}
    try:
        return datetime.now(timezone.utc) - timedelta(**{units[since[-1]]: int(since[:-1])})
    except (KeyError, ValueError, IndexError):
        raise ValueError("since: a number followed by h, d or w (7d, 24h, 4w), or 'all'")


@app.get("/api/report")
async def observation_report(since: str = "7d") -> dict:
    """The observation report: verdicts on recommendations, false disruptive rate."""
    from glorfindel import escalations as esc_module
    try:
        start = _since_start(since)
    except ValueError as exc:
        return {"error": str(exc)}
    return esc_module.observation_report(start)


@app.get("/api/to-judge")
async def to_judge(since: str = "7d") -> dict:
    """The decision cards still waiting for a verdict, newest first — an exercise card
    flagged (`exercise`, `exercise_run`), never left out (H-1)."""
    from glorfindel import escalations as esc_module
    try:
        start = _since_start(since)
    except ValueError as exc:
        return {"error": str(exc)}
    return {"cards": esc_module.to_judge(start)}


@app.get("/api/audit/{vm_name}")
async def audit_resource(vm_name: str) -> dict:
    """Remediation readiness audit for a single resource."""
    from glorfindel import audit as _audit
    from glorfindel.actions import AzureConnector

    resource_id = _resolve_vm(vm_name)
    if not resource_id:
        return {"error": f"resource_id not found for {vm_name}"}

    connector = AzureConnector(dry_run=False)
    # Resolve vault + its RG from config (central vault ≠ VM RG — see /api/audit).
    from glorfindel.config import NO_VAULT_MSG, resolve_backup_vault
    vault, vault_rg, staging_storage = resolve_backup_vault()
    if not vault:
        return {"error": NO_VAULT_MSG}
    # Run blocking Azure SDK calls in a thread pool — prevents event loop stall.
    result = await asyncio.to_thread(
        _audit.run, resource_id, connector, vault, vault_rg, staging_storage)
    return result.to_dict()


@app.get("/api/audit")
async def audit_all() -> dict:
    """Remediation readiness audit for all assets in detection_rules.yaml."""
    from glorfindel import audit as _audit
    from glorfindel.actions import AzureConnector
    from glorfindel.detection_rules import load_config

    rp = _base_rules_path()
    if not rp:
        return {"audits": []}

    connector = AzureConnector(dry_run=False)

    # Vault name + its resource group: from glorfindel-config.yaml action_backends
    # (source of truth). A central vault protects VMs across RGs, so the vault's RG
    # must come from config — deriving it from each VM's resource_id yields a false
    # "backup missing" (ResourceNotFound on the vault under the wrong RG).
    vault_rg = ""
    staging_storage = ""
    try:
        from glorfindel.config import load_glorfindel_config
        _cfg = load_glorfindel_config()
        rsv = _cfg.backup_vault()
        vault = rsv.vault_name if rsv and rsv.vault_name else os.environ.get("GLORFINDEL_BACKUP_VAULT", "")
        vault_rg = rsv.resource_group if rsv and rsv.resource_group else ""
        staging_storage = rsv.restore_staging_storage if rsv else ""
    except Exception:
        vault = os.environ.get("GLORFINDEL_BACKUP_VAULT", "")
        _cfg = None

    # VM targets: fresh read from disk (watch service may have updated the file)
    from glorfindel.discovery import AssetRegistry
    discovered = AssetRegistry().all()
    targets = [(a.resource_id, a.name) for a in discovered if a.resource_id]
    if not targets:
        # Legacy fallback: rules with inline resource_id
        from glorfindel.detection_rules import load_config
        cfg = load_config(rp, glorfindel_cfg=_cfg)
        targets = [
            (r.resource_id, r.asset_name or r.resource_id.split("/")[-1])
            for r in cfg.rules
            if r.resource_id and "${" not in r.resource_id
        ]

    # Deduplicate, then run all audits concurrently in thread pool threads.
    seen: set[str] = set()
    unique: list[tuple[str, str]] = []
    for rid, asset_name in targets:
        if rid not in seen:
            seen.add(rid)
            unique.append((rid, asset_name))

    async def _audit_one(rid: str, asset_name: str) -> dict:
        result = await asyncio.to_thread(
            _audit.run, rid, connector, vault, vault_rg, staging_storage)
        d = result.to_dict()
        d["vault"] = vault
        d["asset_name"] = asset_name
        return d

    audits = await asyncio.gather(*(_audit_one(rid, name) for rid, name in unique))
    return {"audits": list(audits)}


@app.get("/api/backups")
async def backups() -> dict:
    """Vault-level backup inventory (RSV protected items) — the source of truth for
    "do my backups exist?", independent of VM discovery/power state. One cheap
    paginated call (list_backup_items); the per-VM /api/audit stays for readiness.
    """
    from glorfindel.actions import AzureConnector

    from glorfindel.config import NO_VAULT_MSG, resolve_backup_vault
    vault, rg, _ = resolve_backup_vault()
    if not vault or not rg:
        return {"error": NO_VAULT_MSG, "items": []}
    try:
        connector = AzureConnector(dry_run=False)
        items = await asyncio.to_thread(connector.list_backup_items, vault, rg)
        return {"vault": vault, "items": items}
    except Exception as e:
        return {"vault": vault, "items": [], "error": str(e)}


@app.get("/api/nsgs")
async def nsgs() -> dict:
    """Full NSG inventory (network-control layer) — every NSG as a resource, complete
    and independent of VM discovery/power state. The per-VM audit under-counts (misses
    subnet NSGs shared with a NIC's own NSG, AKS subnet NSGs, off-VM NSGs); listing NSG
    resources gives the true count + associations + which carry a Glorfindel rule.
    """
    from glorfindel.actions import AzureConnector

    try:
        connector = AzureConnector(dry_run=False)
        items = await asyncio.to_thread(connector.list_nsgs)
        return {"nsgs": items}
    except Exception as e:
        return {"nsgs": [], "error": str(e)}


@app.get("/api/actions/{vm_name}")
async def vm_actions(vm_name: str, limit: int = 5) -> dict:
    """Return recent Glorfindel decisions for a VM (reasoning + confidence)."""
    import time as _time
    runs = Path("runs")
    if not runs.exists():
        return {"actions": []}

    cutoff = _time.time() - 24 * 3600
    actions: list[dict] = []

    for f in sorted(
        runs.glob("*_debug.jsonl"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    ):
        if f.stat().st_mtime < cutoff:
            break
        for line in reversed(f.read_text().splitlines()):
            if not line.strip():
                continue
            try:
                d = json.loads(line)
                rid = (d.get("signal") or {}).get("resource_id", "")
                if rid.split("/")[-1] != vm_name:
                    continue
                action = d.get("action", "")
                if not action or action in ("snapshot", "improve_detection"):
                    continue
                import re as _re
                full = d.get("reasoning") or ""
                # Strip markdown for display
                full_clean = _re.sub(r'\*\*(.*?)\*\*', r'\1', full)
                full_clean = _re.sub(r'\*(.*?)\*', r'\1', full_clean).strip()
                actions.append({
                    "action": action,
                    "reasoning": _extract_conclusion(full),
                    "full_reasoning": full_clean[:2000],
                    "confidence": d.get("confidence"),
                    "timestamp": d.get("timestamp", ""),
                    "outcome": (d.get("outcome") or {}).get("status", ""),
                    "ttp": (d.get("signal") or {}).get("ttp", ""),
                    "escalate": d.get("escalate", False),
                })
                if len(actions) >= limit:
                    break
            except Exception:
                pass
        if len(actions) >= limit:
            break

    return {"actions": actions}


@app.get("/api/discovered")
async def discovered_assets() -> dict:
    """Return assets discovered from monitoring backends."""
    try:
        from glorfindel.discovery import AssetRegistry
        return {"assets": AssetRegistry().to_dicts()}
    except Exception:
        return {"assets": []}


@app.get("/api/pending/rules")
async def pending_rules() -> dict:
    from glorfindel.proposed_rules import pending
    return {"proposals": pending()}


@app.post("/api/action/approve-rule/{proposal_id}")
async def approve_rule(proposal_id: str) -> dict:
    """Approve a proposed rule: written to the client's layer (P1, ~/.glorfindel/client_rules.yaml),
    the shipped base read to resolve its asset. Says where it went, as the CLI does."""
    rules_path = _base_rules_path()
    if not rules_path:
        return {"error": "detection_rules.yaml not found"}
    try:
        from glorfindel.proposed_rules import approve
        proposal = approve(proposal_id, rules_path)
        return {"ok": True, "rule_name": proposal["rule_name"],
                **{k: proposal.get(k) for k in ("rules_file", "rule_write", "rule_bound",
                                                 "rule_unbound_reason")}}
    except ValueError as e:
        return {"error": str(e)}


@app.post("/api/action/reject-rule/{proposal_id}")
async def action_reject_rule(proposal_id: str) -> dict:
    """Reject a proposed detection rule without adding it to detection_rules.yaml."""
    try:
        from glorfindel.proposed_rules import reject
        proposal = reject(proposal_id)
        return {"ok": True, "rule_name": proposal["rule_name"]}
    except ValueError as e:
        return {"error": str(e)}


_RESTORE_TRACKING = Path.home() / ".glorfindel" / "restore_in_progress.json"


def _restore_start(vm_name: str, resource_id: str) -> None:
    import json as _json
    data: dict = {}
    try:
        if _RESTORE_TRACKING.exists():
            data = _json.loads(_RESTORE_TRACKING.read_text())
    except Exception:
        pass
    data[vm_name] = {
        "resource_id": resource_id,
        "started_at": datetime.now(timezone.utc).isoformat(),
    }
    _RESTORE_TRACKING.parent.mkdir(parents=True, exist_ok=True)
    _RESTORE_TRACKING.write_text(_json.dumps(data))


def _restore_done(vm_name: str) -> None:
    import json as _json
    try:
        if not _RESTORE_TRACKING.exists():
            return
        data = _json.loads(_RESTORE_TRACKING.read_text())
        data.pop(vm_name, None)
        _RESTORE_TRACKING.write_text(_json.dumps(data))
    except Exception:
        pass


def _active_restores() -> list[dict]:
    import json as _json
    try:
        if not _RESTORE_TRACKING.exists():
            return []
        data = _json.loads(_RESTORE_TRACKING.read_text())
        now = datetime.now(timezone.utc)
        result = []
        for vm_name, info in data.items():
            started = datetime.fromisoformat(info["started_at"])
            elapsed_s = int((now - started).total_seconds())
            result.append({
                "vm_name": vm_name,
                "resource_id": info["resource_id"],
                "started_at": info["started_at"],
                "elapsed_s": elapsed_s,
                "elapsed_label": (
                    f"{elapsed_s // 60}m{elapsed_s % 60:02d}s"
                    if elapsed_s >= 60 else f"{elapsed_s}s"
                ),
            })
        return result
    except Exception:
        return []


# A card's restore the command refused or failed (SEC4c): the card says why, never silence.
_RESTORE_FAILURES = Path.home() / ".glorfindel" / "restore_failures.json"


def _restore_failures() -> dict[str, dict]:
    """escalation id → {"vm_name", "error", "at"}."""
    import json as _json
    try:
        data = _json.loads(_RESTORE_FAILURES.read_text())
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


_RESTORE_FAILURES_KEPT = 50


def _note_restore_failure(esc_id: str, vm_name: str, error: str | None) -> None:
    """Keep (error) or clear (None) what a card's last restore said — under the state's file
    lock (two restores ending together lose nothing), only for cards still pending, the
    newest _RESTORE_FAILURES_KEPT at most."""
    import json as _json
    from glorfindel import escalations as _esc
    from glorfindel.response.locks import _file_lock
    from glorfindel.response.state import _atomic_write_text
    with _file_lock(_RESTORE_FAILURES.with_suffix(".lock")):
        data = _restore_failures()
        if error is None:
            data.pop(esc_id, None)
        else:
            data[esc_id] = {"vm_name": vm_name, "error": error[-600:],
                            "at": datetime.now(timezone.utc).isoformat()}
        pending = {e.get("id") for e in _esc.pending()}
        kept = sorted(((k, v) for k, v in data.items() if k in pending),
                      key=lambda kv: str(kv[1].get("at") or ""))[-_RESTORE_FAILURES_KEPT:]
        _atomic_write_text(_RESTORE_FAILURES, _json.dumps(dict(kept)))


async def _bg_restore(resource_id: str, vm_name: str = "", before: str = "", esc_id: str = "") -> None:
    """`glorfindel restore --before` in the background; its refusal or failure is kept for the
    card (SEC4c): the return code and the output are read."""
    from glorfindel import restore_plan
    loop = asyncio.get_running_loop()
    try:
        proc = await loop.run_in_executor(
            None,
            lambda: subprocess.run(
                [_bin(), *restore_plan.restore_args(resource_id, before)],
                capture_output=True, text=True, timeout=1800,
            ),
        )
        error = (None if proc.returncode == 0 else
                 restore_plan.failure_text(proc.returncode, (proc.stdout or "") + (proc.stderr or "")))
    except Exception as exc:  # the command did not run, or not to its end
        error = f"{type(exc).__name__}: {str(exc)[:400]}"
    if esc_id:
        try:
            _note_restore_failure(esc_id, vm_name, error)
        except Exception:
            pass
    if vm_name:
        _restore_done(vm_name)


def _base_rules_path() -> Path | None:
    """The shipped base detection_rules.yaml, found as the glorfindel command finds it: from the
    working directory (the container's /app, the repo's root), else beside the glorfindel
    package — never beside this module, which left glorfindel/ on 26/10 (outside the repo's
    root the console then showed no rule, and approving one failed)."""
    from glorfindel.cli import _find_rules_file
    found = _find_rules_file()
    return Path(found) if found else None


def _find_resource_id(vm_name: str) -> str | None:
    """The resource id behind a VM name the War Room shows: active isolations and
    blocks, pending escalations, then the discovered assets.

    The registry now keeps two VMs that share a name (third review, T1): resolving the
    name to the first match could release, restore or isolate the OTHER one. Several
    distinct ids → AmbiguousVM, the action is refused with a clear message."""
    from glorfindel.actions import active_blocks, active_isolations

    found: dict[str, str] = {}

    def add(rid: str) -> None:
        if rid and rid.rstrip("/").split("/")[-1] == vm_name:
            found.setdefault(rid.rstrip("/").lower(), rid)

    for i in active_isolations():
        add(i.get("resource_id", ""))
    for b in active_blocks():
        add(b.get("resource_id", ""))
    try:
        from glorfindel import escalations as _esc
        for esc in _esc.pending():
            add(esc.get("resource_id", ""))
    except Exception:
        pass
    try:
        from glorfindel.discovery import AssetRegistry
        for asset in AssetRegistry().all():
            if asset.name == vm_name and asset.resource_id:
                found.setdefault(asset.resource_id.rstrip("/").lower(), asset.resource_id)
            else:
                add(asset.resource_id)
    except Exception:
        pass
    if len(found) > 1:
        raise AmbiguousVM(
            f"{vm_name} désigne {len(found)} VMs ({', '.join(sorted(found))}) : action refusée "
            "depuis la console — utiliser la CLI avec l'ID de ressource complet.")
    return next(iter(found.values()), None)


def _write_manual_feed(action: str, resource_id: str, outcome: dict) -> None:
    """Write an operator action entry to runs/manual_actions.jsonl for the live feed."""
    runs = Path("runs")
    runs.mkdir(exist_ok=True)
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "action": action,
        "confidence": 1.0,
        "escalate": False,
        "signal": {"resource_id": resource_id, "ttp": "", "severity": ""},
        "outcome": outcome,
    }
    with open(runs / "manual_actions.jsonl", "a") as f:
        f.write(json.dumps(entry) + "\n")


def _extract_conclusion(text: str, max_chars: int = 120) -> str:
    """Extract the conclusion from a step-by-step LLM reasoning.

    The reasoning is typically structured as:
        Étape 1 – ... (preamble)
        Étape 2 – ... (analysis)
        Étape N – ... (conclusion / action decision)

    We take the LAST step chunk since it contains the decision rationale,
    not the first which is always the preamble.
    """
    import re
    clean = re.sub(r'\*\*(.*?)\*\*', r'\1', text)
    clean = re.sub(r'\*(.*?)\*', r'\1', clean)
    # Split on step markers (Étape N / Step N) — any variant
    parts = re.split(r'(?i)(?:étape|step)\s+\d+\s*[–\-:]', clean)
    # Take the last non-trivial chunk (usually the conclusion)
    chunk = next(
        (p.strip() for p in reversed(parts) if len(p.strip()) > 20),
        clean,
    )
    # First sentence of that chunk
    sentence = re.split(r'[.!?]\s+', chunk)[0] or chunk
    return sentence.strip()[:max_chars]


def _bin() -> str:
    c = Path(sys.executable).parent / "glorfindel"
    return str(c) if c.exists() else "glorfindel"


def _load_recent(n: int, window_h: float = 4.0) -> list[dict]:
    """Load recent feed entries across all runs in the last window_h hours."""
    runs = Path("runs")
    if not runs.exists():
        return []

    import time as _time
    cutoff = _time.time() - window_h * 3600
    entries: list[tuple[str, dict]] = []

    for pat, kind in [
        ("*_signals.jsonl", "signal"),
        ("*_debug.jsonl", "action"),
    ]:
        for f in runs.glob(pat):
            if f.stat().st_mtime < cutoff:
                continue
            for line in f.read_text().splitlines():
                if not line.strip():
                    continue
                try:
                    d = json.loads(line)
                    entries.append(
                        (d.get("timestamp", ""), _parse(d, kind))
                    )
                except Exception:
                    pass

    manual = runs / "manual_actions.jsonl"
    if manual.exists():
        for line in manual.read_text().splitlines():
            if not line.strip():
                continue
            try:
                d = json.loads(line)
                entries.append((d.get("timestamp", ""), _parse(d, "action")))
            except Exception:
                pass

    entries.sort(key=lambda x: x[0])
    return [e for _, e in entries[-n:]]


def _parse(data: dict, kind: str) -> dict:
    if kind == "signal":
        return {
            "type": "signal",
            "timestamp": data.get("timestamp", ""),
            "event": data.get("event", ""),
            "ttp": data.get("ttp", ""),
            "severity": data.get("severity", ""),
            "vm": data.get("resource_id", "").split("/")[-1],
        }
    sig = data.get("signal", {})
    outcome = data.get("outcome", {})
    return {
        "type": "action",
        "timestamp": data.get("timestamp", ""),
        "action": data.get("action", ""),
        "escalate": data.get("escalate", False),
        # A detection-only decision has no action (AL1, C2): the gate that held it.
        "held_by": data.get("held_by", ""),
        "confidence": data.get("confidence", 0),
        "verified": outcome.get("verified"),
        "ttp": sig.get("ttp", ""),
        "vm": sig.get("resource_id", "").split("/")[-1],
    }


# ── Annatar and Gothmog: what they ran, and what Glorfindel made of it (read only) ─────────
# From the files that reach this host: the exercise windows (B2; on H0, pulled by the watch
# from Orodruin), the campaigns Orodruin publishes (#167), the technique catalog, the watch's
# debug files and cards, and the return channel the watch writes (#159). Every route here is a
# GET: a run starts from Orodruin, armed (eregion_core/orodruin.py) — a launch button, later,
# goes through that contract, never around. Until 26/10 these were the atelier's routes
# (/api/atelier/*), which now redirect here.

_RUNS = Path("runs")
# A cycle is slimmed once per debug file version: the files carry the model's past cycles.
_cycle_cache: dict[Path, tuple[tuple[int, int], list[dict]]] = {}
_HEARTBEAT_TTL_S = 20.0
_heartbeat_cache: dict = {"at": 0.0, "value": None}


def _iso(value) -> datetime | None:
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


@app.get("/api/catalog")
async def catalog(kind: str = "") -> dict:
    """The technique catalog, techniques and faults, every resource type (planned ones too);
    ``kind=technique`` (Annatar's) or ``kind=fault`` (Gothmog's) keeps one of them."""
    import yaml
    from eregion_core.experiment import CATALOG
    try:
        data = yaml.safe_load(CATALOG.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:
        return {"error": f"catalog unreadable: {exc}", "entries": []}
    entries = []
    for rtype, body in (data.get("resource_types") or {}).items():
        for entry_kind, key in (("technique", "techniques"), ("fault", "faults")):
            if kind and kind != entry_kind:
                continue
            for e in (body or {}).get(key) or []:
                if not isinstance(e, dict):
                    continue
                entries.append({
                    "resource_type": rtype, "kind": entry_kind,
                    "id": str(e.get("ttp") or e.get("id") or ""),
                    "name": e.get("name", ""), "tactic": e.get("tactic", ""),
                    "status": e.get("status", ""), "destructive": bool(e.get("destructive")),
                    "engine": e.get("engine") or "local-script",
                    "log_source": e.get("log_source", ""),
                    "expected_latency_s": e.get("expected_latency_s"),
                })
    return {"entries": entries}


def _slim_cycle(rec: dict) -> dict | None:
    sig = rec.get("signal")
    if not isinstance(sig, dict):
        return None
    ctx = sig.get("context") if isinstance(sig.get("context"), dict) else {}
    outcome = rec.get("outcome") if isinstance(rec.get("outcome"), dict) else {}
    return {
        "at": rec.get("timestamp", ""), "signal_at": sig.get("timestamp", ""),
        "event": sig.get("event", ""), "ttp": sig.get("ttp", ""),
        "resource_id": sig.get("resource_id", ""), "rule": ctx.get("rule_name", ""),
        "attribution": ctx.get("attribution", ""), "action": rec.get("action", ""),
        "confidence": rec.get("confidence"), "escalate": bool(rec.get("escalate")),
        "status": outcome.get("status", ""), "executed": outcome.get("executed"),
        "verified": outcome.get("verified"), "mode": rec.get("resolved_autonomy_mode", ""),
        "cycle_error": bool(rec.get("cycle_error")),
    }


def _watch_cycles(since_ts: float | None) -> list[dict]:
    """Glorfindel's cycles from every debug file written since ``since_ts`` — the watch's
    ``watch-*`` files, and a run's own on a host that has both."""
    out = []
    for path in sorted(_RUNS.glob("*_debug.jsonl")):
        try:
            st = path.stat()
        except OSError:
            continue
        if since_ts is not None and st.st_mtime < since_ts - 60:  # a cycle ends after its signal
            continue
        key = (st.st_mtime_ns, st.st_size)
        hit = _cycle_cache.get(path)
        if not hit or hit[0] != key:
            cycles = []
            try:
                lines = path.read_text(encoding="utf-8").splitlines()
            except (OSError, UnicodeDecodeError):
                lines = []
            for line in lines:
                try:
                    rec = json.loads(line)
                except ValueError:
                    continue
                if isinstance(rec, dict) and (c := _slim_cycle(rec)):
                    cycles.append(c)
            hit = _cycle_cache[path] = (key, cycles)
        out += hit[1]
    return out


def _run_reports() -> dict[str, Path]:
    """Where each run's report is on this host: ``runs/<run_id>.json`` (a run launched here),
    else under the campaign Orodruin published it with (``runs/campaigns/<id>/runs/``)."""
    found = {p.stem: p for p in _RUNS.glob("campaigns/*/runs/*.json")}
    found.update({p.stem: p for p in _RUNS.glob("*.json")})
    return found


def _slim_probes(by_vm) -> dict:
    """A Gothmog report's ``metrics.before`` / ``after``: ``{<vm>: [{name, ok, observed,
    expect}]}`` (gothmog/probes.py). The report comes from Orodruin and its pull checks
    neither: only that shape is kept, ``ok`` true only when it is ``true``."""
    if not isinstance(by_vm, dict):
        return {}
    return {str(vm): [{"name": str(p.get("name") or ""), "ok": p.get("ok") is True,
                       "observed": str(p.get("observed") or ""), "expect": str(p.get("expect") or "")}
                      for p in probes if isinstance(p, dict)]
            for vm, probes in by_vm.items() if isinstance(probes, list)}


def _slim_run(path: Path) -> dict | None:
    try:
        r = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(r, dict):
        return None
    m = r.get("metrics") if isinstance(r.get("metrics"), dict) else {}
    keep = ("injector", "detection", "detection_latency_s", "attack_time", "fault_start",
            "fault_end", "seen_down_at", "time_to_restore_s", "fallback_used", "aborted")
    metrics = {k: m[k] for k in keep if k in m}
    if m.get("without_glorfindel") is True:  # V1: run --without-glorfindel, shown apart
        metrics["without_glorfindel"] = True
    metrics.update({k: _slim_probes(m[k]) for k in ("before", "after") if k in m})
    return {"scenario": r.get("scenario", ""), "mitre": r.get("mitre", ""),
            "result": r.get("result", ""),
            "checks": r.get("checks") if isinstance(r.get("checks"), dict) else {},
            "metrics": metrics}


def _window_state(w: dict, now: datetime) -> str:
    """``open`` (the injector runs), ``grace`` (ended, detections still count), ``closed``,
    or ``lapsed`` — never closed: the injector died, the window ran out at its expiry."""
    from eregion_core.exercise import live
    start, expires = _iso(w.get("start")), _iso(w.get("expires"))
    if start and now < start:
        return "open"
    if live(w, now):
        return "open" if not w.get("end") and expires and now <= expires else "grace"
    return "closed" if w.get("end") else "lapsed"


def _read_windows() -> list[dict]:
    """The exercise windows as their files hold them. Read only: the watch pulls them, and its
    ``load_windows`` may purge an old one (H-1) — the console never writes there. A file
    without a run_id and a start (unreadable, or a purged window's tombstone) is skipped; the
    targets are kept only as a list of strings. ``refusal``: why Glorfindel does not believe
    the window, as written (``window_refusal``, H-1) — it is shown, never hidden."""
    from eregion_core.exercise import exercises_dir, window_refusal
    directory = exercises_dir(_RUNS)
    now = datetime.now(timezone.utc)
    out = []
    for path in sorted(directory.glob("*.json")) if directory.is_dir() else []:
        try:
            w = json.loads(path.read_text(encoding="utf-8"))
            declared = datetime.fromtimestamp(path.stat().st_mtime, timezone.utc)
        except (OSError, ValueError):
            continue
        if isinstance(w, dict) and w.get("run_id") and w.get("start"):
            targets = w.get("targets") if isinstance(w.get("targets"), list) else []
            out.append({**w, "run_id": str(w["run_id"]),
                        "targets": [t.lower() for t in targets if isinstance(t, str)],
                        "refusal": window_refusal(w, now, declared)})
    return out


@app.get("/api/exercises")
async def exercises(since: str = "7d", injector: str = "") -> dict:
    """The exercise windows, newest first, each with what Glorfindel did during it: the cycles
    on a target inside the window (the return channel's rule, ``covering_runs``), the cards
    carrying its run, and the run's report when it reached this host. ``injector`` keeps one
    injector's windows (its section); the cycles are attributed over every window either way,
    so a window keeps only its own."""
    from eregion_core.exercise import covering_runs, is_enrolled, last_moment
    try:
        start = _since_start(since)
    except ValueError as exc:
        return {"error": str(exc)}
    now = datetime.now(timezone.utc)
    windows = [w for w in _read_windows()
               if start is None or (_iso(w.get("start")) or now) >= start
               or _window_state(w, now) in ("open", "grace")]
    if not windows:
        return {"exercises": []}
    starts = [s for w in windows if (s := _iso(w.get("start")))]
    cycles = await asyncio.to_thread(_watch_cycles, min(starts).timestamp() if starts else None)
    by_run: dict[str, list[dict]] = {}
    for c in cycles:
        for rid in covering_runs(c["resource_id"], c["signal_at"], windows):
            by_run.setdefault(rid, []).append(c)
    from glorfindel import escalations as esc_module
    cards: dict[str, list[dict]] = {}
    for e in esc_module.all_escalations():
        if e.get("exercise_run"):
            cards.setdefault(e["exercise_run"], []).append({
                k: e.get(k) for k in ("id", "timestamp", "action", "escalation_type", "status",
                                      "verdict", "confidence", "ttp", "rule_name")})
    reports = _run_reports()
    # Read as the watch reads it (TagEnrollment, cached): a target not enrolled is never in an
    # exercise for Glorfindel (H-1).
    shown = [w for w in windows if not injector or w.get("injector") == injector]
    vms = sorted({t for w in shown for t in w["targets"]})
    enrolled = await asyncio.to_thread(lambda: {t: is_enrolled(t) for t in vms})
    out = []
    for w in sorted(shown, key=lambda w: str(w.get("start")), reverse=True)[:200]:
        rid = str(w["run_id"])
        last = last_moment(w)
        out.append({
            **{k: w.get(k) for k in ("run_id", "injector", "kind", "experiment", "targets",
                                     "start", "end", "expires", "closed_by", "refusal")},
            "enrolled": {t: enrolled.get(t, False) for t in w["targets"]},
            "experiment_id": str(w.get("experiment") or "").split(" ")[0],
            "state": _window_state(w, now),
            "last_moment": last.isoformat() if last else None,
            "cycles": sorted(by_run.get(rid, []), key=lambda c: str(c["signal_at"])),
            "cards": cards.get(rid, []),
            "run": _slim_run(reports[rid]) if rid in reports else None,
        })
    return {"exercises": out}


@app.get("/api/campaigns")
async def campaigns(since: str = "30d") -> dict:
    """The campaigns on this host, newest first: those Orodruin published (``.pulled``) and
    those run here. On H0 a campaign appears once it is over (its manifest comes last)."""
    try:
        start = _since_start(since)
    except ValueError as exc:
        return {"error": str(exc)}
    out = []
    for mpath in _RUNS.glob("campaigns/*/manifest.json"):
        cdir = mpath.parent
        try:
            m = json.loads(mpath.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            m = None
        if not isinstance(m, dict):
            out.append({"dir": cdir.name, "error": "manifest unreadable"})
            continue
        created = _iso(m.get("created_at"))
        if start and created and created < start:
            continue
        budget = m.get("budget") if isinstance(m.get("budget"), dict) else {}
        scope = m.get("scope") if isinstance(m.get("scope"), dict) else {}
        out.append({
            "dir": cdir.name,
            **{k: m.get(k) for k in ("campaign_id", "created_at", "created_by", "objective",
                                     "state", "kill_switch", "updated_at")},
            "sandbox": scope.get("sandbox", ""),
            "budget": {k: budget.get(k) for k in ("max_scenarios", "allow_destructive",
                                                  "detection_window_s", "reset_nsg_between")},
            "pulled": (cdir / ".pulled").exists(),
            "report": (cdir / "report.md").exists(),
            "without_glorfindel": m.get("without_glorfindel") is True,   # V1: counted apart
            "scenarios": [
                {k: s.get(k) for k in ("seq", "ttp", "tactic", "name", "status", "detection",
                                       "detection_latency_s", "run_id", "started_at",
                                       "finished_at", "error", "destructive",
                                       "target_resource_id")}
                for s in (m.get("scenarios") or []) if isinstance(s, dict)],
        })
    out.sort(key=lambda c: str(c.get("created_at") or ""), reverse=True)
    return {"campaigns": out}


@app.get("/api/campaigns/{cid}")
async def campaign(cid: str) -> dict:
    """One campaign's facts — each run with Glorfindel's decision, read from the files as the
    campaign report reads them (analysis/campaign_report.py) — the scenarios it left out and
    why, and its report, when written."""
    from eregion_core.exercise_channel import safe_part
    if not safe_part(cid):
        return {"error": "campaign id: a plain name"}
    cdir = _RUNS / "campaigns" / cid
    if not (cdir / "manifest.json").is_file():
        return {"error": f"unknown campaign: {cid}"}
    from dataclasses import asdict
    from analysis.campaign_report import collect_facts
    skipped: list[str] = []
    try:
        facts = await asyncio.to_thread(collect_facts, cdir, _RUNS, skipped.append)
    except Exception as exc:
        return {"error": f"campaign unreadable: {exc}"}
    try:
        report = (cdir / "report.md").read_text(encoding="utf-8")
    except OSError:
        report = ""
    return {"campaign_id": cid, "facts": [asdict(f) for f in facts], "skipped": skipped,
            "report_md": report}


def _published_heartbeat() -> dict:
    """The heartbeat on the return channel — what a run on Orodruin reads — cached briefly."""
    import time as _time
    from eregion_core import watch_channel
    if _heartbeat_cache["value"] is not None and \
            _time.monotonic() - _heartbeat_cache["at"] < _HEARTBEAT_TTL_S:
        return _heartbeat_cache["value"]
    try:
        hb = watch_channel.read_heartbeat()
        at = _iso(hb.get("at"))
        value = {"heartbeat": {k: hb.get(k) for k in ("at", "since", "windows")},
                 "age_s": int((datetime.now(timezone.utc) - at).total_seconds()) if at else None,
                 "alive": watch_channel.alive(hb)}
    except Exception as exc:
        value = {"error": f"heartbeat unreadable: {exc}"[:300]}
    _heartbeat_cache.update(at=_time.monotonic(), value=value)
    return value


@app.get("/api/indicators")
async def indicators() -> dict:
    """The five indicators of the finality, for the overview (UI-2, #206): computed from the run
    reports, the watch's cycles, the cards and the catalog over 30 days — never from the
    exercise windows, emptied after 7 (eregion_console/indicators.py)."""
    import time as _time
    from datetime import timedelta
    from eregion_console import indicators as ind
    from glorfindel import escalations as esc_module
    from glorfindel.config import confidence_threshold
    now = datetime.now(timezone.utc)
    since = ind.since_window(now)
    cat = (await catalog()).get("entries", [])

    def gather() -> dict:
        runs = ind.read_runs(_run_reports(), since.timestamp())
        cycles = _watch_cycles(since.timestamp())
        cards = [e for e in esc_module.all_escalations() if e.get("exercise_run")]
        r30 = esc_module.observation_report(since=since)
        r7 = esc_module.observation_report(since=now - timedelta(days=7))
        return ind.compute(runs, cycles, cards, cat, r30.get("disruptive") or {},
                           r7.get("disruptive") or {}, confidence_threshold(), _time.time())
    return await asyncio.to_thread(gather)


@app.get("/api/channel")
async def channel() -> dict:
    """Both channels as this host sees them: the windows the watch pulled (which are live
    now), and the heartbeat it publishes — with the live windows it does not list yet (a run
    of such a window cannot conclude to a miss: ``watch_channel.miss_unprovable``)."""
    from eregion_core import exercise_channel, watch_channel
    from eregion_core.exercise import exercises_dir, live
    now = datetime.now(timezone.utc)
    directory = exercises_dir(_RUNS)
    windows = _read_windows()
    mtimes = [p.stat().st_mtime for p in directory.glob("*.json")] if directory.is_dir() else []
    live_ids = sorted(str(w["run_id"]) for w in windows if live(w, now))
    out = {
        "watch": await watch_status(),
        "exercise_channel": {
            "configured": bool(exercise_channel.channel_url()),
            "newest_window_at": datetime.fromtimestamp(max(mtimes), timezone.utc).isoformat()
            if mtimes else None,
        },
        "return_channel": {"configured": bool(watch_channel.channel_url())},
        "live_windows": live_ids,
    }
    if out["return_channel"]["configured"]:
        published = await asyncio.to_thread(_published_heartbeat)
        out["return_channel"].update(published)
        if "heartbeat" in published:
            listed = set(published["heartbeat"].get("windows") or [])
            out["return_channel"]["unlisted_windows"] = [r for r in live_ids if r not in listed]
    return out


@app.get("/api/channel/detections/{run_id}")
async def delivered(run_id: str) -> dict:
    """The detections the watch delivered on the return channel for this run's window — what
    the run on Orodruin read, or will read."""
    from eregion_core import watch_channel
    if not watch_channel.channel_url():
        return {"configured": False, "detections": []}
    try:
        detections = await asyncio.to_thread(watch_channel.read_detections, run_id)
    except ValueError:
        return {"error": "run id: a plain name"}
    except Exception as exc:
        return {"error": f"return channel unreadable: {exc}"[:300]}
    return {"configured": True, "detections": detections}


def serve(host: str = "127.0.0.1", port: int = 7007) -> None:
    try:
        import uvicorn
    except ImportError as e:
        raise ImportError(
            "The Eregion console requires extra dependencies: "
            "pip install -e '.[console]' from the clone"
        ) from e
    from eregion_console import sections
    sections.override()   # an unknown section stops here, before anything listens
    # Always a token (SEC1): the deployment's, else one drawn at the first start and kept in
    # the operator's file — shown here, with the URL that opens the console once. Flushed: in a
    # container stdout is a pipe, and a buffered line would never reach `docker compose logs`.
    token, where = ensure_token()
    if where == "env":
        print(f"  Eregion console  →  http://localhost:{port}/?token=${TOKEN_ENV}", flush=True)
    else:
        print(f"  Eregion console  →  http://localhost:{port}/?token={token}", flush=True)
        print(f"  (token {'drawn at this first start, ' if where == 'new' else ''}kept in "
              f"{_TOKEN_FILE}, mode 600; {TOKEN_ENV} sets another)", flush=True)
    uvicorn.run(app, host=host, port=port, log_level="warning")
