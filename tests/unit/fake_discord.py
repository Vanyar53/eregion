"""A fake Discord on the loopback, for notify_discord.py and roadmap_discord.py (N1, N2).

The routes the scripts use, as Discord answers them: the webhooks (a message posted, edited,
deleted), the Eregion bot's forum (#lots: its tags, active and archived threads, posts, a file
sent as multipart), its #roadmap channel (pins, last messages, a message posted or edited), and
GitHub's API (workflow runs, milestones, issues, pull requests) under /gh. Nothing leaves the
machine; every request is kept for the tests.
"""
import email.parser
import email.policy
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

# The forum's tags, as set up in Discord (docs/atelier-discord.md).
TAG_NAMES = ("à faire", "en cours", "en relecture", "en correction", "fait", "bloqué",
             "v0.3", "v0.x", "v1.0", "v1.x")
# Ids as if the milestones were created first: Discord gives a thread's tags back sorted by id,
# so not in the order they were sent (state, then milestone) — as the real forum did on 27/10.
TAGS = [{"id": f"t{(i + 4) % 10}", "name": n} for i, n in enumerate(TAG_NAMES)]
TAG = {t["name"]: t["id"] for t in TAGS}
BOT_ID = "BOT"


def _multipart(ctype: str, raw: bytes) -> dict:
    """A multipart body as the tests read it: its payload_json, and its files by name."""
    msg = email.parser.BytesParser(policy=email.policy.default).parsebytes(
        f"Content-Type: {ctype}\r\n\r\n".encode() + raw)
    out = {"payload_json": None, "files": {}}
    for part in msg.iter_parts():
        if part.get_filename():
            out["files"][part.get_filename()] = part.get_content()
        elif part.get_param("name", header="content-disposition") == "payload_json":
            out["payload_json"] = json.loads(part.get_content())
    return out


class FakeDiscord:
    def __init__(self):
        self.requests, self.messages, self.threads, self.runs = [], {}, [], []
        self.roadmap: list[dict] = []        # #roadmap's messages, newest first
        self.gh = {"milestones": [], "issues": [], "pulls": []}
        self.fail: dict[str, int] = {}       # path prefix → status (once if listed in self.once)
        self.once: set[str] = set()
        self.lock, self.next_id = threading.Lock(), 100
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _serve(self):
                n = int(self.headers.get("Content-Length") or 0)
                raw, ctype = (self.rfile.read(n) if n else b""), self.headers.get("Content-Type", "")
                body = _multipart(ctype, raw) if ctype.startswith("multipart/") else json.loads(raw) if raw else None
                status, out, headers = fake.handle(self.command, self.path, body, dict(self.headers))
                raw = b"" if status == 204 else json.dumps(out).encode()
                self.send_response(status)
                for k, v in headers.items():
                    self.send_header(k, v)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)
            do_GET = do_POST = do_PATCH = do_DELETE = _serve

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.server.serve_forever, args=(0.01,), daemon=True).start()
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"

    def close(self):
        self.server.shutdown()
        self.server.server_close()

    def _id(self):
        self.next_id += 1
        return str(self.next_id)

    def thread(self, name, tags=(), archived=False):
        t = {"id": self._id(), "name": name, "parent_id": "FORUM", "applied_tags": sorted(tags),
             "thread_metadata": {"archived": archived, "archive_timestamp": "2026-10-01T00:00:00+00:00"},
             "posts": []}
        self.threads.append(t)
        return t

    def roadmap_message(self, title, author=BOT_ID, pinned=False):
        m = {"id": self._id(), "author": {"id": author}, "embeds": [{"title": title}], "pinned": pinned}
        self.roadmap.insert(0, m)
        return m

    def writes(self, prefix=""):
        return [r for r in self.requests if r["method"] in ("POST", "PATCH") and r["path"].startswith(prefix)]

    def handle(self, method, path, body, headers):
        with self.lock:
            self.requests.append({"method": method, "path": path, "body": body, "headers": headers})
            for prefix, status in list(self.fail.items()):
                if path.startswith(prefix):
                    if prefix in self.once:
                        del self.fail[prefix]
                    return status, {"retry_after": 0}, {"Retry-After": "0"} if status == 429 else {}
            url = urlsplit(path)
            p, query = url.path, parse_qs(url.query)
            parts = p.strip("/").split("/")
            if p.startswith("/gh/"):
                return self._github(p, query)
            if parts[:2] == ["api", "webhooks"]:
                if method == "POST":
                    mid = self._id()
                    self.messages[mid] = body
                    return 200, {"id": mid}, {}
                mid = parts[-1]
                if mid not in self.messages:
                    return 404, {"message": "Unknown Message"}, {}
                if method == "DELETE":
                    del self.messages[mid]
                    return 204, {}, {}
                self.messages[mid] = body
                return 200, {"id": mid}, {}
            if p == "/api/users/@me":
                return 200, {"id": BOT_ID, "username": "Eregion", "bot": True}, {}
            if parts[:3] == ["api", "channels", "ROADMAP"]:
                return self._roadmap(method, parts[3:], body)
            if p == "/api/channels/FORUM" and method == "GET":
                return 200, {"id": "FORUM", "guild_id": "GUILD", "type": 15, "available_tags": TAGS}, {}
            if p == "/api/guilds/GUILD/threads/active":
                return 200, {"threads": [t for t in self.threads if not t["thread_metadata"]["archived"]]}, {}
            if p == "/api/channels/FORUM/threads/archived/public":
                archived = [t for t in self.threads if t["thread_metadata"]["archived"]]
                if "before" not in query and len(archived) > 1:   # Discord pages its answer
                    return 200, {"threads": archived[:1], "has_more": True}, {}
                return 200, {"threads": archived[1:] if "before" in query else archived, "has_more": False}, {}
            if p == "/api/channels/FORUM/threads" and method == "POST":
                t = self.thread(body["name"], body.get("applied_tags") or [])
                t["posts"].append(body["message"])
                return 201, t, {}
            if parts[:2] == ["api", "channels"] and len(parts) >= 3:
                t = next((t for t in self.threads if t["id"] == parts[2]), None)
                if t is None:
                    return 404, {}, {}
                if parts[3:] == ["messages"] and method == "POST":
                    t["posts"].append(body)
                    return 200, {"id": self._id()}, {}
                if method == "PATCH":
                    if "applied_tags" in body:
                        t["applied_tags"] = sorted(body["applied_tags"])
                    if "name" in body:
                        t["name"] = body["name"]
                    if "archived" in body:
                        t["thread_metadata"]["archived"] = body["archived"]
                    return 200, t, {}
            return 404, {}, {}

    def _roadmap(self, method, rest, body):
        if method == "GET" and rest == ["pins"]:
            return 200, [m for m in self.roadmap if m["pinned"]], {}
        if method == "GET" and rest == ["messages"]:
            return 200, self.roadmap[:50], {}
        if method == "POST" and rest == ["messages"]:
            m = {"id": self._id(), "author": {"id": BOT_ID}, "pinned": False, **body}
            self.roadmap.insert(0, m)
            return 200, m, {}
        if method == "PATCH" and rest[:1] == ["messages"]:
            m = next((m for m in self.roadmap if m["id"] == rest[1]), None)
            if m is None:
                return 404, {}, {}
            if m["author"]["id"] != BOT_ID:
                return 403, {"message": "Cannot edit a message authored by another user"}, {}
            m.update(body)
            return 200, m, {}
        return 404, {}, {}

    def _github(self, p, query):
        if p.startswith("/gh/repos/o/r/actions/workflows/"):
            return 200, {"workflow_runs": self.runs}, {}
        if p == "/gh/repos/o/r/milestones":
            return 200, self.gh["milestones"], {}
        if p == "/gh/repos/o/r/issues":
            page = int((query.get("page") or ["1"])[0])
            per = int((query.get("per_page") or ["30"])[0])
            return 200, self.gh["issues"][(page - 1) * per: page * per], {}
        if p == "/gh/repos/o/r/pulls":
            return 200, self.gh["pulls"], {}
        if p.startswith("/gh/repos/o/r/pulls/"):
            pr = next((x for x in self.gh["pulls"] if str(x.get("number")) == p.rsplit("/", 1)[1]), None)
            return (200, pr, {}) if pr else (404, {}, {})
        return 404, {}, {}

    def webhook_posts(self, token):
        return [r["body"] for r in self.requests if r["method"] == "POST" and token in r["path"]]
