"""SEC12 (#418) — the agent sessions' own identity on GitHub: a GitHub App, this repository only.

scripts/agent_token.py runs as the sessions run it — git's credential helper, the gh wrapper —
against a fake GitHub on the loopback that checks the App's JWT with the public half of a key
generated here (tmp_path), never the maintainer's: no network, no real key, no real token, HOME
a tmp dir. The fake answers as GitHub's « Authenticating as a GitHub App installation » says:
GET /repos/{repo}/installation and POST /app/installations/{id}/access_tokens with the JWT,
GET /installation/repositories with the installation token.
"""
import datetime as dt
import json
import os
import stat
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "agent_token.py"
WRAPPERS = ROOT / "scripts" / "agent-bin"
APP_ID = "123456"


def _iso(epoch: float) -> str:
    return dt.datetime.fromtimestamp(int(epoch), dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class FakeGitHub:
    """GitHub's App endpoints, checking each JWT against the test's public key."""

    def __init__(self, public_pem: bytes):
        self.public, self.requests, self.claims, self.headers = public_pem, [], [], []
        self.installation, self.repos, self.n = 7, ["o/r"], 0
        self.status: dict[str, int] = {}         # path → status
        self.answer: dict = {}                   # fields forced in the token's answer
        self.issued: list[str] = []
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _serve(self):
                n = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(n)) if n else None
                status, out = fake.handle(self.command, self.path, body, dict(self.headers))
                raw = json.dumps(out).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)
            do_GET = do_POST = _serve

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.server.serve_forever, args=(0.01,), daemon=True).start()
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"

    def close(self):
        self.server.shutdown()
        self.server.server_close()

    def _app(self, headers) -> bool:
        auth = headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return False
        try:
            claims = jwt.decode(auth[7:], self.public, algorithms=["RS256"], options={"verify_iat": False})
        except jwt.PyJWTError:
            return False
        self.claims.append({"claims": claims, "header": jwt.get_unverified_header(auth[7:]), "at": time.time()})
        return claims.get("iss") == APP_ID and claims["exp"] - claims["iat"] <= 600

    def handle(self, method, path, body, headers):
        self.requests.append({"method": method, "path": path, "body": body})
        self.headers.append(headers)
        if path in self.status:
            return self.status[path], {"message": "forced"}
        if path == "/repos/o/r/installation" and method == "GET":
            return (200, {"id": self.installation}) if self._app(headers) else (401, {"message": "Bad credentials"})
        if path.startswith("/app/installations/") and path.endswith("/access_tokens") and method == "POST":
            if not self._app(headers):
                return 401, {"message": "Bad credentials"}
            if path.split("/")[3] != str(self.installation):
                return 404, {"message": "Not Found"}
            self.n += 1
            token = f"ghs_{self.n:036d}"
            self.issued.append(token)
            return 201, {"token": token, "expires_at": _iso(time.time() + 3600), **self.answer}
        if path.startswith("/installation/repositories"):
            if headers.get("Authorization") not in [f"Bearer {t}" for t in self.issued]:
                return 401, {"message": "Bad credentials"}
            return 200, {"repositories": [{"full_name": r} for r in self.repos]}
        return 404, {"message": "Not Found"}

    def draws(self):
        return [r for r in self.requests if r["path"].endswith("/access_tokens")]


@pytest.fixture(scope="module")
def keypair():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption())
    public = key.public_key().public_bytes(serialization.Encoding.PEM,
                                           serialization.PublicFormat.SubjectPublicKeyInfo)
    return private, public


@pytest.fixture
def gh_fake(keypair):
    f = FakeGitHub(keypair[1])
    yield f
    f.close()


class Agent:
    def __init__(self, tmp_path, fake, private):
        self.tmp, self.fake = tmp_path, fake
        self.home = tmp_path / "home"
        self.dir = self.home / ".config" / "eregion-agents"
        self.dir.mkdir(parents=True)
        self.key = self.dir / "app.pem"
        self.key.write_bytes(private)
        self.key.chmod(0o600)
        (self.dir / "app-id").write_text(APP_ID + "\n")
        self.cache = self.home / ".cache" / "eregion-agents" / "token.json"
        self.env = {k: v for k, v in os.environ.items()
                    if not k.startswith(("EREGION_", "GH_", "GITHUB_", "GIT_"))}
        self.env.update({"HOME": str(self.home), "EREGION_AGENT_API": fake.base, "EREGION_AGENT_REPO": "o/r"})

    def run(self, *args, stdin="", **env):
        return subprocess.run([sys.executable, str(SCRIPT), *args], input=stdin, capture_output=True,
                              text=True, env={**self.env, **env}, timeout=60)

    def credential(self, asked="protocol=https\nhost=github.com\n\n", action="get", **env):
        return self.run("git-credential", action, stdin=asked, **env)

    def cached(self):
        return json.loads(self.cache.read_text())

    def age_cache(self, left_s):
        entry = self.cached()
        entry["expires_at"] = time.time() + left_s
        self.cache.write_text(json.dumps(entry))


@pytest.fixture
def agent(tmp_path, gh_fake, keypair):
    return Agent(tmp_path, gh_fake, keypair[0])


def _password(res):
    lines = dict(line.split("=", 1) for line in res.stdout.splitlines())
    assert lines["username"] == "x-access-token"
    return lines["password"]


# ── the token ────────────────────────────────────────────────────────────────────────

def test_a_token_is_drawn_with_the_jwt_github_asks_for_and_restricted_to_the_repository(agent, gh_fake):
    before = time.time()
    res = agent.credential()
    assert res.returncode == 0, res.stderr
    assert _password(res) == gh_fake.issued[0]
    seen = gh_fake.claims[0]
    claims = seen["claims"]
    assert seen["header"]["alg"] == "RS256" and claims["iss"] == APP_ID
    assert claims["iat"] <= before - 55                      # 60 s in the past: the clock drift
    assert claims["exp"] - claims["iat"] <= 600 and claims["exp"] > time.time() + 300
    assert [r["path"] for r in gh_fake.requests] == ["/repos/o/r/installation", "/app/installations/7/access_tokens"]
    assert gh_fake.draws()[0]["body"] == {"repositories": ["r"]}   # this repository, nothing else


def test_the_token_is_cached_private_and_reused(agent, gh_fake):
    first = _password(agent.credential())
    assert _password(agent.credential()) == first and len(gh_fake.draws()) == 1
    assert stat.S_IMODE(agent.cache.stat().st_mode) == 0o600
    assert stat.S_IMODE(agent.cache.parent.stat().st_mode) == 0o700
    assert agent.cached()["installation"] == 7 and agent.cached()["repo"] == "o/r"


def test_a_token_near_its_expiry_is_drawn_again_never_one_that_lives_on(agent, gh_fake):
    agent.credential()
    agent.age_cache(400)                                     # more than 5 minutes left: reused
    agent.credential()
    assert len(gh_fake.draws()) == 1
    agent.age_cache(200)                                     # less than 5 minutes: a new one
    assert _password(agent.credential()) == gh_fake.issued[1]
    # The installation is remembered: the second draw asks for the token straight away.
    assert [r["path"] for r in gh_fake.requests].count("/repos/o/r/installation") == 1


@pytest.mark.parametrize("spoil", ["mode", "app", "repo", "garbage"])
def test_a_cache_not_ours_or_not_private_is_never_read(agent, gh_fake, spoil):
    agent.credential()
    entry = agent.cached()
    if spoil == "mode":
        agent.cache.chmod(0o644)
    elif spoil == "garbage":
        agent.cache.write_text("{")
    else:
        entry[spoil] = "other"
        agent.cache.write_text(json.dumps(entry))
    assert _password(agent.credential()) == gh_fake.issued[1]
    assert stat.S_IMODE(agent.cache.stat().st_mode) == 0o600


def test_a_reinstalled_app_is_looked_up_again(agent, gh_fake):
    agent.credential()
    agent.age_cache(0)
    gh_fake.installation = 8                                 # uninstalled, then installed again
    assert _password(agent.credential()) == gh_fake.issued[1]
    assert agent.cached()["installation"] == 8


# ── errors, said ─────────────────────────────────────────────────────────────────────

def _said(agent, res, words):
    assert res.returncode == 1 and res.stdout == ""
    assert words in res.stderr
    assert "PRIVATE KEY" not in res.stderr and "ghs_" not in res.stderr


def test_a_missing_or_open_key_is_said_and_nothing_is_asked(agent, gh_fake):
    agent.key.chmod(0o644)
    _said(agent, agent.credential(), "chmod 600")
    agent.key.unlink()
    _said(agent, agent.credential(), "la clé de l'App manque")
    assert gh_fake.requests == []


def test_a_missing_app_id_or_a_key_that_is_no_rsa_key_is_said(agent, gh_fake):
    (agent.dir / "app-id").unlink()
    _said(agent, agent.credential(), "l'ID de l'App manque")
    _said(agent, agent.credential(EREGION_AGENT_APP_ID="12; rm"), "illisible")
    other = ec.generate_private_key(ec.SECP256R1()).private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    agent.key.write_bytes(other)
    _said(agent, agent.credential(EREGION_AGENT_APP_ID=APP_ID), "RSA")
    assert gh_fake.requests == []


@pytest.mark.parametrize("path, status, words", [
    ("/repos/o/r/installation", 404, "n'est pas installée sur o/r"),
    ("/repos/o/r/installation", 401, "horloge"),
    ("/app/installations/7/access_tokens", 403, "403"),
    ("/app/installations/7/access_tokens", 422, "422"),
])
def test_what_github_refuses_is_said(agent, gh_fake, path, status, words):
    gh_fake.status[path] = status
    _said(agent, agent.credential(), words)
    assert not agent.cache.exists()


@pytest.mark.parametrize("answer, words", [
    ({"token": "ghs_x\npassword=other"}, "jeton lisible"),       # a line of git's protocol
    ({"token": ""}, "jeton lisible"),
    ({"expires_at": None}, "quand le jeton expire"),
    ({"expires_at": "tomorrow"}, "quand le jeton expire"),
    ({"expires_at": "2026-11-02T10:00:00"}, "quand le jeton expire"),    # no time zone
    ({"expires_at": _iso(time.time() + 120)}, "expire trop tôt"),
    ({"expires_at": _iso(time.time() + 3 * 3600)}, "plus tard qu'un jeton d'installation"),
])
def test_an_answer_that_is_not_a_token_is_refused(agent, gh_fake, answer, words):
    gh_fake.answer = answer
    _said(agent, agent.credential(), words)
    assert not agent.cache.exists()


def test_github_out_of_reach_is_said(agent):
    _said(agent, agent.credential(EREGION_AGENT_API="http://127.0.0.1:9"), "injoignable")


# ── the outputs ──────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("asked, action", [
    ("protocol=https\nhost=example.com\n\n", "get"),
    ("protocol=http\nhost=github.com\n\n", "get"),
    ("protocol=https\nhost=github.com.example.com\n\n", "get"),
    ("protocol=https\nhost=github.com\npath=other/repo.git\n\n", "get"),
    ("protocol=https\nhost=github.com\nusername=x\npassword=y\n\n", "store"),
    ("protocol=https\nhost=github.com\n\n", "erase"),
])
def test_the_credential_helper_answers_github_over_https_for_this_repository_only(agent, gh_fake, asked, action):
    res = agent.credential(asked, action)
    assert res.returncode == 0 and res.stdout == "" and gh_fake.requests == []


def test_the_credential_helper_answers_for_this_repositorys_path(agent, gh_fake):
    res = agent.credential("protocol=https\nhost=github.com\npath=O/R.git\n\n")
    assert _password(res) == gh_fake.issued[0]


FAKE_GH = """#!{py}
import json, os, sys
open(os.environ["FAKE_GH_OUT"], "w").write(json.dumps({{"argv": sys.argv[1:], "GH_TOKEN": os.environ.get("GH_TOKEN"),
    "GITHUB_TOKEN": os.environ.get("GITHUB_TOKEN"), "GH_CONFIG_DIR": os.environ.get("GH_CONFIG_DIR")}}))
"""


@pytest.fixture
def real_gh(tmp_path):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "gh").write_text(FAKE_GH.format(py=sys.executable))
    (bin_dir / "gh").chmod(0o755)
    return bin_dir, tmp_path / "gh.json"


def test_gh_runs_with_the_apps_token_never_the_maintainers(agent, gh_fake, real_gh):
    bin_dir, out = real_gh
    # The wrapper first on the PATH, as the sessions have it: it finds the real gh behind it.
    res = subprocess.run([str(WRAPPERS / "gh"), "pr", "view", "1"], capture_output=True, text=True, timeout=60,
                         env={**agent.env, "PATH": f"{WRAPPERS}{os.pathsep}{bin_dir}{os.pathsep}{agent.env['PATH']}",
                              "EREGION_AGENT_PYTHON": sys.executable, "GITHUB_TOKEN": "maintainer",
                              "FAKE_GH_OUT": str(out)})
    assert res.returncode == 0, res.stderr
    seen = json.loads(out.read_text())
    assert seen["argv"] == ["pr", "view", "1"] and seen["GH_TOKEN"] == gh_fake.issued[0]
    assert seen["GITHUB_TOKEN"] is None
    assert seen["GH_CONFIG_DIR"] == str(agent.dir / "gh")      # never the maintainer's hosts.yml


def test_without_a_token_gh_is_never_run(agent, gh_fake, real_gh):
    bin_dir, out = real_gh
    gh_fake.status["/repos/o/r/installation"] = 404
    res = agent.run("gh", "pr", "merge", "1", EREGION_AGENT_GH=str(bin_dir / "gh"), FAKE_GH_OUT=str(out))
    _said(agent, res, "n'est pas installée")
    assert not out.exists()


def test_the_git_credential_wrapper_runs_the_helper(agent, gh_fake):
    res = subprocess.run([str(WRAPPERS / "git-credential-eregion-agent"), "get"], capture_output=True, text=True,
                         input="protocol=https\nhost=github.com\n\n", timeout=60,
                         env={**agent.env, "EREGION_AGENT_PYTHON": sys.executable})
    assert _password(res) == gh_fake.issued[0]


@pytest.mark.parametrize("repos, code", [(["o/r"], 0), (["o/r", "o/other"], 1)])
def test_whoami_says_which_repositories_the_token_reaches(agent, gh_fake, repos, code):
    gh_fake.repos = repos
    res = agent.run("whoami")
    assert res.returncode == code and APP_ID in res.stdout and "o/r" in res.stdout
    assert gh_fake.issued[0] not in res.stdout + res.stderr
