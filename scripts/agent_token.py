#!/usr/bin/env python3
"""agent_token — the identity of the agent sessions on GitHub: a GitHub App, on this repository
only (SEC12, #418; docs/sessions.md, « L'identité des sessions »).

  agent_token.py git-credential get   git's credential helper: a token for https://github.com only
  agent_token.py gh ARGS...           gh with GH_TOKEN set to the App's token, never another identity
  agent_token.py whoami               which repositories the token reaches, and until when
  agent_token.py token                the token on stdout (for a script that needs it)

A token is drawn as GitHub asks an App to (« Authenticating as a GitHub App installation »):
- a JWT signed RS256 with the App's private key: iat 60 s in the past (clock drift), exp 9 min
  ahead (GitHub refuses more than 10), iss the App's ID;
- the App's installation on the repository (GET /repos/{repo}/installation, with the JWT);
- an installation token restricted to this one repository (POST
  /app/installations/{id}/access_tokens, {"repositories": [name]}) — an hour long, its rights
  the App's (set by the maintainer when he creates it: never administration, never a tag).

The token is cached (0600, its directory 0700, owned by the user) and reused until MARGIN_S
before it expires; a cache of another App, another repository, readable by others or not ours is
never read. One draw at a time (a lock beside the cache): parallel sessions share one token.

Settings (environment):
  EREGION_AGENT_DIR      ~/.config/eregion-agents  (the App's ID and key: set up by the maintainer)
  EREGION_AGENT_APP_ID   the App's ID (else <dir>/app-id)
  EREGION_AGENT_KEY      the private key, PEM (else <dir>/app.pem) — refused when others can read it
  EREGION_AGENT_REPO     owner/name (Vanyar53/eregion)
  EREGION_AGENT_API      https://api.github.com
  EREGION_AGENT_CACHE    ~/.cache/eregion-agents/token.json
  EREGION_AGENT_GH       the real gh (else the first `gh` on PATH that is not this wrapper)

Errors are said, on stderr, in a sentence (exit 1): never the token, never the key. `gh` and the
credential helper never fall back on another identity: no token, no call. Needs PyJWT and
cryptography (locked: requirements/dev.txt, through msal and azure-identity).
"""
from __future__ import annotations

import contextlib
import datetime as dt
import fcntl
import json
import os
import re
import shutil
import stat
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

HOME = Path.home()
API = (os.environ.get("EREGION_AGENT_API") or "https://api.github.com").rstrip("/")
REPO = os.environ.get("EREGION_AGENT_REPO") or "Vanyar53/eregion"
DIR = Path(os.environ.get("EREGION_AGENT_DIR") or HOME / ".config" / "eregion-agents")
CACHE = Path(os.environ.get("EREGION_AGENT_CACHE") or HOME / ".cache" / "eregion-agents" / "token.json")
HOST = "github.com"
# Reused until 5 minutes before it expires: a push or a merge that starts never holds a token
# that dies on the way.
MARGIN_S = 300
JWT_PAST_S = 60          # GitHub: iat 60 s in the past, for the clock drift
JWT_LIFE_S = 540         # GitHub refuses an exp more than 10 minutes ahead
TOKEN_MAX_S = 3600 + 300  # an installation token lives an hour: anything longer is not GitHub's
# What a token may be: it ends up on a credential helper's line, and in GH_TOKEN. A newline would
# write another key into git's protocol. GitHub's tokens are ghs_… (and, since 2026, ghs_APPID_JWT:
# longer, with dots and dashes) — no assumption on the length.
TOKEN_RE = re.compile(r"[A-Za-z0-9_.\-]{20,4096}")
REPO_RE = re.compile(r"[A-Za-z0-9-]{1,39}/[A-Za-z0-9._-]{1,100}")
APP_ID_RE = re.compile(r"[0-9]{1,12}|Iv[0-9A-Za-z._-]{4,60}")    # an App ID, or a client ID


class TokenError(Exception):
    """Said in one sentence: what is missing or refused, and what to do."""

    def __init__(self, text: str, code: int = 0):
        super().__init__(text)
        self.code = code


# ── the App's ID and key ─────────────────────────────────────────────────────────────

def app_id() -> str:
    value = os.environ.get("EREGION_AGENT_APP_ID", "").strip()
    if not value:
        try:
            value = (DIR / "app-id").read_text(encoding="utf-8").strip()
        except OSError:
            raise TokenError(f"l'ID de l'App manque : EREGION_AGENT_APP_ID, ou {DIR / 'app-id'} "
                             "(docs/sessions.md, « L'identité des sessions »)") from None
    if not APP_ID_RE.fullmatch(value):
        raise TokenError("l'ID de l'App est illisible : un nombre (App ID) ou un client ID (Iv…)")
    return value


def private_key() -> bytes:
    path = Path(os.environ.get("EREGION_AGENT_KEY") or DIR / "app.pem")
    try:
        st = path.stat()
    except OSError:
        raise TokenError(f"la clé de l'App manque : {path} (créée sur GitHub, Settings → Developer "
                         "settings → GitHub Apps → Private keys)") from None
    if st.st_mode & 0o077:
        raise TokenError(f"la clé de l'App est lisible par d'autres ({stat.filemode(st.st_mode)}) : "
                         f"chmod 600 {path}")
    if st.st_uid != os.getuid():
        raise TokenError(f"la clé de l'App n'appartient pas à cet utilisateur : {path}")
    try:
        raw = path.read_bytes()
    except OSError as e:
        raise TokenError(f"la clé de l'App est illisible ({type(e).__name__}) : {path}") from None
    if b"PRIVATE KEY-----" not in raw:
        raise TokenError(f"{path} n'est pas une clé privée PEM")
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    try:
        key = serialization.load_pem_private_key(raw, password=None)
    except (ValueError, TypeError) as e:
        raise TokenError(f"la clé de l'App est illisible ({type(e).__name__}) : {path}") from None
    if not isinstance(key, rsa.RSAPrivateKey):
        raise TokenError(f"{path} n'est pas une clé RSA : GitHub signe les JWT des Apps en RS256")
    return raw


def app_jwt(app: str, key: bytes, now: float | None = None) -> str:
    """The JWT GitHub asks of an App: RS256, iat in the past, exp under 10 minutes."""
    import jwt   # PyJWT (locked through msal); its RS256 uses cryptography
    now = int(time.time() if now is None else now)
    try:
        return jwt.encode({"iat": now - JWT_PAST_S, "exp": now + JWT_LIFE_S, "iss": app}, key, algorithm="RS256")
    except (ValueError, TypeError) as e:
        raise TokenError(f"la clé de l'App ne signe pas en RS256 ({type(e).__name__}) : une clé RSA est attendue") from None
    except Exception as e:   # cryptography's errors for a key it cannot load
        raise TokenError(f"la clé de l'App est refusée ({type(e).__name__})") from None


# ── GitHub ───────────────────────────────────────────────────────────────────────────

SAID = {401: "GitHub refuse le JWT (401) : l'ID de l'App, la clé, ou l'horloge du poste (NTP)",
        403: "GitHub refuse (403) : l'App n'a pas ce droit, ou elle est suspendue",
        404: f"l'App n'est pas installée sur {REPO} (404) : Settings → GitHub Apps → Install, ce dépôt seul",
        422: "GitHub refuse la demande (422) : le dépôt n'est pas dans l'installation de l'App"}


def call(method: str, path: str, bearer: str, body: dict | None = None) -> dict:
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(f"{API}{path}", data=data, method=method, headers={
        "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28",
        "Authorization": f"Bearer {bearer}", "User-Agent": "eregion-agents",
        **({"Content-Type": "application/json"} if data else {})})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            out = json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        raise TokenError(SAID.get(e.code, f"GitHub répond {e.code} sur {path.split('?')[0]}"), e.code) from None
    except (OSError, ValueError) as e:
        raise TokenError(f"GitHub injoignable ou illisible ({type(e).__name__})") from None
    if not isinstance(out, dict):
        raise TokenError(f"réponse illisible de GitHub sur {path}")
    return out


def expiry(text) -> float:
    """expires_at (ISO 8601, « …Z ») as an epoch; ValueError when it is not one."""
    if not isinstance(text, str):
        raise ValueError
    when = dt.datetime.fromisoformat(text.replace("Z", "+00:00"))
    if when.tzinfo is None:
        raise ValueError
    return when.timestamp()


def draw(app: str, key: bytes, installation: int | None = None) -> dict:
    """A new installation token: {token, expires_at, installation}."""
    if not REPO_RE.fullmatch(REPO):
        raise TokenError(f"EREGION_AGENT_REPO illisible : owner/name attendu, pas {REPO!r}")
    bearer = app_jwt(app, key)
    out = None
    if installation is not None:
        try:
            out = call("POST", f"/app/installations/{installation}/access_tokens", bearer,
                       {"repositories": [REPO.split("/", 1)[1]]})
        except TokenError as e:
            if e.code != 404:           # the App reinstalled: its installation looked up again
                raise
    if out is None:
        found = call("GET", f"/repos/{REPO}/installation", bearer)
        installation = found.get("id")
        if not isinstance(installation, int) or isinstance(installation, bool) or installation <= 0:
            raise TokenError(f"l'installation de l'App sur {REPO} est illisible")
        out = call("POST", f"/app/installations/{installation}/access_tokens", bearer,
                   {"repositories": [REPO.split("/", 1)[1]]})
    token = out.get("token")
    if not isinstance(token, str) or not TOKEN_RE.fullmatch(token):
        raise TokenError("GitHub n'a pas rendu de jeton lisible")
    try:
        until = expiry(out.get("expires_at"))
    except ValueError:
        raise TokenError("GitHub n'a pas dit quand le jeton expire") from None
    now = time.time()
    if not now + MARGIN_S < until <= now + TOKEN_MAX_S:
        raise TokenError("le jeton rendu expire trop tôt, ou plus tard qu'un jeton d'installation : "
                         "l'horloge du poste (NTP) ?")
    return {"token": token, "expires_at": until, "installation": installation}


# ── the cache ────────────────────────────────────────────────────────────────────────

def read_cache(app: str) -> dict | None:
    """The cached token, when it is ours, private, for this App and repository, and lives on."""
    try:
        fd = os.open(CACHE, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        return None
    with os.fdopen(fd, "r", encoding="utf-8") as f:
        st = os.fstat(f.fileno())
        if st.st_uid != os.getuid() or st.st_mode & 0o077 or not stat.S_ISREG(st.st_mode):
            return None
        try:
            entry = json.load(f)
        except ValueError:
            return None
    if not isinstance(entry, dict) or entry.get("app") != app or entry.get("repo") != REPO:
        return None
    token, until = entry.get("token"), entry.get("expires_at")
    if not isinstance(token, str) or not TOKEN_RE.fullmatch(token) or not isinstance(until, (int, float)):
        return None
    return entry


def fresh(entry: dict | None) -> bool:
    return bool(entry) and entry["expires_at"] - time.time() > MARGIN_S


def write_cache(entry: dict) -> None:
    CACHE.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(CACHE.parent, 0o700)
    tmp = CACHE.with_name(f".{CACHE.name}.{os.getpid()}")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        os.fchmod(f.fileno(), 0o600)
        json.dump(entry, f)
    os.replace(tmp, CACHE)


@contextlib.contextmanager
def drawing():
    """One draw at a time between the sessions of this user."""
    CACHE.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(CACHE.with_name(CACHE.name + ".lock"), os.O_WRONLY | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def token() -> str:
    app = app_id()
    entry = read_cache(app)
    if fresh(entry):
        return entry["token"]
    with drawing():
        entry = read_cache(app)          # another session may have drawn meanwhile
        if fresh(entry):
            return entry["token"]
        new = draw(app, private_key(), (entry or {}).get("installation"))
        write_cache({**new, "app": app, "repo": REPO})
        return new["token"]


# ── the outputs ──────────────────────────────────────────────────────────────────────

def git_credential(action: str, stdin) -> int:
    """git's credential protocol: on `get` for https://github.com, the App's token; any other
    host or protocol, nothing (git asks its other helpers); `store` and `erase`, nothing."""
    asked = {}
    for line in stdin.read().splitlines():
        if not line:
            break
        k, _, v = line.partition("=")
        asked[k] = v
    if action != "get":
        return 0
    if asked.get("protocol") != "https" or asked.get("host") != HOST:
        return 0
    path = asked.get("path", "").removesuffix(".git").strip("/")
    if path and path.lower() != REPO.lower():
        return 0                        # the token reaches this repository only: say nothing
    sys.stdout.write(f"username=x-access-token\npassword={token()}\n")
    return 0


def real_gh() -> str:
    explicit = os.environ.get("EREGION_AGENT_GH")
    if explicit:
        return explicit
    here = Path(__file__).resolve().parent / "agent-bin"
    path = os.pathsep.join(p for p in os.environ.get("PATH", "").split(os.pathsep)
                           if p and Path(p).resolve() != here.resolve())
    found = shutil.which("gh", path=path)
    if not found:
        raise TokenError("gh introuvable sur le PATH (hors de scripts/agent-bin)")
    return found


def gh(args: list[str]) -> int:
    env = {k: v for k, v in os.environ.items() if k not in ("GITHUB_TOKEN", "GH_ENTERPRISE_TOKEN")}
    env["GH_TOKEN"] = token()
    # Never the maintainer's gh: its hosts.yml is in another directory, never read.
    env["GH_CONFIG_DIR"] = str(Path(os.environ.get("EREGION_AGENT_GH_CONFIG") or DIR / "gh"))
    env["GH_PROMPT_DISABLED"] = "1"
    exe = real_gh()
    os.execve(exe, [exe, *args], env)
    return 0   # not reached


def whoami() -> int:
    tok = token()
    out = call("GET", "/installation/repositories?per_page=100", tok)
    repos = sorted(str(r.get("full_name")) for r in out.get("repositories") or [] if isinstance(r, dict))
    entry = read_cache(app_id()) or {}
    left = int((entry.get("expires_at") or 0) - time.time())
    print(f"jeton de l'App {app_id()} : {', '.join(repos) or 'aucun dépôt'}"
          + (f" ; expire dans {left // 60} min" if left > 0 else ""))
    if [r.lower() for r in repos] != [REPO.lower()]:
        print(f"⚠️ le jeton devrait n'atteindre que {REPO}", file=sys.stderr)
        return 1
    return 0


def main(argv: list[str]) -> int:
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__)
        return 0 if argv else 2
    try:
        if argv[0] == "git-credential":
            return git_credential(argv[1] if len(argv) > 1 else "", sys.stdin)
        if argv[0] == "gh":
            return gh(argv[1:])
        if argv[0] == "whoami":
            return whoami()
        if argv[0] == "token":
            print(token())
            return 0
    except TokenError as e:
        print(f"agent_token : {e}", file=sys.stderr)
        return 1
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
