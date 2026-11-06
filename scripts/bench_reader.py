#!/usr/bin/env python3
"""bench_reader — the bench's read identity, for the Claude session « Banc » alone (BRO1, #614;
docs/operations.md, « L'identité de lecture du banc (BRO1) »; infra/terraform/bench_reader.tf).

  bench_reader.py keygen            the maintainer: a key pair and a certificate, DAYS long (30; 90 at most)
  bench_reader.py profile           the maintainer: the session's profile, from `terraform output -json bench_reader` on stdin
  bench_reader.py status            the profile, the certificate's end: nothing secret
  bench_reader.py login             the Banc session: az login as the reader, in its own AZURE_CONFIG_DIR
  bench_reader.py query KQL [--timespan P1D]   the Banc session: a KQL query on the bench's workspace
  bench_reader.py verify            the Banc session: one query read, one write refused (the tag of the workspace)
  bench_reader.py logout            the Banc session: the reader's tokens cleared

The identity is an application of the bench's tenant and its principal, holding Log Analytics Reader
on the bench's workspace alone. It signs in with a certificate whose private key is drawn here, on the
operator's machine: Terraform gets the public certificate only, so the key never enters its state.

Its directory (EREGION_BANC_DIR, else ~/.config/eregion-banc; 0700, the user's):
  reader.pem    the private key and its certificate, what `az login --certificate` reads (0600)
  reader.crt    the public certificate, what Terraform puts on the application (0600)
  reader.end    the certificate's end (RFC 3339), what Terraform poses as the identifier's end (0600)
  profile.env   tenant, application, workspace: identifiers, no secret (0600)
  az/           the session's AZURE_CONFIG_DIR, never the operator's ~/.azure (0700)

A code session never uses it (docs/sessions.md): every command but `status` refuses inside one —
EREGION_AGENT_SESSION set (the sessions of the repository, SEC12), or a lot's worktree
(.claude/worktrees/) as the current directory; `login`, `query`, `verify` and `logout` also want
EREGION_BANC_SESSION=1 and AZURE_CONFIG_DIR set to the reader's az/, which only the Banc session's
own settings set (without the latter, a bare `az` in the session reads the operator's ~/.azure);
`login`, `query` and `verify` refuse a session that inherited a credential from the shell that
launched it (ARM_*, AZURE_*, GH_*, GITHUB_*, *SECRET*, *TOKEN*: the names said, never the values). A
guard against a mistake,
not against a session that means harm: every session runs as the same Unix user
(docs/design/modele-de-menace.md, frontière 8).

`az` runs with no AZURE_* nor ARM_* variable of the caller's but the reader's AZURE_CONFIG_DIR: the
operator's identity is never mixed in. The workspace is the profile's, never an argument. Errors are
said on stderr, in a sentence (exit 1); `verify` exits 1 when the write passes.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

GUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
WORKSPACE_ID = re.compile(r"/subscriptions/[0-9a-f-]{36}/resourceGroups/[\w.()-]+/providers/"
                          r"Microsoft\.OperationalInsights/workspaces/[\w-]+", re.IGNORECASE)
TIMESPAN = re.compile(r"P(?:\d+D)?(?:T(?:\d+H)?(?:\d+M)?(?:\d+S)?)?")
ROLE = "Log Analytics Reader"
DAYS_DEFAULT = 30
DAYS_MAX = 90
PROFILE_KEYS = ("EREGION_BANC_TENANT_ID", "EREGION_BANC_CLIENT_ID", "EREGION_BANC_WORKSPACE_ID",
                "EREGION_BANC_WORKSPACE_RESOURCE_ID")
SUBJECT = "/CN=eregion-bench-reader"


class ReaderError(Exception):
    """Said on stderr, exit 1."""


def reader_dir(env: dict[str, str] | None = None) -> Path:
    env = os.environ if env is None else env
    return Path(env.get("EREGION_BANC_DIR") or Path.home() / ".config" / "eregion-banc")


# ── the guard ────────────────────────────────────────────────────────────────

def code_session_refusal(env: dict[str, str] | None = None, cwd: str | None = None) -> str:
    """Why this is a code session, or ''. A lot's session carries EREGION_AGENT_SESSION (the
    repository's settings, SEC12) and works in .claude/worktrees/<lot>."""
    env = os.environ if env is None else env
    if env.get("EREGION_AGENT_SESSION"):
        return ("une session de code (EREGION_AGENT_SESSION) : l'identité de lecture du banc est à la "
                "session Banc seule (docs/sessions.md)")
    where = Path(cwd or os.getcwd()).resolve()
    if ".claude" in where.parts and "worktrees" in where.parts[where.parts.index(".claude"):]:
        return f"le worktree d'un lot ({where}) : l'identité de lecture du banc est à la session Banc seule"
    return ""


def banc_session_refusal(env: dict[str, str] | None = None, cwd: str | None = None) -> str:
    """Why this is not the Banc session, or ''. The Banc session's settings also set its
    AZURE_CONFIG_DIR to the reader's: without it, a bare `az` in the session reads the operator's
    ~/.azure, his own sign-in."""
    env = os.environ if env is None else env
    refusal = code_session_refusal(env, cwd)
    if refusal:
        return refusal
    if env.get("EREGION_BANC_SESSION") != "1":
        return ("EREGION_BANC_SESSION n'est pas 1 : seule la session Banc s'en sert, lancée depuis son "
                "dossier (docs/operations.md, « L'identité de lecture du banc (BRO1) »)")
    own = reader_dir(env) / "az"
    cfg = env.get("AZURE_CONFIG_DIR", "")
    if not cfg or Path(cfg).expanduser().resolve() != own.expanduser().resolve():
        return (f"AZURE_CONFIG_DIR n'est pas {own} : sans lui, un az nu de la session lit ton ~/.azure, ta "
                "propre connexion. Le poser dans le .claude/settings.local.json de ~/eregion-banc/ "
                "(docs/operations.md, « La remise à la session Banc »)")
    return ""


def _private(path: Path, *, directory: bool) -> None:
    """Ours, of its kind, and nobody else's to read."""
    try:
        st = path.lstat()
    except FileNotFoundError:
        raise ReaderError(f"{path} absent : make celebrimbor-reader-key, puis make celebrimbor-reader-profile")
    kind = stat.S_ISDIR(st.st_mode) if directory else stat.S_ISREG(st.st_mode)
    if not kind or st.st_uid != os.getuid():
        raise ReaderError(f"{path} : pas un {'dossier' if directory else 'fichier'} de l'utilisateur, refusé")
    if st.st_mode & 0o077:
        raise ReaderError(f"{path} est lisible par d'autres ({stat.filemode(st.st_mode)}) : chmod "
                          f"{'700' if directory else '600'}, refusé")


# ── the profile ──────────────────────────────────────────────────────────────

def parse_profile(text: str) -> dict[str, str]:
    """KEY=value lines, the four keys and nothing else, each checked."""
    values: dict[str, str] = {}
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        key, sep, value = line.partition("=")
        if not sep or key not in PROFILE_KEYS or key in values:
            raise ReaderError(f"profil : ligne refusée ({key or line[:40]!r})")
        values[key] = value
    missing = [k for k in PROFILE_KEYS if k not in values]
    if missing:
        raise ReaderError(f"profil : {', '.join(missing)} manque")
    for key in PROFILE_KEYS[:3]:
        if not GUID.fullmatch(values[key]):
            raise ReaderError(f"profil : {key} n'est pas un GUID en minuscules")
    if not WORKSPACE_ID.fullmatch(values["EREGION_BANC_WORKSPACE_RESOURCE_ID"]):
        raise ReaderError("profil : EREGION_BANC_WORKSPACE_RESOURCE_ID n'est pas l'id ARM d'un workspace")
    return values


def profile_from_output(raw: str) -> str:
    """The profile's text, from `terraform output -json bench_reader`: null (disabled) is refused."""
    try:
        out = json.loads(raw)
    except json.JSONDecodeError:
        raise ReaderError("la sortie de terraform n'est pas du JSON (terraform output -json bench_reader)")
    if not isinstance(out, dict):
        raise ReaderError("bench_reader est null : bench_reader_enabled = true, puis make celebrimbor-reader-up")
    if out.get("role") != ROLE:
        raise ReaderError(f"le rôle de la sortie n'est pas {ROLE} : refusé")
    text = "".join(f"{k}={out.get(f)}\n" for k, f in zip(PROFILE_KEYS, (
        "tenant_id", "client_id", "workspace_id", "workspace_resource_id")))
    parse_profile(text)
    return text


def load_profile(d: Path) -> dict[str, str]:
    _private(d, directory=True)
    path = d / "profile.env"
    _private(path, directory=False)
    return parse_profile(path.read_text(encoding="utf-8"))


def _write_private(path: Path, data: bytes) -> None:
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def _ensure_dir(d: Path) -> None:
    if not d.exists():
        d.mkdir(mode=0o700, parents=True)
    _private(d, directory=True)


# ── the key pair ─────────────────────────────────────────────────────────────

def parse_days(raw: str | None) -> int:
    if raw in (None, ""):
        return DAYS_DEFAULT
    if not re.fullmatch(r"[0-9]{1,3}", raw):
        raise ReaderError(f"DAYS : un nombre de jours, 1 à {DAYS_MAX}")
    days = int(raw)
    if not 1 <= days <= DAYS_MAX:
        raise ReaderError(f"DAYS : {days} jours refusés — 1 à {DAYS_MAX} (une identité à durée courte)")
    return days


def end_date(enddate: str) -> str:
    """`openssl x509 -enddate` (notAfter=Dec  6 12:00:00 2026 GMT) in RFC 3339, UTC: the end
    Terraform poses on the identifier (bench_reader_certificate_end_file), never the API's."""
    value = enddate.strip().removeprefix("notAfter=")
    if not value.endswith(" GMT"):
        raise ReaderError(f"la fin du certificat est illisible ({enddate.strip()[:60]!r})")
    try:
        when = datetime.strptime(" ".join(value.removesuffix(" GMT").split()), "%b %d %H:%M:%S %Y")
    except ValueError:
        raise ReaderError(f"la fin du certificat est illisible ({enddate.strip()[:60]!r})")
    return when.strftime("%Y-%m-%dT%H:%M:%SZ")


def posed_end_said(path: Path, now: datetime | None = None) -> str:
    """What `status` says of reader.end: the date, and PASSÉE once past — the plan does not stop on a
    past end (no lower bound: stable plans), the identity just no longer signs in."""
    if not path.is_file():
        return "absente"
    text = path.read_text(encoding="utf-8").strip()
    try:
        when = datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return f"illisible ({text[:40]!r})"
    if when <= (now or datetime.now(timezone.utc)):
        return f"{text} — PASSÉE : une paire neuve, make celebrimbor-reader-key, puis make celebrimbor-reader-plan"
    return text


def keygen(d: Path, days: int, openssl: str = "openssl") -> None:
    """A fresh RSA key, its self-signed certificate and the certificate's end; the key never leaves `d`."""
    _ensure_dir(d)
    with tempfile.TemporaryDirectory(dir=d, prefix=".keygen.") as tmp:
        key, crt = Path(tmp) / "k", Path(tmp) / "c"
        res = subprocess.run([openssl, "req", "-x509", "-newkey", "rsa:3072", "-nodes", "-keyout", str(key),
                              "-out", str(crt), "-days", str(days), "-subj", SUBJECT],
                             capture_output=True, text=True, timeout=120)
        if res.returncode != 0 or not key.exists() or not crt.exists():
            raise ReaderError(f"openssl a échoué : {res.stderr.strip()[:300]}")
        end = subprocess.run([openssl, "x509", "-noout", "-enddate", "-in", str(crt)],
                             capture_output=True, text=True, timeout=30)
        if end.returncode != 0:
            raise ReaderError(f"openssl a échoué : {end.stderr.strip()[:300]}")
        when = end_date(end.stdout)
        cert = crt.read_bytes()
        _write_private(d / "reader.pem", key.read_bytes() + cert)
        _write_private(d / "reader.crt", cert)
        # Last: if it fails, the end left is the older one, earlier than the new certificate's.
        _write_private(d / "reader.end", f"{when}\n".encode())


# ── az, as the reader ────────────────────────────────────────────────────────

def az_env(d: Path, env: dict[str, str] | None = None) -> dict[str, str]:
    """The caller's environment without its Azure identity, and the reader's AZURE_CONFIG_DIR."""
    env = os.environ if env is None else env
    clean = {k: v for k, v in env.items() if not k.startswith(("AZURE_", "ARM_"))}
    clean["AZURE_CONFIG_DIR"] = str(d / "az")
    clean["AZURE_CORE_COLLECT_TELEMETRY"] = "no"
    return clean


def _az(d: Path, args: list[str]) -> subprocess.CompletedProcess:
    az = shutil.which("az")
    if not az:
        raise ReaderError("az introuvable sur le PATH")
    return subprocess.run([az, *args], env=az_env(d), capture_output=True, text=True, timeout=300)


def login_args(profile: dict[str, str], d: Path) -> list[str]:
    return ["login", "--service-principal", "--username", profile["EREGION_BANC_CLIENT_ID"],
            "--tenant", profile["EREGION_BANC_TENANT_ID"], "--certificate", str(d / "reader.pem"),
            "--allow-no-subscriptions", "--output", "none"]


def query_args(profile: dict[str, str], kql: str, timespan: str | None) -> list[str]:
    if not kql.strip():
        raise ReaderError("une requête KQL vide")
    args = ["monitor", "log-analytics", "query", "--workspace", profile["EREGION_BANC_WORKSPACE_ID"],
            "--analytics-query", kql, "--output", "json"]
    if timespan:
        if not TIMESPAN.fullmatch(timespan) or timespan in ("P", "PT"):
            raise ReaderError("--timespan : une durée ISO 8601 (P1D, PT6H)")
        args += ["--timespan", timespan]
    return args


# The write `verify` tries, harmless if it ever passed: a tag on the workspace, removed at once.
VERIFY_TAG = "eregion-bro1-write-check"


def write_args(profile: dict[str, str]) -> list[str]:
    return ["tag", "update", "--resource-id", profile["EREGION_BANC_WORKSPACE_RESOURCE_ID"],
            "--operation", "merge", "--tags", f"{VERIFY_TAG}=1", "--output", "none"]


# What the Banc session may hold of the kind: its own az and gh directories. The model's own
# credentials (CLAUDE_CODE_*, ANTHROPIC_*) are the session's, never a cloud's nor GitHub's.
_KEPT = ("AZURE_CONFIG_DIR", "GH_CONFIG_DIR")
_MODEL = ("CLAUDE_CODE_", "ANTHROPIC_")


def inherited_credentials(env: dict[str, str] | None = None) -> list[str]:
    """The names, never the values, of the credentials the session inherited from the shell that
    launched it (.envrc sourced there: GLORFINDEL_AZURE_CLIENT_SECRET, ARM_*; an exported GH_TOKEN
    passes over GH_CONFIG_DIR). The script strips them from its own az; a terraform, an SDK or a gh
    of the session would use them."""
    env = os.environ if env is None else env
    names = []
    for name in env:
        if name in _KEPT or name.startswith(_MODEL):
            continue
        upper = name.upper()
        if upper.startswith(("ARM_", "AZURE_", "GH_", "GITHUB_")) or "SECRET" in upper or "TOKEN" in upper:
            names.append(name)
    return sorted(names)


def _session(d: Path) -> dict[str, str]:
    refusal = banc_session_refusal()
    if refusal:
        raise ReaderError(refusal)
    leaked = inherited_credentials()
    if leaked:
        raise ReaderError(f"la session a hérité de {', '.join(leaked)} (le shell qui l'a lancée) : la relancer "
                          "d'un terminal neuf, où .envrc n'a jamais été sourcé (docs/operations.md, « La remise "
                          "à la session Banc »)")
    profile = load_profile(d)
    _private(d / "reader.pem", directory=False)
    _ensure_dir(d / "az")
    return profile


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="bench_reader.py", description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("keygen")
    sub.add_parser("profile")
    sub.add_parser("status")
    sub.add_parser("login")
    q = sub.add_parser("query")
    q.add_argument("kql")
    q.add_argument("--timespan")
    sub.add_parser("verify")
    sub.add_parser("logout")
    a = parser.parse_args(argv)
    d = reader_dir()
    try:
        if a.cmd != "status":
            refusal = code_session_refusal()
            if refusal:
                raise ReaderError(refusal)
        if a.cmd == "keygen":
            days = parse_days(os.environ.get("EREGION_BANC_DAYS"))
            keygen(d, days)
            end = (d / "reader.end").read_text(encoding="utf-8").strip()
            print(f"{d}/reader.pem (la clé, 0600), {d}/reader.crt (le certificat public) et {d}/reader.end "
                  f"(sa fin, {end}) : {days} jours. Puis make celebrimbor-reader-plan, et make "
                  "celebrimbor-reader-up YES=1.")
        elif a.cmd == "profile":
            text = profile_from_output(sys.stdin.read())
            _ensure_dir(d)
            _write_private(d / "profile.env", text.encode())
            print(f"{d}/profile.env écrit (0600) : tenant, application, workspace — aucun secret.")
        elif a.cmd == "status":
            p = load_profile(d)
            end = subprocess.run(["openssl", "x509", "-noout", "-enddate", "-in", str(d / "reader.crt")],
                                 capture_output=True, text=True, timeout=30)
            print(f"application {p['EREGION_BANC_CLIENT_ID']}, workspace {p['EREGION_BANC_WORKSPACE_ID']} ({ROLE})")
            print(f"certificat : {end.stdout.strip() or 'illisible'}")
            posed = d / "reader.end"
            print(f"fin posée sur l'identifiant (reader.end) : {posed_end_said(posed)}")
        elif a.cmd == "login":
            p = _session(d)
            res = _az(d, login_args(p, d))
            if res.returncode != 0:
                raise ReaderError(f"az login a échoué : {res.stderr.strip()[-400:]}")
            print(f"connecté comme l'identité de lecture du banc ({p['EREGION_BANC_CLIENT_ID']}), "
                  f"AZURE_CONFIG_DIR={d / 'az'}")
        elif a.cmd == "query":
            p = _session(d)
            res = _az(d, query_args(p, a.kql, a.timespan))
            if res.returncode != 0:
                raise ReaderError(f"la requête a échoué : {res.stderr.strip()[-400:]}")
            sys.stdout.write(res.stdout)
        elif a.cmd == "verify":
            p = _session(d)
            read = _az(d, query_args(p, "print ok = 1", None))
            if read.returncode != 0:
                raise ReaderError(f"la lecture a échoué : {read.stderr.strip()[-400:]}")
            print("lecture : passée")
            write = _az(d, write_args(p))
            if write.returncode == 0:
                _az(d, ["tag", "update", "--resource-id", p["EREGION_BANC_WORKSPACE_RESOURCE_ID"],
                        "--operation", "delete", "--tags", f"{VERIFY_TAG}=1", "--output", "none"])
                raise ReaderError("ÉCRITURE PASSÉE : l'identité de lecture écrit sur le workspace. Retirer son "
                                  "rôle (bench_reader_enabled = false, make celebrimbor-reader-up), puis comprendre")
            if "AuthorizationFailed" not in write.stderr:
                raise ReaderError(f"l'écriture a échoué, pas par un refus d'autorisation : "
                                  f"{write.stderr.strip()[-400:]}")
            print("écriture : refusée (AuthorizationFailed)")
        elif a.cmd == "logout":
            refusal = banc_session_refusal()
            if refusal:
                raise ReaderError(refusal)
            res = _az(d, ["account", "clear"])
            if res.returncode != 0:
                raise ReaderError(f"az account clear a échoué : {res.stderr.strip()[-400:]}")
            print("les jetons de l'identité de lecture sont effacés")
    except ReaderError as e:
        print(f"bench_reader : {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
