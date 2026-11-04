"""GS1 (#520): make doctor — what a first start needs, checked before it, without calling the
cloud nor the model.

    make doctor                    # PROFILE=discover: Glorfindel alone, read-only (docs/demarrer/bleu.md)
    make doctor PROFILE=bench      # the full bench, before a first attack (docs/demarrer/banc.md)
    python3 scripts/doctor.py [--profile discover|bench]

Each check prints ✓, ✗ with the command that fixes it, or · for something optional left out.
Exit 0 only when no check failed, 1 otherwise, 2 for a profile it does not know — through make,
which gives a failed recipe its own code, 2 in both cases.

**Nothing secret leaves it.** A variable is read for its presence and its shape only — set,
its pair complete, not the example value left from `.envrc.example`, a key of the right form —
and its value is never printed, written, nor compared with anything but the same variable of
another file (the bench's channels: equal or not, never which). The env files of the bench
(`infra/orodruin/orodruin.env`, `infra/glorfindel-host/host.env`) are read the same way.

**Nothing remote.** The only commands it runs are local: `docker info`, `docker compose
version`, `docker ps` (who holds the console's port). No `az`, no `terraform`, no model.

The standard library only: it runs before `make install`. With the venv there (`make doctor`
takes `.venv/bin/python` when it exists), the configuration is also read as the watch reads it
(`glorfindel.config.load_glorfindel_config`, strict, A3).
"""
from __future__ import annotations

import argparse
import base64
import os
import re
import shutil
import socket
import stat
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Mapping

REPO = Path(__file__).resolve().parent.parent
PROFILES = ("discover", "bench")
OK, FAIL, WARN = "ok", "fail", "warn"
MARK = {OK: "✓", FAIL: "✗", WARN: "·"}

PYTHON_MIN = (3, 11)
CONSOLE_PORT = 7007
# glorfindel/config.py, read_only_requested: off only when it clearly says so (G2) — a test
# keeps the two the same.
SWITCH_OFF = {"", "0", "false", "no", "off", "n"}
# What eregion_core/models.py takes when GLORFINDEL_LLM_MODEL is empty (a test keeps it).
DEFAULT_PROVIDER = "anthropic"
# The key each provider of LiteLLM reads, by the prefix of GLORFINDEL_LLM_MODEL.
PROVIDER_KEYS = {
    "anthropic": ("ANTHROPIC_API_KEY",),
    "openai": ("OPENAI_API_KEY",),
    "azure": ("AZURE_API_KEY", "AZURE_API_BASE"),
    "mistral": ("MISTRAL_API_KEY",),
}
# The three services of Glorfindel, each its own principal (V-17, SEC11): the watch's pair is
# required to read Azure; the console's and the bot's are optional, never half set — the bot's
# absence is not even said (`make profile-discover` does not start it).
PAIRS = (("GLORFINDEL", "la watch", True, True), ("EREGION_CONSOLE", "la console", False, True),
         ("GLORFINDEL_BOT", "le bot", False, False))
# The directories the services mount, made as the operator by `make glorfindel-start` — left to
# docker, they would be root's (Makefile, RUNS_DIRS ; docs/profils/README.md).
STATE_DIRS = (".glorfindel", ".glorfindel/injectors", ".cache/chroma", ".eregion",
              ".eregion/analysis", ".eregion/console", ".eregion/console/requests",
              ".eregion/watch-key")
RUNS_WRITERS = ("glorfindel", "console", "annatar", "gothmog", "orodruin", "verdicts")
ORODRUIN_ENV = "infra/orodruin/orodruin.env"
HOST_ENV = "infra/glorfindel-host/host.env"
TFVARS = "infra/terraform/terraform.tfvars"
WORKSPACE_PLACEHOLDER = "YOUR_LAW_WORKSPACE_GUID"

_GUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
# eregion_core/watch_key.py, _PIN: ed25519:<base64 of 32 bytes>.
_WATCH_KEY = re.compile(r"^ed25519:([A-Za-z0-9+/]{43}=)$")
_SSH_FINGERPRINT = re.compile(r"^SHA256:[A-Za-z0-9+/]{43}$")
# The values the examples ship: a placeholder left in place is no value.
# Only their exact forms: a real secret may well hold « ... » or an x run somewhere in it.
_EXAMPLE = re.compile(
    r"x+(?:-x+)*"                                   # xxxxxxxx-xxxx-…, xxxx…xxxx (.envrc.example)
    r"|(?:sk-ant-|sk-|ed25519:|SHA256:)?(?:\.\.\.|…)"  # sk-ant-..., ..., ed25519:…, SHA256:…
    r"|<[^<>]*>"                                    # <appId>, <password>, <ta clé>
    r"|YOUR_LAW_WORKSPACE_GUID"
    r"|ssh-ed25519 AAAA\.\.\. your-key-comment"     # terraform.tfvars.example
    r"|https://<resource>\.openai\.azure\.com",
    re.IGNORECASE)


@dataclass(frozen=True)
class Check:
    group: str
    name: str
    status: str
    fix: str = ""


def example_value(value: str) -> bool:
    """A value from an example file (.envrc.example, the tfvars example), never filled in."""
    return bool(_EXAMPLE.fullmatch(value.strip()))


def env_file(path: Path) -> dict[str, str] | None:
    """KEY=value lines as docker compose reads them (an `export ` before tolerated, the last
    line of a key wins, a `# …` after a blank is a comment — the Makefile's HOST_ENV_VALUE).
    None when the file is not there."""
    try:
        text = path.read_text(encoding="utf-8")
    except (FileNotFoundError, IsADirectoryError, NotADirectoryError):
        return None
    out: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.removeprefix("export ").strip()
        out[key] = re.sub(r"\s+#.*$", "", value).strip().strip('"').strip("'")
    return out


def filled(value: str | None) -> bool:
    return bool(value) and not example_value(value or "")


# ── Probes, swapped by the tests ───────────────────────────────────────────────────

def _run(cmd: list[str]) -> subprocess.CompletedProcess | None:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=15)
    except (OSError, subprocess.TimeoutExpired):
        return None


def _port_free(port: int) -> bool:
    """True when nothing listens on 127.0.0.1:<port> — a bind, released at once."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind(("127.0.0.1", port))
        except OSError:
            return False
    return True


@dataclass
class Probes:
    which: Callable[[str], str | None] = shutil.which
    run: Callable[[list[str]], subprocess.CompletedProcess | None] = _run
    port_free: Callable[[int], bool] = _port_free
    uid: Callable[[], int] = os.getuid
    python: tuple = tuple(sys.version_info[:3])


# ── The checks ─────────────────────────────────────────────────────────────────────

def tools(profile: str, p: Probes, repo: Path) -> list[Check]:
    g = "outils"
    out = []
    version = ".".join(str(n) for n in p.python)
    out.append(Check(g, f"python {version} (≥ 3.11)", OK) if tuple(p.python[:2]) >= PYTHON_MIN
               else Check(g, f"python {version} : 3.11 ou plus attendu", FAIL,
                          "installer Python 3.11 ou plus, puis python3 --version"))
    if profile == "discover":
        if not p.which("docker"):
            out.append(Check(g, "docker absent", FAIL, "installer Docker : https://docs.docker.com/get-docker/"))
        else:
            # Without a daemon, `docker info --format` still exits 0 (measured at the replay,
            # docker 27.3): only a server version printed says the daemon answered.
            r = p.run(["docker", "info", "--format", "{{.ServerVersion}}"])
            out.append(Check(g, "docker répond", OK) if r is not None and r.returncode == 0 and r.stdout.strip()
                       else Check(g, "docker installé, mais son démon ne répond pas", FAIL,
                                  "démarrer Docker ; sous Linux, ton utilisateur dans le groupe docker "
                                  "(sudo usermod -aG docker $USER, puis rouvrir la session)"))
            r = p.run(["docker", "compose", "version"])
            out.append(Check(g, "docker compose", OK) if r is not None and r.returncode == 0
                       else Check(g, "docker compose absent", FAIL,
                                  "installer le greffon compose : https://docs.docker.com/compose/install/"))
    out.append(Check(g, "az (Azure CLI)", OK) if p.which("az")
               else Check(g, "az absent : " + ("Terraform s'authentifie par lui, les rôles et orodruin-fingerprint l'appellent"
                                              if profile == "bench" else "il crée le principal et lit l'espace Log Analytics"),
                          FAIL,
                          "installer Azure CLI : https://learn.microsoft.com/cli/azure/install-azure-cli, puis az login"))
    if profile == "bench":
        for tool, why, fix in (
                ("terraform", "il construit le banc, H0 et Orodruin",
                 "installer Terraform 1.5 ou plus : https://developer.hashicorp.com/terraform/install"),
                ("ssh", "chaque commande vers H0 et Orodruin", "installer le client OpenSSH")):
            out.append(Check(g, tool, OK) if p.which(tool) else Check(g, f"{tool} absent : {why}", FAIL, fix))
        out.append(Check(g, ".venv (make install)", OK) if (repo / ".venv" / "bin" / "python").exists()
                   else Check(g, ".venv absent : make glorfindel-host-env, -push et watch-key le lancent", FAIL,
                              "make install"))
    out.append(Check(g, "direnv", OK) if p.which("direnv")
               else Check(g, "direnv absent (optionnel)", WARN,
                          "sans lui, dans chaque terminal : set -a; . ./.envrc; set +a"))
    return out


def _id(name: str, env: Mapping[str, str], g: str, fix: str) -> Check:
    value = env.get(name, "")
    if not value:
        return Check(g, f"{name} vide", FAIL, fix)
    if example_value(value):
        return Check(g, f"{name} : la valeur d'exemple de .envrc.example", FAIL, fix)
    if not _GUID.match(value.strip()):
        return Check(g, f"{name} n'a pas la forme d'un identifiant Azure", FAIL, fix)
    return Check(g, f"{name}", OK)


def _pair(prefix: str, who: str, required: bool, env: Mapping[str, str], g: str,
          optional_said: bool = True) -> Check | None:
    """The pair of a service: both set, or neither. An optional service left out is said only
    when ``optional_said`` (the console, which the guide sets; never the bot, which it does not
    start) — half set, it always fails."""
    cid, sec = f"{prefix}_AZURE_CLIENT_ID", f"{prefix}_AZURE_CLIENT_SECRET"
    have = (filled(env.get(cid)), filled(env.get(sec)))
    fix = (f"les deux, ou aucun : export {cid}=<appId> et {sec}=<password> "
           "(az ad sp create-for-rbac, docs/demarrer/bleu.md)")
    if have == (True, True):
        return Check(g, f"principal de {who} ({cid}, {sec})", OK)
    if have == (False, False) and not (env.get(cid) or env.get(sec)):
        if required:
            return Check(g, f"aucun principal pour {who} : elle ne lirait rien sur Azure", FAIL, fix)
        if optional_said:
            return Check(g, f"aucun principal pour {who} (optionnel : sans lui, sa page Audit ne lit rien)", WARN,
                         f"le même principal Reader que la watch convient : {cid}, {sec}")
        return None
    return Check(g, f"{cid} / {sec} : paire incomplète, ou une valeur d'exemple", FAIL, fix)


def model(env: Mapping[str, str], g: str = "modèle", *, docker: bool = True) -> list[Check]:
    name = env.get("GLORFINDEL_LLM_MODEL", "")
    provider = (name.split("/", 1)[0] if "/" in name else DEFAULT_PROVIDER) if name else DEFAULT_PROVIDER
    if provider == "ollama":
        base = env.get("GLORFINDEL_LLM_BASE_URL", "")
        if not base:
            return [Check(g, "ollama : GLORFINDEL_LLM_BASE_URL vide", FAIL,
                          "export GLORFINDEL_LLM_BASE_URL=http://<hôte d'Ollama>:11434")]
        if docker and re.search(r"//(localhost|127\.0\.0\.1)\b", base):
            return [Check(g, "ollama sur localhost : dans le conteneur, localhost est le conteneur", FAIL,
                          "l'adresse de l'hôte vue du conteneur (Docker Desktop : http://host.docker.internal:11434)")]
        return [Check(g, "ollama : GLORFINDEL_LLM_BASE_URL (rien ne part de la machine)", OK)]
    keys = PROVIDER_KEYS.get(provider)
    if keys is None:
        return [Check(g, f"fournisseur « {provider} » : sa clé n'est pas vérifiée ici", WARN,
                      "la variable que LiteLLM lit pour lui")]
    missing = [k for k in keys if not filled(env.get(k))]
    if missing:
        return [Check(g, f"{provider} : {', '.join(missing)} vide ou valeur d'exemple", FAIL,
                      f"export {missing[0]}=… dans .envrc ; ou un modèle local : "
                      "GLORFINDEL_LLM_MODEL=ollama/<modèle> et GLORFINDEL_LLM_BASE_URL")]
    return [Check(g, f"{provider} : {', '.join(keys)}", OK)]


def variables(profile: str, env: Mapping[str, str]) -> list[Check]:
    g = "variables"
    out = [_id("AZURE_SUBSCRIPTION_ID", env, g,
               "export AZURE_SUBSCRIPTION_ID=$(az account show --query id -o tsv) dans .envrc, puis direnv allow")]
    if profile == "discover":
        out.append(_id("AZURE_TENANT_ID", env, g,
                       "export AZURE_TENANT_ID=$(az account show --query tenantId -o tsv) dans .envrc"))
        out += [c for prefix, who, required, said in PAIRS
                if (c := _pair(prefix, who, required, env, g, said)) is not None]
        ro = env.get("GLORFINDEL_READ_ONLY", "")
        out.append(Check(g, "GLORFINDEL_READ_ONLY : aucune écriture vers Azure", OK)
                   if ro.strip().lower() not in SWITCH_OFF
                   else Check(g, "GLORFINDEL_READ_ONLY n'est pas posé : l'observation le demande", FAIL,
                              "export GLORFINDEL_READ_ONLY=1 dans .envrc"))
        out += model(env)
    else:
        fp = env.get("ORO_SSH_FINGERPRINT", "")
        out.append(Check(g, "ORO_SSH_FINGERPRINT", OK) if _SSH_FINGERPRINT.match(fp)
                   else Check(g, "ORO_SSH_FINGERPRINT vide ou mal formé : aucune commande ne part vers Orodruin",
                              FAIL, "make orodruin-fingerprint, puis sa ligne export dans .envrc"))
        out.append(Check(g, "HOST_SSH_FINGERPRINT", OK) if _SSH_FINGERPRINT.match(env.get("HOST_SSH_FINGERPRINT", ""))
                   else Check(g, "HOST_SSH_FINGERPRINT vide (optionnel : sans elle, accept-new vers H0)", WARN,
                              "infra/glorfindel-host/README.md, « SSH : la clé d'hôte épinglée »"))
    return out


def configuration(repo: Path, profile: str = "discover") -> list[Check]:
    g = "configuration"
    path = repo / "glorfindel-config.yaml"
    # On the bench, the file is Celebrimbor's fragment (its workspace, its vault) — not the example.
    make = ("make celebrimbor-output, son fragment dans glorfindel-config.yaml" if profile == "bench"
            else "cp glorfindel-config.yaml.example glorfindel-config.yaml")
    if path.is_dir():
        return [Check(g, "glorfindel-config.yaml est un dossier : docker l'a créé, le fichier manquait", FAIL,
                      f"rmdir glorfindel-config.yaml, puis {make}")]
    if not path.is_file():
        return [Check(g, "glorfindel-config.yaml absent : la watch ne détecterait rien", FAIL, make)]
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as e:
        return [Check(g, f"glorfindel-config.yaml illisible ({type(e).__name__})", FAIL,
                      "ls -l glorfindel-config.yaml : à ton nom, lisible")]
    out = []
    try:
        from glorfindel.config import ConfigError, load_glorfindel_config
    except ImportError:
        out.append(Check(g, "lecture stricte de la configuration non faite (sans le venv)", WARN,
                         "make install, puis make doctor"))
        workspaces = re.findall(r"^\s*workspace_id:\s*[\"']?([^\"'#\s]*)", text, re.M)
    else:
        try:
            cfg = load_glorfindel_config(path)
        except ConfigError as e:
            first = str(e).splitlines()[0][:300]
            return [Check(g, f"glorfindel-config.yaml refusé par la watch : {first}", FAIL,
                          "corriger le fichier (glorfindel-config.yaml.example, docs/operations.md, « Configuration »)")]
        out.append(Check(g, "glorfindel-config.yaml lu comme la watch le lit", OK))
        workspaces = [b.workspace_id for b in cfg.monitoring_backends
                      if getattr(b, "type", "") == "azure_monitor"]
    good = [w for w in workspaces if w and w != WORKSPACE_PLACEHOLDER and _GUID.match(w)]
    out.append(Check(g, "l'espace Log Analytics renseigné (workspace_id)", OK) if good
               else Check(g, "aucun workspace_id renseigné : la watch ne lirait aucun journal", FAIL,
                          make if profile == "bench" else
                          "az monitor log-analytics workspace show -g <groupe> -n <espace> --query customerId -o tsv "
                          "→ monitoring_backends[0].workspace_id"))
    return out


def _dir_check(path: Path, label: str, uid: int, fix_owner: str, g: str) -> Check | None:
    """None when absent (make creates it, as the operator) or fine; else what is wrong."""
    try:
        st = path.lstat()
    except FileNotFoundError:
        return None
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        return Check(g, f"{label} n'est pas un dossier (un lien ?) : rien n'y est monté", FAIL,
                     f"le retirer à la main ({label}), puis make profile-discover le recrée")
    if st.st_uid != uid:
        return Check(g, f"{label} n'est pas à ton nom (uid {st.st_uid}) : docker l'a créé ?", FAIL, fix_owner)
    if label.endswith("watch-key") and st.st_mode & 0o077:
        return Check(g, f"{label} lisible par d'autres : la watch refuse d'y tirer sa clé", FAIL,
                     f"chmod 700 {label}")
    return None


def state(home: Path, repo: Path, uid: int) -> list[Check]:
    g = "dossiers d'état"
    bad = []
    for rel in STATE_DIRS:
        fix = ('sudo chown -R "$(id -u):$(id -g)" ~/.eregion' if rel.startswith(".eregion")
               else "make fix-state-ownership")
        c = _dir_check(home / rel, f"~/{rel}", uid, fix, g)
        if c:
            bad.append(c)
    for rel in ("runs", *(f"runs/{w}" for w in RUNS_WRITERS)):
        c = _dir_check(repo / rel, rel, uid, "make fix-state-ownership", g)
        if c:
            bad.append(c)
    return bad or [Check(g, "à ton nom, ou absents (make profile-discover les crée)", OK)]


def port(env: Mapping[str, str], p: Probes) -> list[Check]:
    g = "port"
    raw = env.get("EREGION_CONSOLE_PORT", "") or str(CONSOLE_PORT)
    if not raw.isdigit() or not 0 < int(raw) < 65536:
        return [Check(g, "EREGION_CONSOLE_PORT n'est pas un port", FAIL, "unset EREGION_CONSOLE_PORT (7007 par défaut)")]
    n = int(raw)
    if p.port_free(n):
        return [Check(g, f"{n} libre pour la console", OK)]
    r = p.run(["docker", "ps", "--filter", f"publish={n}", "--format", "{{.Names}}"])
    names = r.stdout.split() if r is not None and r.returncode == 0 else []
    if any(name.endswith("-war-room") for name in names):
        return [Check(g, f"{n} : la console d'Eregion y tourne déjà", OK)]
    return [Check(g, f"{n} pris par un autre programme (une console lancée hors de docker ?)", FAIL,
                  f"le libérer, ou EREGION_CONSOLE_PORT=<port libre> make profile-discover (ss -ltnp | grep {n})")]


def bench(repo: Path, env: Mapping[str, str]) -> list[Check]:
    g = "le banc"
    out = []
    tf = env_file(repo / TFVARS)
    if tf is None:
        out.append(Check(g, f"{TFVARS} absent", FAIL,
                         f"cp {TFVARS}.example {TFVARS}, puis ta clé SSH publique (admin_ssh_public_key)"))
    else:
        out.append(Check(g, f"{TFVARS}", OK) if filled(tf.get("admin_ssh_public_key"))
                   else Check(g, "admin_ssh_public_key vide, ou la valeur d'exemple", FAIL,
                              f"ta clé publique (cat ~/.ssh/id_ed25519.pub) dans {TFVARS}"))
    oro = env_file(repo / ORODRUIN_ENV)
    host = env_file(repo / HOST_ENV)
    if oro is None:
        out.append(Check(g, f"{ORODRUIN_ENV} absent", FAIL, f"cp {ORODRUIN_ENV}.example {ORODRUIN_ENV}"))
    else:
        key = oro.get("EREGION_WATCH_KEY", "")
        m = _WATCH_KEY.match(key)
        good = bool(m) and len(base64.b64decode(m.group(1))) == 32
        out.append(Check(g, "la clé de la watch épinglée pour les injecteurs (EREGION_WATCH_KEY)", OK) if good
                   else Check(g, "EREGION_WATCH_KEY vide ou mal formé dans orodruin.env : tout run serait refusé",
                              FAIL, "make glorfindel-host-watch-key, sa ligne dans orodruin.env, puis "
                                    "make orodruin-push REF=<tag ou commit>"))
        for name, output in (("EREGION_WATCH_CHANNEL", "watch_channel_url"),
                             ("EREGION_WATCH_CHANNEL_SCOPE", "watch_channel_scope"),
                             ("EREGION_EXERCISE_CHANNEL", "channel_url"),
                             ("EREGION_CHANNEL_SCOPE", "channel_scope")):
            out.append(Check(g, f"orodruin.env : {name}", OK) if filled(oro.get(name))
                       else Check(g, f"orodruin.env : {name} vide", FAIL,
                                  f"terraform -chdir=infra/orodruin output -raw {output}"))
        if oro.get("AZURE_CLIENT_ID") or oro.get("AZURE_CLIENT_SECRET"):
            out.append(Check(g, "orodruin.env porte AZURE_CLIENT_* : elles masqueraient l'identité managée", FAIL,
                             "retirer AZURE_CLIENT_ID et AZURE_CLIENT_SECRET d'orodruin.env"))
    if host is None:
        out.append(Check(g, f"{HOST_ENV} absent", FAIL, "make glorfindel-host-env"))
    else:
        out += model(host, g, docker=True)
        for name in ("EREGION_WATCH_CHANNEL", "EREGION_EXERCISE_CHANNEL"):
            out.append(Check(g, f"host.env : {name}", OK) if filled(host.get(name))
                       else Check(g, f"host.env : {name} vide : H0 ne publierait pas son battement", FAIL,
                                  "la valeur d'orodruin.env, puis make glorfindel-host-push"))
    if oro is not None and host is not None:
        for name, why in (("AZURE_SUBSCRIPTION_ID", "la watch d'un autre abonnement est refusée (SEC5)"),
                          ("EREGION_WATCH_CHANNEL", "Orodruin ne lirait pas le battement que H0 publie"),
                          ("EREGION_EXERCISE_CHANNEL", "H0 ne lirait pas les fenêtres qu'Orodruin écrit")):
            a, b = oro.get(name, ""), host.get(name, "")
            if a and b and a != b:
                out.append(Check(g, f"{name} : orodruin.env et host.env diffèrent — {why}", FAIL,
                                 "la même valeur dans les deux, puis make glorfindel-host-push et make orodruin-push"))
    sub = env.get("AZURE_SUBSCRIPTION_ID", "")
    if oro is not None and sub and oro.get("AZURE_SUBSCRIPTION_ID") and oro["AZURE_SUBSCRIPTION_ID"] != sub:
        out.append(Check(g, "AZURE_SUBSCRIPTION_ID : ton environnement et orodruin.env diffèrent", FAIL,
                         "le même abonnement : celui du banc"))
    return out


def run_checks(profile: str, env: Mapping[str, str], home: Path, repo: Path,
               probes: Probes | None = None) -> list[Check]:
    p = probes or Probes()
    checks = tools(profile, p, repo) + variables(profile, env) + configuration(repo, profile)
    if profile == "discover":
        checks += state(home, repo, p.uid()) + port(env, p)
    else:
        checks += bench(repo, env)
    return checks


def render(checks: list[Check]) -> str:
    lines, group = [], None
    for c in checks:
        if c.group != group:
            group = c.group
            lines.append(f"\n{group}")
        lines.append(f"  {MARK[c.status]} {c.name}" + (f"\n      → {c.fix}" if c.status != OK and c.fix else ""))
    failed = sum(c.status == FAIL for c in checks)
    lines.append("")
    lines.append("Tout est prêt." if not failed else f"{failed} point(s) à corriger avant de démarrer.")
    return "\n".join(lines)


def exit_code(checks: list[Check]) -> int:
    return 1 if any(c.status == FAIL for c in checks) else 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="make doctor", description=__doc__.splitlines()[0])
    ap.add_argument("--profile", default="discover")
    args = ap.parse_args(argv)
    if args.profile not in PROFILES:
        print(f"PROFILE={args.profile} : discover ou bench (make doctor PROFILE=discover|bench)", file=sys.stderr)
        return 2
    checks = run_checks(args.profile, os.environ, Path.home(), REPO)
    print(f"make doctor PROFILE={args.profile}" + render(checks))
    return exit_code(checks)


if __name__ == "__main__":
    raise SystemExit(main())
