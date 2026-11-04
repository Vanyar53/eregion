"""Write host.env — the hosted Glorfindel's environment (H0) — from the operator's own.

    python infra/glorfindel-host/host_env.py infra/glorfindel-host/host.env   # .envrc loaded
    python infra/glorfindel-host/host_env.py --check infra/glorfindel-host/host.env

Only what the VM needs: the subscription, the model's key, the Discord bot (the VM runs
it: `docker compose --profile bot`), who may press its buttons, and the webhook. One file,
read by docker compose to fill docker-compose.yml: each container then receives only the
variables its own list names (M-3, #183) — the model's key the watch, the bot's token the
bot, the console's token the console. Never an Azure secret — the VM
authenticates by its managed identity, and AZURE_CLIENT_ID alone would make
DefaultAzureCredential look for a user-assigned identity that doesn't exist. Always
GLORFINDEL_READ_ONLY=1, and a console token drawn here, under its name, EREGION_CONSOLE_TOKEN.
Refuses to overwrite an existing file (the token would change).
Prints the keys it wrote, never a value.

A host.env written before UI-1 carries the token under its former name,
GLORFINDEL_WARROOM_TOKEN: it stays valid, nothing to rename. `--check` (run by
`make glorfindel-host-push`) says which name carries it — the console's rule: the new name
when it is not empty, else the former — and refuses a host.env with neither: pushed, it would
leave the console on the VM without a token. Never prints the token.

The model's key is the one its provider reads (OL1, #525; the rule: eregion_core/models.py,
`required_env`): ANTHROPIC_API_KEY for anthropic/… or the default, OPENAI_API_KEY for
openai/…, AZURE_API_KEY and AZURE_API_BASE for azure/…, MISTRAL_API_KEY for mistral/…; no key
for a local model (ollama/…), but GLORFINDEL_LLM_BASE_URL — in the watch's container, LiteLLM's
default address is the container itself; nothing for an OpenAI-compatible model served at
GLORFINDEL_LLM_BASE_URL (self-hosted). An unknown provider is refused, with the list. The
message names what is missing, never a value; `--check` holds a host.env to the same rule
before the push. The analysis model (EREGION_ANALYSIS_MODEL) writes the campaign reports,
never a decision: its missing key is said, not refused.
"""
from __future__ import annotations

import os
import re
import secrets
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from eregion_core.models import (  # noqa: E402
    DEFAULT_ANALYSIS_MODEL, PROVIDER_ENV, UnknownProvider, missing_env, model_provider,
)

COPIED = ("AZURE_SUBSCRIPTION_ID", "AZURE_WORKSPACE_ID", "ANTHROPIC_API_KEY",
          "GLORFINDEL_LLM_MODEL", "GLORFINDEL_LLM_BASE_URL", "OPENAI_API_KEY",
          # OL1: the other providers' variables. docker-compose.yml (x-models) passes them to
          # the watch, but host.env never carried them: an azure/… or mistral/… H0 had no key.
          "MISTRAL_API_KEY", "AZURE_API_KEY", "AZURE_API_BASE", "AZURE_API_VERSION",
          "GLORFINDEL_WEBHOOK_URL", "GLORFINDEL_BACKUP_VAULT",
          "DISCORD_BOT_TOKEN", "DISCORD_CHANNEL_ID", "DISCORD_PING_ROLE",
          "DISCORD_ALLOWED_USERS", "DISCORD_ALLOWED_ROLES",
          "EREGION_EXERCISE_CHANNEL", "EREGION_WATCH_CHANNEL",
          # IA1: the analysis AI's model, never Glorfindel's — the hosted watch writes the
          # campaign reports with it (analysis/hosted_report.py).
          "EREGION_ANALYSIS_MODEL")
# The model's key is required by its provider (model_missing), never here.
REQUIRED = ("AZURE_SUBSCRIPTION_ID",)
MODEL = "GLORFINDEL_LLM_MODEL"
ANALYSIS = "EREGION_ANALYSIS_MODEL"
# The console's token, and its former name (eregion_console/api.py, console_token).
TOKEN = "EREGION_CONSOLE_TOKEN"
LEGACY_TOKEN = "GLORFINDEL_WARROOM_TOKEN"


def model_missing(environ: dict) -> tuple[str, list[str]]:
    """(the provider of the decision model, the variables it needs that `environ` leaves
    empty). An unknown provider: SystemExit, with the list — never the value."""
    model = environ.get(MODEL, "")
    try:
        return model_provider(model), missing_env(model, environ)
    except UnknownProvider as exc:
        raise SystemExit(f"{MODEL}: {exc}") from None


def analysis_warning(environ: dict) -> str:
    """What the analysis model lacks, said: it writes the campaign reports (IA1), never a
    decision — a report without its key is given up after 3 attempts. "" when nothing."""
    try:
        provider = model_provider(environ.get(ANALYSIS, "") or DEFAULT_ANALYSIS_MODEL)
    except UnknownProvider:
        return (f"⚠ {ANALYSIS} ne nomme aucun fournisseur connu ({', '.join(PROVIDER_ENV)}) : "
                "les rapports de campagne échoueront.")
    lacking = [k for k in PROVIDER_ENV[provider] if not environ.get(k)]
    if not lacking:
        return ""
    return (f"⚠ l'IA d'analyse ({ANALYSIS}, vide : {DEFAULT_ANALYSIS_MODEL}) lit "
            f"{', '.join(lacking)}, vide : les rapports de campagne échoueront. Pose la clé, ou "
            f"un autre modèle dans {ANALYSIS}.")


def host_env(environ: dict) -> dict:
    missing = [k for k in REQUIRED if not environ.get(k)]
    provider, lacking = model_missing(environ)
    if missing or lacking:
        why = f" — {', '.join(lacking)} for the model's provider, {provider} ({MODEL})" if lacking else ""
        raise SystemExit(f"missing in the environment (load .envrc): {', '.join(missing + lacking)}{why}")
    out ={k: environ[k] for k in COPIED if environ.get(k)}
    out["GLORFINDEL_READ_ONLY"] = "1"
    # A powered-off VM stays on the map a week (default 8 h): gondolin, off between
    # exercises, kept vanishing from the observed fleet.
    out.setdefault("GLORFINDEL_DISCOVERY_RETENTION_H", environ.get("GLORFINDEL_DISCOVERY_RETENTION_H") or "168")
    out[TOKEN] = secrets.token_urlsafe(24)
    return out


def read_env(path: Path) -> dict:
    """KEY=value lines of a host.env, as docker compose reads them (`docker compose config`,
    measured 27/10): the last line of a key wins; comment lines and blank lines are skipped;
    the value is trimmed, then a « # … » after a blank is a comment — but `KEY=   # note`
    gives « # note », not an empty value. The Makefile and status.sh read the console's token
    the same way."""
    out = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip() and not line.lstrip().startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            out[key.strip()] = re.sub(r"\s+#.*$", "", value.strip()).strip()
    return out


def token_name(env: dict) -> str:
    """The variable that carries the console's token: TOKEN when it is not empty, else
    LEGACY_TOKEN when it is not, else "". Not empty, not merely present: compose passes both,
    empty when unset."""
    for name in (TOKEN, LEGACY_TOKEN):
        if env.get(name, ""):
            return name
    return ""


def check(dst: str) -> int:
    env = read_env(Path(dst))
    name = token_name(env)
    if name and env[name].startswith("#"):
        # `KEY=   # note`: compose takes « # note » as the value (measured, 27/10).
        raise SystemExit(f"{dst}: {name} holds a comment, which docker compose would take as the "
                         "token — write the value alone on its line.")
    if not name:
        raise SystemExit(f"{dst}: no console token ({TOKEN}, or its former name {LEGACY_TOKEN}) — "
                         f"pushed, the console on the VM would run without one. Set {TOKEN} "
                         "(python -c 'import secrets; print(secrets.token_urlsafe(24))').")
    # OL1: the key the model's provider reads — pushed without it, the watch could not decide.
    provider, lacking = model_missing(env)
    if lacking:
        raise SystemExit(f"{dst}: {', '.join(lacking)} empty — the model's provider, {provider} "
                         f"({MODEL}), needs it: pushed, the watch could not decide.")
    if name == LEGACY_TOKEN:
        print(f"{dst}: console token under its former name, {LEGACY_TOKEN} — valid, nothing to rename")
    else:
        print(f"{dst}: console token under {TOKEN} (a reference before UI-1, v0.3.0 or earlier, "
              f"reads only {LEGACY_TOKEN}: its War Room would start without a token)")
    return 0


def main(dst: str) -> int:
    path = Path(dst)
    if path.exists():
        raise SystemExit(f"{dst} exists — remove it first to draw a new console token")
    env = host_env(dict(os.environ))
    if env.get("DISCORD_BOT_TOKEN") and not (env.get("DISCORD_ALLOWED_USERS") or env.get("DISCORD_ALLOWED_ROLES")):
        print("⚠ DISCORD_ALLOWED_USERS / DISCORD_ALLOWED_ROLES vides : les boutons du bot refuseront "
              "tout clic (fermé par défaut). Ajoute ton id Discord à host.env.", file=sys.stderr)
    if warning := analysis_warning(env):
        print(warning, file=sys.stderr)
    path.touch(mode=0o600)
    path.write_text("".join(f"{k}={v}\n" for k, v in env.items()), encoding="utf-8")
    print(f"{dst}: " + ", ".join(env))
    return 0


if __name__ == "__main__":
    if sys.argv[1] == "--check":
        sys.exit(check(sys.argv[2]))
    sys.exit(main(sys.argv[1]))
