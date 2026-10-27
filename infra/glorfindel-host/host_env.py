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
"""
from __future__ import annotations

import os
import re
import secrets
import sys
from pathlib import Path

COPIED = ("AZURE_SUBSCRIPTION_ID", "AZURE_WORKSPACE_ID", "ANTHROPIC_API_KEY",
          "GLORFINDEL_LLM_MODEL", "GLORFINDEL_LLM_BASE_URL", "OPENAI_API_KEY",
          "GLORFINDEL_WEBHOOK_URL", "GLORFINDEL_BACKUP_VAULT",
          "DISCORD_BOT_TOKEN", "DISCORD_CHANNEL_ID", "DISCORD_PING_ROLE",
          "DISCORD_ALLOWED_USERS", "DISCORD_ALLOWED_ROLES",
          "EREGION_EXERCISE_CHANNEL", "EREGION_WATCH_CHANNEL")
REQUIRED = ("AZURE_SUBSCRIPTION_ID", "ANTHROPIC_API_KEY")
# The console's token, and its former name (eregion_console/api.py, console_token).
TOKEN = "EREGION_CONSOLE_TOKEN"
LEGACY_TOKEN = "GLORFINDEL_WARROOM_TOKEN"


def host_env(environ: dict) -> dict:
    missing = [k for k in REQUIRED if not environ.get(k)]
    if missing:
        raise SystemExit(f"missing in the environment (load .envrc): {', '.join(missing)}")
    out = {k: environ[k] for k in COPIED if environ.get(k)}
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
    path.touch(mode=0o600)
    path.write_text("".join(f"{k}={v}\n" for k, v in env.items()), encoding="utf-8")
    print(f"{dst}: " + ", ".join(env))
    return 0


if __name__ == "__main__":
    if sys.argv[1] == "--check":
        sys.exit(check(sys.argv[2]))
    sys.exit(main(sys.argv[1]))
