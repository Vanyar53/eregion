"""Write host.env — the hosted Glorfindel's environment (H0) — from the operator's own.

    python infra/glorfindel-host/host_env.py infra/glorfindel-host/host.env   # .envrc loaded

Only what the VM needs: the subscription, the model's key, the webhook. Never an Azure
secret — the VM authenticates by its managed identity, and AZURE_CLIENT_ID alone would
make DefaultAzureCredential look for a user-assigned identity that doesn't exist. Never
the Discord bot token: with it set, escalations wait for a bot (`glorfindel bot`) that the
VM doesn't run, and the webhook stays silent. Always GLORFINDEL_READ_ONLY=1, and a War
Room token drawn here. Refuses to overwrite an existing file (the token would change).
Prints the keys it wrote, never a value.
"""
from __future__ import annotations

import os
import secrets
import sys
from pathlib import Path

COPIED = ("AZURE_SUBSCRIPTION_ID", "AZURE_WORKSPACE_ID", "ANTHROPIC_API_KEY",
          "GLORFINDEL_LLM_MODEL", "GLORFINDEL_LLM_BASE_URL", "OPENAI_API_KEY",
          "GLORFINDEL_WEBHOOK_URL", "GLORFINDEL_BACKUP_VAULT")
REQUIRED = ("AZURE_SUBSCRIPTION_ID", "ANTHROPIC_API_KEY")


def host_env(environ: dict) -> dict:
    missing = [k for k in REQUIRED if not environ.get(k)]
    if missing:
        raise SystemExit(f"missing in the environment (load .envrc): {', '.join(missing)}")
    out = {k: environ[k] for k in COPIED if environ.get(k)}
    out["GLORFINDEL_READ_ONLY"] = "1"
    out["GLORFINDEL_WARROOM_TOKEN"] = secrets.token_urlsafe(24)
    return out


def main(dst: str) -> int:
    path = Path(dst)
    if path.exists():
        raise SystemExit(f"{dst} exists — remove it first to draw a new War Room token")
    env = host_env(dict(os.environ))
    path.touch(mode=0o600)
    path.write_text("".join(f"{k}={v}\n" for k, v in env.items()), encoding="utf-8")
    print(f"{dst}: " + ", ".join(env))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
