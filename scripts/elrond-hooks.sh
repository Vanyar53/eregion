#!/usr/bin/env bash
# Optional: user-level Claude Code hooks for elrond.
#   bash scripts/elrond-hooks.sh install    palantir on Stop and SubagentStop (the journal refreshes
#                                           itself), and notify_discord.py on PreToolUse (Agent) and
#                                           SubagentStop (elrond's lots in Discord, docs/atelier-discord.md)
#   bash scripts/elrond-hooks.sh uninstall  remove them (other hooks are kept)
# The hooks live in ~/.claude/settings.json, never in the repository: they would run on every
# contributor's machine. Without them, the elrond skill still runs palantir after each subagent;
# notify_discord.py without its configuration sends nothing.
set -euo pipefail

MODE="${1:-}"
case "$MODE" in install|uninstall) ;; *) echo "usage: $0 install|uninstall" >&2; exit 2 ;; esac

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PALANTIR="$REPO/.claude/skills/elrond/palantir.py"
NOTIFY="$REPO/scripts/notify_discord.py"
SETTINGS="${CLAUDE_HOME:-$HOME/.claude}/settings.json"
[ -f "$PALANTIR" ] || { echo "palantir not found: $PALANTIR" >&2; exit 1; }
mkdir -p "$(dirname "$SETTINGS")"

python3 - "$SETTINGS" "$PALANTIR" "$NOTIFY" "$MODE" <<'PY'
import json, shutil, sys, time
from pathlib import Path

settings, palantir, notify, mode = Path(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4]
data = json.loads(settings.read_text(encoding="utf-8")) if settings.exists() else {}
if settings.exists():
    shutil.copy2(settings, settings.with_name(f"settings.json.bak-elrond-{time.strftime('%Y%m%d-%H%M%S')}"))

OURS = ("elrond/palantir.py", "scripts/notify_discord.py")
# `|| true`: exit 2 from a PreToolUse hook blocks the tool, from SubagentStop it keeps the agent
# going — and python3 exits 2 on a missing file (a checkout without the script).
def entry(script, timeout):
    return {"type": "command", "command": f'python3 "{script}" hook || true', "timeout": timeout, "async": True}
WANTED = {
    "Stop": [("", [entry(palantir, 30)])],
    "SubagentStop": [("", [entry(palantir, 30)]), ("elrond-worker|elrond-reviewer", [entry(notify, 15)])],
    "PreToolUse": [("Agent", [entry(notify, 15)])],
}

hooks = data.setdefault("hooks", {})
for event in set(hooks) | set(WANTED):
    groups = hooks.get(event, [])
    # Drop any previous entry of ours, then add the current ones when installing.
    for g in groups:
        g["hooks"] = [h for h in g.get("hooks", []) if not any(o in h.get("command", "") for o in OURS)]
    groups = [g for g in groups if g.get("hooks")]
    if mode == "install":
        groups += [{"matcher": m, "hooks": h} for m, h in WANTED.get(event, [])]
    if groups:
        hooks[event] = groups
    else:
        hooks.pop(event, None)
if not hooks:
    data.pop("hooks")
settings.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
print(f"elrond hooks (palantir, notify_discord) {'installed' if mode == 'install' else 'removed'} in {settings}")
PY
