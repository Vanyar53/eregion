#!/usr/bin/env bash
# Optional: refresh the elrond journal automatically, through user-level Claude Code hooks.
#   bash scripts/elrond-hooks.sh install    add palantir to the Stop and SubagentStop hooks
#   bash scripts/elrond-hooks.sh uninstall  remove them (other hooks are kept)
# The hooks live in ~/.claude/settings.json, never in the repository: they would run on every
# contributor's machine. Without them, the elrond skill still runs palantir after each subagent.
set -euo pipefail

MODE="${1:-}"
case "$MODE" in install|uninstall) ;; *) echo "usage: $0 install|uninstall" >&2; exit 2 ;; esac

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PALANTIR="$REPO/.claude/skills/elrond/palantir.py"
SETTINGS="${CLAUDE_HOME:-$HOME/.claude}/settings.json"
[ -f "$PALANTIR" ] || { echo "palantir not found: $PALANTIR" >&2; exit 1; }
mkdir -p "$(dirname "$SETTINGS")"

python3 - "$SETTINGS" "$PALANTIR" "$MODE" <<'PY'
import json, shutil, sys, time
from pathlib import Path

settings, palantir, mode = Path(sys.argv[1]), sys.argv[2], sys.argv[3]
data = json.loads(settings.read_text(encoding="utf-8")) if settings.exists() else {}
if settings.exists():
    shutil.copy2(settings, settings.with_name(f"settings.json.bak-elrond-{time.strftime('%Y%m%d-%H%M%S')}"))

hooks = data.setdefault("hooks", {})
for event in ("Stop", "SubagentStop"):
    groups = hooks.get(event, [])
    # Drop any previous palantir entry, then add the current one when installing.
    for g in groups:
        g["hooks"] = [h for h in g.get("hooks", []) if "elrond/palantir.py" not in h.get("command", "")]
    groups = [g for g in groups if g.get("hooks")]
    if mode == "install":
        groups.append({"matcher": "", "hooks": [{"type": "command", "command": f'python3 "{palantir}" hook',
                                                 "timeout": 30, "async": True}]})
    if groups:
        hooks[event] = groups
    else:
        hooks.pop(event, None)
if not hooks:
    data.pop("hooks")
settings.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
print(f"palantir hooks {'installed' if mode == 'install' else 'removed'} in {settings}")
PY
