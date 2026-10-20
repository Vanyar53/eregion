#!/bin/bash
# `make glorfindel-host-status` — is the pre-observation running? One look, read-only.
#
# Azure side (local az): the VMs of the defender and of the bench, the last backups.
# On the VM (one ssh): containers, deployed commit, errors of the last 24 h, discovery,
# bot, cards to judge and the week's count, disk and memory. Nothing is written anywhere;
# the War Room token is read on the VM and never printed.
set -u
HOST_IP="${HOST_IP:?no VM: make glorfindel-host-up first}"
HOST_USER="${HOST_USER:-glorfindel}"
SSH_OPTS="${SSH_OPTS:-}"
BENCH_RG="${BENCH_RG:-rg-celebrimbor}"
VAULT="${VAULT:-rsv-celebrimbor-erebor}"

echo "== Azure"
for rg in rg-glorfindel "$BENCH_RG"; do
  az vm list -g "$rg" -d --query "[].[name, powerState]" -o tsv 2>/dev/null \
    | awk '{ state=$0; sub(/^[^\t]*\t/, "", state); mark = (state ~ /running/) ? "✓" : "·"; printf "  %s %-28s %s\n", mark, $1, state }'
done
az backup item list -g "$BENCH_RG" -v "$VAULT" --backup-management-type AzureIaasVM \
  --query "[].[properties.friendlyName, properties.lastBackupStatus, properties.lastBackupTime]" -o tsv 2>/dev/null \
  | awk '{ mark = ($2 == "Completed") ? "✓" : "✗"; printf "  %s sauvegarde %-24s %s %s\n", mark, $1, $2, substr($3, 1, 16) }'

echo "== VM $HOST_IP"
# shellcheck disable=SC2086
ssh $SSH_OPTS -o BatchMode=yes -o ConnectTimeout=10 "$HOST_USER@$HOST_IP" 'bash -s' <<'REMOTE'
cd eregion || { echo "  ✗ dépôt absent"; exit 1; }
echo "  commit déployé : $(git log --oneline -1 | cut -c1-70)"
for s in eregion-watch eregion-war-room eregion-bot; do
  st=$(docker inspect -f '{{.State.Status}} depuis {{.State.StartedAt}}' "$s" 2>/dev/null || echo "absent")
  mark="✗"; case "$st" in running*) mark="✓";; esac
  printf "  %s %-18s %s\n" "$mark" "$s" "$(echo "$st" | cut -c1-38)"
done
# Les avertissements ne comptent pas (20/10 : LiteLLM signale à chaque démarrage l'absence de
# botocore, « Error: No module named … » dans une ligne WARNING — 4 fausses erreurs par jour).
for s in watch war-room bot; do
  n=$(docker compose logs --no-color --since 24h "$s" 2>&1 | grep -iE "error|traceback|exception" | grep -cviE "warning")
  mark="✓"; [ "$n" -gt 0 ] && mark="⚠"
  printf "  %s erreurs 24 h %-9s %s\n" "$mark" "$s" "$n"
done
# A detection the model could not decide on (cycle_failed): services up, discovery fine,
# and still no decision — a broken LLM dependency did exactly that on 19/10.
nf=$(docker exec eregion-watch python -c '
from datetime import datetime, timedelta, timezone
from glorfindel import escalations as e
since = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
print(sum(1 for x in e.all_escalations() if x.get("escalation_type") == "cycle_failed" and str(x.get("first_seen")) >= since))' 2>/dev/null || echo "?")
mark="✓"; [ "$nf" != "0" ] && mark="⚠"
echo "  $mark décisions impossibles 24 h : $nf"
disc=$(docker compose logs --no-color --since 10m watch 2>&1 | grep -E "heartbeat" | tail -1 | sed -E 's/.*heartbeat/heartbeat/')
[ -n "$disc" ] && echo "  ✓ découverte : $disc" || echo "  ✗ découverte : aucun heartbeat depuis 10 min"
last=$(docker compose logs --no-color bot 2>&1 | grep -E "Posted" | tail -1 | sed -E 's/.*Posted/dernière carte postée :/')
echo "  · bot : ${last:-aucune carte postée}"
H="Authorization: Bearer $(grep '^GLORFINDEL_WARROOM_TOKEN=' .env | cut -d= -f2-)"
# Python 3.10 on the VM (Ubuntu 22.04): no backslash inside an f-string expression.
curl -s -H "$H" "http://127.0.0.1:7007/api/to-judge?since=7d" | python3 -c '
import json, sys
try:
    c = json.load(sys.stdin)["cards"]
except Exception:
    print("  ✗ War Room : pas de réponse"); sys.exit()
print("  %s à juger : %d" % ("⚠" if c else "✓", len(c)))
for x in c[:5]:
    print("      - %s · %s · %sx · depuis %s" % (x["action"], x.get("rule_name") or "", x.get("occurrences") or 1, str(x.get("first_seen"))[:16]))'
curl -s -H "$H" "http://127.0.0.1:7007/api/report?since=7d" | python3 -c '
import json, sys
try:
    r = json.load(sys.stdin)
except Exception:
    sys.exit()
d = r["disruptive"]
rate = "—" if d["false_rate"] is None else "%d%%" % round(d["false_rate"] * 100)
print("  · 7 jours : %s carte(s), %s jugée(s), isoler/bloquer faux %s, exercices écartés %s" % (r["cards"], r["judged"], rate, r["exercises"]))'
echo "  · disque $(df -h / | awk 'NR==2{print $5}') · mémoire dispo $(free -m | awk 'NR==2{print $7}') Mo · $(uptime -p)"
REMOTE

echo "== Poste"
B="${HOST_BACKUPS:-$HOME/.eregion/host-backups}"
last=$(ls -1t "$B"/glorfindel-*.tgz 2>/dev/null | head -1)
if [ -z "$last" ]; then
  echo "  ⚠ copie locale des verdicts : aucune — make glorfindel-host-pull"
else
  age_d=$(( ( $(date +%s) - $(stat -c %Y "$last") ) / 86400 ))
  mark="✓"; [ "$age_d" -ge 7 ] && mark="⚠"
  echo "  $mark copie locale des verdicts : il y a ${age_d} j ($(basename "$last"))"
fi
