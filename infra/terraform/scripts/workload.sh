#!/bin/bash
# H0 — la charge réelle de gondolin pendant la pré-observation : un petit site, et la routine
# d'un admin. `make celebrimbor-workload` la pose par Run Command (idempotent) ; jamais par le
# custom_data, dont tout changement remplace la VM. Pour l'arrêter : supprimer
# /etc/cron.d/eregion-workload (le site reste).
#
# Ce que Glorfindel en voit : Perf (CPU, réseau, disque) et Syslog auth/authpriv/daemon/syslog
# (DCR du banc) — les sudo de maintenance, les démarrages de services. Les logs de cron et de
# nginx ne sont pas collectés. Rien sur /mnt/testdata (le disque de T1486).
set -eu
export DEBIAN_FRONTEND=noninteractive
ADMIN="${ADMIN:-celebrimbor}"

apt-get update -q
apt-get install -y -q nginx unattended-upgrades curl

# Mises à jour automatiques (le défaut d'Ubuntu, rendu explicite).
cat > /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF

# Le site.
mkdir -p /var/www/gondolin /var/backups/gondolin-site
cat > /var/www/gondolin/index.html <<'EOF'
<!doctype html>
<html lang="fr"><meta charset="utf-8"><title>Gondolin</title>
<h1>Gondolin</h1>
<p>Petit site du banc Eregion, pour la pré-observation (H0).</p>
</html>
EOF
cat > /etc/nginx/sites-available/gondolin <<'EOF'
server {
    listen 80 default_server;
    root /var/www/gondolin;
    index index.html;
    access_log /var/log/nginx/gondolin.access.log;
}
EOF
ln -sf /etc/nginx/sites-available/gondolin /etc/nginx/sites-enabled/default
nginx -t
systemctl enable --now nginx
systemctl reload nginx

# La routine de l'admin : un visiteur, la sauvegarde de la nuit, des sudo de maintenance.
cat > /etc/cron.d/eregion-workload <<EOF
# H0 — infra/terraform/scripts/workload.sh. Supprimer ce fichier arrête la routine.
*/5 * * * * $ADMIN curl -fsS -o /dev/null http://127.0.0.1/
30 1 * * * root tar czf /var/backups/gondolin-site/site-\$(date +\%F).tgz -C /var/www gondolin && find /var/backups/gondolin-site -name '*.tgz' -mtime +14 -delete
15 8 * * * $ADMIN sudo -n /usr/sbin/nginx -t && sudo -n systemctl reload nginx
45 */6 * * * $ADMIN sudo -n journalctl --vacuum-time=14d >/dev/null 2>&1
EOF
chmod 644 /etc/cron.d/eregion-workload

curl -fsS -o /dev/null http://127.0.0.1/ && echo "workload: site up, routine installed"
