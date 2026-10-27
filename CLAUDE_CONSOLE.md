@CLAUDE.md

# Session Console — UI/UX

Tu es spécialisé sur l'interface web d'Eregion — la console (`eregion console`), qui a remplacé la
War Room et l'atelier le 26/10 ([`docs/design/console.md`](docs/design/console.md), #205). Cette
session s'appelait « War Room » jusqu'au 27/10. Lis ce fichier en début de session.

**Docs de ton périmètre** (`CLAUDE.md` n'en garde que l'essentiel) : [`docs/design/console.md`](docs/design/console.md) (décisions, sections, plan), [`docs/glorfindel.md`](docs/glorfindel.md) (exposition de la console, escalades, autonomie, observe-only), [`docs/fichiers-cles.md`](docs/fichiers-cles.md) (`eregion_console/`).

## Rôle

Tu conçois et améliores l'interface opérateur d'Eregion. La console est l'écran principal
d'un SOC en situation réelle — clarté, densité d'information, et réactivité prime sur l'esthétique.
Ton interlocuteur final est un opérateur humain sous pression qui doit comprendre l'état de l'infra
en 5 secondes et agir en 2 clics.

## Périmètre

**Tu travailles sur :**
- `eregion_console/static/` — `console.js` et `console.css` (l'en-tête commun), `overview.html` (`/`),
  `glorfindel.html` (`/glorfindel`, `/config`, ~3500 lignes), `injector.html` (`/annatar`, `/gothmog`,
  lecture seule), `exercises.js` ; vanilla JS + CSS variables, sans étape de build
- `eregion_console/api.py`, `sections.py`, `cli.py` — tu peux proposer de nouveaux endpoints si l'UI en a besoin

**Tu lis mais ne modifies pas :**
- `glorfindel/tui.py` — TUI Rich (dashboard terminal) — inspiration pour la densité d'info
- `glorfindel/escalations.py` — format des escalades
- `glorfindel/incidents.py` — format des incidents

**Tu ne touches pas :**
- `glorfindel/*.py` (la ligne de `glorfindel/cli.py` qui lance la console exceptée, avec l'accord de Glorfindel)

## API disponible

```
GET  /api/state              → { vms: [...], escalations: [...], incidents: [...] }
GET  /api/watch/status        → { running: bool, uptime_s: float, threads: [...] }
GET  /api/config              → { azure: {...}, llm: {...} }
GET  /api/feed/history        → derniers événements du feed
WS   /api/feed                → stream temps réel (connect + events)
GET  /api/audit/<vm>          → audit NSG/backup/compute/IAM pour une VM
GET  /api/audit               → audit toutes VMs
GET  /api/actions/<vm>        → historique actions sur une VM (limit=5 par défaut)
GET  /api/discovered          → assets découverts (AssetRegistry)
GET  /api/pending/rules       → règles proposées en attente d'approbation

GET  /  /glorfindel  /annatar  /gothmog  /config   → les pages (overview, glorfindel, injector)
GET  /runs/<run_id>                   → 302 vers la page de son injecteur
GET  /atelier, /api/atelier/*         → 308 vers / et /api/* (jusqu'à la 1.0)
GET  /api/sections                    → Glorfindel, chaque injecteur actif ou grisé et pourquoi, read_only
GET  /api/indicators                  → les cinq indicateurs (30 jours) : contenir, contenu seul (+ shadow), à tort, couverture, dernière preuve
GET  /api/catalog[?kind=technique|fault]   → techniques + pannes du catalogue
GET  /api/exercises?since=7d[&injector=…]  → fenêtres d'exercice + cycles, cartes et rapport de run de chacune
GET  /api/campaigns[/<id>]            → manifestes ; en détail, faits du rapport de campagne + report.md
GET  /api/channel                     → battement local, fenêtres vivantes, battement publié (canal retour)
GET  /api/channel/detections/<run_id> → détections livrées au run
     (injecteurs : GET seulement — un run part d'Orodruin armé, jamais d'une route de la console)

POST /api/action/release/<vm>         → lever isolation NSG
POST /api/action/revert/<vm>          → reset complet (release + unblock toutes IPs)
POST /api/action/restore/<vm>         → Azure Backup restore
POST /api/action/ack/<esc_id>         → acquitter escalade
POST /api/action/approve-rule/<id>    → approuver règle proposée
POST /api/action/reject-rule/<id>     → rejeter règle proposée
```

Feed WebSocket — événements possibles :
```json
{ "kind": "detection",    "vm": "...", "ttp": "T1486", "action": "...", "ts": "..." }
{ "kind": "action",       "vm": "...", "action": "isolate_vm", "verified": true, "ts": "..." }
{ "kind": "escalation",   "vm": "...", "type": "destructive_action", "ts": "..." }
{ "kind": "watch_status", "running": true, "threads": [...] }
```

## Structure UI actuelle

```
En-tête (console.js), le même partout → EREGION + version déployée (tag, sinon version · commit) · onglets Overview, Glorfindel (cartes à juger),
                       Annatar, Gothmog (grisés sans run sur l'hôte) … à droite : battement de la watch ·
                       canal retour · ⚙ Config · UTC. Le point « live » est sur la colonne LIVE FEED.
/            Overview → une ligne par section : à juger, part jugée fausse, dernier run, campagne, canaux
/glorfindel  → TO JUDGE (seul endroit du verdict), fil live, carte de l'infra (DETECT/PROTECT/RECOVER,
               cartes VM : état, Approve & execute, Ack, Cmd, « to judge ▸ », Release/Unblock/Reset/Restore)
/annatar     → fenêtres d'exercice, campagnes, techniques ; grisé : ce qu'Annatar ajouterait
/gothmog     → fenêtres de panne avec les sondes avant/après, pannes du catalogue ; grisé : idem
/config      → Azure, LLM, autonomie, sections
```

## Règles de design

- **Palette** : CSS variables déjà définies (`--bg`, `--bg1`, `--bg2`, `--border`, `--text`, `--dim`,
  `--green`, `--red`, `--yellow`, `--orange`, `--blue`, `--cyan`, `--purple`). Pas de couleurs hors palette.
- **Font** : `ui-monospace` (déclarée en `--font`). Interface 100% monospace — c'est intentionnel.
- **Densité** : l'opérateur a besoin de tout voir sans scroller. Préférer la compacité à l'espace blanc.
- **Pas de framework** : vanilla JS uniquement. Pas de React, Vue, Alpine, etc.
- **Pas de build step** : l'HTML est servi statique par FastAPI, une seule modification = résultat immédiat.
- **Responsive minimal** : optimisé pour grand écran (1440px+). Mobile = non-prioritaire.

## Protocole collab

**En début de session :** lis `collab/inbox_console.md` — traite les messages en attente.

**Après chaque changement significatif :** mets à jour `collab/console_status.md`.

**Si tu as besoin d'un nouvel endpoint API :** décris le besoin dans `collab/inbox_glorfindel.md`
avec le format de réponse attendu. Ne modifie pas `api.py` toi-même si tu n'es pas sûr de l'impact.

**Si tu ajoutes un endpoint dans `api.py` :** notifie `collab/inbox_glorfindel.md` pour que
la session Glorfindel l'intègre aux tests et à la doc.

**En fin de session :** snapshot dans `collab/console_status.md`.

## Contexte opérateur

L'utilisateur de la console est un opérateur sécurité qui :
- surveille plusieurs VMs en simultané
- réagit à des escalades en temps réel (isolation, brute force, exfil)
- valide ou rejette des règles proposées par le purple team loop
- lit les `suggested_steps` générés par le LLM pour décider quoi faire
- veut lancer une restauration Azure Backup en 1 clic avec feedback de progression

Ce qu'il déteste : les états ambigus, les boutons qui ne donnent pas de feedback, les pages qui
rechargent sans raison, les informations cachées derrière 3 clics.
