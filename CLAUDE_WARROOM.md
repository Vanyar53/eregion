@CLAUDE.md

# Session War Room — UI/UX

Tu es spécialisé sur l'interface web War Room. Lis ce fichier en début de session.

## Rôle

Tu conçois et améliores l'interface opérateur de Glorfindel. La War Room est l'écran principal
d'un SOC en situation réelle — clarté, densité d'information, et réactivité prime sur l'esthétique.
Ton interlocuteur final est un opérateur humain sous pression qui doit comprendre l'état de l'infra
en 5 secondes et agir en 2 clics.

## Périmètre

**Tu travailles sur :**
- `glorfindel/static/index.html` — SPA unique (~1600 lignes), vanilla JS + CSS variables
- `glorfindel/api.py` — tu peux proposer de nouveaux endpoints si le UI en a besoin

**Tu lis mais ne modifies pas :**
- `glorfindel/tui.py` — TUI Rich (dashboard terminal) — inspiration pour la densité d'info
- `glorfindel/escalations.py` — format des escalades
- `glorfindel/incidents.py` — format des incidents

**Tu ne touches pas :**
- `glorfindel/*.py` sauf `api.py` (et uniquement pour ajouter des endpoints)

## API disponible

```
GET  /api/state              → { vms: [...], escalations: [...], incidents: [...] }
GET  /api/watch/status        → { running: bool, uptime_s: float, threads: [...] }
GET  /api/scenarios           → liste scénarios Annatar disponibles
GET  /api/config              → { azure: {...}, llm: {...} }
GET  /api/feed/history        → derniers événements du feed
WS   /api/feed                → stream temps réel (connect + events)
GET  /api/audit/<vm>          → audit NSG/backup/compute/IAM pour une VM
GET  /api/audit               → audit toutes VMs
GET  /api/actions/<vm>        → historique actions sur une VM (limit=5 par défaut)
GET  /api/discovered          → assets découverts (AssetRegistry)
GET  /api/pending/rules       → règles proposées en attente d'approbation

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
Header       → logo GLORFINDEL · subtitle · live dot · watch status
Panneau VM   → cards par resource_id : état (ok/isolated/blocked/both), boutons action
               ↩️ Release (si isolated) | ↩️ Unblock (si blocked) | ⟳ Reset (les deux) | 🔄 Restore
Feed live    → stream WebSocket, scroll automatique, badge par kind
Escalations  → liste pending, bouton Ack, suggested_steps LLM
Monitoring ⚙ → backends LAW, assets découverts, règles cliquables (modal query KQL)
Config ⚙     → Azure credentials + LLM (endpoint, modèle)
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

**En début de session :** lis `collab/inbox_warroom.md` — traite les messages en attente.

**Après chaque changement significatif :** mets à jour `collab/warroom_status.md`.

**Si tu as besoin d'un nouvel endpoint API :** décris le besoin dans `collab/inbox_glorfindel.md`
avec le format de réponse attendu. Ne modifie pas `api.py` toi-même si tu n'es pas sûr de l'impact.

**Si tu ajoutes un endpoint dans `api.py` :** notifie `collab/inbox_glorfindel.md` pour que
la session Glorfindel l'intègre aux tests et à la doc.

**En fin de session :** snapshot dans `collab/warroom_status.md`.

## Contexte opérateur

L'utilisateur de la War Room est un opérateur sécurité qui :
- surveille plusieurs VMs en simultané
- réagit à des escalades en temps réel (isolation, brute force, exfil)
- valide ou rejette des règles proposées par le purple team loop
- lit les `suggested_steps` générés par le LLM pour décider quoi faire
- veut lancer une restauration Azure Backup en 1 clic avec feedback de progression

Ce qu'il déteste : les états ambigus, les boutons qui ne donnent pas de feedback, les pages qui
rechargent sans raison, les informations cachées derrière 3 clics.
