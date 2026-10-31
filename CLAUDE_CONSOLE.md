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
  `glorfindel.html` (`/glorfindel`, `/config`), `injector.html` (la vue Runs de Dagorlad, `/dagorlad?view=runs`, lecture seule),
  `dagorlad.html` (`/dagorlad`, le terrain d'exercice, §7 de `docs/design/console.md`) ;
  leur script dans un fichier à part (`overview.js`, `glorfindel.js` ~3000 lignes, `injector.js`, `dagorlad.js`),
  `exercises.js` partagé ; vanilla JS + CSS variables, sans étape de build
- `eregion_console/api.py`, `sections.py`, `cli.py`, `board.py` — tu peux proposer de nouveaux endpoints si l'UI en a besoin

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

GET  /  /glorfindel  /dagorlad  /config   → les pages (overview, glorfindel, dagorlad ; /dagorlad?view=runs → injector)
GET  /annatar, /gothmog               → 308 vers /dagorlad?view=runs&injector=…, la requête gardée (jusqu'à la 1.0)
GET  /runs/<run_id>                   → 302 vers /dagorlad?view=runs&run=…
GET  /atelier, /api/atelier/*         → 308 vers / et /api/* (jusqu'à la 1.0)
GET  /api/sections                    → Glorfindel, chaque injecteur actif ou grisé et pourquoi, read_only
GET  /api/indicators                  → les cinq indicateurs (30 jours) : contenir, contenu seul (+ shadow), à tort, couverture, dernière preuve
GET  /api/catalog[?kind=technique|fault]   → techniques + pannes du catalogue
GET  /api/coverage[?kind=technique|fault]  → la matrice de couverture (C1) : par entrée, dernier run, dernière preuve, état, évolution
GET  /api/exercises?since=7d[&injector=…]  → fenêtres d'exercice + cycles, cartes et rapport de run de chacune
GET  /api/campaigns[/<id>]            → manifestes ; en détail, faits du rapport de campagne + report.md
GET  /api/channel                     → battement local, fenêtres vivantes, battement publié (canal retour)
GET  /api/channel/detections/<run_id> → détections livrées au run
GET  /api/dagorlad/board              → cartes rouges (catalogue), Glorfindel, cibles inscrites (zone, mode)
GET  /api/dagorlad/plan?wire=<exp>@<rid>… → chaque fil jugé comme Orodruin le jugerait, et l'attendu
POST /api/dagorlad/requests           → DG-b : {"wires": [{"experiment", "target"}]} — jugés, puis la demande écrite dans
     ~/.eregion/console/requests/ seulement ; la réponse donne `make orodruin-exercise REQUEST=<id>` (aucun nom tapé ici)
GET  /api/dagorlad/requests/<id>      → la demande écrite ici ou non, ses fils, son statut publié par Orodruin (runs/orodruin/),
     sa phase (written, running, over) et la chronologie de chaque fil (DG-c, eregion_console/follow.py) — lecture seule
GET  /api/dagorlad/stop               → « Stop all » : make orodruin-kill, les fenêtres ouvertes et leurs cibles, ce qui reste en vol
     (injecteurs : un run part d'Orodruin armé, porté par l'opérateur, jamais d'une route de la console)

POST /api/action/release/<vm>         → lever isolation NSG
POST /api/action/revert/<vm>          → reset complet (release + unblock toutes IPs)
GET  /api/restore/plan/<vm>?escalation=<id>[&before=<ISO>] → le moment proposé, d'où, les points d'avant (lecture seule, SEC4c)
POST /api/action/restore/<vm>         → Azure Backup restore de la carte {"escalation": <id>, "before": <ISO>} (jamais une carte ancrée, SEC1 ; jamais sans moment, SEC4c)
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
                       Dagorlad (grisé quand ni Annatar ni Gothmog n'a de run sur l'hôte) … à droite : battement de la watch ·
                       canal retour · ⚙ Config · UTC. Le point « live » est sur la colonne LIVE FEED.
/            Overview → une ligne par section : à juger, part jugée fausse, dernier run, campagne, canaux
/glorfindel  → TO JUDGE (seul endroit du verdict), fil live, carte de l'infra (DETECT/PROTECT/RECOVER,
               cartes VM : état, Approve & execute, Ack, Cmd, « to judge ▸ », Release/Unblock/Reset/Restore)
/dagorlad    → Board : on tire des fils des cartes rouges (catalogue, dernière preuve) vers les cibles inscrites,
               le serveur juge chaque fil et dit l'attendu (phase a) ; « Request run » écrit la demande et donne la
               commande (b) ; puis la chronologie de chaque fil, en direct, fils verrouillés jusqu'à la fin (c)
/dagorlad?view=runs → Runs : fenêtres d'exercice (sondes d'une panne), campagnes, matrice de couverture, des
               deux injecteurs ou d'un seul (filtre) ; grisé : ce qu'ils ajouteraient
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
- **Rien du dehors n'est écrit brut** (#254) : un champ de carte, de règle, du fil, une erreur, un
  nombre du serveur (un `.length` compris : `Number(…)`) passe par `_attr` (glorfindel.js) ou `esc`
  (les autres pages) ; le début d'une URL, `/` de tête compris, par `encodeURIComponent`.
- **Aucun script ni gestionnaire `on…` en ligne** (#257, CSP `script-src 'self'`) : le script d'une
  page est un fichier ; un élément nomme son action avec `_on` (`data-on-click` et ses arguments en
  JSON), appelée par le répartiteur dans `ACTIONS` — une action nouvelle s'ajoute à cette table. Le
  nom d'une action est un littéral de la page, jamais une donnée ; ses arguments, des chaînes ou des
  nombres ; une action qui lit une valeur (`_target.value`) vérifie que l'élément est le sien (`<select>`).
- **La frontière** (SEC1) : une modification part par `_post` (glorfindel.js : un objet JSON, le serveur
  refuse le reste) ; un nom dans un chemin d'API, par `_seg` (`encodeURIComponent`). Le serveur refuse un
  `Host` inconnu, une autre origine, une requête sans jeton ([docs/design/console.md](docs/design/console.md),
  « La frontière de la console ») ; les tests passent par `tests/unit/console_client.py`. Un bouton
  qui écrit sur Azure a son action dans `_WRITE_HANDLERS` (grisé en lecture seule).
- **Ce que le test vérifie** : `tests/unit/test_console_escaping.py` échoue sur ce que le lecteur
  (`python scripts/console_escaping.py` : où, d'où) voit — une valeur non échappée pour sa place dans
  le `${…}` d'un gabarit HTML, une valeur donnée à `innerHTML` ou une concaténation, un gestionnaire ou
  un script en ligne, une URL `javascript:`, `srcdoc`, et les API qui écrivent ailleurs
  (`document.write`, `setAttribute`, `.href =`, `eval`…). Un code qu'il ne sait pas lire lui échappe :
  le relire reste nécessaire ([docs/design/console.md](docs/design/console.md), « Ce qui vient du dehors »).

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
