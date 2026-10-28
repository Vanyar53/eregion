# L'atelier dans Discord (N1, N2)

_Lots N1 (#242) et N2 (#243), 27/10. Le déploiement de H0 (H1, #244) s'y ajoutera ensuite._

Ce que fait l'atelier (la CI, les PR, les lots d'elrond) arrive dans Discord, à part de la défense : le bot de Glorfindel, ses cartes et son channel ne changent pas.

## Ce qui va où

| Où | Quoi | Notifie ? |
|---|---|---|
| `#ci` | PR ouverte, PR fusionnée, issue fermée | non (silencieux) |
| `#ci` | run rouge : PR, main, runs de nuit (invariants, mutants, canary) ; release publiée | oui |
| `#ci` | main de nouveau verte après un rouge | non |
| `#lots` (forum) | un fil par lot ouvert, et seulement un lot (N2) : lancé, rendu, relecture, correction, PR, fusion, issue fermée (N1) ; étiquettes jalon et état tenues à jour | non |
| `#agents` | un message « En cours » réécrit sur place : les agents d'elrond qui tournent, depuis quand | non |
| `#agents` | ce qui t'attend, avec ta mention : repli de modèle, relecture `changes` / `blocking` / sans verdict / non obtenue, lot bloqué, fin de run | oui |
| `#roadmap` | un seul message du bot, réécrit sur place (N2) : une barre par jalon, en cours, relus, bloqués, à faire, les critères de la 1.0, les cinq indicateurs | non |
| `#deploy` | le CD de H0 (H1) : début et succès d'un déploiement ; refus, retour arrière, retour raté avec ta mention ; un agent de CD à mettre à jour | succès : non ; le reste : oui |

Ce qui ne mérite rien n'envoie rien : un run vert sur une PR, un run annulé, une PR fermée sans fusion, les agents qui ne sont pas ceux d'elrond.

**D'où ça vient.**
- **GitHub** : `.github/workflows/notify.yml`. Le workflow ne récupère ni n'exécute jamais le code d'une PR (`pull_request_target` et `workflow_run` lisent les fichiers de la branche par défaut). Le script ne lit que le JSON de l'événement.
- **Les lots d'elrond** : des hooks de Claude Code, chez toi (plus bas). Le lancement passe par `PreToolUse` sur `Agent`. Le retour passe par `SubagentStop` : palantir y lit le transcript de l'agent, qui dit s'il y a eu un repli. Le verdict vient de la ligne `**Verdict : …**` du rapport, que le relecteur rend par l'outil `SubagentHandback` (mesuré le 27/10 sur les transcripts réels : son dernier message n'est pas un texte). Le script le lit dans le transcript ; à défaut, dans le dernier texte, puis dans `last_assistant_message`.
- **La feuille de route** : `.github/workflows/roadmap.yml` lance `scripts/roadmap_discord.py` à chaque push sur main, chaque jour, et quand une issue ou une PR vers main s'ouvre ou se ferme. Un run à la fois, chaque workflow dans son groupe (`roadmap-discord`, `notify-discord`) : GitHub ne garde qu'un run en attente par groupe, et un plus récent l'annule — sans conséquence pour la feuille de route, qui réécrit tout à chaque passage ; pour `notify.yml`, trois événements simultanés perdent celui du milieu (limite connue). La feuille de route ne crée de fils qu'au push, au passage quotidien ou à la main ; sur un événement d'issue ou de PR, c'est N1 qui crée le fil du lot.
- **elrond lui-même**, pour deux choses seulement : `notify_discord.py lot <ID> blocked --note …` et `notify_discord.py run-end "<bilan>"` (`.claude/skills/elrond/SKILL.md`).

**Le fil d'un lot.**
- Il s'appelle « `<ID> · <titre> · #<n>` ». Le script le retrouve, archivé compris, d'abord par le numéro de l'issue, puis par l'ID du lot : la branche `lot/<id>-…`, l'ID en tête du titre ou entre parenthèses (« (A3, #73) »). Un fil qui porte le numéro d'une autre issue n'est jamais repris : les deux issues d'I1F (#226, #231) ont chacune le leur.
- **Qui a un fil** (décisions du 27/10) : les **lots ouverts** des quatre jalons, c'est-à-dire les issues dont le titre commence par un ID de lot (« A3 — … », « I1F suite : … »). Les issues de suivi (#70, #95) et les constats sans lot n'en ont pas : ils restent sur GitHub et dans `#roadmap` ; un fil créé pour l'un d'eux avant cette règle est archivé. Une issue fermée n'en reçoit pas ; le sien, s'il existe, passe à « fait » et s'archive. L'historique d'avant reste sur GitHub et dans les barres de `#roadmap`.
- **L'état** : « fait » pour une issue fermée, et gardé pour une issue encore ouverte (lot fusionné ou relu `ok`, son « Fini quand » pas encore prouvé), sauf si elle a été rouverte ; une PR ouverte du dépôt (jamais celle d'un fork) qui nomme le lot le met au moins « en cours » ; les états fins d'elrond (`en relecture`, `en correction`, `bloqué`) sont gardés ; sinon « à faire ». Un fil créé par elrond est retrouvé par l'ID du lot et renommé au nom canonique. Un fil que Discord a archivé faute d'activité le reste, sauf s'il doit changer.
- Un événement de GitHub (N1) ne crée un fil que pour un lot connu (son ID) ; un run rouge poste dans le fil existant, sans jamais en créer.
- **La PR d'un fork** est annoncée dans `#ci`, jamais dans un fil : son titre peut nommer n'importe quel lot.

## Mise en place (Jonathan, une fois)

**1. Discord, dans l'UI.**
- Une catégorie (chez Jonathan : **Eregion**, qui tient aussi le salon de la défense, `#glorfindel`), avec :
  - `#ci`, `#agents`, `#roadmap`, `#deploy` (salons textuels) ;
  - `#lots` (salon **forum**).
- Dans `#lots` → Paramètres → Étiquettes, ces dix étiquettes, écrites ainsi :
  - les jalons : `v0.3`, `v0.x`, `v1.0`, `v1.x` ;
  - les états : `à faire`, `en cours`, `en relecture`, `en correction`, `fait`, `bloqué`.
- Un webhook par salon textuel : Paramètres du salon → Intégrations → Webhooks → Nouveau → Copier l'URL. L'URL contient le jeton du webhook : c'est un secret.

**2. Le bot « Eregion »**, celui de l'atelier : une seconde application, pas celle de Glorfindel :
- https://discord.com/developers/applications → New Application « Eregion » → Bot → Reset Token (copier le jeton). Aucun intent privilégié n'est nécessaire.
- OAuth2 → URL Generator : scope `bot`, **aucune permission** cochée (permissions=0). Ouvrir l'URL et inviter le bot.
- Catégorie → Modifier → Permissions → ajouter le bot, et autoriser seulement :
  - Voir le salon ;
  - Envoyer des messages (créer un post de forum) ;
  - Envoyer des messages dans les fils ;
  - Gérer les fils ;
  - Lire l'historique ;
  - Intégrer des liens.
- **Si le salon de la défense est dans la même catégorie**, y refuser au bot Eregion « Voir le salon ». Un refus posé sur le salon pour ce membre l'emporte sur l'autorisation de la catégorie. Ne pas resynchroniser ce salon avec la catégorie : le bot de Glorfindel y garde ses droits.
- Le bot ne reçoit rien au niveau du serveur. Ailleurs, il ne voit que ce que `@everyone` voit.
- **Mode développeur** (Paramètres → Avancés). Clic droit sur `#lots`, puis sur `#roadmap` → Copier l'identifiant du salon. Clic droit sur ton nom → Copier l'identifiant de l'utilisateur.

**3. Les secrets.** Ce sont des URL et des jetons : jamais dans le dépôt (public), jamais sur H0. `host_env.py` ne recopie aucune variable `EREGION_DISCORD_*`.

```bash
gh secret set EREGION_DISCORD_WEBHOOK_CI          # l'URL du webhook de #ci (collée au prompt, pas dans l'historique)
gh secret set EREGION_DISCORD_BOT_TOKEN           # le jeton du bot Eregion
gh secret set EREGION_DISCORD_LOTS_FORUM          # l'id du forum #lots
gh secret set EREGION_DISCORD_ROADMAP_CHANNEL     # l'id du salon #roadmap (N2)
```

`#roadmap` n'a pas de webhook : c'est le bot qui poste son message, puis le réécrit. Après le premier run, épingle-le ; le script le retrouve parmi les messages épinglés, puis parmi les 50 derniers, et seulement s'il est de lui.

Sur ton poste, pour les hooks d'elrond : `~/.config/eregion/discord.env`, en `chmod 600`. Les hooks tournent dans l'environnement de Claude Code, qui n'a pas forcément chargé `.envrc` (VS Code). Une variable posée dans l'environnement l'emporte sur le fichier.

```
EREGION_DISCORD_WEBHOOK_AGENTS=https://discord.com/api/webhooks/…
EREGION_DISCORD_BOT_TOKEN=…
EREGION_DISCORD_LOTS_FORUM=…
EREGION_DISCORD_MENTION=<ton id d'utilisateur>
EREGION_DISCORD_WEBHOOK_DEPLOY=https://discord.com/api/webhooks/…   # #deploy (H1)
```

Le webhook de `#deploy` est le seul secret de l'atelier qui va sur H0. `make glorfindel-host-cd-install` le copie dans `~/.eregion-cd/discord.env` (600), avec la mention et rien d'autre : le CD de H0 poste avec (H1, `infra/glorfindel-host/README.md`, « Le CD de H0 »).

**4. Les hooks**, chez toi et jamais dans le dépôt (ils s'exécuteraient chez chaque contributeur) : `bash scripts/elrond-hooks.sh install`. La commande ajoute palantir sur `Stop` et `SubagentStop`, et `notify_discord.py hook` sur `PreToolUse` (`Agent`) et `SubagentStop` (`elrond-worker|elrond-reviewer`). Chaque commande finit par `|| true` : un hook `PreToolUse` qui sort en 2 bloquerait l'outil, et `python3` sort en 2 si le fichier manque. `uninstall` les retire et garde les autres hooks (rtk compris).

**5. Vérifier** : `python3 scripts/notify_discord.py check`. La commande dit ce qui est configuré (les noms, jamais les valeurs), si le forum est lisible et quelles étiquettes manquent. `python3 scripts/roadmap_discord.py --dry-run` affiche le message de `#roadmap` et ce que recevrait le forum, sans rien écrire (avec `GITHUB_TOKEN=$(gh auth token)` pour l'API de GitHub).

**Reste à mesurer** (après la fusion) :
- `notify.yml` ne tourne que depuis main (`workflow_run`, `pull_request_target`). Un événement `release` prend le workflow du commit du tag : une release dont le tag précède ce fichier, v0.4.0 comprise, n'est pas annoncée.
- Les hooks sur un vrai run d'elrond : le `matcher` `Agent` de `PreToolUse`, les champs `agent_type` et `agent_transcript_path` de `SubagentStop`. Ils viennent de la documentation de Claude Code ; seule la fin des transcripts (`SubagentHandback`) a été mesurée.

**Mesuré le 27/10** : le bot n'a jamais besoin de se connecter au gateway. Sans connexion, il a créé un fil de forum et posé ses étiquettes en REST seul (essai de mise en place : `lot ESSAI blocked`, puis `run-end`).

## Les règles du script

`scripts/notify_discord.py`, sans dépendance hors de la bibliothèque standard :
- **Sans configuration, rien n'est envoyé**, et le code de sortie est 0. Ce qui n'est pas configuré n'est pas envoyé : sans bot, pas de fils ; sans `EREGION_DISCORD_WEBHOOK_AGENTS`, pas de `#agents`.
- **Une erreur de Discord ne fait jamais échouer l'appelant** : le job reste vert, l'agent continue. Elle donne une ligne sur stderr, `atelier: not sent — webhook #ci: HTTP 500`, sans URL ni jeton. Après un 429 qui demande 5 s ou moins, le script fait un second essai. Toute erreur de la bibliothèque HTTP est réduite à son nom (`InvalidURL` citerait l'URL, jeton compris), et les valeurs de l'environnement sont débarrassées de leurs espaces et sauts de ligne.
- **Aucune mention venue d'un texte.** `allowed_mentions` est vide sur chaque message : un titre de PR « @everyone » reste du texte. Seules les alertes de `#agents` mentionnent `EREGION_DISCORD_MENTION`.
- **Le hook rend la main tout de suite.** L'envoi part dans un processus détaché, qui écrit ses erreurs dans `~/.local/state/eregion/discord.log`. L'état local (les agents en cours, l'id du message « En cours ») est dans `~/.local/state/eregion/discord.json`, sous verrou. Un message « En cours » supprimé dans Discord est recréé. Un lancement refusé après le hook disparaît au bout de 24 h.

`scripts/roadmap_discord.py` (N2) suit les mêmes règles : sans bot ni salon, rien ; une erreur de Discord ou de GitHub donne une ligne, jamais un job rouge. Il attend jusqu'à 30 s un 429 (un passage crée plusieurs fils). Un `ROADMAP.md` dont la forme a changé perd sa section (critères, indicateurs), et le message le dit ; le message reste sous les limites de Discord (tronqué au-delà, et dit). Si la recherche de son message échoue (épinglés et derniers messages illisibles), il ne poste rien, plutôt qu'un second message figé. Il lit les issues sur toutes leurs pages. Un passage refait ce qui manque : il est idempotent. `--dry-run` sans forum configuré le dit (« non configuré »).

Tests : `tests/unit/test_notify_discord.py` et `tests/unit/test_roadmap_discord.py`, contre un faux Discord et un faux GitHub (`tests/unit/fake_discord.py`, un serveur HTTP sur la boucle locale : rien ne sort de la machine). Mutants M970–M979 et M980–M989 (`scripts/mutation_check.py --only M970,…`).
