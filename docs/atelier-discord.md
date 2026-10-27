# L'atelier dans Discord (N1)

_Lot N1 (#242), 27/10. La feuille de route (N2, #243) et le déploiement de H0 (H1, #244) s'y ajoutent ensuite._

Ce que fait l'atelier (la CI, les PR, les lots d'elrond) arrive dans Discord, à part de la défense : le bot de Glorfindel, ses cartes et son channel ne changent pas.

## Ce qui va où

| Où | Quoi | Notifie ? |
|---|---|---|
| `#ci` | PR ouverte, PR fusionnée, issue fermée | non (silencieux) |
| `#ci` | run rouge : PR, main, runs de nuit (invariants, mutants, canary) ; release publiée | oui |
| `#ci` | main de nouveau verte après un rouge | non |
| `#lots` (forum) | un fil par lot : lancé, rendu, relecture, correction, PR, fusion, issue fermée ; étiquettes jalon et état tenues à jour | non |
| `#agents` | un message « En cours » réécrit sur place : les agents d'elrond qui tournent, depuis quand | non |
| `#agents` | ce qui t'attend, avec ta mention : repli de modèle, relecture `changes` / `blocking` / sans verdict / non obtenue, lot bloqué, fin de run | oui |
| `#roadmap` | N2 | — |
| `#deploy` | H1 | — |

Ce qui ne mérite rien n'envoie rien : un run vert sur une PR, un run annulé, une PR fermée sans fusion, les agents qui ne sont pas ceux d'elrond.

**D'où ça vient.**
- **GitHub** : `.github/workflows/notify.yml`. Le workflow ne récupère ni n'exécute jamais le code d'une PR (`pull_request_target` et `workflow_run` lisent les fichiers de la branche par défaut). Le script ne lit que le JSON de l'événement.
- **Les lots d'elrond** : des hooks de Claude Code, chez toi (plus bas). Le lancement passe par `PreToolUse` sur `Agent`. Le retour passe par `SubagentStop` : palantir y lit le transcript de l'agent, qui dit s'il y a eu un repli. Le verdict vient de la ligne `**Verdict : …**` du rapport, que le relecteur rend par l'outil `SubagentHandback` (mesuré le 27/10 sur les transcripts réels : son dernier message n'est pas un texte). Le script le lit dans le transcript ; à défaut, dans le dernier texte, puis dans `last_assistant_message`.
- **elrond lui-même**, pour deux choses seulement : `notify_discord.py lot <ID> blocked --note …` et `notify_discord.py run-end "<bilan>"` (`.claude/skills/elrond/SKILL.md`).

**Le fil d'un lot.**
- Il s'appelle « `<ID> · <titre>` ». Le script le retrouve, archivé compris, par l'ID du lot : la branche `lot/<id>-…`, l'ID en tête du titre ou entre parenthèses (« (A3, #73) »). À défaut, il le retrouve par le numéro de l'issue.
- Un événement de GitHub ne crée un fil que pour un lot connu (son ID) ; un run rouge poste dans le fil existant, sans jamais en créer.
- Une issue fermée archive son fil.
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
- **Mode développeur** (Paramètres → Avancés). Clic droit sur `#lots` → Copier l'identifiant du salon. Clic droit sur ton nom → Copier l'identifiant de l'utilisateur.

**3. Les secrets.** Ce sont des URL et des jetons : jamais dans le dépôt (public), jamais sur H0. `host_env.py` ne recopie aucune variable `EREGION_DISCORD_*`.

```bash
gh secret set EREGION_DISCORD_WEBHOOK_CI          # l'URL du webhook de #ci (collée au prompt, pas dans l'historique)
gh secret set EREGION_DISCORD_BOT_TOKEN           # le jeton du bot Eregion
gh secret set EREGION_DISCORD_LOTS_FORUM          # l'id du forum #lots
```

Sur ton poste, pour les hooks d'elrond : `~/.config/eregion/discord.env`, en `chmod 600`. Les hooks tournent dans l'environnement de Claude Code, qui n'a pas forcément chargé `.envrc` (VS Code). Une variable posée dans l'environnement l'emporte sur le fichier.

```
EREGION_DISCORD_WEBHOOK_AGENTS=https://discord.com/api/webhooks/…
EREGION_DISCORD_BOT_TOKEN=…
EREGION_DISCORD_LOTS_FORUM=…
EREGION_DISCORD_MENTION=<ton id d'utilisateur>
```

**4. Les hooks**, chez toi et jamais dans le dépôt (ils s'exécuteraient chez chaque contributeur) : `bash scripts/elrond-hooks.sh install`. La commande ajoute palantir sur `Stop` et `SubagentStop`, et `notify_discord.py hook` sur `PreToolUse` (`Agent`) et `SubagentStop` (`elrond-worker|elrond-reviewer`). Chaque commande finit par `|| true` : un hook `PreToolUse` qui sort en 2 bloquerait l'outil, et `python3` sort en 2 si le fichier manque. `uninstall` les retire et garde les autres hooks (rtk compris).

**5. Vérifier** : `python3 scripts/notify_discord.py check`. La commande dit ce qui est configuré (les noms, jamais les valeurs), si le forum est lisible et quelles étiquettes manquent.

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

Tests : `tests/unit/test_notify_discord.py`, contre un faux Discord, un serveur HTTP sur la boucle locale (rien ne sort de la machine). Mutants M970–M979 (`scripts/mutation_check.py --only M970,…`).
