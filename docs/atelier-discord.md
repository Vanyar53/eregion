# L'atelier dans Discord (N1, N2, N3)

_Lots N1 (#242) et N2 (#243), 27/10 ; N3 (#262), 28/10 : `#agents` devient le tableau de ce qui t'attend. Le déploiement de H0 (H1, #244) s'y ajoutera ensuite. REL1 (#269), 29/10 : une release en brouillon y attend que tu la publies._

Ce que fait l'atelier (la CI, les PR, les lots d'elrond) arrive dans Discord, à part de la défense : le bot de Glorfindel, ses cartes et son channel ne changent pas.

## Ce qui va où

| Où | Quoi | Notifie ? |
|---|---|---|
| `#ci` | PR ouverte, PR fusionnée, issue fermée | non (silencieux) |
| `#ci` | run rouge : PR, main, runs de nuit (invariants, mutants, canary) ; release publiée | oui |
| `#ci` | main de nouveau verte après un rouge | non |
| `#lots` (forum) | un fil par lot ouvert, et seulement un lot (N2) : lancé, rendu, relecture, correction, PR, fusion, issue fermée (N1) ; le rapport de chaque exécutant et de chaque relecteur, un aperçu et le fichier `.md` entier (N3) ; étiquettes jalon et état tenues à jour | non |
| `#agents` | **le tableau**, un message réécrit sur place (N3) : 🙋 ce qui t'attend, 🔄 les agents d'elrond en cours (relances comprises), ✅ ce qui est rendu depuis peu, 🏁 le dernier run ; chaque ligne avec ses liens (fil du lot, PR, issue, rapport) | non |
| `#agents` | **un ping par chose qui t'attend**, avec ta mention et ses liens, **effacé une fois réglé** : lot bloqué, relecture non obtenue, la session elrond qui attend ta permission ou ta réponse, une PR à fusionner toi-même, une release en brouillon à publier (REL1), la fin du run | oui |
| `#roadmap` | un seul message du bot, réécrit sur place (N2) : une barre par jalon, en cours, relus, bloqués, à faire, les critères de la 1.0, les cinq indicateurs | non |
| `#deploy` | le CD de H0 (H1) : début, succès, attente de la CI, agent de CD à mettre à jour, résultats du dry-run | non |
| `#deploy` | refus, retour arrière, retour arrière raté, H0 dépareillé, erreur de l'agent : avec ta mention | oui |

Ce qui ne mérite rien n'envoie rien : un run vert sur une PR, un run annulé, une PR fermée sans fusion, les agents qui ne sont pas ceux d'elrond. **Ne te notifie plus** (N3) : une relecture `changes` ou `blocking` (elrond corrige seul), le repli d'un exécutant (elrond le fait relire), un rendu, une relecture sans verdict lisible — c'est dans le fil du lot et dans le tableau.

**Pourquoi N3.** Le premier vrai run avec N1 (28/10 : I1S, I4S, I8S, H1) a donné 10 alertes dans `#agents`, une seule juste. Une pause (un relecteur qui attend ses mutants finit son tour : `SubagentStop`) était prise pour un rendu ; le rapport était lu dans le transcript, où le `SubagentHandback` n'est pas encore écrit quand `SubagentStop` s'exécute (« sans verdict », ou le verdict précédent) ; les corrections et secondes relectures, qu'elrond envoie par `SendMessage` à l'agent qui existe déjà, n'étaient vues par aucun hook (« Rien ne tourne » pendant une relecture). Et rien n'avait de lien.

**D'où ça vient.**
- **GitHub** : `.github/workflows/notify.yml`. Le workflow ne récupère ni n'exécute jamais le code d'une PR (`pull_request_target` et `workflow_run` lisent les fichiers de la branche par défaut). Le script ne lit que le JSON de l'événement.
- **Les lots d'elrond** (`scripts/agents_discord.py`, N3) : des hooks de Claude Code, chez toi (plus bas).
  - **Lancé** : `PreToolUse` sur `Agent`. **Relancé** (correction, seconde relecture) : `PreToolUse` sur `SendMessage`, dont le `to` est l'id d'un agent d'elrond déjà rendu ; tout `SendMessage` d'une session d'elrond est mis en file, et c'est à la livraison, dans l'ordre, qu'on regarde si `to` est l'un de ses agents (son rendu peut être encore en file).
  - **Rendu** : `PreToolUse` sur `SubagentHandback`, dans l'agent ; le rapport est dans `tool_input.message` (c'est ce que la doc de Claude Code recommande). Le verdict vient de sa ligne `**Verdict : …**`. palantir lit le transcript de l'agent pour un repli, **sur le seul tronçon depuis son lancement ou sa relance**.
  - **`SubagentStop`** ne sert plus qu'à deux choses : une pause (`background_tasks` non vide) n'est rien ; un agent qui finit sans `SubagentHandback` (hors auto mode) est lu dans `last_assistant_message`. Un agent qui a déjà rendu une fois par `SubagentHandback` n'est plus jamais lu dans son `SubagentStop` : ce serait une pause, ou l'arrêt en retard d'un tronçon déjà dit. Sauf pour un repli : ses derniers tours peuvent arriver au transcript après la lecture du rendu ; relus à son arrêt, un repli de ce tronçon fait de la relecture une « non obtenue », pingée (elrond relance palantir lui-même : sa garde n'en dépend pas). Un rendu sans lancement ni relance entre deux (un hand-back redit) ne compte les replis que depuis le rendu précédent.
  - **La session qui t'attend** : `Notification` (`permission_prompt`, que Claude Code envoie, selon sa doc, après ~6 s d'attente : non mesuré) et `AskUserQuestion` (une question non répondue au bout de 30 s). Seulement une session d'elrond : elle a lancé un agent d'elrond, ou en a dans son dossier. Le ping s'efface quand la session reprend : `Stop`, la question répondue (`PostToolUse` sur `AskUserQuestion`), ou un lancement, une relance, une autre question de cette session ; jamais un événement d'un sous-agent.
  - **L'ordre** : chaque hook ne fait qu'ajouter l'événement à une file locale et rend la main ; un seul processus à la fois la vide, dans l'ordre. `PreToolUse` et `SubagentStop` sont synchrones (une fraction de seconde : le temps de démarrer Python) : un rendu est en file avant que l'outil ne s'exécute, donc avant son `SubagentStop`, et celui-ci avant qu'elrond puisse relancer l'agent. Les autres hooks sont asynchrones.
  - **Un échec de `#lots`** (le forum, une pièce jointe) est dit et n'empêche jamais `#agents` : ce qui t'attend est au tableau et pingé quand même. Une relecture non obtenue puis le lot bloqué par elrond : un seul ping (le blocage règle le « non obtenue »).
- **Une release en brouillon** (REL1, `make release-draft`, `docs/operations.md`, « Packaging et version ») :
  - **La ligne.** `scripts/release.py` pose au tableau « 🙋 release vX.Y.Z en brouillon, à publier », avec un lien vers le brouillon (visible des seuls membres du dépôt). Un ping la suit, avec ta mention.
  - **L'effacement.** La ligne et le ping s'effacent quand tu publies. `notify.yml` voit `release: published`, mais il tourne sur GitHub, sans l'état local. `release.py` écrit donc dans les notes du brouillon où sont les deux messages : un commentaire HTML, invisible sur la page de la release (`<!-- #agents (REL1) : ping=<id> board=<id> … -->`, des chiffres seulement). Avec ces ids, le webhook de `#agents` lit chaque message avant d'y toucher. Il efface le ping seulement si son titre est celui de ce brouillon. Il réécrit le tableau seulement si c'est le tableau, et n'en retire que la ligne de ce brouillon. Le secret n'est donné à l'étape que pour un événement `release`.
  - **Le relais local.** Le tableau local demande aussi à GitHub si la release est publiée : au plus toutes les 5 min, à chaque événement, et par le veilleur des PR (deux jours au plus). GitHub ne connaît une release par son tag qu'une fois publiée. Sans le secret dans GitHub, c'est ce relais qui efface, au rafraîchissement suivant. Quand le ping d'un brouillon a disparu de Discord (`notify.yml` l'a effacé), GitHub est demandé tout de suite, sans attendre les 5 min (le ping est cherché au plus une fois par minute) : la ligne retirée par `notify.yml` ne revient pas.
  - **À la main** : `agents_discord.py clear vX.Y.Z`, pour un brouillon supprimé sans être publié. Un nouveau brouillon du même tag remplace l'ancien : son lien, et un nouveau ping (l'ancien est effacé).
  - **Sans configuration** : rien n'est envoyé, et la commande réussit.
- **La feuille de route** : `.github/workflows/roadmap.yml` lance `scripts/roadmap_discord.py` à chaque push sur main, chaque jour, et quand une issue ou une PR vers main s'ouvre ou se ferme. Un run à la fois, chaque workflow dans son groupe (`roadmap-discord`, `notify-discord`) : GitHub ne garde qu'un run en attente par groupe, et un plus récent l'annule — sans conséquence pour la feuille de route, qui réécrit tout à chaque passage ; pour `notify.yml`, trois événements simultanés perdent celui du milieu (limite connue). La feuille de route ne crée de fils qu'au push, au passage quotidien ou à la main ; sur un événement d'issue ou de PR, c'est N1 qui crée le fil du lot.
- **elrond lui-même**, pour ce que lui seul sait (`.claude/skills/elrond/SKILL.md`) : `agents_discord.py lot <ID> blocked --note …`, `agents_discord.py lot <ID> merge --pr <n>` (une PR que tu fusionnes toi-même : le classifieur refuse `gh pr merge` ; le ping s'efface quand GitHub la dit fusionnée ou fermée : demandé au plus toutes les 5 min à chaque événement, et par un veilleur détaché, toutes les 5 min tant qu'une PR attend, deux jours au plus — la fusion vient souvent après le run, quand plus rien ne se passe), `agents_discord.py run-end "<bilan>"`. À la main : `agents_discord.py clear <ID>|all` (ce qui attend sur un lot, réglé), `agents_discord.py board` (le tableau réécrit, les PR revérifiées).

**Le fil d'un lot.**
- Il s'appelle « `<ID> · <titre> · #<n>` ». Le script le retrouve, archivé compris, d'abord par le numéro de l'issue, puis par l'ID du lot : la branche `lot/<id>-…`, l'ID en tête du titre ou entre parenthèses (« (A3, #73) »). Un fil qui porte le numéro d'une autre issue n'est jamais repris : les deux issues d'I1F (#226, #231) ont chacune le leur.
- **Qui a un fil** (décisions du 27/10) : les **lots ouverts** des quatre jalons, c'est-à-dire les issues dont le titre commence par un ID de lot (« A3 — … », « I1F suite : … »). Les issues de suivi (#70, #95) et les constats sans lot n'en ont pas : ils restent sur GitHub et dans `#roadmap` ; un fil créé pour l'un d'eux avant cette règle est archivé. Une issue fermée n'en reçoit pas ; le sien, s'il existe, passe à « fait » et s'archive. L'historique d'avant reste sur GitHub et dans les barres de `#roadmap`.
- **L'état** : « fait » pour une issue fermée, et gardé pour une issue encore ouverte (lot fusionné ou relu `ok`, son « Fini quand » pas encore prouvé), sauf si elle a été rouverte ; une PR ouverte du dépôt (jamais celle d'un fork) qui nomme le lot le met au moins « en cours » ; les états fins d'elrond (`en relecture`, `en correction`, `bloqué`) sont gardés ; sinon « à faire ». Un fil créé par elrond est retrouvé par l'ID du lot et renommé au nom canonique. Un fil que Discord a archivé faute d'activité le reste, sauf s'il doit changer.
- Un événement de GitHub (N1) ne crée un fil que pour un lot connu (son ID) ; un run rouge poste dans le fil existant, sans jamais en créer.
- **La PR d'un fork** est annoncée dans `#ci`, jamais dans un fil : son titre peut nommer n'importe quel lot. **Son run rouge aussi** (SEC6, 28/10) : un `workflow_run` dont la tête vient d'un autre dépôt que celui-ci (`head_repository`, absent compris) va dans `#ci` seulement — la branche `lot/<id>-…` d'un fork est à lui de choisir.
- **Une issue fermée par quelqu'un du dehors** (SEC6) : n'importe qui peut ouvrir une issue « A3 — … » et la fermer. Son auteur doit tenir un rôle dans le dépôt (`author_association` : `OWNER`, `MEMBER`, `COLLABORATOR`) pour que le fil du lot passe à « fait » et s'archive ; sinon, `#ci` seulement, et aucun fil créé.

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
gh secret set EREGION_DISCORD_WEBHOOK_AGENTS      # l'URL du webhook de #agents : une release publiée efface la ligne de son brouillon (REL1)
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

**4. Les hooks**, chez toi et jamais dans le dépôt (ils s'exécuteraient chez chaque contributeur) : `bash scripts/elrond-hooks.sh install`, **à relancer après N3** (les hooks de N1 appelaient `notify_discord.py hook`, retirés à la réinstallation). La commande ajoute palantir sur `Stop` et `SubagentStop`, et `agents_discord.py hook` sur `PreToolUse` (`Agent|SendMessage|SubagentHandback|AskUserQuestion`, synchrone), `PostToolUse` (`AskUserQuestion`), `SubagentStop` (`elrond-worker|elrond-reviewer`, synchrone), `Notification` (`permission_prompt`) et `Stop`. Chaque commande finit par `|| true` : un hook `PreToolUse` qui sort en 2 bloquerait l'outil, et `python3` sort en 2 si le fichier manque. `uninstall` les retire et garde les autres hooks (rtk compris).

Après la réinstallation, le message « En cours » épinglé de N1 devient le tableau (même message, réécrit). Les anciennes alertes de `#agents` restent : à supprimer à la main, une fois.

**5. Vérifier** : `python3 scripts/notify_discord.py check`. La commande dit ce qui est configuré (les noms, jamais les valeurs), si le forum est lisible et quelles étiquettes manquent. `python3 scripts/roadmap_discord.py --dry-run` affiche le message de `#roadmap` et ce que recevrait le forum, sans rien écrire (avec `GITHUB_TOKEN=$(gh auth token)` pour l'API de GitHub).

**Reste à mesurer** (après la fusion) :
- `notify.yml` ne tourne que depuis main (`workflow_run`, `pull_request_target`). Un événement `release` prend le workflow du commit du tag : une release dont le tag précède ce fichier, v0.4.0 comprise, n'est pas annoncée.
- Les hooks sur un vrai run d'elrond (N3) : `PreToolUse` sur `SubagentHandback` dans un sous-agent (ses champs `agent_id`, `agent_type`, `transcript_path`), `background_tasks` de `SubagentStop`, `Notification` `permission_prompt` dans VS Code. Ils viennent de la documentation de Claude Code ; le classifieur d'auto mode a refusé, le 28/10, d'installer un hook de mesure. Mesurés dans les transcripts du 28/10 : le `to` de `SendMessage` (l'id de l'agent) et les `questions` d'`AskUserQuestion`. Pour vérifier après un run : `~/.local/state/eregion/discord.trace`, une ligne par événement reçu, les noms de ses champs seulement (jamais leurs valeurs), et `meta=1` quand l'agent a été retrouvé depuis ses champs (`SubagentHandback`, `SubagentStop`), `known=1` quand le `to` d'un `SendMessage` est un agent d'elrond connu.
- La release en brouillon (REL1), sur la 0.4.4 : `gh release edit vX.Y.Z --notes-file` sur un brouillon (gh le retrouve par son tag), le commentaire HTML gardé tel quel dans le `body` de l'événement `release: published`, `GET` d'un message par son webhook, et `releases/tags/vX.Y.Z` en 404 tant que c'est un brouillon. Tout vient de la documentation de GitHub et de Discord, rien n'est mesuré.

**Mesuré le 27/10** : le bot n'a jamais besoin de se connecter au gateway. Sans connexion, il a créé un fil de forum et posé ses étiquettes en REST seul (essai de mise en place : `lot ESSAI blocked`, puis `run-end`).

## Les règles du script

`scripts/notify_discord.py` (GitHub vers `#ci` et `#lots`) et `scripts/agents_discord.py` (elrond vers `#agents` et `#lots`, N3), sans dépendance hors de la bibliothèque standard :
- **Sans configuration, rien n'est envoyé**, et le code de sortie est 0. Ce qui n'est pas configuré n'est pas envoyé : sans bot, pas de fils ; sans `EREGION_DISCORD_WEBHOOK_AGENTS`, pas de `#agents`.
- **Une erreur de Discord ne fait jamais échouer l'appelant** : le job reste vert, l'agent continue. Elle donne une ligne sur stderr, `atelier: not sent — webhook #ci: HTTP 500`, sans URL ni jeton. Après un 429 qui demande 5 s ou moins, le script fait un second essai. Toute erreur de la bibliothèque HTTP est réduite à son nom (`InvalidURL` citerait l'URL, jeton compris), et les valeurs de l'environnement sont débarrassées de leurs espaces et sauts de ligne.
- **Aucune mention venue d'un texte.** `allowed_mentions` est vide sur chaque message : un titre de PR « @everyone » reste du texte. Seuls les pings de `#agents` mentionnent `EREGION_DISCORD_MENTION`.
- **Le hook rend la main tout de suite.** Il ajoute l'événement à `~/.local/state/eregion/discord.queue` ; l'envoi part dans un processus détaché, qui écrit ses erreurs dans `discord.log`. L'état local (les agents en cours et rendus, ce qui t'attend et l'id de son ping, les fils, l'id du tableau) est dans `discord.json`, sous verrou. Un tableau supprimé dans Discord est recréé, mais n'est plus épinglé (un webhook ne peut pas épingler : à réépingler à la main). Un ping supprimé à la main est oublié sans erreur ; un ping dont l'effacement échoue (503…) est gardé et réessayé au rafraîchissement suivant. Un livreur qui trouve la file vidée par un autre ne réécrit rien. Un agent pas revenu depuis 7 jours est oublié. Le rapport joint est coupé au-delà de 1 Mo (les vrais : 1 à 15 Ko). Un lancement refusé après le hook disparaît au bout de 24 h ; « Rendu récemment » garde les 8 derniers.

`scripts/roadmap_discord.py` (N2) suit les mêmes règles : sans bot ni salon, rien ; une erreur de Discord ou de GitHub donne une ligne, jamais un job rouge. Il attend jusqu'à 30 s un 429 (un passage crée plusieurs fils). Un `ROADMAP.md` dont la forme a changé perd sa section (critères, indicateurs), et le message le dit ; le message reste sous les limites de Discord (tronqué au-delà, et dit). Si la recherche de son message échoue (épinglés et derniers messages illisibles), il ne poste rien, plutôt qu'un second message figé. Il lit les issues sur toutes leurs pages. Un passage refait ce qui manque : il est idempotent. `--dry-run` sans forum configuré le dit (« non configuré »).

Tests : `tests/unit/test_notify_discord.py`, `tests/unit/test_agents_discord.py`, `tests/unit/test_release.py` (REL1 : la ligne d'un brouillon posée, puis effacée à la publication) (N3 : la séquence d'I8S du 28/10 rejouée — pause, `blocking`, correction et seconde relecture par `SendMessage`, `ok`) et `tests/unit/test_roadmap_discord.py`, contre un faux Discord et un faux GitHub (`tests/unit/fake_discord.py`, un serveur HTTP sur la boucle locale : rien ne sort de la machine). Mutants M970–M979, M980–M989, M990–M999, M1060–M1076, M1160–M1169, M1430–M1439 et M1470 (`scripts/mutation_check.py --only M970,…`).
