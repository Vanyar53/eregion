# Modèle de menace

_SEC6 (#277), 28/10, sur la 0.4.3. Une page par frontière : qui y est de confiance, ce qui la traverse, les menaces (STRIDE, une ligne chacune), ce qui les tient aujourd'hui — avec le code et le lot qui l'ont posé —, et ce qui reste ouvert._

**Règle d'écriture (dépôt public).** Ce document décrit la politique, les frontières et ce qui les tient. Un point encore ouvert y est dit de façon neutre, « planifié : #n », sans la façon de s'en servir ; le lot qui le ferme le fait passer dans « ce qui tient ». Signaler une faille : [`SECURITY.md`](../../SECURITY.md).

**Ce qu'Eregion protège.** Les charges du client : ne jamais les rendre plus joignables qu'il ne les a conçues, ne jamais les couper à tort sans qu'un humain l'ait voulu, ne jamais y laisser une panne ou une action destructive (la règle de production, `eregion_core/inscription.py`). Puis ce qu'Eregion sait d'elles : journaux, noms, adresses. Puis ses propres secrets : identités Azure, clé du modèle, jetons de Discord et de la console.

**Ce qui n'est pas de confiance, partout.** Le contenu des journaux (un attaquant sur une VM surveillée écrit ses lignes), les noms et attributs que renvoie Azure (n'importe qui ayant le droit d'enregistrer une application Entra choisit son nom), la réponse du modèle, ce qu'un injecteur écrit dans `runs/`, ce qu'un fork ou un inconnu envoie à GitHub.

| Frontière | De confiance | Ce qui la traverse |
|---|---|---|
| [1. La console](#1-la-console-locale-h0) | l'opérateur qui tient le jeton | requêtes HTTP et WebSocket, actions Azure, texte du dehors affiché |
| [2. `runs/` et l'état local](#2-le-canal-runs-et-létat-local) | Glorfindel (watch, console, bot, CLI : un même utilisateur) | signaux et fenêtres des injecteurs, état d'isolation et de blocage, escalades |
| [3. Discord et les webhooks](#3-discord-et-les-webhooks) | les utilisateurs et rôles autorisés | cartes (texte du modèle, noms Azure), clics, nouvelles de l'atelier |
| [4. Le fournisseur du modèle](#4-le-fournisseur-du-modèle) | pour la confidentialité, le fournisseur choisi ; pour la décision, personne | extraits de journaux à l'aller, une proposition au retour |
| [5. Les hôtes](#5-les-hôtes--h0-orodruin-le-banc) | l'opérateur, l'hôte (root) | identités Azure, actions sur le cloud, injecteurs |
| [6. La CI et le CD](#6-la-ci-et-le-cd-github-release-tags) | le mainteneur, `main` protégée | code des PR, événements GitHub, secrets, releases vers H0 |
| [7. Les sessions d'agents → `main` → le CD](#7-les-sessions-dagents--main--le-cd) | le mainteneur (tags `v*`, release, réglages) ; les sessions, pour le code qu'elles fusionnent | branches, PR, fusions, verdicts de relecture, releases en brouillon |

---

## 1. La console (locale, H0)

**De confiance** : l'opérateur qui tient le jeton, depuis un navigateur sur la boucle locale (sur H0, à travers le tunnel SSH). **Pas de confiance** : les autres sites que ce navigateur ouvre, les autres utilisateurs de la machine, le texte qu'affichent les cartes.

**Ce qui la traverse** : des lectures (cartes, état, indicateurs) ; des actions qui touchent Azure (lever, restaurer, approuver, passer un actif en `non_disruptive`) ; du texte venu du dehors (explications du modèle, noms de VM et d'applications, lignes de journaux). Depuis DG-b (#348), la console fait aussi agir sur le cloud, de loin : elle écrit une **demande d'exercice** pour Orodruin. Elle ne la lance pas : l'opérateur la porte, Orodruin la juge et la lance.

| | Menace | Ce qui la tient |
|---|---|---|
| S | Un autre site, ou un autre utilisateur local, agit comme l'opérateur | Toujours un jeton, tiré au premier démarrage s'il manque ; un cookie de session dérivé (HMAC), HttpOnly, SameSite=Strict (SEC1) |
| T | Une page tierce (DNS rebinding, CSRF) change l'état | `Host` d'une liste fermée, `Origin` exacte pour toute modification, corps JSON obligatoire (SEC1) |
| R | Une action sans trace | Le fil des actions de l'opérateur, `runs/manual_actions.jsonl` ; chaque carte garde son verdict et sa date |
| I | Le jeton ou des identifiants fuient | Le jeton retiré de l'URL après la première ouverture, jamais sur une ligne de commande ; ni schéma OpenAPI ni `/docs` ; Config masque abonnement, tenant et client (SEC1) |
| D | La console tombe ou est inondée | Elle est un processus à part : la watch détecte et le bot alerte sans elle |
| E | Un texte du dehors s'exécute dans la page | Rien du dehors écrit brut, aucun script ni gestionnaire en ligne, CSP `default-src 'self'` (#254, #257, SEC1) ; un restore depuis la console n'accepte que la carte de restauration de cette VM, jamais une carte ancrée |
| T | Une page tierce, ou un H0 compromis, fait lancer une attaque ou une panne | La demande passe par SEC1 : jeton, origine, corps JSON. Elle est jugée par le cœur partagé avant d'être écrite ; un fil refusé, rien n'est écrit. La console n'écrit qu'un fichier, dans son propre répertoire (`~/.eregion/console/requests/`), jamais sur le cloud. Rien ne part sans le geste de l'opérateur (`make orodruin-exercise`), qui voit la demande fil par fil sur son poste. Orodruin la rejuge : contrat armé, inscription et zone relues, règle de production, watch vivante, plafond sur la demande entière. Un fil destructif exige le nom de sa cible, tapé sur le poste et jamais dans la console, qu'Orodruin compare au nom qu'il lit (DG-b) |
| S | Le navigateur dit ce que vaut un fil (« non destructif », « zone bench », un nom tapé) | Il n'envoie que deux identifiants par fil ; un champ de plus est refusé, à la console comme au lecteur de la demande. Le serveur, puis Orodruin, recalculent tout (DG-b) |
| I | Le plan rouge entre dans ce que lit la décision | Seul le service de la console monte `~/.eregion/console/` ; aucun service watch ni bot ne monte `~/.eregion`, ni le répertoire de la console. Aucun module de `glorfindel/` ne le nomme. Ce qu'Orodruin publie ne nomme ni l'expérience ni la cible (DG-b, `tests/unit/test_profiles.py`) |
| E | La console reçoit le droit de faire agir Orodruin | Aucun droit ni canal de plus : ni pour la console, ni pour l'identité de H0, ni pour le canal. La demande voyage par SSH, portée par l'opérateur. « Stop all » donne `make orodruin-kill` : la console ne révoque rien et ne le peut pas (DG-b) |

**Où c'est dans le code** : `eregion_console/api.py` (middleware du jeton, de l'hôte et de l'origine ; en-têtes ; `POST /api/dagorlad/requests`), `eregion_console/static/glorfindel.js` (`_post`, `_seg`), `eregion_core/exercise_request.py` (le seul lecteur de la demande), `scripts/console_escaping.py` ; tests `tests/unit/test_console.py`, `tests/unit/test_console_escaping.py`, `tests/unit/test_console_dagorlad_request.py`, `tests/unit/test_profiles.py`. Détail : [`docs/glorfindel.md`](../glorfindel.md), « Console — exposition » ; Dagorlad : [`docs/design/console.md`](console.md), §7.

**Choix assumé** : un jeton, tous les droits de la console — ni comptes ni rôles avant la 1.x. Une demande n'est pas signée par la console : ce qui la tient, c'est le geste de l'opérateur et le jugement d'Orodruin, pas sa provenance.

**Ouvert** : rien de connu à cette frontière au-delà de ce choix.

---

## 2. Le canal `runs/` et l'état local

**De confiance** : Glorfindel, qui seul écrit `~/.glorfindel/` (la watch, la console, le bot et la CLI, sous un même utilisateur). **Moins de confiance** : les injecteurs (Annatar, Gothmog), qui écrivent `runs/` ; tout ce qui s'y trouve est lu comme une donnée à valider.

**Ce qui la traverse** : les signaux des injecteurs (`attack_started`, `detection_missed`), leurs fenêtres d'exercice et leurs rapports ; l'état d'isolation et de blocage ; les escalades ; le battement de la watch, que lisent les injecteurs.

| | Menace | Ce qui la tient |
|---|---|---|
| S | Une ligne de `runs/` se fait passer pour Glorfindel (un `recovery_complete` qui lève une isolation) | La watch ne prend de `runs/` que ce qu'un injecteur émet, chaque champ vérifié ; un `recovery_complete` ne lève seul que s'il vient du chemin propre de Glorfindel (`glorfindel/signal_origin.py`, SEC3) |
| T | Un état illisible ou tronqué est lu comme « pas d'état » et libère une VM | Illisible n'est jamais absent : le balayage ne retire rien et le dit (SEC3) ; la levée, le reset et `verify_release` ne retirent rien d'une carte en quarantaine ou sans NSG et ne disent pas levé, la réaffirmation le dit (SEC4b) ; état écrit entier, en 0600 (dossiers 0700) ; escalades (SEC3) et règles proposées (SEC4b) sous `flock`, réécrites entières |
| R | Une ligne refusée disparaît sans bruit | Elle est journalisée et comptée (`~/.glorfindel/channel_refusals.json`, SEC3) |
| I | Un injecteur lit l'état du bleu (ce qui est isolé, bloqué, escaladé) | Les conteneurs des injecteurs ne montent que `~/.glorfindel/injectors`, en lecture seule, où la watch copie son battement (SEC3) |
| D | Un flot de lignes dans `runs/` | Lecture bornée par fichier et par relevé, débit borné par fichier et pour le canal ; le surplus n'est pas admis, il est dit en une ligne et compté. Ce qu'une ligne admise lance est borné : une recherche par VM et par technique, un nombre de recherches, une file par VM, un nombre de VM ; les durées sont finies. Une technique ni du catalogue ni des règles est refusée : ni recherche ni appel au modèle (SEC8, `glorfindel/channel_reader.py`) |
| D | Une entrée de `runs/` qui bloque la lecture ou ne finit pas | La watch, et la recherche du moment d'un restore, ne lisent que des fichiers ordinaires, ouverts sans bloquer et sans suivre un lien ; le reste est refusé, dit une fois ; une ligne démesurée est refusée, dite (SEC8). Le flux de la console et la TUI ne sont pas encore tenus : voir « Ouvert » |
| T | Une ligne de `runs/` choisit le moment d'un restore | Une ligne ne compte que pour une carte d'exercice rattachée à son run, jamais après la première détection de la carte ; sinon, le plus ancien des moments que Glorfindel a notés, et le champ le dit (SEC8, `glorfindel/restore_plan.py`) |
| I | Une ligne fait interroger un autre espace, ou envoie le jeton ailleurs | L'espace interrogé vient de la config, une ligne qui en nomme un autre est refusée ; un appel ARM qui porte le jeton est construit des parties lues de l'identifiant (abonnement, groupe, nom), jamais de l'identifiant tel qu'il est reçu ; une page suivante hors d'ARM n'est pas suivie (SEC8, `eregion_core/held.py`) |
| E | Une fenêtre d'exercice déclarée pour faire passer une vraie attaque pour un exercice | Fenêtre bornée en durée et en avance (`MAX_DURATION_S`, `FUTURE_SKEW_S`), qui doit nommer une VM inscrite ; une fenêtre refusée l'est pour de bon (B2, `eregion_core/exercise.py`) ; une fenêtre tirée dont la copie locale ne se lit plus n'est jamais remplacée (SEC7) |

**Le rapport d'un run et la matrice de couverture (C1)** : un rapport de run arrive sur H0 par le canal d'exercice, écrit sur Orodruin. Un `missed` forgé peut faire passer une ligne de la matrice en `regressed` : c'est une **fausse alarme**, dite en rouge, **jamais une preuve** — une preuve exige l'enregistrement de la décision par la watch, que Glorfindel seul écrit, sur la VM que le rapport nomme et au plus près de la détection comptée. Un `detected` forgé compte dans la couverture des 30 jours, comme avant C1. Un run daté dans le futur (au-delà de `FUTURE_SKEW_S`) est écarté de la matrice et des indicateurs, et dit ; ce que le rapport nomme est imprimé sans caractère de contrôle par `eregion coverage`, et échappé dans la console (`eregion_console/coverage.py`).

**Où c'est dans le code** : `glorfindel/signal_origin.py`, `glorfindel/channel_reader.py`, `glorfindel/restore_plan.py`, `eregion_core/held.py` (`vm_parts`), `glorfindel/response/state.py`, `glorfindel/response/locks.py`, `glorfindel/reassert_cards.py`, `glorfindel/proposed_rules.py`, `eregion_core/exercise.py` ; tests `tests/unit/test_signal_origin.py`, `tests/unit/test_locks.py`, `tests/unit/test_unreadable_state.py`, `tests/unit/test_exercise_guard.py`, `tests/unit/test_runs_channel.py`, `tests/unit/test_arm_urls.py`. Détail : [`docs/glorfindel.md`](../glorfindel.md), « Le canal runs/ » ; [`docs/fichiers-cles.md`](../fichiers-cles.md).

**Ouvert** : d'autres points de l'état local — planifié : #275 ; un répertoire par écrivain, en lecture seule chez les autres — planifié ; le flux de la console et la TUI lisent encore le canal sans ces bornes — planifié : #425 ; une technique du catalogue sans règle coûte encore un appel au modèle — planifié ; le compte des VM nommées par le canal ne se vide qu'au redémarrage — planifié.

---

## 3. Discord et les webhooks

Trois canaux, à ne pas confondre :
- **le bot de Glorfindel** (le produit) : un fil par VM, une carte par escalade, des boutons ;
- **le bot de l'atelier** (« Eregion ») et ses webhooks (`#ci`, `#agents`, `#deploy`) : les nouvelles de la CI, des lots et du CD — son jeton jamais sur H0 ni dans un conteneur ; sur H0, seul le webhook de `#deploy`, pour le CD ([`docs/atelier-discord.md`](../atelier-discord.md)) ;
- **le webhook de Glorfindel** (`GLORFINDEL_WEBHOOK_URL`) : à sens unique, au format Slack (Slack, Teams, ou Discord par `/slack`).

**De confiance** : les utilisateurs et rôles listés (`DISCORD_ALLOWED_USERS`, `DISCORD_ALLOWED_ROLES`) pour les boutons. **Pas de confiance** : les autres membres du serveur, le texte des cartes. Qui lit le salon voit les cartes (noms de VM, adresses, explications) : un salon privé est le choix de l'opérateur.

| | Menace | Ce qui la tient |
|---|---|---|
| S | Un membre du serveur juge une carte ou lance un restore | Boutons fermés par défaut, autorisés par id seulement, chaque refus dit et journalisé (M-3) |
| T | Un texte du dehors (le nom d'une application Entra, les mots du modèle) déguise un lien, imite une mise en forme ou mentionne tout le monde | Tout texte du dehors échappé avant d'être posté, aucune mention permise sauf le rôle configuré (SEC6, `glorfindel/chat_text.py`) |
| T | La PR d'un fork, son run rouge ou l'issue d'un inconnu déplace le fil d'un lot (l'étiquette, l'archive) | `#ci` seulement : la tête d'un run doit venir du dépôt, l'auteur d'une issue y tenir un rôle (SEC6, `scripts/notify_discord.py`) |
| T | Les notes d'une release publiée font effacer ou réécrire d'autres messages de `#agents` | `notify.yml` n'en lit que deux ids, en chiffres, dans le commentaire posé par `make release-draft`, et lit chaque message avant d'y toucher : le ping n'est effacé que si son titre est celui de ce brouillon, le tableau réécrit que si c'est le tableau, et seule la ligne de ce brouillon en sort ; le webhook n'est donné qu'aux événements `release`, que seul un membre du dépôt déclenche en publiant (REL1, `scripts/notify_discord.py`) |
| T | Les notes ou le nom d'une release, ou une PR de fork nommée `chore/release-X.Y.Z`, déguisent un lien ou une mention dans `#releases` | Notes, nom et titre passés par `glorfindel/chat_text.py`, `allowed_mentions` vide, un bouton seulement vers un lien `https://` ; la PR de version doit venir du dépôt, celle d'un fork reste dans `#ci` ; le webhook n'est donné qu'aux événements `release` et à la PR de version du dépôt (`pull_request_target` dont la tête est ce dépôt-ci et sa branche `chore/release-…`, dans `notify.yml`), puis revérifié par le script ; jamais à la PR d'un fork ni à un run (REL2, `scripts/notify_discord.py`) |
| R | Un clic sans trace | Le bot journalise chaque refus ; verdicts et acquittements dans `escalations.jsonl` |
| I | Un jeton fuit | Le jeton du bot de Glorfindel seulement dans son conteneur (la watch et la console savent qu'il existe, pas sa valeur) ; celui de l'atelier jamais sur H0 ni dans un conteneur (testé) ; une URL de webhook est un secret, jamais imprimée |
| D | Discord tombe | Une escalade est d'abord écrite localement et visible dans la console ; la watch dit au démarrage quand rien n'alerte |
| E | Un bouton exécute plus que prévu | Il lance la CLI de Glorfindel avec des arguments qu'il a lui-même fixés, en liste (sans shell) ; une carte ancrée (contrôle d'Azure, identité) n'a aucun bouton d'action |
| E | Un bouton d'une carte déjà réglée, ou réarmé par un redémarrage, relance une action | Seules les cartes en attente ou encore à juger retrouvent leurs boutons ; au clic, la carte est relue : acquittée, jugée, expirée ou sa VM sortie de la découverte, le bouton répond « carte réglée » et rien ne part (SEC7) ; un restore à la fois par VM, sa réclamation tenue tant que son processus vit (SEC4c, SEC7) |

**Où c'est dans le code** : `glorfindel/bot.py` (`ButtonPolicy`, `allowed_mentions`), `glorfindel/chat_text.py`, `glorfindel/escalations.py` (le webhook), `scripts/notify_discord.py` ; tests `tests/unit/test_bot.py`, `tests/unit/test_chat_escaping.py`, `tests/unit/test_notify_discord.py`.

**Ouvert** : rien de connu au-delà du choix du salon, qui revient à l'opérateur.

---

## 4. Le fournisseur du modèle

**De confiance, pour la confidentialité** : le fournisseur que l'opérateur choisit (Anthropic par défaut, `GLORFINDEL_LLM_MODEL`) reçoit des données du client. **De confiance pour la décision : personne.** La réponse est une proposition ; des gardes déterministes décident de ce qui peut s'exécuter.

**Ce qui part** :
- à chaque décision : les lignes de la détection (extraits de journaux, nom et identifiant de la VM, adresses, noms d'utilisateurs et de processus tels que les journaux les portent), les résultats des requêtes d'investigation, le contexte de l'incident, quelques décisions passées semblables tirées de la mémoire locale, l'état d'isolation de la VM ;
- pour proposer une règle (`propose-rules`, la boucle purple) : la technique visée et les colonnes des tables de journaux (`getschema`) ;
- pour le rapport d'une campagne (IA0) : les faits de la campagne et les décisions de Glorfindel, à son propre modèle (`EREGION_ANALYSIS_MODEL`).

**Ce qui ne part jamais** : les détections du plan de contrôle d'Azure et d'Entra ID (AL1, C2) — leur décision est construite par le code, sans appel au modèle, aucun UPN ne sort ; une règle d'une autre source qui lit leurs tables l'est aussi, quoi qu'elle projette : la requête le dit (C2, SEC7) ; la mémoire et son modèle d'embeddings, qui tournent en local.

**Ce qui revient** : un appel d'outil — l'action, ses paramètres, une confiance, une explication, des étapes.

| | Menace | Ce qui la tient |
|---|---|---|
| S | Une ligne de journal écrite par l'attaquant se fait passer pour une consigne (injection) | La réponse ne décide pas seule : mode par actif (`human_only` par défaut), garde destructive, porte de confiance, `never_block`, adresses protégées ; les règles ancrées ne lisent que les lignes du démon qui les écrit (SEC2) |
| T | Une réponse malformée, une confiance hors bornes | Confiance bornée à [0, 1], `NaN` retenu par la porte ; une action inconnue part en escalade (G2) |
| R | Une décision qu'on ne peut plus expliquer | Chaque cycle écrit : signal, raisonnement, action, résultat (`*_debug.jsonl`, la mémoire) |
| I | Les journaux du client partent chez un tiers | Un modèle local (`ollama/…`, `GLORFINDEL_LLM_BASE_URL`, `--model`) ou un fournisseur sous le contrat du client ; ce qui part est dit dans le [README](../../README.md#evaluate-on-your-infrastructure--read-only-on-azure) |
| D | Le fournisseur se tait ou traîne | Appels bornés (`GLORFINDEL_LLM_TIMEOUT_S`, `EREGION_ANALYSIS_TIMEOUT_S`) ; un échec finit en `cycle_failed` et en carte, jamais en action (G2) |
| E | Le modèle propose une action destructive ou inconnue | Les actions autonomes sont une liste fermée et réversible (isoler, lever, snapshot, bloquer) ; le reste exige un humain, quelle que soit la confiance |

**Où c'est dans le code** : `glorfindel/agent.py` (`decide` et ses gardes, `_build_user_message`), `glorfindel/response/` (la liste des actions autonomes), `glorfindel/rules/azure/detection_rules.yaml` ; tests `tests/unit/test_agent_nodes.py`, `tests/unit/test_forged_logs.py`, `tests/unit/test_dependency_failures.py`. Détail : [`docs/glorfindel.md`](../glorfindel.md), [`docs/architecture.md`](../architecture.md), « Les gardes qui encadrent le LLM ».

**Ouvert** : la décision face à une réponse, une mémoire ou une ligne imprévues — planifié : #275.

---

## 5. Les hôtes : H0, Orodruin, le banc

**H0** (le Glorfindel hébergé) — la watch qui répond, sur le banc seulement : identité managée `Reader` et « Eregion Glorfindel Response » sur le groupe du banc, `Log Analytics Reader` sur son workspace, rien d'autre ; `GLORFINDEL_READ_ONLY=0` ; gondolin et bree en `non_disruptive`, toute autre VM en `human_only` (décision de Jonathan, 31/10 ; bree le 01/11 — l'encadré ci-dessous). Entrée fermée, sauf pour l'opérateur ; la console n'écoute que sur la boucle locale de la VM. Aucun secret dans Terraform : les jetons dans `host.env`, copié à la main. Son CD ne fait que sortir ([`infra/glorfindel-host/README.md`](../../infra/glorfindel-host/README.md)).

**Orodruin** (l'hôte des injecteurs) — un injecteur n'agit que depuis un Orodruin armé, dont le contrat est vérifié au démarrage ; ailleurs il reste passif. Chaque appel au cloud est journalisé avant d'être fait, sous un plafond ; un arrêt d'urgence en une commande ; sa sortie se referme après l'installation ; un état Terraform à part ([`docs/design/orodruin-contract.md`](orodruin-contract.md)). Et jamais sans Glorfindel : sans battement vivant de la watch, un injecteur refuse avant tout appel au cloud (V1).

**Le banc** (Celebrimbor) — jetable, inscrit par zone (`bench`, `twin`, `production`) ; la règle de production refuse toute panne et toute technique destructive hors du banc ou du jumeau (O0, `eregion_core/inscription.py`).

| | Menace | Ce qui la tient |
|---|---|---|
| S | Un injecteur joué depuis un poste quelconque, sur une cible non inscrite | Contrat d'Orodruin armé/passif ; inscription et zone de chaque cible ; tout inconnu refusé (O0, O1) |
| T | Une attaque ou une panne sur une charge réelle | Règle de production codée (O0) ; un apply du banc montre son plan et demande confirmation, sauf `YES=1` (SEC6) |
| R | Un appel au cloud sans trace | Orodruin l'écrit avant de le faire (O1), sur son disque puis dans le canal, hors de l'hôte (SEC5) |
| E | L'identité d'Orodruin agit sur une VM du banc qui n'est pas inscrite | Elle ne lit que le groupe ; elle n'écrit que sur chaque VM inscrite et chaque expérience, et le contrat refuse une écriture sur le groupe entier (SEC5, #182) |
| S | Un battement de watch qui ne parle pas des cibles, une fenêtre d'exercice antidatée | Le battement porte le périmètre de la watch, comparé à celui de l'injecteur et relu avant chaque action ; une fenêtre est bornée par la création de son blob, et ne marque une VM de production que pour une technique non destructive (SEC5) |
| T | Une URL de canal mal réglée, un blob démesuré | Le jeton ne part que vers un point de terminaison Azure Storage ; un tirage lit en flux borné (taille, nombre), et dit ce qui dépasse (SEC5) |
| I | Un secret de l'hôte fuit | Identités managées plutôt que des secrets ; `host.env` hors du dépôt ; le jeton du bot de l'atelier jamais sur H0 |
| E | Une identité de Glorfindel qui peut tout sur l'abonnement | Un principal par service (watch, console, bot), chacun avec ce que son code appelle, sur les groupes inscrits : la réponse à la watch, le restore à la console et au bot seulement (deux rôles personnalisés, `infra/identities/`) ; jamais `Contributor` sur un abonnement, ni dans la doc, ni dans un script, ni dans ce que l'audit conseille ; le conteneur rouge ne prend jamais le principal partagé ; un principal de la watch qui tient le restore est dit (SEC7, testé). **Pas sur H0** : ses trois conteneurs partagent l'identité managée de la VM, qui tient la réponse sur le groupe du banc (l'encadré ci-dessous) |
| S | Un autre hôte répond à l'adresse de H0 | Sa clé d'hôte épinglée par son empreinte, relevée sur la VM, dans l'environnement de l'opérateur : une autre clé refuse avant toute commande ; sans l'empreinte, la première clé acceptée, et c'est dit (SEC7) |
| E | Un processus qui prend un conteneur (une dépendance, une ligne forgée) | Aucune capacité, aucun gain de privilège, la racine en lecture seule : il n'écrit sur l'hôte que dans ses montages (SEC7, testé). **Sur H0**, il tient aussi le jeton de l'identité managée, donc le rôle de la réponse sur le groupe du banc : l'encadré ci-dessous dit ce que ça ouvre |
| T | Un plan d'Orodruin, sur un poste sans l'état de H0, retire à la watch hébergée l'accès au canal | Refusé, sauf `NO_WATCH=1` dit (SEC7) |
| D | Un injecteur qui s'emballe | Plafond, arrêt d'urgence, fenêtres bornées (O1, B2) |
| S | Une demande de Dagorlad forgée sur l'hôte de la console fait agir Orodruin | Orodruin ne tire rien : l'opérateur porte la demande par SSH, après l'avoir vue et confirmée. Elle est relue par son seul lecteur (un champ de plus la refuse). Le contrat doit être armé. Chaque fil est jugé avec les codes de la console, sur ce qu'Orodruin lit maintenant ; un fil refusé, rien ne part. Le nom tapé d'un fil destructif est comparé au nom qu'Orodruin lit, puis à celui qu'Annatar lit (DG-b) |
| D | Une demande qui s'emballe | Les fils tournent l'un après l'autre. Le plafond d'Orodruin porte sur la demande entière : ses appels journalisés, chaque ligne nommant la demande, et son temps. « Stop all » est l'arrêt d'urgence (DG-b) |
| T | Un exercice défait ce que Glorfindel a fait, ou frappe une VM encore en panne | Une VM tenue par Glorfindel (ses règles d'isolation ou de quarantaine sur le NSG de chaque carte et de chaque sous-réseau de la VM ; illisible vaut tenue, `eregion_core/held.py`, la même règle au preflight d'Annatar) est attendue, puis son fil est sauté : jamais levée. Pour lire cartes et sous-réseaux, le rôle de lecture d'Orodruin gagne deux lectures sur le banc, rien en écriture. Une VM dont la panne n'a pas vérifié son retour ne prend plus de fil (DG-b) |
| I | Ce qu'Orodruin publie pour la console | Le verdict (`armed` ou `passive`, les codes, l'heure) et le statut des demandes, sans identifiant, sans expérience ni cible ; même conteneur, même attribution. H0 relit chaque blob contre sa forme avant de l'écrire (DG-b) |
| E | Le Glorfindel hébergé est poussé à écrire | Il n'écrit que sur le groupe du banc, avec le rôle de la réponse : jamais un restore, une suppression, une identité, un rôle. Seule une VM que l'opérateur a passée en `non_disruptive` après son contrôle de préparation (gondolin, bree) reçoit une action seule, réversible, derrière le seuil de confiance et les gardes ; toute autre reste en `human_only`. Le push garde le mode de chaque VM en place sur H0, jamais un plus hardi : le défaut et toute VM inconnue de H0 en `human_only` ; une config de H0 illisible ou que la watch refuserait (un mode inconnu suffit) : toutes les VM en `human_only` ; et c'est dit ; `HUMAN_ONLY=1` remet tout en `human_only` d'un geste (BL1c, 02/11). **La posture de H0 sur le banc** (décision de Jonathan, 31/10) : l'encadré ci-dessous |
| E | L'identité de réponse de H0, partagée par la watch, la console et le bot, lance une commande sur une VM du banc par Run Command (le droit de la coupure des sessions d'une isolation) | **Elle est surveillée** (SID1, #409) : chaque Run Command sous l'identité de Glorfindel qui n'est pas la coupure d'une isolation qu'il a enregistrée sur cette VM (l'heure de la coupure dans l'état, une fenêtre de quelques minutes, une coupure pour une opération) est une carte critique, décidée par le code, sans action sur la VM ; un état illisible est une carte (A0). Ce qu'elle voit : le journal d'activité de l'abonnement (`AzureActivity`), une fois envoyé au workspace (ID1). Son délai : l'ingestion de ce journal, plusieurs minutes, parfois plus de dix — elle dit après coup, elle n'empêche pas. Le rattachement lit l'état local de l'hôte, et tout conteneur qui l'écrit (watch, console, bot) peut y écrire une coupure : elle prend un usage maladroit de l'identité, pas celui d'un attaquant qui connaît Eregion ([`docs/glorfindel.md`](../glorfindel.md), « Notre propre identité surveillée ») |

**La posture de H0 sur le banc (décision de Jonathan, 31/10 ; bree le 01/11).**

Le 30/10, l'exception de BL1 ne valait que le temps de la session de banc
([`docs/banc-bl1.md`](../banc-bl1.md)). Le 31/10, Jonathan l'a gardée : c'est la posture de H0 sur
le banc. H0 répond, il ne fait plus seulement qu'observer.

Depuis le 02/11 (décision de Jonathan, #409), H0 garde ce rôle sur le banc, `runCommand` compris :
un NSG ne coupe pas une connexion établie, retirer le droit affaiblirait l'isolation. Sa mitigation est
la surveillance de sa propre identité (SID1, ligne « E » ci-dessus). Elle dit après coup, sur un
rattachement que l'hôte écrit lui-même : elle ne suffit pas hors du banc. La file d'actions signée — seule
la watch tient le rôle d'écriture, la console et le bot y déposent une demande signée — est un
prérequis avant toute VM hors du banc (« Ouvert »).

- **Ce qui est posé** :
  - l'identité managée de H0 tient « Eregion Glorfindel Response » sur `rg-celebrimbor`, le groupe
    du banc, attribué à la main (`az role assignment create`, [`docs/banc-bl1.md`](../banc-bl1.md),
    étape 3), hors de l'état Terraform de H0 ;
  - `GLORFINDEL_READ_ONLY=0` dans `host.env` ;
  - gondolin et bree en `non_disruptive`, chacune après son contrôle de préparation ; le défaut reste
    `human_only` ;
  - le CD actif : une release publiée redéploie H0 sans toucher `host.env` ni la config, donc sans
    toucher la posture.
- **Ce que ça ouvre** — l'identité est celle de la VM, partagée par la watch, la console et le bot
  (une identité par conteneur ne s'y sépare pas) :
  - **la watch agit seule** sur gondolin et sur bree, dans leur mode : isoler, bloquer, instantané,
    lever. bree n'est pas inscrite : jamais un exercice, jamais une technique ni une panne. Mais une
    vraie détection sur elle peut l'isoler sans humain ;
  - **un clic d'approbation dans la console, ou un bouton du bot** (Revert), écrit sur le banc,
    bree comprise, quel que soit le mode de la VM. C'est un humain qui agit, derrière le jeton de la
    console (et le tunnel SSH) ou la liste d'autorisation de Discord (`DISCORD_ALLOWED_*`) ;
  - **un conteneur de H0 compromis, ou une clé SSH de H0, tient ce rôle** hors du code de
    Glorfindel : le jeton de l'identité managée se lit de chacun des trois conteneurs. Le rôle
    de la réponse donne `runCommand` (la coupure des sessions, `ss -K`) : une commande en root
    sur toute VM du banc, bree et gondolin comprises ; et l'écriture de leurs NSG et de leurs
    cartes réseau. Dans le code, la commande est écrite d'avance ; avec le jeton, elle est
    libre ;
  - le restore n'est pas dans le rôle : un Restore lancé de la console ou du bot échoue sur Azure.
- **Ce qui le borne** :
  - **le rôle** : les écritures de la réponse et rien d'autre
    (`infra/identities/glorfindel-response.json`, « Identités Azure ») ; jamais un restore, une
    suppression, une identité, un rôle ;
  - **le groupe** : `rg-celebrimbor` seul. Rien sur l'abonnement, rien sur le groupe de H0 : H0 ne
    peut ni s'isoler, ni toucher une autre charge ;
  - **les modes** : en `non_disruptive`, seules les actions réversibles partent seules, au-dessus
    du seuil de confiance (0,7), après des tirages qui s'accordent (D-1) et derrière les gardes
    déterministes de `decide` ; le destructif reste à un humain. Toute autre VM est en `human_only` ;
  - **le push** (décision de Jonathan, 02/11 ; SEC7 forçait `human_only` partout à chaque push) :
    `make glorfindel-host-push` garde le mode de chaque VM tel qu'il est sur H0, jamais un plus
    hardi. Le défaut reste `human_only` et la liste destructive vide, quoi que dise la config
    locale. Une config de H0 illisible, ou que la watch refuserait (une seule entrée suffit :
    un mode inconnu, un `match` vide, une clé de plus), met toutes les VM en `human_only` ; une
    VM inconnue de H0 ou un motif partent en `human_only` ; et c'est dit, VM par VM
    (`infra/glorfindel-host/host_config.py`) ; la config de H0, relue juste avant l'envoi, a
    changé entre-temps : rien n'est envoyé.
    Pourquoi : la posture se perdait à chaque push, et se redonnait à la main dans la console.
    **`make glorfindel-host-push HUMAN_ONLY=1`** est le geste d'urgence, qui remet tout en
    `human_only` ;
  - les écritures autonomes hors cycle (le retrait d'une règle orpheline) restent gardées par le
    mode de la VM qu'elles touchent (`glorfindel/orphans.py`, `_ALONE`) ;
  - la règle de production ne change pas : elle porte sur les injecteurs, et bree, non inscrite,
    n'est jamais une cible d'exercice ;
  - le banc est jetable : aucune charge ni donnée d'un client (bree porte une charge d'essai),
    rien qu'on ne recrée ;
  - **ce qui borne un conteneur ou une clé compromis** : le groupe du banc seul (jamais
    l'abonnement, jamais le groupe de H0) ; l'entrée de H0 fermée (SSH depuis l'IP de
    l'opérateur seulement, sa clé d'hôte épinglée ; la console derrière le tunnel et son jeton) ;
    des conteneurs sans capacité, sans gain de privilège, la racine en lecture seule.
- **Revenir à un H0 qui ne fait rien seul**, d'un geste : `make glorfindel-host-push HUMAN_ONLY=1`.
- **Revenir en lecture seule**, si besoin : l'étape 7 de [`docs/banc-bl1.md`](../banc-bl1.md). Le
  rôle retiré, `az role assignment list --assignee <principal> --all` ne montre plus que `Reader` et
  `Log Analytics Reader` ; `GLORFINDEL_READ_ONLY=1` repoussé, le bandeau « lecture seule » de la
  console revient.

**Où c'est** (SEC7) : `infra/identities/` et [`docs/operations.md`](../operations.md), « Identités Azure » ; `docker-compose.yml` ; `infra/glorfindel-host/known_host.sh` ; tests `tests/unit/test_azure_roles.py`, `tests/unit/test_profiles.py`, `tests/unit/test_host_ssh.py`, `tests/unit/test_makefile_bench.py`. La demande de Dagorlad (DG-b) : `eregion_core/exercise_runner.py`, `make orodruin-exercise`, [`orodruin-contract.md`](orodruin-contract.md), « La demande de Dagorlad » ; tests `tests/unit/test_exercise_runner.py`, `tests/unit/test_makefile_exercise.py`, `tests/unit/test_exercise_e2e.py`, `tests/unit/test_orodruin_word.py`.

**Ouvert** : un battement de la watch authentifié, pas seulement lié — planifié ; un journal hors de l'hôte que son identité ne peut pas effacer — planifié ; le canal sans point de terminaison public — planifié  ; l'action approuvée confiée à la watch seule, par une file signée — planifié : #413 ; une identité managée par conteneur sur un même hôte — planifié ; l'identité unique de H0, partagée par la watch, la console et le bot — planifié.

---

## 6. La CI et le CD (GitHub, release, tags)

**De confiance** : le mainteneur (seul à publier une release, et seul à créer un tag `v*` une fois la règle des tags posée, SEC12), la branche `main` protégée (une PR et les vérifications requises). `CODEOWNERS` n'est qu'indicatif (P-07) : aucune revue d'un propriétaire n'est exigée, avec un seul mainteneur et des fusions autonomes ; ce qui tient la revue est à la frontière 7. **Pas de confiance** : les forks, leurs PR, les auteurs d'issues extérieurs, une action tierce sous un tag qui peut bouger.

**Ce qui la traverse** : le code des PR ; les événements `pull_request_target` et `workflow_run`, qui tournent avec les droits de la branche par défaut ; les secrets (Discord de l'atelier ; les identifiants, non secrets en eux-mêmes, du principal du canari) ; les jetons OIDC de courte durée (la publication, le canari) ; les releases, que H0 tire et déploie.

| | Menace | Ce qui la tient |
|---|---|---|
| S | Une PR de fork se fait passer pour un lot | Annoncée dans `#ci`, jamais dans un fil ; son run rouge aussi (SEC6) |
| T | Une action tierce déplacée sous son tag, dans un job qui tient un secret | Tout workflow qui tient un secret, ou tourne sur un événement qu'un fork déclenche, épingle ses actions par commit ; le canari installe Terraform depuis le dépôt signé de HashiCorp, sa clé vérifiée par son empreinte, sans action tierce (SEC6, `tests/unit/test_workflows.py`) |
| T | Une valeur choisie (entrée d'un `workflow_dispatch`, titre d'une PR) exécutée comme du shell | Aucun `run:` ne prend `inputs.*`, `github.event.*` ni `github.head_ref` dans son texte : ces valeurs passent par `env:` (SEC6, testé) |
| T | Une dépendance changée sous son numéro, ou prise sous un autre nom | Dépendances verrouillées, chaque fichier vérifié par son empreinte (M-3, `requirements/`) ; Eregion s'installe depuis le dépôt (README). Les providers de Terraform de chaque module sont verrouillés dans le dépôt (`.terraform.lock.hcl`, empreintes linux et darwin) : `init` ne les monte jamais seul, une montée passe par `make providers-lock` et une PR ; la CI les tire en lecture seule du verrou (`-lockfile=readonly` : une empreinte fausse ou un provider absent font échouer le job), avec un Terraform à version épinglée installé depuis le dépôt de HashiCorp, sa clé vérifiée par son empreinte (CI4, `tests/unit/test_workflows.py`). Le SDK d'AWS (boto3, botocore, s3transfer, jmespath) est installé par litellm 1.100.4 dans les deux images, jamais importé par le code d'Eregion hors d'un adaptateur (MC0, `tests/unit/test_provider_boundary.py`, DEP1) ; litellm ne s'en sert que pour des modèles AWS (bedrock, sagemaker), qu'Eregion ne configure pas |
| T | Une dépendance verrouillée qui a un avis de vulnérabilité, et que personne ne voit | Chaque semaine, `pip-audit` lit les quatre verrous tels quels (empreintes, rien de résolu). Il ouvre une issue par avis, label `security`, jamais deux pour le même avis. Seules les issues ouvertes par le workflow sont relues, et leur clé est vérifiée champ par champ : une issue d'un autre auteur ne fait taire aucun avis et ne fait rien écrire au bot ; et aucun autre workflow ne peut écrire une issue (`issues: write` à celui-là seul, SEC7, testé). Le run est rouge dans `#ci` quand il y a du neuf. `make lock` dit les avis du verrou qu'il écrit. Jamais de PR de montée automatique : la montée passe par le harnais (CI2, `scripts/pip_audit_issues.py`) |
| R | Une release sans histoire | `CHANGELOG.md`, une issue par lot ; les sessions préparent une release en brouillon, le mainteneur la publie |
| S | Un secret Azure de longue durée volé ou fuité, rejoué ailleurs (le canari, P-04) | Plus de secret : le job du canari demande un jeton OIDC de quelques minutes (`id-token: write` à ce job seul), qu'Entra ID n'échange que pour un sujet, `repo:Vanyar53/eregion:environment:canary` (l'identifiant fédéré de `eregion-canary`), un environnement que seul `main` déploie — une PR, un fork, une autre branche n'obtiennent rien, ni un autre job de `main` : le jeton de `publish.yml` porte le sujet `ref:refs/heads/main`, que l'identifiant n'accepte pas ; seul le job du canari est dans cet environnement (testé). Ses identifiants sont des secrets de cet environnement, jamais des variables imprimées en clair ; sans eux le canari échoue. Aucune action tierce à côté du jeton : Terraform le lit lui-même, `az` le reçoit de `curl` (P04, `tests/unit/test_workflows.py`) |
| E | Le principal du canari, volé, agit sur l'abonnement | `Network Contributor` sur `rg-eregion-canary` seul : ni le groupe supprimé, ni une VM, ni un rôle ; le canari n'y crée ni n'y supprime de groupe, et n'enregistre aucun fournisseur de ressources (P04, `infra/canary/jit-terraform/`, testé) |
| I | Un secret exposé au code d'une PR | `pull_request_target` et `workflow_run` ne récupèrent ni n'exécutent jamais le code d'une PR (récupération partielle du seul script, sans identifiants persistés) ; chaque workflow déclare ses permissions, `contents: read` à son niveau ; l'écriture au seul job qui en a besoin — la publication (paquets, attestations, OIDC), le canari (OIDC), l'audit des verrous (issues) — et `notify` lit les runs (SEC7, P04, CI3, testé) |
| D | Une CI rouge passée inaperçue | Annoncée dans `#ci`, avec mention : chaque workflow lancé par un push, une PR ou la nuit est dans la liste de `notify.yml`, ses exceptions écrites (CI1, testé) ; le CD de H0 attend une CI verte |
| D | Un Dockerfile ou un verrou cassé vu seulement au préflight de H0 : la release brûlée | Les deux images construites et éprouvées dans la PR et sur `main` (CI1, `images.yml`) : `--version`, les imports du préflight du CD, la config d'exemple sous A3, un appel d'outil par litellm répondu par son mock (DEP1), pas root, rien de Glorfindel dans l'image des injecteurs. Construites sans push, sans registre, sans secret, actions épinglées par commit, le cache écrit par `main` seulement ; chaque vérification est un `docker run --network none` (`scripts/image_check.py`, testé). Sans filtre `paths` : ses checks peuvent être requis ; une décision absente, un HEAD qui n'est pas le commit de fusion ou une file de fusion construisent (SEC7) |
| E | Une release plus ancienne remise en « latest » (par quiconque peut publier), pour ramener H0 sur un code connu pour une faille | Le CD refuse une release plus ancienne que ce qui tourne, par sa version ou par son commit, et le dit avec la mention ; le seul chemin est un retour arrière demandé sur H0, pour ce tag (`rollback`), vérifié comme toute release (SEC12, `tests/unit/test_host_cd.py`) |
| E | Une release piégée déployée sur H0 | Le CD exige un tag sur `origin/main`, jamais réécrit, tous les checks verts, un préflight dans la candidate, et revient en arrière si la santé échoue (H1) — dont une écriture que la racine en lecture seule refuse, absente de la release d'avant (SEC7) |
| T | Un verrou qui change les décisions de Glorfindel sans que personne le voie | Le CD ne déploie un nouveau verrou qu'avec l'attestation du harnais, deux passages pour le modèle de H0 : le candidat sur ce verrou, la référence sur le verrou en service (H3, `requirements/harness.json`). Il refuse une intégration cassée, une régression (juste à chaque tirage avant, faux à chaque tirage après), une surconfiance que la référence n'a pas (un cas à chaque tirage, ou deux cas), une injection ou une mémoire qui détourne une décision sur le candidat seulement, et une attestation de l'ancien format, incomplète ou sur un autre verrou. Ce qui varie est dit en orange dans `#deploy`, jamais un refus. Elle refuse aussi un cas, de tout genre, qui perd 2 tirages sur 3 face à la référence (p ≈ 1/6 mesuré : environ 4 % de refus à tort par cas bruité, jusqu'à 9 % si p ≈ 1/3 ; de 4 à 20 % par attestation selon le bruit, accepté), un cas qui gagne 2 tirages surconfiants, et 3 tirages perdus ou plus en tout face à la référence, sur tous les cas. **Ce qu'elle laisse** : par cas, un tirage perdu et un tirage surconfiant gagné au plus ; en tout, 2 tirages perdus face à la référence (sur tous les cas) et un cas nouvellement surconfiant au plus — dit en orange (le modèle refuse une température, trois tirages ne le distinguent pas du bruit) ; un recul dû au code d'une release qui change aussi le verrou : les deux passages font tourner le même code, le nouveau, le recul paraît « faux des deux côtés », dit, jamais refusé (l'orange compte ces cas quand `glorfindel/` ou `eregion_core/` change) ; l'attestation est écrite par le mainteneur, pas recalculée par le CD |
| T | Une image déployée qui n'est pas celle que la CI a éprouvée, ou d'un autre commit (P-02) | H0 et Orodruin ne construisent plus : l'image de chaque commit de `main` est éprouvée **avant** d'être poussée sur GHCR, avec une provenance SLSA et un SBOM attestés et une signature sans clé (sigstore, l'OIDC de GitHub) ; H0 la tire **par son digest** après avoir vérifié, par cosign épinglé, la signature et la provenance du workflow de publication de ce dépôt, sur `main`, déclenché par un push, **au commit du tag**, puis relu la provenance et les étiquettes ; Orodruin reçoit l'image ainsi vérifiée sur le poste, et son identifiant y est relu contre le digest (CI3, `scripts/published_image.py`, testé) |
| T | Un tag d'image déplacé, un registre qui ment (V-22) | Le tag `sha-<commit>` n'est qu'une indication : le digest est le sha256 des octets lus, l'en-tête du registre doit dire le même, la signature lie ce digest au commit ; un digest différent de celui vu la première fois pour une release est refusé, comme un tag de git réécrit (CI3, testé) |
| E | Un autre workflow, une PR ou un fork publient une image que H0 accepterait | Seul `publish.yml` peut écrire un paquet ou une attestation, au niveau de son job, sur un push sur `main` de ce dépôt seulement ; un jeton OIDC, lui et le job du canari seuls (P04), dont l'identité de workflow n'est pas celle que le CD exige ; le CD exige ce workflow, cette branche, cet événement dans le certificat (CI3, `tests/unit/test_workflows.py`) |

**Où c'est** : `.github/workflows/`, `.github/CODEOWNERS`, `scripts/notify_discord.py`, `scripts/pip_audit_issues.py`, `scripts/image_check.py`, `scripts/published_image.py`, `infra/glorfindel-host/` (le CD), `infra/canary/` (le canari) ; tests `tests/unit/test_workflows.py`, `tests/unit/test_notify_discord.py`, `tests/unit/test_host_cd.py`, `tests/unit/test_dependency_lock.py`, `tests/unit/test_pip_audit_issues.py`, `tests/unit/test_image_check.py`, `tests/unit/test_published_image.py`.

**Ouvert** :
- les gestes de Jonathan qui ferment P-04, le canari sans secret — planifié ;
- les ressources qu'un runner tué du canari laisse dans son groupe — planifié ;
- quelques actions sans secret encore nommées par leur tag — planifié ;
- les versions propres à Python 3.11, hors de l'audit des verrous — planifié : #298 ;
- la publication du paquet — planifié ;
- le SBOM des images, attesté mais pas lu par le CD — planifié ;
- l'image d'Orodruin, vérifiée seulement sur le poste qui l'envoie — planifié ;
- le déploiement de H0 à la main, qui construit encore sur la VM — planifié.

---

## 7. Les sessions d'agents → `main` → le CD

_SEC12 (#418), 02/11. Décision de Jonathan : une identité propre aux sessions (une GitHub App sur ce seul dépôt), des fusions autonomes, les tags `v*` réservés au mainteneur._

**De confiance** : le mainteneur, pour ce qui déploie (publier une release, créer un tag `v*`, les réglages du dépôt, un retour arrière de H0) ; les sessions d'agents, pour le code qu'elles fusionnent, après une CI verte et une relecture Opus 5.5 « ok ». **Pas de confiance** : un commentaire sur une PR publique, une session hors de son lot, la sortie d'un modèle dans un rapport de relecture.

**Ce qui la traverse** : les branches et les PR des sessions, leurs fusions sur `main` (la racine de confiance du CD : ce qui est fusionné est publié comme image signée, CI3), les verdicts de relecture, les releases en brouillon ; puis la release que le mainteneur publie, que H0 tire.

| | Menace | Ce qui la tient |
|---|---|---|
| S | Une session agit sous le compte du mainteneur (ses droits d'administrateur, ses dérogations) | Les sessions ont leur identité : une GitHub App installée sur ce seul dépôt, son jeton d'une heure limité à ce dépôt (`scripts/agent_token.py`) ; l'emballage `gh` ne lit jamais la config du mainteneur et n'appelle rien sans jeton ; l'assistant de `git` ne répond que pour ce dépôt, en https (SEC12, `tests/unit/test_agent_token.py`) |
| E | Une session publie une release, ou crée, déplace ou supprime un tag `v*` | La règle du dépôt sur `v*` (création, mise à jour, suppression) n'a que l'administrateur pour dérogation ; publier une release crée son tag : l'App ne le peut pas, une release en brouillon ne crée pas de tag (SEC12, `docs/sessions.md`, « Les règles du dépôt ») ; le CD lit cette règle sans jeton et la dit au début de chaque déploiement, en orange si elle manque |
| T | Une session pousse sur `main`, réécrit son histoire ou la supprime | La règle de `main` : une PR obligatoire, ni force-push ni suppression, les checks requis ; la dérogation de l'administrateur en mode « pull requests only » |
| R | Une fusion sans relecture, ou sur un commit que la relecture n'a pas lu | Le commit relu noté au lancement du relecteur, redit par son rapport, jamais la tête lue au moment de publier ; le verdict publié en commentaire de la PR avant la fusion, pour ce commit ; `check` refuse quand la tête de la PR n'est pas lui ; la fusion liée à lui (`--match-head-commit`) ; seuls les auteurs nommés sont lus, un rapport ne porte jamais de clé (SEC12, `scripts/review_verdict.py`, `tests/unit/test_review_verdict.py`). Le verdict est **tracé, pas authentifié** : il prouve qui l'a publié (l'App), pas qu'une relecture l'a rendu |
| E | Une session change ce qui tourne avec les secrets et les jetons OIDC (les workflows) | L'App n'a pas le droit *Workflows* (décision de Jonathan, 02/11, `docs/sessions.md`) : un changement de `.github/workflows/` est poussé et fusionné par le mainteneur |
| E | Une release plus ancienne remise en « latest », pour ramener H0 en arrière | Le CD la refuse et le dit ; seul un retour arrière demandé sur H0, pour ce tag, la déploie (SEC12, frontière 6) |
| I | La clé de l'App ou son jeton fuient | Le jeton vit une heure, limité à ce dépôt et aux droits de l'App, en cache 0600 ; la clé est refusée lisible par d'autres ; aucune erreur ne dit la clé ni le jeton ; un jeton qui pourrait écrire une ligne de plus dans le protocole de `git` est refusé (SEC12, testé) |
| D | Les sessions privées de GitHub : l'App suspendue, sa clé révoquée, GitHub injoignable | Rien ne bascule sur le compte du mainteneur : pas de jeton, pas d'appel, l'erreur dite ; le CD de H0 ne dépend pas de l'App (il lit l'API publique sans jeton) |

**Où c'est** : `scripts/agent_token.py`, `scripts/agent-bin/`, `scripts/review_verdict.py`, `.claude/skills/elrond/SKILL.md`, `docs/sessions.md` (« L'identité des sessions », « Les règles du dépôt »), `infra/glorfindel-host/cd/eregion_cd.py` ; tests `tests/unit/test_agent_token.py`, `tests/unit/test_review_verdict.py`, `tests/unit/test_host_cd.py`.

**Ce qui reste, assumé** : la clé de l'App est lisible par toute session (un même utilisateur Unix) ; elle ne donne que les droits de l'App, révocables d'un clic. La règle des tags est lue par H0 sans jeton : tant que cette lecture n'est pas mesurée, son absence est dite, jamais refusée. L'attestation du harnais est un fichier qu'une fusion peut porter : le CD la lie au sha256 du verrou, pas à son auteur (R-13) ; la proposition est de la signer, sans clé, de l'identité du mainteneur, et de la vérifier au CD.

**Ouvert** :
- les gestes de Jonathan qui ferment cette frontière — planifié : #418
- les identifiants du mainteneur sur le poste des sessions — planifié : #418
- un utilisateur Unix propre aux sessions — planifié
- la règle des tags lue par H0 sans jeton, à mesurer — planifié : #418
- l'attestation du harnais, liée au verrou et non à son auteur — planifié
- la fusion d'une PR de workflow par l'App, à mesurer — planifié

---

## Décisions assumées

- **La revue de conception sans responsable désigné** (T-05). Ce qui la tient : la relecture Opus 5.5 de chaque lot, son verdict publié sur la PR pour le commit relu avant la fusion (SEC12), et le mainteneur, seul à publier une release et à créer un tag `v*`. `CODEOWNERS` (SEC6) ne fait que nommer les chemins sensibles : il n'exige rien (P-07).
- **`runCommand` dans le rôle de la réponse** (V-17, SEC7). C'est son droit le plus fort : une commande en root sur la VM, que l'identité de la watch peut lancer. Il y est pour une seule chose, couper les sessions déjà ouvertes quand la VM est isolée (`ss -K`, Linux) — sans lui, un attaquant connecté garde la main sur une VM « isolée » ; le restore s'en sert aussi, pour neutraliser la dernière commande avant l'échange de disques. Ce qui le borne : la commande est écrite dans le code, jamais par le modèle ; elle ne vise qu'une VM que la décision isole, sur les groupes inscrits ; et la préparation dit « sessions non coupées » quand il manque (`no_drain`), plutôt que d'élargir le rôle. **Sur H0** (sa posture sur le banc, BL1c), ce droit est tenu par l'identité de la VM, que la console, le bot et tout conteneur compromis partagent : la commande n'y est plus bornée par le code, seulement par le groupe du banc, l'entrée fermée de H0 et un banc sans charge ni donnée d'un client — bree porte une charge d'essai (§5).
- **Le banc ouvert à Internet, par conception** (V-37) : c'est une cible d'exercice. Ce qui le borne : il est jetable, inscrit `bench`, et ne porte aucune charge réelle.
- **Qui fusionne sur `main` publie une image que H0 accepte** (CI3, P-02). La signature prouve le workflow, la branche et le commit, pas la relecture du code. Ce qui le borne : la protection de `main` (une PR, les checks requis, ni force-push ni suppression), le verdict de relecture publié sur la PR (SEC12), le mainteneur seul à publier la release qui déploie et seul à créer son tag (SEC12), et sigstore et l'OIDC de GitHub, tenus pour de confiance. Le chemin de secours, un déploiement de H0 à la main (`make glorfindel-host-start`), construit encore l'image sur la VM, hors de la vérification ; `make orodruin-push-dev` aussi, sur le poste, dit comme tel.

- **`human_only` par défaut.** Rien ne s'exécute sans humain tant que l'opérateur n'a pas donné l'autonomie, actif par actif ; l'autonomie se décide sur une mesure (`docs/observation.md`), jamais sur la confiance du modèle.
- **Deux hôtes Glorfindel, deux états : le tag de quarantaine l'emporte sur l'« aucun » de l'état** (I8S, #245, N-08). Quand l'état local dit qu'une carte réseau n'avait pas de NSG et que notre tag en nomme un, le tag fait foi, à la levée comme au `reset --from-azure`. Conséquence acceptée : dans un cas marginal (deux groupes de quarantaine, un tag périmé dans l'un), une carte peut recevoir à la levée un NSG de plus qu'elle n'en avait — jamais un de moins. L'autre option, un tag manquant ou illisible toujours tenu pour inconnu, garderait en quarantaine toute carte nue par conception dont les tags sont perdus. Détail : [`docs/azure.md`](../azure.md).
- **Les sudo attendus des administrateurs n'ouvrent pas de carte** (ADM1, #284). Un compte nommé dans
  `expected_sudo` pour une VM n'est plus une alerte quand il passe root par sudo : si ce compte est volé,
  ses sudo ordinaires passent sans carte (comptés, journalisés, `glorfindel report`). Ce qui le borne :
  l'écart se fait dans le code, avant la décision, jamais par le modèle ; une ligne ambiguë (coupée,
  deux `COMMAND=`, un saut de ligne, un `USER=` autre que root) reste une carte ; les commandes sensibles
  restent des cartes ; **les shells root d'un administrateur** (`sudo -i`, `sudo su -`, `bash`,
  `python -c`, `find -exec`, `vim`, `less`, `screen`, `gdb`, `docker exec … bash`…) **font une carte
  pour les formes connues** — sous sudo, ce qui s'y fait n'est jamais écrit. **La liste n'est pas
  exhaustive** : un script ou un programme non listé, lancé par un compte attendu (`sudo /tmp/x.py`),
  passe sans carte. C'est l'angle mort assumé jusqu'à COR1 (la corrélation avec l'origine de la
  session SSH, qui écartera aussi les shells root d'une origine attendue) et AUD1 (`auditd`, ce qui se
  fait réellement sous root).
- **Un jeton pour la console**, tous ses droits (frontière 1).
- **Le principal du canari, `Network Contributor` sur son groupe** (P-04, P04). Il peut y créer une ressource réseau
  payante (une IP publique, une passerelle). Si le premier run demande plus, le repli est `Contributor` sur ce même groupe, écrit
  ici avec l'action qui l'a demandé (`docs/operations.md`). Ce qui le borne : rien d'autre dans ce groupe ; son jeton ne s'obtient que d'un job de l'environnement
  `canary`, que seul `main` déploie (le canari seul, testé) ; le canari, lui, n'y crée ni n'y supprime de groupe. Jusqu'aux gestes
  de Jonathan (`docs/operations.md`, « Le canari azurerm, sans secret »), l'ancien secret reste au dépôt, inutilisé, et le canari est rouge.

## Comment ce document vit

Chaque lot de sécurité met à jour la page de sa frontière : ce qu'il tient passe dans « ce qui la tient », avec son nom ; ce qu'il laisse est écrit « planifié : #n ». Une frontière nouvelle (un fournisseur cloud, un canal) a sa page avant d'être livrée.
