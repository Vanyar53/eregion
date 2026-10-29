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

---

## 1. La console (locale, H0)

**De confiance** : l'opérateur qui tient le jeton, depuis un navigateur sur la boucle locale (sur H0, à travers le tunnel SSH). **Pas de confiance** : les autres sites que ce navigateur ouvre, les autres utilisateurs de la machine, le texte qu'affichent les cartes.

**Ce qui la traverse** : des lectures (cartes, état, indicateurs) ; des actions qui touchent Azure (lever, restaurer, approuver, passer un actif en `non_disruptive`) ; du texte venu du dehors (explications du modèle, noms de VM et d'applications, lignes de journaux).

| | Menace | Ce qui la tient |
|---|---|---|
| S | Un autre site, ou un autre utilisateur local, agit comme l'opérateur | Toujours un jeton, tiré au premier démarrage s'il manque ; un cookie de session dérivé (HMAC), HttpOnly, SameSite=Strict (SEC1) |
| T | Une page tierce (DNS rebinding, CSRF) change l'état | `Host` d'une liste fermée, `Origin` exacte pour toute modification, corps JSON obligatoire (SEC1) |
| R | Une action sans trace | Le fil des actions de l'opérateur, `runs/manual_actions.jsonl` ; chaque carte garde son verdict et sa date |
| I | Le jeton ou des identifiants fuient | Le jeton retiré de l'URL après la première ouverture, jamais sur une ligne de commande ; ni schéma OpenAPI ni `/docs` ; Config masque abonnement, tenant et client (SEC1) |
| D | La console tombe ou est inondée | Elle est un processus à part : la watch détecte et le bot alerte sans elle |
| E | Un texte du dehors s'exécute dans la page | Rien du dehors écrit brut, aucun script ni gestionnaire en ligne, CSP `default-src 'self'` (#254, #257, SEC1) ; un restore depuis la console n'accepte que la carte de restauration de cette VM, jamais une carte ancrée |

**Où c'est dans le code** : `eregion_console/api.py` (middleware du jeton, de l'hôte et de l'origine ; en-têtes), `eregion_console/static/glorfindel.js` (`_post`, `_seg`), `scripts/console_escaping.py` ; tests `tests/unit/test_console.py`, `tests/unit/test_console_escaping.py`. Détail : [`docs/glorfindel.md`](../glorfindel.md), « Console — exposition ».

**Choix assumé** : un jeton, tous les droits de la console — ni comptes ni rôles avant la 1.x.

**Ouvert** : rien de connu à cette frontière au-delà de ce choix.

---

## 2. Le canal `runs/` et l'état local

**De confiance** : Glorfindel, qui seul écrit `~/.glorfindel/` (la watch, la console, le bot et la CLI, sous un même utilisateur). **Moins de confiance** : les injecteurs (Annatar, Gothmog), qui écrivent `runs/` ; tout ce qui s'y trouve est lu comme une donnée à valider.

**Ce qui la traverse** : les signaux des injecteurs (`attack_started`, `detection_missed`), leurs fenêtres d'exercice et leurs rapports ; l'état d'isolation et de blocage ; les escalades ; le battement de la watch, que lisent les injecteurs.

| | Menace | Ce qui la tient |
|---|---|---|
| S | Une ligne de `runs/` se fait passer pour Glorfindel (un `recovery_complete` qui lève une isolation) | La watch ne prend de `runs/` que ce qu'un injecteur émet, chaque champ vérifié ; un `recovery_complete` ne lève seul que s'il vient du chemin propre de Glorfindel (`glorfindel/signal_origin.py`, SEC3) |
| T | Un état illisible ou tronqué est lu comme « pas d'état » et libère une VM | Illisible n'est jamais absent : le balayage ne retire rien et le dit ; état écrit entier, en 0600 (dossiers 0700) ; escalades sous `flock`, réécrites entières (SEC3) |
| R | Une ligne refusée disparaît sans bruit | Elle est journalisée et comptée (`~/.glorfindel/channel_refusals.json`, SEC3) |
| I | Un injecteur lit l'état du bleu (ce qui est isolé, bloqué, escaladé) | Les conteneurs des injecteurs ne montent que `~/.glorfindel/injectors`, en lecture seule, où la watch copie son battement (SEC3) |
| D | Un flot de lignes dans `runs/` | Refusées une à une, sans appel au modèle ni au cloud |
| E | Une fenêtre d'exercice déclarée pour faire passer une vraie attaque pour un exercice | Fenêtre bornée en durée et en avance (`MAX_DURATION_S`, `FUTURE_SKEW_S`), qui doit nommer une VM inscrite ; une fenêtre refusée l'est pour de bon (B2, `eregion_core/exercise.py`) |

**Où c'est dans le code** : `glorfindel/signal_origin.py`, `glorfindel/response/state.py`, `glorfindel/response/locks.py`, `eregion_core/exercise.py` ; tests `tests/unit/test_signal_origin.py`, `tests/unit/test_locks.py`, `tests/unit/test_exercise_guard.py`. Détail : [`docs/glorfindel.md`](../glorfindel.md), « Le canal runs/ » ; [`docs/fichiers-cles.md`](../fichiers-cles.md).

**Ouvert** : d'autres points de l'état local — planifié : #275.

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
| R | Un clic sans trace | Le bot journalise chaque refus ; verdicts et acquittements dans `escalations.jsonl` |
| I | Un jeton fuit | Le jeton du bot de Glorfindel seulement dans son conteneur (la watch et la console savent qu'il existe, pas sa valeur) ; celui de l'atelier jamais sur H0 ni dans un conteneur (testé) ; une URL de webhook est un secret, jamais imprimée |
| D | Discord tombe | Une escalade est d'abord écrite localement et visible dans la console ; la watch dit au démarrage quand rien n'alerte |
| E | Un bouton exécute plus que prévu | Il lance la CLI de Glorfindel avec des arguments qu'il a lui-même fixés, en liste (sans shell) ; une carte ancrée (contrôle d'Azure, identité) n'a aucun bouton d'action |

**Où c'est dans le code** : `glorfindel/bot.py` (`ButtonPolicy`, `allowed_mentions`), `glorfindel/chat_text.py`, `glorfindel/escalations.py` (le webhook), `scripts/notify_discord.py` ; tests `tests/unit/test_bot.py`, `tests/unit/test_chat_escaping.py`, `tests/unit/test_notify_discord.py`.

**Ouvert** : rien de connu au-delà du choix du salon, qui revient à l'opérateur.

---

## 4. Le fournisseur du modèle

**De confiance, pour la confidentialité** : le fournisseur que l'opérateur choisit (Anthropic par défaut, `GLORFINDEL_LLM_MODEL`) reçoit des données du client. **De confiance pour la décision : personne.** La réponse est une proposition ; des gardes déterministes décident de ce qui peut s'exécuter.

**Ce qui part** :
- à chaque décision : les lignes de la détection (extraits de journaux, nom et identifiant de la VM, adresses, noms d'utilisateurs et de processus tels que les journaux les portent), les résultats des requêtes d'investigation, le contexte de l'incident, quelques décisions passées semblables tirées de la mémoire locale, l'état d'isolation de la VM ;
- pour proposer une règle (`propose-rules`, la boucle purple) : la technique visée et les colonnes des tables de journaux (`getschema`) ;
- pour le rapport d'une campagne (IA0) : les faits de la campagne et les décisions de Glorfindel, à son propre modèle (`EREGION_ANALYSIS_MODEL`).

**Ce qui ne part jamais** : les détections du plan de contrôle d'Azure et d'Entra ID (AL1, C2) — leur décision est construite par le code, sans appel au modèle, aucun UPN ne sort ; la mémoire et son modèle d'embeddings, qui tournent en local.

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

**H0** (le Glorfindel hébergé) — un observateur : identité managée `Reader` sur le groupe du banc et `Log Analytics Reader` sur son workspace, rien d'autre ; `GLORFINDEL_READ_ONLY=1` et `human_only` forcé. Entrée fermée, sauf pour l'opérateur ; la console n'écoute que sur la boucle locale de la VM. Aucun secret dans Terraform : les jetons dans `host.env`, copié à la main. Son CD ne fait que sortir ([`infra/glorfindel-host/README.md`](../../infra/glorfindel-host/README.md)).

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
| D | Un injecteur qui s'emballe | Plafond, arrêt d'urgence, fenêtres bornées (O1, B2) |
| E | Le Glorfindel hébergé est poussé à écrire | Il n'en a pas les droits (Reader) et tourne en lecture seule, `human_only` forcé au push |

**Ouvert** : un battement de la watch authentifié, pas seulement lié — planifié ; un journal hors de l'hôte que son identité ne peut pas effacer — planifié ; le canal sans point de terminaison public — planifié ; le durcissement des conteneurs — planifié.

---

## 6. La CI et le CD (GitHub, release, tags)

**De confiance** : le mainteneur (seul à publier une release), la branche `main` protégée (vérifications requises), `CODEOWNERS` sur tout le dépôt. **Pas de confiance** : les forks, leurs PR, les auteurs d'issues extérieurs, une action tierce sous un tag qui peut bouger.

**Ce qui la traverse** : le code des PR ; les événements `pull_request_target` et `workflow_run`, qui tournent avec les droits de la branche par défaut ; les secrets (Discord de l'atelier, Azure du canari) ; les releases, que H0 tire et déploie.

| | Menace | Ce qui la tient |
|---|---|---|
| S | Une PR de fork se fait passer pour un lot | Annoncée dans `#ci`, jamais dans un fil ; son run rouge aussi (SEC6) |
| T | Une action tierce déplacée sous son tag, dans un job qui tient un secret | Tout workflow qui tient un secret, ou tourne sur un événement qu'un fork déclenche, épingle ses actions par commit ; le canari installe Terraform depuis le dépôt signé de HashiCorp, sa clé vérifiée par son empreinte, sans action tierce (SEC6, `tests/unit/test_workflows.py`) |
| T | Une valeur choisie (entrée d'un `workflow_dispatch`, titre d'une PR) exécutée comme du shell | Aucun `run:` ne prend `inputs.*`, `github.event.*` ni `github.head_ref` dans son texte : ces valeurs passent par `env:` (SEC6, testé) |
| T | Une dépendance changée sous son numéro, ou prise sous un autre nom | Dépendances verrouillées, chaque fichier vérifié par son empreinte (M-3, `requirements/`) ; Eregion s'installe depuis le dépôt (README) |
| R | Une release sans histoire | `CHANGELOG.md`, une issue par lot ; les sessions préparent une release en brouillon, le mainteneur la publie |
| I | Un secret exposé au code d'une PR | `pull_request_target` et `workflow_run` ne récupèrent ni n'exécutent jamais le code d'une PR (récupération partielle du seul script, sans identifiants persistés) ; des permissions en lecture seulement, partout |
| D | Une CI rouge passée inaperçue | Annoncée dans `#ci`, avec mention ; le CD de H0 attend une CI verte |
| E | Une release piégée déployée sur H0 | Le CD exige un tag sur `origin/main`, jamais réécrit, tous les checks verts, un préflight dans la candidate, et revient en arrière si la santé échoue (H1) |

**Où c'est** : `.github/workflows/`, `.github/CODEOWNERS`, `scripts/notify_discord.py`, `infra/glorfindel-host/` (le CD) ; tests `tests/unit/test_workflows.py`, `tests/unit/test_notify_discord.py`, `tests/unit/test_host_cd.py`, `tests/unit/test_dependency_lock.py`.

**Ouvert** :
- un secret Azure de longue durée pour le canari — planifié ;
- quelques actions sans secret encore nommées par leur tag — planifié ;
- la publication du paquet — planifié.

---

## Décisions assumées

- **`human_only` par défaut.** Rien ne s'exécute sans humain tant que l'opérateur n'a pas donné l'autonomie, actif par actif ; l'autonomie se décide sur une mesure (`docs/observation.md`), jamais sur la confiance du modèle.
- **Deux hôtes Glorfindel, deux états : le tag de quarantaine l'emporte sur l'« aucun » de l'état** (I8S, #245, N-08). Quand l'état local dit qu'une carte réseau n'avait pas de NSG et que notre tag en nomme un, le tag fait foi, à la levée comme au `reset --from-azure`. Conséquence acceptée : dans un cas marginal (deux groupes de quarantaine, un tag périmé dans l'un), une carte peut recevoir à la levée un NSG de plus qu'elle n'en avait — jamais un de moins. L'autre option, un tag manquant ou illisible toujours tenu pour inconnu, garderait en quarantaine toute carte nue par conception dont les tags sont perdus. Détail : [`docs/azure.md`](../azure.md).
- **Un jeton pour la console**, tous ses droits (frontière 1).

## Comment ce document vit

Chaque lot de sécurité met à jour la page de sa frontière : ce qu'il tient passe dans « ce qui la tient », avec son nom ; ce qu'il laisse est écrit « planifié : #n ». Une frontière nouvelle (un fournisseur cloud, un canal) a sa page avant d'être livrée.
