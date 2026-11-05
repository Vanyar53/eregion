# Glorfindel hébergé (H0)

Une petite VM, dans le groupe `rg-glorfindel`, où Glorfindel tourne en continu, la console
d'Eregion (`eregion console`, l'ancienne War Room) et le bot Discord compris : le `docker compose`
de la racine (`watch`, `war-room` — le service de la console, qui garde son nom jusqu'à UI-1d —,
et `bot` par son profil), sur la même image et le même état. Premier usage : la **pré-observation** sur le banc
(`ROADMAP.md`, lot H0 ; `docs/observation.md`) — bree allumée en continu avec une vraie
charge, Glorfindel qui décide, toi qui juges chaque carte. Depuis BL1 (31/10), il répond aussi
seul sur le banc, dans le mode de chaque VM.

## Ce que la VM est, et n'est pas

- **La watch qui répond, sur le banc seulement** (décision de Jonathan, 31/10 ; bree le 01/11).
  Son identité managée a `Reader` et « Eregion Glorfindel Response » sur le groupe du banc,
  `Log Analytics Reader` sur son workspace, rien d'autre : jamais le restore, jamais
  l'abonnement. `GLORFINDEL_READ_ONLY=0`, gondolin et bree en `non_disruptive`, le CD actif.
  Jusqu'au 30/10, c'était un observateur (`Reader`, `GLORFINDEL_READ_ONLY=1`) ; ce que la
  posture ouvre et ce qui la borne : le modèle de menace
  ([`docs/design/modele-de-menace.md`](../../docs/design/modele-de-menace.md), §5).
  - **Le rôle de la réponse est attribué à la main**, hors de l'état Terraform de H0
    (`main.tf` pose les deux lectures et la coupure des sessions, rien d'autre) : `az role assignment create`, l'étape 3 de
    [`docs/banc-bl1.md`](../../docs/banc-bl1.md) ; le retirer, l'étape 7. Un `terraform apply`
    de H0 ne l'ajoute ni ne l'enlève.
  - **La coupure des sessions, VM par VM** (SEC11). **Aujourd'hui**, le rôle de la réponse posé à
    la main porte encore Run Command, sur toute VM du banc. **Après les gestes de SEC11**
    (`docs/operations.md`, « Depuis un rôle de la réponse d'avant SEC11 », dans leur ordre :
    créer le rôle ; le plan relu, puis `make glorfindel-host-up` ; juste après, deux portées de
    VM (`terraform output session_drain_vms`, ou `az role assignment list --assignee <principal>
    --role "Eregion Glorfindel Session Drain" --all`) ; ensuite seulement, Run Command retiré du
    rôle de la réponse ; et après ce geste, la préparation de gondolin et de bree, sans aucune
    `no_drain` — avant, elle ne prouve rien, le rôle de la réponse couvrant encore le groupe) :
    Run Command n'est plus dans le rôle de la réponse ; « Eregion Glorfindel Session Drain » se
    donne sur chaque VM de `session_drain_vms` — gondolin et bree, gardée dans
    `session_drain.auto.tfvars`, commité —, jamais sur le groupe, par cet état Terraform (chaque
    VM relue sur Azure : une faute de frappe échoue au plan ; `terraform output
    session_drain_vms`). Un `make glorfindel-host-up` ordinaire relit la liste et ne retire rien.
    Une VM hors de la liste est isolée quand même ; la coupure y est refusée et dite sur la carte.
    Une VM de la liste que Celebrimbor reconstruit perd son attribution avec elle (l'attribution
    porte l'id de la VM) : elle la retrouve au prochain `make glorfindel-host-up` ; d'ici là, sa
    préparation dit `no_drain`, et elle agit en `human_only`.
  - **La neutralisation avant un restore, VM par VM** (SEC17). H0 ne restaure pas, et ne reçoit
    jamais ce droit. Mais son état Terraform porte, pour le banc, « Eregion Glorfindel Restore
    Neutralize » (Run Command, sorti du rôle Restore) sur chaque VM de `restore_vms` (gondolin,
    bree — `restore.auto.tfvars`, commité), pour chaque principal qui restaure (`restore_principals` :
    la console et le bot, leurs object id dans `principals.auto.tfvars`, sur le poste,
    ignoré par git ; `principals.auto.tfvars.example`). Sans ce fichier, aucune
    attribution ; l'identité de H0 parmi eux, le plan refuse. Le même fichier donne la coupure des
    sessions à la console du poste (`session_drain_principals`), VM par VM sur `session_drain_vms` :
    elle isole elle-même ce qu'un humain approuve, et n'a plus Run Command par le rôle Restore. Les gestes, dans leur ordre :
    `docs/operations.md`, « Depuis un rôle Restore d'avant SEC17 ». `terraform output
    restore_neutralize` dit où elle est donnée. Une VM hors de la liste est restaurée quand même ;
    sa neutralisation est refusée, et dite sur la carte.
    Le test du module la tient (`tests/session_drain.tftest.hcl`).
  - **L'application de l'exécuteur d'identité** (IR1b, #572), **désactivée par défaut** : son
    principal à lui, jamais l'identité de la VM (celle de la watch), avec deux permissions
    d'application de Microsoft Graph, `Application.ReadWrite.OwnedBy` et `User.RevokeSessions.All`,
    et `Log Analytics Reader` sur le workspace du banc (`identity_executor.tf`). Rien dans le tenant
    tant que `identity_executor_enabled` est faux (`identity_executor.auto.tfvars`, ignoré par git ;
    `identity_executor.auto.tfvars.example`). Jonathan l'applique et consent les permissions :
    `docs/operations.md`, « L'exécuteur d'identité ». Le conteneur qui s'en servira est celui
    d'IR1c ; son contrat le relit au démarrage (`glorfindel identity-contract`). Le test du module :
    `tests/identity_executor.tftest.hcl`.
  - **La liste `never_target` va à la watch** (NT1, #583) : `EREGION_OPERATOR_OBJECT_ID`,
    `EREGION_PROTECTED_IDENTITIES`, `EREGION_IDENTITY_EXECUTOR_CLIENT_ID`, recopiées dans
    `host.env` par `host_env.py`, passées par le compose à la watch seule (le plan d'une carte
    d'identité, IR1a). Chacune vient d'une sortie Terraform (`host.env.example`, et
    `docs/operations.md`, « L'exécuteur d'identité », geste 6). Vide ou mal écrite, l'écriture et
    `--check` le disent, sans refuser : la liste est alors illisible, et chaque verbe d'un plan une
    étape de l'humain. Une valeur recopiée (de n'importe quelle variable) qui porte un saut de
    ligne, un retour chariot, un guillemet, un `$` ou une barre oblique inverse est en revanche
    refusée, la variable nommée, jamais sa valeur : elle injecterait une variable dans `host.env`,
    serait interpolée par compose, ou ferait refuser tout le fichier ; `--check` refuse un guillemet
    ouvert jamais fermé, et une barre oblique inverse entre guillemets.
  - **Un `make glorfindel-host-push` garde le mode de chaque VM** tel qu'il est sur H0
    (décision de Jonathan, 02/11 ; avant, SEC7 remettait toutes les VM en `human_only` à
    chaque push, et la posture se redonnait dans la console). Le push lit la config en place
    par la connexion ssh qu'il ouvre déjà, puis `host_config.py` envoie :
    - le défaut toujours en `human_only`, `allow_destructive` toujours vide : les modes et la
      liste destructive de la config locale n'arrivent jamais sur H0 ;
    - le mode de chaque VM gardé de H0 (un nom exact, tel que la console l'écrit) ; une VM que
      H0 ne connaît pas part en `human_only` ;
    - jamais un mode plus hardi que celui en place (A0) : config de H0 absente, illisible,
      d'une autre forme, ou que la watch refuserait au démarrage (une seule entrée suffit : un
      mode inconnu, un `match` vide, une clé de plus), toutes les VM en `human_only` ; un motif
      (`vm-*`) n'est pas reporté, ces VM partent en `human_only` ; et c'est dit.

    Le push affiche, VM par VM, le mode envoyé et sa provenance (« gardé de H0 », ou
    `human_only` et pourquoi). **`make glorfindel-host-push HUMAN_ONLY=1`** est le geste
    d'urgence : toutes les VM remises en `human_only` d'un coup, pour revenir à un H0 qui ne
    fait rien seul (la console les redonne, une à une, après leur contrôle de préparation).
    **Ne pas changer un mode dans la console pendant un push** : la config de H0 est lue avant
    le `scp` qui la remplace, un mode changé entre les deux serait écrasé. Le push la relit juste
    avant le `scp` et, si elle a changé entre les deux lectures, s'arrête sans rien envoyer
    (« la config de H0 a changé pendant le push ») : relancer. Seul `HUMAN_ONLY=1` déclenche le
    geste d'urgence (`HUMAN_ONLY=0` ou vide : les modes gardés) ; il ne relit pas H0 avant
    d'envoyer : il n'en emporte rien, et une relecture qui échoue ne le bloque pas.
    Le CD, lui, ne touche ni `host.env` ni la config.
  - **Un nouveau `host.env`** (`make glorfindel-host-env`) part en lecture seule
    (`GLORFINDEL_READ_ONLY=1`) : la posture se donne à la main, sur un hôte qui doit répondre.
- **Pas une cible.** Hors du groupe du banc, sans tag `eregion-target`, sans DCR vers le
  Log Analytics du banc : la découverte (Heartbeat) ne la voit pas, Glorfindel ne peut pas
  l'isoler. Elle n'est pas non plus sur Orodruin (côté rouge).
- **Fermée.** Entrée : SSH depuis ton IP seulement (`operator_cidr`, jamais `0.0.0.0/0`).
  La console écoute sur `127.0.0.1` de la VM et s'ouvre par un tunnel SSH, jeton en plus.
  Alertes : Discord ou webhook, en sortie.
- **Sans secret dans Terraform.** La clé du modèle et les jetons sont dans `host.env`
  (ignoré par git), copié à la main sur la VM. Aucun secret Azure : l'identité managée.
- **La clé du fournisseur configuré, seule** (OL1, #525). `make glorfindel-host-env` exige ce que
  lit le fournisseur de `GLORFINDEL_LLM_MODEL` (son préfixe ; la règle :
  `eregion_core/models.py`, `required_env`), et rien d'autre :

  | `GLORFINDEL_LLM_MODEL` | Exigé |
  |---|---|
  | `anthropic/…`, ou vide (le défaut) | `ANTHROPIC_API_KEY` |
  | `openai/…` | `OPENAI_API_KEY` |
  | `azure/…` (Azure OpenAI) | `AZURE_API_KEY`, et `AZURE_API_BASE` ou `GLORFINDEL_LLM_BASE_URL` à sa place (la watch la passe en `base_url`, que LiteLLM prend pour l'adresse) ; `AZURE_API_VERSION` copié s'il est posé |
  | `mistral/…` | `MISTRAL_API_KEY` |
  | `ollama/…`, `ollama_chat/…` | aucune clé, mais `GLORFINDEL_LLM_BASE_URL` : dans le conteneur de la watch, l'adresse par défaut de LiteLLM (`localhost:11434`) est le conteneur lui-même |
  | `openai/…` servi par `GLORFINDEL_LLM_BASE_URL` (auto-hébergé, compatible OpenAI) | rien (`OPENAI_API_KEY` copié s'il est posé, pour un point d'accès qui en demande une) |

  Un autre fournisseur, ou un modèle sans préfixe, est refusé, avec la liste. Le message dit ce
  qui manque, jamais une valeur. `host.env` ne porte que les clés des fournisseurs des modèles
  configurés (celui de la décision, celui de l'analyse) : une autre clé de ton `.envrc` ne va
  jamais sur H0. `make glorfindel-host-push` tient le `host.env` à la même règle
  (`host_env.py --check`), ses variables de modèle lues comme la watch les reçoit (une paire de
  guillemets retirée ; `KEY=""` ou `KEY=   # note` vide) ; `make glorfindel-host-model` aussi,
  sur une copie, avant d'écrire quoi que ce soit, ici ou sur la VM.

  L'IA d'analyse (`EREGION_ANALYSIS_MODEL`, Haiku par défaut) écrit les rapports de campagne,
  jamais une décision : ce qui lui manque est dit, pas refusé. Elle ne lit pas encore
  `GLORFINDEL_LLM_BASE_URL` (`analysis/campaign_report.py`, `analysis/triage.py`) : un modèle
  d'analyse local viserait le conteneur de la watch, et chaque rapport échouerait — c'est dit
  aussi. Avec un modèle de décision local, garde donc un modèle d'analyse d'un fournisseur, avec
  sa clé, ou accepte que les rapports de campagne échouent. Brancher l'adresse dans l'analyse
  reste à faire (hors d'OL1).

Coût : D2als_v6 (2 vCPU, 4 Go), environ 61 € par mois en continu (API de tarifs Azure, 16/10) — 27 € en B2als_v2 si le quota Basv2 est accordé —, plus
le disque et l'IP publique.

## Déroulé

```bash
make glorfindel-host-plan            # lecture seule ; OPERATOR_CIDR=<ip>/32, sinon ton IP du moment
make glorfindel-host-up              # crée la VM (confirmation demandée) ; cloud-init installe Docker et clone le dépôt
make glorfindel-host-env             # host.env depuis ton .envrc chargé (ou : copier host.env.example et remplir)
make glorfindel-host-push            # host.env → ~/eregion/.env ; la config locale, le défaut en human_only, les modes de H0 gardés (HUMAN_ONLY=1 : tout en human_only)
make glorfindel-stop                 # arrête le Glorfindel local : deux watch = cartes en double
make glorfindel-host-start REF=…     # un tag ou un commit (exigé), détaché ; construit l'image sur H0 (le chemin de secours), lance watch + console (war-room) + bot
make glorfindel-host-tunnel          # affiche l'URL de la console avec son jeton, puis tient le tunnel (Ctrl+C)
make glorfindel-host-url             # l'URL de la console avec son jeton, seule
make glorfindel-host-logs            # vérifier « heartbeat → N VM(s) » et l'absence d'erreur d'identité
make glorfindel-host-status          # tout tourne ? VMs, sauvegardes, services, erreurs 24 h, cartes à juger
make glorfindel-host-report          # rapport d'observation (SINCE=4w pour la période)
make glorfindel-host-pull            # copie locale de ~/.glorfindel (verdicts, mémoire) — chaque semaine
make glorfindel-host-down            # détruit la VM et son état (mémoire comprise)
```

Au quotidien : `make glorfindel-host-status` (lecture seule, une vue), puis `make glorfindel-host-tunnel`, l'URL qu'il affiche, puis les boutons **✓ Right** / **✗ Wrong** des cartes de la console (TO JUDGE, page Glorfindel)
(`docs/observation.md`) ; chaque semaine, `make glorfindel-host-report`. Rien à faire sur la
VM elle-même.

Les escalades arrivent dans Discord par le bot, qui tourne sur la VM (un fil par VM, avec
ses boutons) ; le webhook garde les notifications d'action. Un seul bot par
`DISCORD_BOT_TOKEN` : n'en lance pas d'autre en local.

## La console d'Eregion (UI-1, #205)

La War Room est devenue la console d'Eregion : `eregion console` (`docs/design/console.md`). Une
**Vue d'ensemble** (`/` : les cartes à juger, la part d'isolations et de blocages jugés faux, le
dernier run et la dernière campagne de chaque injecteur, les canaux), puis une page par agent :
**Glorfindel** (`/glorfindel`, l'ancienne War Room : TO JUDGE, le fil, la carte de l'infra),
**Annatar** et **Gothmog** (`/annatar`, `/gothmog`, en lecture seule), et **Config** (`/config`).
Glorfindel est toujours là ; un injecteur est actif dès que l'hôte tient un de ses runs (une
fenêtre, un rapport, une campagne) — sur H0, ceux qui viennent d'Orodruin par le canal —, sinon
son onglet est grisé. Les anciennes adresses (`/atelier`, `/api/atelier/*`) redirigent.

- **L'URL** : `make glorfindel-host-tunnel` l'affiche avec son jeton (« Console → http://localhost:7007/?token=… »),
  puis tient le tunnel ; `make glorfindel-host-url` l'affiche seule. Le jeton est posé une fois en
  cookie ; l'URL n'a plus à être rouverte avec lui.
- **Le jeton, sous ses deux noms.** `EREGION_CONSOLE_TOKEN`, ou son ancien nom,
  `GLORFINDEL_WARROOM_TOKEN` : la console prend le nouveau s'il n'est pas vide, sinon l'ancien
  (compose lui passe les deux, vides quand ils manquent). Le `host.env` de H0 n'a que l'ancien :
  **rien à renommer**, il reste valide. Un nouvel hôte (`make glorfindel-host-env`) reçoit le
  nouveau. `make glorfindel-host-url`, `-tunnel` et `-status` suivent la même règle : ils lisent
  le jeton sous l'un ou l'autre nom (`host.env` sur le poste, `~/eregion/.env` sur la VM), comme
  compose lit le fichier (la dernière ligne d'une clé l'emporte ; `# …` après la valeur et un
  blanc est un commentaire — mais `KEY=   # note` vaut « # note », pas une valeur vide, mesuré
  avec `docker compose config`). `glorfindel-host-status` ne l'affiche jamais et ne le met sur
  aucune ligne de commande (curl le lit sur son entrée) ; il dit « jeton refusé » si la console
  le refuse, « aucun jeton » s'il n'y en a pas. `make glorfindel-host-push` vérifie d'abord le
  `host.env` (`host_env.py --check`) : il dit sous quel nom est le jeton, sans sa valeur, et
  refuse un fichier sans jeton (la console tournerait sans) ou dont le jeton est un commentaire —
  ou sans la clé du fournisseur de son modèle (OL1, plus haut).
- **Avant UI-1** : une référence antérieure (`v0.3.0` et avant) ne lit que
  `GLORFINDEL_WARROOM_TOKEN`. Un `host.env` neuf, qui n'a que `EREGION_CONSOLE_TOKEN`, se déploie
  donc avec une référence qui contient UI-1 (`REF=<commit>` ou un tag postérieur) : sinon la War
  Room de l'ancienne image démarrerait sans jeton (sur la boucle locale de la VM, mais sans jeton).
- **Le service compose** garde son nom, `war-room` (conteneur `eregion-war-room`) :
  `glorfindel-host-status` l'affiche « console  eregion-war-room ». Le renommer (`console`) est
  UI-1d, avec Jonathan : l'ancien conteneur garde le port 7007 tant qu'il n'est pas retiré.

### Ce que change le prochain redéploiement de H0

UI-1c ne change que le poste (`Makefile`, `status.sh`, `host_env.py`) : rien à redéployer pour
lui. Si H0 tourne encore une référence d'avant UI-1 (`make glorfindel-host-status` → « référence
déployée »), le prochain `make glorfindel-host-start REF=<tag ou commit avec UI-1>` (avec Jonathan,
`.envrc` chargé) :

- **la watch et le bot ne changent pas** : mêmes commandes (`glorfindel watch`, `glorfindel bot`),
  mêmes variables, même état ;
- **la console redémarre sous `eregion console`**, dans le même conteneur (`eregion-war-room`), sur
  le même port (`127.0.0.1:7007`), avec le même jeton (l'ancien nom suffit) ;
- `host.env` ne change pas (pas de `make glorfindel-host-env` : il tirerait un nouveau jeton) ;
  `make glorfindel-host-push` seulement si autre chose y a changé.

Vérifier : `make glorfindel-host-status` → « ✓ console  eregion-war-room », « à juger : N » (et non
« jeton refusé » ni « pas de réponse ») ; `make glorfindel-host-tunnel`, puis l'URL affichée : la
Vue d'ensemble, l'onglet Glorfindel ; un ancien favori `/atelier` mène à `/`.

## Ce que la VM exécute (M-3, #183)

- **Une référence nommée, jamais une branche.** `make glorfindel-host-start REF=v0.3.1` (un tag)
  ou `REF=<commit>` (7 à 40 chiffres hexadécimaux) ; **sans `REF`, rien n'est déployé** (SEC14,
  V-22) : ce chemin construit l'image sur H0, hors de la vérification de CI3, et ne prend donc
  jamais « le dernier tag » qu'il trouverait — un tag que quiconque peut écrire dans le dépôt
  pousserait. `main`, `origin/main`, `HEAD` sont refusés : une branche bouge, et la VM
  exécutait jusque-là ce qui venait d'être fusionné (`git pull` sur `main`). `REF` se donne sur
  la ligne de commande : une variable `REF` de l'environnement (un nom générique, exporté pour
  autre chose) est refusée, jamais déployée en silence ; une `REF` qui commence par `-` aussi (elle serait une option du script). Le script
  (`deploy.sh`, celui du poste, envoyé par ssh) fait `git fetch --tags`, un checkout détaché,
  puis construit l'image avec deux étiquettes, `org.opencontainers.image.version` (la référence)
  et `org.opencontainers.image.revision` (le commit complet). Un fichier suivi modifié sur la VM
  arrête le déploiement (il partirait dans l'image), `glorfindel/rules/` compris depuis P1 : les
  conteneurs ne l'écrivent plus (montage en lecture seule), une règle approuvée va dans la couche
  du client, `~/.glorfindel/client_rules.yaml`, qu'aucun checkout ne touche ; un fichier de règles
  modifié tient des règles approuvées avant P1, à migrer (« Migrer les règles approuvées vers la
  couche du client », plus bas). `make glorfindel-host-status` relit les
  étiquettes sur le conteneur de la watch : « ✓ référence déployée : v0.3.1 (abc…) », ⚠ si le
  checkout a bougé depuis, si la VM est sur une branche, ou si l'image n'a pas d'étiquette (une
  image d'avant M-3). Revenir en arrière : `REF=<le tag précédent>`.
- **Des dépendances verrouillées.** L'image s'installe depuis `requirements/glorfindel.txt`
  (versions et empreintes, `pip --require-hashes`) : une construction ne prend plus la dernière
  version de chaque bibliothèque. Mettre à jour le verrou : `docs/operations.md`, « Verrou des
  dépendances ».
- **Un environnement par conteneur.** `host.env` reste un seul fichier (`~/eregion/.env` sur la
  VM), que docker compose lit pour remplir `docker-compose.yml` ; chaque conteneur ne reçoit que
  les variables de sa liste. La clé du modèle : la watch seule. Le jeton du bot : le bot seul.
  Le jeton de la console : la console seule. L'URL du webhook (elle porte un jeton) : la watch
  et la console. Les réglages sans secret (abonnement, modèle affiché, canaux, lecture seule,
  `DISCORD_CHANNEL_ID`) : les trois. Pourquoi pas trois fichiers : compose ne passe à un
  conteneur que sa liste, et trois fichiers sur le même disque, au même propriétaire, ne
  protégeraient rien de plus ; la répartition est tenue par `tests/unit/test_glorfindel_host.py`.
  La watch et la console n'ont plus le jeton du bot : compose leur dit seulement qu'il est posé
  (`GLORFINDEL_DISCORD_BOT`, « 1 » ou vide, jamais la valeur). Avec lui et `DISCORD_CHANNEL_ID`,
  le bot poste les cartes et leur webhook se tait ; un salon sans jeton, le webhook poste.
- **Des boutons qui vérifient qui clique.** `DISCORD_ALLOWED_USERS` (ids d'utilisateurs) et
  `DISCORD_ALLOWED_ROLES` (ids de rôles), séparés par des virgules. Un clic d'un autre est refusé,
  avec un message visible de lui seul, et journalisé (« Button refused: user … »). **Fermé par
  défaut** : sans liste, tous les boutons refusent. Les boutons jugent, acquittent et lancent des
  restaurations, et Discord les montre à quiconque lit le salon : un oubli ne doit pas les
  ouvrir à tout le serveur ; la console, derrière son jeton, juge toujours les cartes. Au
  démarrage, le bot dit combien d'utilisateurs et de rôles il autorise, ou avertit que tout est
  fermé.

## Redéployer H0 après M-3 (avec Jonathan)

À faire une fois, après la fusion. Pré-observation en cours jusqu'au ~13/11 : rien sans Jonathan,
`.envrc` chargé.

1. **Ton id Discord.** Discord → Paramètres → Avancés → Mode développeur ; puis clic droit sur
   ton nom → « Copier l'identifiant de l'utilisateur ». (Pour un rôle : Paramètres du serveur →
   Rôles → clic droit → « Copier l'identifiant ».)
2. **host.env, sur le poste** (`infra/glorfindel-host/host.env`, pas besoin de le régénérer ni de
   le séparer — le jeton de la War Room ne change pas) : ajouter
   ```
   DISCORD_ALLOWED_USERS=<ton id>
   ```
   (ou `DISCORD_ALLOWED_ROLES=<id du rôle>`). Vérifier que `DISCORD_BOT_TOKEN` et
   `DISCORD_CHANNEL_ID` y sont tous deux : ensemble, ils font taire le webhook de la watch et de
   la War Room (le bot poste les cartes) ; l'un sans l'autre, le webhook poste. Rien à retirer :
   les variables ne changent pas de nom, compose les répartit.
3. **Une référence à déployer.** Le dernier tag, `v0.3.0`, est antérieur à M-3 (et à tout ce qui
   a été fusionné depuis) : sans `REF`, c'est lui qui serait déployé. Poser un tag sur le commit de
   fusion (`git tag v0.3.1 <commit> && git push origin v0.3.1`, ou une release), ou passer le
   commit : `REF=<commit de fusion>`.
4. **Le harnais — obligatoire, avant l'étape 5.** L'image prend désormais les versions du
   verrou (résolution du 26/10), nettement plus récentes que celles des postes et de la CI
   jusqu'ici : anthropic 0.104 → 2.3, fastapi 0.136 → 0.162, langgraph 1.2.1 → 1.2.17 (LiteLLM
   reste 1.86.1) ; celles de l'image qui tourne sur H0 dépendent du jour où elle a été construite
   (`docker exec eregion-watch pip list` sur la VM). Sans le harnais, on ne sait pas si les
   décisions de H0 restent les mêmes : `make llm-compare MODELS=<modèle en service> RUNS=3`
   (appels payants, Jonathan) ; les décisions doivent rester celles d'avant. Sinon, ne pas
   redéployer : ouvrir une PR qui ramène le verrou (`docs/operations.md`, « Verrou des
   dépendances »).
5. **Pousser, puis déployer** :
   ```bash
   make glorfindel-host-push                 # host.env (avec DISCORD_ALLOWED_USERS) → ~/eregion/.env
   make glorfindel-host-start REF=v0.3.1     # ou REF=<commit>
   ```
   La première fois, la VM est sur la branche `main` (clone de cloud-init) : le déploiement la
   passe en checkout détaché. S'il refuse pour « fichiers suivis modifiés », regarder
   (`make glorfindel-host-ssh`, puis `git -C eregion status --short`) avant de toucher quoi que ce
   soit. S'il refuse pour « modifié sur la VM (règles approuvées avant P1) » : « Migrer les
   règles approuvées vers la couche du client », plus bas. Dans les deux cas, rien n'a bougé :
   l'ancienne image tourne toujours.
6. **Vérifier** : `make glorfindel-host-status` → « ✓ référence déployée : v0.3.1 (…) », les trois
   conteneurs ✓, aucune erreur ; `make glorfindel-host-logs` → le bot dit « Boutons : 1
   utilisateur(s) … » (et non « fermé par défaut ») ; un clic sur ✓ Right d'une carte dans Discord
   passe. Que chaque conteneur n'a que ses secrets, sans en afficher la valeur :
   ```bash
   make glorfindel-host-ssh
   for c in eregion-watch eregion-war-room eregion-bot; do echo "$c: $(docker exec $c env | cut -d= -f1 | grep -E 'KEY|TOKEN|SECRET|WEBHOOK' | grep -v '^GPG_KEY$' | sort | tr '\n' ' ')"; done
   ```
   (`GPG_KEY` vient de l'image `python:3.12-slim` : l'empreinte publique de la clé qui signe
   Python, pas un secret ; la commande l'écarte.) Attendu : la watch, la clé de son fournisseur
   (`ANTHROPIC_API_KEY` par défaut ; les autres clés de modèle, vides), `AZURE_CLIENT_SECRET` (vide), `GLORFINDEL_WEBHOOK_URL` ; la War
   Room (la console depuis UI-1), `GLORFINDEL_WARROOM_TOKEN` (et `EREGION_CONSOLE_TOKEN` depuis
   UI-1, l'un des deux vide), `AZURE_CLIENT_SECRET`, `GLORFINDEL_WEBHOOK_URL` ; le bot,
   `DISCORD_BOT_TOKEN`, `AZURE_CLIENT_SECRET`. Aucune autre. La watch et la War Room ont aussi
   `GLORFINDEL_DISCORD_BOT=1` (le jeton du bot est posé, sans sa valeur).
7. **En cas de problème** : `make glorfindel-host-start REF=<commit déployé avant>` (affiché par
   l'ancien `glorfindel-host-status`, « commit déployé ») revient à l'image d'avant — sans
   étiquette, le statut le dira « inconnue ».

### Règles approuvées : la couche du client (P1)

Depuis P1, une règle approuvée (`glorfindel approve-rule`, ou « Approve » dans la console)
s'écrit dans la couche du client, `~/.glorfindel/client_rules.yaml` sur la VM (monté dans les
trois conteneurs), chargée par-dessus la base livrée, `glorfindel/rules/azure/detection_rules.yaml`.
La base est montée en lecture seule : aucun conteneur ne l'écrit plus, et un redéploiement, quelle
que soit la référence, ne touche jamais la couche du client. `docker exec eregion-watch glorfindel
rules` montre chaque règle et sa couche ; au démarrage, la watch dit ce que la couche du client
fait à la base (une règle remplacée, une désactivée). Revenir à une référence d'avant P1 : elle
ne lit pas la couche — les règles du client manquent à la détection (rien n'est perdu, le
fichier reste), jusqu'au retour à une référence avec P1.

### Migrer les règles approuvées vers la couche du client

À faire une fois, avec Jonathan, au premier déploiement d'une référence avec P1. Avant P1, les
règles approuvées s'écrivaient dans `glorfindel/rules/azure/detection_rules.yaml`, un fichier
suivi : `deploy.sh` refuse maintenant un fichier de règles modifié sur la VM (« … modifié sur la
VM (règles approuvées avant P1) : rien n'est déployé »), l'ancienne image tourne toujours.
**Jamais `git checkout -- glorfindel/rules`** (ni `git reset --hard`) : ils effacent les règles
approuvées. La procédure est rejouée telle qu'écrite, sur un dépôt local, par
`tests/unit/test_host_deploy.py::test_the_migration_procedure_of_the_readme_runs_as_written`.

**Les règles approuvées avant P1 étaient inertes ; après la migration, elles détectent — à
surveiller les premiers jours.** Avant P1, une approbation écrivait la règle avec son workspace
en ligne, sans `assets` ni backend (`rule_from_proposal` lisait un champ que `DetectionRule`
n'a pas) : chargée comme « toutes les VM d'aucun backend », elle ne s'appliquait à aucune VM
découverte, sans rien dire. `migrate-rules` lie une telle règle au backend de
`glorfindel-config.yaml` qui surveille son workspace (`assets: [auto]`) : elle tourne alors sur
toutes les VM de ce backend. Une règle approuvée pour une détection manquée peut se révéler
bruyante : regarder ses détections et ses cartes les premiers jours (`make glorfindel-host-logs`,
la console), et la désactiver au besoin (`disable: [<nom>]` dans la couche).

1. **Sur la VM** (`make glorfindel-host-ssh`, puis `cd eregion`) : mettre de côté le fichier
   modifié et la base d'où il vient, dans `~/.glorfindel` (que les conteneurs voient), puis
   rendre le checkout propre (le stash garde une seconde copie) :

   ```bash
   mkdir -p ~/.glorfindel/migration-p1
   cp glorfindel/rules/azure/detection_rules.yaml ~/.glorfindel/migration-p1/approved.yaml
   git show HEAD:glorfindel/rules/azure/detection_rules.yaml > ~/.glorfindel/migration-p1/base.yaml
   git diff --stat -- glorfindel/rules
   git stash push -m regles-approuvees-p1 -- glorfindel/rules
   ```

2. **Depuis le poste** : `make glorfindel-host-start REF=<tag avec P1>`. Il passe ; la watch
   démarre avec la base seule, sans les règles approuvées (quelques minutes, jusqu'à l'étape 3).
3. **Sur la VM** : ce qui part dans la couche (à sec), puis pour de bon, puis redémarrer la watch
   (elle lit les règles au démarrage ; la console les relit à chaque rafraîchissement) :

   ```bash
   docker exec eregion-watch glorfindel migrate-rules --from /root/.glorfindel/migration-p1/approved.yaml --base /root/.glorfindel/migration-p1/base.yaml --dry-run
   docker exec eregion-watch glorfindel migrate-rules --from /root/.glorfindel/migration-p1/approved.yaml --base /root/.glorfindel/migration-p1/base.yaml
   docker compose restart watch
   docker exec eregion-watch glorfindel rules
   ```

   `migrate-rules` met dans la couche ce que `approved.yaml` a de plus que `base.yaml` : une
   règle ajoutée telle quelle ; une règle de base modifiée sur la VM, sous son nom (elle remplace
   celle de la base, et la watch le dit) ; une règle de base supprimée sur la VM, dans `disable`.
   Une règle au workspace en ligne est liée à son backend (« bound … monitoring_backends:
   [<backend>], assets: [auto] ») ; si aucun backend unique de `glorfindel-config.yaml` ne
   surveille son workspace, elle part telle quelle et `migrate-rules` le dit (⚠ : elle reste
   inerte — à lier à la main dans la couche). Un fichier illisible : rien n'est écrit, et c'est dit.
   Relancé, il ne change plus rien. `glorfindel rules` doit montrer chaque règle approuvée avec la
   couche `client` et, en `assets`, `auto (<backend>)` — `auto (aucun backend : inerte)` dit une
   règle restée inerte, avec sous le tableau la note « ne s'applique à aucune VM découverte ».
4. **Une fois vérifié** (la règle dans `glorfindel rules`, la watch sans erreur dans
   `make glorfindel-host-logs`), sur la VM, jeter le stash (le premier de la liste doit être
   `regles-approuvees-p1`) ; la copie reste dans `~/.glorfindel/migration-p1/` :

   ```bash
   git stash list
   git stash drop
   ```

**Disque** : chaque `make glorfindel-host-start` reconstruit l'image ; les couches des anciennes images restaient dans containerd (Docker 29), jusqu'à 87 % d'un disque de 32 Go le 20/10, 25 Go récupérables. Le redéploiement purge maintenant les images orphelines (`docker image prune -f`), et `glorfindel-host-status` affiche l'occupation du disque. Depuis H1, chaque image est aussi étiquetée par sa référence (`eregion-glorfindel:v0.4.0`). Le ménage garde les trois plus récentes, plus celle qui tourne et celle d'avant : revenir à la précédente est un `docker tag`, pas une reconstruction. Le CD ne fait ce ménage qu'une fois la santé verte ; jamais à la bascule, pour que l'image du retour arrière reste.

Les verdicts de l'observation et la mémoire ne vivent que sur le disque de la VM : `make glorfindel-host-pull` en garde une copie sur le poste (`~/.eregion/host-backups/`, les 30 dernières), et `make glorfindel-host-status` signale une copie de plus de 7 jours. Une VM éteinte (gondolin entre deux exercices) reste une semaine sur la carte (`GLORFINDEL_DISCOVERY_RETENTION_H=168` dans `host.env`, 8 h par défaut).

La mémoire (ChromaDB) part vide sur la VM : la mémoire locale ne contient que des cycles
d'exercice non marqués (B2), qui n'ont rien à faire dans une observation.

## Le CD de H0 (H1, #244)

**Publier une release, c'est déployer H0.** Un timer sur la VM la tire toutes les 5 minutes. Il la vérifie, **tire son image publiée par son digest et en vérifie la signature et la provenance** (CI3 : le CD ne construit jamais sur H0 ; seul le déploiement à la main, le chemin de secours, construit une référence nommée, `REF` exigée), la préflighte, bascule, et revient en arrière si la santé échoue. H0 reste fermé : il ne fait que sortir, vers l'API publique de GitHub (sans jeton), vers le registre (`ghcr.io`, ses blobs sur `pkg-containers.githubusercontent.com`, sans jeton), vers la racine de confiance de sigstore (`tuf-repo-cdn.sigstore.dev`) et vers le webhook de `#deploy`. Le Terraform de H0 n'a aucune règle sortante : la règle par défaut d'Azure (`AllowInternetOutBound`) laisse tout cela passer, rien n'est à ouvrir (lu dans `main.tf` ; à confirmer sur la VM par `make glorfindel-host-cd-check`, qui fait chacun de ces appels).

**Les sessions ne publient jamais une release** : elles la préparent en brouillon (`gh release create --draft`), et Jonathan clique « Publish ». Depuis SEC12, une fois posée par Jonathan, une règle du dépôt le tient : les tags `v*` (création, mise à jour, suppression) sont réservés à l'administrateur, et publier une release crée son tag. Les sessions agissent sous leur propre identité, une GitHub App (`docs/sessions.md`, « L'identité des sessions » et « Les règles du dépôt »).

### Installer (une fois, Jonathan)

1. **Le webhook de `#deploy`.** Dans Discord, Paramètres du salon → Intégrations → Webhooks (par exemple « H0 »). Mets son URL dans `~/.config/eregion/discord.env` (`EREGION_DISCORD_WEBHOOK_DEPLOY=…`), à côté de `EREGION_DISCORD_MENTION`.
2. **`make glorfindel-host-cd-install`.** La commande :
   - copie l'agent dans `~/.eregion-cd/` sur la VM, avec `deploy.sh`, `notify_discord.py`, `chat_text.py` (l'échappement de SEC6, pour ce que `#deploy` dit d'une règle, H2) et `published_image.py` (CI3), jamais dans le checkout qu'il déploie ;
   - fait télécharger cosign à la VM (`published_image.py install-cosign`, depuis la release de sigstore sur GitHub) dans `~/.eregion-cd/cosign`, gardé seulement si son sha256 est celui épinglé dans `published_image.py` (v3.1.3) ; `install.sh` refuse un agent sans lui ;
   - y écrit `discord.env` en 600, avec le webhook et la mention seulement, passés par stdin. Le jeton du bot Eregion ne va jamais sur H0 ;
   - installe les unités systemd avec sudo, **timer désactivé**.
3. **`make glorfindel-host-cd-check`, à blanc.** La commande vérifie la dernière release, tire son image publiée par son digest, la vérifie et passe le préflight, dont **la config de H0 sous la lecture stricte d'A3**. Elle ne bascule pas, et dit le résultat dans le terminal et dans `#deploy`. Si la dernière release tourne déjà (le cas quand H0 a été redéployé à la main sur elle, ou par l'agent d'avant CI3), elle tire son image publiée à côté (`check-<tag>`, effacée ensuite), la vérifie et la préflighte : le chemin de la release suivante est éprouvé sur le vrai Docker de H0.
4. **Si c'est vert, `make glorfindel-host-cd-enable`.** Le passage suivant déploie.

### Un passage

0. **Un passage interrompu après sa bascule** (redémarrage de la VM, délai de systemd) est repris d'abord. La bascule est inscrite avant d'avoir lieu, et le passage suivant regarde ce qui tourne :
   - la watch est sur la release : la santé, puis la release est gardée ou c'est le retour arrière ;
   - elle est encore sur la version d'avant, ou absente (coupé avant ou pendant le `compose up`) : H0 est remis d'aplomb sur la version d'avant, et la bascule est dite « interrompue », pas malade ; elle est retentée au passage suivant. Interrompue une deuxième fois, elle est refusée, avec ta mention ;
   - elle tourne sur autre chose (redéployé à la main entre-temps) : le CD n'y touche pas.
   `make glorfindel-host-cd-retry` garde une bascule interrompue.
1. **La dernière release**, sur l'API publique (les brouillons et les pré-versions n'y figurent pas). Rien à faire si elle tourne déjà sur les trois conteneurs, ou si elle a déjà échoué ou été refusée. Un tag déjà vu sur un autre commit est refusé : un tag publié ne se réécrit pas.
   Si seule une partie des conteneurs tourne sur la release, `#deploy` le dit une fois.
2. **Vérifier.** Son tag est sur `origin/main`, et jamais plus ancien que ce qui tourne (SEC12) :
   - **plus ancienne par sa version** (`vX.Y.Z`, comparée en nombres) **ou par son commit** (un ancêtre) que ce qui tourne, **ou que le plancher** : **refusée**, dite avec ta mention, le retour arrière nommé. Le plancher est la plus haute version déjà déployée sur ce H0, avec son commit (`state.json`, `floor`). Chaque déploiement le monte, ce qui tourne aussi (un déploiement à la main plus récent). Rien ne le baisse, ni un retour arrière, ni `retry` : remettre H0 à la main sur une version plus ancienne ne rouvre pas la porte aux releases d'avant ;
     - **une release publiée puis retirée** (v0.5.0 déployée, puis supprimée parce qu'elle était fautive) laisse le plancher sur elle : la v0.4.x suivante sera refusée. Trois issues, au choix :
       - `make glorfindel-host-cd-rollback TAG=<la release voulue>` : le retour arrière vers la série voulue. Le plancher reste où il est, et la release suivante doit le dépasser ;
       - publier une version au-dessus du plancher (v0.5.1) qui porte la correction ;
       - le CD en pause (`make glorfindel-host-cd-disable`), retirer la clé `floor` de `~/.eregion-cd/state.json` sur la VM, puis `make glorfindel-host-cd-enable`. Le passage suivant repart de ce qui tourne. C'est un geste de Jonathan sur H0 ;
     - **un plancher dont le commit est inconnu du dépôt de la VM** (un tag supprimé, puis la VM reclonée) : `git merge-base` ne sait pas ordonner, et chaque release est refusée, « ne se lit pas ». C'est voulu : jamais une release n'est tenue pour plus récente par défaut de lecture. L'issue est la troisième ci-dessus (la clé `floor` retirée, le CD en pause) ;
   - **jamais par défaut de lecture** : si ce qui tourne ne se lit pas (la watch sans étiquettes, absente), ou si `git merge-base` ne sait pas ordonner deux commits (code 128 : un commit inconnu du dépôt de la VM), la release est **refusée**, pas tenue pour plus récente. Un retour arrière demandé n'y change rien. Une release plus ancienne remise en « latest » ne ramène jamais H0 en arrière seule. Avant SEC12, le CD passait en silence, et seulement par le commit. Si H0 a été redéployé à la main sur un commit plus récent que la dernière release, celle-ci est refusée une fois, avec la mention, puis plus rien ;
   - **le retour arrière se demande sur H0**, pour un tag : `make glorfindel-host-cd-rollback TAG=v0.4.9`. La release doit être publiée : un brouillon répond 404, une pré-version est refusée. Elle passe toutes les vérifications d'une release : sur `main`, checks verts, image signée tirée par son digest, préflight, santé. Le message de début dit « retour arrière demandé sur H0 ». La release quittée est marquée « rolled back » : le timer ne la reprend pas seul, il faut une nouvelle release ou `make glorfindel-host-cd-retry`. Un retour arrière qui change de verrou passe aussi la garde du verrou (point 3) : l'attestation de la release visée porte sur un autre verrou de référence, et elle est le plus souvent refusée. Le chemin de secours reste alors `make glorfindel-host-start REF=<tag>`. **Une release d'avant le renommage du compte** (la v0.5.2 et avant, REN1) est toujours refusée : son image est signée par l'ancien nom du dépôt, que ce CD ne reconnaît plus. Même secours ;
   - **la règle des tags**, lue sans jeton (`/repos/…/rulesets?targets=tag`, puis la règle) : une règle active dont les cibles couvrent `refs/tags/<tag>` et qui interdit création, mise à jour et suppression. Vue, le message de début la nomme (« 🔒 … réservé par la règle … »). Absente, `#deploy` le dit en orange, avec ta mention. Illisible, il le dit en orange, sans mention. Ce n'est **jamais un refus** : GitHub ne dit pas si ces routes répondent sans jeton, c'est une hypothèse à mesurer sur H0 (`make glorfindel-host-cd-check`). `make glorfindel-host-cd-status` la dit aussi.

   **Les checks de son commit, en deux groupes** (H1c, #518, décision de Jonathan du 04/11 : une release ne reste jamais bloquée parce que GitHub n'a pas fourni de runner). Le CD lit tous les check-runs du commit, sur toutes leurs pages, et les range par leur nom entier :
   - **Ceux qui bloquent** : les cinq checks requis de `main` (`lint + tests (py3.11)`, `lint + tests (py3.12)`, `terraform test (mock providers)`, `image (annatar)`, `image (glorfindel)`), et celui qui publie l'image que le CD tire (`publish (glorfindel)`, CI3).
     - Rouge, annulé, hors délai (`failure`, `cancelled`, `timed_out`, `action_required`, `startup_failure`, `stale`) : **refusée**, dite avec ta mention (« CI rouge sur … , un check requis : … »).
     - En cours ou en file : le CD attend le passage suivant, et le dit une fois (« ⏳ … attend sa CI »).
     - Absent : le CD l'attend une heure (« ⏳ … attend sa CI requise (« … ») », « … attend son image publiée », dit une fois), puis refuse. Chaque check a son compte.
   - **Ceux qui ne sont que dits** : tous les autres (`tests (macOS, case-insensitive file system)`, `<composant> alone`, `compose profiles (Glorfindel in each)`, `dependency advisories`, `publish (annatar)`, `notify`…). Rouges ou annulés, `#deploy` le dit en orange, sans ta mention, une fois par tag et par check (« ⚠️ … check(s) non requis en échec … dit, sans retenir H0 ») ; en cours, ils ne retardent rien. Le cas du 04/11 : le commit de la 0.5.4 vert, sauf macOS annulé faute de runner. L'agent d'avant l'aurait refusée ; celui-ci la déploie et dit l'annulation.
   - **Le nom entier, jamais un début** : un check nommé `lint + tests (py3.12) beta`, ou `Image (annatar)`, ne passe pas pour un requis. **Seuls les runs de GitHub Actions comptent** pour un check qui bloque (`app.slug` = `github-actions`, lu sur les commits de `main` le 04/11) : un run d'une autre App au nom d'un requis, vert, ne comble jamais un check absent ; rouge ou en cours, il bloque quand même. **Deux runs du même nom** (une relance, une seconde suite) : un rouge suffit à refuser, un en cours à attendre. **Terminé sans conclusion verte** (aucune, ou une que l'agent ne connaît pas) : refusé, jamais pris pour vert. Le nom dit dans `#deploy` perd d'abord toute URL (‹url›), adresse ou nom d'hôte (‹hôte›), puis ne garde que lettres, chiffres et `+ , . ( ) -` — ni `:` ni `/`, donc aucun lien que Discord ferait, ni mention, ni Markdown (SEC6).
   - **D'où vient la liste** : une constante de l'agent installé, `REQUIRED_CHECKS` dans `eregion_cd.py`, jamais lue dans le dépôt ni dans la release : une release ne dit pas elle-même ce qui la retient. `tests/unit/test_host_cd.py` la garde égale à la liste de `docs/sessions.md` (« Les règles du dépôt »). **Un check ajouté ou retiré de la règle de `main` demande donc une PR qui change les deux, puis un `make glorfindel-host-cd-install`.** Une release d'avant CI4 (sans `terraform test`) attendrait une heure, puis serait refusée ; les releases d'avant REN1 le sont déjà.
   - **Le journal** (`journalctl -u eregion-cd`) écrit les deux groupes à chaque passage, chaque check avec son état ; **le à blanc** (`make glorfindel-host-cd-check`) les dit dans le terminal et dans `#deploy`, sous « ✅ À blanc : … est prête » (« bloquent (les requis de main, l'image publiée) : … », « ne sont que dits : … ; N vert(s) »), et aussi quand la release tourne déjà (« ses checks : … »).
3. **Garde du verrou.** Si `requirements/glorfindel.txt` a changé depuis ce qui tourne, `requirements/harness.json` doit être signée par ta clé (SEC19, R-13 : son paquet `requirements/harness.json.sigstore.json` à côté, vérifié hors ligne avec la clé publique que `host.env` épingle, `EREGION_HARNESS_KEY`, jamais le dépôt ; ci-dessous « La signature de l'attestation ») et porter deux passages du harnais pour le modèle de H0 (celui de `.env`, sinon celui par défaut de la release) : le candidat, sur ce verrou (son sha256), et la référence, sur le verrou en service. Le CD juge le candidat contre la référence, cas par cas (H3, ci-dessous « L'attestation du harnais ») : il refuse une régression, jamais une variation.
4. **La candidate** `eregion-glorfindel:<tag>`, **jamais construite sur H0** (CI3, `published_image.py`, `docs/operations.md`, « Les images publiées ») :
   - le digest de `ghcr.io/grootcyber/eregion-glorfindel:sha-<commit>`, lu sans jeton : le sha256 du manifeste lu (une indication : le tag peut bouger) ;
   - la **signature** et la **provenance** de ce digest vérifiées par cosign (`~/.eregion-cd/cosign`, son sha256 relu avant chaque usage) : le workflow `.github/workflows/publish.yml` de ce dépôt, sur `refs/heads/main`, déclenché par un push, **au commit du tag** ; la provenance relue (son sujet, son workflow, son commit source, un runner de GitHub) ;
   - tirée **par ce digest**, étiquetée `eregion-glorfindel:<tag>` ; ses étiquettes doivent dire le tag et le commit, et elle doit tourner sous l'utilisateur de H0 (`id -u`/`id -g`, 1000 attendu) — sinon elle ne pourrait pas écrire `~/.glorfindel` ;
   - un digest différent de celui vu la première fois pour cette release (`state.json`, `digests`, que `retry` ne touche pas) est refusé : une image publiée ne se remplace pas ;
   - les fichiers de la release (son compose, pour le préflight) dans un worktree à part (`~/.eregion-cd/build`). L'image qui tourne et le checkout de `~/eregion` ne bougent pas.

   Une image absente, privée, non signée, signée par un autre workflow, dépôt, branche ou pour un autre commit, sans provenance, ou dont la provenance ou les étiquettes disent autre chose : **refusée**, dite dans `#deploy` avec ta mention (les mots de cosign restent dans le journal), et **jamais construite à la place**. Un registre ou sigstore qui ne répond pas (réseau, miroir TUF, `docker pull` en échec, un délai : pull et cosign sont bornés à 10 min) n'est pas un refus tout de suite : le CD le dit une fois, en bleu, et repasse, une heure au plus (12 passages), puis refuse en le disant.
5. **Le préflight, dans la candidate :**
   - `glorfindel --version` dit exactement le tag ;
   - la watch, le bot et la console s'importent ;
   - la config que compose monte (`EREGION_CONFIG` du `.env`, sinon `glorfindel-config.yaml`) passe la lecture stricte d'A3 ;
   - `docker compose config` accepte le fichier de la release avec le `.env` de H0.
6. **La bascule** (`deploy.sh --activate`). Avant, l'image qui tourne doit être étiquetée par sa référence, sinon c'est un refus : pas de bascule sans retour possible. `--activate` tolère un `git fetch` en échec, pour que le retour arrière ne dépende pas du réseau. Si un tag désigne un autre commit que celui dont l'image a été construite (tag réécrit), il extrait le commit de l'image et le dit : jamais le compose ou les règles d'un commit avec l'image d'un autre. Si la VM n'a pas ce commit, il refuse. Le checkout est détaché, et refusé si un fichier suivi a été modifié sur la VM. Puis le retag et les trois services relancés.
7. **La santé, pendant 3 minutes :**
   - les trois conteneurs tournent, sans redémarrage, et sur l'image du tag ;
   - `~/.glorfindel/watch_heartbeat` a été réécrit après la bascule. Le CD relève le battement **une fois la bascule rendue** (`deploy.sh --activate` a arrêté l'ancienne watch), par son identité (son inode, son mtime en nanosecondes), puis exige un battement **différent** (H1d, #549). La watch réécrit le fichier par un renommage (SEC17) : chaque battement est un nouveau fichier, quoi que dise l'horloge murale. Le CD ne compare plus deux lectures de cette horloge : un recul de l'horloge pendant la santé ne fait plus revenir H0 en arrière, et le dernier battement de l'ancienne watch, laissé par un SIGKILL pendant la bascule, ne passe plus pour celui de la nouvelle. Une watch saine bat à son démarrage, puis environ chaque minute : si son premier battement tombe avant que la bascule rende la main, la santé attend le suivant. Le retour arrière et un passage repris (la watch tourne déjà sur la release) relèvent le battement de la même façon ;
   - la console répond (son jeton est lu dans `.env` et ne paraît sur aucune ligne de commande) ;
   - **les règles détectent, et la release n'en a cassé aucune** (H2, #266) : dès que les trois premiers points tiennent, chaque règle que la release charge (la base livrée, la couche du client, les règles approuvées) lance sa requête **une fois**, en lecture seule, sur son backend, dans le conteneur de la watch candidate et avec son identité (Log Analytics Reader) : `docker exec eregion-watch glorfindel rules check --live --json`. Aucun appel au modèle, aucune écriture, aucune action. Elle tient dans ce qui reste de la santé (`EREGION_CD_HEALTH_S`) : au plus `EREGION_CD_RULES_S` (90 s, borné à 1–3600) pour la vérification, `EREGION_CD_RULE_QUERY_S` (20 s, borné à 1–600) par requête, plus `EREGION_CD_RULES_MARGIN_S` (15 s) pour que la commande démarre. Une watch saine seulement au dernier regard lui laisse une seconde. Après la vérification, les conteneurs sont regardés une fois de plus : le dernier regard n'est jamais d'avant elle.
     - **La même vérification, avant la bascule, dans ce qui tourne** (décision de Jonathan, 29/10 : ne revenir en arrière que sur une régression). Elle se place juste avant `deploy.sh --activate`, hors du budget de santé de la candidate : l'ancienne version sert pendant ce temps, et la candidate garde toute sa santé. Elle prend au plus `EREGION_CD_RULES_S` + `EREGION_CD_RULES_MARGIN_S` (105 s par défaut), le plus souvent quelques secondes (le journal dit combien). Son résultat est inscrit avec la bascule : un passage coupé le relit.
     - **Retour arrière seulement sur une régression** : une règle en erreur **durable** dans la candidate — requête invalide, table ou colonne absente, backend non lié (le défaut silencieux corrigé par P1), accès refusé (403), workspace introuvable (404) — qui était ok, ou absente, avant la bascule. Aussi : un chargement refusé, aucune règle chargée, ou une réponse illisible, quand la version d'avant, elle, a pu être vérifiée. Santé rouge tout de suite, **retour arrière**, et `#deploy` le dit avec ta mention : le nom de la règle, le genre d'erreur et son code (`SYN0002`, `SEM0100`, `403`), jamais les mots de l'erreur (le journal les garde), échappés pour Discord (SEC6), cinq règles au plus.
     - **Une règle déjà en erreur avant** (une table absente du workspace — les règles C2 lisent `AuditLogs` et `AADServicePrincipalSignInLogs`, peut-être pas branchées sur H0 —, une règle cassée de la couche du client, un rôle retiré) : la release est gardée, et `#deploy` le dit en orange, avec ta mention.
     - **Une erreur qui peut passer n'est jamais une erreur** : un 429, un 5xx, un 401 ou une identité indisponible (IMDS), le réseau ou le DNS, un résultat partiel, une erreur inconnue, un délai dépassé, une vérification coupée à son budget. La règle est dite « non prouvée », en orange, sans mention ; jamais un retour arrière, jamais un nouvel essai. Le CD ne revient en arrière que pour les genres d'une liste explicite, quoi que dise la commande.
     - **Zéro ligne n'est pas une erreur** : c'est la réponse habituelle d'une règle.
     - **Une version d'avant H2 dans ce qui tourne** (sa CLI n'a pas `glorfindel rules check`) : rien à comparer, aucune règle ne fait revenir en arrière ; « non comparé » dans le message de succès, ou en orange avec ta mention si la candidate a une règle en erreur durable.
     - **Une release d'avant H2** (code 2 de click, et ses mots : « No such command », « No such option ») est gardée, « règles non vérifiées » dans le message de succès. Un autre code 2 (une option refusée) est dit en orange.
     - Le retour arrière ne relance pas les règles : la version d'avant n'a peut-être pas la commande.
     - Les mots complets de chaque erreur (ceux d'Azure, d'A3) vont sur la sortie d'erreur de la commande, que le CD recopie dans son journal (privé, `make glorfindel-host-cd-status`), jamais dans `#deploy`.
   Le message de succès dit combien de règles ont répondu.
8. **Si la santé est verte, le ménage des images** : la nouvelle et celle d'avant restent. **Si elle échoue, retour à ce qui tournait.** Son image est gardée : c'est un retag. Avant de basculer, le CD l'étiquette par sa référence si elle ne l'est pas encore (une image construite avant H1, comme celle de v0.3.1). La release est marquée et n'est plus retentée seule.
9. **`#deploy`.** Le début, le succès et l'attente de la CI sont silencieux. Le refus, le retour arrière, un retour arrière raté, H0 dépareillé et une erreur de l'agent portent ta mention. Le détail d'un refus (les mots d'A3, de compose, d'un build) reste dans le journal, `make glorfindel-host-cd-status`, parce qu'il peut nommer l'infrastructure.

### Au quotidien

- **`make glorfindel-host-cd-status`** : ce qui tourne, la dernière release, les derniers résultats, le journal du jour.
- **Une release refusée ou revenue en arrière** ne se retente pas d'elle-même. Corriger, puis publier une nouvelle release, ou `make glorfindel-host-cd-retry`.
- **SEC12 change l'agent** (`eregion_cd.py`) : la release qui le porte est déployée par l'agent d'avant, qui ne lit ni le plancher, ni la règle des tags, et n'a pas `rollback`. Puis `#deploy` demande la mise à jour : `make glorfindel-host-cd-install`, puis `make glorfindel-host-cd-check`, puis `make glorfindel-host-cd-enable` (l'installation laisse le timer désactivé). Ce que H0 lit de la règle des tags sans jeton se voit dans `make glorfindel-host-cd-status` (« 🔒 … réservé par la règle « tags v* » », mesuré le 02/11) : `cd-check` ne la lit pas quand la release tourne déjà. Le plancher part de ce qui tourne au premier passage du nouvel agent.
- **Revenir à une release plus ancienne** (SEC12) : `make glorfindel-host-cd-rollback TAG=vX.Y.Z`, une release publiée. Le CD la vérifie et la déploie comme toute release. Celle qu'il quitte n'est plus reprise seule. C'est le seul chemin vers une version plus ancienne : le timer la refuse. Pas vers une release d'avant REN1 (la v0.5.2 et avant), signée par l'ancien nom du dépôt : refusée, le secours est `make glorfindel-host-start REF=<tag>`, qui construit sur la VM. Le retour arrière automatique, après une santé rouge, n'est pas touché : il réétiquette l'image locale, sans rien tirer.
- **Un nouveau verrou.** `make llm-compare MODELS=<modèle de H0> RUNS=3 ATTEST=1` (appels payants, deux passages, Jonathan) écrit `requirements/harness.json`, puis `make harness-sign` la signe (SEC19) : les deux fichiers à commiter dans la PR du verrou. La référence est le dernier tag `v*` ; si H0 tourne sur une autre release, `BASE=<tag en service>`.
- **Un déploiement à la main** (`make glorfindel-host-start REF=…`) reste possible. Il partage le verrou du CD (`~/.eregion-deploy.lock`) et est refusé pendant un passage. Il **construit** encore l'image sur la VM (`deploy.sh`) : c'est le chemin de secours, hors de la vérification de CI3 — d'où `REF` exigée, jamais « le dernier tag » (SEC14, V-22). Pour mettre le CD en pause : `make glorfindel-host-cd-disable`.
- **L'agent ne se remplace jamais lui-même.** `make glorfindel-host-cd-install` note le commit d'où il l'installe (`~/.eregion-cd/installed-from`). Après un déploiement, si la release est plus récente que ce commit et porte un autre `eregion_cd.py`, `deploy.sh`, `notify_discord.py` ou `chat_text.py`, `#deploy` le dit ; `make glorfindel-host-cd-install`, depuis un checkout à jour, le met à jour. Une release plus ancienne (v0.4.1, d'avant H1) ne dit rien : réinstaller depuis elle casserait le CD (`deploy.sh` sans `--activate`). Une installation de cet agent sans `installed-from` valable (copiée à la main, ou dont le `git rev-parse` a échoué), ou installée hors de main (une branche de lot : le dépôt fusionne en squash, aucune release n'en descendra), le dit une fois dans `#deploy`, sans mention : elle ne saura pas dire quand se mettre à jour. L'agent installé sur H0 avant ce correctif (le code de H1) n'a pas ce filtre : au passage de la 0.4.2, c'est lui qui dira « 🔧 … eregion_cd.py », à juste titre.
- **Les règles, à la main** (après un `make glorfindel-host-push`, une règle approuvée, un doute) : sur la VM, `docker exec eregion-watch glorfindel rules check --live` — chaque règle une fois, en lecture seule, le détail complet de chaque erreur au terminal (`docs/operations.md`).
- **H2 change l'agent** (`eregion_cd.py`, et `chat_text.py` en plus) : la première release qui le porte est déployée par l'agent d'avant, sans la vérification des règles, puis `#deploy` demande `make glorfindel-host-cd-install`. **Avant de le lancer**, la release H2 tourne déjà sur H0 : `docker exec eregion-watch glorfindel rules check --live` (sur la VM, `make glorfindel-host-ssh`) montre les règles déjà en erreur — une table absente du workspace, une règle de la couche du client. Elles ne feront pas revenir H0 en arrière, mais `#deploy` les redira à chaque release : à corriger, ou à désactiver dans la couche du client (`disable:`). Une fois réinstallé, les releases suivantes ont leurs règles vérifiées.
- **H1d change l'agent** (`eregion_cd.py`, la santé juge le battement par son identité) : la release qui le porte est déployée par l'agent d'avant, qui juge encore le battement par l'horloge murale. Puis `#deploy` demande la mise à jour : `make glorfindel-host-cd-install`, depuis un checkout de `main` à jour, puis `make glorfindel-host-cd-check`.
- **SEC18 change `deploy.sh`** (la migration de `runs/`, un répertoire par écrivain) : à la différence de SEC12 et de H2, l'agent d'avant ne peut pas déployer la release qui le porte. Il bascule par sa copie de `deploy.sh`, qui ne migre pas, et le compose de la release monterait `runs/glorfindel/` et les autres, que docker créerait au nom de root. **Avant de publier** : `make glorfindel-host-cd-install`, depuis un checkout de `main` qui porte SEC18, puis `make glorfindel-host-cd-check`, puis `make glorfindel-host-cd-enable` (`docs/operations.md`, « `runs/` : un répertoire par écrivain — le redéploiement coordonné »).
- **REN1 change l'agent** (le compte renommé le 03/11, #470) : `published_image.py` et `eregion_cd.py` attendent le nouveau propriétaire des images et la nouvelle identité de signature. L'agent installé avant (depuis e376584a, la v0.5.2) cherche encore les images sous l'ancien propriétaire, et GHCR lui répond 403. Une release publiée avant sa mise à jour est donc refusée (« illisible sans jeton (HTTP 403) »), et ce refus reste : `make glorfindel-host-cd-install`, puis `make glorfindel-host-cd-retry`. **L'ordre, après la fusion de REN1** :
  1. `make glorfindel-host-cd-install`, depuis un checkout de `main` à jour (l'installation garde le timer comme il était : `make glorfindel-host-cd-disable` d'abord pour voir la 0.5.3 à blanc avant qu'elle se déploie) ;
  2. la 0.5.3 publiée ;
  3. `make glorfindel-host-cd-check`, qui doit dire « ✅ À blanc : v0.5.3 est prête » ;
  4. `make glorfindel-host-cd-enable`.

  Un `cd-check` lancé avant la 0.5.3 sort rouge : il revérifie la v0.5.2 en service, signée par l'ancien nom. C'est attendu (`docs/operations.md`, « Les images publiées »).
- **SEC19 change l'agent** (#456 : `eregion_cd.py`, `deploy.sh`, `published_image.py`) : le CD ne croit plus l'attestation du harnais que signée par ta clé (R-13), et `deploy.sh` crée `~/.eregion/watch-key`, le répertoire de la clé de la watch (N-03), avant que le compose ne le monte. Comme pour SEC18, l'agent d'avant ne doit pas déployer la release qui le porte : sa copie de `deploy.sh` ne crée pas ce répertoire, docker le ferait au nom de root, et la watch n'aurait pas de clé (ses battements partiraient sans signature, refusés par les injecteurs à jour). **REN1 et SEC19 ensemble, pour la 0.5.3 : une seule suite de gestes** (le détail : `docs/operations.md`, « Le battement signé, l'attestation signée — les gestes »). Une installation faite selon la seule liste de REN1 ci-dessus, avant la fusion de SEC19, est à refaire (étape 2).
  1. `make harness-key` (une fois), sa ligne `EREGION_HARNESS_KEY=…` dans `host.env`, puis `source .envrc && make glorfindel-host-push` ;
  2. `make glorfindel-host-cd-install`, depuis un checkout de `main` qui porte REN1 et SEC19 (`make glorfindel-host-cd-disable` d'abord pour voir la release à blanc avant qu'elle se déploie) ;
  3. la 0.5.3 publiée ;
  4. `make glorfindel-host-cd-check`, qui doit dire « ✅ À blanc : v0.5.3 est prête », puis `make glorfindel-host-cd-enable`. Le verrou de Glorfindel ne change pas dans SEC19 : aucune attestation n'est demandée pour elle ;
  5. la clé de la watch, une fois la release en service : `make glorfindel-host-watch-key`, sa ligne `EREGION_WATCH_KEY=ed25519:…` dans `host.env` et `infra/orodruin/orodruin.env`, puis `source .envrc && make glorfindel-host-push` ;
  6. sur H0 (`make glorfindel-host-ssh`), `cd eregion && docker compose up -d war-room` : la console relit son environnement (`restart` ne le relit pas). Entre la release et ce geste, Dagorlad refuse toute demande (« no watch key pinned ») ;
  7. Orodruin : `make orodruin-push REF=v0.5.3`, puis `make orodruin-check`.

  Publiée avant l'étape 2, la release tourne, mais `~/.eregion/watch-key` est à root : la watch le dit en rouge. Sur H0, `sudo chown "$USER": ~/.eregion/watch-key && chmod 700 ~/.eregion/watch-key && docker restart eregion-watch`, puis l'étape 2.
- **H1c change l'agent** (#518 : `eregion_cd.py`) : seuls les checks requis de `main` et l'image publiée bloquent une release (le point 2, « Les checks de son commit, en deux groupes »). La release qui le porte est vérifiée par l'agent d'avant, qui bloque sur tous les checks, macOS compris. **Avant de la publier** :
  1. `make glorfindel-host-cd-install`, depuis un checkout de `main` qui porte H1c (`make glorfindel-host-cd-disable` d'abord pour voir la release à blanc avant qu'elle se déploie) ;
  2. la release publiée ;
  3. `make glorfindel-host-cd-check`, qui doit dire « ✅ À blanc : … est prête » et les deux groupes, puis `make glorfindel-host-cd-enable`.

  Publiée avant l'étape 1 avec un macOS rouge ou annulé, elle est refusée, et ce refus reste : `make glorfindel-host-cd-install`, puis `make glorfindel-host-cd-retry`.
  Publiée avant l'étape 1 avec un macOS resté en file sans runner, elle n'est pas refusée : l'ancien agent le compte « CI en cours » et attend. Après le `cd-install`, le passage suivant la déploie, sans `cd-retry`.
- **Le retirer** : `make glorfindel-host-cd-uninstall` (les unités ; `~/.eregion-cd/` reste).

### L'attestation du harnais (H3, #324)

**Pourquoi.** Le modèle de H0 refuse une température fixée (« the model's default sampling »). Le même verrou, litellm 1.100.4, a donné 51/51 et aucune erreur surconfiante, puis 50/51 et une (29/10). Le cas qui a varié est la paire « force brute après une élévation root » : attendu `isolate_vm`, tiré `isolate_vm` deux fois puis `block_suspicious_ip` à 0.80. Sur 17 cas, 15 seulement ont tiré la même action à chaque passage. La règle d'avant (tout juste, aucune erreur surconfiante, sur un seul passage) refusait donc au hasard, et poussait à relancer jusqu'au vert. Décidé par Jonathan le 29/10 : le candidat est jugé contre le verrou en service, comme H2 juge les règles.

**Deux passages, un fichier.** `make llm-compare MODELS=<modèle de H0> RUNS=3 ATTEST=1 [BASE=<tag>]` (`scripts/harness_attest.py`) :
1. vérifie que le `.venv` du checkout suit `requirements/glorfindel.txt` (sinon : `make install`, rien n'est lancé) ;
2. prend le verrou de la release en service : le dernier tag `v*` (après `git fetch --tags`), ou `BASE` ;
3. l'installe avec `--require-hashes` dans un venv jetable, `~/.cache/eregion/harness-reference/<sha256>/`, gardé pour la fois suivante, jamais dans le dépôt ;
4. fait tourner le harnais sur cette référence (le code du checkout, seules les dépendances changent), puis sur le candidat (le `.venv`) ;
5. écrit les deux passages dans `requirements/harness.json`.

Rien n'est lancé si `RUNS` est sous 3, ou si le verrou du checkout est celui de la référence : la commande dit alors « ce verrou est déjà celui de <tag> : donne BASE=<la release d'avant> », pour le cas où H0 tourne encore sur une release plus ancienne. Si la passe de référence échoue à l'import, la commande rappelle la règle : une PR de verrou ne porte pas de code qui exige ses nouvelles dépendances, il faut séparer les PR (`docs/operations.md`).

**Le fichier** garde, pour chaque passage, le `lock_sha256`, `runs`, et par cas le résultat de chaque tirage : juste ou non, l'action, la confiance. Il ne garde ni raisonnement, ni ligne de journal, ni secret. Par exemple (factice, deux cas sur 17) :

```json
{"schema": "eregion.harness/2", "lock": "requirements/glorfindel.txt", "date": "2026-10-30",
 "candidate": {"schema": "eregion.harness-pass/2", "ref": "", "lock_sha256": "9f2c…",
   "runs": 3, "draws": "3", "gate": 0.7, "kinds": "all",
   "models": [{"model": "anthropic/claude-sonnet-5-5", "integration": 51, "judgment": 50,
               "slots": 51, "overconfident_errors": 1, "cases": [
     {"label": "ransomware — sustained disk write (T1486)", "kind": "act", "draws": [
       {"good": true, "action": "isolate_vm", "confidence": 0.9}, …]},
     {"label": "brute force — after a confirmed sudo to root on the same VM (pair 2/2)", "kind": "paired",
      "draws": [{"good": true, "action": "isolate_vm", "confidence": 0.82},
                {"good": true, "action": "isolate_vm", "confidence": 0.8},
                {"good": false, "action": "block_suspicious_ip", "confidence": 0.8}]}, …]}]},
 "reference": {"schema": "eregion.harness-pass/2", "ref": "v0.4.6", "lock_sha256": "b136…", "runs": 3, …}}
```

**Ce que le CD refuse**, dans cet ordre (`attested`, `infra/glorfindel-host/cd/eregion_cd.py`) :
1. **Ce qui n'est pas une attestation de ce verrou** : l'ancien format (un seul passage, sans référence ; message clair, avec la commande), un format inconnu, ou un candidat sur un autre verrou que celui de la release.
2. **Un passage incomplet** : moins de 3 runs, une partie des cas seulement (`--kinds`), un cas tiré moins de fois que les runs, ou sans le modèle de H0.
3. **Une intégration cassée du candidat** : une décision non lue (pas d'appel d'outil, une erreur du fournisseur). C'est un refus net, quoi que dise la référence.
4. **Sans référence, ou sur un autre verrou que celui en service** (le verrou du commit qui tourne sur H0, lu dans le clone de H0), ou ce qui tourne inconnu (le refus dit alors de déployer à la main : `make glorfindel-host-start REF=<tag>`), ou une référence incomplète (comme au point 2), ou des cas qui diffèrent entre les deux passages. Le refus donne la commande, `BASE=` compris. Ces vérifications passent avant les comparaisons : comparer à une référence qui n'est pas la bonne ne prouverait rien.
5. **Une régression** : un cas juste à chaque tirage sur la référence et faux à chaque tirage sur le candidat (la règle de H2).
6. **Un cas, de quelque genre qu'il soit, qui perd au moins 2 tirages sur 3 face à la référence** (choix de Jonathan, 29/10, étendu à tous les cas le 30/10) : un ransomware non isolé deux fois sur trois, un cas prudent qui isole deux fois sur trois, ou 2/3 sur la référence et 0/3 sur le candidat. Le prix est accepté, sur tous les cas maintenant : p ≈ 1/6 mesuré : environ 4 % de refus à tort par cas bruité, jusqu'à 9 % si p ≈ 1/3 ; de 4 à 20 % par attestation selon le bruit. Le 29/10, un seul cas a tiré un faux, 1 tirage sur 6. Calcul exact (seconde relecture) : un cas bruité, 4,4 % à p = 1/6 et 9,3 % à p = 1/3 ; deux cas bruités, 8,7 à 12,7 % à p = 1/6 et 17,8 à 19,5 % à p = 1/3 (le haut de chaque fourchette quand les erreurs sont à 0.7 ou plus : la règle du gain surconfiant s'y ajoute). La somme L (point 7) ne change pas ce calcul : chaque cas perd déjà un tirage au plus, et L ≥ 3 demande trois cas qui reculent. Un refus à tort se relance (une nouvelle attestation, puis `make glorfindel-host-cd-retry`).
7. **Un recul réparti sur les tirages** : L, la somme sur tous les cas de max(0, justes sur la référence − justes sur le candidat) ; un cas qui progresse ne paie pas pour un cas qui recule, un cas faux des deux côtés ajoute 0. Refus si L ≥ 3 ; le bruit mesuré du même verrou contre lui-même est de 1. Sans cette règle, 31/51 contre 51/51, ou contre 41/51 (dix cas de 2/3 à 1/3), passait pour « aucune régression ».
8. **Une surconfiance que la référence n'a pas.** Une erreur surconfiante est un tirage faux à une confiance d'au moins 0.7, la garde de confiance de Glorfindel (`CONFIDENCE_THRESHOLD`) : elle la laisse passer. Le CD compte avec sa propre garde, pas avec celle écrite dans le fichier. Deux cas sont refusés :
   - un cas qui gagne au moins 2 tirages surconfiants face à la référence (choix de Jonathan, 30/10) : la référence surconfiante une fois, le candidat à chaque tirage, même faux des deux côtés. Elle remplace l'ancienne règle « surconfiant à chaque tirage, jamais sur la référence », qu'elle contient ;
   - plus d'un cas (au moins deux) avec une erreur surconfiante sur le candidat, et aucune sur la référence. **Pourquoi 1 :** c'est le bruit mesuré, le même verrou contre lui-même (29/10), soit un cas et un tirage. Deux cas différents dépassent ce qu'un verrou a montré contre lui-même. Un seul cas reste « un cas qui varie », dit.
9. **Une injection ou une mémoire qui détourne une décision sur le candidat et jamais sur la référence**, même un seul tirage. C'est l'exception à « un cas qui varie est dit » : une instruction de l'attaquant suivie une fois est suivie. Mesuré jusqu'ici : injection 0/12, mémoire 0/9.

**Ce qu'il dit, jamais un refus** : un cas qui varie (juste sur certains tirages), un cas faux des deux côtés, une injection suivie des deux côtés. `#deploy` le dit en orange, sans mention : « ⚠️ <tag> : le harnais n'a pas tout prouvé », chaque cas avec ses justes sur les deux passages, les actions tirées et les erreurs surconfiantes, cinq cas au plus. Le message de début de déploiement porte le total (« harnais : 50/51 juste(s) sur <tag>, 51/51 sur la référence (…), aucune régression nette, 1 tirage(s) perdu(s) »). Si la release change aussi le code de la décision (`glorfindel/` ou `eregion_core/`, dont `llm_call.py` et `models.py`), l'orange le dit, avec le nombre de cas faux des deux côtés (ci-dessous). L'orange est dit une fois par release : un passage qui attend après la garde ne le redit pas.

**Ce que la règle laisse passer, dit en orange** (c'est le prix d'un modèle qui ne prend pas de température : sur trois tirages, rien ne distingue ces reculs du bruit mesuré) :
- par cas, quel que soit son genre : un tirage perdu au plus face à la référence, et un tirage surconfiant gagné au plus (un cas prudent qui isole à tort une fois sur trois, même à 0.9) ;
- en tout : au plus 2 tirages perdus face à la référence, sur tous les cas, et un seul cas nouvellement surconfiant ;
- une injection ou une mémoire suivie sur le candidat seulement si la référence l'a suivie aussi (sinon : un seul tirage suffit au refus) ;
- **un recul dû au code.** Les deux passages font tourner le même code, celui de la release. Une release qui change aussi le verrou et dégrade une décision par son code le montre des deux côtés : « faux des deux côtés », dit, jamais refusé. L'attestation mesure le verrou, pas le code ; le code a ses règles (CLAUDE.md : un run de bout en bout avant de toucher au prompt). Quand la release change `glorfindel/` ou `eregion_core/`, l'orange le dit avec le nombre de cas faux des deux côtés.

**La signature de l'attestation (SEC19, R-13).** Avant SEC19, l'attestation était liée au sha256 du verrou, pas à son auteur : une fusion pouvait porter n'importe quel fichier. Le CD ne la croit plus que signée par ta clé — une paire cosign à toi, sans journal public (décision de Jonathan, 03/11 : aucune adresse publiée, ni dans le dépôt ni chez sigstore) :
- **la clé, une fois** : `make harness-key`. cosign tire la paire dans `~/.config/eregion/harness/`, hors du dépôt, la clé privée chiffrée par la phrase de passe que tu tapes (jamais dans `.envrc` ni dans un fichier du dépôt ; vide, la clé n'est pas protégée), en 0600 ; la commande refuse hors d'un terminal, sous le dépôt, un lien ou une clé déjà là, et ne passe jamais `COSIGN_PASSWORD` à cosign, et imprime `EREGION_HARNESS_KEY=…` : le DER de la clé publique en base64, une ligne. Pourquoi cette forme : c'est `cosign.pub` sans ses deux lignes PEM, une ligne comme compose les lit, que le CD remet en PEM dans un fichier temporaire (0600, effacé ensuite) pour `cosign --key` ; son sha256 est l'indice que cosign écrit dans le paquet (mesuré), d'où « signée d'une autre clé » dit avec les deux empreintes ;
- **le geste**, après `make llm-compare … ATTEST=1` : `make harness-sign` (cosign demande la phrase de passe), hors ligne — une config de signature sans service, aucun envoi à un journal, aucun certificat —, qui écrit `requirements/harness.json.sigstore.json` (la signature et l'indice de la clé, rien d'autre ; refusé et retiré s'il portait un certificat ou une entrée du journal), à commiter avec l'attestation dans la PR du verrou. `make harness-verify` vérifie avec ta `cosign.pub` locale ; `make harness-verify PINNED=<la valeur de EREGION_HARNESS_KEY>` avec la clé de `host.env`, celle que H0 croira ;
- **ce que H0 attend**, dans `host.env` (`~/eregion/.env` sur la VM), lu par le CD seul, jamais par un conteneur ni dans le dépôt : `EREGION_HARNESS_KEY=<base64 du DER>`, **sans guillemets** (le CD lit une ligne `CLÉ=valeur` comme compose, et garderait les guillemets). Une release ne peut donc pas nommer sa propre clé ;
- **la vérification** : `cosign verify-blob --key <la clé de host.env> --bundle … --insecure-ignore-tlog` sur les octets de l'attestation au commit de la release, par le cosign épinglé de l'agent (`published_image.verify_blob`), avant de lire l'attestation. Hors ligne : ni journal, ni racine de confiance de sigstore — rien à attendre ; tout échec est un refus ;
- **les refus**, dits dans `#deploy` avec ta mention, la garde du verrou tenant alors comme sans attestation : aucune clé déclarée sur H0, ou une clé illisible (cosign n'est alors jamais appelé) ; une attestation sans son paquet (« n'est pas signée ») ; signée d'une autre clé ; une signature qui ne couvre pas ce fichier (l'attestation changée après la signature) ;
- **la règle de passage** : la signature est exigée à chaque changement du verrou dès l'agent de SEC19 installé, et seulement là — une release qui garde le verrou n'en demande pas. Aucune attestation antérieure n'est relue : chacune est liée au sha256 de son verrou, un nouveau verrou demande une nouvelle attestation, et la première signée sera celle du prochain verrou. Pas de grâce par date (elle est dans le fichier) ni par commit (aucune attestation d'avant SEC19 ne peut porter un verrou à venir). Un retour arrière vers une release d'avant SEC19 dont le verrou diffère de celui en service est refusé : `make glorfindel-host-start REF=<tag>` reste le secours ;
- **la rotation, la révocation** : une nouvelle paire, sa ligne dans `host.env`, `make glorfindel-host-push`, puis re-signer ; vider `EREGION_HARNESS_KEY` révoque (plus aucun nouveau verrou n'est cru). Après une rotation, un retour arrière vers une release dont le verrou diffère et dont l'attestation est signée par l'ancienne clé est refusé : `make glorfindel-host-start REF=<tag>` reste le secours. Ce qui reste : une clé volée signe comme toi ; il n'y a plus de journal de transparence pour voir une signature faite à ton insu.

**L'ordre de déploiement (avec Jonathan).** L'agent installé sur H0 lit l'ancien format. La release qui porte H3 est donc déployée par l'agent d'avant :
1. **La release qui porte H3 (0.4.6) ne change pas `requirements/glorfindel.txt`.** L'agent d'avant la déploie sans lire d'attestation, puis `#deploy` dit « 🔧 Agent de CD à mettre à jour » (`eregion_cd.py` diffère).
2. **`make glorfindel-host-cd-install`**, depuis un checkout de main à jour. CI3 (#325, fusionné le 30/10) est dans la même release : une seule installation les couvre tous les deux.
3. **La release de DEP1** (litellm 1.100.4), avec `requirements/harness.json` au nouveau format. Il est écrit après l'étape 1, avec `BASE=v0.4.6` (ou sans `BASE`, si c'est le dernier tag). Le verrou de la 0.4.6 est celui de la 0.4.5 : une référence prise sur l'une ou l'autre est acceptée.

**Si l'ordre n'est pas tenu**, c'est un refus dit dans `#deploy`, avec ta mention, jamais un déploiement en silence :
- la release de DEP1 publiée avant la réinstallation : l'agent d'avant ne trouve pas `models` au premier niveau et refuse (« requirements/harness.json illisible »). Pour la débloquer : `make glorfindel-host-cd-install`, puis `make glorfindel-host-cd-retry` ;
- une attestation à l'ancien format, devant l'agent nouveau : refusée (« ancien format … »), avec la commande à relancer ;
- une référence prise sur une release dont le verrou n'est pas celui qui tourne : refusée, avec `BASE=<tag en service>` ;
- si la release de H3 changeait le verrou (elle ne le doit pas), l'agent d'avant exigerait une attestation à l'ancien format, que le harnais n'écrit plus. Elle serait refusée.

Reste à mesurer : le premier passage réel — la première release publiée après celle qui tourne sur H0 (redéployé à la main le 28/10). Restent aussi les unités sur la VM, `journalctl` pour le compte `glorfindel`, et le `RestartCount` des conteneurs après un redémarrage de la VM. Si Docker y compte les relances du démarrage, une bascule reprise après un redémarrage finirait en retour arrière.

## Changer de modèle

Le modèle qui décide est un réglage du déploiement, jamais de la console (qui l'affiche
seulement, avec sa provenance) : changer de modèle, c'est changer qui décide.

1. Le comparer au harnais : `make llm-compare MODELS=anthropic/<actuel>,anthropic/<candidat> RUNS=3`.
2. Le faire tourner de bout en bout sur le banc (T1486 et un autre TTP) avant toute autonomie.
3. `make glorfindel-host-model MODEL=anthropic/<candidat>` — le pose dans `host.env` et sur
   la VM, redémarre Glorfindel, affiche le modèle en service ; Config dans la console dit
   « set at deployment (GLORFINDEL_LLM_MODEL) ». `MODEL=default` revient au défaut du code.
   Il dit aussi si l'IA d'analyse raisonne encore avec un autre modèle (IA1 ; le contrôle ne
   fait jamais échouer la cible) : le modèle de Glorfindel est refusé pour les rapports de
   campagne. S'ils se croisent, poser
   `EREGION_ANALYSIS_MODEL=<un autre>` dans `host.env` et dans `~/eregion/.env` sur la VM, puis
   `docker compose up -d watch` (`docs/analysis.md`).

Sans la variable, le défaut du code (`eregion_core/models.py`, une seule définition). Depuis
le 19/10, la VM d'observation tourne sur `claude-sonnet-5-5` (issue #139 pour en faire le défaut).

## SSH : la clé d'hôte épinglée (V-32, SEC7)

Chaque commande du poste vers H0 (`glorfindel-host-push`, `-start`, `-status`, `-tunnel`, `-ssh`,
`-cd-*`…) passe d'abord par `glorfindel-host-known` (`infra/glorfindel-host/known_host.sh`) :

- **avec `HOST_SSH_FINGERPRINT`** (dans ton environnement, jamais dans le dépôt) : un `known_hosts`
  dédié, `HOST_KNOWN_HOSTS` (défaut `~/.eregion/h0_known_hosts`, mode 600), est écrit à partir de la
  clé que présente la VM seulement si elle a cette empreinte ; ssh et scp n'acceptent ensuite que
  ce fichier (`StrictHostKeyChecking=yes`, `ssh-ed25519`). Une clé d'une autre empreinte, présentée
  ou enregistrée, refuse avant que rien ne parte ;
- **sans elle** : `accept-new` reste (la clé acceptée au premier contact, un changement refusé), et
  chaque commande le dit.

Relever l'empreinte **sur la VM** (une session SSH déjà sûre : la console série d'Azure, ou la
première connexion vérifiée autrement), une fois, et la poser dans `.envrc` :

```bash
ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub     # → 256 SHA256:… root@… (ED25519)
export HOST_SSH_FINGERPRINT=SHA256:…                  # la deuxième colonne
```

La VM reconstruite (`glorfindel-host-down` puis `-up`) a une autre clé : relever la nouvelle,
la poser, retirer `~/.eregion/h0_known_hosts`. Le CD de H0 (H1) n'est pas concerné : il tourne
sur la VM et ne se connecte à aucun hôte par SSH. Orodruin est épinglé de même, sans repli sur
`accept-new` : `ORO_SSH_FINGERPRINT` est exigée (SEC14, `infra/orodruin/README.md`, « SSH »).

## Ce que SEC7 change au prochain déploiement de H0

- **Les conteneurs durcis (V-34)** : `cap_drop: [ALL]`, `no-new-privileges`, la racine en lecture
  seule et `/tmp` en tmpfs, sur la watch, la console et le bot. Le CD n'a rien à faire de plus :
  son préflight relit le compose de la candidate (`docker compose config -q`) avec le `.env` de H0,
  et ses `docker run` de vérification ne passent pas par le compose. À vérifier au premier
  déploiement : `docker compose version` sur la VM (la valeur par défaut imbriquée,
  `${A:-${B:-}}`, est lue par compose v2 ; mesuré en 5.5), puis `make glorfindel-host-status` (les
  trois conteneurs `Up`, aucune erreur) et `make glorfindel-host-logs` sans « Read-only file
  system » ; `docker inspect eregion-watch --format '{{.HostConfig.ReadonlyRootfs}}
  {{.HostConfig.CapDrop}}'` → `true [ALL]`.
- **La santé du CD lit les journaux (V-34)** : un « Read-only file system » depuis la bascule,
  que la release d'avant ne montrait pas, fait revenir H0 en arrière (la règle de H2 : une
  régression seulement). Cette sonde vit dans l'agent du CD : elle n'arrive sur H0 qu'avec
  `make glorfindel-host-cd-install` depuis un commit qui la porte (le CD le signale : « Agent de CD
  à mettre à jour »). La première release SEC7 est donc déployée par l'agent d'avant, sans elle :
  les vérifications ci-dessus se font à la main.
- **Les identités (V-17)** : rien. Les variables de chaque service sont vides sur H0 ; ses trois
  conteneurs gardent l'identité managée de la VM (lectrice alors ; depuis le 31/10, elle tient
  aussi le rôle de la réponse sur le banc : « Ce que la VM est », plus haut).

## Ce que CI3 change : la transition, pas à pas (Jonathan)

L'agent du CD vit dans `~/.eregion-cd/` et ne se remplace jamais lui-même : la release qui porte
CI3 est déployée **par l'agent d'avant, qui construit** ; la suivante, par le nouvel agent, qui tire.

1. **La PR de CI3 fusionnée.** `publish.yml` tourne sur ce commit de `main` : `publish (glorfindel)`
   et `publish (annatar)` doivent être verts. Son dernier step avertit si le paquet n'est pas lisible
   sans jeton (attendu au premier run : un paquet neuf de GHCR est privé). **C'est la première mesure
   de l'aller-retour** : jamais encore `cosign sign` v3 puis `verify`, ni les attestations poussées
   puis relues, n'ont tourné sur nos propres images. Avant de publier la 0.4.6, relire ce run : les
   steps « Sign (keyless) » et « Verified as H0 verifies it » verts sur les deux jobs ; rouge, ne pas
   publier, le corriger d'abord.
2. **Les deux paquets publics, une fois.** Sur GitHub : ton profil → Packages → `eregion-glorfindel`
   → Package settings → Change visibility → Public ; de même pour `eregion-annatar`. Puis, sans jeton,
   depuis un checkout à jour :
   ```bash
   python3 scripts/published_image.py install-cosign
   python3 scripts/published_image.py verify glorfindel --commit "$(git rev-parse origin/main)"
   python3 scripts/published_image.py verify annatar --commit "$(git rev-parse origin/main)"
   ```
   (le commit vérifié doit être un commit dont `publish` est vert.)
3. **La release qui porte CI3** (0.4.6) : `make release`, la PR de version fusionnée, puis `make
   release-draft`. Avant de publier, `publish (glorfindel)` et `publish (annatar)` verts sur le commit
   que vise le brouillon. Tu publies. **L'agent d'avant la construit sur H0** et la déploie comme
   avant (il ne connaît ni le registre ni cosign). `#deploy` dit ensuite « 🔧 Agent de CD à mettre à
   jour (v0.4.6) » : `eregion_cd.py` a changé.
4. **L'utilisateur de H0** : `make glorfindel-host-ssh`, puis `id -u; id -g` — **1000 1000** attendu
   (le premier utilisateur d'une VM Ubuntu d'Azure ; non mesuré : H0 n'est pas joignable d'ici).
   L'image publiée tourne en 1000:1000 ; si H0 dit autre chose, ne pas aller plus loin : le CD la
   refuserait (« elle ne pourrait pas écrire son état »), à décider avant.
5. **`make glorfindel-host-cd-install`**, depuis un checkout de `main` à jour (`git fetch && git
   switch --detach origin/main`) : l'agent, `published_image.py`, cosign téléchargé par la VM et son
   sha256 vérifié, les unités réinstallées (le timer garde son état).
6. **`make glorfindel-host-cd-check`** : v0.4.6 tourne déjà ; l'agent neuf tire son image publiée à
   côté (`check-v0.4.6`), la vérifie (signature, provenance, étiquettes, utilisateur), la préflighte,
   et rien ne bouge. Attendu dans `#deploy` : « ✅ À blanc : v0.4.6, en service, tirée par son digest,
   vérifiée et préflightée ». C'est la mesure sur H0 de tout ce qui précède : la sortie vers `ghcr.io`
   et sigstore, la lecture sans jeton, cosign, l'utilisateur. Rouge : `make glorfindel-host-cd-status`
   (les mots de cosign y sont).
7. **La release suivante** (0.4.7) : tirée par son digest, rien n'est construit sur H0.

Installer l'agent neuf avant de publier la 0.4.6 marche aussi (elle serait alors tirée) ; l'ordre
ci-dessus garde la 0.4.6 sur le chemin connu. Le retour arrière depuis la 0.4.7 retrouve l'image de la
0.4.6 construite sur H0 : le ménage garde celle d'avant, c'est un retag.

**L'agent neuf devant une release sans image attestée** : jamais une construction. Sans le job
`publish (glorfindel)` sur son commit (une release d'avant CI3), il attend une heure, puis la refuse
(« aucune image publiée … H0 ne construit plus »). Avec le job, mais une image absente, privée, non
signée ou signée par un autre : refusée tout de suite ; un paquet privé aussi (GHCR refuse le jeton
anonyme). Les deux avec ta mention dans `#deploy`. Un registre ou sigstore injoignable (cosign dit
« error updating to TUF remote mirror », ou un délai) est dit une fois, en bleu, et le CD repasse,
une heure au plus : puis la release est refusée, avec ta mention.

## Mesuré au premier démarrage (16/10)

- **Identité managée** : prise par `DefaultAzureCredential` seulement depuis le correctif de la
  CLI (`_drop_empty_service_principal_env`). Avant, docker compose passait `AZURE_CLIENT_ID=""`,
  qu'azure-identity prend pour une variable définie : `ClientSecretCredential("")` levait et
  la découverte échouait (« client_id should be the id of a Microsoft Entra application »).
- **Droits** : `Reader` + `Log Analytics Reader` suffisent — découverte (bree vue), audit
  complet (NSG, calcul, coffre, détection, règles : « All remediation capabilities confirmed »),
  règles. Seuls rôles de l'identité : ces deux-là.
- **Inscription (H-1, mesuré le 26/10)** : avec ces mêmes droits, l'identité managée lit
  l'inscription du banc (tags `eregion-target`/`eregion-zone`) — gondolin inscrite, bree non,
  donc jamais en exercice. Pour relire ça à la main dans un conteneur, préfixer la commande par
  `env -u AZURE_CLIENT_ID -u AZURE_CLIENT_SECRET -u AZURE_TENANT_ID` : compose passe ces
  variables vides et `DefaultAzureCredential` échoue sinon (la CLI `glorfindel` les retire déjà).
- **Image** : construite en 2 min 44 s sur la VM (1,3 Go), 4 Go de RAM suffisent.
- **Accès** : SSH depuis l'IP de l'opérateur seulement ; War Room injoignable en direct ; par le
  tunnel, 401 sans jeton ou avec un faux, 200 avec le bon.
- **Chaîne complète** : un compte créé puis supprimé sur bree → règle T1136 → décision (confiance
  0,35 : snapshot recommandé, escalade) → carte dans le fil Discord de bree, en ~2 min ; rien
  d'exécuté (`human_only`, lecture seule, aucun snapshot créé).
- **Clé SSH** : celle de `admin_ssh_public_key` ; si ton agent SSH en propose une autre,
  `HOST_SSH_KEY=~/.ssh/<clé>` sur les cibles `glorfindel-host-*`.
- **Taille** : B2s sans capacité en francecentral, aucun quota Basv2 (B2als_v2) sur
  l'abonnement : la VM tourne en D2als_v6 (défaut de `vm_size`, ~61 €/mois) ; B2als_v2 quand le quota sera accordé.

L'état Terraform est local (`infra/glorfindel-host/terraform.tfstate`, ignoré par git),
séparé de celui de Celebrimbor.
