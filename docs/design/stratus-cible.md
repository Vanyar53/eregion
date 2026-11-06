# Stratus — l'abonnement de test dédié et la cible (R2b)

_Conception — 2026-11-06 (v4 — identité et zone **tranchées par Jonathan le 06/11**, après les relectures Opus 5.5 v1 `blocking` et v2 `changes`) — statut : **conception, à relire avant tout code** (R2b, #608, « Partie de #79 »). Fait suite à R2a (fusionné le 06/11, `3f6ae335`)._

## La décision (Jonathan, 06/11, en interactif)

**Stratus tourne dans un abonnement de test dédié, unique et permanent**, où **rien d'autre ne vit** : ni H0, ni Orodruin, ni le canari, ni `rg-celebrimbor`. La cible d'une technique est le groupe que crée son `warmup` **dans cet abonnement**. Cette décision remplace celle du matin (le groupe dans l'abonnement du banc partagé), cassée par la relecture v1 : sous l'identité d'Orodruin, créer/détruire un groupe dans l'abonnement partagé demandait des droits qui atteignaient tout le banc, et un « droit de tag étroit » ne bornait rien.

**Ce que l'abonnement dédié règle, et ce qu'il ne règle pas.** Le périmètre devient l'abonnement entier : **plus de tag d'inscription** (donc plus de `tags/write`, plus d'ABAC) — appartenir à l'abonnement dédié *est* l'inscription. Mais **l'abonnement vide n'est pas, à lui seul, un garde-fou** : un rôle large (Contributor) y permettrait encore d'aveugler la watch (supprimer le paramètre de diagnostic), de supprimer l'alerte de budget, de créer des ressources coûteuses, de créer une identité managée à credential fédéré (persistante dans le tenant), ou d'ouvrir une sortie Internet par une VM pilotée en Run Command — ce qui contournerait « Orodruin sans Internet ». Le garde-fou est donc **un rôle personnalisé fermé + une Azure Policy** sur l'abonnement dédié (§ 1, § 6), pas la seule vacuité. Le blast radius est l'abonnement dédié **borné par ce rôle et cette policy**.

Le coût d'un abonnement est nul en lui-même ; l'ingestion d'`AzureActivity` dans un workspace est **gratuite** (`infra/terraform/activity_log.tf`). Le seul risque est un `cleanup` raté qui laisse des ressources payantes — l'**Azure Policy** (types/SKU/régions) en est le vrai plafond, l'alerte de budget n'étant qu'une notification (évaluée avec 8–24 h de retard).

Le cycle de R2a est inchangé — `warmup → detonate → revert → cleanup` ; R2b change **où** il tourne et **comment la watch l'observe**.

---

## 1. L'identité qui agit (B — identité dédiée + bac à sable), et le contrat

### La décision : une identité propre à Stratus, dans un bac à sable (Jonathan, 06/11)

**Stratus n'agit pas sous l'identité d'Orodruin.** Une **seconde identité**, dédiée à Stratus, porte un **rôle personnalisé fermé sur le seul abonnement dédié** (jamais Contributor ; `NotActions` : `diagnosticSettings/write`+`/delete` — la lecture reste, pour le contrat (b) —, `Consumption`/`CostManagement`, les credentials fédérés — § 6). Stratus, son Terraform et azurerm tournent dans un **bac à sable qui ne peut pas obtenir le jeton propre d'Orodruin** : Stratus n'a aucune entrée de cible, seul le RBAC le borne, donc son identité doit être strictement la sienne.

**Le mécanisme du bac à sable est une hypothèse à mesurer au banc** (écrite comme telle) : soit un conteneur ou un espace réseau avec un **proxy de jeton limité au `client_id` de Stratus**, soit une fédération « identité managée comme credential » d'une application. **Mesure, avant le code** : depuis le bac à sable, une **demande de jeton pour l'identité d'Orodruin doit échouer**.

**À écarter explicitement** : une UAMI attachée à la VM **sans** bac à sable n'isole rien (le bac à sable pourrait demander le jeton propre d'Orodruin) — ce n'est pas la solution. Le danger est **à sens unique** : seul le sens **bac à sable (Stratus) → jeton d'Orodruin** est à interdire. Le sens inverse est **voulu** — le processus d'Orodruin, **hors du bac à sable**, détient le jeton de Stratus pour lancer l'outil et pour les lectures du contrat (ci-dessous). L'identité de Stratus **vit dans le tenant**, comme tout principal ; l'invariant porte sur ce qu'elle **fait**, pas sur où elle existe.

L'identité distincte donne un **appelant distinct** dans `AzureActivity`, ce qui fonde un invariant à écrire : **une identité Stratus vue agir hors de l'abonnement dédié = critique** (N5).

### Ce que le contrat doit faire — et avec quel jeton il lit (N1)

Le contrat d'Orodruin pour **sa propre identité reste quasi tel quel** (`orodruin.py:226-227`). Mais `orodruin-check` doit **lire** l'abonnement dédié pour l'armer (les attributions de Stratus, le paramètre de diagnostic, les groupes à COLD), et `read_identity` lit avec le **jeton d'Orodruin** : sans aucun droit là, il prend un 403 — ou pire, une **liste vide** qu'il croirait prouver une absence (le bug M191). D'où un partage des lectures, **par jeton**, qui ne demande aucune décision de Jonathan :

- **(a) les attributions de Stratus** (prouver que son identité ne tient qu'un rôle fermé, sur ce seul abonnement) se lisent avec le **jeton d'Orodruin** : son identité reçoit, **sur l'abonnement dédié seulement**, exactement `AUTHZ_READ_ONLY` (`roleAssignments/read`, `roleDefinitions/read`) — le **seul** droit que le contrat **inchangé** admet déjà hors du banc (`orodruin.py:105-108, 322-324`). Rien d'autre pour l'identité d'Orodruin là-bas.
- **(b) le paramètre de diagnostic et les groupes (COLD)** se lisent avec le **jeton de Stratus**, par le processus d'Orodruin **hors du bac à sable** (sens voulu, § décision). Le rôle fermé de Stratus contient donc `Microsoft.Insights/diagnosticSettings/read` et `…/resourceGroups/read` ; et son `NotActions` sur les paramètres de diagnostic se resserre de `*` à **`write` + `delete`** (lire oui, modifier/supprimer non — Stratus ne peut pas aveugler la watch).
- **l'absence ailleurs** (le banc, l'abonnement de la VM : l'identité Stratus n'y tient rien) se lit avec le **jeton d'Orodruin**, filtré `assignedTo('<oid de Stratus>')`.
- **Rôle fermé (SEC11)** : jamais un joker, **aucune action `Microsoft.Authorization` sauf `roleAssignments/read` et `roleDefinitions/read`** (N6) ; les actions d'attaque minimales par technique, mesurées au banc (§ Questions).
- **Refuser si `EREGION_STRATUS_SUBSCRIPTION` vaut l'abonnement du banc, celui de la VM, celui de H0 ou celui de la VM d'Orodruin** : sans ce refus, une ligne d'`orodruin.env` ramènerait le bloquant v1. `orodruin-check` → `passive`.
- **Les autres abonnements du tenant restent improuvables** (la lecture ne prouve l'absence que sur l'abonnement dédié, le banc et la VM).

**À mesurer** : que le jeton d'Orodruin, avec `AUTHZ_READ_ONLY` sur l'abonnement dédié, liste bien les attributions de Stratus (et non un 403 ou une liste vide trompeuse).

### Le kill coupe l'identité Stratus seule (constat 2, N3)

`orodruin-kill` ne révoque aujourd'hui que les scopes du contrat et de la VM : il ne toucherait pas le rôle de l'identité Stratus sur l'abonnement dédié. Mais **Orodruin ne peut pas le révoquer lui-même** : sur l'abonnement dédié il n'a que `AUTHZ_READ_ONLY` (lecture), et le rôle fermé de Stratus n'a aucun `Authorization/*/write`. La révocation est donc un **geste de l'opérateur** (sous son `az login`), que `kill.py` outille :

- `kill.py` reçoit l'**oid de Stratus** et l'**abonnement dédié** (en arguments ou depuis une sortie Terraform), jamais en dur ;
- la **révocation** = l'opérateur supprime l'attribution de l'identité Stratus sur `EREGION_STRATUS_SUBSCRIPTION` ;
- la preuve **« rien à révoquer »** = la liste de l'opérateur `az role assignment list --all --assignee-object-id <oid de Stratus> --subscription <dédié>` (le patron M191 : **`--all`** pour attraper une attribution posée sur un groupe, **`--subscription`** pour viser le bon abonnement) ;
- des mutants.

---

## 2. La garde, l'abonnement du sous-processus, la fenêtre, la watch, le kill

### L'abonnement vient de la config, jamais du banc (constat 7)

`stratus_host.py:_env` passe tout `os.environ` au sous-processus, donc `AZURE_SUBSCRIPTION_ID` = le banc ; `_run_stratus` retombe aussi dessus (`engine.py`). R2b doit :

- l'abonnement de Stratus vient **seulement** de `EREGION_STRATUS_SUBSCRIPTION` ;
- l'environnement du sous-processus **remplace** `AZURE_SUBSCRIPTION_ID` et `ARM_SUBSCRIPTION_ID` par l'abonnement dédié (noms exacts à mesurer ; un 403 attendu si on vise l'abonnement du banc) ;
- le repli sur l'abonnement du banc **disparaît**.

### La garde — zone `bench` réservée, posée par le scope (Jonathan, 06/11)

Le moteur Stratus a son propre `Scope`, borné à l'abonnement dédié (`EREGION_STRATUS_SUBSCRIPTION`), construit par lui seul — **jamais** le chemin VM, qui garde `Scope.for_bench()` et `rg-celebrimbor`. `Scope.check` autorise toute ressource de cet abonnement et refuse le reste. Les deux périmètres sont disjoints (abonnements différents).

**Zone : `bench`, réservée, posée par le scope Stratus lui-même — sans étiquette.** `ZONES`, `check_zone`, `Scope.for_bench()` et O0 restent **inchangés** (`inscription.py:77, 224-236`) — une zone étiquetable (une zone `stratus` lue d'un tag) rouvrirait `enrollment()`, ce qu'on ne veut pas. Le scope impose `bench` ; en plus, le scope Stratus **refuse explicitement `kind: fault`** (sans quoi `check_zone("bench")` accepterait une panne) : Stratus ne joue que des techniques, jamais une panne. Un champ **« périmètre » (`stratus-subscription`)** dans la fenêtre d'exercice et le rapport distingue les runs Stratus des autres.

### La fenêtre — une seule, avant le `warmup`, sur l'abonnement (constats 3, 4)

Ma v2 « affinait » la fenêtre au groupe une fois son nom connu : **c'est interdit** (SEC14, `exercise.py:247-267` ; `_fields` ne laisse changer que `end`, `closed_by`, `channel_created` — réécrire la cible refuse la fenêtre et compte le run comme réel). Correction :

- **une seule fenêtre**, ouverte **avant le `warmup`**, ciblant **l'abonnement dédié**, et rien d'autre. L'abonnement étant dédié, cette cible est **exacte**, pas « large ». Le **nom du groupe** créé va au **rapport** (pour l'indice de remise en état), **pas** dans la fenêtre.
- Une fenêtre qui **nomme un abonnement** est une **nouvelle primitive** côté lecteur (H-1) : aujourd'hui `_targets` compare des identifiants exacts. La watch doit tenir l'identifiant de l'abonnement dédié **de sa propre configuration sur H0**, **jamais** de la fenêtre, et **refuser** s'il vaut l'abonnement du banc — sinon une fenêtre nommant `/subscriptions/<banc>` étiquetterait tout le banc « exercice » pendant 2 h 15.

### La watch étiquette sur le `SubscriptionId` (constat 5)

Aujourd'hui `RowAttribution` (`detection_rules.py:1158-1163, 1327-1329`) lit le `_ResourceId` d'une VM : hors des actifs découverts, une ligne de VM part `named=True, target=None` et `_route` la jette en silence ; une ligne sans VM (Bastion, groupe) part « non attribuée », `resource_id` vide, et `source_of` répond `unknown`. L'opération de `azure.execution.vm-run-command` — la technique principale — n'atteindrait jamais l'étiquetage. R2b doit, côté watch :

- nommer **`RowAttribution`, `_route` et `source_of`** comme points de changement ;
- poser l'étiquetage « exercice » sur le **`SubscriptionId`** de la ligne (quand il vaut l'abonnement dédié **tenu par la config de H0** et qu'une fenêtre est ouverte), pas sur un `resourceId` de VM ;
- **(N7, recommandé) exiger aussi l'appelant Stratus** sur la ligne : l'étiquette « exercice » ne vaut que pour `SubscriptionId == <dédié>` **et** l'appelant = l'identité de Stratus — pas pour un tiers qui agirait dans l'abonnement ;
- **(N4)** la watch passe aussi par `is_enrolled` et `zone_allows` (`exercise.py:522-556`) : l'inscription et la zone `bench` de l'abonnement dédié viennent de la **config de H0**, jamais `production` ;
- **(N8)** la watch **refuse** comme cible d'une fenêtre non seulement l'abonnement du banc, mais aussi celui de **H0** et celui de la **VM d'Orodruin** — tenus de sa config, jamais de la fenêtre ;
- lister les règles **AL1** qui vont tirer sur le `warmup`/`cleanup` : p. ex. `nsg-change-outside-glorfindel` sur le NSG que crée la technique (carte critique) ;
- dire qu'**aucune règle actuelle** ne détecte Run Command, ni le lien Bastion par un autre appelant — c'est ID1, mais à écrire. Les lignes `AzureActivity` de l'abonnement dédié sont des **données contrôlées** par qui agit dedans ; AL1 décide **sans modèle**, à garder ainsi.

### Le kill — révoquer, puis vider l'abonnement (constats 2, 9)

`orodruin-kill` révoque l'identité **d'Orodruin** (banc, VM) et ferme les fenêtres ; le rôle de l'identité **Stratus** sur l'abonnement dédié est révoqué par l'**opérateur** (§ 1, le kill — Orodruin n'y a que la lecture). Le nettoyage de l'abonnement dédié **ne peut pas** non plus passer par `stratus cleanup --all` depuis le poste de l'opérateur : l'état Terraform de Stratus vit dans le `HOME` d'Orodruin, que le kill vient de désallouer — il n'y a plus d'état. Le bon geste, rendu possible par l'abonnement dédié : **vider l'abonnement** — `az group list --subscription <dédié>` puis `az group delete` de chaque groupe **hors de la liste des groupes qu'Azure crée lui-même** (§ 4), sous le `az login` de l'opérateur, et vérifier qu'il est vide.

---

## 3. Le journal d'activité, le paramètre de diagnostic, sa fraîcheur (constat 10)

Pour que la watch voie les techniques **sans droit sur l'abonnement dédié** : un **paramètre de diagnostic** sur l'abonnement dédié route sa catégorie `Administrative` d'`AzureActivity` vers le **Log Analytics workspace du banc** (celui que H0 lit déjà en `Log Analytics Reader`, `infra/glorfindel-host/main.tf:208-210`). Le pont est à sens unique ; H0 n'a aucun droit sur l'abonnement dédié.

Mais **ce workspace est jetable** (il part avec `celebrimbor-down`) : le paramètre pointerait alors sur un workspace détruit et la watch serait **aveugle sans le savoir**. R2b doit donc :

- une **preuve de fraîcheur par run** : l'**événement de création** du `warmup` doit être **vu dans `AzureActivity`** ; sinon le rapport le dit (détection non mesurée, canal muet) ;
- une ligne d'`orodruin-check` qui **lit le paramètre de diagnostic** (présent, pointant un workspace vivant) comme une garantie.

L'ingestion d'`AzureActivity` est **gratuite** (pas « marginale »).

---

## 4. Les majeurs

- **Gabarit de nom et adresse Terraform par technique, au catalogue.** `<resource_prefix>-rg-<correlation.short>` et l'adresse `azurerm_resource_group.lab_environment` **diffèrent par technique** ; le préfixe **n'est pas configurable** côté Stratus. Chaque entrée `engine: stratus` déclare son `resource_prefix` et l'adresse Terraform ; l'adaptateur lit l'état à cette adresse pour relever le groupe (→ rapport, indice de remise en état). La garde n'en dépend pas (périmètre d'abonnement).
- **`HOME` propre au run, avec le Terraform stagé lié et revérifié.** Un répertoire de travail neuf par run (état Stratus indépendant), **recevant** le binaire Terraform stagé (copie ou lien) **avec revérification de son empreinte** comme pour le binaire Stratus (R2a). Le cache de plugins reste stagé et partagé (hors-ligne).
- **`COLD` avant `warmup`, et après `cleanup` (constat 8).** « Appartenir = inscription » suppose « rien d'autre ne vit dans l'abonnement » — **une hypothèse à mesurer**, pas un acquis : à l'armement, à COLD **avant chaque `warmup`**, et **après le `cleanup`** (sonde absente de la v2). Avec une **liste fermée des groupes qu'Azure crée lui-même** (`NetworkWatcherRG` naît avec un VNet ; Defender / `DeployIfNotExists` peuvent créer `DefaultResourceGroup-*`). Un groupe de plus de `MAX_RUN_S` **sans fenêtre vivante** est un orphelin : **`createdTime` suffit** (pas d'étiquette d'expiration). **Un seul run Stratus à la fois** dans l'abonnement dédié (COLD l'implique).
- **Le lien Bastion masqué (constat 12).** Le secret imprimé par `create-bastion-shareable-link` est un **lien partageable de Bastion** — un accès porteur. Le masquage couvre l'affichage de `stdout` (`stratus_host.py:168`), l'erreur de `stderr` (`stratus_host.py:164-167`) **et** le rapport. Ces endroits sont nommés dès la conception.
- **Le timeout du `warmup` (constat 13).** Le `warmup` du Bastion (VNet + VM) frôle souvent `PHASE_TIMEOUT_S = 900` ; un timeout tue `stratus` et peut laisser tourner `terraform` et un verrou d'état. À mesurer par technique ; relever le plafond pour ces techniques si besoin.

---

## 5. La technique FIC sort du périmètre de R2b

`azure.persistence.backdoor-managed-identity-fic` **ne touche aucune application** (ma sonde de R2a était fausse) : elle demande des écritures d'annuaire privilégiées et des attributions de rôles, que le contrat refuse à raison. Elle **reste `planned`**, **hors R2b**. À corriger au code : **retirer/corriger sa `graph_probe`** du catalogue (ajoutée à tort en R2a). Aucun droit Graph d'écriture n'entre dans R2b ; les techniques Entra reviendront dans un lot dédié.

---

## 6. Les gestes de Jonathan — en Terraform (constat 11)

Tous **manuels** (une session n'applique jamais) ; le plan montré avant. **En Terraform plutôt qu'`az`** (plan, réversibilité, trace — convention du dépôt) : le rôle personnalisé + son attribution et le paramètre de diagnostic dans `infra/orodruin` (variable vide par défaut) ; le budget via le module `activity_log` avec un **alias de fournisseur** sur l'abonnement dédié. Valeurs réelles jamais dans le dépôt (variables).

1. **L'abonnement de test dédié**, vide, **dans le tenant d'Orodruin**. Vérif : `az account show --subscription <id>` répond, `az resource list --subscription <id>` est vide. Enregistrer **d'avance** les fournisseurs de ressources qu'un rôle étroit ne laissera pas s'enregistrer (azurerm en enregistre beaucoup à l'`init`).
2. **Le rôle personnalisé fermé + son attribution** (jamais Contributor), au scope `/subscriptions/<id>` :
   - `Actions` = la liste minimale mesurée par technique ; **`NotActions`** = `Microsoft.Insights/diagnosticSettings/*` (écriture/suppression), `Microsoft.Consumption/*`, `Microsoft.CostManagement/*`, les credentials fédérés ;
   - attribution avec `--assignee-object-id <oid> --assignee-principal-type ServicePrincipal` ;
   - **Vérif (le piège M191, N2)** : `az role assignment list --all --assignee-object-id <oid> --subscription <id>` (comme `kill.py:124-127`) — **`--all`** pour attraper une attribution posée sur un **groupe** (sans lui, elle échappe), **`--subscription`** pour viser chaque abonnement ; répéter sur le banc et la VM pour prouver l'absence. Puis `orodruin-check` s'arme.
3. **Une Azure Policy** sur l'abonnement dédié (le vrai plafond) : types, SKU et régions autorisés, **adresses IP publiques refusées sauf celle du Bastion**.
4. **Le paramètre de diagnostic** (abonnement dédié → workspace du banc), en Terraform. **Premier test** : avec un groupe vide **créé puis supprimé par Jonathan**, avant tout run Stratus — vérifier que l'événement arrive dans `AzureActivity`.
5. **Le budget** via Terraform (`azurerm_consumption_budget_subscription` + un groupe d'action, éprouvé par `az monitor action-group test-notifications`) ; dire qu'il est évalué avec **8–24 h de retard** (ce n'est pas un plafond temps réel).

Ces gestes iront dans `docs/operations.md` au code (avec la date), pas dans cette doc.

---

## Ce que R2b ne fait pas

- **Le run réel au banc** et la mesure de détection (`azure_activity`, AL1) : **ID1 (#281)**.
- **Appliquer** le rôle / la policy / le diag setting / le budget : gestes de Jonathan, jamais une session.
- Les techniques **Entra** (dont la FIC) : hors périmètre, `planned`.
- Les règles AL1 pour Run Command et le lien Bastion : à écrire (ID1).

## À mesurer au banc avant le code

- Les actions minimales de chaque phase, par technique (`vm-run-command`, `create-bastion-shareable-link`), pour un rôle fermé ; puis le refus effectif sur les paramètres de diagnostic et les budgets.
- Les variables d'abonnement que lisent Stratus et azurerm, et le 403 attendu si on vise le banc.
- (B) depuis le bac à sable, une demande de jeton pour l'identité d'Orodruin doit **échouer**.
- Les groupes qu'Azure crée de lui-même dans l'abonnement dédié (Network Watcher, Defender), avant et **après `cleanup`**.
- `createdTime` d'un groupe, la **latence** de l'événement de création dans `AzureActivity`, et les champs vus par la watch (`SubscriptionId`, `_ResourceId`, l'appelant).
- La durée du `warmup` de chaque technique face à `PHASE_TIMEOUT_S`.
- La sortie Internet d'une VM d'un VNet neuf (depuis le 30/09/2025, pas d'accès sortant par défaut — à confirmer).
- La forme exacte des commandes/ressources Terraform du paramètre de diagnostic et du budget.

## Décisions de Jonathan (06/11, tranchées)

1. **Identité : B** (§ 1) — une identité dédiée à Stratus, dans un bac à sable sans l'IMDS d'Orodruin ; rôle fermé sur le seul abonnement dédié ; `orodruin-check` lit cette seconde identité ; le kill la coupe seule ; le contrat de l'identité d'Orodruin reste inchangé.
2. **Zone : `bench` réservée** (§ 2) — posée par le scope Stratus, sans étiquette, `kind: fault` refusé dans ce scope ; `ZONES`/`check_zone`/`Scope.for_bench()`/O0 inchangés ; un champ « périmètre » (`stratus-subscription`) dans la fenêtre et le rapport.

---

## Les mesures avant R2c (sur l'abonnement dédié permanent)

_Protocole — 2026-11-06, v2 (R2b/#608). **On mesure directement sur l'abonnement dédié permanent**, pas sur un jetable : les deux seraient vides et hors du banc, donc le jetable n'ajoute aucune sûreté dès lors que le rôle large de mesure est retiré avant la pose du rôle fermé et qu'Orodruin ne s'arme qu'après le rôle fermé + une sonde COLD. **La session Annatar guide Jonathan ; une session ne lance jamais une technique, un `apply`, ni `az login`.**_

### Préambule

- **Aucun identifiant réel dans le dépôt.** Tout est en variables, écrites une fois par Jonathan dans un fichier **hors dépôt** (`${MEAS}`), jamais recopié de l'écran : `${STRATUS_SUB}` (abonnement dédié), `${BENCH_SUB}`, `${BENCH_WORKSPACE_GUID}` (le GUID du workspace, pas son resource id), `${STRATUS_APPID}` / `${STRATUS_OID}`, `${ORODRUIN_OID}`, `${TENANT}`. Sortie : `export MEAS=~/r2b-mesures.env` ; chaque relevé par `echo "VAR=$(…)" >> ${MEAS}`.
- **Stratus tourne sous l'identité Stratus SEULE, jamais sous le `az login` de Jonathan** (sinon il agit comme lui, et un warmup « contre le banc » réussirait). Pour chaque `stratus` : un shell propre, **hors d'un répertoire chargé par direnv**, `export AZURE_CONFIG_DIR=~/r2b-az-stratus` (cache de connexion à part), **[J]** `az login --service-principal -u ${STRATUS_APPID} -p … --tenant ${TENANT}`, et `AZURE_SUBSCRIPTION_ID`/`ARM_SUBSCRIPTION_ID` **explicites** dans l'environnement du sous-processus. Jamais le cache de connexion de Jonathan pour un appel Stratus.
- **Gestes de Jonathan [J]** : tout `az login`, toute création/suppression d'attribution de rôle, tout `terraform apply`/`make … YES=1`, **toute technique lancée** (`stratus warmup|detonate|revert|cleanup`), **toute tentative d'écriture** (M1b). Les lectures suivent un `az login` de Jonathan ; la session les prépare et les lit avec lui. Plan montré avant tout `apply`.
- **L'identité Stratus existe dès l'Étape 0**, avec un **credential à expiration courte** (`--end-date`) : il **borne le rôle large** même si on oublie de le retirer. **Toute reprise de la session de mesure commence par relever l'état des attributions** (preuve ci-dessous) avant de continuer.

### Étape 0 — bâtir l'abonnement vide + l'identité Stratus

1. **[J] G1** — l'abonnement dédié vide, dans `${TENANT}` ; enregistrer les fournisseurs en **boucle** (un `--namespace` à la fois) : `for ns in Microsoft.Compute Microsoft.Network Microsoft.Insights Microsoft.Authorization; do az provider register -n ${ns} --subscription ${STRATUS_SUB} --wait; done` (+ `Microsoft.Consumption` si M1 le montre nécessaire). Vérif par espace : `for ns in …; do echo "PROV_${ns}=$(az provider show -n ${ns} --subscription ${STRATUS_SUB} --query registrationState -o tsv)" >> ${MEAS}; done`. `az resource list --subscription ${STRATUS_SUB}` vide.
2. **[J] L'identité Stratus** (service principal), credential à **expiration courte** (p. ex. `--end-date $(date -u -d '+2 days' +%Y-%m-%d)`). Relever `${STRATUS_APPID}`/`${STRATUS_OID}`.
3. **[J] G5** — l'Azure Policy, **plafond de coût dès la mesure** : types, SKU et régions autorisés ; **refuser une IP publique sur une carte réseau** (`Microsoft.Network/networkInterfaces` avec `ipConfigurations[*].publicIPAddress`) ; **inclure le SKU Bastion Standard/Premium** (le lien partageable l'exige). La Policy ne borne pas le *nombre* de ressources — c'est le budget + la revue des mesures qui le font. Terraform, plan montré.
4. **[J] G6** — paramètre de diagnostic `${STRATUS_SUB}` → workspace du banc (catégorie `Administrative`), Terraform. Le workspace doit **vivre pendant toute la mesure** (il part avec `celebrimbor-down`).
5. **[J] G7** — budget + **groupe d'action hors de l'abonnement dédié** (sinon COLD, « vider l'abonnement » et le rôle fermé le toucheraient ; à défaut, dans l'abonnement mais en liste fermée avec `Microsoft.Insights/actionGroups/write`+`/delete` en `NotActions`). Éprouver : `az monitor action-group test-notifications create …`.

### Étape 1 — mesures sous le rôle large (un seul point de retrait, à la fin)

**[J]** Attribuer à l'identité Stratus un rôle **large** (Contributor sur `${STRATUS_SUB}`), **borné par l'expiration courte du credential** (Étape 0). **Avant M2** [J-lecture] : prouver qu'elle ne tient **rien sur le banc** — `echo "STRATUS_ON_BENCH=$(az role assignment list --all --assignee-object-id ${STRATUS_OID} --subscription ${BENCH_SUB} --query 'length(@)')" >> ${MEAS}` (attendu : `0`).

- **M1 — actions minimales par technique.** `T0=$(date -u +%Y-%m-%dT%H:%M:%SZ)` relevé avant chaque run ; **[J]** le cycle complet par technique (`vm-run-command`, `create-bastion-shareable-link`) sous l'identité Stratus ; **attendre ~15 min** (retard du journal) ; puis : `echo "OPS_VMRC=$(az monitor activity-log list --subscription ${STRATUS_SUB} --start-time ${T0} --max-events 1000 --query "[?caller=='${STRATUS_APPID}'].authorization.action" -o tsv | sort -u | tr '\n' ',')" >> ${MEAS}` (idem par technique). Réussite : liste **non vide** contenant `Microsoft.Resources/subscriptions/resourceGroups/write`. Les **lectures** du rôle fermé (`…/read` par type écrit) sont ajoutées à la main, puis **éprouvées par un cycle complet sous le rôle fermé** en Étape 2.
- **M2 — d'où vient l'abonnement.** Sous l'identité Stratus seule, trois cas : (a) `AZURE_SUBSCRIPTION_ID=${STRATUS_SUB}` + `ARM_SUBSCRIPTION_ID=${STRATUS_SUB}` → **succès** ; (b) croisé `ARM_SUBSCRIPTION_ID=${BENCH_SUB}` → **échec** (l'identité Stratus n'a aucun droit sur le banc, cf. le relevé ci-dessus) ; (c) **aucune** variable → **échec** (Stratus/azurerm sans abonnement). Relever les trois codes. **[J]** (warmup lancé).
- **M6 — groupes qu'Azure crée de lui-même.** `RG_COLD_0` **avant** tout warmup, `RG_COLD_1` **après** un warmup, `RG_COLD_2` **après** cleanup : `echo "RG_COLD_0=$(az group list --subscription ${STRATUS_SUB} --query '[].name' -o tsv | tr '\n' ',')" >> ${MEAS}` (puis _1, _2). Note : **Network Watcher naît de façon asynchrone** (il peut n'apparaître qu'après un délai) ; `DefaultResourceGroup-*` vient de Defender. COLD les exclura.
- **M7 — fraîcheur + champs de la watch.** **[J]** un warmup. `az group show` **n'expose pas `createdTime`** → la fraîcheur se lit sur **l'événement de création** du journal d'activité : relever son horodatage et la **latence** depuis `T0` (direct et via le workspace), et les champs `SubscriptionId`, `_ResourceId`, l'appelant. Réussite : l'événement apparaît ; latence chiffrée ; l'étiquetage « exercice » tient sur `SubscriptionId` + appelant.
- **M8 — durée du warmup.** **[J]** `SECONDS=0; stratus warmup <technique>; echo "WARMUP_S_<technique>=${SECONDS}" >> ${MEAS}`. Réussite : si > ~900 s (le Bastion, VNet+VM), relever `PHASE_TIMEOUT_S` pour cette technique.
- **M9 — sortie Internet d'une VM d'un VNet neuf.** **[J]** dans une VM d'un warmup, via Run Command, tenter une sortie hors Azure ; relever succès/échec. Réussite : **pas de sortie** par défaut (depuis le 30/09/2025 ; sinon, mesure côté Policy).
- **M10 — le diag route (vérif).** Créer puis supprimer un groupe vide **[J]** ; confirmer son événement dans le workspace : `AzureActivity | where SubscriptionId == "${STRATUS_SUB}"` (le `-w` du diag attend le **GUID** `${BENCH_WORKSPACE_GUID}`, workspace vivant). Réussite : l'événement arrive ; la notification budget au test est arrivée.
- **Fin d'Étape 1 — retrait du rôle large (le seul point).** **[J]** retirer l'attribution large ; **preuve** : `echo "STRATUS_BROAD_LEFT=$(az role assignment list --all --assignee-object-id ${STRATUS_OID} --subscription ${STRATUS_SUB} --query "length([?roleDefinitionName=='Contributor'])")" >> ${MEAS}` (attendu : `0`).

### Étape 2 — le rôle fermé, puis la fédération et les refus (M3, M4, M1b, M5)

- **[J] G3** — le **rôle personnalisé fermé** : `Actions` = la liste de M1 **plus** `Microsoft.Insights/diagnosticSettings/read` et `…/resourceGroups/read` ; `NotActions` = `Microsoft.Insights/diagnosticSettings/write`+`/delete`, `Microsoft.Consumption/*`, `Microsoft.CostManagement/*`, les credentials fédérés (et `actionGroups/write`+`/delete` si le groupe d'action est dans l'abonnement) ; **aucune action `Microsoft.Authorization`**. Attribué à `${STRATUS_OID}`, portée `/subscriptions/${STRATUS_SUB}`.
- **[J] G4** — `AUTHZ_READ_ONLY` à `${ORODRUIN_OID}` sur `${STRATUS_SUB}` seulement, **rôle personnalisé en Terraform** (`roleAssignments/read`, `roleDefinitions/read` ; Reader casserait le contrat, `orodruin.py:322`).
- Resserrer **[J] G5** : la Policy refuse désormais l'IP publique **sauf** celle du Bastion.
- **M3 — mécanisme du jeton (après le rôle fermé).** **[J] G2** configure la fédération (workload identity : le bac à sable reçoit l'**assertion d'audience `api://AzureADTokenExchange`** et fait l'échange lui-même — ce n'est donc pas « il ne reçoit que le jeton de Stratus »). Lancer un warmup sous cette fédération, **avec le rôle fermé** (jamais Contributor) : Stratus/azurerm s'authentifient. Relever : **aucune autre application ne fait confiance à l'identité d'Orodruin** — `echo "ORODRUIN_FIC=$(az ad app federated-credential list --id ${ORODRUIN_APPID} --query 'length(@)')" >> ${MEAS}` (le bac à sable n'y est pas sujet).
- **M4 — échec du jeton d'Orodruin depuis le bac à sable.** **[J]**, depuis le bac à sable, **jamais `az login`** (il mettrait un jeton en cache) ; tenter de joindre le point de jeton d'Orodruin et **ne relever que le code HTTP** : `echo "ORODRUIN_TOKEN_HTTP=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 <endpoint IMDS/jeton d'Orodruin>)" >> ${MEAS}`. Témoin : ARM joignable **et** Stratus s'authentifie (le bac à sable marche), **alors que** le jeton d'Orodruin est inatteignable. Essais de lecture, code seul : `for f in <orodruin.env> <secret du canal> <HOME d'Orodruin>; do echo "READ_${f}=$(test -r ${f}; echo $?)" >> ${MEAS}; done` (attendu : non lisibles).
- **M1b — le rôle fermé refuse.** **[J]**, **après G3**, sur un **second** paramètre de diagnostic et un budget nommés `r2b-probe` (jamais les vrais) : une écriture/suppression → **refusée** ; relever **seul le code de retour**.
- **M5 — une liste vide ≠ une absence de droit.** La lecture des attributions de Stratus par `AUTHZ_READ_ONLY` d'Orodruin se fait **par `orodruin-check` lui-même** (s'authentifier comme Orodruin est un geste réservé), ou **[J]**. Témoin : là où Orodruin a `AUTHZ_READ_ONLY`, la lecture **réussit** (liste) ; là où il ne l'a pas, elle rend une **erreur**, **jamais une liste vide** (sinon on confondrait « pas le droit » et « rien attribué » — le bug M191).

### Étapes 3 à 5

- **(3) sonde COLD + `orodruin-check`** : l'abonnement est vide (hors la liste M6), le rôle fermé et `AUTHZ_READ_ONLY` sont en place → `orodruin-check` s'arme pour Stratus. **Invariant R2c (mutant)** : `orodruin-check` reste **passif** tant que l'identité Stratus tient autre chose que le rôle fermé (p. ex. un reliquat du rôle large).
- **(4) R2c** : le code hermétique, avec les valeurs mesurées (mutants **M4440–M4469**) ; sa PR corrige la doc (C1–C6).
- **(5) ID1 (#281)** : le run réel au banc et la mesure de détection (AL1).
