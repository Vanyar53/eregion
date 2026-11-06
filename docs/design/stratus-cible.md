# Stratus — l'abonnement de test dédié et la cible (R2b)

_Conception — 2026-11-06 (re-décision de Jonathan ; v3 après deux relectures Opus 5.5 — v1 `blocking`, v2 `changes`) — statut : **conception, à relire avant tout code** (R2b, #608, « Partie de #79 »). Fait suite à R2a (fusionné le 06/11, `3f6ae335`). **En attente d'une décision de Jonathan** sur deux points, marqués ⏳ : l'identité (A ou B) et la zone._

## La décision (Jonathan, 06/11, en interactif)

**Stratus tourne dans un abonnement de test dédié, unique et permanent**, où **rien d'autre ne vit** : ni H0, ni Orodruin, ni le canari, ni `rg-celebrimbor`. La cible d'une technique est le groupe que crée son `warmup` **dans cet abonnement**. Cette décision remplace celle du matin (le groupe dans l'abonnement du banc partagé), cassée par la relecture v1 : sous l'identité d'Orodruin, créer/détruire un groupe dans l'abonnement partagé demandait des droits qui atteignaient tout le banc, et un « droit de tag étroit » ne bornait rien.

**Ce que l'abonnement dédié règle, et ce qu'il ne règle pas.** Le périmètre devient l'abonnement entier : **plus de tag d'inscription** (donc plus de `tags/write`, plus d'ABAC) — appartenir à l'abonnement dédié *est* l'inscription. Mais **l'abonnement vide n'est pas, à lui seul, un garde-fou** : un rôle large (Contributor) y permettrait encore d'aveugler la watch (supprimer le paramètre de diagnostic), de supprimer l'alerte de budget, de créer des ressources coûteuses, de créer une identité managée à credential fédéré (persistante dans le tenant), ou d'ouvrir une sortie Internet par une VM pilotée en Run Command — ce qui contournerait « Orodruin sans Internet ». Le garde-fou est donc **un rôle personnalisé fermé + une Azure Policy** sur l'abonnement dédié (§ 1, § 6), pas la seule vacuité. Le blast radius est l'abonnement dédié **borné par ce rôle et cette policy**.

Le coût d'un abonnement est nul en lui-même ; l'ingestion d'`AzureActivity` dans un workspace est **gratuite** (`infra/terraform/activity_log.tf`). Le seul risque est un `cleanup` raté qui laisse des ressources payantes — l'**Azure Policy** (types/SKU/régions) en est le vrai plafond, l'alerte de budget n'étant qu'une notification (évaluée avec 8–24 h de retard).

Le cycle de R2a est inchangé — `warmup → detonate → revert → cleanup` ; R2b change **où** il tourne et **comment la watch l'observe**.

---

## 1. ⏳ L'identité qui agit, et le contrat

### Le choix d'identité (à trancher par Jonathan)

Stratus s'authentifie avec l'identité que l'adaptateur lui donne. Deux options :

- **Option A** — l'identité d'Orodruin, plus un rôle sur le seul abonnement dédié. *Contre* : `assess_identity` (`orodruin.py:226-227`) refuse toute attribution hors banc ; A élargit donc le périmètre du jeton d'Orodruin, et ne donne pas d'appelant distinct dans `AzureActivity`.
- **Option B** — une identité propre à Stratus, dans un bac à sable **sans l'IMDS d'Orodruin** (depuis le bac à sable, une demande de jeton pour l'identité d'Orodruin doit échouer — à mesurer). *Pour* : l'identité banc d'Orodruin reste intacte ; Stratus apparaît comme un **appelant distinct** dans le journal d'activité (utile à la détection).

**Le relecteur recommande B.** Stratus n'a aucune entrée de cible : seul le RBAC le borne, donc une identité à périmètre propre est plus sûre qu'un élargissement de l'identité d'Orodruin. **Décision en attente de Jonathan** ; la suite de la doc tient pour A comme pour B — seul « quelle identité le contrat lit » change.

### Ce que le contrat doit faire (vaut pour A et B)

Aujourd'hui `orodruin-check` ne liste les attributions que sur l'abonnement du banc (`read_identity`, `orodruin.py:417-420`) : il ne verrait pas, et ne jugerait pas, un rôle sur l'abonnement dédié. R2b doit :

- **une seconde lecture**, à la portée de l'abonnement dédié, avec sa propre preuve d'absence (`roleAssignments/read` sur `/subscriptions/<EREGION_STRATUS_SUBSCRIPTION>`) — en A sur l'identité d'Orodruin, en B sur l'identité de Stratus ;
- **un rôle tenu à une liste fermée d'actions** (l'esprit de SEC11) : jamais un joker, jamais `Microsoft.Authorization/*/write` ; les actions minimales par technique, mesurées au banc (§ Questions) ;
- **refuser si `EREGION_STRATUS_SUBSCRIPTION` vaut l'abonnement du banc ou celui de la VM** : sans ce refus, une ligne d'`orodruin.env` ramène exactement le bloquant v1 (un rôle large sur le banc). `orodruin-check` → `passive` ;
- **dire que les autres abonnements du tenant restent improuvables**, en A comme en B (la seconde lecture ne prouve l'absence que sur l'abonnement dédié et le banc, pas sur un troisième).

### Le kill révoque aussi le rôle dédié (constat 2)

`orodruin-kill` (`orodruin-contract.md`, `orodruin.py` `kill`) ne révoque aujourd'hui que l'abonnement du contrat et celui de la VM : après un kill, l'identité **garde** son rôle sur l'abonnement dédié. R2b doit :

- **révoquer** l'attribution sur `EREGION_STRATUS_SUBSCRIPTION` ;
- prouver **« rien à révoquer »** en relisant cet abonnement (le patron M191) ;
- des mutants.

---

## 2. La garde, l'abonnement du sous-processus, la fenêtre, la watch, le kill

### L'abonnement vient de la config, jamais du banc (constat 7)

`stratus_host.py:_env` passe tout `os.environ` au sous-processus, donc `AZURE_SUBSCRIPTION_ID` = le banc ; `_run_stratus` retombe aussi dessus (`engine.py`). R2b doit :

- l'abonnement de Stratus vient **seulement** de `EREGION_STRATUS_SUBSCRIPTION` ;
- l'environnement du sous-processus **remplace** `AZURE_SUBSCRIPTION_ID` et `ARM_SUBSCRIPTION_ID` par l'abonnement dédié (noms exacts à mesurer ; un 403 attendu si on vise l'abonnement du banc) ;
- le repli sur l'abonnement du banc **disparaît**.

### La garde — ⏳ zone `bench` réservée, posée par le scope

Le moteur Stratus a son propre `Scope`, borné à l'abonnement dédié (`EREGION_STRATUS_SUBSCRIPTION`), construit par lui seul — **jamais** le chemin VM, qui garde `Scope.for_bench()` et `rg-celebrimbor`. `Scope.check` autorise toute ressource de cet abonnement et refuse le reste. Les deux périmètres sont disjoints (abonnements différents).

**Zone (à trancher par Jonathan ; le relecteur recommande) :** la zone `bench`, **réservée** et **posée par le scope** (pas par une étiquette), la faute refusée. `ZONES` et `check_zone` (`inscription.py:77, 224-236`) restent **inchangés** — une zone étiquetable (p. ex. une zone `stratus` lue d'un tag) rouvrirait `enrollment()` au moteur Stratus, ce qu'on ne veut pas. Pas de tag : le scope impose la zone.

### La fenêtre — une seule, avant le `warmup`, sur l'abonnement (constats 3, 4)

Ma v2 « affinait » la fenêtre au groupe une fois son nom connu : **c'est interdit** (SEC14, `exercise.py:247-267` ; `_fields` ne laisse changer que `end`, `closed_by`, `channel_created` — réécrire la cible refuse la fenêtre et compte le run comme réel). Correction :

- **une seule fenêtre**, ouverte **avant le `warmup`**, ciblant **l'abonnement dédié**, et rien d'autre. L'abonnement étant dédié, cette cible est **exacte**, pas « large ». Le **nom du groupe** créé va au **rapport** (pour l'indice de remise en état), **pas** dans la fenêtre.
- Une fenêtre qui **nomme un abonnement** est une **nouvelle primitive** côté lecteur (H-1) : aujourd'hui `_targets` compare des identifiants exacts. La watch doit tenir l'identifiant de l'abonnement dédié **de sa propre configuration sur H0**, **jamais** de la fenêtre, et **refuser** s'il vaut l'abonnement du banc — sinon une fenêtre nommant `/subscriptions/<banc>` étiquetterait tout le banc « exercice » pendant 2 h 15.

### La watch étiquette sur le `SubscriptionId` (constat 5)

Aujourd'hui `RowAttribution` (`detection_rules.py:1158-1163, 1327-1329`) lit le `_ResourceId` d'une VM : hors des actifs découverts, une ligne de VM part `named=True, target=None` et `_route` la jette en silence ; une ligne sans VM (Bastion, groupe) part « non attribuée », `resource_id` vide, et `source_of` répond `unknown`. L'opération de `azure.execution.vm-run-command` — la technique principale — n'atteindrait jamais l'étiquetage. R2b doit, côté watch :

- nommer **`RowAttribution`, `_route` et `source_of`** comme points de changement ;
- poser l'étiquetage « exercice » sur le **`SubscriptionId`** de la ligne (quand il vaut l'abonnement dédié **tenu par la config de H0** et qu'une fenêtre est ouverte), pas sur un `resourceId` de VM ;
- lister les règles **AL1** qui vont tirer sur le `warmup`/`cleanup` : p. ex. `nsg-change-outside-glorfindel` sur le NSG que crée la technique (carte critique) ;
- dire qu'**aucune règle actuelle** ne détecte Run Command, ni le lien Bastion par un autre appelant — c'est ID1, mais à écrire. Les lignes `AzureActivity` de l'abonnement dédié sont des **données contrôlées** par qui agit dedans ; AL1 décide **sans modèle**, à garder ainsi.

### Le kill — révoquer, puis vider l'abonnement (constats 2, 9)

`orodruin-kill` révoque l'identité (y compris le rôle dédié, § 1) et ferme les fenêtres. Le nettoyage de l'abonnement dédié **ne peut pas** passer par `stratus cleanup --all` depuis le poste de l'opérateur : l'état Terraform de Stratus vit dans le `HOME` d'Orodruin, que le kill vient de désallouer — il n'y a plus d'état. Le bon geste, rendu possible par l'abonnement dédié : **vider l'abonnement** — `az group list --subscription <dédié>` puis `az group delete` de chaque groupe **hors de la liste des groupes qu'Azure crée lui-même** (§ 4), sous le `az login` de l'opérateur, et vérifier qu'il est vide.

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
   - **Vérif (le piège M191)** : `az role assignment list --assignee <oid> --subscription <id>` montre ce rôle ; répéter **abonnement par abonnement** (`--all` ne liste que l'abonnement courant de la CLI). Puis `orodruin-check` s'arme.
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

## Décisions en attente de Jonathan

1. **Identité A ou B** (§ 1) — le relecteur recommande **B** (bac à sable sans l'IMDS d'Orodruin, appelant distinct).
2. **Zone** (§ 2) — le relecteur recommande **`bench` réservée, posée par le scope**, `ZONES` inchangé.
