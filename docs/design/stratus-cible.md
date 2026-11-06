# Stratus — l'abonnement de test dédié et la cible (R2b)

_Conception — 2026-11-06 (re-décision de Jonathan, **remplace** celle du matin ; v2 après une relecture Opus 5.5 `blocking`) — statut : **conception, à relire avant tout code** (R2b, #608, « Partie de #79 »). Fait suite à R2a (l'adaptateur, fusionné le 06/11, `3f6ae335`)._

## La décision (Jonathan, 06/11, en interactif, avec les faits de la relecture)

**Stratus tourne dans un abonnement de test dédié, unique et permanent**, où **rien d'autre ne vit** : ni H0, ni Orodruin, ni le canari, ni `rg-celebrimbor`. La cible d'une technique Stratus est le groupe que crée son `warmup` **dans cet abonnement**.

Cette décision remplace celle du matin (« le groupe du warmup dans l'abonnement du banc partagé »), que la relecture a cassée : Stratus agissant sous l'identité d'Orodruin, créer/détruire un groupe dans l'abonnement **partagé** demandait des droits à l'échelle de l'abonnement qui atteignaient H0, Orodruin, le canari et `rg-celebrimbor` ; `resourceGroups/write` réécrit déjà les tags de n'importe quel groupe, donc un « droit de tag étroit » ne bornait rien, et le contrat d'Orodruin ne s'armait pas. La condition ABAC sur les tags d'un groupe n'était probablement pas réalisable.

**Ce que l'abonnement dédié change — et pourquoi c'est sain :** le périmètre n'est plus un groupe qu'il faut inscrire au milieu d'un abonnement peuplé ; c'est **l'abonnement entier**, vide par construction. Un droit large *dans cet abonnement* (même Contributor) n'atteint **rien de valeur** — il ne peut que créer/détruire des ressources de test jetables. Les deux bloquants disparaissent :

- **plus de tag d'inscription à poser** (donc plus de `tags/write`, plus d'ABAC) : être dans l'abonnement dédié **est** l'inscription ;
- **le blast radius est l'abonnement vide**, pas le banc.

Le coût d'un abonnement est nul en lui-même (Jonathan l'a validé) ; le seul risque est un `cleanup` raté qui laisse des ressources payantes — couvert par une **alerte de budget** propre à cet abonnement (geste de Jonathan, § Gestes).

Le cycle de R2a est inchangé — `warmup → detonate → revert → cleanup` ; R2b change **où** il tourne (l'abonnement dédié) et **comment la watch l'observe** (journal d'activité routé vers le workspace du banc).

---

## 1. L'identité qui agit dans l'abonnement dédié

Stratus et son Terraform s'authentifient avec l'identité que l'adaptateur leur donne (`annatar/executors/stratus_host.py`, `_env` passe l'environnement d'Orodruin). Il faut une identité qui a le droit d'agir **dans l'abonnement dédié et nulle part ailleurs**. Deux options ; le contrat d'Orodruin (`eregion_core/orodruin.py`, `assess_identity`) refuse aujourd'hui **toute** attribution hors du banc, sauf la liste blanche étroite des canaux (conteneur du canal d'exercice, conteneur du canal retour en lecture seule).

**Option A — l'identité d'Orodruin, plus un rôle sur le seul abonnement dédié (recommandée).**
Orodruin garde son identité unique ; on lui ajoute **une** attribution, à la portée de l'abonnement dédié, avec les actions dont le cycle Stratus a besoin. Le contrat gagne **une** entrée de liste blanche : une attribution au scope `EREGION_STRATUS_SUBSCRIPTION` (déclaré, comme `EREGION_CHANNEL_SCOPE`) est acceptée ; toute autre attribution hors du banc reste un manque (`identity_outside_bench`). C'est le même patron que les canaux, en une ligne de plus dans `assess_identity`.
- *Pour* : une seule identité, un seul contrat à raisonner ; `orodruin-check` lit déjà les attributions de cette identité.
- *Contre* : le jeton d'Orodruin (qui lit aussi le banc, Graph…) peut désormais écrire tout l'abonnement dédié. Mais cet abonnement est vide : le blast radius en cas d'hôte compromis est « créer des ressources de test », pas le banc.

**Option B — une identité propre à Stratus.**
Une identité gérée distincte, avec un rôle sur le seul abonnement dédié, et **rien** ailleurs ; Orodruin l'assume pour lancer Stratus, mais sa propre identité reste strictement banc. Le contrat doit alors **lire une seconde identité** et prouver qu'elle ne tient qu'un rôle sur l'abonnement dédié.
- *Pour* : l'identité banc d'Orodruin reste inchangée, tendue ; la séparation est explicite.
- *Contre* : `orodruin-check` doit évaluer **deux** principals (le sien, celui de Stratus) ; Orodruin détient de toute façon le credential de Stratus pour l'exécuter, donc l'isolement en cas de compromission totale de l'hôte est marginal.

**Recommandation : Option A.** L'isolement vient de la **frontière d'abonnement**, pas de la frontière d'identité ; un abonnement vide et dédié rend une seconde identité peu rentable face au doublement du contrat. **Ce que le contrat doit accepter, et seulement cela** (Option A) : pour l'identité d'Orodruin, une attribution au scope exact `/subscriptions/<EREGION_STRATUS_SUBSCRIPTION>` portant les actions du cycle Stratus (création/lecture/suppression de groupes et des ressources des techniques au catalogue), **et aucune autre attribution hors du banc**. Une attribution Stratus à une portée plus large que cet abonnement (le tenant, un management group), ou sur un autre abonnement, → `passive`. La liste exacte des actions se mesure au banc (§ Questions).

> À trancher à la relecture : A ou B. La suite de la doc est écrite pour A ; un basculement vers B ne change que « quelle identité le contrat lit », pas le reste.

---

## 2. La garde et la fenêtre sur l'abonnement dédié

### La garde

Le moteur Stratus a son **propre périmètre**, borné à l'abonnement dédié — **jamais** celui du chemin VM. R2a appelait déjà `check_target(rg_scope, rg_tags, rg_tags, …)` ; ça ne convient plus (il attend des tags d'inscription et la zone `bench` de `rg-celebrimbor`). R2b introduit un `Scope` Stratus :

- un `Scope` dont le périmètre est l'abonnement dédié entier (`EREGION_STRATUS_SUBSCRIPTION`), construit par le moteur Stratus seul. `Scope.check(resource_id)` autorise toute ressource **dans cet abonnement** et refuse tout le reste. La zone est une zone dédiée (p. ex. `stratus`, à ajouter à `ZONES`, ou `bench` réservée à cet abonnement — à trancher) ; elle n'autorise que `kind: technique`, jamais une panne, jamais la production (il n'y a pas de production ici).
- le chemin VM (`atomic`, `local-script`) garde `Scope.for_bench()` et `rg-celebrimbor` **inchangé** ; les deux périmètres sont disjoints par construction (abonnements différents), ce qui empêche un scénario VM de viser l'abonnement Stratus et inversement.

Comme rien d'autre ne vit dans l'abonnement dédié, **aucune étiquette d'inscription n'est posée** : appartenir à l'abonnement dédié est la preuve d'inscription. C'est la simplification centrale de la v2.

### La fenêtre d'exercice et la watch

Le `warmup` crée le groupe `<prefix>-rg-<correlation.short>` (§ 4) ; son nom est lu dans l'état Terraform **après** le warmup. La fenêtre d'exercice (`eregion_core/exercise.py`, `open_window`) doit alors couvrir **tout ce que ce run fait naître dans l'abonnement dédié** :

- **Cible exacte** : la fenêtre nomme le groupe créé (et, à défaut de le connaître avant le warmup, l'abonnement dédié jusqu'à ce que le nom soit lu). La relecture a raison : aujourd'hui la watch n'étiquetterait rien « exercice » ici, parce que son lecteur d'inscription (`TagEnrollment`, SEC8) est réservé aux **VM** de `rg-celebrimbor`, et H0 n'est Reader que sur `rg-celebrimbor`. R2b doit donc, côté watch :
  - étendre l'étiquetage « exercice » aux événements du **journal d'activité** de l'abonnement dédié, pendant une fenêtre ouverte, **sans** passer par le lecteur d'inscription par VM : dans l'abonnement dédié, tout ce qui naît pendant une fenêtre est un exercice (il n'y a rien d'autre). La garde d'inscription par VM (SEC8, verrou SEC14) **ne s'applique pas** à ce chemin ; le périmètre d'abonnement la remplace.
  - cette étiquette « exercice » vaut pour les événements `AzureActivity` dont le `SubscriptionId` est celui de l'abonnement dédié et dont l'horodatage tombe dans une fenêtre — pas pour des `resourceId` de VM.
- **Lecteur / droits de H0** : voir § 3 — H0 lit le journal d'activité **dans le workspace du banc** (où le diag setting le route), donc H0 n'a besoin d'**aucun droit** sur l'abonnement dédié. Le verrou SEC14 (le registre des fenêtres vues) reste ; la seule nouveauté est un type de cible « abonnement/plan de contrôle » à côté des VM.

### Le `warmup` hors fenêtre, et le kill

- **Warmup hors fenêtre** : le groupe se crée avant que la fenêtre couvrant le run ne soit connue par son nom. La fenêtre doit s'**ouvrir avant le warmup**, sur l'abonnement dédié (cible « large » connue d'avance), puis se **préciser** sur le groupe une fois son nom lu — pour qu'aucune création ne tombe hors fenêtre. (R2a ouvrait la fenêtre avant le cycle ; ici la cible initiale est l'abonnement, affinée au groupe.)
- **Kill** : `orodruin-kill` révoque l'identité et ferme les fenêtres. Il doit aussi **pouvoir vider l'abonnement dédié** d'un run en cours. Mais le kill révoque l'identité d'Orodruin : une fois révoquée, elle ne peut plus détruire. Donc le nettoyage de l'abonnement dédié après kill repose sur **le `az login` de l'opérateur** (§ Gestes, `stratus cleanup --all` dans l'abonnement dédié), pas sur l'identité révoquée. À décrire dans `orodruin-contract.md` au code.

---

## 3. Le journal d'activité de l'abonnement dédié vers le workspace du banc

Les techniques Stratus se voient dans le **journal d'activité** (`AzureActivity`, détection AL1). Pour que la watch de H0 les voie **sans droit sur l'abonnement dédié** :

- un **diagnostic setting** sur l'abonnement dédié envoie sa catégorie `Administrative` (au moins) du journal d'activité vers le **Log Analytics workspace du banc** (celui que H0 lit déjà). Geste de Jonathan (§ Gestes).
- H0 interroge `AzureActivity` dans ce workspace, filtré sur le `SubscriptionId` dédié et la fenêtre — exactement comme il lit les autres tables. **Aucun droit de H0 sur l'abonnement dédié** : le diag setting fait le pont, à sens unique.

**Coût** : le journal d'activité est à faible volume (événements de plan de contrôle, pas de la donnée) ; l'ingestion dans le workspace est marginale. À mesurer : la **latence** de l'événement de création (la relecture note qu'il serait une preuve de fraîcheur plus forte que `createdTime`) et le volume réel (§ Questions).

---

## 4. Les majeurs de la relecture

- **Gabarit de nom et adresse Terraform par technique, au catalogue.** Le nom du groupe (`<resource_prefix>-rg-<correlation.short>`) et l'adresse Terraform de la ressource (`azurerm_resource_group.lab_environment`) **diffèrent par technique** ; le préfixe **n'est pas configurable** côté Stratus (réponse à la question 4 de la v1). Donc chaque entrée `engine: stratus` du catalogue déclare son `resource_prefix` et l'adresse Terraform du groupe, et l'adaptateur lit l'état à cette adresse pour relever le groupe et la corrélation de ce run. (Sert surtout à nommer la fenêtre et l'indice de remise en état ; la garde, elle, ne dépend plus du nom — c'est le périmètre d'abonnement, § 2.)
- **`HOME` propre au run.** R2a montait un `HOME` stagé (pour le Terraform pré-installé) partagé. Pour un état Stratus indépendant d'un run à l'autre, R2b donne un **répertoire de travail propre au run** (l'état de la technique, `$HOME/.stratus-red-team/<technique>/`, parti d'un état neuf), tout en gardant le binaire Terraform et le cache de plugins stagés et partagés (hors-ligne, R2a).
- **`COLD` avant le `warmup`.** Avant de lancer le warmup, vérifier que l'état de la technique et l'abonnement dédié sont **propres** (pas de groupe résiduel d'un run précédent mal nettoyé) — une sonde « COLD » analogue à la sonde d'état initial de R1/R2a. Un résidu → refus (nettoyer d'abord), jamais attaquer par-dessus.
- **Retrait et expiration.** Plus de tag à retirer (§ 2). Il reste : la **fenêtre** se ferme toujours (teardown robuste de R2a) ; une ressource qui survit à un `cleanup` raté est dans l'abonnement dédié vide (donc sans danger pour le banc) et relève de l'**alerte de budget** + l'indice de remise en état (`stratus cleanup --all`). Une **étiquette d'expiration** sur les ressources du run (proposée par la relecture) permettrait à un balayage périodique de nettoyer les orphelins — à concevoir au code si on l'ajoute.
- **Le kill depuis le `az login` de l'opérateur** : décrit au § 2 — l'identité révoquée ne nettoie plus, donc le vidage de l'abonnement dédié après kill est un geste opérateur (§ Gestes).
- **Le jeton masqué** : une technique Stratus imprime un secret (relevé par la relecture). La sortie des phases doit être **masquée** avant journalisation/affichage (le journal d'Orodruin ne doit pas contenir le jeton). À traiter au code.
- **L'index de `CLAUDE.md`** : lier cette doc de conception à sa place au code, pas avant.

---

## 5. La technique FIC sort du périmètre de R2b

`azure.persistence.backdoor-managed-identity-fic` **ne touche aucune application** (la relecture corrige mon hypothèse de R2a) : elle demande des **écritures privilégiées sur l'annuaire** et des **attributions de rôles**, que le contrat d'Orodruin refuse à raison. Elle **reste `planned`** au catalogue, **hors de R2b**.

Deux corrections à faire (au code, pas dans cette doc) : sa **sonde `graph_probe`** du catalogue (ajoutée à tort en R2a — elle lisait les applications) est à **retirer/corriger** ; et aucun droit Graph d'écriture n'entre dans R2b. Les techniques Entra reviendront dans un lot dédié, avec leur propre modèle de menace.

---

## 6. Les gestes de Jonathan (créer l'abonnement et son cadre)

Tous **manuels** (une session n'applique jamais) ; l'`apply`/le plan est montré avant exécution. Chacun a sa vérification. Valeurs réelles (ids d'abonnement, de workspace) **jamais** dans le dépôt — en variables (`EREGION_STRATUS_SUBSCRIPTION`, …).

1. **Créer l'abonnement de test dédié** (portail ou `az account` selon l'accord d'entreprise), vide. Vérif : `az account show --subscription <id>` répond, et `az resource list --subscription <id>` est **vide**.
2. **L'identité et son droit** (Option A) : attribuer à l'identité d'Orodruin le rôle du cycle Stratus **au scope de ce seul abonnement**. Montré avant :
   `az role assignment create --assignee <orodruin-oid> --role <rôle> --scope /subscriptions/<id>`.
   Vérif : `az role assignment list --assignee <orodruin-oid> --scope /subscriptions/<id>` montre **ce** rôle, et `… --all` n'en montre aucun autre hors du banc. Puis `orodruin-check` s'arme (il accepte ce scope déclaré, et refuserait toute autre attribution hors banc).
3. **Le diagnostic setting** : router le journal d'activité de l'abonnement dédié vers le workspace du banc.
   `az monitor diagnostic-settings subscription create --subscription <id> --name stratus-activity --workspace <workspace-resource-id> --logs '[{category: Administrative, enabled: true}]'` (forme exacte à caler).
   Vérif : après un run, `AzureActivity | where SubscriptionId == "<id>"` renvoie des lignes dans le workspace.
4. **L'alerte de budget** sur l'abonnement dédié (contre un `cleanup` raté).
   `az consumption budget create … --subscription <id> …` (forme exacte à caler), seuil bas, notification à Jonathan.
   Vérif : le budget est listé ; un dépassement notifie.

Ces gestes vont dans `docs/operations.md` au code (avec la date), pas dans cette doc de conception.

---

## Ce que R2b ne fait pas

- **Le run réel au banc** et la mesure de détection (`azure_activity`, AL1) : **ID1 (#281)**, avec Jonathan.
- **Appliquer** le rôle / le diag setting / le budget : gestes de Jonathan (§ 6), jamais une session.
- Les techniques **Entra** (dont la FIC) : hors périmètre, restent `planned`.

## Questions ouvertes pour la relecture — à mesurer au banc

1. **Les droits effectifs de chaque phase, par technique**, sur un abonnement jetable : la liste minimale des actions du rôle (Option A) — Contributor suffit-il, ou veut-on plus étroit ? (Mesure, pas doc.)
2. **`createdTime` d'un groupe** et la **latence** de l'événement de création au journal d'activité (preuve de fraîcheur / COLD).
3. La **corrélation** lisible dans l'état après `warmup`, et l'état **propre** avant (COLD), avec un `HOME` propre au run.
4. Les **`resourceId`/champs** que la watch voit dans `AzureActivity` pour l'abonnement dédié (pour l'étiquetage « exercice » sans lecteur d'inscription par VM).
5. **Zone** : une zone `stratus` dédiée, ou `bench` réservée à cet abonnement ? (Trancher à la relecture.)
6. **Identité A ou B** (§ 1) : à trancher à la relecture.
