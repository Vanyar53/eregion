# Stratus — la cible d'une technique du plan de contrôle (R2b)

_Conception — 2026-11-06 — statut : **conception, à relire avant tout code** (R2b, #608, « Partie de #79 »). Fait suite à R2a (l'adaptateur, fusionné le 06/11, `3f6ae335`), qui avait laissé ouverte une question de conception (constat 3 de la relecture) : **où le `warmup` de Stratus crée-t-il ses ressources, et donc quelle est la cible inscrite ?**_

## La décision (Jonathan, 06/11, en interactif)

**La cible d'une technique Stratus est le groupe de ressources que crée son `warmup`.** Orodruin l'inscrit **avant `detonate`** : les étiquettes d'inscription (`eregion-target`, `eregion-zone`) sont posées sur ce groupe, et la fenêtre d'exercice s'ouvre sur lui. Le tout **dans l'abonnement du banc**, partagé avec H0 et le canari — **sans abonnement dédié**.

C'est l'inverse du chemin VM (R1 Atomic) : là, Celebrimbor inscrit la cible à la construction, et Annatar ne fait que vérifier l'inscription. Ici la cible **n'existe pas avant le run** — c'est Stratus qui la crée —, donc l'inscription devient un geste d'Orodruin, borné et prouvé, intercalé entre `warmup` et `detonate`.

Le cycle de R2a reste `warmup → detonate → revert → cleanup`. R2b insère l'inscription après `warmup` (quand le groupe existe) et son retrait avant/pendant `cleanup` :

```
warmup      Stratus crée le groupe <prefix>-rg-<correlation.short> (+ ses ressources)
  └─ inscription  Orodruin : prouve que le groupe est de CE run, pose les tags, ouvre la fenêtre
detonate    l'attaque sur le plan de contrôle
revert      (si supporté)
cleanup     Stratus détruit le groupe
  └─ désinscription  Orodruin : retire les tags, ferme la fenêtre (le groupe part de toute façon)
```

Pourquoi ce cadre plutôt qu'un abonnement dédié : un abonnement par run coûte cher, est lent à provisionner, et sort du modèle d'Orodruin (un hôte, un abonnement de banc). Le groupe jetable par run donne le même isolement de « blast radius » à l'échelle du groupe, tant que **le droit d'Orodruin de le toucher est borné au seul groupe qu'il vient de créer** — ce que cette conception garantit.

---

## 1. Le groupe que crée le `warmup`

Chaque technique Azure de Stratus crée **son propre groupe de ressources** au `warmup` (vérifié dans le dépôt amont, `v2/internal/attacktechniques/azure/**/main.tf`) :

```hcl
locals { resource_prefix = "srt-vmrc" }          # un préfixe par technique
resource "azurerm_resource_group" "lab_environment" {
  name = "${local.resource_prefix}-rg-${var.correlation.short}"
}
```

- `resource_prefix` est **fixe par technique** (p. ex. `srt-vmrc` pour `azure.execution.vm-run-command`, `stratus-red-team-shareable-link` pour `azure.persistence.create-bastion-shareable-link`).
- `var.correlation.short` est l'identifiant de **corrélation que Stratus génère par technique** (`v2/internal/state`, `TerraformCorrelation{ID}`), passé à Terraform comme variable `correlation` ; `.short` en est une forme courte (début de l'UUID). Il est **nouveau à chaque `warmup`** d'un état neuf.

Donc le nom du groupe est **`<resource_prefix>-rg-<correlation.short>`** : un préfixe connu d'avance (par la technique du catalogue) et un suffixe que Stratus choisit à ce run. C'est cette double propriété — **préfixe attendu** + **corrélation fraîche de ce run** — qui sert de preuve au § 2.

**Comment l'adaptateur apprend le nom exact.** Après `warmup`, l'adaptateur lit l'état de Stratus (son dossier d'état sous `$HOME/.stratus-red-team/<technique>/`, `terraform.tfstate` / `.terraform-outputs`) pour relever le groupe créé et sa corrélation — jamais en devinant le nom, jamais en listant l'abonnement. La lecture d'état est **locale à Orodruin** (pas un appel cloud). À préciser au code (R2b) : la forme exacte de la sortie à lire ; l'idéal est que la technique du catalogue déclare le `resource_prefix` attendu, et que l'adaptateur recoupe `prefix + correlation` lu dans l'état avec le groupe réellement présent.

---

## 2. La preuve que le groupe est de CE run

Le danger : poser une inscription (donc rendre « attaquable » et « exercice ») sur un groupe qui n'est **pas** celui de ce run — un groupe préexistant, celui de H0, d'Orodruin, du canari, ou un groupe qu'un tiers aurait nommé au motif de Stratus pour se faire inscrire. L'inscription ne doit **jamais** toucher autre chose que le groupe neuf de ce `warmup`.

Trois conditions cumulatives, toutes vérifiées **avant** de poser le moindre tag :

1. **Le motif de nom** : le groupe porte `<resource_prefix>-rg-<correlation.short>`, où `resource_prefix` est celui que la technique du catalogue déclare, et `correlation.short` est la corrélation de **cet** état Stratus (lue au § 1). Un nom hors motif → refus.
2. **La provenance Terraform** : le groupe figure dans l'état Terraform que **ce run** vient d'écrire (il est une ressource gérée de cet état, `azurerm_resource_group.lab_environment`), avec la corrélation de ce run. Un groupe absent de l'état, ou présent dans un état d'un autre run, → refus. C'est ce qui distingue « un groupe au bon nom » de « le groupe que je viens de créer ».
3. **La fraîcheur** : la date de création du groupe (lue sur ARM, `Microsoft.Resources/subscriptions/resourceGroups` → `createdTime` via le `Microsoft.Resources/tags`… à confirmer : Azure n'expose pas toujours `createdTime` sur un groupe ; repli = l'horodatage de l'état Terraform de ce run, écrit après le `warmup`) est **postérieure au début du run**. Un groupe plus vieux que le run → refus.

**Liste noire explicite** : les groupes de H0, d'Orodruin et du canari sont refusés par nom (variables d'environnement d'Orodruin, p. ex. `EREGION_BENCH_RG`, le groupe de H0, celui du canari), en plus des trois conditions — défense en profondeur, pour qu'une erreur de motif ne puisse jamais inscrire l'infrastructure du banc elle-même. Fail-closed : la moindre condition qui ne tient pas, ou une lecture qui échoue, → l'inscription est refusée et `detonate` n'a pas lieu (le `warmup` est nettoyé comme en R2a).

---

## 3. Le droit d'Orodruin de poser les tags (le plus étroit possible)

Poser `eregion-target`/`eregion-zone` sur le groupe est une **écriture** — un droit nouveau pour Orodruin, dans un abonnement **partagé** avec H0 et le canari. Il doit être le plus étroit possible : **jamais `Tag Contributor` sur tout l'abonnement sans borne** (il pourrait alors ré-étiqueter H0, le canari, n'importe quoi).

Mécanisme proposé — une attribution **conditionnée par le nom du groupe** (Azure ABAC) :

- un rôle personnalisé dont la seule action d'écriture est celle qui pose un tag sur un groupe de ressources — `Microsoft.Resources/tags/write` (à confirmer au banc : selon l'API, poser un tag sur un groupe passe par `Microsoft.Resources/subscriptions/resourceGroups/write` ou par le fournisseur `Microsoft.Resources/tags`) ;
- **assorti d'une condition ABAC** qui restreint l'écriture aux groupes **dont le nom commence par un préfixe Stratus** : `@Resource[Microsoft.Resources/subscriptions/resourceGroups:name] StringStartsWithIgnoreCase 'srt-'` (ou la liste des préfixes des techniques au catalogue). Azure évalue la condition sur la ressource visée ; une écriture de tag sur un groupe hors motif est refusée **par Azure**, pas seulement par notre code ;
- **assignée au niveau de l'abonnement du banc** (il le faut, car le groupe n'existe pas à l'avance), mais **bornée par la condition** — c'est ce qui remplace `Tag Contributor` nu.

Deux lignes de défense se cumulent donc : la condition ABAC d'Azure (le droit lui-même est borné) **et** la preuve du § 2 (notre code ne tente l'écriture que sur le groupe prouvé de ce run). La première protège même si notre code a un trou ; la seconde protège même si la condition est plus large que prévu.

**Le contrat d'Orodruin** (`orodruin-contract.md`, `eregion_core/orodruin.py`) doit alors :
- déclarer cette action d'écriture de tag dans `WRITE_ACTIONS` / `_HELD_AT`, **à la portée d'un groupe au motif Stratus** et **seulement conditionnée** — une attribution de tag-write **non conditionnée**, ou à l'abonnement entier, doit faire passer le contrat en `passive` (comme aujourd'hui une écriture sur le groupe entier est un manque) ;
- vérifier la condition ABAC comme une garantie : `orodruin-check` lit l'attribution et refuse de s'armer si la condition manque ou est trop large. C'est la partie la plus délicate (lire et juger une condition ABAC) — à cadrer au code.

À trancher au code (R2b) : la liste des préfixes (un par technique, ou un préfixe commun imposé à Stratus via sa config `resource_prefix` si c'est configurable — à vérifier ; sinon la liste des préfixes du catalogue).

---

## 4. La garde et la fenêtre, lues sur ce groupe

Une fois le groupe prouvé (§ 2) et inscrit (tags posés, § 3) :

- **La garde** (`eregion_core/inscription.py`, `check_target`) s'applique au groupe comme cible, exactement comme R2a le fait déjà pour « le groupe est la cible » : `check_target(rg_scope, rg_tags, rg_tags, kind="technique", destructive=…)` — inscrit, **zone `bench` seule** (un Stratus crée de vraies ressources), tag hérité `annatar-test` refusé. R2a a déjà ce code ; R2b change seulement **qui pose les tags** (Orodruin, à chaud) au lieu de les supposer présents.
- **La fenêtre d'exercice** (`eregion_core/exercise.py`, `open_window(targets=[rg_scope])`) s'ouvre sur le groupe, avant `detonate`, et se ferme au `cleanup` — comme R2a, mais sur le groupe réellement créé (dont le nom est désormais connu après `warmup`, § 1), pas sur un groupe supposé d'avance. La watch de H0 étiquette alors « exercice » ce que Glorfindel voit sur ce groupe pendant le run.

Ordre, donc : `warmup` → (prouver + tagger + ouvrir la fenêtre) → `detonate` → … Le `detonate` n'a lieu que si l'inscription a réussi ; sinon, refus et nettoyage (R2a).

---

## 5. Le retrait de l'inscription au `cleanup`

Au `cleanup`, Stratus **détruit le groupe** — les tags partent avec lui. Mais l'inscription ne doit pas survivre à l'échec d'un `cleanup` :

- Orodruin **retire les tags** `eregion-target`/`eregion-zone` du groupe **avant** (ou indépendamment de) la destruction par Stratus, pour qu'un groupe qui resterait (cleanup échoué, interrompu) ne reste **jamais inscrit** — un groupe inscrit mais abandonné serait une cible « attaquable » orpheline.
- La **fenêtre d'exercice** se ferme dans tous les cas (le teardown robuste de R2a, `_stratus_teardown_and_report`, déjà en place).
- Si le `cleanup` échoue et que le groupe survit : l'indice de remise en état (R2a, `_stratus_recovery_hint`) dit à l'opérateur de lancer `stratus cleanup <id>` à la main, **et** que le groupe a été désinscrit (il n'est plus une cible, même s'il traîne).

Le retrait des tags est une écriture : il passe par le même droit borné (§ 3) et est **journalisé par le contrat** (`Session.before_call`) comme toute écriture d'un injecteur.

---

## 6. Le droit d'écriture Graph et le modèle de menace

Certaines techniques Stratus touchent **Entra ID** (p. ex. `azure.persistence.backdoor-managed-identity-fic` ajoute un federated identity credential à une application). Leur `warmup`/`detonate` **écrit** dans l'annuaire — ce qu'Orodruin n'a pas le droit de faire aujourd'hui : son jeton Graph est **lecture seule** (`GRAPH_READ_ONLY` = `Application.Read.All`, `RoleManagement.Read.Directory`, IDI1).

R2b doit donc ajouter, pour ces techniques, **`Application.ReadWrite.OwnedBy`** (déjà prévu au cadrage) — un droit d'écriture **borné aux applications qu'Orodruin possède** : il ne peut modifier qu'une application dont il est propriétaire, jamais une application tierce ni un utilisateur. C'est le pendant Graph du § 3 : le plus étroit possible.

Conséquences pour le modèle de menace (`docs/design/modele-de-menace.md`, la frontière Entra ID d'Orodruin) et le contrat (`orodruin-contract.md`) — à écrire **quand le code suit** :
- `orodruin-check` doit juger ce droit : `Application.ReadWrite.OwnedBy` déclaré (quand une technique Entra est au catalogue) et **rien de plus** (jamais `Application.ReadWrite.All`, jamais un rôle d'annuaire) ; sinon `passive`. La garantie Graph passe de « lecture seule » à « lecture, plus écriture sur ses propres applications seulement ».
- la frontière du modèle de menace : ce qui tient (le groupe jetable, le droit conditionné, l'écriture Graph bornée au possédé, la liste noire de l'infra du banc) ; ce qui reste ouvert (une condition ABAC mal lue, une technique Stratus qui créerait hors de son groupe — à vérifier technique par technique au catalogue).

---

## Ce que R2b ne fait pas (reste à ID1 / plus tard)

- **Le run réel au banc** et la mesure de détection dans le journal d'activité (`azure_activity`, AL1) : c'est **ID1 (#281)**. R2b conçoit et code l'inscription du groupe ; ID1 l'éprouve en vrai, avec Jonathan.
- **Appliquer le Terraform** du nouveau rôle conditionné (`infra/orodruin/`) : geste de Jonathan, après relecture (jamais `terraform apply` par une session).
- Les techniques Stratus qui ne créeraient **pas** de groupe propre, ou qui écriraient hors de leur groupe : à auditer technique par technique avant de les passer `implemented` au catalogue ; hors de cette conception.

## Questions ouvertes pour la relecture

1. **La corrélation Stratus** est-elle lisible de façon stable depuis l'état après `warmup`, et le `resource_prefix` est-il garanti par technique (donc déclarable au catalogue) ? (À recouper au banc.)
2. **L'action d'écriture de tag** exacte et sa **condition ABAC** : `Microsoft.Resources/tags/write` conditionné sur le nom du groupe tient-il, ou faut-il `…/resourceGroups/write` (plus large) ? La condition ABAC sur `:name StringStartsWith` est-elle évaluable à la portée d'une écriture de tag ? (À mesurer — certitude par la mesure, pas par la doc.)
3. **La fraîcheur du groupe** : ARM expose-t-il une date de création fiable sur un groupe, ou faut-on se reposer sur l'état Terraform de ce run ?
4. Faut-il **imposer un `resource_prefix` unique** à Stratus par sa config (si c'est configurable), pour n'avoir qu'un seul préfixe à condition­ner, plutôt que la liste des préfixes des techniques ?
