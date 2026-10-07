# Module d'isolation compatible avec l'infrastructure as code

_Conception — 2026-10-05, mise à jour le 2026-10-07 — statut : isolation juste à temps par NSG de quarantaine livrée et validée sur Azure (L1–L5, L7 ; PR #17 à #24), canary du comportement Terraform en place ; restent l'écran d'activation (L6) et le module de renfort optionnel (L8)._

## Pourquoi ce chantier

Le 2026-10-05, une mesure sur le banc a montré que la règle `allow-ssh` du NSG de subnet était en priorité 100.
Un NSG applique la première règle qui correspond, par priorité croissante. Résultat :

- une isolation (deny posé à la première priorité libre, donc 101) laissait SSH ouvert sur la VM « isolée » ;
- un blocage d'IP (deny à partir de 200) laissait passer un brute force SSH ;
- la vérification, qui ne contrôle que la présence des règles, répondait `verified=True`.

La PR #16 corrige le symptôme : détection des règles allow prioritaires (vérification et audit), et
`allow-ssh` passé en 1000 sur le banc. Mais le constat pose une question de fond : **comment Glorfindel
doit-il poser ses règles dans une infrastructure qu'il ne possède pas, et qui est souvent déployée en
Terraform ?** Le mécanisme actuel crée des règles pendant l'incident et décale des règles client. Il entre
en concurrence avec la numérotation du client et avec son code.

Objectif : la meilleure intégration possible avec une infrastructure existante, en priorité une
infrastructure gérée en Terraform.

## Faits établis

### Évaluation des NSG ([doc Azure](https://learn.microsoft.com/en-us/azure/virtual-network/network-security-groups-overview))

1. Priorités de 100 à 4096 ; numéro bas évalué en premier ; la première règle qui correspond (allow ou
   deny) gagne.
2. Un trafic doit être autorisé par le NSG du subnet **et** par celui de la NIC : un deny dans l'un suffit.
3. Une règle créée ou modifiée ne s'applique qu'aux **nouvelles** connexions. Une session déjà établie
   continue (l'exemple de la doc : une session SSH ouverte survit à la suppression de la règle qui
   l'autorisait).

### Terraform, provider azurerm

| Ce que Glorfindel modifie | Effet d'un `terraform apply` quand la ressource est gérée par Terraform | Source |
|---|---|---|
| Règle ajoutée à un NSG à règles **en ligne** (`security_rule {}`) | Supprimée : les règles en ligne sont autoritaires | [doc azurerm](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/network_security_rule), constaté sur le banc |
| Règle ajoutée à un NSG à règles **séparées** (`azurerm_network_security_rule`) | Conservée. Mais un apply qui ajoute une règle client à une priorité occupée échoue | doc azurerm |
| Règle client décalée de la priorité 100 (isolation actuelle sur NSG dédié) | Remise à 100, en conflit avec le deny de Glorfindel | déduit |
| Association NSG ↔ NIC changée hors Terraform (NSG échangé) | **Conservée, sans dérive** — mesuré le 06/10 (la note du 05/10 disait « rétablie » : déduction fausse). Seuls un remplacement forcé de l'association et un redéploiement Bicep/ARM remettent le NSG du client | test sur le banc, `network_interface_security_group_association_resource.go` |
| **NIC ajoutée à une ASG** | **Conservée, sans dérive dans le plan** | [source du provider](https://github.com/hashicorp/terraform-provider-azurerm/blob/main/internal/services/network/network_interface.go) |
| **NSG accroché à une NIC qui n'en a pas** (pas de ressource `azurerm_network_interface_security_group_association` pour elle) | **Conservé, sans dérive dans le plan** (vérifié le 06/10) | [`resourceNetworkInterfaceUpdate`](https://github.com/hashicorp/terraform-provider-azurerm/blob/main/internal/services/network/network_interface_resource.go) |

Les deux dernières lignes viennent du code du provider. Pour le NSG d'une NIC :
`resourceNetworkInterfaceUpdate` relit la NIC sur Azure, part de ce modèle (`payload := existing.Model`)
et n'écrase que les champs qui ont changé ; le NSG n'y est jamais touché, et le schéma de
`azurerm_network_interface` ne le contient pas (il passe par la ressource d'association). Un NSG accroché
hors Terraform survit donc à un `apply` et n'apparaît pas comme une dérive. Pour les ASG,

`parseFieldsFromNetworkInterface` relit les ASG présentes sur Azure et `mapFieldsToNetworkInterface` les
réécrit telles quelles quand les `ip_configuration` changent. Le schéma de la NIC ne contient pas les ASG (elles passent par des ressources
d'association), donc une appartenance ajoutée hors Terraform n'apparaît pas comme une dérive.

### ASG ([doc](https://learn.microsoft.com/en-us/azure/virtual-network/application-security-groups))

Groupe logique de NICs utilisable comme source ou destination d'une règle NSG. Toutes les NICs d'une
ASG sont dans le même VNet ; 10 ASG maximum par source ou destination de règle ; 3 000 ASG par
abonnement.

### Règles d'admin AVNM ([doc](https://learn.microsoft.com/en-us/azure/virtual-network-manager/concept-security-admins))

Évaluées **avant** tous les NSG. Trois actions : Deny (bloqué sans consulter le NSG), Always Allow
(autorisé sans consulter le NSG), Allow (le NSG décide ensuite). Un déploiement prend « quelques
minutes » ; une seule configuration par région et par Network Manager ; les groupes contiennent des
VNets ; environ 0,02 $ par heure et par VNet géré ; pas d'effet sur les private endpoints ni, par
défaut, sur les VNets avec SQL Managed Instance ou Databricks. Trop lent et trop lourd pour la réponse
à incident ; à **lire** pour détecter un Always Allow qui contournerait la quarantaine.

## Conception proposée

**Principe : Terraform possède la structure ; Glorfindel ne modifie que l'état de l'incident, à des
endroits que Terraform ne réécrit pas.**

### Points d'ancrage, déclarés une fois dans le code du client

Eregion fournit un module Terraform que le client ajoute à son code :

- une ASG `glorfindel-quarantine` par VNet ;
- dans chaque NSG gouvernant des VMs défendues, deux règles en **priorité 100** :
  - entrée : deny `*` → ASG quarantaine ;
  - sortie : deny ASG quarantaine → `*` ;
- dans chaque NSG, une règle « liste de blocage » en **priorité 101** (deny, entrée et sortie), dont le
  contenu appartient à Glorfindel : `lifecycle { ignore_changes = [source_address_prefixes] }` (et
  l'équivalent destination pour la sortie) ;
- un **rôle Azure minimal** pour l'identité de Glorfindel : modifier l'appartenance des NICs à l'ASG,
  mettre à jour la règle de blocage, tout lire. Plus étroit que Network Contributor (liste exacte des
  actions à valider).

La plage réservée devient **100–101**, et elle est visible dans le code du client, donc dans ses revues.

### À l'exécution

| Action | Ce que fait Glorfindel | Ce que voit Terraform |
|---|---|---|
| Isoler | Ajoute toutes les NICs de la VM à l'ASG quarantaine | Rien (pas de dérive) |
| Lever | Retire les NICs de l'ASG | Rien |
| Bloquer | Ajoute l'IP à la liste de blocage | Rien (`ignore_changes`) |
| Débloquer | Retire l'IP de la liste | Rien |
| Vérifier | Appartenance réelle à l'ASG, présence et précédence des règles d'ancrage, IP présente dans la liste | — |

Conséquences :

- plus aucune ressource créée pendant un incident, plus aucune règle client touchée ;
- un NSG partagé ne pose plus de problème : seules les NICs membres de la quarantaine sont touchées ;
- l'état de l'incident vit dans Azure (appartenance, contenu de la liste) : l'état local devient un
  cache, cohérent avec `reset --from-azure` ;
- **repli** : sans ancrages, Glorfindel garde le mécanisme actuel (règles dans la plage réservée) et
  l'audit signale l'absence d'ancrages.

## Décisions ouvertes

1. **Portée du blocage.** Avec une liste par NSG, une IP bloquée l'est pour toutes les VMs derrière ce
   NSG, alors qu'aujourd'hui le blocage vise une VM. Proposé : périmètre du NSG par défaut pour une IP
   confirmée malveillante. Décision de Jonathan.
2. **NSG à règles en ligne.** `ignore_changes` ne peut pas viser une seule règle en ligne. Options :
   migrer le NSG vers des règles séparées (une fois, avec des blocs `import`), ou un repli où Glorfindel
   repose le blocage et alerte quand un apply le retire.
3. ~~**Sessions déjà établies.**~~ **Tranché le 05/10** : mesuré sur le banc, une session SSH active
   (17 min), une session inactive (11 min) et un téléchargement sortant survivent à une règle NSG ; les
   nouvelles connexions sont refusées. Run Command passe pendant l'isolation et `ss -K` coupe tout →
   `isolate_vm` coupe désormais les connexions établies après la pose des règles (`drain_connections`),
   et une isolation dont les sessions restent ouvertes n'est pas vérifiée. Vaudra pour tout mécanisme
   (règles, NSG accroché, ASG).
4. **Bicep / ARM.** Un redéploiement de la NIC réécrit probablement sa liste d'ASG (non vérifié).
5. **Topologies.** Une ASG par VNet (VMs réparties sur plusieurs VNets) ; VMs multi-NIC (toutes les
   NICs dans la quarantaine) ; VM sans aucun NSG (rien où s'ancrer : l'audit le signale).
6. **AVNM.** Lecture seule : détecter un Always Allow qui couvre une VM défendue.

## Avancement au 2026-10-06 — le mécanisme par défaut, durci

La seconde passe de l'analyste (05/10) a proposé de garder l'activation en un clic : les règles posées à
la volée restent le mécanisme par défaut, durci, et le module devient un renfort optionnel (choix
prérequis/renfort : à trancher). Livré et validé sur Azure réel (PR #17 à #19) :

| Lot | Ce qui a changé | Validé |
|---|---|---|
| L1 | Un échec de vérification est escaladé en `verification_failed` (Revert) ; préséance illisible → non vérifié | 05/10 |
| L2 | Mesure des sessions établies (ci-dessus) | 05/10 |
| L3 | Aucune règle client déplacée (le deny prend la 1re priorité libre) ; si une allow passe avant lui sur le NSG de la carte, le deny va sur le NSG du subnet (un deny dans l'un suffit) ; blocage jugé selon le port de la menace (une allow sur un autre port = exposition, pas contournement) | 06/10 |
| L5 | Règles disparues d'Azure (apply sur NSG à règles en ligne, retrait manuel) → reposées une fois + alerte ; disparues à nouveau → alerte seule ; `human_only` → alerte seule | 06/10 |
| L7 | Sessions ouvertes coupées après l'isolation (Run Command, `ss -K`) ; restore : la dernière commande Run Command est neutralisée avant (le disque restauré la rejouait) | 05/10 |

Ce qui reste exposé avec le mécanisme par défaut :
- **NIC sans NSG dont le NSG de subnet a une allow avant notre deny** : pas d'autre NSG où poser le deny
  → isolation signalée contournée (vérification en échec), sans parade. → L4.
- **NSG de subnet à règles en ligne géré en Terraform** : un `apply` efface nos règles ; L5 les repose une
  fois puis alerte. → L4 (pour les NIC sans NSG), ou le module.
- **NSG en ligne de la NIC** : même chose, sans parade hors module.

## L4 — isolation JIT par NSG de quarantaine

**Mesuré sur le banc le 06/10** (azurerm 4.81.0, pile Terraform jetable : réseau, NSG client, une NIC associée
en code, une NIC sans NSG) :

| # | Situation | Résultat |
|---|---|---|
| 2 | NSG client de la NIC échangé contre le nôtre, hors Terraform | `plan` sans changement, `apply` ne remet rien |
| 3 | Notre NSG accroché à une NIC sans NSG | idem |
| 4 | `apply` qui modifie les deux NIC (tag) pendant ce temps | notre NSG reste sur les deux |
| 5 | Le client ajoute en code une association sur la NIC L4 | son `apply` échoue (import requis), notre NSG reste |
| 6 | Remplacement forcé de l'association (≈ changement de NSG dans le code) | son NSG revient, le nôtre part |
| 7 | NSG client remis à la levée | `plan` propre |
| 8 | Redéploiement ARM/Bicep de la NIC (incrémental) | notre NSG retiré (NIC L4 sans NSG, NIC échangée avec le NSG client) |

**Validé avec Jonathan** : l'isolation devient JIT — chaque NIC porte notre NSG le temps de l'incident,
le NSG client (s'il y en a un) est mis de côté intact et revient à la levée ; l'original est noté en tag sur
notre NSG (source de vérité Azure). Les cas 6 et 8 sont suivis par la boucle L5 (relecture toutes les 60 s,
réechange une fois, alerte avec l'auteur lu dans le journal d'activité).


**Décidé le 06/10 avec Jonathan, dans cet ordre :** d'abord le NSG de quarantaine pour toute NIC sans
NSG ; puis, après la mesure ci-dessus, l'échange pour une NIC qui en a déjà un (le NSG client est mis de
côté intact et remis à la levée ; l'original est gardé en tag sur notre NSG, ce qui lève la dépendance à
l'état local). Glorfindel crée le NSG au premier besoin (un par région) dans un RG configuré ; le module
Terraform reste un renfort optionnel. Repli si l'échange est refusé (Azure Policy, droits) : règles L3.

**Dépendance au provider** : ce comportement est celui d'azurerm 4.81.0. `make canary-jit`
(`infra/canary/jit-terraform/run.sh`, et chaque semaine en CI : `.github/workflows/canary-azurerm.yml`)
le revérifie sur la dernière version du provider et échoue s'il a changé. Premier passage le 07/10 : PASS.

Implémenté (`isolate_vm` / `release_isolation` / vérifications / `reset --from-azure`) ; détails dans
CLAUDE.md. Points ci-dessous : la conception d'origine de L4 (NIC sans NSG), avant l'échange.

Une NIC sans NSG propre est gouvernée par le seul NSG de son subnet. Glorfindel y accroche son propre NSG,
qui ne contient que deux règles deny-all (entrée et sortie) : le trafic doit passer les deux NSG, donc la
VM est isolée quel que soit le contenu du NSG de subnet.

Pourquoi c'est intéressant :
- aucune règle client touchée, **aucune préséance possible** (notre NSG ne contient que nos règles) ;
- aucun autre VM concerné ;
- **compatible Terraform** : le NSG d'une NIC sans ressource d'association n'est pas géré par la ressource
  NIC (vérifié dans le provider, tableau ci-dessus) ; un `apply` sur le NSG de subnet à règles en ligne ne
  touche pas notre NSG non plus ;
- c'est le modèle des playbooks Sentinel (`Isolate-AzureVMtoNSG`), sans leurs défauts : on n'écrase pas un
  NSG existant (NIC sans NSG uniquement) et on sait revenir en arrière.

Points de conception à trancher :
1. **Quand l'utiliser** : en premier choix pour toute NIC sans NSG (proposé — plus robuste que des règles
   dans le NSG de subnet), ou seulement quand le NSG de subnet a une allow devant notre deny ?
2. **Le NSG de quarantaine** : un par région et par abonnement (une NIC ne peut recevoir qu'un NSG de sa
   région/abonnement), créé par Glorfindel dans son propre RG au premier besoin, ou fourni par le module /
   l'onboarding ? Contenu fixe : deny `*` entrée et sortie en 100 (les adresses plateforme 168.63.129.16 et
   169.254.169.254 ne sont pas filtrées par un NSG : Run Command et la coupure des sessions marchent).
3. **État et levée** : enregistrer que la NIC n'avait pas de NSG ; la levée détache notre NSG (et seulement
   le nôtre, vérifié par son id) ; `reset --from-azure` le reconnaît par son nom.
4. **Vérification** : la NIC porte bien notre NSG + ses deux règles ; L5 réaccroche une fois s'il a été
   détaché.
5. **Droits** : `Microsoft.Network/networkInterfaces/write` (large : permet aussi de changer IP et NSG d'une
   NIC — le même plancher que l'ASG) + `Microsoft.Network/networkSecurityGroups/join/action` sur notre NSG ;
   création du NSG si Glorfindel le crée lui-même.
6. **Risques à vérifier** : une Azure Policy qui interdit les NSG au niveau NIC (fréquente : « NSG au
   subnet seulement ») → refus 403 → repli sur les règles dans le NSG de subnet ; un redéploiement
   **Bicep/ARM** de la NIC (PUT complet) retire très probablement notre NSG → L5 le réaccroche une fois puis
   alerte (non vérifié) ; durée de la mise à jour d'une NIC (~10–30 s) ; VM multi-NIC (chaque NIC sans NSG).
7. **Topologie de test** : une VM dont la NIC n'a pas de NSG et dont le NSG de subnet a une allow en 100
   (le cas que L3 ne sait pas traiter) ; vérifier `terraform plan` vide après l'accroche.

## Pour le module (L8) — ajouts de la seconde passe

- L'appartenance à une ASG se fait **par ipConfiguration** : mettre en quarantaine toutes les
  ipConfigurations de toutes les NICs, et le vérifier (sinon le trou multi-NIC de juin revient une couche
  plus bas).
- La règle « liste de blocage » exige au moins un préfixe : une **sentinelle** quand elle est vide
  (adresse de documentation, ex. `192.0.2.1/32`) et une **garde** qui refuse `*`, `0.0.0.0/0`, `Internet`,
  `VirtualNetwork` ou tout préfixe large (sinon un bug devient un deny-all en 101 pour tout le NSG).
- Plancher de droits : `networkInterfaces/write` + `applicationSecurityGroups/joinIpConfiguration/action`.
- Garder le mécanisme par défaut en repli = deux moteurs d'isolation à maintenir : le repli reste-t-il
  autonome, ou devient-il une recommandation ?

## Plan initial (05/10)

1. Mesurer sur le banc : une session SSH ouverte survit-elle à une isolation ?
2. Écrire le module Terraform des ancrages ; migrer le NSG du banc vers des règles séparées.
3. Prototype sur le banc : isoler par l'ASG, puis `terraform plan` (doit être vide) et `terraform apply`
   (ne doit rien défaire) ; même test avec la liste de blocage.
4. Connecteur : détecter les ancrages ; isolate/release/verify par l'ASG ; block/unblock/verify par la
   liste ; repli sur le mécanisme actuel.
5. Audit : présence des ancrages, précédence, règles client dans la plage réservée, Always Allow AVNM.
6. Documentation : section « Intégration Terraform » dans le README, publication du module.
