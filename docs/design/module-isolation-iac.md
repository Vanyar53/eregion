# Module d'isolation compatible avec l'infrastructure as code

_Conception — 2026-10-05 — statut : proposition, à prototyper sur le banc Celebrimbor._

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
| Association NSG ↔ NIC ou subnet changée | Rétablie | ressources `*_security_group_association` |
| **NIC ajoutée à une ASG** | **Conservée, sans dérive dans le plan** | [source du provider](https://github.com/hashicorp/terraform-provider-azurerm/blob/main/internal/services/network/network_interface.go) |

Le dernier point vient du code du provider : à chaque mise à jour d'une NIC,
`parseFieldsFromNetworkInterface` relit les ASG présentes sur Azure et `mapFieldsToNetworkInterface` les
réécrit telles quelles. Le schéma de la NIC ne contient pas les ASG (elles passent par des ressources
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
3. **Sessions déjà établies.** Ni la quarantaine ni les règles ne coupent une session ouverte. À mesurer
   d'abord sur le banc ; ensuite décider d'une action complémentaire (couper les sessions dans la VM,
   arrêter la VM).
4. **Bicep / ARM.** Un redéploiement de la NIC réécrit probablement sa liste d'ASG (non vérifié).
5. **Topologies.** Une ASG par VNet (VMs réparties sur plusieurs VNets) ; VMs multi-NIC (toutes les
   NICs dans la quarantaine) ; VM sans aucun NSG (rien où s'ancrer : l'audit le signale).
6. **AVNM.** Lecture seule : détecter un Always Allow qui couvre une VM défendue.

## Plan

1. Mesurer sur le banc : une session SSH ouverte survit-elle à une isolation ?
2. Écrire le module Terraform des ancrages ; migrer le NSG du banc vers des règles séparées.
3. Prototype sur le banc : isoler par l'ASG, puis `terraform plan` (doit être vide) et `terraform apply`
   (ne doit rien défaire) ; même test avec la liste de blocage.
4. Connecteur : détecter les ancrages ; isolate/release/verify par l'ASG ; block/unblock/verify par la
   liste ; repli sur le mécanisme actuel.
5. Audit : présence des ancrages, précédence, règles client dans la plage réservée, Always Allow AVNM.
6. Documentation : section « Intégration Terraform » dans le README, publication du module.
