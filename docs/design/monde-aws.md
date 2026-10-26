# Un monde simulé par fournisseur : AWS (MC1)

MC1 décline le faux Azure des invariants (`tests/unit/fake_azure.py`) pour AWS : un faux AWS en
mémoire (`tests/unit/fake_aws.py`), un adaptateur AWS écrit contre lui
(`glorfindel/providers/aws/`), et la machine à invariants qui les fait tourner
(`tests/unit/test_invariants_aws.py`). Code seul : aucun appel AWS, aucun compte, aucune
dépendance nouvelle. L'adaptateur parle à un client EC2 injecté, qui a les noms, les arguments
et les réponses de `boto3` ; en MC1 seul le faux monde l'implémente, en MC2 le vrai client
`boto3` prendra sa place, sur un banc AWS.

**Chaque sémantique d'AWS écrite ici est une hypothèse tirée de la documentation d'AWS, à
mesurer sur le banc AWS (MC2).** Elles sont numérotées (H1…H14) ; le faux monde et
l'adaptateur renvoient à ces numéros. La règle du dépôt tient : un comportement d'un cloud n'est
affirmé qu'après une mesure ([`preuves.md`](preuves.md)). Rien de ce document n'est mesuré.

## Les mots, d'Azure à AWS

| Azure | AWS | Ce qui change |
|---|---|---|
| carte réseau (NIC) | interface réseau élastique (ENI) ; une instance peut en avoir plusieurs, dans des sous-réseaux différents du même VPC | rien pour Glorfindel : chaque carte est traitée |
| NSG de carte, un au plus | groupes de sécurité (SG), **1 à 5 par ENI** (H2), du VPC de l'ENI | une ENI n'est jamais « sans groupe » : une carte « nue » d'Azure devient une ENI remise sur le groupe `default` |
| règles allow et deny, par priorité | un SG **n'a que des autorisations**, l'union des règles de tous les groupes de l'ENI décide ; **à états** : la réponse d'un flux autorisé passe (H1) | un SG ne peut rien refuser |
| NSG de sous-réseau | **ACL réseau** (NACL) du sous-réseau : **sans état**, entrées numérotées 1 à 32766, allow et deny, la plus petite qui correspond décide, la dernière (`*`) refuse (H5) | une entrée entrante ne nomme que la **source**, une sortante que la **destination** : une NACL ne peut pas viser une seule instance |
| NSG de quarantaine (un par région) | **SG de quarantaine** (un par VPC, `glorfindel-quarantine`), **sans aucune règle** : la règle de sortie par défaut d'un SG neuf (H3) est retirée | même principe : il remplace les groupes de l'ENI le temps de l'isolation |
| repli par règles (deny sur les NSG du client) | **pas d'équivalent** : un SG ne refuse pas, et une NACL couperait tout le sous-réseau | sans quarantaine, pas d'isolation : refusée, rien d'écrit |
| blocage d'une IP (deny sur le NSG, adressé aux IP de la carte) | entrées **deny** de la NACL du sous-réseau, attaquant en `/32`, tous protocoles, entrée et sortie, à un numéro libre **avant** la première entrée qui laisse passer l'attaquant | **toujours à l'échelle du sous-réseau** : le blocage coupe l'attaquant de toutes les instances du sous-réseau, et le dit (`scope: subnet`) |
| DNS et IMDS d'Azure (refusables par étiquette de service) | résolveur DNS d'Amazon et IMDS : **ni les SG ni les NACL ne les filtrent** (H6) | toujours joignables, et toujours déclarés (`platform_open`) — le réseau ne peut pas les refuser |
| coupure des sessions (`ss -K` par Run Command) | une connexion suivie survit au changement de groupes (H10) | MC1 ne coupe pas les sessions : AWS ne déclare pas `session_drain` |
| tags réécrits en entier (`update_tags`) | `create_tags` fusionne par clé, `delete_tags` retire les clés nommées (H7) | la course qui effaçait le tag d'une autre isolation (Q7) n'existe pas ; le verrou reste |
| abonnement dans l'identifiant | l'ARN porte **compte et région** ; un client EC2 est régional | I12 devient « un autre compte ou une autre région » |
| groupe de ressources de la quarantaine (`quarantine_rg`) | pas d'équivalent : un SG appartient à un VPC | `isolation.quarantine_rg` est ignoré sur AWS ; `isolation.quarantine_nsg` allume ou éteint le SG de quarantaine |

## Isoler, lever, bloquer, débloquer, vérifier

**Isoler** (`isolate_vm`). Pour chaque ENI de l'instance : trouver ou créer le SG de quarantaine
de son VPC (sous verrou ; un SG qui porte le nom sans le tag `managed-by=glorfindel` n'est jamais
adopté) et remettre son contenu en ordre (aucune sortie ; en entrée, seuls les accès forensiques
de la configuration, TCP 22 et 3389 depuis `isolation.forensic_sources`). Noter la liste
ordonnée des groupes d'origine en tag sur le SG de quarantaine (`glorfindel-orig-<eni>`), relire
le tag, puis remplacer les groupes de l'ENI par le seul SG de quarantaine — si l'ENI porte encore
ce qui a été lu — et relire l'ENI. L'état local garde l'origine de chaque ENI. Une ENI que le
service refuse (une SCP, un droit manquant) laisse une isolation partielle, notée et dite.
Configuration illisible ou quarantaine éteinte : refus avant toute écriture.

**Lever** (`release_isolation`). Noter l'intention dans l'état, puis, pour chaque ENI en
quarantaine, remettre ses groupes d'origine (de l'état ; à défaut, du tag) et relire l'ENI.
Origine inconnue (état et tag perdus), ou un groupe d'origine supprimé depuis : l'ENI reste en
quarantaine et la levée dit quel tag poser — un SG recréé a un nouvel identifiant (H4), c'est
l'opérateur qui le donne. Une ENI que quelqu'un a sortie de la quarantaine vers le groupe
`default` (l'équivalent d'une carte laissée nue) retrouve son origine connue.

**Bloquer** (`block_suspicious_ip`). Pour chaque NACL des sous-réseaux des ENI : sous un verrou par
NACL, réutiliser les entrées qu'un autre blocage de la même IP a posées et qui sont intactes, sinon
choisir pour chaque sens le plus grand numéro libre en dessous de la première entrée qui
autorise l'attaquant ; **noter l'intention dans l'état avant de créer** (une entrée de NACL n'a ni
nom ni description : seule la note dit qu'elle est à Glorfindel), créer, puis noter le résultat.
Pas de numéro libre avant une autorisation de l'attaquant : rien n'est posé sur cette NACL, et le
blocage le dit.

**Débloquer** (`unblock_ip`). Sous le verrou de chaque NACL : retirer les entrées notées, si
elles disent encore « deny attaquant/32 », et si aucun autre blocage noté (une autre instance du
même sous-réseau) ne les tient. Sans état, rien n'est retiré : `not_found`, rien ne dit quelles
entrées sont à Glorfindel.

**Vérifier.** L'isolation est vraie si chaque ENI ne porte que le SG de quarantaine de son VPC et
que ce SG est intact, lu par son contenu. La levée est vraie si aucune ENI ne porte un SG de
quarantaine et que chaque ENI dont l'origine est connue la porte. Le blocage est vrai si, sur
chaque NACL, les entrées notées sont là, intactes, et que la première entrée qui couvre
l'attaquant dans chaque sens est un refus de tous les protocoles. Une lecture en échec donne
« inconnu », jamais « oui ».

## Hypothèses, à mesurer en MC2

| | Hypothèse (documentation d'AWS) | Où elle compte |
|---|---|---|
| H1 | un SG n'a que des autorisations ; l'union des groupes d'une ENI décide ; à états | évaluation des flux |
| H2 | une ENI porte de 1 à 5 SG, tous de son VPC ; `[]`, un sixième ou un SG d'un autre VPC est refusé (`InvalidParameterValue`, `SecurityGroupsPerInterfaceLimitExceeded`, `InvalidGroup.NotFound`) | échange de groupes |
| H3 | un SG neuf a une règle de sortie « tout autoriser » et aucune entrée | création du SG de quarantaine (retirée aussitôt) |
| H4 | le nom d'un SG est unique dans son VPC (`InvalidGroup.Duplicate`) ; le groupe `default` existe toujours ; un SG porté par une ENI ne se supprime pas (`DependencyViolation`) ; un SG recréé a un nouvel identifiant | quarantaine, levée après suppression |
| H5 | NACL sans état, entrées 1 à 32766, la plus petite qui correspond décide, `*` refuse ; une entrée entrante ne nomme que la source ; 20 entrées par sens ; un numéro pris est refusé (`NetworkAclEntryAlreadyExists`) ; supprimer une entrée absente échoue (`InvalidNetworkAclEntry.NotFound`) ; un sous-réseau a une NACL | blocage, évaluation |
| H6 | ni SG ni NACL ne filtrent le résolveur DNS d'Amazon ni l'IMDS | `platform_open` toujours déclaré |
| H7 | `create_tags` fusionne par clé ; `delete_tags` retire les clés nommées | origine en tag |
| H8 | erreurs au format de `ClientError` de botocore : codes `….NotFound`, `RequestLimitExceeded` (503), `UnauthorizedOperation` (403) | lecture des erreurs sans SDK |
| H9 | `authorize`/`revoke` d'un SG sont tout ou rien ; une règle déjà là (`InvalidPermission.Duplicate`) ou absente (`InvalidPermission.NotFound`) fait échouer l'appel | réparation du SG de quarantaine |
| H10 | une connexion suivie survit à un changement des groupes de l'ENI | pas de `session_drain` déclaré |
| H11 | `terraform apply` sur `aws_network_interface` (ou `vpc_security_group_ids` d'`aws_instance`) remet les groupes du code : il défait la quarantaine ; `aws_network_acl` à entrées en ligne retire les entrées absentes du code | monde qui bouge, réaffirmation |
| H12 | un appel d'écriture d'EC2 a pris effet quand il répond | relectures |
| H13 | une SCP ou une condition IAM peut refuser l'échange de groupes d'une seule ENI (`UnauthorizedOperation`) | isolation partielle |
| H14 | ARN d'instance `arn:aws:ec2:<région>:<compte>:instance/<id>` ; un client EC2 n'agit que dans sa région et son compte | I12 |

Non modélisé, et à mesurer avant de s'y fier : **la cohérence à terme** des lectures d'EC2 (un
`describe` juste après une écriture peut rendre l'état d'avant — les relectures de l'adaptateur
devront attendre ou réessayer en MC2), les listes de préfixes gérées, les SG référencés par un
autre SG (ils empêchent sa suppression), IPv6, les pare-feu au-dessus du VPC (AWS Network
Firewall, routes, Gateway Load Balancer).

## Les invariants sur AWS

| | Sur Azure | Sur AWS |
|---|---|---|
| I1 | aucune VM plus joignable que conçue | **tel quel** |
| I2 | configuration du client intacte ; par auteur, Glorfindel n'écrit que ce qui est à lui | **tel quel**, par le journal des appels : il crée et règle son seul SG de quarantaine, pose et retire ses tags sur lui, change les groupes d'une ENI vers sa quarantaine ou vers son origine, crée des entrées de NACL à des numéros libres et ne retire que celles qu'il a créées, contenu inchangé |
| I3 | aucun succès sur un mensonge | **tel quel**, DNS et IMDS toujours déclarés |
| I4 | une opération sur une VM ne change rien pour une autre (sauf les flux de l'attaquant d'un blocage de périmètre) | **change** : tout blocage est de périmètre (sous-réseau) ; en plus, le blocage noté d'une autre instance du même sous-réseau tient toujours (un déblocage ne retire pas des entrées qu'un autre blocage tient) |
| I5 | la réaffirmation n'ouvre rien, n'agit pas sans état, n'écrit rien en `human_only` | **tel quel** (`glorfindel/reassert.py` est commun) |
| I6 | une VM, un fichier d'état | **tel quel** (l'identifiant d'instance est unique : pas d'homonymes) |
| I7 | depuis tout état, la levée ramène à la conception, ou garde en quarantaine en disant ce qui manque | **tel quel** ; l'opérateur donne un SG recréé par le tag |
| I8 | ce qui reste sur le cloud est dans l'état | **tel quel**, et pour les blocages : toute entrée de NACL de Glorfindel encore là est notée dans un état |
| I9 | une levée commencée n'est pas défaite par la réaffirmation | **tel quel** |
| I10 | configuration respectée, illisible : rien d'écrit | **change** : quarantaine éteinte ou configuration illisible, l'isolation n'écrit rien du tout (pas de repli) ; le SG de quarantaine est dans le VPC de l'ENI (imposé par AWS) |
| I11 | deux opérations à la fois finissent comme l'une après l'autre | **tel quel**, avec un verrou de plus par NACL |
| I12 | une VM d'un autre abonnement n'est pas touchée | **change** : un autre compte ou une autre région (l'ARN), et un identifiant qui n'est pas un ARN d'instance |
| L1 | un blocage disparu est reposé ou signalé, même derrière la quarantaine | **tel quel** ; la quarantaine ne cache jamais un blocage sur AWS (la NACL est au sous-réseau) |
| U1 | une règle laissée par une carte disparue, qui coupe une carte vivante, est signalée | **sans équivalent** : aucune règle de Glorfindel n'est adressée à l'IP d'une carte |

Ce que la machine AWS ne joue pas encore : `reset --from-azure` (pas d'équivalent écrit pour AWS),
les isolations d'une ancienne version, un autre hôte qui écrit l'ENI pendant une levée (il est
joué pendant l'isolation et la levée), les instantanés et les restaurations (non déclarés).
