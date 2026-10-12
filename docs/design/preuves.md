# Comment on prouve ce qu'on avance

Glorfindel modifie le réseau d'un client, parfois seul. Une affirmation du type « la VM est
isolée » doit donc être vraie, pas probable. Ce document montre les couches de preuve, ce que
chacune voit et ne voit pas, et ce qu'elles ont trouvé. Vue d'ensemble du produit :
[`../architecture.md`](../architecture.md).

## Les couches

```mermaid
flowchart BT
    U["Tests unitaires<br/>~760, 20 s, aucun appel Azure ni LLM"]
    I["Invariants Hypothesis<br/>faux Azure, monde qui bouge, pannes, concurrence<br/>500 séquences par push, 10 000 par nuit"]
    M["Mutation<br/>bugs réels réinjectés un par un<br/>chaque lundi"]
    L["Verrous entre processus<br/>vrais flock"]
    B["Banc Celebrimbor<br/>comportements Azure mesurés"]
    C["Canary azurerm<br/>3.x, 4.x, 5.x chaque jour"]
    R["Runs réels<br/>6 TTPs, RTO mesuré"]
    U --> I --> M
    L --> I
    B --> C
    B --> R
    M -.->|"mesure la force de"| I
    B -.->|"fixe les hypothèses de"| I
```

| Couche | Ce qu'elle voit | Ce qu'elle ne voit pas |
|---|---|---|
| Tests unitaires | une fonction, un cas écrit à la main | les enchaînements, les cas auxquels personne n'a pensé |
| Invariants | des milliers de réseaux et de séquences tirés au hasard, avec pannes, monde qui bouge et deux opérations à la fois | ce que le faux Azure ne modélise pas (deux hôtes, couches au-dessus du NSG) |
| Mutation | si les invariants attrapent un bug connu | un bug d'une classe jamais vue |
| Verrous entre processus | l'exclusion mutuelle réelle de `flock` | un verrou entre deux hôtes |
| Banc Celebrimbor | le comportement réel d'Azure et de Terraform | la variété des réseaux clients |
| Canary azurerm | qu'un comportement mesuré du provider tient encore | Bicep, ARM, autres outils |
| Runs réels | la boucle complète, de l'attaque à la remise en service | la répétition à grande échelle |

Règle de travail : un comportement d'Azure ou de Terraform n'est affirmé qu'après une mesure
sur le banc. Le faux Azure reprend ces mesures ; ce qu'il suppose sans mesure est écrit en
tête de `tests/unit/fake_azure.py`.

## La machine à invariants

```mermaid
flowchart LR
    subgraph Draw["Hypothesis tire"]
        N["un réseau client<br/>NSG de carte, de tier, de subnet<br/>politiques, deux régions, Windows"]
        Q["une séquence d'étapes"]
    end
    subgraph Steps["Étapes possibles"]
        O["Glorfindel<br/>isoler, lever, bloquer, débloquer<br/>vérifier, réaffirmer, reset"]
        Wd["le monde bouge<br/>règles, IP, NSG ou VM supprimés<br/>redéploiement, terraform apply, tags"]
        F["pannes<br/>429, crash avant ou après écriture<br/>API saturée, 403, disque plein"]
        Cc["deux opérations à la fois<br/>entrelacées appel par appel"]
    end
    FA[("faux Azure en mémoire<br/>évalue les NSG comme Azure")]
    P{"11 propriétés<br/>après chaque étape"}
    N --> FA
    Q --> O & Wd & F & Cc
    O & Wd & F & Cc --> FA
    FA --> P
    P -->|"violée"| SH["Hypothesis réduit<br/>la séquence"]
    SH --> REG["exemple figé<br/>test_invariant_regressions.py"]
```

Les propriétés, vérifiées après chaque étape :

| | Propriété |
|---|---|
| I1 | aucune VM n'est plus joignable que son propriétaire ne l'a conçue |
| I2 | la configuration du client est ce qu'il a écrit en dernier ; une carte porte son NSG ou celui de quarantaine, jamais aucun ni un autre |
| I3 | aucun succès sur un mensonge : chaque vérification qui dit vrai est vraie, à chaque étape |
| I4 | une opération sur une VM ne change rien pour une autre, homonymes compris |
| I5 | la réaffirmation n'ouvre jamais rien, et n'écrit rien en `human_only` |
| I6 | une VM, un fichier d'état |
| I7 | depuis tout état atteint, la levée ramène chaque VM à sa conception, ou la garde en quarantaine en disant ce qui manque |
| I8 | ce qu'une opération laisse sur Azure est dans l'état |
| I9 | une levée commencée n'est jamais défaite par la réaffirmation |
| I10 | la configuration est respectée ; illisible, l'isolation n'écrit rien |
| I11 | deux opérations à la fois finissent comme l'une après l'autre : l'état local dit ce qu'Azure a |

### Deux opérations à la fois

La War Room, la CLI et le watch sont trois processus qui peuvent viser la même VM. Un
ordonnanceur fait avancer deux opérations un appel Azure à la fois, dans un ordre tiré au
hasard, avec les vrais verrous. Un fil qui attend un verrou le signale ; il ne reçoit son tour
qu'une fois le verrou pris.

```mermaid
sequenceDiagram
    participant S as ordonnanceur
    participant R as levée, War Room
    participant A as réaffirmation, watch
    participant L as verrou de la VM
    participant Z as faux Azure
    S->>R: à toi
    R->>L: prend le verrou
    R->>Z: note la levée en cours
    S->>A: à toi
    A->>L: attend, et le signale
    S->>R: à toi, seul prêt
    R->>Z: retire la quarantaine, relit la carte
    R->>L: rend le verrou
    L-->>A: verrou pris
    S->>A: à toi
    A->>Z: relit l'état : rien à reposer
    Note over S,Z: Verrou retiré (mutant M17) : les deux écritures s'entrelacent<br/>et l'état local finit par contredire Azure. I11 l'attrape à chaque tour.
```

Le `flock` qui sépare les processus est testé à part, sur de vrais processus
(`tests/unit/test_locks.py`) : quatre processus sur le même verrou ne se chevauchent jamais,
l'ID canonique et l'ID en minuscules prennent le même verrou, une tâche de fond renonce au
bout de son délai. Sans `flock`, ces tests échouent.

## La mesure par mutation

Un test qui passe ne dit rien de sa force. `scripts/mutation_check.py` réinjecte, un par un,
des bugs que Glorfindel a vraiment eus, dans une copie jetable du dépôt, et regarde si les
invariants les attrapent.

```mermaid
flowchart LR
    B["bug réel connu<br/>revues, L24 à L27"] --> Mu["mutant : le bug réinjecté<br/>par remplacement exact"]
    Mu --> Cp["copie jetable du dépôt"]
    Cp --> T["invariants<br/>500 séquences, 2 tours"]
    T -->|"échec"| Ok["attrapé"]
    T -->|"succès"| Ko["survit : il manque une propriété<br/>ou un mouvement du monde"]
```

| Étape | Attrapés à chaque tour, au budget du push |
|---|---|
| Invariants L24/L25, avant le monde qui bouge | 1 sur 17 |
| L26 : le monde bouge, quatre propriétés de plus | 15 sur 17 |
| L27 : deux opérations à la fois, verrou compris | 17 sur 22 (M01 à M25) |

Quatre mutants sont écartés du décompte, avec leur raison écrite dans le harnais :
- **deux équivalents** : M02 (le partage d'un NSG ne change plus la règle posée depuis L24) et
  M11 (plus aucun appelant ne voit un « not found » autre qu'un 404) ;
- **un qui demande deux hôtes**, M14 : la relecture après la levée ne sert que si un autre
  hôte écrit entre notre écriture et notre relecture. Le verrou est par hôte, et un test
  unitaire couvre ce cas.

Les mutants M18 à M25 réinjectent les défauts trouvés par la machine elle-même. Les plus rares
(M21 à M24, trouvés à des milliers de séquences) ne sont pas attrapés à chaque tour au budget
du push ; leur séquence figée, elle, les attrape à chaque push.

## Ce que les invariants ont trouvé

Aucun de ces défauts n'avait été vu en revue. Chacun a son test et sa séquence figée.

| Lot | Défaut | Effet avant correction |
|---|---|---|
| L24 | nom de règle commun aux homonymes | isoler l'un rouvrait l'autre |
| L24 | présence par nom prise pour une preuve | une règle restreinte comptait comme isolation |
| L24 | état réécrit par une ré-isolation interrompue | « released » avec une carte encore isolée |
| L24 | NSG d'origine masqué par la quarantaine | un ancien repli échappait à la levée |
| L24 | any/any sur un NSG partagé qui semblait dédié | une autre VM coupée à sa propre levée |
| L24 | subnet illisible lu comme « sans NSG » | « released » sans rien retirer |
| L24 | reste contourné qui masquait un deny sain | fausse alerte |
| L24 | déblocage sans état | « unblocked », règles en place |
| L24 | blocage sain à côté d'un ancien contourné | lu « contourné » |
| L26 | règle de l'ancienne IP après un changement d'adresse | la VM suivante sur cette IP aurait été coupée |
| L26 | blocage vérifié sur les IP du moment du blocage | « bloqué », la nouvelle adresse ouverte |
| L26 | blocage caché derrière la quarantaine | « bloqué », quarantaine vidée, attaquant passé |
| L26 | original demandé pour une carte redéployée | levée en échec pour toujours |
| L26 | seconde levée lisant l'état comme un ancien format | **NSG de quarantaine partagé vidé, VMs rouvertes** |
| L27 | déblocage aveugle derrière la quarantaine | « not_found », IP rebloquée à la levée |
| L27 | `reset --from-azure` qui lisait l'original dans le seul tag | reset partiel alors que l'état connaissait l'original |
| L27 | reset partiel qui laissait l'état intact | la réaffirmation aurait reposé ce que l'opérateur retirait |

Le plus grave : après une levée qui échoue en partie, une seconde levée lisait les champs de
rétro-compatibilité de l'état comme un ancien format, et supprimait les deny du NSG de
quarantaine **partagé**. Toutes les VMs en quarantaine du même groupe étaient rouvertes. La
machine ne l'a trouvé qu'à 5 000 séquences.

## Cadence

```mermaid
flowchart LR
    push["chaque push"] --> ci["ruff, tests unitaires<br/>py3.11, py3.12, macOS<br/>invariants 500 + rejeu"]
    nuit["chaque nuit"] --> inv["invariants 10 000<br/>Linux et macOS"]
    inv -. "séquences en échec<br/>gardées dans la base" .-> ci
    jour["chaque jour"] --> can["canary azurerm<br/>sur Azure"]
    lundi["chaque lundi"] --> mut["mutation, 1 000 séquences<br/>rouge sous 14 attrapés"]
```

Une séquence trouvée la nuit est rejouée en premier à chaque push jusqu'à sa correction, puis
écrite dans `tests/unit/test_invariant_regressions.py`.

## Ce qui n'est pas couvert

- **Deux hôtes** : les verrous sont par hôte. Deux déploiements de Glorfindel sur deux
  machines qui visent la même VM ne sont pas modélisés.
- **VM supprimée et état perdu** : les règles qu'une isolation par règles a laissées sur un
  NSG partagé sont introuvables, faute de cartes pour dire où chercher.
- **Couches au-dessus du NSG** : règles d'administration d'Azure Virtual Network Manager,
  routes, pare-feu. Elles peuvent contourner une isolation et ne sont pas encore lues.
- **Hypothèses du faux Azure** non mesurées : le code d'erreur d'un NSG d'une autre région,
  le refus de supprimer un NSG attaché, Run Command shell refusé sous Windows.
