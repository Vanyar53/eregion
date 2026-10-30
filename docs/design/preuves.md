# Comment on prouve ce qu'on avance

Glorfindel modifie le réseau d'un client, parfois seul. Une affirmation du type « la VM est
isolée » doit donc être vraie, pas probable. Ce document montre les couches de preuve, ce que
chacune voit et ne voit pas, et ce qu'elles ont trouvé. Vue d'ensemble du produit :
[`../architecture.md`](../architecture.md).

## Les couches

```mermaid
flowchart BT
    U["Tests unitaires<br/>~870, 30 s, aucun appel Azure ni LLM"]
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
    classDef data fill:#e9edf3,stroke:#8a96a8,color:#18212b
    classDef blue fill:#2f6fd6,stroke:#1d4a9a,color:#ffffff
    classDef guard fill:#f2b33d,stroke:#b07a12,color:#2b1d00
    classDef azure fill:#7b5cd6,stroke:#4f3a99,color:#ffffff
    classDef human fill:#2e9e6a,stroke:#1d6b47,color:#ffffff
    class U,L data
    class I blue
    class M guard
    class B,C azure
    class R human
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
        Wd["le monde bouge<br/>règles, IP, NSG ou VM supprimés ou créés<br/>redéploiement, terraform apply, tags<br/>règles de Glorfindel retournées, horloge"]
        F["pannes<br/>429, crash avant ou après écriture<br/>API saturée, 403, disque plein"]
        Cc["deux opérations à la fois<br/>entrelacées appel par appel<br/>un autre hôte qui écrit la carte"]
    end
    FA[("faux Azure en mémoire<br/>évalue les NSG comme Azure")]
    P{"15 propriétés<br/>après chaque étape"}
    N --> FA
    Q --> O & Wd & F & Cc
    O & Wd & F & Cc --> FA
    FA --> P
    P -->|"violée"| SH["Hypothesis réduit<br/>la séquence"]
    SH --> REG["exemple figé<br/>test_invariant_regressions.py"]
    classDef data fill:#e9edf3,stroke:#8a96a8,color:#18212b
    classDef blue fill:#2f6fd6,stroke:#1d4a9a,color:#ffffff
    classDef human fill:#2e9e6a,stroke:#1d6b47,color:#ffffff
    classDef red fill:#d64545,stroke:#9e2a2a,color:#ffffff
    classDef azure fill:#7b5cd6,stroke:#4f3a99,color:#ffffff
    classDef guard fill:#f2b33d,stroke:#b07a12,color:#2b1d00
    class N,Q,SH,REG data
    class O,Cc blue
    class Wd human
    class F red
    class FA azure
    class P guard
    style Draw fill:#f4f7fb,stroke:#aab4c3,color:#18212b
    style Steps fill:#f4f7fb,stroke:#aab4c3,color:#18212b
```

Les propriétés, vérifiées après chaque étape :

| | Propriété |
|---|---|
| I1 | aucune VM n'est plus joignable que son propriétaire ne l'a conçue |
| I2 | la configuration du client est ce qu'il a écrit en dernier ; une carte porte son NSG ou celui de quarantaine, jamais aucun ni un autre ; et, par auteur (journal des écritures de l'API), Glorfindel n'écrit que ce qui est à lui |
| I3 | aucun succès sur un mensonge : chaque vérification qui dit vrai est vraie, à chaque étape |
| I4 | une opération sur une VM ne change rien pour une autre, homonymes compris — et ne supprime jamais l'ancienne isolation d'une autre VM, même là où aucun flux ne le dit (I4S, lu dans le journal du test) |
| I5 | la réaffirmation n'ouvre jamais rien, et n'écrit rien en `human_only` |
| I6 | une VM, un fichier d'état |
| I7 | depuis tout état atteint, la levée ramène chaque VM à sa conception, ou la garde en quarantaine en disant ce qui manque |
| I8 | ce qu'une opération laisse sur Azure est dans l'état |
| I9 | une levée commencée n'est jamais défaite par la réaffirmation |
| I10 | la configuration est respectée ; illisible, l'isolation n'écrit rien |
| I11 | deux opérations à la fois finissent comme l'une après l'autre : l'état local dit ce qu'Azure a |
| I12 | une VM d'un autre abonnement n'est jamais touchée, ni déclarée isolée |
| L1 | un blocage dont les règles ont disparu est reposé ou signalé, même derrière la quarantaine |
| L2 | un NSG de quarantaine que quelqu'un a modifié, et qui porte encore des cartes, est reposé ou signalé — l'état de ces cartes perdu compris (I1F) ; signalé, il le reste quand il sort de la liste : rôle retiré sur son groupe, notre tag retiré (I1S) |
| U1 | une règle laissée par une carte qui n'existe plus, et qui coupe une carte vivante, est signalée, puis retirée par le balayage — sauf si une de nos règles retournée en autorisation se tient derrière elle : gardée et dite (I5Q) ; rien d'autre ne bouge ; en fin de séquence, chaque VM vivante revient à sa conception en entier (A3) |

**Des oracles qui ne demandent rien au code.** Ce qu'une propriété juge vient du journal du test :
la levée qu'il a demandée (I9), ce qu'il a perdu et quand (une carte « intraçable »), qui a écrit
quoi (I2 par auteur). Lire les marqueurs que le code pose revenait à le croire sur parole : un bug
qui efface l'état d'une carte gagnait l'exemption prévue pour une carte dont l'état est perdu (A0).

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

**Une course qui ne revient pas échoue, elle ne fige pas le job (U3F).** Un tour qui dure plus
de 20 s (temps réel) fait échouer I11 : « operations stuck » ou « … never came back ». Le fil qui
attendait son tour y restait, ses verrous pris, et le teardown qui les prend ensuite attendait
sans fin. L'ordonnanceur abandonne maintenant la course avant de lever l'échec : chaque fil en
attente lève `_Abandoned`, qui ne dérive pas d'`Exception` (aucun `except Exception` du code ne
l'avale), et relâche ses verrous en se déroulant (`test_a_stuck_race_fails_and_lets_the_teardown_through`,
M1346). Le délai d'un tour reste 20 s.

Ce délai ne voyait pas tout interblocage (relecture d'U3F). Un verrou piloté pris est réessayé à
chaque tour, sans fin quand l'appelant ne donne pas de délai (les verrous de VM des écritures) :
si op-1 tient A et veut B pendant qu'op-2 tient B et veut A, chacun rend son tour à chaque essai,
chaque tour revient à temps, et I11 ne tombait jamais — la course tournait sans fin. L'ordonnanceur
compte maintenant les tours d'affilée passés seulement sur des verrous trouvés pris : au-delà de
2 000, I11 tombe, « livelock (deadlock between driven locks?) », par le même chemin d'abandon
(`test_two_driven_locks_taken_in_reverse_order_fail_fast`, M1349 ; une seconde environ). Mesuré à
500 séquences, le plus long de ces passages dans une vraie course est de 10 à 16 tours selon les
graines, pour une limite de 2 000. Ce qui est tenu : un interblocage entre verrous pilotés échoue en bien moins d'un
tour de délai ; un fil bloqué hors de la vue de l'ordonnanceur (un verrou non piloté, une attente
quelconque) échoue au bout d'un tour, 20 s. Un tel fil ne se déroule pas : l'échec le nomme
(« still running, never unwound »), et le teardown de la machine saute alors la remise à plat qui
attendrait derrière ses verrous — I11 a déjà échoué (M1440). Ce qu'il tient reste tenu : les
registres de verrous du processus (`locks._VM_LOCKS`, `_QUARANTINE_LOCKS`, `_FILE_LOCKS`) ne sont
jamais remis à zéro entre deux exemples, et l'exemple suivant — Hypothesis en rejoue pendant la
réduction — attendait derrière lui à sa première écriture sur la même VM. Les courses suivantes
reçoivent des registres neufs (le `flock` ne gêne pas : un nouvel exemple a un nouveau HOME, donc de
nouveaux fichiers), et chaque fil d'une course a un nom à elle (`op-1#7`, les messages d'I11 disent
`op-1`) : réveillé plus tard, un tel fil n'entre jamais dans une course suivante
(`test_a_thread_out_of_sight_holding_a_lock_does_not_hang_the_teardown`, M1442). Ce qui ne l'est
pas : un fil qui boucle sans jamais rendre son tour ni prendre de verrou piloté, et un fil qui
boucle **en rendant son tour** — des appels Azure sans fin, chaque tour productif — ne sont vus que
par la borne du job. Les jobs qui lancent la machine sont bornés : CI Linux 30 min, macOS 25 min, nuit
150 min (M1347, M1348) ; sur Linux comme sur macOS, un test qui dure plus de 8 min écrit la pile de
ses fils (M1441).

## La mesure par mutation

Un test qui passe ne dit rien de sa force. `scripts/mutation_check.py` réinjecte, un par un,
des bugs que Glorfindel a vraiment eus, dans une copie jetable du dépôt, et regarde si les
invariants les attrapent.

```mermaid
flowchart LR
    B["bug réel connu<br/>revues, L24 à L28"] --> Mu["mutant : le bug réinjecté<br/>par remplacement exact"]
    Mu --> Cp["copie jetable du dépôt"]
    Cp --> T["invariants<br/>1 000 séquences, 2 tours"]
    T -->|"échec"| Ok["attrapé"]
    T -->|"succès"| Ko["survit : il manque une propriété<br/>ou un mouvement du monde"]
    classDef red fill:#d64545,stroke:#9e2a2a,color:#ffffff
    classDef data fill:#e9edf3,stroke:#8a96a8,color:#18212b
    classDef guard fill:#f2b33d,stroke:#b07a12,color:#2b1d00
    classDef go fill:#2e9e6a,stroke:#1d6b47,color:#ffffff
    classDef warn fill:#fbe3e3,stroke:#d64545,color:#7a1f1f
    class B,Mu red
    class Cp data
    class T guard
    class Ok go
    class Ko warn
```

| Étape | Attrapés à chaque tour, au budget du push |
|---|---|
| Invariants L24/L25, avant le monde qui bouge | 1 sur 17 |
| L26 : le monde bouge, quatre propriétés de plus | 15 sur 17 |
| L27 : deux opérations à la fois, verrou compris | 17 sur 22 (M01 à M25) |
| A0 : monde v3 (voir plus bas), 41 mutants | 22 sur 36 par les séquences tirées, les autres par leur séquence figée |

**Le jeu de contrôle.** Seize bugs plausibles proposés par la septième passe, jamais utilisés pour
orienter la génération (`--control`) : il mesure si la suite trouve ce qu'on ne lui a pas appris.
Au budget du push : 3 sur 16 à son arrivée, 6 après la première étape d'A0, **10 sur 16** à la fin
d'A0 (et 2 intermittents).

Écartés du décompte, avec leur raison écrite dans le harnais : **M11** (plus aucun appelant ne voit
un « not found » autre qu'un 404) et **M25** (depuis A0 le reset note son intention avant de toucher
Azure : l'état d'un reset partiel est tenu de toute façon). **M02** et **M14**, autrefois écartés,
sont attrapés depuis A0 : M02 par les isolations d'une ancienne version dans le monde, M14 par un
autre hôte qui écrit la carte juste après Glorfindel. M36 (fichier d'état ancien) n'est couvert que
par un test unitaire : il faut un crash entre deux opérations de fichier.

Les mutants M18 à M29 réinjectent les défauts trouvés par la machine elle-même. Les plus rares
(M21 à M24, trouvés à des milliers de séquences) ne sont pas attrapés à chaque tour au budget
du push ; leur séquence figée, elle, les attrape à chaque push.

### Les pannes des dépendances (G2)

Les invariants modélisent les pannes d'Azure sous l'isolation (429, crash, 403, disque plein).
G2 couvre les autres dépendances de la décision — le modèle, l'API du cloud au contrôle de
préparation, la télémétrie de l'enquête, la configuration — par dix-sept mutants mesurés par
`tests/unit/test_dependency_failures.py` (table `TESTS`). Les pannes passent par un cycle
complet du graphe, avec un témoin positif qui exécute quand rien ne tombe ; les lecteurs des
réglages (borne de l'appel, seuil, âge d'approbation, lecture seule, `docker-compose.yml`)
sont testés directement :

| Mutant | Panne réinjectée | Effet |
|---|---|---|
| M151 | l'appel de décision sans borne | un modèle pendu tient la file de la VM des heures, sans carte |
| M152 | VM jamais contrôlée tenue pour prête | Azure injoignable au contrôle : la VM agit seule |
| M153 | requête d'enquête en échec lue comme « aucune ligne » | isolation décidée sur une absence que la télémétrie n'a pas dite |
| M154 | garde de télémétrie retirée | idem, l'échec connu mais ignoré |
| M155 | `--mode` appliqué sur une configuration illisible | une VM épinglée `human_only` devient autonome |
| M156 | seuil de confiance illisible accepté | `nan` ou `-1` : la porte de confiance ne retient plus rien |
| M157 | interrupteur de lecture seule lu strictement | `on`, `TRUE` : les écritures restent ouvertes |
| M158 | âge maximal d'approbation `nan` ou `inf` accepté | une carte de tout âge s'exécute depuis la War Room |
| M170 | âge maximal d'approbation ≤ 0 ramené à 2 h | une approbation en un clic fermée exprès se rouvre |
| M171 | âge maximal ≤ 0 sans refus propre | une carte datée en avance sur l'horloge s'exécute |
| M172 | porte de confiance écrite `confiance < seuil` | une confiance `NaN` du modèle passe la porte |
| M173 | confiance du modèle non bornée | un 5.0 s'affiche 500 % sur la carte et dans la mémoire |
| M174 | requêtes en échec tues sur une carte retenue plus tôt | l'opérateur approuve sans savoir que l'enquête n'a rien lu |
| M175 | `GLORFINDEL_LLM_TIMEOUT_S` absent d'`x-env` | réglé dans `.envrc`, ignoré par les conteneurs |
| M176 | seuil lu dans l'agent par la War Room | un import en échec fait disparaître la matrice de capacités |
| M177 | `--mode` appliqué à la bannière sur une configuration illisible | la bannière annonce un mode que rien n'applique |
| M178 | carte d'une configuration illisible lue « réponse autonome configurée » | elle annonce un mode que personne n'a configuré |

M151–M158 : huit sur huit attrapés au premier tour (21/10) ; M170–M178, ajoutés après la
relecture : neuf sur neuf (21/10). Détail des pannes et de ce que fait Glorfindel :
[`../glorfindel.md`](../glorfindel.md), « Pannes des dépendances ».

### La stabilité de la décision (D-1)

La même force brute a reçu un blocage à 0,80 le 21/10, puis une isolation à 0,78 le 23/10.
D-1 fixe la température du premier tirage (0, ou l'échantillonnage par défaut d'un modèle
qui la refuse, comme `claude-sonnet-5-5`), et ne laisse partir seule une action disruptive
que si plusieurs tirages s'accordent. Treize mutants, mesurés par
`tests/unit/test_decision_stability.py` ; les cycles passent par le graphe complet là où la
carte compte :

| Mutant | Défaut réinjecté | Effet |
|---|---|---|
| M200 | premier tirage sans température | rien ne fixe le tirage, même sur un modèle qui l'accepte |
| M201 | refus de la température non rattrapé | `claude-sonnet-5-5`, le modèle par défaut : toute décision échoue |
| M202 | tirage dit fixé sur un modèle qui a refusé | la ligne de debug ment sur la reproductibilité |
| M203 | accord des tirages jamais vérifié | une action disruptive part sur un seul tirage |
| M204 | tirages de confirmation à la température du premier | ils répètent le premier au lieu de sonder la variance |
| M205 | tirage de confirmation sous le seuil compté d'accord | une isolation à 40 % confirme une isolation à 95 % |
| M206 | tirage en échec écarté, les autres comptés | un fournisseur qui tombe à mi-chemin laisse passer l'action |
| M207 | moins de tirages que demandé comptés d'accord | idem, sans même un échec |
| M208 | `GLORFINDEL_DECISION_DRAWS=1` accepté | un seul tirage, aucun accord |
| M209 | valeur illisible lue comme le défaut | une faute de frappe n'est plus vue |
| M210 | garde d'accord sans type de carte | la carte dit « confiance insuffisante » |
| M211 | carte instable non approuvable en un clic | l'opérateur ne peut pas exécuter le premier tirage qu'il juge bon |
| M212 | `GLORFINDEL_DECISION_DRAWS` absent d'`x-env` | réglé dans `.envrc`, ignoré par la watch |

Treize sur treize attrapés au premier tour (26/10). Détail :
[`../glorfindel.md`](../glorfindel.md), « Stabilité de la décision ».

### Une fenêtre d'exercice n'est plus crue sur parole (H-1)

Qui écrit dans `runs/exercises/` ou dans le canal pouvait faire passer une vraie attaque pour
un exercice. H-1 met les gardes côté lecteur : la watch, et H0 pour les campagnes. Dix-neuf
mutants, mesurés par `tests/unit/test_exercise_guard.py` (M57 suit la vérification des cibles
dans `_targets`) :

| Mutant | Défaut réinjecté | Effet |
|---|---|---|
| M220 | fenêtre plus longue que 2 h crue | une fenêtre d'un jour couvre toute la journée |
| M221 | fenêtre déclarée pour plus tard crue | elle couvre ce qui viendra |
| M222 | VM non inscrite marquée | la vraie charge passe pour un exercice |
| M223 | raccourci par `run_id` sur une VM que la fenêtre ne nomme pas | n'importe quelle VM marquée par un nom de run |
| M224 | carte d'exercice cachée de TO JUDGE | une vraie attaque couverte n'atteint jamais l'opérateur |
| M225 | fenêtre jamais purgée | son `run_id` marque encore des semaines plus tard |
| M226 | fenêtre nommée `watch-…` crue | une détection du RulePoller devient un exercice par son `run_id` |
| M227 | sans vérification d'inscription, tout est inscrit | une watch qui ne peut pas lire les tags croit toutes les fenêtres |
| M228 | lecture des tags en échec lue « inscrite » | un 403 ouvre la porte |
| M229 | fenêtre écrite aujourd'hui pour demain crue demain | le refus du futur ne dure qu'un jour |
| M230 | fenêtre purgée supprimée au lieu d'être vidée | le canal la ramène à chaque tirage |
| M231 | manifeste d'une autre forme accepté par H0 | rapport écrit sur un fichier forgé |
| M232 | run du canal sans fenêtre connue gardé | un run inventé entre dans les faits |
| M233 | run du canal sur une VM non inscrite gardé | idem, sur la vraie charge |
| M234 | run du canal sur une VM que sa fenêtre ne nomme pas gardé | idem |
| M235 | provenance des faits tue dans le rapport | le lecteur prend le manifeste pour une observation |
| M236 | scénario du canal mal formé gardé | des chiffres non typés dans les faits |
| M237 | rapport de run d'un autre run gardé | l'heure d'attaque d'un autre run |
| M238 | fenêtre de plus de 2 h bornant la recherche d'une décision | une décision de trois jours rattachée au run |

Dix-neuf sur dix-neuf attrapés au premier tour (26/10), et M57 aussi. Détail :
[`../glorfindel.md`](../glorfindel.md), « Une fenêtre n'est plus crue sur parole », et
[`../analysis.md`](../analysis.md), « Ce que H0 accepte du canal ».

### Le découpage d'`actions.py` (A1, MC0)

Un découpage ne doit rien changer : il est prouvé par ce qui précède, avant et après. Les
4 394 lignes d'`actions.py` ont été déplacées sans changement de texte
(`scripts/check_paragraphs.py --old 03b29ce:glorfindel/actions.py` retrouve chaque ligne, hors la
ligne `class AzureConnector(...)`), dans `glorfindel/response/` et `glorfindel/providers/azure/`.
Les mutants qui visaient `actions.py` visent maintenant le module où leur texte est arrivé (aucun
STALE). `glorfindel/actions.py` reste le chemin d'import, et un seul espace de noms : un
`monkeypatch` à travers lui atteint chaque module qui lit le nom — sans quoi le `conftest`
hermétique n'aurait redirigé l'état que dans un module, et les verrous auraient écrit sous le
vrai `~/.glorfindel`.

Mesuré le 26/10 au budget du lundi (1 000 séquences, 2 tours), avant (`03b29ce`) et après :

| | Avant | Après |
|---|---|---|
| Suite complète | 1 535 | 1 549 (+ 14 tests d'A1) |
| Invariants à 500 séquences, rejeu, verrous | verts | verts (31) |
| Harnais, attrapés à chaque tour | 216 sur 230 | 227 sur 240 (217 sur 230, et les 10 d'A1) |
| Jeu de contrôle | 11 sur 16 | 11 sur 16 (C07, C10, C12 survivent avant comme après) |

Les écarts sur M01–M41 sont ceux du tirage (M22, M23, M28, M31, M32, M36, M38, M39 passent
de « flaky » à « figé seulement » ou l'inverse) : aucun mutant attrapé à chaque tour avant ne
l'est plus après.

Quatorze mutants pour ce qu'A1 et MC0 ajoutent (M460–M463 après la relecture), tous attrapés au premier tour (26/10), mesurés par
`tests/unit/test_actions_split.py`, `test_provider_boundary.py`, `test_readiness.py` et
`test_jobs.py` :

| Mutant | Défaut réinjecté | Effet |
|---|---|---|
| M450 | une écriture à travers la façade n'atteint qu'un module | les verrous restent sous le vrai `~/.glorfindel` |
| M451 | la façade lie des copies | une valeur que son module change (`_warmed_up`) se lit périmée |
| M452 | un module du découpage oublié par la façade | ses noms injoignables par `glorfindel.actions` |
| M453 | droits des règles lus sur ceux de la quarantaine | « blocage possible » sans droit sur les règles |
| M454 | capacité disponible malgré ses droits manquants | « prête » sans les droits |
| M455 | capacité non déclarée comptée disponible | un fournisseur sans coupure de sessions passe pour l'avoir |
| M456 | connecteur sans déclaration lu comme Azure | un second fournisseur jugé sur les droits d'Azure |
| M457 | la frontière laisse le SDK d'un fournisseur dans l'adaptateur d'un autre | le contrôle de CI ne voit plus la fuite |
| M458 | la déclaration d'Azure dérive de `check_permissions` | la préparation lit un droit que personne ne vérifie |
| M459 | job de restauration relu dans le groupe de la VM | le statut d'une restauration jamais trouvé |
| M460 | capacités lues sur `type()` | un `MagicMock(spec=AzureConnector)` fait tomber la préparation |
| M461 | la déclaration portée par l'instance ignorée | un connecteur jugé sur les droits de sa classe |
| M462 | une dette du socle partagé déclarée adaptateur | la frontière ne la voit plus |
| M463 | suppression à travers la façade ignorée en silence | `mock.patch` laisse sa valeur dans tous les modules |

### Le monde simulé AWS (MC1)

Les invariants tournent aussi sur un faux AWS (`tests/unit/fake_aws.py`), avec l'adaptateur AWS
écrit contre lui (`glorfindel/providers/aws/`) : `tests/unit/test_invariants_aws.py`, la même
machine, le même harnais (pannes, deux opérations à la fois avec les vrais verrous, journal par
auteur), les mêmes réglages `GLORFINDEL_INVARIANT_*` ; en CI, à 500 séquences avec le reste, et chaque nuit à 10 000 (AWS1). Code
seul : aucun appel AWS, aucun compte. **La sémantique d'AWS du faux monde est faite d'hypothèses
tirées de la documentation, toutes à mesurer sur le banc AWS (MC2)** : leur liste (H1–H14), ce
qu'isoler, bloquer et lever veulent dire sur AWS et la transposition de chaque invariant sont dans
[`monde-aws.md`](monde-aws.md). I1–I12 et L1 tiennent, transposés là où AWS diffère (I4 : tout
blocage est à l'échelle de l'ACL : tous les sous-réseaux qui lui sont associés, souvent tout le VPC pour l'ACL par défaut, et le blocage d'une autre instance tient ; I10 : pas de repli par
règles ; I12 : compte et région) ; U1 n'a pas d'équivalent.

Ce que la machine AWS a trouvé dans l'adaptateur en se construisant, avant toute revue :

| Défaut | Effet avant correction |
|---|---|
| un blocage réutilisait les entrées d'un autre, qu'une autorisation ajoutée depuis par le client précède | « bloqué », l'instance joignait l'attaquant sur ses ports hauts |
| le blocage n'était pas relu | idem, dès qu'une entrée posée passe après une autorisation |
| une ENI laissée sur `default`, un de ses groupes d'origine supprimé | la levée retentait l'origine de l'état, jamais le tag que l'opérateur pose |

Mesuré le 26/10 au budget du lundi (1 000 séquences, 2 tours). Dix-huit mutants, M600–M617 :
les défauts trouvés, et ceux que la note de conception ou l'histoire d'Azure nomment. M600, M601,
M602, M608, M612 et M614, rares dans les séquences tirées (M600 trouvé à 5 000), sont aussi mesurés
par leur cas écrit à la main (`tests/unit/test_aws_adapter.py`) ; M617, une fausse alerte sans
fausse affirmation, par lui seul.

| Mutant | Défaut réinjecté | Attrapé |
|---|---|---|
| M600 | un blocage réutilise une entrée qu'une autorisation du client précède | à chaque tour |
| M601 | le blocage n'est pas relu | à chaque tour |
| M602 | ENI sur `default`, groupe d'origine supprimé : l'origine de l'état, jamais le tag | à chaque tour |
| M603 | quarantaine éteinte ignorée : écritures sans repli (I10) | à chaque tour |
| M604 | DNS et IMDS d'Amazon non déclarés par l'isolation (H6) | à chaque tour |
| M605 | une ENI laissée sur `default` ne retrouve pas son origine (U2) | à chaque tour |
| M606 | ré-isoler une ENI laissée sur `default` note `default` comme origine (U2) | un tour sur deux |
| M607 | ENI déjà en quarantaine : ce qu'elle porte lu comme son origine (S1) | à chaque tour |
| M608 | une autorisation ajoutée au groupe de quarantaine y reste | à chaque tour |
| M609 | une vérification qui ne lit pas une ENI dit « isolée » | à chaque tour |
| M610 | l'isolation n'est pas notée (I8) | à chaque tour |
| M611 | une levée en échec efface l'état (I8) | à chaque tour |
| M612 | pas de verrou par ACL : un déblocage retire les entrées qu'un blocage voisin réutilise | à chaque tour |
| M613 | verrou de l'instance inopérant (le M17 d'AWS) | un tour sur deux |
| M614 | une entrée lue comme de Glorfindel quelle que soit l'adresse qu'elle refuse | à chaque tour |
| M615 | un déblocage garde le blocage noté | à chaque tour |
| M616 | `verify_isolation` se porte garant d'une instance d'un autre compte (I12) | à chaque tour |
| M617 | isolation vérifiée sur les ENI lues avant l'échange | à chaque tour |

La relecture de MC1 a trouvé quatre trous, corrigés : un blocage annonçait le sous-réseau de
l'instance alors qu'une ACL en sert souvent plusieurs (celle par défaut d'un VPC sert tous les
sous-réseaux qu'on n'a pas associés ailleurs) ; un groupe de quarantaine privé de son tag
`managed-by` laissait la levée dire `released`, état effacé, l'ENI encore dedans ; la garde de compte
et de région s'ouvrait quand l'adaptateur n'en avait pas ; une instance sans interface était dite
isolée. Six mutants de plus, M618–M623, mesurés par leurs cas de `tests/unit/test_aws_adapter.py` :

| Mutant | Défaut réinjecté |
|---|---|
| M618 | un blocage ne nomme que les sous-réseaux de l'instance, pas tous ceux de son ACL |
| M619 | une ENI qui porte un groupe nommé comme la quarantaine, que rien ne note, dite levée |
| M620 | garde ouverte sans compte ni région configurés (I12) |
| M621 | une instance sans interface dite isolée |
| M622 | le groupe de quarantaine noté dans l'état ignoré une fois son tag perdu |
| M623 | `verify_release` aveugle à un groupe nommé comme la quarantaine |

**Un échec instable, c'était l'oracle** (AWS1, #334, 30/10). Vu une fois à la relecture de C1, passé à
la relance. La séquence : notre blocage de `i-web1` (deny entrant et sortant au numéro 99, sous l'allow
100 de l'ACL par défaut), l'entrée entrante retournée par quelqu'un, la remise en état (l'opérateur ôte
ce qu'on a retourné, le déblocage ôte la sortante), puis le client pose sa propre entrée entrante au
numéro 99, libre. I2 disait « customer entries changed » sur un monde tel que le client l'a écrit.
Le faux garde, à `(ACL, sens, numéro)`, ce que Glorfindel a écrit tant que Glorfindel ne l'a pas ôté tel
quel : l'opérateur l'ayant ôté hors de l'API, la trace restait. L'oracle écartait des entrées du client
toute entrée à une clé de cette trace (ou d'une altération) : l'entrée du client au numéro repris
manquait d'un côté, pas de l'autre. **Ni le faux ni l'adaptateur n'avaient tort** : un numéro libre se
prend (AWS refuse un numéro pris, `NetworkAclEntryAlreadyExists`, et la suppression le libère : H5, à
mesurer au banc, MC2 ; ici le numéro était libre, ce comportement ne décidait pas) ; le déblocage n'ôte
qu'une entrée encore telle qu'il l'a écrite (`_is_our_deny`), celle du client n'est jamais touchée.
**L'oracle écarte maintenant une entrée par son contenu** : celle de Glorfindel telle qu'il l'a écrite,
ou ce que quelqu'un en a fait. Il n'écarte rien de plus qu'avant : la seule séquence qu'il laisse passer
en plus est celle où l'entrée du client à cette clé est exactement celle du design (A0). Séquence
figée, et son pendant — l'entrée du client à ce numéro, changée ou ôtée par un autre, se voit
(`tests/unit/test_invariant_regressions_aws.py`). Deux mutants de l'oracle : M1950 (l'exclusion par la
clé, le défaut), M1951 (la clé écartée des deux côtés, le correctif tentant qui affaiblit), attrapés à
chaque tour.

Pourquoi instable : il faut, dans l'ordre, un blocage, l'altération de l'une de ses entrées, une remise
en état, puis une entrée du client sur la même ACL (une sur cinq), dans le même sens (une sur deux
environ) et au même numéro (un sur sept). Sur la base, **1 run sur 24 à 500 séquences** (graines
100–123, `--hypothesis-seed`, sans réduction : la graine 101, même empreinte, sur `acl-default-vpc-b`) ;
après, 24 sur 24 verts sur les mêmes graines, et verts à 2 000 séquences (graines 2000 et 101).
La base Hypothesis de la CI ne pouvait pas la rejouer : au push, le cache `.hypothesis-invariants` est
seulement restauré ; seul le job de nuit l'enregistre, et il ne lançait que `test_invariants.py` (Azure) —
un échec de la machine AWS n'était gardé nulle part, une autre branche tirait de nouvelles graines.
**Depuis AWS1, la machine AWS tourne aussi chaque nuit** (`.github/workflows/invariants.yml`, une étape
à elle, lancée même si celle d'Azure échoue), au même budget (10 000) et dans la même base, que le job
Linux du push restaure et rejoue pour les deux machines (`pytest tests/`, 500). Durée estimée : 19 min
en local à 10 000 (2 000 en 225 s), 20 à 40 min sur un runner, soit 75 à 105 min avec Azure sur Linux,
sous la borne de 150 min — à mesurer au premier run de nuit. Chaque machine a sa borne d'étape
(Azure 95 min, AWS 45) : un dépassement fait échouer son étape sans annuler le job, l'étape AWS tourne
encore et la base est enregistrée après les deux (`always()`). Tenu par `tests/unit/test_workflows.py`
(`-k night_runs_both`, `-k push_replays`) ; mutants M1952 (l'étape AWS ôtée) et M1953 (la base
enregistrée seulement sur une nuit verte), attrapés.

**Le jeu de contrôle sur AWS.** Seize bugs plausibles de l'adaptateur, M630–M645, écrits et commités
avant la machine AWS (dans le même commit que l'adaptateur) et jamais utilisés pour l'orienter, dans la
discipline de C01–C16 (`--control`). Au budget du lundi, **AWS 9 à 10 sur 16, Azure 9 à 11 sur 16,
selon le tirage** : 10 sur 16 sur la machine finale (M631 un tour sur deux), 9 sur 16 à la relecture
(M638 survit, M630 un tour sur deux, M631 attrapé) ; Azure 11 puis 10 sur 16 sur la base, 9 sur 16 sur
la branche à la relecture, code identique. M630, M631 et M638 sont au bord du tirage. Les survivants
constants, ce qu'il manque pour les voir — non ajouté, pour ne pas orienter la génération sur eux :

| Mutant | Défaut | Ce que la machine ne joue pas |
|---|---|---|
| M633 | les groupes d'une ENI écrits sans vérifier ce qu'elle porte | quelqu'un qui change l'ENI entre la lecture de Glorfindel et son écriture |
| M636 | une entrée numérotée sans regarder les autorisations du client | rien de faux n'est dit : la relecture (M601) dit `partial` ; aucune propriété n'exige qu'un blocage possible soit posé |
| M640 | un blocage vérifié sans les entrées qui le précèdent | une autorisation du client glissée devant sur un port que les sondes regardent |
| M641 | une ENI qui porte la quarantaine parmi d'autres groupes, lue isolée | quelqu'un qui ajoute un groupe à une ENI en quarantaine |
| M644 | un groupe au nom de la quarantaine, sans son tag, adopté | un groupe du client qui porte ce nom (un test unitaire le couvre) |

**Azure inchangé.** Aucun fichier d'Azure n'a bougé (seule la docstring de
`glorfindel/providers/__init__.py`). Mesuré au même budget, avant (`18df2d6`) et après :

| | Avant | Après |
|---|---|---|
| Suite complète | 1 654 | 1 680 (+ 26 tests de MC1) |
| Invariants Azure à 500 séquences, rejeu, verrous | verts (31) | verts (31) |
| Harnais, mutants d'Azure attrapés à chaque tour | 297 sur 311 | 299 sur 311 |
| Jeu de contrôle d'Azure | 11 sur 16 (10 à la relecture) | 10 sur 16 (C05 ; 9 à la relecture) |

Les écarts sont ceux du tirage : M34 passe de « attrapé » à « un tour sur deux », M21, M36, M41
l'inverse ; C05 survit à 2 tours. Remesurés à 4 tours sur le code d'après, C05 et M34 sont attrapés
3 fois sur 4, M21 4 fois sur 4, M36 jamais (il était « un tour sur deux » avant) : des mutants au bord
du tirage, comme A1 l'avait noté pour M22–M39.

### Ce qui a changé depuis la campagne précédente (D-2)

Le rapport de campagne se compare à la campagne précédente. Le code la choisit par une règle :
la dernière campagne `done` antérieure qui partage une clé (une technique sur une VM). Il joint
les runs par clé en faits typés, rend la section, et écarte un écart qui ne vient pas d'un
fait. Vingt mutants, mesurés par `tests/unit/test_campaign_changes.py`, sur des campagnes
écrites sur le disque :

| Mutant | Défaut réinjecté | Effet |
|---|---|---|
| M260 | campagne `aborted` choisie | le rapport se compare à une campagne interrompue |
| M261 | campagne postérieure choisie | il se compare à l'avenir |
| M262 | campagne sans clé commune choisie | aucune ligne à comparer, la vraie précédente ignorée |
| M263 | clé sans la VM | une technique sur une autre VM passe pour la même |
| M264 | la plus ancienne choisie | l'écart porte sur une campagne dépassée |
| M265 | section muette sans précédente | le lecteur ne sait pas pourquoi rien n'est comparé |
| M266 | VM comparée avec sa casse | la même VM, écrite autrement, n'a plus de précédent |
| M267 | clés d'un seul côté tues | une technique qui n'est plus jouée disparaît sans un mot |
| M268 | scénario sauté compté comme clé | une technique jamais jouée est comparée |
| M269 | runs indexés sans l'état ni le début de leur campagne | aucun rapport n'a jamais de précédente |
| M270 | deux runs d'une même clé appariés à l'envers | le premier fait face au dernier |
| M271 | section absente du rapport | la comparaison calculée n'est pas rendue |
| M272 | faits de changement absents du message au modèle | il ne peut pas les citer |
| M273 | affirmation `change` sans fait de changement gardée | un écart affirmé sans fait |
| M274 | nombre absent des faits cités gardé | « 40 s plus tard » quand l'écart est de 15 s |
| M275 | nombres d'une tendance non contrôlés | le même écart inventé, écrit en `trend` |
| M276 | noms lus comme des nombres | « T1110.001 » écarte une affirmation juste |
| M277 | `value` d'un changement non contrôlé | une action qu'aucun fait ne porte |
| M278 | campagne reversée : faits recalculés | une décision vue par le rapport devient inconnue après la purge |
| M279 | campagne en cours versée dans l'index | des faits incomplets entrent dans l'index |

Vingt sur vingt attrapés au premier tour (26/10). La relecture de D-2 a trouvé quatre trous dans
la vérification : un écart inventé passait s'il était écrit en `observation` ; « a isolé » sur
une décision inconnue passait dès qu'un fait de changement était cité ; des tendances justes
étaient barrées (un écart entre deux runs, « le 21 octobre », « en 2026 », « au 2ᵉ run », « dans
les 2 campagnes ») ; le sens d'un changement n'était pas lu. M275 et M276 suivent le code
corrigé. Dix mutants de plus, dans la plage M510–M519 (M260–M279 est pleine), mesurés par le
même fichier :

| Mutant | Défaut réinjecté | Effet |
|---|---|---|
| M510 | nombres d'une `observation` qui cite un fait de changement non contrôlés | « vue 40 s plus tard » gardé en `observation` |
| M511 | fait de changement cité : « a isolé » permis quels que soient ses côtés | une décision inconnue dite prise |
| M512 | écart entre deux runs cités refusé | « augmente de 15 s » barré dans une tendance juste |
| M513 | date en toutes lettres, année, ordinal lus comme des nombres | « le 21 octobre », « en 2026 », « au 2ᵉ run » barrés |
| M514 | décompte lu comme un nombre de fait | « dans les 2 campagnes » barré |
| M515 | décompte sans borne | « dans les 3 campagnes » gardé avec deux runs cités |
| M516 | action ou détection absente des faits gardée | « de detected à missed » sur une clé détectée deux fois |
| M517 | passage d'une action à une autre non contrôlé | « de l'isolement au blocage » quand c'est l'inverse |
| M518 | nombres à l'envers gardés | « de 106,9 s à 91,9 s » quand la latence a augmenté |
| M519 | côté d'un fait lu sur l'identifiant du run | un run sans `run_id` dit « seulement dans la précédente » |

Les trente (M260–M279, M510–M519) attrapés au premier tour (26/10), aucun périmé.

La deuxième relecture de D-2 a trouvé un bug et des trous bon marché : l'unité de « de X à Y »
était obligatoire (un `?` portait sur le lookahead de l'unité), si bien que « de 0,78 à 0,8 »
ou « de 107 à 92 secondes » n'étaient pas lus ; le sens et les actions d'une `trend` n'étaient
pas contrôlés ; une durée inventée passait pour un décompte (« vue 1 heure plus tard ») ; un
nombre était accepté quelle que soit son unité (« vue en 2 s » parce que 2 est un écart de
points) ; « entre le 21 et le 23 octobre » était barré ; une `observation` qui cite un fait de
changement pouvait nommer une action qu'aucun fait ne porte. La session principale a tranché :
c'est la dernière correction de cette famille ; la section calculée fait foi, et ce qui reste
est écrit dans les limites connues. M513, M516 et M518 suivent le code corrigé. Dix mutants de
plus, dans la plage M530–M539 (M510–M519 est pleine), mesurés par le même fichier :

| Mutant | Défaut réinjecté | Effet |
|---|---|---|
| M530 | unité obligatoire dans « de X à Y » | « de 0,78 à 0,8 » à l'envers gardé |
| M531 | sens d'une `trend` non lu | « passe de 106,9 s à 91,9 s » gardé en tendance |
| M532 | actions d'une `trend` non contrôlées | « wipe_storage cette fois » gardé en tendance |
| M533 | actions d'une `observation` qui cite un fait de changement non contrôlées | « a pris un wipe_storage » gardé |
| M534 | tout mot fait un décompte | « vue 1 heure plus tard » gardé |
| M535 | unité ignorée | « vue en 2 s » gardé, 2 étant un écart de points |
| M536 | durée non convertie | « 15 ms plus tard » lu 15 s, gardé |
| M537 | plage de dates lue comme des nombres | « entre le 21 et le 23 octobre » barré |
| M538 | écart relatif refusé | « +16 % » barré quand la latence passe de 91,9 s à 106,9 s |
| M539 | « de X à Y » qui part d'un côté sans arriver à l'autre gardé | « de 91,9 s à 15 s » gardé |

Les quarante (M260–M279, M510–M519, M530–M539) attrapés à chaque tour (26/10), aucun périmé.

La troisième relecture de D-2 a trouvé un faux positif réel, introduit par M539 : une `trend`
ne mettait face à face qu'un run antérieur et un run de cette campagne, si bien qu'une
tendance juste sur trois campagnes (« de 120 s (19/10) à 91,9 s (21/10), puis à 106,9 s »,
« 0,85 → 0,80 → 0,78 », « du blocage à l'isolement (avant), puis retour au blocage ») était
barrée. Deux runs antérieurs de la même technique se font maintenant face aussi, dans les deux
sens : leur ordre n'est pas connu. Un sens inversé entre un run antérieur et un run de cette
campagne reste écarté, sauf quand un autre run antérieur cité porte la même action, ou la même valeur, que le run de cette campagne : la tendance peut alors décrire le passage entre deux runs antérieurs, dont l'ordre n'est pas lu (limite
connue, voir [`../analysis.md`](../analysis.md)). Et deux trous bon marché : une date en anglais (« since October 21 »)
était lue comme un nombre, et un nombre nu avant une date (« baisse de 12, le 23 octobre »)
était avalé comme premier jour d'une plage. M513 et M537 suivent le code corrigé. Cinq mutants
de plus, M540–M544 (M530–M539 est pleine), mesurés par le même fichier :

| Mutant | Défaut réinjecté | Effet |
|---|---|---|
| M540 | deux runs antérieurs jamais face à face | « 120 s → 91,9 s → 106,9 s » barré |
| M541 | deux runs antérieurs face à face dans l'ordre cité seulement | la même tendance barrée selon l'ordre de ses runs |
| M542 | deux runs antérieurs de techniques différentes face à face | « de l'isolement au blocage » gardé, l'isolement étant celui d'une autre technique |
| M543 | mois anglais absents | « since October 21 » barré |
| M544 | une plage de dates sans « le », « entre », « du », « des », « aux »… devant | « baisse de 12, le 23 octobre » gardé |

Les quarante-cinq (M260–M279, M510–M519, M530–M544) attrapés (26/10), aucun périmé.

La quatrième relecture a trouvé une régression de M544 : « les runs des 21 et 23 octobre »,
« aux 21 et 23 octobre » étaient barrés (21 lu comme un nombre). « des », « aux », « au » (et
« the ») ouvrent maintenant une plage, « de » toujours pas ; « du 21 et du 23 octobre » est
lu ; un jour de plage va de 1 à 31, si bien que « between 70 and 60, 23 October » n'est plus
avalé. Trois mutants de plus, M545–M547 :

| Mutant | Défaut réinjecté | Effet |
|---|---|---|
| M545 | un jour de plage peut être n'importe quel nombre | « between 70 and 60, 23 October » gardé |
| M546 | « des », « aux », « au » n'ouvrent pas une plage | « les campagnes des 21 et 23 octobre » barré |
| M547 | « du » refusé à l'intérieur d'une plage | « du 21 et du 23 octobre » barré |

Avec M280–M289 et M520–M528 de M-3, venus de main, tous attrapés au premier tour (26/10),
aucun périmé.

D2b a repris les trois points que les relectures de D-2 avaient laissés. Une tendance met
désormais ses runs face à face dans l'ordre où ils ont été joués (le début de leur campagne,
gardé dans l'index, ou son identifiant quand c'est une date ; le `seq` dans une campagne) : une
paire de runs antérieurs ne sert plus d'alibi. Le début d'une campagne venue du canal est borné
par ce que H0 a vu (la première fenêtre crue de ses runs, le marqueur `.pulled`) : une date
forgée ne change plus la campagne précédente. « au » et « the » seuls n'ouvrent plus une plage
de dates ; « au 21 et au 23 », « from the 21 to the 23 », « on the 21st and 23rd » en sont.
M540–M542, M546 et M547 suivent le code corrigé. Dix-sept mutants, M650–M666, mesurés par le
même fichier :

| Mutant | Défaut réinjecté | Effet |
|---|---|---|
| M650 | ordre des runs d'une tendance non lu | une paire de runs antérieurs sert d'alibi à « de l'isolement au blocage » |
| M651 | runs face à face à rebours du temps | « de 120 s (19/10) à 91,9 s (21/10) » barré |
| M652 | début de campagne de l'index non lu avec le run | l'ordre retombe sur l'inconnu |
| M653 | runs de cette campagne sans son début | le run d'une campagne postérieure passe pour antérieur |
| M654 | identifiant daté ignoré | des runs indexés sans début restent sans ordre |
| M655 | deux runs d'une campagne non ordonnés par `seq` | l'alibi revient dans une seule campagne |
| M656 | début du manifeste après la première fenêtre cru | une date forgée choisit une campagne postérieure |
| M657 | début du manifeste bien avant la première fenêtre cru | une date forgée saute la vraie précédente |
| M658 | début du manifeste après le tirage par H0 cru | sans fenêtre, rien ne borne la date |
| M659 | début refusé tu | le lecteur ne sait pas que la date a été écartée |
| M660 | début refusé gardé | la date forgée choisit quand même |
| M661 | fenêtre refusée par H-1 prise pour borne | une fenêtre forgée couvre une date forgée |
| M662 | « au » ouvre une plage | « tombe au 12, le 23 octobre » gardé |
| M663 | « the » seul ouvre une plage | « by the 12, 23 October » gardé |
| M664 | « au 21 et au 23 octobre » lu comme des nombres | une tendance juste barrée |
| M665 | « au », « aux », « the » refusés dans la suite d'une plage | « From the 21 to the 23 October » barré |
| M666 | jours sans « st », « nd », « rd » | « On the 21st and 23rd October » barré |

La relecture de D2b a trouvé un bug : une date que le manifeste donne et qu'aucune date UTC ne
tient (« 9999-12-31T23:59:59-05:00 », l'an 10000 en UTC) était bien refusée, puis le message
qui le disait levait, et le rapport n'était jamais écrit. Elle a aussi noté qu'un début devenu
inconnu laissait l'ancien dans l'index (ChromaDB fusionne les métadonnées d'une ligne), et que
la condition « deux runs de cette campagne ne font pas une tendance » n'était pas mesurée.
Trois mutants de plus :

| Mutant | Défaut réinjecté | Effet |
|---|---|---|
| M667 | date hors de portée UTC non rattrapée | le rapport de la campagne n'est jamais écrit |
| M668 | début inconnu absent de la ligne | le début forgé d'une indexation antérieure reste, et peut être choisi |
| M669 | deux runs de cette campagne face à face dans une tendance | un sens pris dans la seule campagne passe pour une tendance |

Avec M163, M260–M279, M510–M519 et M530–M547, les soixante-neuf attrapés au premier tour
(26/10), aucun périmé.
Détail : [`../analysis.md`](../analysis.md), « Ce qui a changé depuis la campagne précédente ».

### L'hôte de Glorfindel : référence épinglée, verrou, un environnement par conteneur, boutons (M-3)

H0 déployait la tête de `main`, sans verrou de dépendances ; les trois conteneurs recevaient tous
les secrets ; un bouton Discord obéissait à qui cliquait. Dix-neuf mutants (dix du lot, neuf
de sa relecture), mesurés par `tests/unit/test_bot.py`, `test_glorfindel_host.py`,
`test_host_deploy.py` et `test_dependency_lock.py` :

| Mutant | Défaut réinjecté | Effet |
|---|---|---|
| M280 | un bouton Discord obéit à qui clique | n'importe qui sur le serveur lance un Restore |
| M281 | sans liste d'autorisés, tout clic passe | les boutons ouverts par défaut |
| M282 | n'importe quel rôle autorise un clic | un rôle sans rapport suffit |
| M283 | un clic refusé n'est pas journalisé | une tentative ne laisse pas de trace |
| M284 | le jeton du bot revient à chaque conteneur | un conteneur compromis a le bot |
| M285 | la War Room reçoit les clés des modèles | elle n'en appelle aucun et les tient quand même |
| M286 | la watch ne connaît le bot que par son jeton | chaque carte part aussi au webhook |
| M287 | H0 déploie une branche : toute révision se résout | la tête de `main` revient sur l'hôte |
| M288 | l'image ne porte pas sa référence | on ne sait plus ce qui tourne |
| M289 | l'image résout ses dépendances sans verrou | une version mineure change les décisions |
| M520 | un clic refusé est dit, puis passe à son action | le refus n'empêche rien |
| M521 | un salon Discord seul fait taire le webhook, sans bot | les escalades ne partent nulle part |
| M522 | la watch et la War Room reçoivent le jeton du bot, pas seulement sa présence | le secret voyage |
| M523 | la watch compte un salon seul comme une alerte | l'avertissement « aucune alerte » se tait |
| M524 | `REF=--checkout-only` atteint `deploy.sh` comme une option | un checkout sans reconstruction, dit comme un déploiement |
| M525 | une `REF` exportée dans l'environnement est déployée en silence | un nom générique choisit ce qui tourne |
| M526 | make développe une `REF` refusée en l'exportant | `$(shell …)` s'exécute |
| M527 | la ligne ssh recopie `REF` dans la recette | make la développe avant qu'elle soit vérifiée |
| M528 | règles approuvées sur la VM que la référence change : « gardé », puis git refuse (depuis P1 : un fichier de règles modifié refusé sans dire comment migrer) | l'opérateur répare et efface les règles |

Dix-neuf sur dix-neuf attrapés, trois tours (26/10, #202). Détail :
[`../../infra/glorfindel-host/README.md`](../../infra/glorfindel-host/README.md), « Ce que la VM
exécute » et « Redéployer H0 après M-3 ».

### Les couches de règles (P1)

La base livrée reste intacte ; les règles du client vivent dans leur couche,
`~/.glorfindel/client_rules.yaml`, chargée par-dessus ; une entrée invalide de la couche ne
coupe jamais la détection ; une règle approuvée se lie au backend de son workspace. Vingt-deux
mutants, mesurés par `tests/unit/test_rule_layers.py`, `test_proposed_rules.py` et
`test_host_deploy.py`, tous attrapés au premier tour (26/10) ; M528 (M-3) suit le nouveau refus
de `deploy.sh`, attrapé aussi. L'export d'une règle généralisée, sans identifiant, est reporté à
un lot rattaché à P2 (relu par un humain avant tout envoi) : ses mutants (M679–M684, M689–M694,
M702–M712, M717–M719) sont partis avec lui ; les numéros laissent un trou (M700–M701 ont été
réattribués à A3 le 27/10).

| Mutant | Défaut réinjecté | Effet |
|---|---|---|
| M670 | la règle approuvée écrite dans la base livrée | une mise à jour la perd |
| M671 | la couche du client pas chargée | une mise à jour « perd » toutes les règles du client |
| M672 | la règle de base gagne sur celle du client de même nom | la version du client ignorée |
| M673 | `disable:` ignoré | une règle de base que le client a désactivée tourne |
| M674 | une règle de base remplacée sans le dire | rien dans les notes ni la bannière |
| M675 | les notes pas journalisées | le journal de la watch ne dit rien de la couche |
| M676 | une couche illisible empêche la base de charger | la watch ne détecte plus rien |
| M677 | une couche illisible lue vide, puis écrite par-dessus | les règles du client effacées |
| M678 | la proposition approuvée avant que sa règle soit écrite | « approuvée » sans règle |
| M685 | la migration ne prend que les règles nouvelles | une règle de base modifiée sur la VM perdue |
| M686 | la migration oublie une règle de base supprimée sur la VM | elle revient |
| M687 | H0 : un fichier de règles modifié repart dans l'image | les règles approuvées avant P1 jamais migrées |
| M688 | la base montée en écriture dans la watch | un conteneur peut de nouveau l'écrire |
| M695 | une entrée de la couche pas validée | `interval_s: 30s` : plus aucune règle, base comprise |
| M696 | une clé de la couche qui n'est pas une liste pas dite | des règles absentes en silence |
| M697 | la règle approuvée reprend la forme en ligne | elle ne s'applique à aucune VM |
| M698 | la migration ne lie pas une règle en ligne à son backend | une règle d'avant P1 reste inerte |
| M699 | une règle qui ne s'applique à aucune VM pas dite au chargement | inerte en silence |
| M713 | `glorfindel rules` cache le backend d'une règle auto | liée et inerte se confondent |
| M714 | une règle approuvée d'un autre workspace prend le backend de la première règle | elle tourne sur le mauvais workspace |
| M715 | une config illisible lue « aucun backend » par `migrate-rules` | la vraie cause tue |
| M716 | une couche ignorée dite « absente » | contredit la note |

### Annatar et Gothmog exigent Glorfindel (V1)

Avant chaque run, et avant tout appel au cloud, l'injecteur lit le battement de la watch
(`eregion_core/watch_gate.py`) et refuse sans battement vivant ; `--without-glorfindel` passe, et
le rapport le dit. Le cloud des tests échoue si on l'appelle : le contrat d'Orodruin, l'exécuteur
de la cible et le réseau lèvent, et chaque tentative est notée. Trente mutants, mesurés par
`tests/unit/test_watch_gate.py` et `tests/unit/test_gothmog.py`, tous attrapés au premier tour
(27/10) ; M750–M759 après la relecture.

| Mutant | Défaut réinjecté | Effet |
|---|---|---|
| M720 | `annatar run` sans watch vivante pas refusé | l'attaque part, détection jamais mesurée |
| M721 | Annatar lit la watch après le contrat d'Orodruin | un appel au cloud avant le refus |
| M722 | un atomic `--without-glorfindel` ne le dit pas au rapport | un run de dév pris pour un `unknown` |
| M723 | un script `--without-glorfindel` ne le dit pas au rapport | idem |
| M724 | `gothmog run` sans watch vivante pas refusé | la panne part sans personne pour la voir |
| M725 | Gothmog lit la watch après le contrat d'Orodruin | un appel au cloud avant le refus |
| M726 | une panne `--without-glorfindel` ne le dit pas au rapport | « rien de disruptif » sans watch |
| M727 | `gothmog preflight` ignore la watch | « la panne pourrait partir », puis refus au run |
| M728 | une campagne sans watch démarre | passe `running`, chaque run en erreur |
| M729 | une campagne continue après un refus pour watch absente | une chaîne de refus marqués erreurs |
| M730 | `campaign run --without-glorfindel` n'atteint pas ses runs | chaque run refusé |
| M731 | un battement de n'importe quel âge vaut une watch | une watch arrêtée depuis des jours compte |
| M732 | le canal retour n'est pas lu | depuis Orodruin, la watch hébergée jamais vue |
| M733 | un canal illisible lève au lieu de refuser | une trace au lieu d'une raison |
| M734 | H0 accepte un run sans Glorfindel qui revendique un verdict | un `detected` sans watch |
| M735 | la console perd le drapeau | un run de dév affiché `unknown` |
| M736 | un script `--without-glorfindel` attend encore la détection | 30 s perdues, puis `unknown` |
| M737 | un atomic `--without-glorfindel` attend encore la détection | idem |
| M738 | `make gothmog-run` perd `WITHOUT_GLORFINDEL` | la dérogation ne passe pas sur Orodruin |
| M739 | `make orodruin-campaign-run` perd `WITHOUT_GLORFINDEL` | idem pour une campagne |
| M750 | une campagne `--without-glorfindel` ne le dit pas dans son manifeste | ses runs comptés « sans mesure », sans raison |
| M751 | une campagne reprise avec un autre réglage | détections mesurées et non mesurées mêlées |
| M752 | une campagne sans Glorfindel a un rapport d'analyse | « décision inconnue » cherchée, appel au modèle |
| M753 | H0 écrit le rapport d'une campagne sans Glorfindel | idem, sur H0 |
| M754 | une campagne sans Glorfindel entre dans l'index | choisie comme précédente (D-2) |
| M755 | une campagne `aborted` sort en 0 | `make orodruin-campaign-run` réussit |
| M756 | un battement daté dans le futur reste frais | une horloge fausse vaut une watch pour toujours |
| M757 | `WITHOUT_GLORFINDEL=0` lève l'exigence | la dérogation par erreur |
| M758 | un fichier local vivant compte malgré le canal | une watch locale prise pour la watch hébergée |
| M759 | la console compte une campagne sans Glorfindel en `unknown` | un run de dév pris pour un trou |

### Les règles orphelines, la restauration, la configuration (A3)

La passe de réaffirmation de la watch (chaque minute, découverte ou non) alerte, puis retire la
règle d'une carte disparue qui coupe une carte vivante derrière son NSG, quand cette VM est en
`non_disruptive` ou plus ; en `human_only`, la carte seule (U1, décisions D-A et D-B du 27/10).
La machine le prouve : règle `orphan_sweep` (le mode de la VM coupée tiré ; après elle, en
`non_disruptive`, plus aucune VM vivante coupée par une orpheline, hors VM que l'état tient
isolée ou bloquée — la seule exemption lue des enregistrements du code ; aucune autre VM, aucun état, aucune carte ne
bouge ; rien de plus ouvert que ce que les orphelines fermaient), composite `address_reused`
(une VM bloquée ou isolée, supprimée avec ou sans son état, une VM créée à son adresse, sur le
NSG de sa devancière ou non) — sans elle, aucun des 313 balayages tirés à 500 séquences ne
trouvait une orpheline qui coupe ; avec, 47 sur 356. En fin de séquence, après la levée de tout, chaque VM vivante
revient à sa conception en entier, plus seulement « à ses yeux » : la limite connue d'I7 est
levée. Mesuré avant (`6c958e1`) et après, au même budget (500 séquences, 1 tour) :

| | Avant | Après |
|---|---|---|
| Invariants à 500 séquences, rejeu | verts | verts |
| M01–M41, attrapés au tour | 26 sur 39 | 23 sur 39 |
| Jeu de contrôle (C01–C16) | 10 sur 16 | 11 sur 16 |

Les sept écarts de M01–M41 (M17, M18, M20, M21, M22, M29, M38) remesurés sur trois tours des
deux côtés : identiques (M17 et M20 2 sur 3, M21 3 sur 3, M22 et M38 figés seulement), ou
meilleurs après (M18 et M29 3 sur 3, contre 2 et 1 avant) — le tirage, pas une perte.

Seize mutants (M760–M775), tous attrapés au premier tour (27/10) ; M760–M763 par les
invariants (M760, M762 et M763 aussi par `test_orphan_sweep.py` : le mode tiré les rend plus
rares), les autres par `test_orphan_sweep.py`, `test_config.py` et `test_glorfindel.py`.
M28 suit le code (sa condition a deux lignes). Après la première relecture, douze de plus
(M776–M779, M880–M887), attrapés à chaque tour ; M760, M768 et M769 visent `orphans.py`, M830
et M834 suivent le code (la passe appelle `_whatever_the_state`).

| Mutant | Défaut réinjecté | Effet |
|---|---|---|
| M760 | le balayage alerte et ne retire jamais | la VM reste coupée (L28) |
| M761 | la règle d'une carte vivante prise pour une orpheline | une isolation levée en silence |
| M762 | le retrait vide toutes les règles de Glorfindel du NSG | les isolations des voisines levées |
| M763 | l'adresse visée lue du mauvais côté de la règle | l'orpheline jamais retirée |
| M764 | le NSG de la carte visée pas comparé | une règle qui ne coupe personne retirée |
| M765 | une carte attachée au NSG manque à la liste : retrait quand même | une isolation d'une carte invisible levée |
| M766 | une carte de l'état, présente, prise pour disparue | idem, la carte que Glorfindel a isolée |
| M767 | anciens noms d'une carte vivante pris pour des orphelines | une isolation d'avant L24 levée |
| M768 | identifiants en lecture seule : retrait tenté | une écriture refusée à chaque passage |
| M769 | carte résolue malgré un retrait en échec | la VM coupée, plus rien ne le dit |
| M770 | une clé que rien ne lit acceptée | `quarantaine_nsg: false` laisse la quarantaine |
| M771 | `"false"` entre guillemets lu vrai | `exclude_all: "false"` sort la VM des règles |
| M772 | un texte seul pris pour une liste, lettre par lettre | `allow_destructive: "vm-*"` donne `*` |
| M773 | la watch démarre sur une config refusée | « Could not load rules », aucune détection |
| M774 | la restauration revient à trois noms CustomScript | VMAccess ramène la clé de l'attaquant |
| M775 | une extension au type illisible acceptée | l'inconnu passe pour sûr |
| M776 | le retrait ignore le mode de la VM coupée | `human_only` écrit (D-A) |
| M777 | le balayage hors de la passe de la watch | sans découverte, la VM reste coupée (D-B) |
| M778 | la règle d'une carte recréée sous une VM isolée trouvée retirable | l'isolation levée sans humain |
| M779 | le retrait ne relit pas l'état | une isolation enregistrée entre-temps levée |
| M880 | toute erreur de lecture d'une carte de l'état prise pour un 404 | un 403 vaut « disparue » |
| M881 | une carte de l'état illisible (403, 429) n'empêche pas le retrait | idem |
| M882 | un `type` de backend inconnu accepté | `azure_monitr` : un backend que rien ne lit |
| M883 | la carte ne dit pas pourquoi la règle est gardée | l'opérateur devine |
| M884 | levée retenue par une extension : la carte accuse Run Command | l'opérateur cherche ailleurs |
| M885 | Guest Configuration dans la liste blanche | le script d'une politique revient |
| M886 | une orpheline redite à chaque passage | une carte par minute, l'acquittement perdu |
| M887 | toute carte d'orpheline fermée à chaque passage | la règle reste, plus rien ne le dit |
| M888 | la VM tenue comparée par son ID exact | un état en minuscules la manque : isolation levée |
| M889 | config illisible lue `non_disruptive` | le balayage écrit sur un mode deviné |
| M700 | réaffirmation coupée : la posture ne les dit plus | l'alerte de L28 perdue |
| M701 | une règle qui coupe des VM de modes différents retirée si l'une le permet | `human_only` écrit |

Correction après la première relecture, mesurée avant (`ae4f021`, A3 fusionné avec I1F et D1)
et après, au même budget (500 séquences, 1 tour) : invariants à 500 et à 2 000 séquences verts
(à 2 000, une fin de séquence balayait dans le mode `human_only` laissé par une règle précédente :
séquence figée, la fin de séquence donne aux VM leur mode) ; M01–M41 21 sur 39 avant, 24 sur 39
après ; jeu de contrôle C01–C16 12 sur 16 avant, 10 sur 16 après. Les écarts remesurés par la
seconde relecture, 500 séquences × 6 tours de chaque côté (avant `ae4f021`, après `06fa423`) :
M26 3/6 → 6/6, C05 2/6 → 4/6, C07 0/6 (séquence figée seulement) → 1/6. L'hypothèse « plus
d'appels par passe » testée directement (balayage retiré de la passe de la machine : C05 2/6,
C07 3/6) n'est pas confirmée : c'est le tirage, aucune baisse réelle.

### « Déjà alerté » après la carte (L1F)

La machine a trouvé L1 en défaut en cinq étapes : un blocage, le rôle retiré, un
`terraform apply` qui supprime sa règle, une réaffirmation qui tente de la reposer (refusée)
et meurt juste après sa première écriture, puis une réaffirmation en `human_only`. La
réaffirmation écrivait « déjà alerté » (`drift_alerted_at`) avant la carte ; le crash tombait
entre les deux, et chaque passe suivante se taisait sur ce marqueur. La carte vient d'abord
maintenant (`glorfindel/reassert.py`). Trois mutants, attrapés à chaque tour (27/10) : M900 et
M902 sont rares dans les séquences tirées (un crash pile entre la carte et le marqueur) — la
machine seule ne les voit ni à 500 séquences (2 tours) ni à 2 000 (1 tour) ; M900 est attrapé
par la séquence figée et par `tests/unit/test_reassert.py`, M902 par ce dernier ; M901 n'a pas de propriété de vivacité dans la
machine (une isolation disparue), son test unitaire le mesure.

| Mutant | Défaut réinjecté | Effet |
|---|---|---|
| M900 | un blocage qu'on n'a pas pu reposer marqué « alerté » avant sa carte | crash entre les deux : blocage disparu, rien de dit |
| M901 | une isolation qu'on n'a pas pu reposer marquée « alertée » avant sa carte | idem pour une isolation |
| M902 | un blocage disparu en `human_only` marqué « alerté » avant sa carte | idem, sans tentative de repose |

### Absent de la liste n'est pas disparu (I1S)

Relevé par les troisième et quatrième relectures d'I1F (#231), pas par la machine : elle ne
savait pas faire sortir un NSG de la liste sans le supprimer. Une carte `quarantine_altered`
se fermait dès que son NSG manquait à la liste de l'abonnement — rôle retiré sur son groupe,
notre tag retiré avec nos règles, carte d'un autre abonnement — alors qu'il était encore modifié
et portait des cartes. Le NSG d'une carte absente de la liste est maintenant relu par son ID
(`read_quarantine`) : seul un 404 la ferme.

Le faux Azure apprend une **hypothèse**, pas une mesure : une liste à l'échelle de l'abonnement
qu'ARM filtrerait selon les droits, sans erreur, et un refus (403) sur tout appel à ce NSG
(`unreadable`). Le tag retiré est une édition du monde, comme les autres. La machine les tire
dans la règle composée d'I1F (`_out_of_sight`), **après** que L2 a tenu sur ce NSG : rôle
retiré, tag retiré, ou les deux, une ou deux passes, puis le rôle rendu et le tag remis — la
suite de la séquence ne porte pas sur eux. L'oracle reste celui du test : L2 juge un NSG que le
test a lui-même sorti de la vue (`out_of_sight`, son journal) comme s'il était tagué ; rien n'est
lu des cartes ni de `quarantine_alerts.json` pour l'accorder. Mutants M1020–M1026 (28/10, 500
séquences) : tous attrapés à chaque tour ; M1020, M1021, M1023 et M1026 aussi par la machine
seule (3/3, à 500) et par les séquences figées (`test_a_said_quarantine_out_of_the_listing_stays_said`).
M1020, la machine seule ne l'attrape qu'à partir de quelques centaines de séquences (relecture
d'I1S ; remesuré pour ISU, #264) : 1/6 à 60, le budget par défaut d'un `pytest` local, 4/4 à 200
(une remesure de la relecture : 2/3), 4/4 à 500 (le budget du push), qui est le budget sûr. À 60, ce sont `test_reassert.py` et la séquence figée qui le tiennent.
M1022 (l'abonnement), M1024 (le coût) et M1025 (un acquittement d'un NSG supprimé) ne sont pas
des propriétés du monde de la machine (un seul abonnement, pas de compte des appels, aucun
acquittement) : `tests/unit/test_reassert.py`. Au même budget (500 séquences, deux tours), les 87
mutants du chemin d'isolation avant et après : 72/87 attrapés à chaque tour avant, 74/87 après
(M880, dont le texte se retrouvait deux fois dans `sweep.py`, rendu unique et remesuré) ; aucun
perdu — M34, attrapé avant et 1/2 après, l'est 4/4 sur quatre tours (le bruit déjà noté) ; M10,
M17 et M33 passent de 1/2 à 2/2. Les invariants à 500 sont verts sur trois graines (11, 22, 33),
chacune passant une trentaine de fois par un NSG sorti de la vue.

| Mutant | Défaut réinjecté | Effet |
|---|---|---|
| M1020 | carte fermée sur la simple absence de la liste | NSG modifié, cartes dedans, rien de dit jusqu'au retour des droits |
| M1021 | notre tag exigé à la relecture | tag retiré avec les règles : même silence |
| M1022 | abonnement ignoré à la relecture | l'homonyme de cet abonnement (entier) ou un 404 ferme la carte de l'autre |
| M1023 | relecture en échec (403, 429) lue comme « disparu » | carte fermée sur un NSG qu'on ne peut pas lire |
| M1024 | chaque NSG de carte relu à chaque passe, listé ou non | un `get` par carte et par minute (coût, throttling) |
| M1025 | un changement acquitté jamais relu | son NSG supprimé, l'acquittement fait taire le suivant au même ID |
| M1026 | 403 lu comme 404 par le connecteur | carte fermée |

### Les suites des relectures du 28/10 (ISU)

Quatre suites laissées par les relectures 5.5 d'I1S, I8S et I4S (#264), aucune trouvée par la
machine : elle n'a qu'un répertoire d'état et qu'un abonnement, et ne lit pas les messages. Le
déblocage derrière la quarantaine suit la règle de la levée pour l'original — l'« aucun » de
l'état cède au tag qui nomme un NSG, un tag illisible fait échouer (`unblock_partial`) ; un
original supprimé dit comment en sortir, sur chaque chemin (carte en quarantaine, carte nue
avec état, carte nue sans état ; levée et reset), et un original seulement illisible (403) n'est
jamais dit supprimé ; une carte d'un autre abonnement est écartée avant la relecture, dite une
fois, redite après une nouvelle carte ; un blocage à nom simple sur un NSG qui est aussi celui du
sous-réseau est dit « d'une ancienne version ou de périmètre ». Tests à la main sur le faux Azure
(`test_two_hosts_an_unblock_behind_the_quarantine_finds_the_block_on_x`,
`test_an_original_gone_says_how_to_get_out` — huit chemins —,
`test_an_original_that_cant_be_read_is_not_called_gone`,
`test_an_unblock_says_a_plain_block_may_be_a_perimeter_one`,
`test_a_card_of_another_subscription_is_said_once_never_read`,
`test_a_card_whose_nsg_is_refused_warns_at_every_pass_in_its_case`) : tous échouent sur `main`
(971e608) sauf le cas témoin (un NSG qui n'est pas celui du sous-réseau) et le test du 403
(`test_an_original_that_cant_be_read_is_not_called_gone`, qui garde contre M1104). Mutants M1100–M1115,
mesurés par ces tests : 16/16. Au même budget (500 séquences, deux tours, deux passes côte à côte),
les 87 mutants du chemin d'isolation (`unblock.py`, `reassert.py`, `release.py`, `sweep.py`,
`quarantine.py`, `network.py`), `main` puis la branche : 72/86 attrapés à chaque tour avant, 77/86
après (M10, M14, M19, M21 et M39 passent à 2/2) ; aucun perdu. M22 et M35 (1/2 avant, 0/2 après)
et M37 (0/2 puis 1/2) remesurés sur six tours de chaque côté : M22 0/6 et 0/6, M35 0/6 et 0/6, M37
1/6 et 0/6 — du bruit, et tous trois attrapés par leurs séquences figées (`FIXED-ONLY`). Invariants
à 500 verts sur deux graines (17, 29).

| Mutant | Défaut réinjecté | Effet |
|---|---|---|
| M1100 | le déblocage suit l'« aucun » de l'état contre le tag qui nomme X | `not_found`, l'IP reste bloquée sur X, revient à la levée |
| M1101 | un tag illisible lu « aucun » au déblocage | même `not_found`, au hasard |
| M1102 | un original supprimé ne dit que l'erreur d'Azure | aucune sortie dite |
| M1103 | le tag « none » proposé alors que l'état nomme l'original | une sortie qui ne change rien |
| M1104 | un original illisible (403, 429) dit supprimé | « recréer » un NSG qui existe |
| M1105–M1108 | la sortie oubliée sur un chemin (carte nue avec état, levée sans état, reset d'une carte nue, carte en quarantaine) | même silence sur ce chemin |
| M1109, M1112 | la carte d'un autre abonnement passée au lecteur (le filtre, le connecteur) | un avertissement à chaque passe, sans fin |
| M1110 | dite à chaque passe | même bruit |
| M1115 | jamais oubliée | une nouvelle carte sur ce NSG, après la fermeture de la première, jamais dite |
| M1111 | l'acquittement seul nommé par sa clé en minuscules | le nom n'est pas celui d'Azure |
| M1113, M1114 | « ou de périmètre » jamais dit (le libellé, la marque de la cible) | un blocage de périmètre présenté comme d'une ancienne version |

### Le journal d'activité, détection seule (AL1)

Un faux `AzureActivity` (des lignes comme celles de la table, rendues par la requête du
détecteur parent) traverse le vrai `AzureActivityDetector`, le RulePoller et le graphe, modèle
simulé. Trente-cinq mutants (M810–M829, puis M850–M859 et M890–M894 après les relectures 5.5), mesurés par
`tests/unit/test_activity_logs.py`, tous attrapés (27/10).

| Mutant | Défaut réinjecté | Effet |
|---|---|---|
| M810 | les écritures de Glorfindel ne sont pas écartées | sa propre isolation s'escalade |
| M811 | le plan de contrôle décidé par le modèle | il est appelé, et `isolate_vm` part |
| M812 | un jeton d'utilisateur sans `idtyp` lu comme celui d'une application | l'`appid` de la CLI écarte tout le monde |
| M813 | une carte du plan de contrôle fusionnée dans la précédente | l'écriture sur une règle de Glorfindel, invisible |
| M814 | la décision ignore la source lue | `respond` demande au modèle |
| M815 | le type `control_plane_change` perdu | carte `low_confidence`, approuvable en un clic |
| M816 | une règle `glorfindel-*` pas vue comme sienne | le cas le plus grave, banal |
| M817 | le NSG de quarantaine pas vu comme sien | idem |
| M818 | son identité écartée quoi qu'elle fasse sur ce qui est à lui | un rôle attribué sous son identité, jamais vu |
| M819 | l'identité du jeton ignorée | ses écritures s'escaladent |
| M820 | les identifiants de `Claims` ignorés | idem, pour un principal de service |
| M821 | l'appelant comparé à la casse près | idem |
| M822 | déduplication par ligne | `Start` puis `Success` : deux détections |
| M823 | une règle plus courte que la latence, en silence | les lignes en retard jamais vues |
| M824 | la règle NSG livrée regarde 10 minutes | idem |
| M825 | une sous-ressource de VM non attribuée | un rôle sur la VM ignoré |
| M826 | la ligne la plus récente d'abord, avant l'écriture sur une règle de Glorfindel | le cas grave après les autres, ou dans la synthèse |
| M827 | l'écriture sur une règle de Glorfindel pas critique | sévérité banale |
| M828 | une ligne du plan de contrôle normalisée comme une IP | ni opération ni appelant |
| M829 | une règle `azure_activity` liée à aucun backend | désactivée, elle ne tourne jamais |
| M850 | jeton d'utilisateur : l'`appid` de la CLI pris pour celui de Glorfindel | toute écriture faite avec `az` écartée |
| M851 | son identité sur une règle du client écartée | un credential volé, invisible |
| M852 | une règle du client décalée par une isolation pas vue comme sienne | sa levée s'escalade, critique |
| M853 | une carte par relevé sur le plan de contrôle | les autres opérations marquées envoyées, jamais vues |
| M854 | au-delà du plafond, pas de carte de synthèse | des opérations marquées envoyées sans carte |
| M855 | un bouton sur une carte ancrée sur une VM | un clic restaure une VM que la détection ne nomme pas |
| M856 | la décision du plan de contrôle recommande d'isoler | « Recommandé : isoler » sur la VM d'ancrage |
| M857 | un signal non attribué ouvre l'incident de la VM d'ancrage | le cycle suivant y lit « 2 signaux » |
| M858 | un cycle du plan de contrôle dans la mémoire de décision | un précédent servi au plan de données |
| M859 | ce qu'un état d'isolation attribuait, oublié avec l'état | la ligne de la levée s'escalade |
| M890 | un nom `glorfindel-*` suffit à faire une règle sienne | un credential volé cache une autorisation derrière |
| M891 | les états de blocage ignorés | son propre blocage s'escalade |
| M892 | l'abonnement hors de la clé d'une règle | les mêmes noms ailleurs pris pour les siens |
| M893 | une ligne `AzureActivity` lue par une autre source va au modèle | un snapshot part seul |
| M894 | une règle du plan de contrôle sans `CorrelationId`, en silence | deux opérations n'en font qu'une |

### Les identités : Entra ID, détection seule (C2)

De faux journaux d'Entra ID (des lignes comme celles que projettent les règles livrées, rendues par
la requête du détecteur parent) traversent le vrai `AzureEntraDetector`, le RulePoller et le
graphe, modèle simulé. Vingt mutants (M920–M939), mesurés par `tests/unit/test_entra_detection.py`,
tous attrapés (27/10).

| Mutant | Défaut réinjecté | Effet |
|---|---|---|
| M920 | une détection d'identité décidée par le modèle | il est appelé, avec l'UPN d'un administrateur |
| M921 | la route après `decide` envoie une détection d'identité vers une action | un `decide` contourné isole |
| M922 | la détection d'identité reconnue par son seul plan | une ligne aux colonnes muettes va au modèle |
| M923 | une ligne d'Entra lue par une autre source va au modèle | ni plan ni source |
| M924 | tout rôle d'annuaire est un constat | Lecteurs d'annuaire comme Administrateur général |
| M925 | un principal sans historique, inhabituel | les premiers jours après le paramètre inondent |
| M926 | une opération échouée est un constat | des cartes pour rien |
| M927 | l'identité de Glorfindel, acteur, pas marquée | son identifiant volé, pas critique |
| M928 | l'identité de Glorfindel, cible, pas marquée | un identifiant ajouté à Glorfindel, banal |
| M929 | une carte d'identité fusionnée dans la précédente | l'identifiant ajouté à Glorfindel, invisible |
| M930 | après un `decide` contourné, le type `low_confidence` | approuvable en un clic |
| M931 | une commande sur la VM d'ancrage d'une carte d'identité | `glorfindel restore` proposé |
| M932 | un cycle d'identité dans la mémoire de décision | son UPN servi au modèle plus tard |
| M933 | une détection d'identité ouvre l'incident de la VM d'ancrage | le cycle suivant y lit « 2 signaux » |
| M934 | un constat dédupliqué par son heure | deux consentements dans la même seconde : une carte |
| M935 | une carte par cycle pour les identités | le second identifiant ajouté du relevé, jamais vu |
| M936 | un signal d'identité sans son plan | un constat sur Glorfindel, pas critique |
| M937 | une règle d'identité sans `EventId`, en silence | deux constats n'en font qu'un |
| M938 | une carte de rôle sans la façon de retirer l'attribution | l'humain ne sait pas révoquer |
| M939 | le paramètre de diagnostic du tenant toujours posé | les journaux de tout le tenant envoyés |

Après les relectures 5.5 (27/10), onze de plus (M940–M949, M955), tous attrapés :

| Mutant | Défaut réinjecté | Effet |
|---|---|---|
| M940 | sous `az login`, l'`oid` de l'opérateur pris pour Glorfindel dans Entra | ses actions lues comme un vol |
| M941 | un jeton d'utilisateur pris pour celui d'une application | idem |
| M942 | la règle de rôle filtre sur `Role.DisplayName` | une attribution sans lui disparaît avant l'adaptateur |
| M943 | l'ancienne valeur d'un premier identifiant n'est pas un tableau | `set_difference` tait la ligne |
| M944 | une règle du client sur une table d'Entra, sans colonne révélatrice, va au modèle | son UPN envoyé |
| M945 | `respond` sur une requête d'Entra d'une autre source va au modèle | idem |
| M946 | une carte de consentement propose de désactiver le principal de la ressource | tout le tenant coupé |
| M947 | une carte d'identité étiquetée exercice par une fenêtre sur sa VM d'ancrage | un vrai constat pris pour un exercice |
| M948 | l'ancien nom de Global Administrator pas privilégié | une attribution lue sous ce nom, tue |
| M949 | le nom du rôle pas repris de sa cible | une attribution sans `Role.DisplayName`, sans nom |
| M955 | un signal de `respond` sur le journal d'activité forcé `real` (seconde relecture) | un exercice déclaré compté comme un incident |

### L'IA d'analyse : son modèle, sa mémoire, le tri, rien sans un humain (IA1)

L'IA d'analyse refuse le modèle de décision de Glorfindel et toute mémoire rangée dans son état
(`analysis/separation.py`). Le tri d'une campagne (`analysis/triage.py`) est calculé depuis les
runs, le catalogue, les règles et le code d'infrastructure ; le modèle explique et propose ; la
vérification écarte ce que les faits ne portent pas, et chaque proposition attend un humain. Vingt
mutants, mesurés par `tests/unit/test_analysis_separation.py` et `tests/unit/test_analysis_triage.py`
(les cas du harnais y tournent avec un modèle simulé), tous attrapés au premier tour (27/10).

| Mutant | Défaut réinjecté | Effet |
|---|---|---|
| M780 | le modèle de décision de Glorfindel accepté | le rapport partage les angles morts du défenseur |
| M781 | le modèle comparé avec son préfixe | `claude-sonnet-5-5` passe pour un autre que `anthropic/claude-sonnet-5-5` |
| M782 | le chemin de l'index lu sans être résolu | `..` ou un lien mènent dans `~/.glorfindel` |
| M783 | l'index permis dans l'état de Glorfindel | l'analyse écrit dans la mémoire du défenseur |
| M784 | le rapport ouvre son index sans le contrôle | idem, par `EREGION_ANALYSIS_INDEX` |
| M785 | le rapport appelle son modèle sans le contrôle | idem, par `EREGION_ANALYSIS_MODEL` |
| M786 | une escalade triée avant une technique manquée | ce qui est passé n'est plus en tête |
| M787 | un commentaire du code d'infrastructure vaut collecte | « collectée » sur une ligne que Terraform ignore |
| M788 | `disable:` de la couche du client ignoré | une règle désactivée « surveille » encore |
| M789 | une proposition que les faits ne portent pas gardée | « écrire une règle » quand une règle existe |
| M790 | une proposition qui porte une règle gardée | l'analyse écrit une requête de détection |
| M791 | le statut écrit par le modèle gardé | une proposition « approuvée » sans humain |
| M792 | une décision sans nom d'humain enregistrée | une approbation que personne n'a donnée |
| M793 | une proposition décidée deux fois | la trace de la première décision perdue |
| M794 | un nouveau tri écrit par-dessus une décision | la décision d'un humain perdue |
| M795 | « Glorfindel a isolé » gardé sur une décision inconnue | un inconnu présenté comme un fait |
| M796 | une deuxième entrée pour un item la remplace | l'explication gardée n'est plus celle vérifiée la première |
| M797 | le tri appelle le modèle de Glorfindel | idem M780, pour le tri |
| M798 | le harnais ne compte pas l'obéissance que la vérification a écartée | l'obéissance du modèle à une ligne plantée n'est plus mesurée |
| M799 | une collecte illisible dite « non collectée » | un inconnu présenté comme une cause |

Après les relectures (27/10), douze de plus, tous attrapés à chacun des trois tours ; M840 est
mesuré par `tests/unit/test_analysis_rules_parity.py`, qui prend le chargeur de la watch pour
oracle, M874 par `tests/unit/test_analysis_separation.py`. M843 (un filtre de la prose du modèle,
« approuvée par … ») a été retiré avec ce filtre : ce qui fait foi est le statut écrit par le
code, et M871–M878 mesurent cette garantie (M876–M878 à travers un vrai moteur CommonMark,
markdown-it).

| Mutant | Défaut réinjecté | Effet |
|---|---|---|
| M840 | une entrée de la couche du client que la watch écarte remplace la règle de base | `no_rule` sur une technique que la watch surveille encore : `author_rule` permis, `review_rule` interdit |
| M841 | `decide` sans le verrou de la campagne | deux décisions prises en même temps : la seconde écriture perd la première |
| M842 | un `triage.json` illisible laisse passer l'exception | une trace Python au lieu d'un refus |
| M844 | la raison d'une entrée écartée, qui cite le modèle, sans `_cell` | un retour à la ligne du modèle casse `triage.md` |
| M871 | le statut affiché à côté d'une proposition pris du texte du modèle | `triage.md` montre une décision que le code n'a pas écrite |
| M872 | le Markdown du modèle rendu tel quel | son texte dessine un « Statut (écrit par le code) » à lui |
| M873 | un nouveau tri écrit sans le verrou | une décision prise pendant ce temps est perdue |
| M874 | un refus du modèle d'analyse sort avec 1, comme une erreur | `glorfindel-host-model` ne donne pas son conseil |
| M875 | l'en-tête de `triage.md` ne dit plus que seul le statut du code fait foi | le texte du modèle peut passer pour une décision |
| M876 | la raison d'une entrée écartée rendue sans échappement | un statut en gras écrit dans « Écarté » |
| M877 | une ligne ne finit que sur `\n` | un `\r` du modèle ouvre un item de liste à côté des vraies propositions |
| M878 | la raison d'une proposition inconnue cite le texte du modèle | le modèle écrit dans la colonne du code |

### Le run unifié, la matrice de couverture, la non-régression (C1)

Un run d'attaque et un run de panne écrivent le même rapport (`eregion_core/run_report.py`), qui
dit ce qu'il est (`metrics.run_format`, `kind`, `injector`, `experiment_id`) ; la matrice
(`eregion_console/coverage.py`) en tire, pour chaque technique du catalogue et chaque panne, la
dernière preuve, son âge, l'évolution et la non-régression. Les tests rejouent des runs factices
(rapports et enregistrements de la watch dans un `runs/` temporaire) : aucun appel au cloud ni au
modèle. Vingt-six mutants, mesurés par `tests/unit/test_coverage.py`, `tests/unit/test_run_report.py`
et les tests des injecteurs (`-k unified`), tous attrapés (30/10) ; M1803 a survécu au premier
passage (le cas de test le donnait par son injecteur), attrapé depuis par une panne d'un autre
injecteur.

| Mutant | Défaut réinjecté | Effet |
|---|---|---|
| M1800 | un run d'Annatar (script) ne dit plus ce qu'il est | le format deviné de nouveau |
| M1801 | un run Atomic ne dit plus ce qu'il est | idem |
| M1802 | un run de panne ne dit plus ce qu'il est | idem, côté Gothmog |
| M1803 | le `kind` du rapport ignoré | une panne d'un autre moteur prise pour une attaque |
| M1804 | une isolation exécutée mais non vérifiée comptée contenue | un temps pour contenir sans preuve |
| M1805 | la ligne perd son temps pour contenir | l'incident contenu affiché sans son temps |
| M1806 | une détection sans décision rattachée vaut preuve | « prouvé » sans la réponse |
| M1807 | pas d'« aging » entre 21 et 30 jours | l'alerte arrive sans le jaune d'avant |
| M1808 | l'indicateur garde sa preuve sur 30 jours | une preuve de 40 jours dite « none » |
| M1809 | la non-régression ne se déclenche jamais | une technique perdue reste « proven » |
| M1810 | une détection inconnue prise pour un raté | un run qui n'a rien mesuré fait régresser |
| M1811 | tout raté de l'histoire fait régresser | une technique détectée de nouveau reste rouge |
| M1812 | jamais détectée dite régressée | une régression sans rien de perdu |
| M1813 | une panne PASS `--without-glorfindel` vaut preuve | une preuve de Glorfindel sans Glorfindel |
| M1814 | une panne refusée prise pour un échec | un refus du garde-fou fait régresser |
| M1815 | l'évolution compte tout l'avant, pas ses 30 jours | la couverture ne baisse jamais |
| M1816 | les indicateurs ne sont plus nourris par la matrice | ni régression dite, ni preuve au-delà de 30 jours |
| M1817 | `eregion coverage --check` n'échoue jamais | la non-régression muette |
| M1818 | une technique prévue jamais jouée comptée en manque | un trou qui n'en est pas un |
| M1819 | un run hors du catalogue disparaît | une technique jouée cachée |
| M1820 | les runs d'une campagne perdent leur campagne | d'où vient la preuve, perdu |
| M1821 | une date qu'aucun calendrier ne tient prise pour une date | un rapport forgé casse la page |
| M1822 | les pages d'Annatar et de Gothmog lisent le catalogue, pas la matrice | la matrice absente de la console |
| M1823 | le temps de la vérification retiré du cycle | le temps pour contenir s'arrête à l'enregistrement (BL1) |
| M1824 | le temps pour contenir s'arrête à l'enregistrement | idem, dans le calcul |
| M1825 | `/api/coverage` prend n'importe quel `kind` | un paramètre non vérifié |

Après la relecture (30/10), quatorze de plus, tous attrapés ; M560 (UI-2) est reciblé sur la
recherche indexée (bissection) qui remplace la lecture de tous les cycles.

| Mutant | Défaut réinjecté | Effet |
|---|---|---|
| M1826 | la décision d'une autre VM rattachée au run | une preuve tirée d'une autre machine |
| M1827 | entre plusieurs enregistrements, le plus ancien | la décision d'une détection voisine |
| M1828 | un run rangé sous une technique prend la décision d'une autre | une preuve croisée |
| M1829 | un run daté dans le futur gardé | un `missed` de 2076 fait régresser pour toujours |
| M1880 | une panne au démarrage échoué prise pour un échec | une régression sans rien d'injecté |
| M1881 | un rapport supprimé gardé en cache | le cache grossit sans fin |
| M1882 | un fichier de la watch supprimé gardé en cache | idem |
| M1883 | la matrice en cache servie après un nouveau rapport | une régression dite 30 s trop tard, ou jamais |
| M1884 | le temps pour contenir de l'accueil mesuré à part de `timeline` | deux définitions |
| M1885 | les indicateurs comptent un run daté dans le futur | une couverture qui n'existe pas |
| M1886 | `eregion coverage` imprime les caractères de contrôle d'un rapport | un rapport forgé pilote le terminal |
| M1887 | un run d'Annatar ne nomme plus sa VM | la décision de n'importe quelle VM |
| M1888 | deux runs de la même seconde dans l'ordre de lecture | l'état dépend du système de fichiers |
| M1889 | le démarrage échoué d'une panne non lu dans ses `checks` | idem M1880, côté lecteur |

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
| L28 | carte détachée vers « aucun NSG » à la levée (U2, septième passe) | `released`, carte laissée sans son NSG, tag effacé |
| L28 | réisolation d'une carte nue | « aucun » enregistré par-dessus le vrai original, carte laissée sans NSG à la levée |
| A0 | une seule priorité (l'entrante) pour juger les deux sens | deny sortant déplacé derrière une allow client : « isolée », mouvement latéral ouvert |
| A0 | allow sortante avant le deny d'un blocage comptée comme « exposition » | « bloqué », la VM joignait encore l'attaquant |
| A0 | carte pas relue après l'échange de NSG | un autre hôte défait l'échange : « isolée », carte sans NSG |
| A0 | ancienne règle à nom fixe sur un NSG partagé ou au partage illisible | « levée », la VM encore coupée |
| A0 | ancien état mono-NSG ignoré par `verify_release` | « levée », règles de l'ancienne version en place |
| A0 | `reset --from-azure` sans intention notée | interrompu, la réaffirmation réisolait en pleine levée |
| A0 | ancien fichier d'état réécrit avant d'être déplacé | crash : deux fichiers, la recherche par nom lisait l'ancien |
| A0 | alertes de la réaffirmation clées par le nom | l'alerte d'un homonyme fermait la carte de l'autre : blocage disparu, rien de dit |
| A0 | blocage disparu derrière la quarantaine | rien de dit avant que la levée rouvre la carte |
| A0 | original d'une carte nue lu dans le seul tag par le reset | « swept », état effacé, carte sans NSG en silence |
| A0 | NSG d'origine remis sans en lire les règles | « swept », VM encore coupée par une ancienne isolation |
| A0 | NSG supprimé lu comme « illisible » | blocage disparu jamais signalé, levée partielle pour toujours |
| L1F | « déjà alerté » écrit avant la carte quand la repose échoue | crash entre les deux : blocage disparu, plus rien de dit |
| I1F | NSG de quarantaine modifié (deny passé en Udp), état et tags de la carte perdus | VM joignable en TCP depuis le VNet, rien de dit : la réaffirmation ne lisait que les isolations dont elle avait l'état |
| I8F | original inconnu (état et tags perdus), carte laissée nue puis réisolée | « aucun NSG » écrit par-dessus l'inconnu : `released`, carte sans son NSG, une ancienne isolation restée sur ce NSG sans état |
| I8F | même carte nue, `reset --from-azure` | carte sautée : `swept`, état effacé, même reste |
| I8F | même carte nue, un 429 à la lecture de notre tag (relecture) | l'erreur lue « aucun NSG » et écrite : même reste |
| I3F | original inconnu (état et tags perdus), carte réisolée puis laissée nue | `verify_release` : `verified: True`, carte sans son NSG, une ancienne isolation restée sur ce NSG ; `glorfindel release`, qui le consulte d'abord, effaçait l'état |
| U3F | blocage coupé avant son état, VM isolée par quarantaine, notre NSG retiré de la carte laissée nue | `unblock` : `not_found`, la règle de blocage restée sur le NSG propre de la carte ; la levée remettait ce NSG, l'IP de nouveau bloquée |
| I5R | blocage de périmètre (200) puis de la VM (210), la règle de la VM passée en allow par un tiers, réaffirmation | la règle de périmètre réécrite au premier numéro libre (220), sous cet allow : **l'attaquant atteignait la VM sur tous ses ports** |
| RB1 | blocage de périmètre puis de la VM (une entrée), la règle de la VM passée en allow par un tiers, deux réaffirmations (ou une en `human_only`) | seul le périmètre réécrit ; « l'IP n'est plus bloquée » alors que le périmètre la coupait encore (faux, du côté prudent) |
| RB1 | même chose, la seconde carte de Db--01 sur un autre subnet (tirage ajouté) | « reposé une fois » alors que la seconde carte restait ouverte à l'attaquant |
| I4A | VM bloquée, sa règle entrante passée en allow par un tiers, son IP changée, une nouvelle VM à l'ancienne adresse, VM bloquée de nouveau (graine 8675 à 500, trouvé par la machine de RB1) | le blocage réécrivait sa règle par son nom, pour la nouvelle adresse : l'allow ôtée, **la nouvelle VM coupée** de flux qu'une opération sur l'autre ne doit pas toucher (I4) |
| I4B | après la séquence d'I4A (une allow retournée laissée sur l'ancienne adresse, une nouvelle VM dessus), `unblock` ou `reset` (graines 42 et 8675 à 500, une fois l'oracle durci) | la règle retirée à l'empreinte de la carte : **la nouvelle VM coupée** des flux que l'allow lui donnait (I4) |
| I4B | VM isolée par règles, sa règle d'isolation entrante passée en allow, son IP changée, une nouvelle VM à l'ancienne adresse, VM réisolée (ou réaffirmée, graine 322 à 2 000) | l'isolation réécrite par son nom : la nouvelle VM coupée ; ou notre refus déplacé de l'ancienne adresse où une de nos règles retournée attendait : **la nouvelle VM ouverte** (I4, I5) |
| I4B | blocage coupé avant son état, VM isolée par quarantaine, état et tags perdus, quarantaine retirée par quelqu'un, VM réisolée (CI macOS, graine au hasard à 500) | la levée remet la carte nue ; `unblock` : `not_found`, le blocage resté sur le NSG que la carte portait (I7) |
| I5R | VM supprimée, l'entrée de son blocage perdue | `unblock` : `not_found` sans avoir cherché, le blocage resté sur le NSG partagé pour la VM suivante à cette adresse (trouvé en relecture d'I7S, hors de la machine) |
| I8S | deux hôtes aux états séparés : « aucun » de l'hôte 1, tag X de l'hôte 2 (la carte a reçu X entre-temps) | la levée suivait l'« aucun » périmé : `released`, carte sans NSG, tag X effacé (trouvé en relecture, hors de la machine) |
| I8S | même scénario, reset ; deux groupes de quarantaine (relecture 5.5) | un 429 sur le tag : carte remise nue, X effacé ; le « aucun » trouvé dans un groupe l'emportait sur X dans l'autre |
| I4F | NSG d'origine d'une carte en quarantaine (ou nue) jugé sans elle | le reset de la nouvelle VM prenait l'ancienne isolation d'une autre VM pour la sienne : **l'autre VM rouverte** |
| I4S | NSG jugé sans la carte d'une autre VM partie en quarantaine (ou nue) | le reset (ou la levée) de la VM restée seule supprimait l'ancienne isolation de l'autre : aucun flux, mais plus rien au retour de sa carte hors de Glorfindel |
| I7S | isolation par règles sur un NSG partagé, état perdu, carte laissée nue, réisolée sur le NSG du subnet (lectures des NSG en 429), VM supprimée | la levée de la VM supprimée ne cherchait rien : `released`, la première isolation restée sur le NSG partagé, visant l'adresse que reçoit la VM suivante |

**I1F (27/10, #226) : un oracle qui lisait mal, et un trou derrière.** Le run profond (10 000
séquences) a fait tomber I1 à l'étape même où quelqu'un passe le deny entrant de la quarantaine
en Udp : le TCP du VNet retombe sur l'`AllowVnetInBound` par défaut d'Azure, alors que le NSG
du client refusait le VNet. Glorfindel n'avait encore rien pu faire : l'échec venait du test, qui
lisait un deny d'un seul protocole comme un deny-all (`_quarantine_intact`) et ne comptait donc
pas l'ouverture pour celle de ce quelqu'un. Le test lit maintenant le protocole, et n'accorde
cette exemption qu'aux NSG de quarantaine qu'il a modifiés lui-même (son journal, `altered`,
comme sur AWS) : un NSG que Glorfindel écrirait mal n'en gagne aucune (M832). Derrière, un vrai
trou : l'état et les tags perdus, rien ne relisait ce NSG. La propriété L2 le borne ; la
réaffirmation liste les NSG de quarantaine et lève une carte par NSG modifié qui porte des
cartes (M830), close d'elle-même quand il est de nouveau entier (M833). Sans rien écrire : sans
état, rien ne dit quelle VM ni sous quel mode (I5). La séquence réduite garde deux
`lose_everything` et cinq éditions identiques du client : des restes du rétrécissement —
`isolate` puis le deny passé en Udp suffisaient à faire tomber I1, avec ou sans état. Tirées
une à une, les étapes qui mènent à L2 ne se rencontraient presque jamais : M830 et M831
n'étaient attrapés que par leurs séquences figées à 500 séquences. Une règle composée
(`quarantine_altered_then_reasserted` : isoler, perdre l'état ou non, vider la quarantaine ou
en retourner un deny — l'entrant passé à un autre protocole une fois sur deux —, réaffirmer
sans panne) les fait attraper : 4/4 à 500 séquences (tirage uniforme : M831 1/2). La relecture
a trouvé ce que la machine ne voyait pas : la passe de la watch s'arrêtait avant toute lecture
quand l'état local était vide (la machine appelait la réaffirmation directement ; elle passe
maintenant par `reassert_pass`, comme la watch), un acquittement défait à chaque passe, une
carte fermée sur un NSG illisible ou hors d'une liste qui ne couvrait que son groupe — depuis la
seconde relecture, la liste est celle de l'abonnement : une carte s'y ferme quand son NSG en a
disparu, jamais quand la liste échoue (M897). Mutants M834–M837, mesurés par
`tests/unit/test_reassert.py` (M834 aussi par la machine, 2/4 à 500 : il faut un monde sans
aucun état). Une seconde relecture a trouvé le trou que la première consigne avait ouvert : listés
dans le seul `quarantine_rg`, les NSG de quarantaine créés dans un autre groupe avant que le
réglage change n'étaient plus lus (la machine ne l'a trouvé qu'une fois sur 11 à 500) — tout
l'abonnement est relu, la séquence est figée (M838). La passe de la watch est sortie dans
`cli._watch_reassert_pass`, testée sur son comportement ; un test structurel ne garde que ce que
le comportement ne voit pas, les deux closures de la watch (M835, M839, M895–M898).

**I8F (27/10, #227) : un inconnu devenu « aucun ».** A3 a fait tomber I8 sur le code non muté
(500 séquences, 186 étapes, dont des 429 sur la carte et les NSG). Réduite, la séquence tient en
quatre étapes : une quarantaine dont l'état et les tags sont perdus, réisolée (l'original est
inconnu, Q7) ; quelqu'un retire notre NSG et laisse la carte nue ; une nouvelle isolation ; la
levée. Le correctif d'U2 (septième passe) reprenait l'original noté pour une carte nue ; noté
nulle part, il écrivait « aucun NSG », alors que l'état tenait la carte en quarantaine avec un
original inconnu. La levée, fidèle à son état, ne remettait rien et disait `released`. I8 le
voyait parce que le monde avait une isolation d'une ancienne version sur le NSG de la carte :
plus rien ne la notait. La réisolation garde maintenant l'inconnu (M860), le reset aussi (M861,
même trou, voisin). Les 429 *toujours* actifs de la séquence d'A3 étaient des restes du
rétrécissement ; un 429 *unique*, lui, faisait le même tort : à la lecture de notre tag lors de la
réisolation, l'erreur se lisait « aucun NSG » et s'écrivait (relecture 5.5 ; M863) — et, l'état
perdu mais le tag intact, par-dessus un tag valide : l'original disparaissait d'Azure (seconde
relecture ; M864). Un tag illisible vaut maintenant un inconnu, rien n'est écrit ; seul le
« aucun » explicite de l'état tient. **L'oracle avait un défaut à
côté** : I8 comptait les règles du NSG propre d'une carte laissée nue que rien ne relie plus à ce
NSG (le journal du test le dit : `_untraceable`), là où I3 et les blocages l'excluent déjà ;
l'état et les tags perdus, la levée ne peut pas le savoir. Il ne les compte plus que si le
**test** a perdu l'état de la VM après la dernière fois qu'il a vu un état tenir la carte en
quarantaine pendant qu'elle était nue (`quarantine_held`, son journal) : cet état savait qu'on
avait retiré notre NSG. Une carte isolée nue après la perte, que rien ne dit nôtre, garde
l'exemption (2 000 séquences, figé). I3 avait le même défaut (`_named_leftovers` : les règles de Glorfindel nommées pour une
carte nue, sur son NSG d'origine hors d'elle) : même exemption, même journal (`_untied`, 500
séquences, figé), et `_consistent` (I8 du reset, I11) aussi (2 000 séquences, figé). Une première version lisait l'état dont la levée
partait : une levée qui jetait le placement qu'elle n'avait pas su défaire gagnait l'exemption
(relecture ; M862, figé).
Une règle composée (`bare_with_an_unknown_original`) rend la séquence courante : tirées une à
une, ses étapes ne se rencontraient qu'avec l'isolation d'une ancienne version (un monde sur
quinze environ) ; dans un monde qui n'en a pas, la règle la pose sur une VM que rien n'a encore
touchée, comme `build`. Elle ne favorise pas la VM d'un monde qui en a une : son ancien état
effacé, M34 tombait à un tour sur cinq. Elle finit par une réisolation sous panne puis une levée,
deux levées, ou un reset. Par la machine seule, au budget du push (500) : M860 2/3, M861 3/3,
M862 3/3, et M863, M864, M865 jamais (0/3 ; le 429 au bon appel reste rare, le reste demande deux
pertes et deux détachements) — d'une mesure à l'autre, ces chiffres bougent (M861 2/5 la veille).
La table `TESTS` les mesure donc par leurs séquences figées puis la machine (précédent de L1F) :
chacun est attrapé à chaque push. M01–M41 et le jeu de contrôle, mesurés sur deux tours à côté
de `main` après la fusion de I1F : 23/39 contre 21/39 attrapés aux deux tours, contrôle 19/32
contre 17/32 ; seul M34 avait reculé (0/2 contre 1/2), repris sur trois tours : 3/3 contre 2/3.
Rien n'est à mesurer au banc : le faux Azure n'est pas en cause.
La seconde relecture a trouvé un angle mort de l'exemption : les tags perdus par le test, une
réisolation d'une carte nue dont l'état connaît l'original réécrit le tag (U2) — le journal ne le
voyait pas, la carte passait pour intraçable, et une levée sans état qui ignorait ce tag (M865)
passait. Le faux Azure note les tags écrits, le test note quand Glorfindel réécrit un original
(`retagged_at`) : la carte n'est plus intraçable s'il l'a réécrit après la perte (figé, avec la
variante sans perte de tags).

**I4F (27/10, #235) : le NSG d'une carte absente.** À 2 000 séquences (graine 101), I4 est
tombée sur une course `release`/`reset` : les flux sortants d'`api` rouverts par deux
opérations sur une autre VM. La séquence, longue de 17 étapes, se réduit à quatre, dont deux opérations sur la nouvelle VM : une ancienne
isolation d'`api` (noms fixes, any/any, état perdu) sur son NSG, une VM créée sur ce même
NSG puis isolée par quarantaine, et le reset de cette VM, seul : la course n'y était pour rien.
Le défaut est dans le produit (`_original_view`, `release.py`). Pour balayer le NSG d'origine
d'une carte en quarantaine, le reset en comptait les cartes attachées, sans celle qui en est
partie. Il n'en restait qu'une, celle d'`api` : le NSG passait pour dédié à la nouvelle VM, et
les noms fixes pour les siens. La carte absente compte maintenant parmi celles de son NSG
(`_nsg_sharing(..., away_nic=)`, `network.py`). Le NSG est lu partagé, et l'ancienne règle,
qu'on ne peut attribuer, est dite (`swept_partial`) au lieu d'être supprimée. La carte nue
passait par le même chemin. La levée n'était pas touchée : elle remet la carte avant de lire.
L'oracle n'y est pour rien : le test sait, par son propre journal, à quelle VM l'ancienne
version a laissé cette règle. Les trois cas sont figés dans les régressions (le reset, la
course telle que trouvée, la carte nue), mutants M960–M961. Tirées une à une, les étapes ne se
rencontraient presque jamais : sans aide, la machine n'attrapait pas M960 à 500 séquences (0/2).
Une règle composée les enchaîne (`joins_an_old_isolation`) : une VM créée sur le NSG d'une
ancienne isolation, la quarantaine allumée, isolée, sa carte laissée nue ou non, puis le reset
(trois fois sur quatre) ou la levée. À 500 séquences, la machine seule attrape M961 3/3 et M960
1/3 ; avec la séquence figée, les deux sont attrapés à chaque tour. Au même budget (60 séquences,
deux tours), aucun mutant du chemin d'isolation n'est perdu : les écarts restent dans le bruit
de mesure (M16 : 3/8 avant, 5/8 après ; M19 : 3/8 puis 1/8 ; ils sont aussi attrapés par leurs
séquences figées). La relecture 5.5 l'a remesuré à 500 séquences, deux tours, sur les seize mutants
de `release.py`, `network.py` et `sweep.py` : 6/15 attrapés à chaque tour avant comme après (8/17 avec
M960–M961), M02 passé de FIXED-ONLY à attrapé par la machine, M26 7/8 de chaque côté sur huit tours.
Limite alors connue, sans flux ouvert (#239) : le cas symétrique, corrigé par I4S (ci-dessous).

**I4S (28/10, #239) : le NSG d'une autre VM partie.** Le cas symétrique d'I4F : l'ancienne
isolation d'`api` (noms fixes, état perdu), `api` envoyée en quarantaine, puis une VM créée sur le
NSG d'`api`, seule attachée. Le reset (ou la levée) de la nouvelle VM prenait les noms fixes pour
les siens et supprimait l'ancienne isolation d'`api`. Aucun flux ne s'ouvrait — la quarantaine
tient `api` —, si bien qu'aucune propriété ne le voyait : I4 ne lisait que les flux et l'état des
autres VMs. L'oracle s'étend donc, sans rien retirer : I4 lit aussi le journal du faux Azure, et
une ancienne isolation (le test sait, par son propre registre `legacy`, à quelle VM l'ancienne
version l'a laissée) n'est jamais supprimée par l'opération d'une autre VM
(`_old_isolations_kept`, après chaque opération et chaque course). Deux exceptions, tirées du
journal du test : la VM n'existe plus, ou le test a perdu tout ce qui rattachait sa carte à ce NSG
(tags et état, `_record_lost`, le cœur de `_untraceable` sans la condition « carte nue ») — la
machine l'a trouvé à 60 séquences, une carte réisolée sur un original inconnu (I8F) : rien, ni sur
Azure ni dans un état, ne dit à quel NSG elle revient. Le correctif est dans le produit
(`_tied_while_away`, `network.py`) : sur un NSG qui porte un nom fixe et ne gouverne qu'une carte,
une carte d'une autre VM partie de ce NSG compte parmi les siennes — en quarantaine, ou laissée
nue — quand notre tag de quarantaine ou, le tag perdu, l'état local de sa VM le désigne comme son
original. Un tag périmé ne rattache rien (la carte supprimée, ou rendue à un NSG hors de
Glorfindel) : la VM réellement seule reprend ses noms fixes. Liste des NSG ou des cartes illisible :
inconnu, les noms fixes restent et le rapport le dit (« au partage illisible »). Règle composée
`an_old_isolations_vm_goes_away` (la VM de l'ancienne isolation isolée, sa carte nue ou non, les
tags perdus ou non, une VM créée sur ce NSG, puis reset trois fois sur quatre, ou levée) ; dix
cas figés (reset, levée, carte nue, tags perdus, état perdu, liste des cartes illisible ; liste des
NSG illisible ; et le pendant : la VM seule avec un tag périmé, la VM elle-même en quarantaine, la
carte du reset sans aucune liste) ; mutants M1030–M1037, attrapés à chaque tour, d'abord par leurs
séquences figées. La relecture 5.5 a trouvé le nom de blocage simple (`glorfindel-block-<ip>`, sans
VM) compté parmi les noms fixes sans qu'aucun cas ne le prouve, et le déblocage muet quand le
partage est illisible : `not_found`, la règle laissée (l'IP restait bloquée : côté sûr, mais faux).
Trois cas figés de plus (le blocage d'`api` gardé au déblocage de la nouvelle VM ; le NSG, puis la
liste des NSG, illisibles : `unblock_partial`, le blocage dit et laissé, repris une fois lisible),
mutants M1038–M1039. La course avec la réaffirmation n'est plus exemptée : elle ne supprime aucune
règle hors de notre NSG de quarantaine, seule l'autre opération compte comme acteur. Le mécanisme couvre aussi le cas
d'I4F (la carte de la nouvelle VM porte notre tag) : M960–M961 n'y restent visibles que par un cas
figé où les listes sont illisibles — la carte du reset elle-même suffit à dire le NSG partagé, sans
rien lire d'autre. Mesures : machine verte à 500 séquences (graines 1, 7, 42) et à 2 000 (graine
101) ; harnais à 500 séquences, deux tours, sur les 32 mutants de `release.py`, `network.py` et
`sweep.py`, à côté de `main` (0f32b92) : 24/32 attrapés à chaque tour avant, 25/32 après, aucun
perdu ; les huit nouveaux, 8/8. Le seul écart, M33 (1/2 puis 2/2), est du bruit : 6/6 de chaque
côté sur six tours (M10, instable des deux côtés : 4/6 avant, 5/6 après).

**I8S (28/10, #245) : deux hôtes, deux états, un « aucun » périmé.** Trouvé par la troisième
relecture d'I8F, hors de la machine : elle n'a qu'un répertoire d'état. Une carte nue ; l'hôte 1
l'isole (état et tag : « aucun ») ; quelqu'un retire notre NSG, le client donne ensuite un NSG X à
la carte ; l'hôte 2 l'isole (tag : X) ; notre NSG retiré de nouveau ; l'hôte 1 la réisole, un 429
à l'appel k, puis la lève. Sur les 26 positions, 10 finissaient `released`, la carte sans NSG et
le tag X effacé : la levée suivait l'« aucun » de son état sans lire le tag. Le reset, `verify_release`
et une levée sans réisolation avaient le même défaut. Correctif, option (a) de l'issue : quand
l'état dit « aucun », un tag lisible qui nomme un NSG l'emporte ; un tag illisible fait échouer la
levée ; la réisolation n'écrit plus « aucun » par-dessus un tag qu'elle n'a pas lu. L'option (b) — un
tag absent ou illisible toujours inconnu — aurait gardé en quarantaine toute carte nue par conception
dont les tags sont perdus. L'oracle n'est pas touché. La relecture 5.5 a trouvé deux trous de plus :
le reset notait l'« aucun » avant de lire le tag, et un 429 sur ce tag remettait la carte nue en
effaçant X (corrigé, M1048) ; deux hôtes dans deux groupes de quarantaine, le premier tag trouvé (le
« aucun » de l'hôte 1) l'emportait sur X dans l'autre groupe — ancien, `main` aussi — : un tag qui
nomme un NSG gagne maintenant sur un « aucun » trouvé d'abord (M1049). Le scénario est écrit à la
main, avec deux répertoires d'état sur le faux Azure (`test_two_hosts_a_stale_none_never_leaves_the_nic_bare`,
259 cas : la carte réisolée, nue ou encore dans la quarantaine de l'hôte 2, dans le même groupe ou
un autre, levée ou reset, un 429 avant ou après chaque appel ; I1 et I2 de la machine vérifiés
après chaque levée ; 189 échouent sur la 0.4.0, dont 10 des 26 positions). Mutants M1040–M1049,
mesurés par ces cas : 10/10 attrapés. Au même budget (60 séquences, deux tours), les 62 mutants
du chemin d'isolation : 33/62 attrapés à chaque tour avant comme après la première version, aucun
perdu ; après la correction, les 29 de `sweep.py` et `quarantine.py` : 19/29 de chaque côté, aucun
perdu. Les écarts restent dans le bruit, mais M04, M17, M19 et M33 reculent sur quatorze tours
(M04 10/14 contre 14/14, M17 2/14 contre 6/14). Cause probable : la levée d'une carte dont l'état
dit « aucun » lit maintenant le tag, et un 429 la fait échouer ; les séquences tirées changent. À
500 séquences, le budget du push, une seule passe de deux tours sur la première version : les
quatre attrapés 2/2 ; la relecture, une autre passe de deux tours, a eu M19 (un blocage, sans lien
avec le lot) à 1/2.

**I3F (28/10, #287) : un inconnu lu comme levé.** Le harnais de SEC3 a fait tomber I3 une fois
sur le code non muté, ancien (`main` aussi) : « verify_release True, …/api not back to its design ».
Réduite, la séquence tient en trois étapes, dans un monde où une ancienne version a isolé `api`
sur son propre NSG : `an_old_isolations_vm_goes_away` (`api` en quarantaine, les tags perdus, la
carte laissée nue, une nouvelle VM sur ce NSG remise à zéro), `config_changes` (le groupe de la
quarantaine devient celui de la VM), puis `bare_with_an_unknown_original`. Dans cette dernière, la
carte nue est réisolée dans une seconde quarantaine (l'original est lu dans l'état), perd cet état
et les tags de ce NSG, est réisolée — son original inconnu maintenant (Q7) — puis laissée nue.
Jusque-là, `verify_release` répondait « api-nic : sans NSG, nsg-api-nic non remis » ; ensuite,
`verified: True`. **Cause** (`providers/azure/verify.py`) : pour une carte nue, `verify_release`
cherchait l'original dans l'état, puis dans notre tag, et ne trouvant ni l'un ni l'autre, ne
disait rien. Une carte que l'état tient en quarantaine sans original était donc lue comme
levée. C'est le trou d'I8F, resté dans la vérification. Il pesait plus qu'un mot :
`glorfindel release` consulte `verify_release` d'abord, et sur un `True` efface l'état sans rien
lever. Correctif : une telle carte est un inconnu, `verified: False`, et `original_unknown` la
nomme (M1340). La levée gardait déjà le placement ; elle disait « la carte reste en quarantaine »,
« NSG de quarantaine non détaché », d'une carte qui n'avait plus de NSG. Elle dit maintenant
« carte sans NSG, NSG d'origine non remis » et comment en sortir : poser le NSG sur la carte, ou
le tag (M1341, M1342 ; `test_a_bare_nic_whose_original_is_unknown_is_said_bare`).
**L'oracle laissait passer le même cas, plus courant** : l'exemption d'une carte nue
(`_untraceable`) valait dès que le test avait perdu l'état et les tags après que Glorfindel avait
noté l'original. Or, dans la règle composée d'I8F, l'état d'après (celui de la réisolation) tenait
la carte en quarantaine sans original, et Glorfindel pouvait le lire. Six séquences déjà figées
(I8F) passaient ainsi sur le code non corrigé. La séquence de SEC3 ne tombait que parce que
l'original avait été réécrit en tag sur l'*autre* NSG de quarantaine (`retagged_at`). I3 n'exempte
plus une carte nue que le test a vue tenue en quarantaine sans original par un état, depuis la
dernière perte de cet état (`_held_unknown`) : pour `verify_release`, pour la levée et pour le reset.
Sans le correctif, ces six séquences et la nouvelle tombent ; avec lui, elles passent.
Par la machine seule, M1340 est attrapé 5/5 à 60 séquences et 3/3 à 500. Invariants : 500
séquences sur cinq graines, et 2 000 sur deux graines, verts. Au même budget (60 séquences, deux
tours), les 64 mutants mesurables de `verify.py`, `release.py`, `quarantine.py` et `sweep.py`
donnent 51/64 attrapés à chaque tour, avant comme après. Huit d'entre eux bougent d'un côté à
l'autre. Remesurés sur six tours : 28/48 avant, 33/48 après, instables d'au moins un côté (M15 attrapé 6/6 des deux côtés)
(M09 5/6 → 3/6, M26 3/6 → 2/6, M29 0/6 → 4/6). Aucun n'est perdu : un mutant à 0/2 par la machine
reste attrapé par ses séquences figées.

**Le verrou des escalades, hors de l'ordonnanceur (29/10, #292).** Sur cette branche, le job macOS
de la CI restait bloqué dans la machine. La pile écrite par `faulthandler` l'a montré : dans une
course où les deux opérations laissent une carte, l'une, arrêtée par l'ordonnanceur à son écriture
pendant qu'elle tenait le verrou du magasin (SEC3), laissait l'autre bloquée dans ce verrou, hors
de sa vue ; le teardown attendait ensuite derrière. C'était aussi le « op-2 never came back »
d'I11, qu'on croyait dû à la charge. Le défaut était dans le banc, latent sur `main` depuis SEC3 :
tout verrou réel qu'une course peut prendre doit être celui de l'ordonnanceur (`_scheduled`).
`_file_lock` prend un `timeout` comme `_vm_lock`, et la machine l'essaie sans attendre ; la
régression `test_a_race_whose_two_operations_rewrite_the_escalations_store` rejoue la course, et le
mutant M1395 (le verrou qui ignore son délai) y est attrapé. Le job macOS est borné (25 min) et un
test qui dure plus de 8 min y écrit la pile de ses fils.

**SEC4b (29/10, #275) : un état illisible, un contournement, des propositions perdues.** La
machine n'écrit jamais d'état illisible : les lecteurs qui concluaient « personne » d'un fichier
qu'ils ne lisaient pas (`_held_in_quarantine` pour `verify_release`, `_recorded_original` pour la
levée et le reset, `_tied_while_away`, la passe de réaffirmation) sont mesurés par
`tests/unit/test_unreadable_state.py`, sur le faux Azure de la machine : chaque cas échoue sur
`main` (16 tests, avec ceux de `test_reassert.py`). Le contournement (V-16) y est aussi, de bout en
bout : notre deny passé derrière une allow d'un tiers, une carte, aucune écriture sur Azure, la
règle toujours là. Le magasin des règles proposées est mesuré entre vrais processus
(`measure_proposals`, `test_locks.py`) : sur `main`, 28 propositions perdues sur 60, 5 approbations
et 1 rejet perdus, 2 lectures d'un fichier à moitié écrit ; aucune après. Mutants M1250–M1259,
M1390–M1394 : 15/15 attrapés par ces tests. Invariants à 500 séquences, deux graines : verts.
Au même budget (60 séquences, deux tours, `--jobs 4`), les 95 mutants de `state.py`, `network.py`,
`release.py`, `verify.py`, `sweep.py` et `reassert.py` : 78/94 attrapés à chaque tour avant, 75/94
après (M865, M1212 et M1340 suivent le code déplacé : 2/2). Aucun n'est perdu : M10 et M36 survivent
des deux côtés, les autres écarts sont des tours de moins ou de plus. Remesurés sur six tours, M01,
M07 et M28 font 6/6 après ; M26, 3/6 avant comme après.
La relecture a trouvé ce que la première version cassait à côté : un état illisible d'une autre
VM empêchait d'isoler une carte sans NSG (l'isolation levait `StateUnreadable`), un déblocage
derrière la quarantaine la laissait échapper après ses suppressions, une ré-isolation à côté de
son propre état illisible levait. L'isolation lit maintenant l'illisible comme inconnu (jamais
arrêtée, l'original inconnu non écrit), le déblocage finit `unblock_partial`, et l'état illisible
de la VM est mis de côté au lieu d'être écrit par-dessus. La seconde relecture : mis de côté sous `<fichier>.unreadable.json`, puis réparé,
le fichier redevenait un état actif (deux isolations de la VM, et la migration remettait l'ancien
état à la place du courant) : il va dans `isolation/aside/`, hors des états, listé tant qu'il existe.
Une isolation dont l'original reste inconnu le dit tout de suite (`original_unknown`). Mutants
M1520–M1531, attrapés par leurs tests ; M678 et M860, restés sur l'ancien texte, suivent le code (2/2). Ces chemins ne changent
rien quand aucun état n'est illisible : la machine, qui n'en écrit jamais, ne les voit pas.

**U3F (29/10, #293) : « introuvable » sur une règle laissée.** À 500 séquences, la graine 210
faisait tomber I3 de façon déterministe, sur `main` aussi : « unblock said not_found, rules left
for …/api: ['glorfindel-block-…-api-api-nic-…'] ». Hypothesis s'est arrêté de réduire au bout de
cinq minutes ; réduite à la main, la séquence tient en quatre étapes : `block` sur `api`, coupé
par un crash avant son état (après la règle entrante, ou après les deux), `isolate` (quarantaine),
`someone_detaches_the_quarantine` (la carte laissée sans NSG), puis `unblock`. **Cause**
(`providers/azure/unblock.py`, `_sweep_block`) : sans entrée d'état, le déblocage balaie les NSG
des cartes, et le NSG propre d'une carte, hors d'elle, n'y était cherché que derrière une
quarantaine. Une carte nue ne montrait que le NSG de son subnet : `not_found`, la règle restée,
et la levée qui suit remettait ce NSG — l'IP de nouveau bloquée. Correctif (`_original_away`) :
l'original d'une carte nue se lit comme à la levée — l'état, sinon notre tag sur le NSG de
quarantaine de la région, l'« aucun » de l'état cédant au tag qui nomme un NSG. Une carte que
l'état tient en quarantaine sans original, qu'aucun tag ne nomme (Q7), donne `unblock_partial`
qui la nomme (A0 : jamais « rien » sur un inconnu). Séquences figées
(`test_an_unblock_looks_behind_a_quarantine_taken_off`, `test_an_unblock_of_a_bare_nic_takes_the_block_or_says_it`) ;
M1343–M1345 attrapés ; M23 suit le code déplacé (attrapé par ses séquences figées). Invariants :
500 séquences sur 38 graines (dont 210 et 203 ; 26 lancées ensemble sur 16 cœurs, 3 à 6 fois plus
lentes), et 2 000 sur 210 et 203, vertes — sauf la graine 322, qui tombe aussi sur `main` (I7,
ci-dessous). Au même budget (60 séquences, deux tours), les 71 mutants mesurables par la machine
de `providers/azure/` (blocage, déblocage, levée, vérification, quarantaine, reset, réseau, NSG),
de l'état et de la réaffirmation : 42 attrapés à chaque tour avant, 38 après, mais les graines
changent à chaque tour ; aucun perdu — tout mutant attrapé avant l'est après, par la machine ou
par ses séquences figées, et seul M36 survit après (M10 et M36 avant). Remesurés sur quatre
tours, les sept qui avaient bougé donnent 5/7 attrapés à chaque tour après, 4/7 avant.

**I7S (29/10, #303) : les règles d'une VM supprimée sur un NSG partagé.** Trouvée pendant U3F, la
graine 322 à 500 séquences faisait tomber I7 de façon déterministe, sur `main` aussi : « I7: rules
of the deleted …/web left: ['nsg-tier/glorfindel-iso-web-web-nic-…', …-out] ». Réduite à la main
(une étape retirée à la fois, tant que l'échec reste), la séquence tient en trois étapes et le
`recover` du démontage : `block_then_isolate` sur `web` (quarantaine éteinte : isolée par règles
sur `nsg-tier`, NSG qu'elle partage), `bare_with_an_unknown_original` (quarantaine allumée, isolée,
état et tags perdus — l'état qui nommait les règles de `nsg-tier` avec eux —, réisolée, carte
laissée nue, levée deux fois : l'original inconnu), puis `address_reused` : isolée pendant que
`nsg.get` répond 429 (la quarantaine refusée, la carte nue isolée par règles sur le NSG du subnet,
l'état réécrit ne nomme plus que celui-là), puis supprimée. **Cause**
(`providers/azure/release.py`, `_sweep_isolation`) : la levée d'une VM supprimée défaisait les
placements de son état, trouvait la VM absente et s'arrêtait là (`return []` : « la VM est
partie, ses cartes avec elle ») — `released`. Les règles de la première isolation restaient sur
`nsg-tier`, nommées pour `web-nic` et visant son adresse : la VM suivante qui la reçoit derrière ce
NSG est coupée (une action disruptive à tort ; jamais une ouverture). Le balayage des orphelines
le disait déjà (`orphans_are_reported`), et ne la retire que si elle coupe une VM vivante, en
`non_disruptive`. Correctif (`_gone_vm_rules`) : la VM absente, la levée cherche les règles nommées
pour les cartes que ses états nomment (placements de l'isolation, des blocages, et celles qu'une
levée partielle a gardées, `known_nics`) sur tous les NSG de l'abonnement — l'empreinte de la carte
dans le nom ne désigne qu'elle — et les retire ; une liste qui échoue donne `release_partial`
(A0 : jamais « levée » sur un inconnu), l'état et ses cartes gardés pour le nouvel essai. Séquences
figées : `test_a_deleted_vm_leaves_no_isolation_on_a_shared_nsg` (la graine réduite) et
`test_a_deleted_vms_rules_go_with_its_release_or_are_said` (l'état réécrit ou le seul blocage qui
nomme la carte ; une VM recréée à la même adresse, coupée et dite avant la levée, revenue à sa
conception après ; la liste en 429). Mutants M1550–M1555 attrapés par ces séquences (M1550 aussi
par la machine, graine 322 à 500) ; M07 suit l'appel déplacé. L'oracle n'a pas bougé. Invariants :
500 séquences sur six graines (322, 210, 203, 1, 42, 777) et 2 000 sur 322, 210 et 203, vertes.
Au même budget (60 séquences, deux tours, `--jobs 4`), les 76 mutants mesurables par la machine
de `providers/azure/`, de `response/`, de la réaffirmation et des orphelines : 44/74 attrapés à
chaque tour avant comme après ; aucun perdu — tout mutant attrapé avant (par la machine ou ses
séquences figées) l'est après, M761 attrapé après seulement ; M10, M36 et M864 survivent des deux
côtés. Les huit qui avaient bougé, remesurés sur quatre tours : 1/8 attrapés à chaque tour des deux
côtés. Le harnais a aussi trouvé, sur sa graine du moment, un échec d'I5 sans lien (« the
reassertion opened flows of …/web », l'attaquant sur 443), présent sur `main` : réduit à quatre
étapes (`block_perimeter` coupé, `block` sous 429, notre blocage passé en allow par quelqu'un,
`quarantine_altered_then_reasserted`), à traiter dans un lot à part.
La relecture 5.5 a trouvé deux trous que la machine ne voit pas (elle n'écrit jamais d'état
illisible, et sa suppression d'une VM emporte ses cartes). Un état illisible de la VM supprimée
(isolation ou blocage) : `released`, les règles laissées, et le seul fichier qui nommait la carte
effacé — maintenant `release_partial`, le fichier gardé (M1556–M1558). Une carte qu'Azure garde
après sa VM (`az vm delete` et Terraform la détachent par défaut), rattachée à une autre VM du même
nom que Glorfindel isole : la levée retirait l'isolation de celle-ci, qui porte les mêmes noms —
la carte est maintenant lue d'abord ; 404, détachée ou sur une VM d'un autre nom, ses règles sont
cherchées ; sur un homonyme, elles restent et c'est dit ; illisible, « non vérifiée » (M1559,
M1600, M1601 ; c'est la garde « Azure dit 404 » d'A3, étendue). Séquences figées : quatre cas de
plus à `test_a_deleted_vms_rules_go_with_its_release_or_are_said`,
`test_a_deleted_vms_nic_that_azure_kept_is_read_first` (quatre cas). Seuls les noms actuels à
empreinte sont cherchés — ni ceux d'avant L24 ni ceux suffixés par la VM, partagés par des
homonymes : voulu, pour I2.

**I5R (29/10, #311) : une réaffirmation qui ouvrait.** Trouvée par la machine pendant I7S,
présente sur `main`, déterministe : « I5: the reassertion opened flows of …/rg-app2/…/web »,
l'attaquant sur ses ports 22 et 443. Réduite à quatre étapes : `block_perimeter` sur `web` (la
règle de périmètre à 200), `block` de la même VM (sa règle à 210, dans la même entrée d'état),
`tamper_with_our_rule` qui passe la règle de la VM en allow, puis la réaffirmation (ici dans
`quarantine_altered_then_reasserted`, sur une autre VM : le crash et le 429 tirés n'y jouent
pas). **Cause** (`providers/azure/blocks.py`) : la vérification voit la règle de la VM manquer,
la réaffirmation repose le blocage — de périmètre, l'entrée étant `scoped: false` — et la règle
réécrite sous son nom prenait le premier numéro libre, le sien compté comme pris : de 200 à 220,
sous l'allow à 210. Remettre ce qui manquait déplaçait ce qui tenait. Correctif
(`nsg.py`, `_pair_priorities`) : nos deux noms ne comptent pas parmi les numéros pris, et une
règle déjà à nous garde le sien s'il est plus petit, dans sa direction (Azure n'y met aucune
autre règle) — une réécriture monte ou reste, jamais ne descend. Le même chemin vaut pour le
blocage d'une VM et pour l'isolation par règles, qui excluait déjà ses noms mais déplaçait une
paire séparée à la main (la règle sortante déplacée, son numéro pris par une autre). Ce que la
réaffirmation ne remet pas (la règle de la VM retournée), elle le dit : la carte de dérive, puis
« disparu une deuxième fois ». Séquences figées (`test_a_perimeter_block_put_back_keeps_its_place`,
`test_the_sequence_the_machine_found_on_i5`, `test_a_block_written_again_never_moves_down`,
`test_an_isolation_written_again_never_moves_down`) ; M1590–M1594 attrapés. Tirées une à une,
les étapes ne se rencontraient presque jamais : la machine seule laissait M1590 et M1591 à 0/2 à
500 séquences. Une règle composée (`block_turned_then_reasserted` : bloquer sur le subnet, pour
la VM ou les deux, passer un de nos deny en allow — celui de la VM une fois sur deux —, puis
réaffirmer hors faute, hors `human_only` plus souvent) rend M1592 courant : attrapé par la
machine seule à 500 séquences (2/3, puis 2/2 à la relecture) ; M1591 rarement (2 sur 5 en
cumulant les deux mesures), tenu surtout par les séquences figées. M1590 (une paire séparée dont le numéro est
pris par une autre règle), M1593 et M1594 restent aux séquences figées : il y faut une règle
d'autorisation posée entre nos deux numéros, que la machine ne pose pas.

**Le déblocage d'une VM supprimée (I5R).** Le défaut qu'I7S corrige pour la levée, côté
déblocage : `_sweep_block` répondait `[], []` sur une VM absente, et un blocage dont l'entrée
était perdue (un crash avant qu'elle soit écrite, ou réécrite depuis) restait sur un NSG
partagé, `not_found` annoncé — l'IP de l'attaquant coupée pour la VM suivante à cette adresse.
Correctif (`unblock.py`, `_gone_vm_blocks`) sur les aides de la levée d'I7S (`release.py`,
dites maintenant pour l'acte qu'elles servent) : les cartes que l'état nomme (`_known_nics` : les
placements du blocage, de l'isolation), leurs règles de blocage cherchées sur tous les NSG de
l'abonnement et retirées (`_gone_vm_rules`) ; une carte gardée et rattachée depuis à une autre
VM du même nom n'est pas touchée, et c'est dit (`_gone_nic_check`) ; un état illisible est dit
(`_gone_vm_unknown`). En plus de la levée : une règle nommée pour la VM dont rien ne nomme plus
la carte, et qu'aucune carte vivante ne porte, ne se distingue pas de celle d'un homonyme
supprimé — laissée et dite (`unblock_partial`, `_unnamed_blocks`) ; une liste refusée aussi. La
machine ne débloque pas une VM supprimée : tests figés (`test_an_unblock_of_a_deleted_vm_*`),
M1595–M1599 attrapés ; ces tests mesurent aussi les mutants d'I7S (`-k deleted_vm`), 12/12
attrapés.

**Mesures d'I5R.** Invariants sur le code final, la règle composée comprise : 500 séquences sur
les graines 1, 42, 203, 210, 322 et 777, puis 2 000 sur 42 et 322, verts (la 322 tombait sur I7
avant I7S). Au même budget (60 séquences, deux tours), les 124 mutants des modules touchés
(blocage, isolation, NSG, déblocage, levée, réaffirmation), ceux qu'I7S avait choisis et les
siens, avant (`main` avec I7S) et après : 92 attrapés à chaque tour avant, 95 après. M03 suivait
l'ancien texte de l'isolation (attrapé 2/2 une fois corrigé). Deux ont semblé perdus, dilués par
la règle composée. M761 (une règle d'une carte vivante prise pour orpheline) : 2/2 avant, 0/2
après ; remesuré sur six tours, 5/6 avant, 2/6 après, 5/6 après sans la règle composée ; à 500
séquences, 3/3 avant comme après. M831 (`nsg.py`, relevé à la relecture) : 3/3 puis 5/6 avant,
0/1, 1/3 puis 1/6 après à 60 séquences ; à 500, 3/3 après (graines 11, 99, 1234). Aucun mutant
n'est perdu au budget de la CI (500).

**RB1 (29/10, #321) : ce que dit la carte d'un blocage fusionné.** Trouvé à la relecture d'I5R,
présent sur `main` ; rien ne s'ouvrait par Glorfindel, les cartes se trompaient. Un
`block_perimeter` et un `block` de la même VM partagent une entrée (`scoped: false`). La règle de
la VM passée en allow par un tiers, la réaffirmation ne reposait que le périmètre (l'entrée dit
« sous-réseau »). **Cause** : `verify_block_ip` ne lisait, pour une entrée à placements, que les
règles de la VM — le périmètre ni compté là où il tient une carte, ni vérifié lui-même — et
`_reassert_block` reposait le blocage dans la portée de l'entrée, puis disait « reposé » sur la foi
de l'écriture. Sur un seul subnet, le périmètre coupait encore l'attaquant, et la passe suivante
(ou la première en `human_only`) disait « l'IP n'est plus bloquée » ; sur une VM dont la seconde
carte est sur un autre subnet (le périmètre couvre celui de la carte primaire), « reposé une fois »
avec cette carte ouverte. **Correctif** : la vérification compte, carte par carte, un blocage de
périmètre de l'IP sur un NSG qui gouverne la carte — celui de l'entrée, ou celui d'une autre VM du
subnet : la machine l'a trouvé sur le premier correctif, graines 1 et 203 à 500 séquences
(`held_by_perimeter`, `open_nics`, `perimeter_unread` : illisible n'est ni tenu ni ouvert), et
vérifie la paire de périmètre de l'entrée (supprimée, elle disparaissait en silence pour les autres
VM du subnet) ; la réaffirmation repose le périmètre **puis** les placements de la VM, relit Azure,
et ne dit « reposé une fois » que d'un blocage entier — sinon `partial`, dit une fois par épisode ;
sa carte ne dit plus « n'est plus bloquée » d'une IP que le périmètre ou la quarantaine coupe
encore (`reassert.py::_block_drift`, `providers/azure/perimeter.py`). **La machine** gagne un tirage
(la seconde carte de Db--01 sur un subnet à elle, `data_subnet`, tiré en dernier) et un oracle sur
ce que disent les cartes de blocage d'une passe (`_block_cards_true`, jugé sur le monde et le
journal du faux Azure), carte réseau par carte réseau, sur celles que la carte nomme (toutes celles
de la VM si elle n'en nomme aucune) : « reposé une fois » ou « reste bloquée » → l'attaquant
n'atteint pas ces cartes ; « n'est plus bloquée » → jamais d'une carte que notre périmètre, intact
sur son subnet, coupe seul — le NSG du subnet seul, sans nos autres deny, les règles qu'un tiers a
retournées gardées (une isolation, ou le NSG propre d'une carte qui ferme aussi le port, ne comptent
pas pour le périmètre : le modèle de préséance du code, un NSG à la fois ; trouvé par la machine,
graine 42 à 2 000) ; seule exemption, une carte d'escalade quand la même passe a écrit ce périmètre
(le journal le dit) pour l'entrée d'une autre VM — dite avant l'écriture, elle était vraie (graine
322 à 2 000) ; une carte de repose, écrite après sa propre relecture, n'en a pas. Sur `main`, la
machine seule fait tomber l'oracle aux graines 1, 322 et 1234 (500 séquences), sur les deux formes
du constat. **Le tirage `data_subnet`** fait passer les mondes où les deux cartes de Db--01 partagent
un subnet d'environ 100 % à environ 50 % (`st.one_of(st.none(), …)`), et, tiré en dernier mais
ajouté au flux d'octets, il décale les exemples que `GLORFINDEL_INVARIANT_DB` rejoue : une séquence
mémorisée avant RB1 rejoue une autre séquence.

**La relecture 5.5 de RB1 : I3 de `block_perimeter`, et une écriture échouée.** Le premier correctif
avait borné le contrôle de préséance d'un blocage de périmètre (I3 de `block_perimeter`) aux cartes
du subnet du périmètre, pour toutes les VM. La relecture l'a défait sur une copie : la machine
échoue en 5 min (graine 1, 300 séquences), réduite à `build(subnet_nsg=[], data_subnet=[])` puis
`block_perimeter(Db--01)` — « perimeter block said blocked, … reaches Db--01 ». Le borner cachait un
vrai défaut, qui ouvrait une carte : `block` de Db--01 sur ses deux subnets, puis
`block_perimeter(replace=True)` — la promotion retirait les placements des **deux** cartes, alors
que le périmètre ne couvre que le subnet de la carte primaire ; db-nic-1 ouverte, `blocked` dit,
`verify_block_ip` vrai (une entrée de périmètre seul ne lisait que sa paire), aucune carte. Sans
promotion, `blocked` aussi, la seconde carte ouverte. **Correctif** (`blocks.py`, `perimeter.py`,
`unblock.py`) : la promotion garde les placements des cartes hors du subnet du périmètre (et de
toutes, si les cartes ne se lisent pas) ; un blocage de périmètre nomme les cartes qu'il ne couvre
et que rien ne bloque (`uncovered_nics`, statut `blocked_partial`, ou `nics_unread`) ; la
vérification d'une entrée de périmètre seul lit ces cartes — fausse, la réaffirmation le dit sur sa
carte (« n'est plus bloquée sur db-nic-1 »). **Le test** : pour la VM visée, I3 garde toutes ses
cartes — sauf celles qu'elle nomme non couvertes, que le test vérifie hors du subnet (sa propre
connaissance) ; pour les autres VM du subnet, leurs cartes derrière le périmètre ; I3 sur
`verify_block_ip` couvre toute entrée, de périmètre seul comprise. Second cas de la relecture : une
entrée fusionnée sur web2, sa règle propre retournée, le NSG du subnet illisible (403), en
`non_disruptive` — la repose du périmètre échoue, celle de la VM réussit, et la relecture disait
vrai, l'état `unknown` de la paire de périmètre compté nulle part : « reposé une fois », l'erreur
avalée. Maintenant une écriture échouée n'est jamais « reposé » (`partial`, l'erreur dans la carte),
et une paire de périmètre illisible rend la vérification inconnue. Séquences figées
`test_a_perimeter_block_never_says_blocked_with_a_nic_left_open` (celle de la relecture),
`test_a_promotion_keeps_the_block_of_a_nic_the_perimeter_doesnt_cover`,
`test_a_perimeter_block_alone_is_verified_on_every_nic`,
`test_a_perimeter_block_whose_nics_cant_be_read_takes_no_block_off`,
`test_a_write_that_failed_is_never_said_put_back` (toutes échouent sur `main`) et un test de
`test_reassert.py` ; mutants M1635–M1640. Sur ce correctif, la machine a encore trouvé (graine 777
à 500) une carte hors du périmètre jugée bloquée sur la foi de l'état : son blocage enregistré,
ses règles retirées depuis (un `terraform apply`), `blocked` dit. Ce qui la bloque est relu sur
Azure (`verify_block_ip`) ; séquence `test_a_perimeter_block_reads_the_other_nics_own_block_on_azure`,
mutant M1641.

**Seconde relecture : une dérive qui n'existait pas.** Introduite par la reprise : après
`block(Db--01)` puis `block_perimeter(Db--01, replace=True)` sur deux subnets, l'entrée ne garde
que le placement de db-nic-1 ; la vérification lisait db-nic-0, absente des placements, comme une
carte ajoutée depuis aux règles manquantes (`held_missing`). En `human_only`, « a disparu d'Azure
en partie (db-nic-0) » — c'est la promotion qui l'avait retirée ; ailleurs, les règles de la VM
réécrites sur db-nic-0, la promotion défaite, « reposé une fois », et `reasserted_at` posé : la
vraie dérive suivante escaladée sans être reposée. **Correctif** (`perimeter.py`,
`_left_to_perimeter`) : une carte d'une entrée fusionnée sans placement, derrière la paire de
périmètre de l'entrée sur un NSG qui la gouverne, et que cette paire tient, est couverte par
conception ; le périmètre retourné, elle est ouverte. Et un périmètre seul sur une VM dont une carte
est sur un autre subnet ne dit plus « a disparu — l'IP n'est plus bloquée sur db-nic-1 » d'une carte
jamais bloquée, et ne réécrit plus le périmètre pour rien : « ne couvre pas db-nic-1 … non couverte
depuis le blocage (autre subnet) — bloquer aussi la VM (scope vm) », une fois, sans écriture. **La
machine** gagne un oracle (aucun retiré ni restreint) : une suite de blocages et de promotions
réussis, sans faute ni rien d'autre qui touche le monde entre eux (le journal du faux Azure et une
image du monde à la fin de chacun), puis une passe — une entrée dont toutes les règles nommées avant
la passe sont des écritures de cette suite n'a aucune carte « disparu »
(`_no_drift_on_untouched`). Séquences `test_a_promotion_is_no_drift_for_the_next_pass` (les deux
modes : l'oracle les fait tomber sur le code d'avant), `test_a_promotion_leaves_the_next_pass_silent_and_writes_nothing`,
`test_a_nic_left_to_a_perimeter_someone_turned_is_open` ; mutants M1642–M1644.

**Troisième relecture : un acquittement qui faisait taire la suite.** La carte « ne couvre pas »
posait `drift_alerted_at`, que seule une vérification vraie efface — jamais, pour cette entrée.
Acquittée, puis la paire de périmètre supprimée par un tiers : chaque passe s'arrêtait sur le
marqueur, le périmètre (l'IP coupée pour tout le subnet) ni reposé ni dit ; une régression de RB1
(sur la base, ce blocage se vérifiait vrai, sa disparition reposée ou dite). **Correctif** : la
carte a son propre marqueur, `uncovered_said` (l'ensemble des cartes non couvertes, redite s'il
change), et la paire lue entière, un épisode de dérive d'avant est clos (`drift_alerted_at`
effacé) ; une disparition ultérieure suit le chemin normal. **La machine** gagne une règle,
`operator_acknowledges` : l'opérateur acquitte une carte de blocage en attente de la réaffirmation,
tirée au hasard — les cartes de blocage seulement : les autres (quarantaine, orphelines,
contournement) restent dites par conception une fois acquittées, et leurs oracles comptent les
cartes en attente. L1 tient une carte de dérive acquittée pour dite, pour son épisode (tant que
Glorfindel n'a réécrit aucune règle du blocage depuis), comme le code le veut. Stable : 500 séquences
vertes sur huit graines (1, 42, 203, 322, 777, 1234, 2718, 8675), et 2 000 sur 322 ; sur le code
d'avant, quatre graines à 500 n'atteignent pas la séquence (il y faut un périmètre seul sur Db--01,
sa carte acquittée, la paire supprimée, une passe) — elle reste aux séquences figées
`test_a_perimeter_gone_after_its_uncovered_card_is_acknowledged_is_put_back_or_said` (les deux
modes, et une seconde disparition après la repose) et
`test_an_uncovered_card_is_said_again_when_the_uncovered_nics_change`, qui échouent sur le code
d'avant ; mutants M1645–M1647.

**Quatrième relecture : ce qui empire après un acquittement.** L'assouplissement de L1 (une carte
de dérive acquittée vaut dite tant que Glorfindel n'a réécrit aucune règle du blocage) laissait
passer un vrai silence, introduit par RB1. Une entrée fusionnée sur web2, ses règles propres
passées en allow : en `human_only`, « … l'IP reste bloquée sur web-nic par la règle de périmètre »
— vrai alors ; acquittée, puis la paire de périmètre supprimée par un tiers : `drift_alerted_at`
encore posé (l'entrée jamais relue entière), chaque passe muette, l'attaquant sur web2. Sur la
base, la carte disait « n'est plus bloquée », que rien ne contredisait ensuite. **Correctif**
(`reassert.py`, `_situation`, `_worse`) : l'entrée garde ce que la carte a dit (`drift_said` :
les règles manquantes, les cartes tenues, ouvertes, inconnues, l'IP bloquée ou non) ; la carte
est redite quand c'est pire — une carte tenue devenue ouverte ou inconnue, une règle de plus qui
manque, l'IP plus bloquée ; pareil ou mieux, rien n'est redit (une carte par disparition). Une
entrée d'une version d'avant, sans ce qui a été dit, se tait comme avant. **L'oracle** : l'exemption
de L1 ne vaut que tant que les règles de l'entrée sur Azure, paire de périmètre comprise, sont
identiques à un instantané pris à l'acquittement ; pour une entrée fusionnée, `_block_vanished`
dit « disparu » quand toutes les règles de ses placements ont disparu (le critère d'avant) **ou**
quand sa paire de périmètre a disparu — deux conditions alternatives : les exiger toutes les deux,
comme la quatrième version, affaiblissait L1 (cinquième relecture). La règle `operator_acknowledges` tire son indice avant de lire les cartes
en attente, avec des bornes fixes : tiré parmi elles, il changeait d'une relecture à l'autre de la
même séquence (Hypothesis : « FlakyStrategyDefinition », graine 1). Séquences
`test_a_drift_card_acknowledged_is_said_again_only_when_it_worsens` (la paire supprimée : redite ;
rien, ou mieux : rien) et `test_the_machine_finds_a_perimeter_deleted_after_its_card_is_acknowledged`
(par les règles de la machine, L1) ; les deux cas « pire » échouent sur le code d'avant. Mutants
M1648 (jamais redite) et M1649 (redite à chaque passe) ; M900 et M902 suivent la ligne du marqueur.
M1646 n'est pas équivalent, contrairement à ce que j'avais écrit : quand les **mêmes** règles
disparaissent une seconde fois (périmètre seul sur Db--01 : « ne couvre pas », acquittée ; la paire
supprimée, « disparu », acquittée ; bloqué de nouveau, la paire revenue ; la paire supprimée encore),
rien ne la dit pire, et seul l'épisode clos la fait redire — avec M1646, le silence, web1 atteinte ;
séquence `test_the_same_perimeter_gone_twice_is_said_twice`, qui mesure M1646.

**Le déblocage d'une VM supprimée (RB1).** Ce qu'il laisse porte sa commande
(`az network nsg rule delete -g … --nsg-name … -n …`) et le dit redit tant que la règle reste — la
retirer met fin à l'`unblock_partial`, le déblocage suivant aboutit. L'entrée perdue, un blocage de
périmètre de l'IP (nom simple) qu'aucune entrée d'une autre VM n'enregistre n'était ni cherché ni
dit (`not_found`) : dit et laissé (il couvre tout un subnet). **Notre `-out` retourné en Inbound**
(`nsg.py`, `_pair_priorities`, d'avant I5R) : son numéro comptait comme libre, la règle entrante y
entrait en collision, Azure refusait, rien n'était reposé ; seule une règle à nous dans sa propre
direction libère le sien.

**Séquences figées** (`test_invariant_regressions.py`) : les séquences de RB1, relectures
comprises ; vingt cas échouent sur `main` pour la raison dite, les autres (un périmètre contourné
sur le port de la menace, un périmètre d'une autre VM au déblocage, l'entrée gardée) gardent des
mutants ; tests de `test_reassert.py`. Mutants M1620–M1649 attrapés par elles ; M1599 réaligné. Conséquence
voulue de la relecture après repose : un blocage tenu par la quarantaine dont les règles, sur le
NSG propre de la carte (hors de la carte jusqu'à la levée), ont disparu n'est plus dit « reposé » —
la repose écrit sur le NSG qui gouverne la carte, celles-là manquent toujours : `partial`, dit.

**Mesures de RB1** (code final, relecture comprise). Invariants : 500 séquences sur les graines 1,
777, 1234 et 2718, puis 2 000 sur 322 et 42, verts (avant la relecture, 500 sur 1, 11, 42, 99, 203,
322, 777, 1234 et 2 000 sur 42, 322, 1234). Les vingt-deux mutants M1620–M1641 sont attrapés par
leurs séquences figées (et `test_reassert.py`), M1590–M1599 aussi. Par la machine seule (mesuré
avant la relecture, 500 séquences, deux tours) : M1621, M1625 et M1634 à chaque tour, M1622 une
fois sur deux, M1627 jamais (tenu par `test_reassert.py`), les autres par les séquences figées
seulement — la relecture après repose suffit à rendre vraie la carte d'une repose incomplète
(M1620), c'est la séquence figée qui voit la règle de la VM restée retournée. Harnais avant/après
au même budget (60 séquences, deux tours, `--jobs 4`) sur les mutants des modules du chemin
d'isolation (blocage, déblocage, NSG, réseau, quarantaine, isolation, levée, vérification, état,
réaffirmation) : 138 avant (`main`), les mêmes et M1620–M1641 après ; attrapés à chaque tour,
113/138 avant, 112/138 après, 134/160 avec les nouveaux. Aucun perdu : M10 (un subnet illisible lu
« sans NSG »), 1/2 avant et 0/2 après à ce budget, remesuré — 1/6 avant, 4/6 après à 60 séquences,
2/2 des deux côtés à 500 ; M36 et M864 survivent des deux côtés. M761 et M831, dilués à 60
séquences depuis I5R : à 500, 2/2 avant comme après. Après la seconde relecture : M1620–M1644 et
M1590–M1599, 35/35 par leurs séquences figées ; invariants à 500 sur les graines 1, 777 et 2718,
puis 2 000 sur 322, verts ; harnais avant/après (60 séquences, deux tours) sur les mutants des
modules touchés (déblocage, périmètre, réaffirmation et ce qui en est sorti) : 32 attrapés à chaque
tour avant comme après, aucun perdu (M830, 1/2 avant, ne l'est plus qu'aux séquences figées), et
les vingt nouveaux à chaque tour. Après la troisième : M1620–M1647 et M1590–M1599, 38/38 par leurs
séquences figées ; M1645 par la machine seule, 0/2 à 500 (la séquence n'est pas tirée) ; invariants
à 500 sur huit graines et 2 000 sur 322, verts, la règle d'acquittement comprise ; harnais
avant/après (60 séquences, deux tours) sur les mutants du déblocage, du périmètre et de la
réaffirmation : 34 attrapés à chaque tour avant, 35 après, aucun perdu (M13 2/2 → 1/2, M19 et M830
attrapés à chaque tour après), les vingt-trois nouveaux à chaque tour. Après la quatrième :
M1620–M1649, M1590–M1599 et M900–M902, 42/42 par leurs séquences figées (M1646 mesuré depuis la cinquième relecture par sa propre séquence) ;
invariants à 500 sur les graines 1, 42, 777, 2718 verts, 2 000 sur 322 vert ; la graine 8675 à 500
tombe sur I4, un défaut **hors de RB1**, présent sur `main` (1996a49) : rejoué à l'identique sur la
base, figé en `xfail` strict (`test_a_block_written_again_after_an_ip_change_leaves_the_new_owner_of_the_old_address` :
api bloquée, sa règle entrante retournée en allow par un tiers, son IP changée, une nouvelle VM à
l'ancienne adresse, api bloquée de nouveau — l'opération change les flux de la nouvelle VM ; cause
supposée, non établie), pour un lot à part. Harnais avant/après (60 séquences, deux tours, mêmes
modules) : 33 attrapés à chaque tour avant comme après, aucun perdu, les nouveaux à chaque tour.

**I5Q (29/10, #327) : une réaffirmation qui ouvrait une VM après une adresse reprise.** Trouvée
par la quatrième relecture de RB1, graine 101 à 500 séquences (« I5: the reassertion opened flows
of …/rg-new/…/web », l'attaquant sur 22), présente sur `main` avant RB1. Réduite de 14 étapes à
quatre : `block` d'`api` (sa règle à 200), `block_turned_then_reasserted` (`both` : la règle de
périmètre à 210, puis celle d'`api` passée en allow par quelqu'un), `address_reused` (`api` isolée
par règles sur son NSG, supprimée, une nouvelle VM `rg-new/web` à son adresse et sur ce NSG), puis
la réaffirmation en `non_disruptive`. **Cause** (`providers/azure/sweep.py`, `find_orphan_rules`) :
le balayage des orphelines retirait l'isolation d'`api`, qui coupait la nouvelle VM — mais ce refus
était le dernier à tenir l'attaquant dehors : sur le NSG du subnet, notre règle retournée le laisse
passer avant le blocage de périmètre, et le NSG de la carte l'autorise sur 22. Le balayage ne lisait
que nos refus ; une de nos règles devenue autorisation ne comptait pas. Correctif
(`providers/azure/turned.py`, `_turned_allows`, `_turned_behind`) : un refus d'une carte disparue reste, « Gardée :
notre règle … retournée en autorisation … », quand une de nos règles (`glorfindel-iso-*`,
`glorfindel-block-*`) passée en allow, du même côté, visant l'adresse de la carte qu'il coupe ou
toutes (`*`, un préfixe qui la contient, une étiquette — lue comme la contenant), se tient sur un
NSG qui gouverne cette carte. La carte le dit ; remise en refus ou retirée, la règle retournée
libère le passage suivant, qui retire le refus. La VM reste coupée en attendant — jamais ouverte.

**La levée d'une VM supprimée, le même trou.** Une règle composée (`turned_then_address_reused` :
`block`, `block_turned_then_reasserted` et `address_reused` sur la même VM, puis la réaffirmation
hors faute, hors `human_only` plus souvent) rend l'état courant ; à 500 séquences, la graine 322 y a
trouvé la levée : « I4: an operation on …/rg-edge/…/api opened flows of …/rg-app2/…/api ». La
levée de la VM supprimée défait les placements de son état, ou cherche ses noms sur tous les NSG
(I7S) : elle retirait le même refus. Correctif (`release.py` ; `turned.py`, `_held_by_turned` sur
les placements, `_turned_guard` dans `_gone_vm_rules`) : le refus reste, `release_partial`, la
règle retournée nommée ; la levée suivante le retire une fois celle-ci remise. Une VM vivante qui
tient elle-même l'adresse n'est jamais retenue par sa propre règle retournée (ce qu'elle laisse
passer est le fait de quelqu'un, sur l'adresse de la VM : I1 le juge ainsi). Le déblocage d'une VM
supprimée retire avec ses refus ses propres règles retournées : rien n'y attend derrière.

**L'oracle.** I5 n'a pas bougé. La vivacité d'U1 (après le balayage en `non_disruptive`, plus
aucune VM coupée par une orpheline) contredisait I5 dans cet état : une orpheline gardée derrière
une règle retournée en est exemptée, lue du journal du test (`tampered`, la règle encore telle que
quelqu'un l'a laissée), jamais des cartes du code, et elle doit être dite avec ce qui la retient :
une carte en attente nomme une règle que le journal dit retournée derrière elle, et ne dit pas d'abord
de retirer le refus. **L'exemption est volontairement prudente, plus large que le seul conflit avec
I5** : le code garde le refus dès qu'une de nos règles retournée, du même côté, vise l'adresse sur un
NSG de la carte — sans évaluer si une sonde passerait (une règle retournée sur un autre port, un NSG
de carte sans autorisation : le retrait n'ouvrirait rien, le refus reste quand même, dit), et
l'oracle l'exempte de même. Borner l'exemption aux retraits qui ouvriraient vraiment un flux absent
de la conception de la VM demanderait au code d'évaluer les NSG comme Azure ; une VM coupée à tort,
dite, plutôt qu'ouverte. Au démontage, l'opérateur remet les règles
retournées que de tels refus retiennent, comme la carte le demande, avant les levées ; I7 et U1
restent entiers ensuite. Séquences figées : `test_the_sequence_the_machine_found_on_i5_after_an_address_reused`
(la graine réduite), `test_an_orphan_deny_behind_a_turned_rule_stays_said_then_goes` (la règle de
la VM ou celle du périmètre), `test_a_deleted_vms_deny_behind_a_turned_rule_stays_with_its_release`
(placements, ou état perdu), `test_a_live_vms_release_is_not_held_by_its_own_turned_rule`, et dans
`test_orphan_sweep.py` les adresses (`*`, un préfixe, une étiquette, une autre adresse). Mutants
M1730–M1736, attrapés à chaque tour ; par la machine seule à 500 séquences, M1730 et M1734 1/3
(M1730 0/6 avant la règle composée).

**La carte partagée.** Après la reprise de RB1, la graine 101 à 500 a trouvé la suite : « U1: the
orphan rule glorfindel-iso-web-… kept behind a rule turned into an allow, cutting […/batch], not
said ». Les refus entrant et sortant de la VM supprimée coupent la même VM : dits en `human_only`,
ils partagent une carte (le magasin fusionne par VM). Passée en `non_disruptive`, la passe retire
le sortant (la règle retournée est entrante) et résolvait la carte, que l'entrant, gardé, partageait :
le refus restait, plus dit. Correctif (`orphans.py`) : une carte qu'une orpheline encore suivie
partage reste ouverte. Test `test_a_card_two_rules_share_stays_open_while_one_stands` ; M1737
attrapé.

**La relecture d'I5Q.** La séquence figée de la graine ne prouvait plus rien sur `main` : depuis
RB1, la réaffirmation lancée dans `block_turned_then_reasserted` en `non_disruptive` remet la règle
retournée en refus, et l'état fautif n'est jamais atteint. L'étape 2 tourne maintenant en
`human_only` : la séquence tombe sur I5 avec `glorfindel/` de `56fc9f0`, passe sur la branche. Une
carte dite avant le retournement (en `human_only`, ou partagée avec l'autre refus de la VM) n'était
jamais réécrite : elle disait encore de retirer le refus (`az network nsg rule delete`), seul pas
proposé, ce qui ouvrirait la VM. Correctif (`orphans.py`) : la carte d'un refus gardé qui ne nomme
pas la règle retournée est fermée et réécrite, les refus qu'elle couvrait dits de nouveau, les gardés
d'abord ; son premier pas dit de remettre la règle en refus (`az network nsg rule update …
--access Deny`), le retrait seulement après. La liste des NSG peut dater d'un passage : juste avant
le retrait, `remove_orphan_rule` relit par leur id les NSG qui gouvernent la carte coupée (le sien
et celui du subnet) et rejoue la garde ; une lecture refusée garde la règle. La levée d'une VM ne
consulte plus la garde pour un placement dont la carte vit encore quand la liste des NSG est
refusée : sa propre adresse, rien d'une autre VM n'y attend. Tests
`test_a_card_said_before_the_turn_is_replaced_by_one_naming_it` (le second passage en `human_only`
ou en `non_disruptive`, la carte partagée par les deux refus), `test_a_rule_turned_after_the_listing_stops_the_removal`,
`test_a_live_vms_release_is_not_held_by_its_own_turned_rule[refused]` ; mutants M1738–M1743.
L'oracle resserré a aussitôt trouvé deux suites (graine 31337 à 500) : les deux refus d'une VM
gardés derrière deux règles retournées différentes — la carte que le magasin fusionne par VM ne
nommait que la première ; et le nom de la règle de périmètre commence celui de chaque règle de VM de
son IP — lu comme une sous-chaîne, une carte ancienne qui disait de retirer une règle de VM passait
pour nommer le périmètre, et restait. La carte d'une VM nomme maintenant chaque règle retournée que
ses refus gardés attendent (« notre règle X (… », le nom entier) et les remet toutes en refus
d'abord ; l'oracle lit le nom entier. Séquence figée `test_a_card_names_the_turned_rule_by_its_whole_name`,
tests `test_the_card_of_a_vm_names_every_rule_its_kept_denies_wait_behind`,
`test_a_card_naming_a_vm_rule_of_the_ip_is_no_card_naming_the_perimeter` ; M1744, M1745. Mesures
après la relecture : M1730–M1745 attrapés à chaque tour ; invariants à 500 verts sur les graines
31337, 4242 et 9001 (la 101 rouge sur L2 seule), à 2 000 vert sur 322. Harnais au même budget
(60 séquences, deux tours) sur les modules touchés (`sweep.py`, `release.py`, `readers.py`,
`turned.py`, `orphans.py`), avant (`56fc9f0`) et après : 13/22 attrapés à chaque tour avant,
14/22 après (27/35 avec les nouveaux) ; aucun perdu — M12 (1/2 puis ses séquences figées seules)
et M33 (2/2 puis 1/2), remesurés sur quatre tours après : 2/4 et 3/4.

**La seconde relecture d'I5Q.** Un refus gardé nouveau, sans carte à lui, se fondait dans la carte
en attente de sa VM (celle d'une orpheline non gardée), dont le magasin garde la première raison :
l'opérateur ne voyait que le retrait d'un refus déjà parti, le refus gardé nommé nulle part pendant
une passe. La carte en attente de la VM est lue aussi, et remplacée si elle ne nomme pas tout le
groupe (`test_a_new_kept_deny_never_merges_into_a_stale_card_of_its_vm`, M1746). La levée d'une VM
vivante, la liste des NSG refusée, ne lâche son refus que si sa carte tient encore toutes les
adresses qu'il vise (`test_a_live_vms_release_is_not_held_by_its_own_turned_rule[refused, address
moved]`, M1747). L'oracle d'U1 exige que la carte qui nomme la règle retournée porte sur une VM que
le refus coupe, ou sur son NSG. Après la reprise d'I4A, une seule règle dit si une adresse est
visée : `nsg._takes_in` d'I4A (plus précis sur les valeurs entourées d'espaces) remplace celui
d'I5Q, et le `takes_in` de l'oracle s'y aligne ; M1732 le suit.
La graine 322 à 2 000, après I4A, a trouvé trois échecs. Un est d'I5Q : la levée d'une VM vivante
dont l'IP a changé garde son refus sur l'ancienne adresse, que la règle composée d'I4A donne à une
nouvelle VM, une règle retournée derrière (`release_partial`, voulu) ; l'opérateur du démontage ne
remettait que ce que retiennent les refus des VM supprimées — il remet maintenant ce que retient tout
refus des nôtres sur l'adresse d'une autre carte (`_cutting_others`), puis I7 tient
(`test_a_live_vm_whose_deny_waits_before_a_turned_rule_is_released_once_it_is_put_back`). Les deux
autres échouent aussi avec `glorfindel/` de `20cb5b5` (I4A), de la famille qu'I4A a laissée ouverte
(une IP changée) : une isolation réaffirmée sous ses noms quitte l'ancienne adresse où attend une règle
retournée (I5), et une levée interrompue ouvre la nouvelle VM (I4) — figées en `xfail` strict
(`test_a_reasserted_isolation_moves_off_the_old_address_a_turned_rule_waits_behind`,
`test_an_interrupted_release_after_an_ip_change_opens_the_new_owner`), pour la suite d'I4A.

**Trouvé en chemin, hors d'I5Q : L2.** La même graine tombe ensuite sur L2 (« the quarantine NSG
…/rg-sec/…/nsg-glorfindel-quarantine-westeurope was altered, holds […/api-nic-5]; the
reassertion neither put it back nor said so ») : réduite à 14 étapes écrites avec les règles de
`main`, elle échoue de même avec `glorfindel/` de `171a242` (RB1) et de `b83cb92` (avant RB1).
La configuration est lisible à chaque étape. Cause (établie par la relecture d'I5Q,
`reassert_quarantine._report_altered_quarantines`) : un accès forensique change le diff du NSG, la
carte du nouveau changement est écrite mais pas `quarantine_alerts.json` (disque plein), qui garde
l'identifiant de l'ancien ; l'accès retiré, le diff revient à l'ancien changement, lu « déjà dit ou
acquitté » — aucune carte, le NSG toujours vidé. Figée en `xfail` strict
(`test_an_altered_quarantine_stays_said_when_its_change_comes_back`) pour le lot L2Q (#331). La graine 101 à 500 reste rouge sur L2 jusqu'à lui (levé par L2Q, ci-dessous).

**Mesures d'I5Q.** Avant la reprise de RB1 : invariants à 500 séquences sur les graines 101, 202,
322, 1, 42 et 777, puis 2 000 sur 101, 322 et 42, verts. Sur le code final (RB1 et la 0.4.6 repris) :
la séquence du relecteur (graine 101, 14 étapes) passe, et tombe toujours sur I5 avec `glorfindel/`
de `b83cb92` ; à 500 séquences, verts sur les graines 202, 322, 1, 42, 777 et 2718, la 101 rouge sur L2 seule (ci-dessus) ; à 2 000, verts sur 322, 42 et 777. Au même budget (60 séquences,
deux tours, `--jobs 4`), les 80 mutants mesurables par la machine de `providers/azure/`, de
`response/`, de la réaffirmation et des orphelines, avant (`b83cb92`) et après (avant la reprise de
RB1) : 51/80 attrapés à chaque tour avant, 50/80 après (57/87 avec M1730–M1736). Aucun perdu : M19
et M26, attrapés par la machine avant, ne l'étaient plus que par leurs séquences figées après ;
remesurés sur quatre tours, 2/4 puis 1/4 (M19), 2/4 puis 2/4 (M26), et 2/2 chacun à 500 après. M02,
M04, M14, M18, M20, M32, M34, M830 et M831 gagnent un tour ; M08, M09, M12 et M17 en perdent un
(remesurés sur quatre tours : entre 1/4 et 4/4 des deux côtés). À 500, le code d'avant tombe déjà,
sur une graine du moment, sur une autre propriété (« I4: … cut off … », hors de ce lot) : la mesure
d'avant à 500 n'a pas pu tourner.
**I4A (29–30/10, #328) : un blocage réécrit sur une adresse reprise.** Le défaut figé par RB1 en
`xfail` strict (graine 8675 à 500), présent sur `main` avant RB1. **Cause, établie** : api bloquée sur
le NSG de son subnet, sa règle entrante (`glorfindel-block-<ip>-api-api-nic-<empreinte>`) passée en
allow par un tiers ; l'IP d'api change, Azure donne l'ancienne à une nouvelle VM (la plus basse
libre) — l'allow retournée laisse maintenant l'attaquant joindre cette VM. api bloquée de nouveau
(`block`, ou la réaffirmation hors `human_only`) : `_block_ip_vm` (`providers/azure/blocks.py`)
écrivait sa paire sous les mêmes noms (`_put_deny_rule`, un `create_or_update`), pour la nouvelle
adresse d'api ; l'allow disparaissait, la nouvelle VM perdait les flux qu'elle lui ouvrait. Ce
n'est pas une ouverture : une action disruptive sur la mauvaise VM (I4).

**Correctif.** Avant d'écrire, le blocage lit la paire en place (`_plan_block`) ; une règle qui,
réécrite ou retirée, changerait les flux d'une autre VM est **laissée** (`_left_on_others`) : une
allow à notre nom dont une adresse n'est plus celle de la carte et qu'une autre carte tient (la
liste des cartes, une fois par blocage), ou dont on ne sait pas qui la tient (cartes illisibles,
une plage, une étiquette — jamais lu « personne », A0), ou `*` sur un NSG que d'autres partagent.
La paire va alors sous le **second nom** de la carte (`…-<carte>-b-<empreinte>`,
`_placement_rule_bases`) : même empreinte en fin de nom, la vérification sans état, le déblocage,
le reset, la VM supprimée et le balayage des orphelines la lisent comme la première. L'autre règle
de la première paire, à nous et ne visant aucune autre VM, est retirée une fois la paire posée
(elle coupait la nouvelle VM : la retirer ne rend que ce qu'elle coupait). L'ancienne adresse à
personne : réécrite comme avant (I7S). Ce qui est laissé est dit (`left_rules`, la commande qui
le retire) et gardé dans le placement ; la passe suivante le dit sur une carte `rule_left`, une
fois par ensemble (`left_said`), sans écrire.

**Trouvé par la machine sur le premier correctif** (sa nouvelle règle, graine 42 à 2 000, présent
sur `main` aussi, rejoué à la main sur 171a242) : web2 bloquée sur son NSG, sa règle sur le NSG du
subnet (un placement plus ancien) passée en allow ; batch créée sur le NSG de web2 à l'ancienne
adresse. Le blocage réécrit déplaçait **notre deny** vers la nouvelle adresse : l'allow retournée,
derrière lui, laissait l'attaquant joindre batch sur 22 — une ouverture. Notre deny sur une
adresse d'une autre VM est donc gardé aussi quand une règle du blocage de la carte, sur un NSG de
la carte, est passée en allow pour cette adresse (`_turned_behind`) ; ces NSG illisibles, il est
gardé (le garder n'ouvre rien). Même principe que I5Q pour la levée et le balayage (un deny qu'une
règle retournée attend derrière ne part pas).

**La relecture 5.5** a trouvé trois manques, corrigés : l'allow retournée qui attend derrière notre deny était cherchée par son adresse exacte — une plage (`10.0.0.0/16`) ou une étiquette (`VirtualNetwork`) lues « rien », le blocage ouvrait batch sur 22 (un inconnu lu « rien », A0) : `_takes_in` (`nsg.py`, la règle d'I5Q, à partager à la fusion) prend l'adresse, `*`, une plage qui la contient, et compte une étiquette ou une valeur illisible comme la prenant ; l'échec du retrait de la règle de la première paire était écrit où rien ne le lisait, `blocked` dit alors que notre deny `-out` restait sur l'adresse de la nouvelle VM — dit maintenant (`drop_failed`) ; la vérification sans état prenait la première paire présente par son nom — elle lit d'abord celle qui bloque la carte telle qu'elle est (deux deny de l'attaquant pour ses adresses), une allow avant la seconde paire n'est plus cachée. **Reste ouvert** (I4B, #333, avec le pendant de l'isolation) : le déblocage et le reset retirent une règle à l'empreinte de la carte quoi qu'elle soit devenue (`_nic_owns`) — l'allow retournée que le blocage laisse aussi : la VM qui a reçu l'ancienne adresse perd encore ces flux, au déblocage et non plus au blocage. La machine ne le voit pas : `unblock` et le reset jugent I4 sans les flux de l'attaquant (`perimeter=True`). Figé en `xfail` strict (`test_the_unblock_and_the_reset_leave_the_new_owner_of_the_old_address`, avec et sans re-blocage). « Personne » veut dire aucune carte de VM : une instance de VMSS qui tient l'adresse n'est pas vue (angle mort ancien).

**La machine** tire maintenant la séquence (`address_reused_under_a_turned_rule` : bloquer, une
règle du blocage retournée, l'IP changée, une VM créée à la plus basse adresse libre, bloquer de
nouveau ; I4 vérifié par `_block`). Aucune règle retirée ni restreinte, aucun oracle affaibli.
**Séquences figées** : la séquence de 8675 (plus `xfail`), l'adresse reprise dite sur une carte une
fois (redite après acquittement : non), l'adresse à personne réécrite, notre deny réécrit pour la
VM qu'il bloque, le détenteur inconnu, une plage, `*` sur un NSG partagé (le contournement dit), le
second nom trouvé sans état (vérification, déblocage — l'IP changée de nouveau —, reset), le deny
gardé quand une allow retournée attend derrière (NSG lisible ou non). **Hors du lot, figé en
`xfail` strict** : le pendant de l'isolation (même séquence, api isolée par règles puis réisolée —
la réisolation réécrit l'allow retournée par son nom, la nouvelle VM coupée), trouvé en sondant ce
lot.

**Mesures d'I4A.** `pytest` complet : 4 018 réussis, 7 sautés, 1 `xfail` ; `ruff` propre. Invariants :
500 séquences sur les graines 8675, 1, 777 et 2718, puis 2 000 sur 42 et 322, verts (sur le premier
correctif, 2 000 sur 42 tombait sur l'ouverture ci-dessus). Mutants M1755–M1769 (blocage,
déblocage, reset, réseau, réaffirmation) : 15/15 par leurs séquences figées, à chaque tour. Par la
machine seule : M1755 (la règle retournée réécrite) une graine sur deux à 500 (1 : I4 ; 2 : non),
M1768 (notre deny levé devant l'allow retournée) sur 42 à 2 000. Harnais avant/après (60 séquences,
deux tours, `--jobs 4`) sur les 144 mutants des modules touchés (blocage, déblocage, reset, levée,
réseau, réaffirmation, ses cartes) : 123 attrapés à chaque tour avant (171a242) comme après, et les
quinze nouveaux ; M1555 (le nom `-out` de la VM supprimée) réaligné sur la ligne réécrite.
Aucun perdu : M20 et M830, 2/2 avant et 1/2 après à ce budget, remesurés à 500 séquences — 2/2 des deux côtés ; M02, M16, M23, M24, M26 et M761 mieux après (bruit à 60).
Après la relecture : `pytest` complet 4 027 réussis, 7 sautés, 5 `xfail` (le pendant de
l'isolation, le déblocage et le reset après une adresse reprise) ; M1755–M1769 et M1920–M1923,
19/19 par leurs séquences figées à chaque tour ; invariants à 500 sur 8675 et 31337, puis 2 000
sur 42, verts.

**I4B (30/10, #333) : le déblocage, le reset, la levée et l'isolation, sur une adresse reprise.**
La suite d'I4A, relevée par sa relecture. **L'oracle d'abord** : au déblocage et au reset,
`perimeter=True` retirait tous les flux de l'attaquant des autres VM de la comparaison (un
déblocage peut lever un périmètre, qui les ouvre). Durci sans rien affaiblir : ces flux d'une
autre VM ne sont plus jamais retirés (`_attacker_never_cut`, sauf une VM en quarantaine, comme
`_only_sealed`), et ils ne s'ouvrent que derrière un périmètre réellement levé — une règle au nom
de l'IP seule retirée d'un NSG qui gouverne la VM, d'après le journal du faux
(`_perimeter_lifted_for`) — ou là où seule la règle restée d'une autre carte fermait ; de même dans
deux opérations à la fois. Sur `main`, 500 séquences : les graines 42 et 8675 tombent (« I4: an
operation on …/api cut off …/rg-app1/…/api », le déblocage), 1, 101, 322 et 31337 passent ; aucune
séquence n'a ouvert à tort.

**Causes et correctifs.** (1) **Le déblocage et le reset** (`xfail` d'I4A, quatre cas) retiraient
une règle à l'empreinte de la carte quoi qu'elle soit devenue (`_nic_owns`) : l'allow retournée
laissée par I4A, qui vise la VM ayant repris l'adresse, partait avec — cette VM perdait ce qu'elle
lui ouvrait. (2) **La garde d'I5Q** (`_turned_guard`) laissait partir une allow (`!= deny`). Une
seule garde maintenant pour toute suppression d'une de nos règles par son nom
(`turned._held_by_turned`) : une règle passée en allow qui vise une autre carte vivante qu'un de
ses NSG gouverne — son adresse, `*` sur un NSG d'autres cartes, une plage ou une étiquette (A0) —
reste (`_opens_another`), comme notre refus qu'une règle retournée attend derrière (I5Q). Le
déblocage (placements et balayage), le reset et le balayage de la levée la demandent, le premier
pour toute règle, les autres quand la règle vise autre chose que les adresses de la VM
(`_aims_elsewhere`) ; ce qui reste est dit (`unblock_partial`, `swept_partial`, `release_partial`).
(3) **L'isolation réécrite** (`xfail` ancien) : réisolée après le changement d'IP, elle réécrivait
par son nom l'allow retournée qui vise la nouvelle VM. (4) **La réaffirmation** (graine 322 à
2 000) et (5) **la levée interrompue** (même graine, 18 étapes — la cause, non établie par I5Q,
est l'isolation par laquelle l'étape commence, pas la levée) : l'isolation réécrite déplaçait notre
refus de l'ancienne adresse, où une règle de blocage de la VM, retournée, attendait derrière lui sur
le NSG du subnet — la nouvelle VM s'ouvrait. L'isolation fait maintenant comme le blocage d'I4A
(`_plan_isolation`) : elle lit sa paire, laisse ce que la garde garde (`left_rules`, `left_note`, la
carte de la réaffirmation), s'écrit sous le second nom de la carte (`…-b-<empreinte>`, lu par la
vérification, la levée et le reset) et retire l'autre paire. Les deux séquences de 322 échouaient
dans leur dernière étape ; elles reçoivent les tirages de la fin de l'étape, jamais atteinte avant.
(6) **Le quatrième point de la fiche** : la garde du blocage (`_turned_behind`, I4A) ne lisait que
les règles du blocage de la carte, sur ses NSG ; elle lit aussi toute règle retournée des nôtres sur
un NSG qui gouverne le détenteur de l'adresse (`_waits_for`) — une isolation retournée derrière notre
refus le laissait lever ; illisibles : gardé.

**Le septième cas, trouvé par la CI macOS** (graine au hasard, 500 séquences ; présent sur `main`
897cd21) : « I7: block rules of …/api left after unblock ». Rejoué à l'identique sur `main`, puis
instrumenté : la levée du démontage remet la carte d'api **nue** (son original, enregistré « aucun »
après que quelqu'un a retiré la quarantaine), et le déblocage, l'entrée du blocage perdue (un crash
après les écritures), ne regardait que les NSG que la carte porte — aucun : `not_found`, le blocage
resté sur `nsg-api-nic`. **Le code, pas la machine** : ses règles portent l'empreinte de la carte,
d'aucune autre ; le déblocage les cherche maintenant sur tous les NSG de l'abonnement quand la carte
n'a pas de NSG à elle que rien n'enregistre (`_unplaced_blocks`, comme pour une VM supprimée). La
séquence de 39 étapes, réduite à la main à 7, est figée
(`test_the_unblock_finds_the_block_of_a_nic_left_with_no_nsg_it_knows`, entrée perdue : rouge sur
`main` avec le même message ; entrée gardée : verte des deux côtés).

**Le démontage** : ce que les opérations gardent maintenant, l'opérateur le remet comme il était,
comme elles le disent — en plus des règles retournées que retiennent nos refus (I5Q), les règles
retournées qui visent une autre carte (`_turned_aimed_elsewhere`, la convention et le journal du
test, jamais les marques du code) — jusqu'à ce qu'il n'en reste aucune : remise, une allow redevient un refus des nôtres sur l'adresse d'une autre carte, qui peut à son tour retenir une autre règle retournée (graine 101 à 500 sur le code d'I4B, le trou de l'opérateur et non du code, figée : `test_a_turned_rule_put_back_may_hold_back_another_in_its_turn`). Aucune règle de la machine retirée ni restreinte.

**Limites de l'oracle, relevées par la relecture d'I4B** (pour un lot de suite, non réglées ici) :
la machine ne vérifie pas que ce que le déblocage garde est **dit** — seules les séquences figées le
voient (`unblock_partial`, la règle nommée) ; et l'exemption « périmètre levé » (`_perimeter_lifted_for`)
exempte toute ouverture des flux de l'attaquant vers la VM dans l'opération, alors qu'elle pourrait
n'exempter que les flux que les règles de périmètre retirées fermaient.

**Après la relecture.** La garde de la recherche sur tous les NSG a sa séquence
(`test_the_search_on_every_nsg_keeps_a_turned_rule_aimed_at_the_vm_that_took_the_address`, rouge sur
`main`) et son mutant M1906 ; la séquence de la CI de la PR #342, rejouée tirage par tirage, est figée
(`test_the_sequence_of_pr_342_reasserts_without_opening_the_vm_at_the_old_address` : rouge sur `main`,
« I5: the reassertion opened flows of …/rg-app2/…/api » ; la seule qui attrape M1898 hors des siennes) ;
l'aperçu du reset demande la garde (`test_the_reset_preview_says_what_it_keeps`).

**Mesures d'I4B.** `pytest` complet : 4 143 réussis, 7 sautés, 1 `xfail` (L2, du lot L2Q) ; `ruff`
propre. Invariants : 500 séquences sur les graines 1, 42, 101, 322, 8675 et 31337, puis 2 000 sur 42,
322 et 8675, verts (101 à 500 tombait sur le trou de l'opérateur avant sa reprise). Mutants
M1890–M1905 : 16/16 par leurs séquences figées, à chaque tour (60 séquences, deux tours). Par la
machine seule, une graine au hasard à 500 : M1900 (les lecteurs aveugles au second nom de
l'isolation) ; M1890 (la garde qui laisse partir une allow) sur 42 et 8675 à 500 ; M1898
(l'isolation réécrite par-dessus) ni sur 322 ni sur 42 à 2 000 — ses séquences figées seulement.
Harnais avant/après (60 séquences, deux tours, `--jobs 4`) sur les 150 mutants des modules touchés
(déblocage, vérification du blocage, blocage, reset, levée, isolation, règles retournées,
réaffirmation) : 134 attrapés à chaque tour sur `main` 897cd21, 147/166 après (les seize nouveaux
compris). Deux perdus à la première mesure, rendus : M1345 (le tag d'une carte nue ignoré) et M1761
(le balayage du déblocage aveugle au second nom) — la recherche sur tous les NSG
(`_unplaced_blocks`) faisait le même travail par un autre chemin ; chacun a maintenant une séquence
où rien ne le remplace (la liste des NSG refusée ; la carte a un NSG à elle). M03 et M761, attrapés
avant et à moitié après à 60, remesurés à 500 : 2/2 des deux côtés ; M830 et M21 mieux après.

**L2Q (30/10, #331) : un changement de quarantaine qui revient, lu « déjà dit ».** Le défaut figé
par I5Q (graine 101 à 500, 14 étapes), présent avant RB1. **Cause, établie** (la relecture d'I5Q,
confirmée pas à pas) : la configuration est lisible à chaque étape. Étape 9, le NSG de quarantaine
est vidé, une carte dit le changement A et `quarantine_alerts.json` reçoit A ; étape 11, un accès
forensique ajouté change le diff (B) : la carte A est fermée, la carte B écrite, mais l'écriture de
`quarantine_alerts.json` échoue (la faute tirée, un disque plein) et le fichier garde A ; étape 12,
l'accès retiré, le diff redevient A ; étape 13, la passe ferme la carte B et lit A dans le fichier
comme « dit, ou acquitté » (`reassert_quarantine._report_altered_quarantines`) : aucune carte, le
NSG toujours vidé. « Redit à la passe suivante : plus bruyant, pas muet » ne tenait pas quand le
fichier garde un identifiant périmé et que le diff revient à l'ancien changement. Une
configuration illisible y mène aussi : elle cache l'accès forensique, le diff ne compte plus que nos
deny — celui de A.

**Correctif.** Un changement ne se tait que sur **le dernier mot de l'opérateur** : la dernière
carte de ce NSG (dans le magasin des escalades, dans son ordre) est celle de ce changement, fermée
par un humain. Les fermetures de Glorfindel portent maintenant une note (« a encore changé », ou
entier, vide, disparu), comme celles des contournements et des orphelines ; le fichier reste la
condition rapide, plus jamais la seule. Ce qui ferme mal est donc redit, jamais tu : un fichier
périmé, une carte B qu'on n'a pas pu écrire après la fermeture de A (le magasin refusé), un
acquittement de B quand le fichier a gardé A. Limite : une carte fermée par Glorfindel avant ce
correctif n'a pas de note et se lit comme acquittée — le comportement d'avant, pour celle-là
seulement.

**La machine** tire maintenant la séquence (`quarantine_change_comes_back` : la quarantaine
modifiée et dite, l'accès forensique qui change pendant une passe où **le disque se remplit** —
la faute `(n, "from-full")`, nouvelle : la n-ième écriture de l'état local et les suivantes
refusées, ce qui est écrit avant tient —, puis l'accès remis comme avant ou la configuration
illisible). Un disque plein pour toute la passe ne suffisait pas : la carte A ne se fermait pas,
rien ne bougeait. Aucune règle retirée ni restreinte, aucun oracle touché. **Séquences figées** :
celle de la graine 101 (plus `xfail`), et celle de la nouvelle règle, accès retiré et
configuration illisible.

**Mesures de L2Q.** `pytest` complet : 4 130 réussis, 7 sautés, 7 `xfail` ; `ruff` propre. Sur le
code de `main` (897cd21), échouent : la séquence de 101, les deux séquences de la nouvelle règle et
quatre tests de `tests/unit/test_reassert.py`. Invariants sur le correctif, avec la machine de
`main` : 500 séquences sur 101, 202, 322, 42 et 777, et 2 000 sur 322, verts ; avec la nouvelle
règle : 500 sur 101, 202, 322, 42, 777 et 1, puis 2 000 sur 101 et 322, verts. Mutants M1860–M1866
(le fichier seul, la note retirée, le changement ou le NSG de la dernière carte ignorés, la
première carte lue au lieu de la dernière, une fermeture de Glorfindel lue comme un acquittement) :
7/7 par leurs tests à chaque tour. Par la machine seule, M1860 (le fichier seul) : pas vu à 60
séquences (six graines), ni à 500 sans la nouvelle règle (graines 101, 1, 42, 777, 2718, 8675) ;
avec elle, à 500 sur les graines 1, 101 et 42. M836 réaligné sur la ligne réécrite. Harnais
avant/après (60 séquences, deux tours, `--jobs 4`) sur les 56 mutants de la réaffirmation, de ses
cartes, de la quarantaine et de `reassert_quarantine` : 50/56 attrapés à chaque tour avant (897cd21),
51/56 après, plus les sept nouveaux. Aucun perdu : M13 (2/2 avant, 0/2 après par la machine seule,
attrapé par ses séquences figées) remesuré sur quatre tours, 1/4 des deux côtés, et 2/2 des deux côtés
à 500 ; M09, M14 et M27, bruit à 60 (sur quatre tours : M09 4/4 puis 2/4, M14 3/4 puis 0/4, M27 3/4
puis 4/4), M09 et M14 2/2 des deux côtés à 500 ; M864 survit des deux côtés (déjà vrai avant). Dix
graines à 60 séquences, vertes sur `main` comme sur la branche. **Hors du lot** : à 2 000 séquences,
la graine 101 tombe sur `main` (897cd21) sur I5 et I4 (« an operation on …/rg-edge/…/api opened
flows of …/rg-app1/…/api », `address_reused_under_a_turned_rule` puis
`block_turned_then_reasserted`) — un blocage, une règle retournée, une adresse reprise : le terrain
d'I4B (#333), sans rapport avec la quarantaine.

**I11 sous charge (29/10).** Le délai d'un tour (20 s) n'a pas été dépassé : 26 runs de la
machine à 500 séquences en même temps sur 16 cœurs (312 à 647 s chacun, contre une centaine
seul), puis deux harnais à `--jobs 4` en même temps. Rien n'a été relâché : aucune variable
ajoutée, la sévérité de la CI et de la nuit inchangée.

Le plus grave : après une levée qui échoue en partie, une seconde levée lisait les champs de
rétro-compatibilité de l'état comme un ancien format, et supprimait les deny du NSG de
quarantaine **partagé**. Toutes les VMs en quarantaine du même groupe étaient rouvertes. La
machine ne l'a trouvé qu'à 5 000 séquences.

## Cadence

```mermaid
flowchart LR
    push["chaque push"] --> ci["ruff, tests unitaires<br/>py3.11, py3.12, macOS<br/>invariants 500 + rejeu"]
    nuit["chaque nuit"] --> inv["invariants 10 000<br/>Azure et AWS<br/>Linux et macOS"]
    inv -. "séquences en échec<br/>gardées dans la base" .-> ci
    jour["chaque jour"] --> can["canary azurerm<br/>sur Azure"]
    lundi["chaque lundi"] --> mut["mutation, 1 000 séquences<br/>rouge sous 14 attrapés"]
    classDef data fill:#e9edf3,stroke:#8a96a8,color:#18212b
    classDef blue fill:#2f6fd6,stroke:#1d4a9a,color:#ffffff
    class push,nuit,jour,lundi data
    class ci,inv,can,mut blue
```

Une séquence trouvée la nuit est rejouée en premier à chaque push jusqu'à sa correction, puis
écrite dans `tests/unit/test_invariant_regressions.py` (Azure) ou
`tests/unit/test_invariant_regressions_aws.py` (AWS).

## Ce qui n'est pas couvert

- **Deux hôtes** : les verrous sont par hôte. Un autre hôte qui écrit la carte juste après
  Glorfindel est modélisé (A0) ; deux Glorfindel complets sur deux machines ne le sont pas. Deux
  états séparés le sont à la main, sur une seule séquence (I8S, figée ; le déblocage, ISU) : la
  machine n'a qu'un répertoire d'état.
- **VM supprimée et état perdu** : les règles qu'une isolation par règles a laissées sur un
  NSG partagé se retrouvent par l'empreinte de leur nom et sont retirées quand elles coupent une
  VM vivante en `non_disruptive` ou plus (A3) ; la VM reste coupée jusqu'au passage suivant de la
  watch (une minute), ou, en `human_only`, jusqu'à ce qu'un humain agisse. Tant qu'un état de la
  VM (isolation, blocage) nomme encore la carte, sa levée les cherche sur tous les NSG (I7S),
  sous leurs seuls noms actuels à empreinte (ni ceux d'avant L24 ni ceux suffixés par la VM : I2) ;
  un NSG que l'identité ne lit plus manque à cette liste sans erreur (hypothèse I1S). Une liste des cartes
  partielle (droits de lecture), des VNets qui se recouvrent et une carte recréée sous une VM
  vivante ne sont pas dans la machine : des tests unitaires couvrent les gardes
  (`test_orphan_sweep.py`). La garde « liste partielle » ne lit que les NSG attachés aux cartes :
  des VNets qui se recouvrent derrière un NSG de subnet, une carte de l'autre VNet absente de la
  liste, ne sont pas détectés (une règle peut alors être prise pour orpheline).
- **Couches au-dessus du NSG** : règles d'administration d'Azure Virtual Network Manager,
  routes, pare-feu. Elles peuvent contourner une isolation et ne sont pas encore lues.
- **Hypothèses du faux Azure** non mesurées : le code d'erreur d'un NSG d'une autre région,
  le refus de supprimer un NSG attaché, Run Command shell refusé sous Windows, et (I1S) une
  liste des NSG de l'abonnement qui omet sans erreur un NSG que l'identité ne peut plus lire,
  un `get` de ce NSG refusé (403) ; (ISU) l'association d'un NSG supprimé à une carte refusée
  (`InvalidResourceReference`, 400) plutôt qu'acceptée.
- **L'exemption d'une carte nue (I8F)** : elle vaut si le test a perdu l'état après la dernière
  fois qu'il a vu un état tenir la carte en quarantaine *pendant qu'elle était nue*. Un état qui
  l'a tenue après la perte, mais pas nue, puis que le code abandonne, laisse l'exemption à une
  carte que quelqu'un détache ensuite. Aucun mutant naturel ne l'exploite ; le journal ne dit
  pas mieux sans lire l'état comme le code l'a laissé (A0). Pour I3 depuis I3F, une carte nue que le test a vue tenue
  en quarantaine **sans original** par un état, depuis la dernière perte de cet état, ne gagne plus
  l'exemption (`_held_unknown`) : cela lit l'absence d'original dans l'état, mais ne rend l'oracle
  que plus strict — un code qui perd un original connu n'y gagne rien, un code qui en écrit un faux
  est jugé comme avant.
- **Le monde simulé AWS** (MC1) : rien n'y est mesuré. Ses seize hypothèses attendent le banc AWS
  (MC2), et la cohérence à terme des lectures d'EC2 n'est pas modélisée ([`monde-aws.md`](monde-aws.md)).
