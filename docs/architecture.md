# Architecture d'Eregion

Ce document montre comment les pièces s'emboîtent : la boucle rouge/bleu, les processus et
l'état qu'ils partagent, le graphe de décision, les gardes qui encadrent le LLM, la vie
d'une isolation et la réaffirmation ; puis la cible de la 0.3 (composants, vocabulaire commun,
les trois zones, l'arborescence). Les schémas sont en Mermaid (rendus par GitHub), avec un code couleur
commun : rouge = attaque (Annatar), bleu = Glorfindel, ambre = garde ou vérification, vert = humain ou succès,
violet = Azure, rose = escalade ou échec, gris = données.
Pour **comment on prouve** que tout cela tient, voir [`design/preuves.md`](design/preuves.md) ;
pour l'isolation compatible avec l'infrastructure as code, [`design/module-isolation-iac.md`](design/module-isolation-iac.md).

## La boucle complète

Annatar attaque pour de vrai, Glorfindel détecte dans les journaux, raisonne, agit, vérifie
sur Azure et retient. Un humain approuve ce qui est destructif, et ce que le mode de la VM
ne laisse pas faire seul. Une attaque ratée produit une règle de détection proposée.

```mermaid
flowchart LR
    subgraph Red["Annatar — rouge"]
        A1["Scénario ou campagne<br/>MITRE ATT#amp;CK"] --> A2["Attaque réelle<br/>par Run Command"]
    end
    subgraph Az["Azure"]
        VM[("VM cible")] --> LAW[("Log Analytics<br/>Perf, Syslog, StorageBlobLogs")]
    end
    subgraph Blue["Glorfindel — bleu"]
        RP["RulePoller<br/>une requête par règle"] --> INV["investigate<br/>requêtes ciblées"]
        INV --> DEC["decide<br/>LLM + mémoire RAG + exemples"]
        DEC --> G{"gardes<br/>déterministes"}
        G -->|autorisé| EX["execute_action"]
        EX --> VER["verify_action<br/>relu sur Azure"]
        VER --> ST["store_cycle<br/>ChromaDB + journal"]
        G -->|retenu| ESC["escalade"]
    end
    H["Humain<br/>console, Discord, CLI"]
    A2 --> VM
    LAW --> RP
    EX -->|"quarantaine, deny, snapshot"| VM
    ESC --> H
    H -->|"approuve"| EX
    A2 -. "detection_missed" .-> PR["propose_detection_rule<br/>autoring groundé"]
    PR --> H
    H -->|"approve-rule"| RULES[("detection_rules.yaml")]
    RULES --> RP
    classDef red fill:#d64545,stroke:#9e2a2a,color:#ffffff
    classDef azure fill:#7b5cd6,stroke:#4f3a99,color:#ffffff
    classDef blue fill:#2f6fd6,stroke:#1d4a9a,color:#ffffff
    classDef guard fill:#f2b33d,stroke:#b07a12,color:#2b1d00
    classDef warn fill:#fbe3e3,stroke:#d64545,color:#7a1f1f
    classDef human fill:#2e9e6a,stroke:#1d6b47,color:#ffffff
    classDef data fill:#e9edf3,stroke:#8a96a8,color:#18212b
    class A1,A2 red
    class VM,LAW azure
    class RP,INV,DEC,EX,ST,PR blue
    class G,VER guard
    class ESC warn
    class H human
    class RULES data
    style Red fill:#fdeeee,stroke:#d64545,color:#7a1f1f
    style Az fill:#f1edfc,stroke:#7b5cd6,color:#4f3a99
    style Blue fill:#eaf1fd,stroke:#2f6fd6,color:#1d4a9a
```

Deux asymétries voulues : la **réaction** est raisonnée par le LLM (aucune table TTP → action),
la **détection** est faite de règles explicites exécutées par un poller déterministe — même
quand c'est le LLM qui les a écrites, elles restent des propositions qu'un humain ratifie.

## Processus et état partagé

Le watch, la console et la CLI sont trois processus distincts sur l'hôte de l'opérateur. Ils
partagent l'état local et ne touchent une VM qu'un à la fois.

```mermaid
flowchart TB
    subgraph Host["Hôte de l'opérateur"]
        W["watch — conteneur<br/>RulePoller, découverte,<br/>préparation, réaffirmation"]
        WR["Console — conteneur<br/>127.0.0.1:7007, jeton optionnel"]
        CLI["CLI glorfindel"]
        S[("~/.glorfindel<br/>isolation/ et blocks/ par VM<br/>escalations.jsonl, readiness.json<br/>locks/")]
    end
    W <--> S
    WR <--> S
    CLI <--> S
    W & WR & CLI -->|"un écrivain par VM<br/>verrou de fil + flock"| AZ["Azure<br/>NSG, cartes réseau, Compute, Backup"]
    W -->|"KQL"| LAW[("Log Analytics")]
    W -->|"LiteLLM"| LLM["LLM<br/>Claude par défaut"]
    classDef blue fill:#2f6fd6,stroke:#1d4a9a,color:#ffffff
    classDef human fill:#2e9e6a,stroke:#1d6b47,color:#ffffff
    classDef data fill:#e9edf3,stroke:#8a96a8,color:#18212b
    classDef azure fill:#7b5cd6,stroke:#4f3a99,color:#ffffff
    class W blue
    class WR,CLI human
    class S,LLM data
    class AZ,LAW azure
    style Host fill:#f4f7fb,stroke:#aab4c3,color:#18212b
```

- **Un fichier d'état par VM**, nommé `<nom>--<empreinte de l'ID>.json` en minuscules : deux VMs
  homonymes dans deux groupes ne se mélangent pas, et la casse de l'ID ne crée pas de doublon.
- **Un écrivain par VM** : isoler, lever, bloquer, débloquer, `reset --from-azure` et la
  réaffirmation prennent le verrou de la VM (fil + `flock`, réentrant). Le `flock` est ce qui
  sépare les processus ; il est testé à part, sur de vrais processus (`tests/unit/test_locks.py`).

## Le graphe de décision

```mermaid
flowchart LR
    LC["load_context"] -->|"attack_started"| PD["poll_detection"]
    LC -->|"détection"| INV["investigate"]
    LC -->|"detection_missed"| PDR["propose_detection_rule"]
    PD --> INV
    INV --> DEC["decide"]
    DEC -->|"action autonome<br/>autorisée"| EX["execute_action"]
    EX --> VA["verify_action"]
    VA -->|"vérifiée"| SC["store_cycle"]
    VA -->|"non vérifiée,<br/>échec"| ESC["escalate_to_human"]
    DEC -->|"retenue"| ESC
    ESC --> SC
    PDR --> SC
    classDef blue fill:#2f6fd6,stroke:#1d4a9a,color:#ffffff
    classDef guard fill:#f2b33d,stroke:#b07a12,color:#2b1d00
    classDef warn fill:#fbe3e3,stroke:#d64545,color:#7a1f1f
    class LC,PD,INV,DEC,EX,SC,PDR blue
    class VA guard
    class ESC warn
```

Toute exception d'un cycle finit en escalade (`action_failed`, `cycle_failed`), jamais en
ligne de console : une menace détectée n'est pas perdue parce qu'un appel a échoué. Plus
largement, une dépendance qui tombe (modèle, API du cloud, télémétrie, configuration) fait
échouer Glorfindel **fermé** : rien de disruptif ne part seul (G2,
[`glorfindel.md`](glorfindel.md), « Pannes des dépendances »).

## Les gardes qui encadrent le LLM

Le LLM propose ; une suite de gardes déterministes décide si l'action part seule. Une action
destructive n'est jamais autonome, quel que soit le mode. Chaque garde qui retient une action
autonome donne son propre type d'escalade, que la console affiche. Une VM retenue parce
qu'elle n'est pas prête reçoit en plus, du contrôle de préparation, une carte `readiness_hold`.

```mermaid
flowchart LR
    LLM["Réponse du LLM<br/>tool call"] --> P{"décision<br/>lisible ?"}
    P -->|non| E0["escalade forcée"]
    P -->|oui| K{"quelle<br/>action ?"}
    K -->|"destructive<br/>restore, delete…"| E7["destructive_action<br/>jamais autonome"]
    K -->|"inconnue"| E1["proposed_action"]
    K -->|"autonome"| X{"implémentée ?"}
    X -->|non| E1
    X -->|oui| C{"confiance<br/>≥ 0,7 ?"}
    C -->|non| E2["low_confidence"]
    C -->|oui| S{"isoler, bloquer :<br/>signal caractérisé ?"}
    S -->|non| E3["uncharacterized_signal"]
    S -->|oui| A{"isoler, bloquer :<br/>attribué à cette VM ?"}
    A -->|non| E4["unattributed_signal"]
    A -->|oui| T{"isoler, bloquer :<br/>télémétrie lue ?"}
    T -->|"requête d'enquête<br/>en échec"| E8["telemetry_gap"]
    T -->|oui| R{"lever :<br/>après recovery_complete ?"}
    R -->|non| E5["release_hold"]
    R -->|oui| M{"mode effectif<br/>de la VM"}
    M -->|"human_only, ou VM<br/>pas encore prête"| E6["mode_hold"]
    M -->|"non_disruptive"| D{"isoler, bloquer :<br/>les tirages s'accordent ?"}
    D -->|non| E9["unstable_decision"]
    D -->|oui| GO(("exécuter"))
    classDef blue fill:#2f6fd6,stroke:#1d4a9a,color:#ffffff
    classDef guard fill:#f2b33d,stroke:#b07a12,color:#2b1d00
    classDef warn fill:#fbe3e3,stroke:#d64545,color:#7a1f1f
    classDef go fill:#2e9e6a,stroke:#1d6b47,color:#ffffff
    class LLM blue
    class P,K,X,C,S,A,T,R,M,D guard
    class E0,E1,E2,E3,E4,E5,E6,E7,E8,E9 warn
    class GO go
```

Le mode configuré n'est qu'une intention : une VM ne devient autonome qu'une fois contrôlée
**prête** (droits, préséance des règles, coupure des sessions possible), ou après que ses
réserves ont été montrées et acceptées.

## La vie d'une isolation

```mermaid
stateDiagram-v2
    state "Libre" as Free
    state "En quarantaine" as Q
    state "Isolée par règles" as Rules
    state "Partielle" as Partial
    state "Levée en cours" as Releasing
    state "Levée partielle" as RelPartial

    [*] --> Free
    Free --> Q: isolate_vm
    Free --> Rules: isolate_vm, échange refusé
    Free --> Partial: isolate_vm, une carte échoue
    Q --> Releasing: release_isolation
    Rules --> Releasing: release_isolation
    Partial --> Releasing: release_isolation
    Releasing --> Free: released, relu sur Azure
    Releasing --> RelPartial: release_partial
    RelPartial --> Releasing: l'opérateur corrige
    Q --> Q: réaffirmation
    Rules --> Rules: réaffirmation
    classDef human fill:#2e9e6a,stroke:#1d6b47,color:#ffffff
    classDef blue fill:#2f6fd6,stroke:#1d4a9a,color:#ffffff
    classDef guard fill:#f2b33d,stroke:#b07a12,color:#2b1d00
    classDef warn fill:#fbe3e3,stroke:#d64545,color:#7a1f1f
    class Free human
    class Q,Rules blue
    class Releasing guard
    class Partial,RelPartial warn
```

- **Partielle** : une carte a échoué ; ce qui est posé reste posé et enregistré.
  **Levée en cours** : l'intention est notée (`releasing_at`) avant de toucher Azure.
  **Levée partielle** : quelque chose n'a pas pu être défait ou vérifié ; l'état est gardé.
- **Quarantaine** : chaque carte porte, le temps de l'isolation, le NSG de quarantaine de
  Glorfindel à la place du sien. Le NSG du client reste intact et revient à la levée.
  L'original est noté dans l'état **et** en tag sur le NSG de quarantaine, pour qu'une levée
  sans état sache quoi remettre ; s'il est inconnu, la carte reste en quarantaine et la levée
  le dit. Le NSG de quarantaine refuse aussi le DNS et l'IMDS d'Azure.
- **Par règles** (repli quand une politique ou les droits refusent l'échange) : un deny entrant
  et sortant qui vise toujours les IP de la carte, sur le NSG de la carte, ou sur celui du
  subnet si une allow du client passe avant. Ce repli ne peut pas refuser le DNS et l'IMDS à
  une seule VM : il le déclare (`platform_open`).
- **La levée balaie toujours** : elle défait ce que l'état connaît, puis relit chaque carte et
  retire ce que l'état ignore (crash, réponse perdue, ancienne adresse d'une carte).

## La réaffirmation

Toutes les 60 secondes, le watch relit sur Azure chaque isolation et chaque blocage
enregistrés, sous le verrou de la VM.

```mermaid
sequenceDiagram
    participant W as watch, toutes les 60 s
    participant L as verrou de la VM
    participant S as état local
    participant A as Azure
    W->>L: prendre, 30 s au plus
    W->>S: relire l'état
    alt levée en cours, partielle ou en échec
        W-->>W: rien, c'est à l'opération en cours
    else
        W->>A: vérifier, règles lues par leur contenu
        alt en place
            W->>S: verified_at
        else disparue
            alt human_only
                W-->>W: une alerte par disparition
            else première fois
                W->>A: réappliquer une fois
                W-->>W: alerte « reposée »
            else de nouveau
                W-->>W: alerte seule, sans se battre
            end
        end
    end
    W->>L: rendre
```

Une isolation retirée par un `terraform apply` ou à la main est reposée une fois, puis
Glorfindel alerte sans insister : il ne se bat pas contre un pipeline ou une décision humaine.

## Vers la 0.3 : composants, vocabulaire et zones

Cette section décrit la cible de la huitième passe (13/10, voir [`ROADMAP.md`](../ROADMAP.md),
« Vers la 1.0 ») ; le code l'adopte lot par lot — l'inscription et la zone avec O0, l'expérience
avec E1, Orodruin avec O1, Gothmog avec G0. Les schémas ci-dessus décrivent le code d'aujourd'hui.

### Les composants

Glorfindel est le produit ; le reste est l'atelier qui l'éprouve.

| Composant | Rôle | Où | État |
|---|---|---|---|
| Glorfindel | détecter, enquêter, répondre ; son IA est l'IA sous test | `glorfindel/` | existe |
| Annatar | attaques : ses scénarios aujourd'hui, puis des adaptateurs vers des bibliothèques publiques (R1 Atomic Red Team, R2 Stratus Red Team) | `annatar/`, interface d'injecteur dans `annatar/executors/` | existe, évolue |
| Gothmog | pannes déclarées en code, exécutées par un moteur public (Chaos Studio d'abord) | `gothmog/` ; l'expérience dans `infra/terraform/chaos.tf` | G0 ✅ (19/10, arrêt de VM mesuré sur le banc) |
| Orodruin | hôte d'exécution jetable des injecteurs : identité limitée, sortie réseau limitée, contrat vérifié au démarrage, arrêt d'urgence | `infra/orodruin/`, état Terraform séparé | O1 |
| Celebrimbor | construit et inscrit les cibles du banc | `infra/terraform/` | existe |
| Inscription et périmètre | un seul garde-fou de cible pour tout injecteur, présent ou futur | `eregion_core/inscription.py` | existe (O0) |
| Schéma d'expérience | une même description pour une technique et pour une panne | `schemas/`, `technique_catalog.yaml` | E1 |
| IA d'analyse | explique, trie, rapporte ; chaque affirmation cite son run ; n'écrit pas de règle, n'agit pas ; chaque proposition attend un humain | collection ChromaDB distincte, autre modèle, refusés s'ils sont ceux de Glorfindel (`analysis/separation.py`) ; tri `analysis/triage.py` | IA0, IA1 |

### Le vocabulaire commun

Le framework ne parle qu'avec ces mots ; la correspondance par cloud passe par l'interface de
fournisseur (MC0, livrée avec A1 le 26/10, `glorfindel/providers/interface.py`). Chaque fournisseur
a un adaptateur, seul à importer son SDK, et y déclare ses capacités dans ces mots : le contrôle
réseau en `network_quarantine` (isoler par un groupe de quarantaine) et `network_rules` (isoler par
règles, bloquer), `session_drain` (couper les sessions déjà ouvertes), `restore_point`, chacune avec
les droits qu'elle demande. La préparation de Glorfindel lit ces droits. Azure est le seul
adaptateur qui tourne (`glorfindel/providers/azure/`). Un second, AWS (`glorfindel/providers/aws/`,
MC1, 26/10), est écrit contre un monde simulé et ne tourne sur aucun compte avant MC2 : il déclare
`network_quarantine` (un groupe de sécurité de quarantaine par VPC) et `network_rules` pour les seuls
blocages (ACL réseau du sous-réseau) — ni isolation par règles, ni `session_drain`, ni
`restore_point`. Ce que les mots veulent dire sur AWS, et les hypothèses à mesurer :
[`design/monde-aws.md`](design/monde-aws.md).

| Concept | Sens |
|---|---|
| Cible | ressource qu'on a le droit d'éprouver |
| Inscription | marque posée à la construction (tags `eregion-target=<banc>` et `eregion-zone` sur la cible et son groupe) ; sans elle, aucun injecteur n'agit ; elle porte la zone de la cible |
| Zone | `bench`, `twin` ou `production` — ce qu'une expérience a le droit d'y faire |
| Contrôle réseau | ce qui autorise ou refuse le trafic : isoler, bloquer, lever |
| Télémétrie | où arrivent les logs et les métriques |
| Requête de détection | règle dans le langage de la télémétrie |
| Point de restauration | sauvegarde ou instantané pour revenir à un état connu |
| Moteur d'injection | outil public qui exécute une technique ou une panne, par identifiant |
| Expérience | une technique (`kind: technique`) ou une panne (`kind: fault`), décrite par le même schéma |
| Identité d'exécution | l'identité d'Orodruin, limitée aux cibles inscrites, révocable |
| Mode ombre | Glorfindel décide sur le vrai trafic sans agir ; on mesure ses décisions (`human_only` + verdicts) |
| VM sentinelle | une VM vide dans le réseau de production, inscrite, pour éprouver la chaîne complète |
| Jumeau | réplique de la topologie du client, depuis son code ou la découverte, avec son rapport d'écart |
| Banc de référence | nos topologies types (Celebrimbor), sur lesquelles nous publions nos preuves |
| Glorfindel de base | le produit livré par versions : surface surveillée, règles de base, actions, garde-fous |
| Glorfindel adapté | la couche du client : ses règles, sa mémoire, sa retenue, ses marches ; une mise à jour ne l'écrase jamais |

### Les trois zones

Règle de production : **jamais de panne ni d'action destructive sur une charge réelle.**

| Zone | Ce qui y tourne | Refusé |
|---|---|---|
| `bench` | techniques, destructif, pannes, reprise | — |
| `twin` | idem, avec le rapport d'écart au client | — |
| `production` | mode ombre ; techniques `destructive: false` sur VM inscrites ; chaîne complète sur la VM sentinelle | toute panne, toute expérience destructive |

Seule la zone `bench` sert en 0.3 ; les deux autres sont codées et testées (O0, `eregion_core/inscription.py`) : tout ce qui est inconnu est refusé — pas de tag, identifiant de banc vide, valeur dans une autre casse (Azure garde les valeurs telles qu'écrites, compare les noms sans casse), zone absente ou hors des trois, groupe et cible en désaccord, caractère destructif non déclaré en production. Pendant la migration, l'ancien tag `annatar-test=true` (posé seulement sur Celebrimbor) vaut zone `bench`. La feuille de
route 1.0 envisage, en production, des pannes des seules dépendances de Glorfindel (modèle,
télémétrie, configuration), jamais des charges du client : O0 les refuse comme toute panne ; une
exception, si elle vient, viendra par un lot explicite.

### Le cycle d'une expérience

Une même boucle pour une technique et pour une panne.

| Étape | Eregion aujourd'hui | Bibliothèques d'attaque | Moteurs de chaos |
|---|---|---|---|
| Préparer | `eregion_core/inscription.py` (périmètre, inscription, zone), préflight ; `gothmog preflight` (cibles relues dans l'expérience) | Stratus `warmup` | cible inscrite auprès du moteur (`chaos.tf`) |
| État normal | `glorfindel/posture.py`, `glorfindel/readiness.py` ; `gothmog/probes.py` (avant, pendant, après) | — | Chaos Toolkit `steady-state-hypothesis` |
| Injecter | `annatar/executors/` ; `gothmog/engines/chaos_studio.py` | Stratus `detonate`, test Atomic, capacité Caldera | expérience ou objet de panne |
| Observer | `annatar/collectors/`, signaux (`attack_started` ; `fault_started` dans `runs/gothmog/`, hors de ce que la watch lit) | — | sondes pendant l'expérience |
| Revenir | `annatar clean`, `glorfindel release` ; retour d'une panne vérifié par sonde, repli `start_vm` | Stratus `revert`, `cleanup` | Chaos Toolkit `rollbacks` |
| Verdict | `annatar/runner/report.py`, `gothmog report`, la console (Annatar, Gothmog) | — | — |

### L'arborescence visée

```
glorfindel/              le produit (existe)
annatar/                 attaque (existe) ; executors/ devient l'interface d'injecteur (R1)
gothmog/                 pannes (G0) : moteur Chaos Studio, sondes, exécuteur, signaux, rapport
eregion_core/            inscription et périmètre (O0) ; validation des schémas d'expérience et du catalogue (E1) ; existent
schemas/                 scenario.schema.json (existe) + experiment.schema.json + technique_catalog.schema.json (E1, existent)
technique_catalog.yaml   techniques (existe) + pannes (E1)
infra/terraform/         Celebrimbor (existe) ; pose eregion-target (O0), inscrit les cibles Chaos Studio (G0, chaos.tf)
infra/orodruin/          Orodruin, état Terraform séparé (O1, fait) : VM, identité, sortie fermée, canal des fenêtres et canal retour (#159)
infra/canary/            canary azurerm (existe)
CLAUDE_ORODRUIN.md       session Orodruin (O1, O2)
CLAUDE_GOTHMOG.md        session Gothmog (G0 à G4)
```
