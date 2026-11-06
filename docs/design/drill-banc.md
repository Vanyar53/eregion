# Le drill du banc — un exercice chaque semaine, lancé par Orodruin (DRL1)

_Conception — 06/11 (DRL1, #613) — statut : **conception seulement**. Rien n'est codé, armé ni
mesuré. À relire en Opus 5.5 avant tout code ; l'armement reste à Jonathan._

> **Décision de Jonathan (06/11, « Cadence du banc », D1).** Un exercice planifié chaque semaine,
> pour que l'âge de la dernière preuve (moins de 30 jours, un des cinq indicateurs de la 1.0) se
> tienne tout seul :
> - un drill **fixe**, déclaré dans le dépôt et relu ;
> - **non destructif**, sur le **banc seul** (zone `bench`) ;
> - lancé par un **minuteur d'Orodruin**, sous son contrat : Orodruin armé, jamais sans Glorfindel
>   (V1), sous plafond ;
> - son rapport lu par une session « Banc », d'identité en lecture seule (BRO1, #614) ;
> - la règle « une attaque sur le banc reste à Jonathan » change **pour ce drill seul**.
>
> Les deux décisions sœurs : BRO1 (#614), l'identité de la session « Banc » ; VP1 (#615), le verdict
> proposé sur une carte d'exercice attendue.

## En bref

Le drill de la semaine est un **drill livré** (DG-d, `drills/`) qui porte deux blocs de plus : quand
il tourne (`schedule`) et ce que la watch doit voir (`expect`). Une seule technique pour commencer :
**T1136.001**, par l'atomic épinglé d'Atomic Red Team, sur gondolin.

Un minuteur systemd d'Orodruin le lance. Il ne lit rien que trois choses :
- l'image des injecteurs, vérifiée à son envoi (CI3) ;
- un fichier d'armement, écrit par Jonathan ;
- l'horloge.

Il fabrique lui-même la demande, et la donne au même juge que les demandes de Dagorlad
(`eregion_core/exercise_runner.py`, DG-b). Toutes les gardes d'aujourd'hui valent donc, et le drill
en ajoute :
- son empreinte épinglée à l'armement ;
- la zone `bench` seule ;
- une fois par semaine au plus ;
- jamais rejoué après un arrêt d'urgence.

**Qui dit quoi :**
- **H0** juge chaque occurrence et alerte, y compris quand rien n'est arrivé : c'est l'observateur qui
  tient l'alarme d'absence, jamais l'acteur.
- **La session « Banc »** relit le workspace en témoin indépendant.
- **VP1** lit ce que le drill attend, pour proposer un verdict que Jonathan confirme.

```
Jonathan ── arme (une fois, puis à chaque changement du drill) ──▶ Orodruin
                                                                     │ minuteur, mardi 18:00 UTC
                                                                     ▼
   image vérifiée (drills/banc-hebdo.yaml) + armement + horloge ─▶ le drill
        contrat armé ? V1 ? empreinte ? zone bench ? une fois par semaine ? pas d'arrêt d'urgence ?
                                                                     │ demande → exercise_runner
                                                                     ▼
                                       Run Command (atomic T1136.001) sur gondolin, journalisé avant
                                                                     │
   gondolin ── Syslog ──▶ workspace ──▶ H0 : RulePoller → carte d'exercice → VP1 propose → Jonathan
                              │                     ▲
                              │   canal : fenêtres, rapports, statuts, orodruin/drill.json
                              ▼
                   session « Banc » (BRO1, lecture seule) : la règle rejouée, l'indice brut, le Heartbeat
```

---

## 1. Ce que le drill joue, et où il se déclare

### 1.1 Le choix des techniques

Une technique entre dans le drill de la semaine si elle tient **toutes** ces conditions, relues en CI
et à chaque occurrence sur Orodruin :

1. au catalogue (`technique_catalog.yaml`), `status: implemented` : script ou atomic, règle et
   validation en réel existent ;
2. `destructive: false`, dans le catalogue (le mot du catalogue, `catalog_destructive`, SEC5) ;
3. d'une **bibliothèque publique**, version épinglée (`engine: atomic`, plus tard `stratus`). Jamais
   un script maison, la règle de BL1b, décidée par Jonathan le 02/11 et sans exception ;
4. **validée en réel depuis Orodruin**, et sa détection prouvée (`docs/historique.md`, rapports de
   banc) ;
5. une règle de la base livrée, `enabled`, du même `ttp`, que le drill nomme (`expect.rule`).

| Technique | Moteur | Destructive | Validée depuis Orodruin | Verdict |
|---|---|---|---|---|
| **T1136.001** (création de compte) | atomic épinglé | non | oui : le 20/10, détection 117,5 s ; BL1 le 31/10, détection 144 s | **retenue** |
| T1059.004 (shell depuis un chemin ouvert) | atomic épinglé | non | non : la règle repose sur les hypothèses d'auditd (AUD1, A1–A13), pas mesurées | plus tard, après la mesure d'AUD1 |
| T1548.003, T1110.001, T1041 | script maison | non | oui, mais par un script maison | écartées : bibliothèques publiques seulement |
| T1486, T1070.002, T1053.003 | — | **oui** | — | écartées : le drill est non destructif |
| Stratus, plan de contrôle (R2a) | stratus | non | non (ID1, #281) | plus tard |
| La panne `vm-shutdown` | chaos-studio | non | oui (G0, BL1) | écartée en v1 : c'est une panne, pas une technique (question 3) |

**Le drill v1 : un fil, T1136.001, sur la VM inscrite `bench` que Jonathan nomme à l'armement
(gondolin).** C'est la technique qui a déjà fait la dernière preuve du 31/10. La décision que la
watch en a prise (un instantané, une escalade, 35 % de confiance) suffit à la preuve : pour la matrice
de C1, une preuve est une technique détectée **dont la décision est rattachée**, pas une technique
contenue. Le drill garde la dernière preuve sous 30 jours ; il ne mesure ni le temps pour contenir ni
la part contenue seule, qui se mesurent sur le trafic réel (BL1b).

### 1.2 Où il se déclare : un drill livré, avec deux blocs de plus

Le drill vit dans **`drills/banc-hebdo.yaml`** : un drill livré de DG-d (`eregion_core/drill.py`),
relu en PR, remplacé par une mise à jour. Il en garde le format exact : nom, auteur `eregion`,
fils dont la cible est un sélecteur (`{zone: bench}`), jamais un nom de VM ni un identifiant de
ressource. Le lot de code ajoute au lecteur deux blocs, **optionnels**, lus avec la même exactitude
(aucun champ de plus, aucun de travers) :

```yaml
# The weekly bench drill (DRL1, docs/design/drill-banc.md): shipped, reviewed in a PR. Orodruin's
# timer plays it once a week, armed by the operator, who names its targets then.
name: banc-hebdo
author: eregion
description: "The weekly proof on the bench: a public, non-destructive technique already proven from Orodruin."
schedule:                  # this drill may be played by Orodruin's timer
  day: tue                 # mon … sun
  at: "18:00"              # UTC, HH:MM
  max_injections: 6        # its own cap, at most the cap Orodruin declares
  max_run_s: 2400
wires:
  - experiment: T1136.001
    target: {zone: bench}
    expect:                # what the watch should see — read by VP1 and the Banc session, never by Orodruin
      rule: t1136-001-local-account-creation-linux-v1
      within_s: 900        # after the wire's T0
```

**`schedule`** : seulement dans un drill livré. Le lecteur le refuse si une seule de ces conditions
manque :
- chaque fil vise `{zone: bench}` : ni `twin` ni `production`, même pour une technique que la règle de
  production admet ;
- chaque expérience est une technique (jamais une panne en v1), `implemented`, non destructive, d'un
  moteur public ;
- `max_injections` et `max_run_s` restent sous les plafonds absolus (`CEILING_INJECTIONS`,
  `CEILING_RUN_S`) ;
- `day` et `at` se lisent.

`sentinelle` (zone `production`) et `bl1-reponse` (une panne) n'en portent pas, et ne le pourraient
pas.

**`expect`** : dans tout drill, livré ou de l'instance. Il nomme la règle attendue (une règle de la
base livrée, `enabled`, du même `ttp` que l'expérience), et le délai après le T0 du fil. C'est ce que
lisent VP1 (§8) et la session « Banc » (§4.3).
- **Orodruin ne le lit pas.** La demande ne le porte pas : son format ne change pas, « aucun résultat
  attendu », Annatar reste aveugle à Glorfindel.
- **La décision ne le voit jamais**, ni la fenêtre d'exercice : Glorfindel reste aveugle à Annatar.

**E1 et le schéma.** Les fils nomment des entrées du catalogue, validées par
`schemas/technique_catalog.schema.json` (E1). Le drill lui-même n'a pas de schéma JSON : son lecteur
exact (`drill.read`) en tient lieu, le même sur la console, le poste et Orodruin. Le lot ajoute un
test de CI qui relit `drills/banc-hebdo.yaml` contre le catalogue (les cinq conditions de 1.1) et
contre la base de règles (la règle d'`expect`). Un drill qui ne les tient plus fait échouer la PR qui
le casse : un changement du catalogue, l'atomic retiré, la règle renommée.

**Changer le drill** : une PR relue. Puis Jonathan le réarme, car son empreinte est épinglée (§2.3).
Un drill changé ne tourne jamais seul.

### 1.3 Ce que le drill ne porte pas

Ni nom de VM, ni identifiant, ni abonnement : le dépôt est public, et un drill livré ne connaît pas
les VM d'une instance. La cible se donne à l'armement, par son nom (`TARGETS=gondolin`). « Jamais
choisie à la place de l'opérateur » (Jonathan, 03/11) : il la choisit une fois, en armant. `all` est
refusé pour un drill armé : une VM inscrite plus tard ne deviendrait pas une cible sans geste.

---

## 2. Le minuteur sur Orodruin

### 2.1 Ce qui est posé

Sur le modèle de l'agent de CD de H0 (H1), le minuteur s'installe **désactivé**, puis Jonathan le
vérifie à blanc et l'active.

| Cible Make (depuis le poste, par la clé d'hôte épinglée) | Fait |
|---|---|
| `make orodruin-drill-check [DRILL=banc-hebdo TARGETS=gondolin]` | à blanc : relit le drill dans l'image d'Orodruin, son empreinte, le contrat, la watch, la cible ; dit ce que ferait la prochaine occurrence et quand. Aucune écriture sur Azure |
| `make orodruin-drill-arm DRILL=banc-hebdo TARGETS=gondolin` | **Jonathan.** Écrit le fichier d'armement, pose les unités systemd, active le minuteur, publie `orodruin/drill.json` |
| `make orodruin-drill-disarm` | désactive le minuteur, retire l'armement, publie « désarmé » |

**Le fichier d'armement** (`~/drill/armed.json`, mode 600, sur le disque de l'hôte, hors de `~/runs`)
dit :
- le nom du drill et son empreinte sha256, lue dans l'image au moment d'armer ;
- les noms des cibles ;
- l'heure de l'armement ;
- le commit de l'image.

Il ne contient rien que le drill ne dise déjà, sauf les noms des cibles : aucun identifiant, aucun
secret. Les conteneurs le montent en lecture seule, et ne peuvent donc pas le réécrire.

**Les unités.**
- `eregion-drill.timer` :
  - `OnCalendar` est tiré du `schedule` du drill au moment d'armer (`Tue *-*-* 18:00:00 UTC`) ;
  - `Persistent=false` : une occurrence manquée n'est **jamais rattrapée** au démarrage suivant. Elle
    est dite manquée (§4), elle ne part pas à une heure où personne ne l'attend ;
  - `AccuracySec=1min`.
- `eregion-drill.service` : un `docker run` durci comme les autres (ORO_HARDEN) :
  - racine en lecture seule, aucune capacité ;
  - `~/runs/{annatar,gothmog,orodruin}` montés comme pour une demande ;
  - l'armement en lecture seule ;
  - une commande fixe, `python -m eregion_core.scheduled_drill run`, sans argument venu d'ailleurs ;
  - `RuntimeMaxSec` borne le tout au-dessus du `max_run_s` du drill.

Le minuteur est posé par SSH, pas par le `custom_data` de Terraform : changer `custom_data`
recréerait la VM.

### 2.2 Orodruin ne tire rien, et n'écoute rien

C'est le cœur du lot. Aujourd'hui, une demande vient de l'opérateur : il la porte par SSH
(« Orodruin ne tire rien et n'écoute rien : la commande vient de l'opérateur »,
[`orodruin-contract.md`](orodruin-contract.md), DG-b). Avec le minuteur, Orodruin agit sans
commande, **mais toujours sans rien tirer ni écouter**. Ce qui décide d'une occurrence :

| Entrée | D'où | Qui peut la changer |
|---|---|---|
| le drill | l'image des injecteurs (`/app/drills/`), vérifiée à `make orodruin-push` : digest, signature, provenance (CI3) | une PR relue, une release, puis le réarmement de Jonathan |
| l'armement | `~/drill/armed.json`, écrit par `make orodruin-drill-arm` | Jonathan (ou root sur Orodruin, §7) |
| l'heure | l'horloge d'Orodruin | — |

Rien ne vient de H0, du canal, de la console ni du réseau. Un H0 compromis, ou qui écrit le canal,
ne peut ni lancer une occurrence, ni en changer le contenu, ni la cible. **Écartés** :
- un ordonnancement sur H0 : H0 commanderait une attaque ;
- un workflow planifié de GitHub : un chemin d'écriture de la CI vers Azure ;
- un `cron` dans le conteneur : un processus de plus qui tourne en continu, et l'armement relu de
  l'intérieur.

### 2.3 Ce qui l'empêche de lancer autre chose que le drill déclaré

Le service ne prend aucun argument. Il relit, dans cet ordre, et refuse au premier manque :

1. **L'armement** se lit, et nomme un drill. Absent : `disarmed`, rien ne part, rien n'est publié de
   plus.
2. **Le drill vient de l'image**, par son seul lecteur, dans la couche livrée seulement
   (`drill.load_file(…, SHIPPED)` sur `/app/drills/<nom>.yaml`, jamais `drill.find`, qui préfère la
   couche de l'instance) : jamais `~/.eregion/console/drills`, jamais un répertoire où Orodruin écrit. Il porte `schedule`,
   et tient les conditions de 1.2.
3. **Son empreinte est celle de l'armement.** Une release qui change `drills/banc-hebdo.yaml` change
   l'empreinte : `drill_changed`, dit, et rien ne part jusqu'au réarmement. Changer ce qui attaque
   seul demande donc la relecture de la PR, **et** un geste de Jonathan.
4. **Le catalogue de l'image** confirme chaque fil : `implemented`, non destructive, moteur public.
   Les deux lisent le même fichier ; le drill relu en CI ne suffit pas, car l'image peut être d'avant.
5. **L'occurrence est la bonne** :
   - l'heure tombe dans les 30 minutes qui suivent l'heure du `schedule` (`off_schedule`) : un
     déclenchement à la main du service, ou un `OnCalendar` réécrit, est refusé ;
   - la dernière occurrence jouée, au registre (`runs/orodruin/drills/played.jsonl`, écrit sur le
     disque **avant** le jugement, comme le registre des demandes), date d'au moins 6 jours
     (`too_soon`) ;
   - un registre illisible ne laisse rien jouer.
6. **Les cibles** : chaque nom de l'armement est une VM inscrite lue maintenant par l'identité
   d'Orodruin, une seule de ce nom, en zone **`bench`** (`not_placed`, `not_bench`). Plus strict que la
   règle de production, qui admettrait T1136.001 en `production`.
7. Puis **la demande** : le drill la fabrique (`exercise_request.new`), avec les identifiants des VM
   relues, et la donne à `exercise_runner`. C'est le même chemin que DG-b, sans second chemin.

Le lot de code écrit un mutant pour chacune de ces gardes (§9).

---

## 3. Les garde-fous, et quand quelque chose manque

### 3.1 L'ordre d'une occurrence

Rien n'atteint le cloud avant les trois premières gardes. Démarrer une VM est une écriture : elle
passe après le contrat, V1, et le journal.

```
0  armement, drill, empreinte, catalogue, occurrence (§2.3, 1–5)   ← rien d'appelé encore
1  verrou « un run à la fois » (flock) : pris, sinon busy           ← jamais attendu, jamais rattrapé
2  contrat : orodruin.check() armé, sinon passive (ses codes)
3  V1 : battement signé de la watch, frais, du bon périmètre ;
       relu jusqu'à 10 min (un déploiement de H0 en cours), puis refus watch
4  cibles relues, zone bench (§2.3, 6) ; plafond : celui du drill ≤ celui déclaré
5  demande → exercise_runner : il rejuge tout (contrat, V1, inscription, zone, plafond)
6  cible prête : VM arrêtée → démarrée (journalisé avant, droit déjà au contrat),
       puis Heartbeat frais attendu (la sonde de Gothmog), sinon fil sauté not_ready
7  VM tenue par Glorfindel : attendue 20 min (WAIT_ISOLATION_S), puis sautée isolated — jamais levée
8  le fil : annatar wire, journal avant chaque appel, fenêtre d'exercice (son request),
       l'attente de la détection signée (SEC21), le nettoyage de l'atomic
9  statuts publiés : la demande (orodruin/requests/<id>.json, avec le drill) et orodruin/drill.json
```

**Le plafond** tient à trois étages :
- celui du drill (`max_injections`, `max_run_s`) ;
- celui qu'Orodruin déclare (`EREGION_MAX_INJECTIONS`, `EREGION_MAX_RUN_S`), relu par le contrat ;
- le plafond absolu.

Le reste de la demande borne chaque fil. Le chemin atomic demandait 5 appels le 20/10 : 6 laissent
le démarrage de la VM.

**La fenêtre d'exercice** est celle d'aujourd'hui :
- ouverte avant le premier appel, fermée dans un `finally` ;
- bornée (`MAX_DURATION_S`), avec 15 min de grâce ;
- elle porte l'identifiant de la demande, et rien de ce que le drill attend.

**L'arrêt d'urgence.** `make orodruin-kill` révoque, annule, désalloue et ferme les fenêtres. Le
minuteur, lui, reste sur le disque, et reprendrait après un `make orodruin-lock` (les droits
reposés) puis un démarrage. Le kill écrit donc aussi une **pierre tombale** dans le canal
(`orodruin/killed.json`, l'heure). L'opérateur y écrit déjà pour fermer les fenêtres
(`channel_operator`, M-1). Une occurrence la lit avant tout : un kill daté après l'armement →
`killed`, rien ne part. Une pierre tombale illisible refuse aussi. Seul un réarmement de Jonathan
relance. Le kill le dit dans sa sortie : « drill timer armed: refused until re-armed ».

### 3.2 Quand quelque chose manque

| Cas | Ce qui se passe | Qui le dit |
|---|---|---|
| **H0 en panne** (watch morte, VM arrêtée) | V1 refuse avant tout appel au cloud (`watch`), après 10 min de relecture ; statut publié dans le canal | personne sur l'instant : H0 est celui qui alerte. Au retour, H0 tire le statut et le dit ; la session « Banc » ne voit aucun indice. À la troisième semaine sans preuve, la ligne passe `aging`, puis `stale` à 30 jours : c'est l'indicateur lui-même |
| **H0 en déploiement** (CD) à l'heure | battement manquant moins de 90 s : la relecture de 10 min le couvre | rien si ça passe |
| **Le banc éteint** (gondolin désallouée, le cas ordinaire : elle s'éteint à 23:00 UTC) | démarrée par le drill (étape 6), Heartbeat attendu avant la technique ; elle s'éteindra à 23:00 UTC par son extinction quotidienne. Le drill ne l'arrête pas : arrêter n'est pas au contrat d'Orodruin, et ne le sera pas pour ça | le statut dit le démarrage |
| **Le banc détruit**, gondolin renommée ou désinscrite | `not_placed` : refus entier, rien ne part | H0 : alerte |
| **La télémétrie cassée** (agent, DCR, workspace) | la technique joue ; la détection ne vient pas : `missed` sur un battement de fin d'attente signé, sinon `unknown` | H0 : alerte ; la session « Banc » sépare les causes : l'indice brut arrivé ou non, la règle qui le voit ou non (§4.3) |
| **Orodruin éteint à l'heure** | le minuteur ne part pas, et rien n'est rattrapé (`Persistent=false`) | H0 : « not run », par l'alarme d'absence (§4.2) |
| **Orodruin rallumé** (OI3) | `make orodruin-start`, depuis le poste, le met à jour sur la dernière release. Si la release change le drill : `drill_changed` jusqu'au réarmement. Un démarrage planifié (§5) ne met **pas** à jour : la mise à jour part du poste, et la sortie d'Orodruin est fermée | H0 compare le commit de l'image (dans `drill.json`) à sa propre version : « Orodruin behind ». En retard d'un format signé (SEC21), les runs sont `unknown`, dits |
| **Le drill précédent pas fini**, ou une demande, une campagne, un run à la main en cours | le verrou est pris : `busy`, avec ce qui le tient ; jamais attendu, jamais rattrapé | H0 : alerte (sans mention si une demande de Jonathan le tenait) |
| **gondolin tenue par Glorfindel** (une isolation de la semaine passée, pas levée) | attendue 20 min, puis sautée (`isolated`). Le drill ne lève jamais une isolation | H0 : alerte « target held since … » |
| **Le contrat passif** (droit changé, sortie rouverte, jeton Graph hors liste) | `passive` et ses codes | H0 : alerte, avec mention |
| **Un arrêt d'urgence** depuis l'armement | `killed` | H0 : « disarmed by kill » |
| **L'horloge d'Orodruin** dérive | `off_schedule` au-delà de 30 min ; le registre borne à une fois par 6 jours quoi qu'il arrive | H0 : alerte |

---

## 4. Le rapport, et ce qui fait une alerte

### 4.1 Où il va

**Aucun canal nouveau.** Le drill publie dans le conteneur des fenêtres, sous la même attribution,
ce qui existe déjà :
- les fenêtres ;
- le rapport de chaque run (`runs/<run_id>.json`) ;
- le statut de la demande (`orodruin/requests/<id>.json`).

Il y ajoute deux choses, sans identifiant ni cible, comme le statut des demandes :
- **un champ `drill`** dans le statut de la demande : nom, empreinte, occurrence prévue (l'heure du
  `schedule`) ;
- **`orodruin/drill.json`**, le pouls du drill : `armed` ou `disarmed` (et pourquoi : `killed`,
  `drill_changed`), le nom, l'empreinte, la prochaine occurrence, la dernière (son heure, son état,
  son code), le commit de l'image. Il est réécrit à l'armement, au désarmement et à chaque
  occurrence, refusée comprise.

H0 les tire, comme aujourd'hui (`pull_runs`, `runs/orodruin/`), chacun relu contre sa forme. Le lot
ajoute un lecteur exact pour `drill.json`.

### 4.2 Le verdict d'une occurrence, et les alertes

**H0 juge chaque occurrence**, par le code, jamais par le modèle. Il croise trois choses :
- l'heure prévue, tirée de **sa propre copie** du drill (le dépôt, dans son image) ;
- `drill.json` ;
- le statut de la demande, et le rapport de run.

| État | Ce qu'il veut dire | Alerte |
|---|---|---|
| `proven` | détectée, et la décision rattachée : une preuve, la règle de C1 | aucune ; une ligne dans le fil du drill, et la tuile de l'accueil |
| `missed` | la technique a joué, aucune détection, la fin d'attente signée par la watch | **oui, avec mention** : c'est une régression (`regressed` dans la matrice) |
| `unknown` | la mesure n'a pas pu conclure : canal coupé, détection refusée, Orodruin en retard | sans mention la première fois ; **deux de suite, avec mention** : la mesure est cassée |
| `refused` | avant tout appel : `passive`, `watch`, `not_placed`, `not_bench`, `busy`, `off_schedule`, `too_soon`, `killed`, `drill_changed` | oui. Avec mention pour `passive`, `not_placed`, `not_bench`, `off_schedule`, `too_soon`. Sans mention pour `drill_changed` et `killed`, attendus après une release ou un kill |
| `skipped` | le fil sauté : `isolated`, `not_ready` | oui |
| `not_run` | `drill.json` dit le drill armé, et aucun statut pour l'occurrence 2 h après son heure ; ou `drill.json` vieux de plus de 8 jours (« Orodruin silent ») | **oui, avec mention** |

**L'alarme d'absence** (`not_run`) vit chez l'observateur. Orodruin éteint ne peut pas dire qu'il
n'a pas tourné. H0 ne l'arme que sur un `drill.json` qui dit `armed` : un drill jamais armé, ou
désarmé par Jonathan, n'alerte pas.

**Où.**
- **Dans la console** : une ligne « Weekly drill » sur la page de Dagorlad (la dernière occurrence,
  son état, la prochaine, l'armement), et les vues existantes : Runs, la matrice de couverture, la
  tuile de la dernière preuve.
- **Dans Discord** : par le **bot de Glorfindel**, celui du produit, que H0 tient déjà, dans un fil à
  lui (« drill · banc-hebdo »). Le texte passe par `chat_text.py`, sans autre mention que le rôle
  configuré. Le jeton du bot de l'atelier ne va jamais sur H0, et Orodruin n'a pas de sortie vers
  Discord : ni l'un ni l'autre ne change (question 4).
- **La carte d'exercice** elle-même reste dans TO JUDGE, marquée, avec le verdict proposé de VP1
  (§8).

### 4.3 Comment la session « Banc » le lit

BRO1 donne à la session « Banc » le rôle **Lecteur Log Analytics sur le seul workspace du banc**.
Elle ne lit ni H0, ni le canal, ni Orodruin. Elle n'est donc pas un second lecteur du rapport de H0,
mais un **témoin indépendant**, qui relit dans le workspace ce qui aurait dû s'y écrire. Pour une
occurrence (l'heure du `schedule`, plus ou moins une heure) :

1. **La règle attendue, rejouée** : la requête KQL de `expect.rule`, prise dans le dépôt, sur la
   fenêtre. Matche-t-elle sur la cible ? C'est la preuve que la détection *pouvait* se faire, sans H0.
2. **L'indice brut** : la ligne que la technique écrit (pour T1136.001, `new user: name=` en
   `auth`/`authpriv`, étiquetée `useradd`), sur la cible. Elle sépare « rien n'est arrivé » de « la
   règle ne voit plus ».
3. **Le Heartbeat de la cible** : allumée ou non, à l'heure.
4. **Le journal d'activité** (si AL1 l'envoie au workspace) : un Run Command dont l'appelant est
   l'identité d'Orodruin, à l'heure. Son identifiant vient de la configuration de la session, jamais
   du dépôt.

| La règle matche | L'indice brut | Le Heartbeat | Lecture |
|---|---|---|---|
| oui | oui | oui | la détection était possible : si H0 dit `missed`, c'est la watch (ou le canal) |
| non | oui | oui | **la règle régresse**, ou l'ingestion a changé de forme |
| non | non | oui | la technique n'a pas joué (voir le statut), ou la télémétrie Syslog est coupée |
| non | non | non | la cible n'était pas allumée : `not_ready`, `not_placed`, ou le drill n'a pas tourné |

Elle rend son constat à Jonathan (et l'Orchestre le range). Elle n'écrit rien sur Azure, et ne lance
rien : la règle « jamais seule : une attaque sur le banc » vaut toujours pour **toutes** les
sessions. Le drill n'est lancé que par le minuteur que Jonathan a armé. Ses requêtes sont écrites
dans le dépôt (le lot BRO1), relues comme le reste.

---

## 5. Le coût, et l'extinction

### 5.1 Orodruin doit être allumé à l'heure

Aujourd'hui, Orodruin est éteint entre les sessions (`orodruin-stop` désalloue), et un minuteur sur
une VM désallouée ne part jamais. Trois façons :

| | Comment | Coût d'Orodruin | Ce que ça ouvre |
|---|---|---|---|
| **(b) recommandée** : démarrage planifié côté Azure | une Logic App (Consumption), avec sa propre identité managée : un rôle personnalisé, `virtualMachines/start/action` et la lecture, **sur la seule VM d'Orodruin**. Elle le démarre à T − 20 min. Une extinction quotidienne d'Orodruin à 23:00 UTC (le planning DevTest, qui désalloue), comme le banc | environ 5 h par semaine, quelques euros par mois | une identité de plus, qui ne peut qu'allumer Orodruin (§7) ; une ressource Terraform dans `infra/orodruin/`, désactivée par défaut (`drill_autostart_enabled`) ; l'extinction de 23:00 UTC vaut aussi les autres jours, et protège d'un Orodruin oublié allumé la nuit |
| (a) allumé en continu | rien de neuf | D2als_v6 : environ 61 € par mois, le chiffre de la VM de H0, de même taille ; environ 27 € en B2als_v2 si le quota le permet | l'hôte qui tient l'identité des injecteurs, allumé tout le temps : SSH ouvert à l'IP de l'opérateur seulement, sortie fermée, mais plus de temps exposé |
| (c) Jonathan l'allume | — | — | n'est plus un drill automatique : écartée |

Avec (b), le démarrage planifié ne met pas à jour l'image (§3.2) : après une release, Jonathan lance
`make orodruin-start` ou `make orodruin-update` depuis son poste, comme il le fait déjà (OI3). Sinon,
H0 dit « Orodruin behind ». **À mesurer** : la Logic App, son identité, son rôle à la portée d'une
VM, le délai jusqu'à docker prêt. Un service Azure plus simple pour démarrer une VM à heure fixe, s'il
existe dans la région, se compare au banc avant d'être choisi (certitude par la mesure).

### 5.2 Les VM du banc

gondolin s'éteint chaque jour à 23:00 UTC (le planning DevTest de Celebrimbor). Le drill la démarre
s'il le faut (son droit `start` est déjà au contrat, sur chaque VM inscrite), et la laisse s'éteindre
à 23:00 UTC. L'occurrence à 18:00 UTC la garde donc allumée environ 5 h :
- assez pour la grâce de la fenêtre, la décision de la watch, et que Jonathan regarde le soir même ;
- peu pour le coût.

Un drill tôt le matin la garderait allumée 15 h. bree reste hors du drill : allumée en continu, mais
jamais inscrite, et elle porte la vraie charge de la pré-observation.

### 5.3 Ce que coûte une occurrence

| Poste | Ordre de grandeur, à mesurer |
|---|---|
| Orodruin, (b) | environ 5 h de D2als_v6 par semaine |
| gondolin | environ 5 h de D2as_v6 par semaine, quand elle était éteinte |
| L'instantané que la watch déclenche (T1136.001 → snapshot) | un point de sauvegarde à la demande, expirant à 30 jours : 4 à 5 à la fois sur gondolin |
| La décision du modèle, sur H0 | un appel par occurrence |
| Journaux, canal, Logic App | négligeable |
| Chaos Studio | rien : pas de panne |

Ordre de grandeur, à confirmer au banc : moins de 10 € par mois avec (b) ; environ 60 € avec (a).

---

## 6. Ce qui reste à Jonathan, et ce qui est à mesurer

### 6.1 Les gestes de Jonathan

La règle « une attaque sur le banc reste à Jonathan » change ainsi, **pour ce drill seul** : son
geste n'est plus chaque attaque, mais **l'armement**. Il le refait à chaque changement de ce qui
attaque. Aucune session n'arme, ne déclenche ni ne réarme le drill. La ligne « Jamais seule » de
`CLAUDE.md` le dira quand le code sera fusionné : rien ne change tant que rien n'est armé.

1. Relire cette conception (avec la relecture Opus 5.5).
2. Si (b) : appliquer le Terraform du démarrage planifié (son plan relu), puis `make orodruin-lock`
   si le contrat demande une lecture de plus.
3. `make orodruin-drill-check DRILL=banc-hebdo TARGETS=gondolin`, à blanc.
4. `make orodruin-drill-arm DRILL=banc-hebdo TARGETS=gondolin`.
5. **La première occurrence** : celle du minuteur, à son heure, Jonathan présent (la console ouverte,
   `make orodruin-kill` à portée). Pas de lancement « tout de suite » : ce serait le chemin que le
   drill refuse (`off_schedule`).
6. Après chaque release qui change le drill (`drill_changed`) : relire, réarmer. Après chaque release
   tout court : mettre Orodruin à jour (OI3).
7. Désarmer (`make orodruin-drill-disarm`), ou l'arrêt d'urgence, quand il le veut.

### 6.2 À mesurer au banc

1. Le minuteur part à l'heure, dans le conteneur durci. Le journal précède chaque appel, le démarrage
   de gondolin compris.
2. Le démarrage planifié (b) : la Logic App allume Orodruin, son identité ne peut rien d'autre (une
   tentative sur une autre VM échoue), l'extinction de 23:00 UTC désalloue.
3. gondolin démarrée à froid par le drill :
   - le délai jusqu'au premier Heartbeat ;
   - la ligne Syslog d'une technique jouée juste après, perdue ou non ;
   - la latence de détection, à comparer aux 117–144 s mesurées sur une VM chaude.
4. L'alarme d'absence de H0 : Orodruin éteint à l'heure → `not_run` deux heures après.
5. H0 arrêté à l'heure → refus `watch` ; dit au retour de H0.
6. Un arrêt d'urgence → la pierre tombale → l'occurrence suivante `killed`, même après
   `make orodruin-lock`, jusqu'au réarmement.
7. Une release qui change le drill → `drill_changed`.
8. La session « Banc » (BRO1) : la règle rejouée matche sur l'occurrence, l'indice brut se lit.
9. Le coût réel d'une semaine : Orodruin, gondolin, les points de sauvegarde.
10. `OnCalendar` en UTC, et l'horloge d'Orodruin.

---

## 7. Le modèle de menace : une frontière de plus (proposée)

_Proposée ici, pas encore écrite dans [`modele-de-menace.md`](modele-de-menace.md). Le lot de code
l'y porte, en §8 du tableau des frontières, avec ses tests._

**8. Le minuteur d'Orodruin.** Jusqu'ici, chaque attaque sur le banc partait d'un geste humain : une
commande, une demande portée par SSH. Le minuteur en lance une sans geste à chaque fois.
- **De confiance** : l'opérateur qui arme ; l'image vérifiée ; l'hôte (root).
- **Ce qui traverse** : rien du dehors. L'heure, l'armement et le drill de l'image décident ; vers le
  dehors partent les mêmes appels qu'une demande, et les statuts publiés.

| | Menace | Ce qui la tiendrait |
|---|---|---|
| S | Quelqu'un fait jouer une attaque à Orodruin sans Jonathan : par H0, par le canal, par la console | Orodruin ne tire ni n'écoute rien : le drill vient de l'image, l'armement du disque, l'heure de l'horloge. Rien de H0 ni du canal n'entre dans la décision |
| T | Le contenu du drill change : une PR, une release, une image | La PR relue ; l'image vérifiée à son envoi (CI3) ; l'empreinte épinglée à l'armement : un drill changé est refusé jusqu'au réarmement de Jonathan |
| T | Le drill joue plus souvent que prévu : un `OnCalendar` réécrit, le service déclenché à la main, une horloge fausse | Une fois par 6 jours au plus (le registre, écrit avant le jugement ; illisible, rien ne joue) ; l'heure dans les 30 min du `schedule` ; jamais rattrapé (`Persistent=false`) ; un run à la fois (le verrou) |
| E | Le drill atteint une VM hors du banc, ou joue une technique destructive | La zone `bench` exigée, plus stricte que la règle de production ; le catalogue de l'image relu à chaque occurrence (implémentée, non destructive, bibliothèque publique) ; les cibles nommées à l'armement, jamais `all` ; puis toutes les gardes de DG-b et d'O0 |
| E | L'identité du démarrage planifié (b) | Un seul droit, démarrer la VM d'Orodruin, à la portée de cette VM. Compromise, elle n'allume qu'Orodruin, dont le minuteur ne joue qu'à son heure et sous son contrat |
| R | Une occurrence sans trace | Le journal avant chaque appel (O1), sur l'hôte et dans le canal (SEC5) ; le registre des occurrences ; `drill.json` ; l'alarme d'absence sur H0 |
| D | Un drill qui s'emballe, ou qui use le banc | Les trois plafonds ; `RuntimeMaxSec` ; le nettoyage de l'atomic (le compte créé, retiré) ; les points de sauvegarde expirent à 30 jours |
| D | Le drill masque un vrai incident sur sa cible | La fenêtre ne marque que ses cibles, pour un temps borné (B2, H-1) ; une carte d'exercice reste devant l'opérateur, marquée ; VP1 propose, ne pose jamais. **Assumé**, comme pour tout exercice : un vrai incident sur gondolin dans la fenêtre est d'abord lu comme un exercice, et c'est Jonathan qui juge la carte |
| I | Ce que le drill publie | Ce que publient déjà les demandes : ni identifiant, ni cible, ni abonnement. Le nom du drill, son empreinte et ses heures sont ceux du dépôt public |
| S | Un verdict proposé forgé : une fenêtre ou un statut qui se dit du drill | H0 lit ce qu'il attend dans **sa propre copie** du drill, jamais dans le canal ; l'empreinte annoncée doit être celle de cette copie ; un verdict proposé n'est jamais compté (VP1) |
| D | Le minuteur repart après un arrêt d'urgence | La pierre tombale du kill, lue avant tout ; seul un réarmement relance |

**Ce qui resterait ouvert**, dit neutre :
- root sur Orodruin peut déjà lancer tout injecteur sous le contrat (la limite de DG-b) : le minuteur
  ne lui donne rien de plus. L'armement et le registre, sur son disque, sont à sa main ;
- la pierre tombale est dans un conteneur où Orodruin écrit. Elle évite une reprise par mégarde, pas
  celle d'un Orodruin compromis, qui n'en a pas besoin ;
- H0 en panne, aucune alerte sur l'instant : l'indicateur de la dernière preuve finit par le dire.

**Une décision assumée de plus** : « Un minuteur attaque le banc sans geste humain à chaque fois
(DRL1, décision de Jonathan, 06/11). Ce qui le borne : une technique publique et non destructive, la
zone `bench` seule, une fois par semaine, sous le contrat d'Orodruin et V1, l'armement par Jonathan,
refait à chaque changement du drill. »

---

## 8. Ce que verra Glorfindel, et VP1

### 8.1 Ce que la watch voit

Comme le 31/10, rien de plus :
- **sur gondolin**, une ligne `useradd` « new user: name=… » ;
- **le RulePoller** : `t1136-001-local-account-creation-linux-v1` matche, après la latence d'ingestion
  (117–144 s mesurées, `expected_latency_s: 480`) ;
- **le cycle** : sa source est `exercise`, puisqu'une fenêtre couvre gondolin à cette heure, avec
  l'identifiant du run et celui de la demande ;
- **la décision** : le 31/10, un instantané recommandé à 35 %, escaladé sous le seuil de 0,7. En
  `non_disruptive`, l'instantané peut partir seul ;
- **la carte** : dans TO JUDGE, marquée exercice (« ⚑ exercise · run … »).

Le modèle n'est pas déterministe : une semaine, il peut isoler. gondolin reste alors tenue jusqu'à
ce que Jonathan la libère. L'occurrence suivante est sautée (`isolated`), et c'est dit.

**Glorfindel reste aveugle.** `expect` ne va ni dans la fenêtre, ni dans la demande, ni dans
`_build_user_message()`, ni au modèle. Le lot ne touche à aucune des trois zones du prompt, et ne
demande donc pas le run de bout en bout. La source `exercise` ne baisse aucune garde : le label ne
sert qu'au rapport et à la carte, comme pour tout exercice.

### 8.2 Ce que le drill déclare pour VP1

VP1 propose un verdict à une carte d'exercice qui correspond à la détection attendue : la bonne
règle, la bonne cible, dans la fenêtre. Il lit, **sur H0** :

| Ce qu'il compare | D'où il le lit |
|---|---|
| la règle attendue | `expect.rule` du fil, dans **la copie du drill de H0** (son image), trouvée par le nom et l'empreinte que porte le statut de la demande (`drill`), les deux égaux |
| le délai | `expect.within_s`, après le T0 du fil (l'heure de l'appel de l'atomic, le rapport du run) |
| la cible | la VM du fil : celle de la fenêtre (`targets`) **et** celle du rapport (`metrics.resource_id`), les deux égales |
| la fenêtre | début, fin, et 15 min de grâce (`GRACE_AFTER_S`) |
| le lien carte ↔ run | la carte est `exercise`, son `exercise_run` est ce run, ce run est un fil de cette demande (`metrics.request`) |

Il propose seulement si **tout** concorde, sur **une seule** carte par fil :
- la règle d'une carte est celle du fil ;
- sa VM est la cible ;
- son heure tombe dans `[T0, T0 + within_s]`, et dans la fenêtre ;
- la carte est la première de ce run et de cette règle.

Une carte d'une autre règle, d'une autre VM, hors de la fenêtre, une seconde carte, un drill dont
l'empreinte ne concorde pas (Orodruin et H0 sur deux versions) : pas de proposition, et la raison
est dite.

VP1 propose sur la **détection**, pas sur la qualité de la décision. Le drill ne déclare aucune
décision attendue : le dire, ce serait juger le modèle par une attente écrite côté rouge, et la
décision reste à Jonathan. Le nom du verdict proposé, et son registre à part des verdicts posés,
sont à VP1. Le drill lui donne ce qu'il lit, rien de plus.

---

## 9. Le code à venir (proposé)

| Lot | Contenu | Où |
|---|---|---|
| **DRL1a** (Orodruin, cœur) | `schedule` et `expect` dans le lecteur de drill ; `drills/banc-hebdo.yaml` ; `eregion_core/scheduled_drill.py` (l'armement, les gardes de §2.3, la demande, `exercise_runner`, la pierre tombale, `drill.json`) ; le champ `drill` du statut ; les cibles Make `orodruin-drill-check`, `-arm`, `-disarm` ; les unités systemd ; le kill qui écrit la pierre tombale ; le test de CI drill ↔ catalogue ↔ règles | `eregion_core/`, `drills/`, `Makefile`, `infra/orodruin/kill.py` |
| **DRL1b** (H0) | le verdict de chaque occurrence, l'alarme d'absence, les alertes par le bot de Glorfindel, la ligne « Weekly drill » de la console ; le lecteur exact de `drill.json` | `eregion_console/`, `glorfindel/` (le pull, le bot) |
| **DRL1c** (Terraform, si b) | la Logic App, son identité, son rôle à la portée de la VM d'Orodruin, l'extinction de 23:00 UTC, désactivés par défaut | `infra/orodruin/` |
| VP1, BRO1 | ce qu'ils lisent du drill (§4.3, §8.2) | leurs lots |

**Tests hermétiques** : faux `systemd`, fausse horloge, faux Azure, faux canal. Aucun appel Azure ni
au modèle, un `HOME` jetable.

**Mutants proposés** (la plage, à demander à l'Orchestre) :
- l'empreinte non comparée ;
- la zone `production` admise ;
- une technique destructive, ou une panne, admise ;
- `too_soon` ou `off_schedule` sautés ;
- la pierre tombale ignorée ;
- le démarrage de la VM avant V1 ou avant le journal ;
- une occurrence manquée rattrapée ;
- `expect` écrit dans la fenêtre ou dans la demande ;
- `all` admis comme cible ;
- l'alarme d'absence armée sur un drill désarmé ;
- VP1 qui propose sur une autre VM.

---

## 10. Questions pour Jonathan

Une à la fois, l'option recommandée d'abord.

1. **Allumer Orodruin à l'heure.**
   - **Recommandé : (b)**, une Logic App qui ne peut qu'allumer Orodruin, et une extinction
     quotidienne à 23:00 UTC : quelques euros par mois, une identité de plus, bornée.
   - (a) Orodruin allumé en continu : environ 61 € par mois, rien de neuf à poser.
2. **L'heure.** **Recommandé : le mardi à 18:00 UTC** : un jour de semaine, le soir à Paris, environ
   5 h avant l'extinction des VM. Autre choix : un matin en semaine, plus de VM allumée (environ 15 h),
   les alertes vues dans la journée.
3. **Le contenu.**
   - **Recommandé : T1136.001 seule en v1.** T1059.004 s'ajoute après la mesure d'AUD1, une technique
     de Stratus après ID1 ; chaque ajout est une PR, puis un réarmement.
   - La panne `vm-shutdown` chaque semaine : non. Elle éteint la cible, et une panne n'est pas une
     technique au sens de la décision.
4. **Où vont les alertes.** **Recommandé : le bot de Glorfindel**, dans un fil à lui : H0 le tient
   déjà, et le jeton de l'atelier ne va jamais sur H0. Autre choix : un webhook de l'atelier de plus
   sur H0, un secret de plus.
5. **Réarmer à chaque changement du drill** (son empreinte épinglée). **Recommandé : oui.** C'est ce
   qui fait de « ce drill seul » une règle tenue par le code. Autre choix : faire confiance à la
   seule relecture de la PR.
6. **Ce que lit la session « Banc ».**
   - **Recommandé : le workspace seul en v1**, comme BRO1 l'a décidé. Elle est un témoin indépendant
     de H0 ; le verdict de H0, Jonathan le lit dans la console.
   - Plus tard, si le besoin se montre : une lecture des préfixes `runs/` et `orodruin/` du canal, une
     frontière de plus.

## Ce que ce document ne décide pas

- Rien n'est mesuré : les comportements d'Azure (la Logic App, le démarrage à froid, la latence)
  sont des hypothèses, à prouver au banc.
- Le format du verdict proposé et son registre sont à VP1. L'identité de la session « Banc » et la
  façon de la lui donner sont à BRO1.
- Les drills des instances d'un client (couche `instance`) ne se planifient pas : seul un drill livré
  porte `schedule`. Un client qui voudrait son propre drill hebdomadaire est une question pour la
  1.x.
- Ni le jumeau ni la production : le drill est du banc seul. La sentinelle de production
  (`sentinelle`) reste une demande portée à la main.
