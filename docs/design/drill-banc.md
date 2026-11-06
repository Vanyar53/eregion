# Le drill du banc — un exercice chaque semaine, lancé par Orodruin (DRL1)

_Conception — 06/11 (DRL1, #613) — statut : **conception seulement**, relue une première fois en
Opus 5.5 (06/11) et corrigée. Rien n'est codé, armé ni mesuré. L'armement reste à Jonathan._

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

Le drill de la semaine est un **drill livré** (DG-d, `drills/`) qui porte un bloc de plus : quand il
tourne (`schedule`). Ce que la watch doit voir est écrit **à part**, dans
`expectations/banc-hebdo.yaml`, un fichier que l'image des injecteurs ne contient pas. Une seule
technique pour commencer : **T1136.001**, par l'atomic épinglé d'Atomic Red Team, sur gondolin.

Un minuteur systemd d'Orodruin le lance.

**Trois entrées décident d'une occurrence**, et seules elles peuvent la déclencher :
- l'image des injecteurs, vérifiée à son envoi (CI3), qui porte le drill ;
- un fichier d'armement, écrit par Jonathan ;
- l'horloge.

**Ce qui vient d'ailleurs ne peut que refuser.** Le battement de la watch (V1), qui vient de H0 par
le canal ; la pierre tombale d'un arrêt d'urgence, dans le canal ; les tags et l'état des cibles, lus
dans Azure. Aucun ne peut lancer une occurrence, ni en changer le contenu ou la cible.

**Aucune écriture sur une ressource du banc** (démarrer gondolin comprise) avant que le contrat, V1
et le journal soient passés.

Le drill fabrique lui-même la demande, et la donne au même juge que les demandes de Dagorlad
(`eregion_core/exercise_runner.py`, DG-b). Toutes les gardes d'aujourd'hui valent donc, et le drill
en ajoute :
- son empreinte épinglée à l'armement ;
- la zone `bench` seule, rejugée avant chaque fil ;
- une fois par semaine au plus, tenu par un registre lu et écrit sous le verrou d'Orodruin ;
- jamais rejoué après un arrêt d'urgence.

**Qui dit quoi :**
- **H0** juge chaque occurrence et alerte, y compris quand rien n'est arrivé : c'est l'observateur qui
  tient l'alarme d'absence, jamais l'acteur.
- **La session « Banc »** relit le workspace en témoin indépendant.
- **VP1** lit ce que le drill attend, pour proposer un verdict que Jonathan confirme.

```
Jonathan ── arme (une fois, puis à chaque changement du drill) ──▶ Orodruin
                                                                     │ minuteur, mardi 19:00 UTC
                                                                     ▼
   image vérifiée (drills/banc-hebdo.yaml) + armement + horloge ─▶ le drill   (décident)
   V1, pierre tombale, tags et état des cibles ──────────────────▶ le drill   (refusent seulement)
        empreinte ? catalogue ? heure ? verrou + registre ? contrat ? V1 ? zone bench ? isolée ?
                                                                     │ demande → exercise_runner
                                                                     ▼
            gondolin démarrée s'il le faut, puis Run Command (atomic T1136.001), journalisés avant
                                                                     │
   gondolin ── Syslog ──▶ workspace ──▶ H0 : RulePoller → carte d'exercice → VP1 propose → Jonathan
                              │                     ▲   (VP1 : expectations/banc-hebdo.yaml, sur H0)
                              │   canal : fenêtres, rapports, statuts, orodruin/drill.json
                              ▼
                   session « Banc » (BRO1, lecture seule) : la règle rejouée, l'indice brut, le Heartbeat
```

---

## 1. Ce que le drill joue, et où il se déclare

### 1.1 Le choix des techniques

Une technique entre dans le drill de la semaine si elle tient **toutes** ces conditions :

1. au catalogue (`technique_catalog.yaml`), `status: implemented` : script ou atomic, règle et
   validation en réel existent ;
2. `destructive: false`, dans le catalogue (le mot du catalogue, `catalog_destructive`, SEC5) ;
3. d'une **bibliothèque publique**, version épinglée (`engine: atomic`, plus tard `stratus`). Jamais
   un script maison, la règle de BL1b, décidée par Jonathan le 02/11 et sans exception ;
4. **validée en réel depuis Orodruin**, et sa détection prouvée (`docs/historique.md`, rapports de
   banc) ;
5. une règle de la base livrée, `enabled`, du même `ttp`, que les attentes du drill nomment (§1.2).

**Qui vérifie quoi.**
- Les conditions 1 à 3 se lisent dans le catalogue : la CI les relit, et Orodruin aussi à chaque
  occurrence, dans le catalogue de son image.
- La condition 4 n'est écrite dans aucun fichier que le code lit : elle se tient à la relecture de
  la PR qui ajoute la technique.
- La condition 5 se vérifie en CI seulement : ni la base de règles ni les attentes ne sont dans
  l'image des injecteurs, et Orodruin n'en a pas besoin.

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
watch en a prise (un instantané recommandé à 35 %, sous le seuil, escaladé) suffit à la preuve :
pour la matrice de C1, une preuve est une technique détectée **dont la décision est rattachée**, pas
une technique contenue. Le drill garde la dernière preuve sous 30 jours. Il ne mesure ni le temps
pour contenir ni la part contenue seule, qui se mesurent sur le trafic réel (BL1b).

**Le biais de l'indicateur, dit.** La matrice de couverture (`eregion_console/coverage.py`,
`matrix`) prend pour « dernière preuve » la plus récente, **toutes techniques confondues**. Un drill
qui prouve T1136.001 chaque semaine garde donc l'indicateur vert, même quand les autres techniques
vieillissent. L'indicateur finirait par mesurer « la boucle tourne sur une technique », plus « la
couverture est prouvée » : la mesure devient la cible (Goodhart).
- Ce qui le compense aujourd'hui : chaque ligne de la matrice garde son propre état (`aging` à
  21 jours, `stale` à 30), et `stalest` liste les techniques les moins récemment prouvées.
- Ce que DRL1b ajoute : la tuile de la dernière preuve dit quand elle vient du drill de la semaine,
  et montre à côté la technique la plus ancienne de `stalest`.
- **La suite, hors DRL1 : la rotation.** Plusieurs drills fixes, chacun déclaré, relu et armé ; la
  semaine joue la technique éligible la moins récemment prouvée. Elle vient quand une deuxième
  technique tient les cinq conditions (T1059.004 après AUD1, une technique de Stratus après ID1).

### 1.2 Où il se déclare : un drill livré, et ses attentes à part

**Le drill** vit dans **`drills/banc-hebdo.yaml`** : un drill livré de DG-d
(`eregion_core/drill.py`), relu en PR, remplacé par une mise à jour. Il en garde le format exact :
- un nom, l'auteur `eregion` ;
- des fils dont la cible est un sélecteur (`{zone: bench}`), jamais un nom de VM ni un identifiant
  de ressource.

Le lot de code ajoute au lecteur un bloc **optionnel**, lu avec la même exactitude (aucun champ de
plus, aucun de travers) :

```yaml
# The weekly bench drill (DRL1, docs/design/drill-banc.md): shipped, reviewed in a PR. Orodruin's
# timer plays it once a week, armed by the operator, who names its targets then. What the watch
# should see is not here: expectations/banc-hebdo.yaml, never in the injectors' image.
name: banc-hebdo
author: eregion
description: "The weekly proof on the bench: a public, non-destructive technique already proven from Orodruin."
schedule:                  # this drill may be played by Orodruin's timer
  day: tue                 # mon … sun
  at: "19:00"              # UTC, HH:MM
  max_injections: 6        # its own cap, at most the cap Orodruin declares
  max_run_s: 1800
wires:
  - experiment: T1136.001
    target: {zone: bench}
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

**Les attentes** vivent dans **`expectations/banc-hebdo.yaml`**, un fichier à part, avec son propre
lecteur exact :

```yaml
# What the watch should see when the weekly drill plays (DRL1, docs/design/drill-banc.md).
# Read on H0 (VP1) and by the Banc session. Never copied into the injectors' image: Orodruin
# cannot read it.
drill: banc-hebdo
wires:
  - rank: 1
    experiment: T1136.001
    rule: t1136-001-local-account-creation-linux-v1
    within_s: 900          # after the wire's T0
```

Elles nomment, pour chaque fil, la règle attendue (une règle de la base livrée, `enabled`, du même
`ttp` que l'expérience) et le délai après le T0 du fil. C'est ce que lisent VP1 (§8) et la session
« Banc » (§4.3).

**Pourquoi à part : Orodruin ne peut pas les lire.** Le dire ne suffit pas, la séparation est dans
la structure :
- l'image des injecteurs (`annatar/Dockerfile`) copie `drills/`, jamais `expectations/` ; l'image de
  Glorfindel (`glorfindel/Dockerfile`) copie les deux ;
- un test relit les deux Dockerfile ;
- `eregion_core/scheduled_drill.py` et `exercise_runner.py` n'importent pas le lecteur des attentes,
  et un test le vérifie.

La demande ne les porte pas non plus : son format ne change pas, « aucun résultat attendu », Annatar
reste aveugle à Glorfindel. **La décision ne les voit jamais**, ni la fenêtre d'exercice : Glorfindel
reste aveugle à Annatar (§8.1).

**L'empreinte** est le sha256 du **fichier du drill entier**, octet pour octet : nom, description,
`schedule`, fils. Elle ne couvre pas les attentes. Changer une attente ne change rien de ce qui
attaque : une PR relue suffit, sans réarmement. Ce que couvre l'empreinte est la question 5.

**E1 et le schéma.** Les fils nomment des entrées du catalogue, validées par
`schemas/technique_catalog.schema.json` (E1). Le drill n'a pas de schéma JSON : son lecteur exact
(`drill.read`) en tient lieu, le même sur la console, le poste et Orodruin. Les attentes non plus :
leur lecteur exact en tient lieu.

Le lot ajoute un test de CI qui relit `drills/banc-hebdo.yaml` et `expectations/banc-hebdo.yaml` :
- contre le catalogue : les conditions 1 à 3 de 1.1 ;
- contre la base de règles : la règle de chaque attente existe, `enabled`, du même `ttp` ;
- l'un contre l'autre : une attente par fil, au même rang et de la même expérience.

Un drill qui ne les tient plus fait échouer la PR qui le casse : un changement du catalogue, l'atomic
retiré, la règle renommée.

**Changer le drill** : une PR relue. Puis Jonathan le réarme, car son empreinte est épinglée (§2.3).
Un drill changé ne tourne jamais seul.

### 1.3 Ce que le drill ne porte pas

Ni nom de VM, ni identifiant, ni abonnement : le dépôt est public, et un drill livré ne connaît pas
les VM d'une instance. La cible se donne à l'armement, par son nom (`TARGETS=gondolin`). « Jamais
choisie à la place de l'opérateur » (Jonathan, 03/11) : il la choisit une fois, en armant. `all` est
refusé pour un drill armé : une VM inscrite plus tard ne deviendrait pas une cible sans geste.

Les attentes d'un drill de l'instance (couche `instance`) ne sont pas prévues en v1 : seul un drill
livré a des attentes, dans le dépôt. Elles viendront, si le besoin se montre, avec les drills
planifiés d'un client (1.x).

---

## 2. Le minuteur sur Orodruin

### 2.1 Ce qui est posé

**Rien n'est posé avant l'armement.** La vérification à blanc n'écrit rien ; l'armement pose les
unités et active le minuteur dans le même geste, celui de Jonathan.

| Cible Make (depuis le poste, par la clé d'hôte épinglée) | Fait |
|---|---|
| `make orodruin-drill-check [DRILL=banc-hebdo TARGETS=gondolin]` | à blanc : relit le drill dans l'image d'Orodruin, son empreinte, le contrat, la watch, la cible ; dit ce que ferait la prochaine occurrence et quand. Aucune écriture, ni sur Orodruin ni sur Azure |
| `make orodruin-drill-arm DRILL=banc-hebdo TARGETS=gondolin` | **Jonathan.** Écrit le fichier d'armement, pose les unités systemd, active le minuteur, active le démarrage planifié (§5.1, par l'identité de l'opérateur), publie `orodruin/drill.json` |
| `make orodruin-drill-disarm` | désactive le minuteur et retire ses unités, retire l'armement, **désactive le démarrage planifié** (identité de l'opérateur), publie « désarmé » ; dit chacun de ces pas, et sort en erreur si l'un manque |

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
  - `OnCalendar` est tiré du `schedule` du drill au moment d'armer (`Tue *-*-* 19:00:00 UTC`) ;
  - `Persistent=false` : une occurrence manquée n'est **jamais rattrapée** au démarrage suivant. Elle
    est dite manquée (§4), elle ne part pas à une heure où personne ne l'attend ;
  - `AccuracySec=1min`.
- `eregion-drill.service` : un `docker run` durci comme les autres (ORO_HARDEN) :
  - `--pull never` : l'image est celle qu'`orodruin-push` a chargée et vérifiée
    (`eregion-annatar:orodruin`), jamais tirée ; absente, le service échoue, et H0 le dit (`not_run`) ;
  - un nom fixe (`--name eregion-drill`) et `--init` (§3.1, l'arrêt du service) ;
  - racine en lecture seule, aucune capacité ;
  - `~/runs/{annatar,gothmog,orodruin}` montés comme pour une demande ;
  - l'armement en lecture seule ;
  - une commande fixe, `python -m eregion_core.scheduled_drill run`, sans argument venu d'ailleurs ;
  - `RuntimeMaxSec=3600`, `ExecStop=docker stop --time 90 eregion-drill`, `TimeoutStopSec=120`
    (le calcul : §3.1).

Le minuteur est posé par SSH, pas par le `custom_data` de Terraform : changer `custom_data`
recréerait la VM.

**L'image doit contenir le drill.** Aujourd'hui, `annatar/Dockerfile` ne copie pas `drills/` : un
drill livré se lit sur le poste de l'opérateur (`make orodruin-exercise DRILL=…`). DRL1a ajoute
`COPY drills/ drills/` à l'image des injecteurs (le lecteur le cherche en `/app/drills`,
`drill.shipped_dir()`), et un test qui relit le Dockerfile : `drills/` copié, `expectations/` jamais.

### 2.2 Orodruin ne tire rien, et n'écoute rien

C'est le cœur du lot. Aujourd'hui, une demande vient de l'opérateur : il la porte par SSH
(« Orodruin ne tire rien et n'écoute rien : la commande vient de l'opérateur »,
[`orodruin-contract.md`](orodruin-contract.md), DG-b). Avec le minuteur, Orodruin agit sans
commande, **mais toujours sans rien tirer ni écouter**.

**Ce qui décide, et peut déclencher, une occurrence :**

| Entrée | D'où | Qui peut la changer |
|---|---|---|
| le drill | l'image des injecteurs (`/app/drills/`), vérifiée à `make orodruin-push` : digest, signature, provenance (CI3) | une PR relue, une release, puis le réarmement de Jonathan |
| l'armement | `~/drill/armed.json`, écrit par `make orodruin-drill-arm` | Jonathan (ou root sur Orodruin, §7) |
| l'heure | l'horloge d'Orodruin | — |

**Ce qui ne peut que refuser :**

| Lu | D'où | Ce qu'il peut faire |
|---|---|---|
| le battement de la watch (V1) | H0, par le canal | refuser (`watch`) ; jamais lancer, ni rien changer de ce qui joue |
| la pierre tombale d'un arrêt d'urgence | le canal, écrite par l'opérateur | refuser (`killed`) |
| le contrat | les droits effectifs de l'identité d'Orodruin, lus dans Azure | refuser (`passive`) |
| les cibles : inscription, zone, état, isolation | Azure, par l'identité d'Orodruin | refuser (`not_placed`, `not_bench`), sauter un fil (`isolated`, `not_ready`) ; démarrer une VM arrêtée **déjà nommée à l'armement** (§3.1) |

Un H0 compromis, ou qui écrit le canal, peut donc empêcher une occurrence, jamais en lancer une, ni
en changer le contenu ou la cible. **Écartés** :
- un ordonnancement sur H0 : H0 commanderait une attaque ;
- un workflow planifié de GitHub : un chemin d'écriture de la CI vers Azure ;
- un `cron` dans le conteneur : un processus de plus qui tourne en continu, et l'armement relu de
  l'intérieur.

### 2.3 Ce qui l'empêche de lancer autre chose que le drill déclaré

Le service ne prend aucun argument. Il relit, dans cet ordre, et refuse au premier manque :

1. **L'armement** se lit, et nomme un drill. Absent : `disarmed`, rien ne part, rien n'est publié de
   plus.
2. **Le drill vient de l'image**, par son seul lecteur, dans la couche livrée seulement
   (`drill.load_file(…, SHIPPED)` sur `/app/drills/<nom>.yaml`). Jamais `drill.find`, qui préfère la
   couche de l'instance ; jamais `~/.eregion/console/drills` ni un répertoire où Orodruin écrit. Il
   porte `schedule`, et tient les conditions de 1.2.
3. **Son empreinte est celle de l'armement.** Une release qui change `drills/banc-hebdo.yaml` change
   l'empreinte : `drill_changed`, dit, et rien ne part jusqu'au réarmement. Changer ce qui attaque
   seul demande donc la relecture de la PR, **et** un geste de Jonathan.
4. **Le catalogue de l'image** confirme chaque fil : `implemented`, non destructive, moteur public.
   Les deux lisent le même fichier ; le drill relu en CI ne suffit pas, car l'image peut être d'avant.
5. **L'heure tombe dans les 30 minutes** qui suivent l'heure du `schedule` (`off_schedule`) : un
   déclenchement à la main du service, ou un `OnCalendar` réécrit, est refusé. Rien n'est écrit
   avant ce point : un déclenchement hors de l'heure ne consomme pas l'occurrence de la semaine.
6. **Pas d'arrêt d'urgence depuis l'armement** : la pierre tombale du canal (§3.1) ; un kill daté
   après l'armement → `killed`. Une pierre tombale illisible refuse aussi.
7. **Le verrou « un run à la fois »** (`request_lock`, flock), pris par `scheduled_drill` et tenu
   toute l'occurrence ; pris ailleurs → `busy`, jamais attendu, jamais rattrapé. **Le descripteur
   passe au runner** par `EREGION_RUN_LOCK_FD` (`exercise_runner.LOCK_FD_ENV`), comme le runner le
   passe à ses fils. Sans lui, `Runner.run()` reprend `request_lock()` en non bloquant
   (`exercise_runner.py`, `run`) et se refuse `Busy` à chaque occurrence. Le runner reconnaît le
   descripteur hérité (`_inherited` : le même fichier, son périphérique et son inode) et le tient sans
   le relâcher.
8. **Le registre**, sous ce verrou, comme `_spent` et `_played` pour les demandes :
   - lu : la dernière occurrence jouée (`runs/orodruin/drills/played.jsonl`) date d'au moins 6 jours,
     sinon `too_soon` ;
   - puis écrit, sur le disque (fsync), **avant** le jugement : quoi qu'il arrive ensuite (un refus,
     un crash), cette semaine est jouée ;
   - un registre illisible ne laisse rien jouer.

   Lu hors du verrou, deux occurrences côte à côte le liraient vide toutes les deux : le mutant
   « registre lu hors du verrou » le prouve.
9. **Le contrat, V1, les cibles** (§3.1, étapes 2 à 4) : chaque nom de l'armement est une VM inscrite
   lue maintenant par l'identité d'Orodruin, une seule de ce nom, en zone **`bench`** (`not_placed`,
   `not_bench`). Plus strict que la règle de production, qui admettrait T1136.001 en `production`.
10. Puis **la demande** : le drill la fabrique (`exercise_request.new`), avec les identifiants des VM
    relues, et la donne à `exercise_runner`. C'est le même chemin que DG-b, sans second chemin, avec
    trois réglages que le runner prend déjà en paramètre ou qu'il gagne :
    - **`zones=("bench",)`**, un paramètre nouveau du runner (par défaut aucun : DG-b ne change pas).
      Le runner le rejuge **avant chaque fil**, dans `_recheck`, avec l'inscription et la zone lues
      à ce moment-là. Sans lui, `_recheck` rejuge par `check_zone`, qui admet T1136.001 en
      `production` : une VM retaguée `production` entre le jugement et le fil passerait ;
    - `wait_isolation_s=0` : pas d'attente d'isolation pour le drill (§3.1) ;
    - le plafond rendu au runner (§3.1).

Le lot de code écrit un mutant pour chacune de ces gardes (§9).

---

## 3. Les garde-fous, et quand quelque chose manque

### 3.1 L'ordre d'une occurrence

Rien n'atteint le cloud avant les étapes 0 à 3. Démarrer une VM est une écriture : elle passe après
le contrat, V1 et le journal.

```
0  armement, drill, empreinte, catalogue, heure (off_schedule),        ← lectures locales ; la seule
   pierre tombale (§2.3, 1–6)                                             lecture du dehors refuse
1  verrou « un run à la fois » (flock) : pris, sinon busy ;            ← jamais attendu, jamais rattrapé
   registre lu (too_soon) puis écrit, sous le verrou
2  contrat : orodruin.check() armé, sinon passive (ses codes)
3  V1 : battement signé de la watch, frais, du bon périmètre ;
       relu jusqu'à 10 min (un déploiement de H0 en cours), puis refus watch
4  cibles relues : inscription, zone bench (§2.3, 9) ; plafond : celui du drill ≤ celui déclaré
5  isolation lue AVANT tout démarrage : VM tenue par Glorfindel → fil sauté isolated, tout de suite,
       rien n'est démarré — le drill ne lève jamais une isolation
6  cible prête : VM arrêtée → démarrée, par scheduled_drill (journalisé avant par before_call,
       compté dans le plafond) ; puis Heartbeat frais attendu (lecture, hors plafond),
       10 min au plus, sinon fil sauté not_ready
7  demande → exercise_runner (zones=("bench",), wait_isolation_s=0, verrou hérité) :
       il rejuge tout (contrat, V1, inscription, zone, plafond), puis rejuge chaque fil (_recheck)
8  le fil : annatar wire, journal avant chaque appel, fenêtre d'exercice (son request),
       l'attente de la détection signée (SEC21), le nettoyage de l'atomic
9  statuts publiés : la demande (orodruin/requests/<id>.json, avec le drill) et orodruin/drill.json
```

**Démarrer gondolin : où, et comment.** Ni le runner ni `annatar wire` ne démarrent une VM : le
préalable d'Annatar (`AzureVMExecutor.check_preflight`) bloque une VM arrêtée, et c'est voulu. Le
démarrage vit donc dans **`scheduled_drill`**, entre l'étape 5 et la demande :
- `eregion_core` ne peut pas importer `gothmog` (D1) : la sonde de Gothmog ne se réutilise pas ;
  `scheduled_drill` lit le Heartbeat lui-même, une requête au workspace du banc, avec le rôle
  « Lecteur Log Analytics » qu'Orodruin a déjà (`bench_logs_reader`) ;
- le démarrage est un `POST …/start` d'ARM, sans SDK (comme les lectures de l'inscription), par
  l'identité d'Orodruin : le droit `virtualMachines/start/action` est déjà au contrat
  (`injector_vm`, `infra/orodruin/main.tf`), attribué VM par VM ;
- il passe par une session armée (`orodruin.arm(…, request=<id>)`) : `before_call("start_vm", …)` le
  journalise avant l'appel, sur le disque puis dans le canal, et le compte dans le plafond ;
- DG-b ne change pas : une demande de Dagorlad ne démarre toujours rien.

**Le plafond** tient à trois étages :
- celui du drill (`max_injections`, `max_run_s`) ;
- celui qu'Orodruin déclare (`EREGION_MAX_INJECTIONS`, `EREGION_MAX_RUN_S`), relu par le contrat ;
  un drill dont le plafond dépasse celui déclaré est refusé ;
- le plafond absolu.

Le runner compte les appels journalisés **depuis son propre départ** (`_calls_used`) : il ne voit pas
le démarrage, fait avant lui. `scheduled_drill` lui rend donc, par son paramètre `check`, le verdict
du contrat avec un plafond réduit : celui du drill, moins l'appel du démarrage. Le chemin atomic
demandait 5 appels le 20/10 : 6 laissent le démarrage de la VM.

**Le budget de temps.**

| Étape | Au plus | D'où vient le chiffre |
|---|---|---|
| V1 relu | 10 min | un déploiement de H0 (CD) |
| démarrage de gondolin, Heartbeat frais | 10 min | à mesurer à froid (§6.2) |
| le runner (`max_run_s`) | 30 min (1 800 s) | ci-dessous |
| verrou, lectures, statuts | quelques minutes | — |
| **`RuntimeMaxSec`** | **60 min (3 600 s)** | 10 + 10 + 30, et une marge de 10 |

Ce que borne `max_run_s`, pour un fil T1136.001 :
- la sonde de départ, puis l'atomic par Run Command : jusqu'à 5 reprises en cas de conflit (15 + 30
  + 60 + 90 + 120 = 315 s au pire) ;
- l'attente de la détection signée : 600 s, la latence du catalogue (480 s) plus la marge de 120 s,
  jamais sous le plancher Syslog de 480 s (`annatar/campaign/synthesizer.py`, `_detection_timeout`) ;
- le nettoyage de l'atomic, et la sonde du retour.

Soit environ 20 min au pire : 30 min laissent la marge. Aucune attente d'isolation n'y entre : une
VM tenue est sautée tout de suite (étape 5). `max_run_s` reste loin sous le plafond absolu
(`CEILING_RUN_S`, 2 h).

**L'arrêt du service.** À `RuntimeMaxSec`, systemd arrête le service. Deux pièges :
- le client `docker run` tué n'arrête pas le conteneur ;
- un Python premier processus d'un conteneur ignore SIGTERM s'il n'a pas de gestionnaire (le noyau
  ne délivre pas au PID 1 d'un espace de noms un signal dont l'action est celle par défaut).

D'où :
- `ExecStop=docker stop --time 90 eregion-drill` : SIGTERM au conteneur, SIGKILL 90 s après ;
- `--init` : un `init` minimal est le PID 1, et relaie le signal au Python ;
- un gestionnaire SIGTERM dans `scheduled_drill`, qui arrête le fil en cours et lève : chaque
  `finally` tourne, le statut est publié (`stopped`) ;
- le même gestionnaire dans `annatar wire` : sa fenêtre se ferme, le nettoyage de l'atomic part (un
  changement côté Annatar, dit à sa session) ;
- un test : un SIGTERM pendant un faux fil → la fenêtre fermée, le statut publié, la sortie.

Une fenêtre laissée ouverte par un SIGKILL expire d'elle-même (`MAX_DURATION_S`, puis la grâce).

**La fenêtre d'exercice** est celle d'aujourd'hui :
- ouverte avant le premier appel, fermée dans un `finally` ;
- bornée (`MAX_DURATION_S`), avec 15 min de grâce ;
- elle porte l'identifiant de la demande, et rien de ce que le drill attend.

**L'arrêt d'urgence.** Aujourd'hui, `make orodruin-kill` (`infra/orodruin/kill.py`) révoque
l'identité, annule les pannes, désalloue la VM et ferme les fenêtres. Pour le drill, deux trous :
- **il ne touche pas au démarrage planifié** (§5.1) : la semaine suivante, la Logic App rallumerait
  l'Orodruin tué ;
- **il retire à Orodruin l'écriture du canal** (la révocation) : `drill.json` resterait `armed`, et
  H0 lèverait `not_run` à tort.

DRL1a ajoute au kill un pas « drill », par l'identité de l'opérateur, après les quatre d'aujourd'hui :
1. **désactiver le démarrage planifié**, et le dire ; un échec est une erreur du kill (sortie 1),
   comme les autres pas ;
2. **écrire la pierre tombale** dans le canal (`orodruin/killed.json`, l'heure). L'opérateur y écrit
   déjà pour fermer les fenêtres (`channel_operator`, M-1) ;
3. **écrire `orodruin/drill.json`** à `disarmed`, raison `killed`.

H0 lit aussi la pierre tombale : une pierre tombale plus récente que `drill.json` vaut désarmé, même
si le troisième pas a échoué. Pas de `not_run` après un kill.

Le minuteur, lui, reste sur le disque d'Orodruin. Après un `make orodruin-lock` (l'apply du module,
qui repose les attributions révoquées) puis un démarrage, une occurrence lit la pierre tombale :
`killed`, rien ne part. Seul un réarmement de Jonathan relance, et réactive le démarrage planifié.
Le kill le dit dans sa sortie : « drill: scheduled start disabled; refused until re-armed ».

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
| **Orodruin reconstruit** (`orodruin-down`, puis `-up`) | le minuteur, l'armement et le registre étaient sur son disque : perdus. Le canal est détruit avec le module, `drill.json` avec lui. Rien ne joue, et rien ne le dit sur Orodruin | H0 garde sa dernière copie de `drill.json` : « Orodruin silent » quand elle a plus de 8 jours. DRL1a fait dire à `orodruin-down` : « drill armed: lost, re-arm after up » |
| **Le drill précédent pas fini**, ou une demande, une campagne, un run à la main en cours | le verrou est pris : `busy`, avec ce qui le tient ; jamais attendu, jamais rattrapé. Le registre n'est pas écrit : il se lit et s'écrit sous le verrou | H0 : alerte (sans mention si une demande de Jonathan le tenait) |
| **gondolin tenue par Glorfindel** (une isolation de la semaine passée, pas levée) | lue avant tout démarrage : sautée tout de suite (`isolated`), rien n'est démarré. Le drill ne lève jamais une isolation | H0 : alerte « target held since … » |
| **Le contrat passif** (droit changé, sortie rouverte, jeton Graph hors liste) | `passive` et ses codes | H0 : alerte, avec mention |
| **Un arrêt d'urgence** depuis l'armement | le démarrage planifié désactivé ; `drill.json` à `disarmed (killed)`, écrit par le kill ; une occurrence lancée malgré tout : `killed` | H0 : « disarmed by kill », sans `not_run` |
| **L'horloge d'Orodruin** dérive | `off_schedule` au-delà de 30 min ; le registre borne à une fois par 6 jours quoi qu'il arrive | H0 : alerte |
| **Le service dépasse `RuntimeMaxSec`** | arrêté (§3.1) : SIGTERM, la fenêtre fermée, le statut `stopped` ; SIGKILL 90 s après | H0 : alerte |

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
  `schedule`). Le lecteur du statut est exact (`exercise_request.STATUS_FIELDS`) : le champ y entre,
  optionnel, dans la même release. Un H0 plus ancien qu'Orodruin refuse ce statut, et l'occurrence
  est `unknown`, dite ;
- **`orodruin/drill.json`**, le pouls du drill : `armed` ou `disarmed` (et pourquoi : `killed`,
  `drill_changed`), le nom, l'empreinte, la prochaine occurrence, la dernière (son heure, son état,
  son code), le commit de l'image. Il est réécrit à l'armement, au désarmement et à chaque
  occurrence, refusée comprise. Après un kill, c'est l'opérateur qui l'écrit (§3.1).

H0 les tire, comme aujourd'hui (`pull_runs`, `runs/orodruin/`), chacun relu contre sa forme. Le lot
ajoute un lecteur exact pour `drill.json` et pour `killed.json`.

### 4.2 Le verdict d'une occurrence, et les alertes

**H0 juge chaque occurrence**, par le code, jamais par le modèle. Il croise trois choses :
- l'heure prévue, tirée de **sa propre copie** du drill (le dépôt, dans son image) ;
- `drill.json`, et la pierre tombale ;
- le statut de la demande, et le rapport de run.

| État | Ce qu'il veut dire | Alerte |
|---|---|---|
| `proven` | détectée, et la décision rattachée : une preuve, la règle de C1 | aucune ; une ligne dans le fil du drill, et la tuile de l'accueil |
| `missed` | la technique a joué, aucune détection, la fin d'attente signée par la watch | **oui, avec mention** : c'est une régression (`regressed` dans la matrice) |
| `unknown` | la mesure n'a pas pu conclure : canal coupé, détection refusée, Orodruin en retard | sans mention la première fois ; **deux de suite, avec mention** : la mesure est cassée |
| `refused` | avant tout appel : `passive`, `watch`, `not_placed`, `not_bench`, `busy`, `off_schedule`, `too_soon`, `killed`, `drill_changed` | oui. Avec mention pour `passive`, `not_placed`, `not_bench`, `off_schedule`, `too_soon`. Sans mention pour `drill_changed` et `killed`, attendus après une release ou un kill |
| `skipped` | le fil sauté : `isolated`, `not_ready` | oui |
| `stopped` | le service arrêté à `RuntimeMaxSec` | oui |
| `not_run` | `drill.json` dit le drill armé, aucune pierre tombale plus récente, et aucun statut pour l'occurrence 2 h après son heure ; ou `drill.json` vieux de plus de 8 jours (« Orodruin silent ») | **oui, avec mention** |

**L'alarme d'absence** (`not_run`) vit chez l'observateur. Orodruin éteint ne peut pas dire qu'il
n'a pas tourné. H0 ne l'arme que sur un `drill.json` qui dit `armed`, sans pierre tombale plus
récente : un drill jamais armé, désarmé par Jonathan, ou tué, n'alerte pas.

**Où.**
- **Dans la console** : une ligne « Weekly drill » sur la page de Dagorlad (la dernière occurrence,
  son état, la prochaine, l'armement), et les vues existantes : Runs, la matrice de couverture, la
  tuile de la dernière preuve (qui dit quand elle vient du drill, §1.1).
- **Dans Discord** : par le **bot de Glorfindel**, celui du produit, que H0 tient déjà, dans un fil à
  lui (« drill · banc-hebdo »). Le texte passe par `chat_text.py`, sans autre mention que le rôle
  configuré. Le jeton du bot de l'atelier ne va jamais sur H0, et Orodruin n'a pas de sortie vers
  Discord : ni l'un ni l'autre ne change (question 4).
- **La carte d'exercice** elle-même reste dans TO JUDGE, marquée, avec le verdict proposé de VP1
  (§8).

### 4.3 Comment la session « Banc » le lit

BRO1 donne à la session « Banc » le rôle **Lecteur Log Analytics sur le seul workspace du banc**.
Elle ne lit ni H0, ni le canal, ni Orodruin. Elle n'est donc pas un second lecteur du rapport de H0,
mais un **témoin indépendant**, qui relit dans le workspace ce qui aurait dû s'y écrire.

**La fenêtre qu'elle relit.** Elle ne connaît pas le T0 du fil (il est dans le canal) : elle prend
l'heure prévue par le `schedule`, de 5 min avant à 75 min après (le service, `RuntimeMaxSec`, plus
le délai d'`expectations/banc-hebdo.yaml`).

1. **La règle attendue, rejouée** : la requête KQL de la règle que nomment les attentes, prise dans
   le dépôt. Une règle porte son propre filtre relatif (`ago(…)`) : rejouée des heures après, elle
   exclurait l'occurrence et dirait « ne matche pas » à tort. Ses `ago(…)` sont donc réécrits pour
   remonter au début de la fenêtre, et la requête est bornée à la fenêtre, comme le fait
   `glorfindel/campaign_replay.py` (`would_have_caught`). Matche-t-elle sur la cible ? C'est la
   preuve que la détection *pouvait* se faire, sans H0.
2. **L'indice brut** : la ligne que la technique écrit (pour T1136.001, `new user: name=` en
   `auth`/`authpriv`, étiquetée `useradd`), sur la cible. Elle sépare « rien n'est arrivé » de « la
   règle ne voit plus ».
3. **Le Heartbeat de la cible** : allumée ou non, à l'heure.
4. **Le journal d'activité** (si AL1 l'envoie au workspace) : un Run Command, et un démarrage, dont
   l'appelant est l'identité d'Orodruin, à l'heure. Son identifiant vient de la configuration de la
   session, jamais du dépôt.

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
| **(b) recommandée** : démarrage planifié côté Azure | une Logic App (Consumption), avec sa propre identité managée. Elle démarre Orodruin à T − 20 min. Une extinction quotidienne d'Orodruin à 23:00 UTC (le planning DevTest, qui désalloue), comme le banc | environ 4 h 20 par semaine, quelques euros par mois | une identité de plus, qui ne peut qu'allumer Orodruin (§7) ; une ressource Terraform dans `infra/orodruin/` (DRL1c) ; l'extinction de 23:00 UTC vaut aussi les autres jours : elle protège d'un Orodruin oublié allumé la nuit, et coupe une session tardive de Jonathan (question 1) |
| (a) allumé en continu | rien de neuf | D2als_v6 : environ 61 € par mois, le chiffre de la VM de H0, de même taille ; environ 27 € en B2als_v2 si le quota le permet | l'hôte qui tient l'identité des injecteurs, allumé tout le temps : SSH ouvert à l'IP de l'opérateur seulement, sortie fermée, mais plus de temps exposé |
| (c) Jonathan l'allume | — | — | n'est plus un drill automatique : écartée |

**L'identité du démarrage planifié (b)** :
- un **rôle personnalisé** qui ne porte qu'une action, `Microsoft.Compute/virtualMachines/start/action` ;
- son `assignable_scopes` est le groupe d'Orodruin (`azurerm_resource_group.host`), jamais le banc ;
- il est attribué à l'identité de la Logic App **à la portée de la VM d'Orodruin** seule.

C'est une hypothèse à mesurer : l'action d'ARM de la Logic App peut demander aussi
`virtualMachines/read`. Si oui, on l'ajoute, à la même portée, et la mesure le dit.

**Son état.** Terraform la crée **désactivée**, et ignore ensuite son état
(`lifecycle { ignore_changes = [enabled] }`). Seuls `orodruin-drill-arm` l'active, et
`orodruin-drill-disarm` et le kill la désactivent, par l'identité de l'opérateur. Sans cela, un
`make orodruin-lock` après un kill la rallumerait.

**Les autres moyens, à comparer au banc** avant de choisir (certitude par la mesure) :
- un runbook Azure Automation : plus lourd (un compte, un runbook, un planning, une identité) ;
- `Microsoft.ComputeSchedule` (les actions planifiées sur des VM) : plus simple s'il existe dans la
  région ; sa disponibilité et son API restent à confirmer.

Avec (b), le démarrage planifié ne met pas à jour l'image (§3.2) : après une release, Jonathan lance
`make orodruin-start` ou `make orodruin-update` depuis son poste, comme il le fait déjà (OI3). Sinon,
H0 dit « Orodruin behind ». **À mesurer** : la Logic App, son identité, son rôle à la portée d'une
VM, le délai jusqu'à docker prêt.

### 5.2 Les VM du banc

gondolin s'éteint chaque jour à 23:00 UTC (le planning DevTest de Celebrimbor). Le drill la démarre
s'il le faut (§3.1, son droit `start` est déjà au contrat, sur chaque VM inscrite), et la laisse
s'éteindre à 23:00 UTC. L'occurrence à 19:00 UTC la garde donc allumée environ 4 h :
- assez pour la grâce de la fenêtre, la décision de la watch, et que Jonathan regarde le soir même ;
- peu pour le coût.

Un drill tôt le matin la garderait allumée 15 h. bree reste hors du drill : allumée en continu, mais
jamais inscrite, et elle porte la vraie charge de la pré-observation.

### 5.3 Ce que coûte une occurrence

| Poste | Ordre de grandeur, à mesurer |
|---|---|
| Orodruin, (b) | environ 4 h 20 de D2als_v6 par semaine |
| gondolin | environ 4 h de D2as_v6 par semaine, quand elle était éteinte |
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
2. Si (b) : appliquer DRL1c, le module d'Orodruin, son plan relu (`make orodruin-plan`, puis
   `make orodruin-lock`, qui en est l'apply). Aucun droit de plus pour l'identité d'Orodruin : le droit
   `start` est déjà au contrat (`injector_vm`, `infra/orodruin/main.tf`).
3. `make orodruin-drill-check DRILL=banc-hebdo TARGETS=gondolin`, à blanc.
4. `make orodruin-drill-arm DRILL=banc-hebdo TARGETS=gondolin`.
5. **La première occurrence** : celle du minuteur, à son heure, Jonathan présent (la console ouverte,
   `make orodruin-kill` à portée). Pas de lancement « tout de suite » : ce serait le chemin que le
   drill refuse (`off_schedule`).
6. Après chaque release qui change le drill (`drill_changed`) : relire, réarmer. Après chaque release
   tout court : mettre Orodruin à jour (OI3). Après une reconstruction d'Orodruin : réarmer.
7. Désarmer (`make orodruin-drill-disarm`), ou l'arrêt d'urgence, quand il le veut.

### 6.2 À mesurer au banc

1. Le minuteur part à l'heure, dans le conteneur durci. Le journal précède chaque appel, le démarrage
   de gondolin compris.
2. Le démarrage planifié (b) :
   - la Logic App allume Orodruin, avec le seul droit `start/action` (ou dit qu'il lui faut `read`) ;
   - son identité ne peut rien d'autre : une tentative sur une autre VM échoue ;
   - l'extinction de 23:00 UTC désalloue ;
   - un `make orodruin-lock` après une désactivation ne la réactive pas.
3. gondolin démarrée à froid par le drill :
   - le délai jusqu'au premier Heartbeat (le budget de 10 min tient-il ?) ;
   - la ligne Syslog d'une technique jouée juste après, perdue ou non ;
   - la latence de détection, à comparer aux 117–144 s mesurées sur une VM chaude.
4. L'alarme d'absence de H0 : Orodruin éteint à l'heure → `not_run` deux heures après.
5. H0 arrêté à l'heure → refus `watch` ; dit au retour de H0.
6. Un arrêt d'urgence :
   - le démarrage planifié désactivé, `drill.json` à `disarmed (killed)`, aucun `not_run` ;
   - l'occurrence suivante `killed`, même après `make orodruin-lock` et un démarrage à la main,
     jusqu'au réarmement.
7. Une release qui change le drill → `drill_changed`.
8. La session « Banc » (BRO1) : la règle rejouée, ses `ago(…)` réécrits, matche sur l'occurrence ;
   l'indice brut se lit.
9. Le coût réel d'une semaine : Orodruin, gondolin, les points de sauvegarde.
10. `OnCalendar` en UTC, et l'horloge d'Orodruin.
11. L'arrêt du service : `docker stop --time 90` sur un conteneur lancé avec `--init` ; la fenêtre
    fermée, le statut publié.

---

## 7. Le modèle de menace : une frontière de plus (proposée)

_Proposée ici, pas encore écrite dans [`modele-de-menace.md`](modele-de-menace.md). Le lot de code
l'y porte, en §8 du tableau des frontières, avec ses tests._

**8. Le minuteur d'Orodruin.** Jusqu'ici, chaque attaque sur le banc partait d'un geste humain : une
commande, une demande portée par SSH. Le minuteur en lance une sans geste à chaque fois.
- **De confiance** : l'opérateur qui arme ; l'image vérifiée ; l'hôte (root).
- **Ce qui traverse** : trois entrées décident (l'heure, l'armement, le drill de l'image). Ce qui
  vient du dehors (V1, la pierre tombale, l'état des cibles) ne peut que refuser. Vers le dehors
  partent les mêmes appels qu'une demande (le démarrage de la cible en plus), et les statuts publiés.

| | Menace | Ce qui la tiendrait |
|---|---|---|
| S | Quelqu'un fait jouer une attaque à Orodruin sans Jonathan : par H0, par le canal, par la console | Orodruin ne tire ni n'écoute rien. Seuls le drill de l'image, l'armement du disque et l'heure de l'horloge peuvent déclencher ; ce qui vient de H0 ou du canal (V1, la pierre tombale) ne peut que refuser |
| T | Le contenu du drill change : une PR, une release, une image | La PR relue ; l'image vérifiée à son envoi (CI3) ; l'empreinte du fichier entier, épinglée à l'armement : un drill changé est refusé jusqu'au réarmement de Jonathan |
| T | Le drill joue plus souvent que prévu : un `OnCalendar` réécrit, le service déclenché à la main, une horloge fausse | Une fois par 6 jours au plus (le registre, lu et écrit sous le verrou, écrit avant le jugement ; illisible, rien ne joue) ; l'heure dans les 30 min du `schedule` ; jamais rattrapé (`Persistent=false`) ; un run à la fois (le verrou) |
| E | Le drill atteint une VM hors du banc, ou joue une technique destructive | La zone `bench` exigée au jugement **et avant chaque fil** (`zones` rejugé dans `_recheck`), plus stricte que la règle de production ; le catalogue de l'image relu à chaque occurrence (implémentée, non destructive, bibliothèque publique) ; les cibles nommées à l'armement, jamais `all` ; puis toutes les gardes de DG-b et d'O0 |
| E | L'identité du démarrage planifié (b) | Un rôle personnalisé, une seule action (`start/action`), attribué à la portée de la VM d'Orodruin, assignable dans son seul groupe. Compromise, elle n'allume qu'Orodruin, dont le minuteur ne joue qu'à son heure et sous son contrat |
| R | Une occurrence sans trace | Le journal avant chaque appel, démarrage compris (O1), sur l'hôte et dans le canal (SEC5) ; le registre des occurrences ; `drill.json` ; l'alarme d'absence sur H0 |
| D | Un drill qui s'emballe, ou qui use le banc | Les trois plafonds ; `RuntimeMaxSec`, un arrêt qui ferme les fenêtres ; le nettoyage de l'atomic (le compte créé, retiré) ; les points de sauvegarde expirent à 30 jours |
| D | Le drill masque un vrai incident sur sa cible | La fenêtre ne marque que ses cibles, pour un temps borné (B2, H-1) ; une carte d'exercice reste devant l'opérateur, marquée ; VP1 propose, ne pose jamais. **Le calendrier est public** (le `schedule` est dans le dépôt) : quelqu'un sait à quelle heure, chaque semaine, ce que fait gondolin est d'abord lu comme un exercice. **Impact faible, assumé** : le banc seul, environ une heure par semaine, aucune donnée réelle, et c'est Jonathan qui juge la carte (question 7) |
| I | Ce que le drill publie | Ce que publient déjà les demandes : ni identifiant, ni cible, ni abonnement. Le nom du drill, son empreinte et ses heures sont ceux du dépôt public |
| S | Un verdict proposé forgé : une fenêtre ou un statut qui se dit du drill | H0 lit le drill dans **sa propre copie** (`load_file(…, SHIPPED)`), et les attentes dans son image, jamais dans le canal ; l'empreinte annoncée doit être celle de cette copie ; un verdict proposé n'est jamais compté (VP1) |
| D | Le minuteur repart après un arrêt d'urgence | Le kill désactive le démarrage planifié, écrit la pierre tombale et `drill.json` désarmé ; la pierre tombale est lue avant tout ; un apply ne réactive pas le démarrage planifié ; seul un réarmement relance |

**Ce qui resterait ouvert**, dit neutre :
- root sur Orodruin peut déjà lancer tout injecteur sous le contrat (la limite de DG-b) : le minuteur
  ne lui donne rien de plus. L'armement et le registre, sur son disque, sont à sa main ;
- la pierre tombale est dans un conteneur où Orodruin écrit. Elle évite une reprise par mégarde, pas
  celle d'un Orodruin compromis, qui n'en a pas besoin ;
- H0 en panne, aucune alerte sur l'instant : l'indicateur de la dernière preuve finit par le dire ;
- un Orodruin reconstruit perd minuteur et armement sans rien dire, jusqu'à « Orodruin silent ».

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
- **la décision** : le 31/10, un instantané recommandé à 35 %, sous le seuil de 0,7, escaladé ;
- **la carte** : dans TO JUDGE, marquée exercice (« ⚑ exercise · run … »).

**Ce que le mode de gondolin change.** gondolin est en `non_disruptive` (depuis le 01/11). Une
action autonome (`snapshot`, `isolate_vm`…) part seule **au-dessus du seuil de confiance**, et reste
une proposition escaladée **en dessous** (`docs/glorfindel.md`). Le modèle n'est pas déterministe :
une semaine, il peut isoler au-dessus du seuil. gondolin reste alors tenue jusqu'à ce que Jonathan
la libère. L'occurrence suivante est sautée (`isolated`), et c'est dit.

**Glorfindel reste aveugle.** Les attentes ne vont ni dans la fenêtre, ni dans la demande, ni dans
`_build_user_message()`, ni au modèle. Le lot ne touche à aucune des trois zones du prompt, et ne
demande donc pas le run de bout en bout. La source `exercise` ne baisse aucune garde : le label ne
sert qu'au rapport et à la carte, comme pour tout exercice.

DRL1a le prouve en étendant `tests/unit/test_dagorlad_blind.py`. Avec, présents sur l'hôte de la
watch :
- le statut de la demande avec son champ `drill` ;
- `runs/orodruin/drill.json` et `killed.json` ;
- `expectations/banc-hebdo.yaml` ;

le message de `_build_user_message()` reste identique, à l'octet, à celui d'avant. Un mutant le
garde (§9).

### 8.2 Ce que le drill déclare pour VP1

VP1 propose un verdict à une carte d'exercice qui correspond à la détection attendue : la bonne
règle, la bonne cible, dans la fenêtre. Il lit, **sur H0** :

| Ce qu'il compare | D'où il le lit |
|---|---|
| le drill | **sa copie dans l'image de H0**, par `drill.load_file(<image>/drills/<nom>.yaml, SHIPPED)`, jamais `drill.find` (qui préfère la couche de l'instance : un drill de la console du même nom prendrait sa place) ; son nom et son empreinte égaux à ceux du statut de la demande (`drill`) |
| la règle attendue | `expectations/<nom>.yaml`, dans l'image de H0, l'attente du fil au même rang et de la même expérience |
| le délai | `within_s` de l'attente, après le T0 du fil (l'heure de l'appel de l'atomic, le rapport du run) |
| la cible | la VM du fil : celle de la fenêtre (`targets`) **et** celle du rapport (`metrics.resource_id`), les deux égales |
| la fenêtre | début, fin, et 15 min de grâce (`GRACE_AFTER_S`) |
| le lien carte ↔ run | la carte est `exercise`, son `exercise_run` est ce run, ce run est un fil de cette demande (`metrics.request`) |

Il propose seulement si **tout** concorde, sur **une seule** carte par fil :
- la règle d'une carte est celle de l'attente ;
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
| **DRL1a** (Orodruin, cœur) | `schedule` dans le lecteur de drill ; `drills/banc-hebdo.yaml` ; `expectations/banc-hebdo.yaml` et son lecteur exact ; `COPY drills/` dans l'image des injecteurs (jamais `expectations/`), `COPY expectations/` dans celle de Glorfindel, et leur test ; `eregion_core/scheduled_drill.py` (l'armement, les gardes de §2.3, le verrou et son descripteur passé au runner, le registre sous le verrou, le démarrage de la cible et le Heartbeat, la demande, la pierre tombale, `drill.json`, le gestionnaire SIGTERM) ; le paramètre `zones` du runner, rejugé dans `_recheck` ; le champ `drill` du statut, optionnel dans son lecteur exact ; les cibles Make `orodruin-drill-check`, `-arm`, `-disarm` ; les unités systemd ; le pas « drill » du kill ; la ligne de `orodruin-down` ; le gestionnaire SIGTERM d'`annatar wire` (dit à la session Annatar) ; le test de CI drill ↔ attentes ↔ catalogue ↔ règles ; l'extension de `test_dagorlad_blind.py` | `eregion_core/`, `drills/`, `expectations/`, `annatar/Dockerfile`, `glorfindel/Dockerfile`, `annatar/cli.py`, `Makefile`, `infra/orodruin/kill.py` |
| **DRL1b** (H0) | le verdict de chaque occurrence, l'alarme d'absence, les alertes par le bot de Glorfindel, la ligne « Weekly drill » de la console, la tuile de la dernière preuve qui dit le drill ; les lecteurs exacts de `drill.json` et `killed.json` | `eregion_console/`, `glorfindel/` (le pull, le bot) |
| **DRL1c** (Terraform, si b) | la Logic App, créée désactivée et son état ignoré ; son identité ; son rôle personnalisé (`start/action` seul, assignable dans le groupe d'Orodruin, attribué à la VM d'Orodruin) ; l'extinction de 23:00 UTC | `infra/orodruin/` |
| VP1, BRO1 | ce qu'ils lisent du drill et des attentes (§4.3, §8.2) | leurs lots |

**Tests hermétiques** : faux `systemd`, fausse horloge, faux Azure, faux canal. Aucun appel Azure ni
au modèle, un `HOME` jetable.

**Mutants proposés** (la plage, à demander à l'Orchestre) :
- l'empreinte non comparée ;
- la zone `production` admise au jugement ;
- **la zone `production` admise au rejugement** (`zones` ignoré dans `_recheck`) ;
- une technique destructive, ou une panne, admise ;
- `too_soon` ou `off_schedule` sautés ;
- **le registre lu hors du verrou** ;
- le registre écrit avant `off_schedule` (un déclenchement à la main consomme la semaine) ;
- le descripteur du verrou non passé au runner (`busy` à chaque occurrence) ;
- la pierre tombale ignorée ;
- **le kill qui laisse le démarrage planifié actif** ;
- **le kill qui laisse `drill.json` à `armed`** (H0 lève `not_run`) ;
- l'apply de Terraform qui réactive le démarrage planifié ;
- le démarrage de la VM avant V1, avant le journal, ou avant la lecture de l'isolation ;
- le démarrage non compté dans le plafond rendu au runner ;
- une occurrence manquée rattrapée ;
- **`scheduled_drill` qui lit les attentes**, ou l'image des injecteurs qui les copie ;
- les attentes écrites dans la fenêtre ou dans la demande ;
- **`_build_user_message()` qui voit le drill** : son statut, `drill.json` ou les attentes ;
- `all` admis comme cible ;
- l'alarme d'absence armée sur un drill désarmé, ou tué ;
- le SIGTERM sans gestionnaire (la fenêtre reste ouverte) ;
- VP1 qui lit le drill par `drill.find`, ou qui propose sur une autre VM.

---

## 10. Questions pour Jonathan

Une à la fois, l'option recommandée d'abord.

1. **Allumer Orodruin à l'heure.**
   - **Recommandé : (b)**, un démarrage planifié (une Logic App) qui ne peut qu'allumer Orodruin :
     quelques euros par mois, une identité de plus, bornée. Avec deux conditions :
     - le kill et le désarmement le désactivent (question 6) ;
     - l'extinction quotidienne d'Orodruin à 23:00 UTC coupe aussi une session tardive de Jonathan
       sur Orodruin : il la relance, ou repousse l'extinction ce soir-là.
   - (a) Orodruin allumé en continu : environ 61 € par mois, rien de neuf à poser, plus de temps
     exposé.
2. **L'heure.** **Recommandé : le mardi à 19:00 UTC.**
   - Elle évite l'heure habituelle des releases (publiées le plus souvent l'après-midi, UTC), après
     lesquelles le CD redéploie H0 et Orodruin attend sa mise à jour.
   - Le soir à Paris, environ 4 h avant l'extinction des VM, et Jonathan peut regarder le soir même.
   - Autre choix : un matin en semaine, plus de VM allumée (environ 15 h), les alertes vues dans la
     journée.
3. **Le contenu.**
   - **Recommandé : T1136.001 seule en v1.** T1059.004 s'ajoute après la mesure d'AUD1, une technique
     de Stratus après ID1 ; chaque ajout est une PR, puis un réarmement. La rotation vient alors
     (§1.1).
   - La panne `vm-shutdown` chaque semaine : non. Elle éteint la cible, et une panne n'est pas une
     technique au sens de la décision.
4. **Où vont les alertes.** **Recommandé : le bot de Glorfindel**, dans un fil à lui : H0 le tient
   déjà, et le jeton de l'atelier ne va jamais sur H0. Autre choix : un webhook de l'atelier de plus
   sur H0, un secret de plus.
5. **Ce que couvre l'empreinte**, épinglée à l'armement.
   - **Recommandé : le fichier du drill entier**, octet pour octet (nom, description, `schedule`,
     fils), et pas les attentes, qui sont à part et n'attaquent pas. Simple, sans forme canonique à
     tenir. Une description corrigée demande un réarmement, rare. Un `schedule` changé doit de toute
     façon réarmer : `OnCalendar` en est tiré.
   - Autre choix : les fils seuls, dans une forme canonique. Moins de réarmements, une forme de plus
     à écrire et à tester, et `schedule` à ajouter quand même.
   - Le réarmement à chaque changement reste la règle dans les deux cas : c'est ce qui fait de « ce
     drill seul » une règle tenue par le code.
6. **Le kill désactive-t-il le démarrage planifié ?** **Recommandé : oui.** Sinon, un Orodruin tué
   est rallumé chaque semaine : sans droits, il ne joue rien, mais il ne peut rien publier, et
   `drill.json` reste figé. Le désarmement fait de même. Seul le réarmement le réactive. Autre
   choix : laisser la seule pierre tombale refuser (un Orodruin allumé pour rien chaque semaine).
7. **Le calendrier : public, ou dans l'armement ?**
   - **Recommandé : public**, dans le `schedule` du drill livré, et le risque dit au modèle de menace
     (ligne D, impact faible : le banc seul, environ une heure par semaine). H0 tire l'heure prévue de
     sa propre copie du drill, ce qui tient l'alarme d'absence sans rien croire d'Orodruin.
   - Autre choix : l'heure donnée à l'armement (`AT=…`), hors du dépôt. Elle ne serait plus publique,
     mais H0 devrait la lire dans `drill.json`, écrit par Orodruin : l'alarme d'absence dépendrait de
     l'acteur.

## Ce que ce document ne décide pas

- Rien n'est mesuré : les comportements d'Azure (la Logic App et le droit qu'il lui faut, le
  démarrage à froid, la latence, l'arrêt d'un conteneur sous `--init`) sont des hypothèses, à
  prouver au banc.
- Le format du verdict proposé et son registre sont à VP1. L'identité de la session « Banc » et la
  façon de la lui donner sont à BRO1.
- Les drills des instances d'un client (couche `instance`) ne se planifient pas, et n'ont pas
  d'attentes en v1 : seul un drill livré porte `schedule` et des attentes. Un client qui voudrait son
  propre drill hebdomadaire est une question pour la 1.x.
- La rotation de plusieurs drills (§1.1) est une suite, hors DRL1.
- Ni le jumeau ni la production : le drill est du banc seul. La sentinelle de production
  (`sentinelle`) reste une demande portée à la main.
