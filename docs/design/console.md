# La console d'Eregion

Conception du 26/10/2026, session War Room. **Décidé par Jonathan le 26/10**, question par question.
**UI-1 construit et déployé sur H0 le 26/10** (#209, #210, #212, #216) ; **UI-2 construit le 27/10** (#206), définitions décidées le 27/10.
Ce document sert aux sessions qui implémentent : le lot UI-1 (le socle, #205), le lot UI-2 (les cinq
indicateurs, #206), et le lot d'Annatar et de Gothmog qui vérifie, avant chaque run, que Glorfindel
tourne.

## 0. Décisions

| Question | Choix de Jonathan | Écarté |
|---|---|---|
| Organisation | **console Eregion, une section par agent** : Overview, Glorfindel, Annatar, Gothmog, Config | console Glorfindel à sections par question (Defense, Proof, Config) ; renommer seulement l'atelier |
| Page d'arrivée | **`/` = Overview**, l'accueil d'Eregion : les cinq indicateurs, les cartes à juger, le dernier run de chaque injecteur, la watch | `/` = Glorfindel |
| Navigation | **les noms seuls** ; le rôle au survol et dans le titre de chaque page | nom et rôle ; rôle seul |
| Commande et jeton | **`eregion console`** ; `glorfindel war-room` reste un alias caché. Jeton **`EREGION_CONSOLE_TOKEN`**, avec repli sur `GLORFINDEL_WARROOM_TOKEN` | `glorfindel console` ; ne rien changer |
| Code | **un paquet `eregion_console/`**, hors de `glorfindel/` | garder dans `glorfindel/` |
| Glorfindel et les injecteurs | **Glorfindel est toujours présent : c'est le produit de base. Annatar et Gothmog l'exigent**, et s'y ajoutent l'un, l'autre ou les deux. Dans un SaaS (1.x), ce seraient des packs | des injecteurs sans Glorfindel |
| Comment l'imposer | **vérifié avant d'agir**. Sans battement de la watch, Annatar et Gothmog refusent avant tout appel au cloud. `--without-glorfindel` permet un run de développement, et le rapport l'inscrit | règle produit seulement ; aucune dérogation |
| Sections affichées | **Glorfindel toujours. Annatar et Gothmog détectés automatiquement** ; `--sections` / `EREGION_CONSOLE_SECTIONS` l'emporte | toujours explicite ; toujours toutes |
| Injecteur absent | **onglet grisé**, qui mène à une page d'installation | onglet caché ; rien |
| Verdict | **seulement dans TO JUDGE**. La carte de la VM garde Approve & execute, Ack et Cmd, et un lien « to judge ▸ » | aux deux endroits |
| Heure | **UTC partout**, avec la mention « UTC » | heure locale ; les deux |
| Lots | **UI-1** : le socle, les sections modulaires et les corrections de doublons. **UI-2** : les cinq indicateurs. **Un lot Annatar et Gothmog** pour la vérification avant d'agir | un seul lot ; trois lots UI |

**Choisi par défaut, sans objection :**
- `/atelier` redirige vers `/`.
- L'API de l'atelier perd son préfixe (`/api/exercises`…). L'ancien redirige jusqu'à la 1.0.
- Le cookie `glorfindel_warroom` est gardé : il est invisible.
- Le service compose n'est renommé qu'en option, plus tard.
- Si Glorfindel n'est pas configuré, la console démarre sur une page qui dit quoi faire.
- Les techniques du catalogue vont dans Annatar, les pannes dans Gothmog.

## 1. Pourquoi

Le constat a été fait sur H0 (vraies données, par le tunnel, en lecture seule) et sur une instance
locale aux données fictives, à 1440 et 1600 px. Les captures restent hors du dépôt, parce que celles
de H0 portent l'abonnement du banc.

- **Les deux pages parlent de Glorfindel.** `/` montre ce qu'il fait sur le trafic réel. `/atelier`
  montre ce qu'il a fait pendant les exercices : ses cycles, ses cartes, ses décisions, le verdict de
  chaque run. Le nom « Atelier » et le sous-titre « Annatar · Gothmog » nomment les outils, pas ce
  qu'on y lit.
- **Trois noms d'application et deux langues dans un seul processus.**
  - Les noms : `Glorfindel — War Room` ; `Eregion — Atelier`, présentée comme une page enfant
    (« ◂ War Room ») ; la commande `glorfindel war-room`.
  - Les langues : la page du jeton est en français, l'interface en anglais.
  - Dans Glorfindel : « War Room Incidents » et « carte MONITORING » désignent des écrans qui
    n'existent plus.
- **Onze doublons et incohérences à l'écran**, que corrige UI-1 :
  1. la même carte trois fois, et un verdict possible à deux endroits ;
  2. une carte d'exercice sans lien vers son run, et un run dont l'identifiant n'apparaît qu'une
     fois la fenêtre dépliée ;
  3. deux horloges : `16:51 UTC` d'un côté, `17:51` local sans mention de l'autre ;
  4. deux battements de la watch, en deux mots ;
  5. « read only » avec deux sens : les droits Azure, et une page qui ne lance rien ;
  6. deux comptes côte à côte, « TO JUDGE · 3 » et « 2 cards » (le rapport écarte les exercices) ;
  7. tout le rapport d'observation sur une seule ligne d'en-tête ;
  8. un filtre « 30 days » alors que les fenêtres sont vidées après 7 jours : une preuve vieille de
     10 jours s'affiche « — » ;
  9. l'identifiant de la VM affiché avec l'abonnement ;
  10. une configuration qui n'est qu'une bascule, sans adresse ;
  11. des pages servies sans `Cache-Control`, restées en cache sur H0 (#197).
- **Un seul des cinq indicateurs de la finalité est affiché** : « isolate/block wrong », noyé dans
  l'en-tête.
- **Pas de port dédié.** Il coûterait un jeton, un tunnel et un conteneur de plus, et n'isolerait
  rien sur localhost : les cookies et SameSite ignorent le port.

## 2. Glorfindel toujours présent

- **Sans Glorfindel, les injecteurs n'ont pas de sens.** Annatar attaque sans savoir si l'attaque
  est vue, et Gothmog fait du chaos générique. C'est la finalité : « Annatar et Gothmog servent la
  confiance dans Glorfindel ; ils ne sont pas une fin. »
- **Dans un SaaS**, cela donne Glorfindel de base, avec des packs.
- **En open source**, rien ne se débloque : la règle vaut pour le produit, les profils et la
  console.

| Combinaison | Pour qui | Onglets actifs | Ce que la console dit de ce qui manque |
|---|---|---|---|
| Glorfindel | être défendu d'abord, en observation (« découvrir ») | Overview, Glorfindel, Config | « Proof: none yet » ; Annatar et Gothmog grisés, avec ce qu'ils ajouteraient |
| Glorfindel + Annatar | « ma détection marche-t-elle ? » | + Annatar | Gothmog grisé |
| Glorfindel + Gothmog | « mon infra tient-elle ? », et Glorfindel avec elle | + Gothmog | Annatar grisé |
| Tout | « défense éprouvée » (H0) | tous | — |

**À General.**
- Les profils de la 1.0 deviennent ces combinaisons.
- Dans D1, « chaque composant tourne seul » désigne une séparation technique (la CI, un adaptateur
  développé à part), pas un produit vendu seul.

### La vérification avant d'agir (lot Annatar et Gothmog)

**✅ Fait (V1, #214, 27/10)** : `eregion_core/watch_gate.py`, appelé par `annatar run`, chaque
run d'une campagne (et la campagne avant son premier run), `gothmog run` et `gothmog preflight` ;
tests `tests/unit/test_watch_gate.py` et `tests/unit/test_gothmog.py` ; mutants M720–M739. Le
rapport porte `metrics.without_glorfindel: true` et `metrics.detection_note` ; la console montre
« not measured, by choice » (`exercises.js`, et pour une campagne `overview.html`,
`injector.html`). Une campagne ainsi lancée le porte dans son manifeste, ne se reprend que de la
même façon et n'a pas de rapport d'analyse (M750–M759). Le canal retour fait foi s'il est
configuré, sinon le fichier local. Cibles Make d'Orodruin : `WITHOUT_GLORFINDEL=1`.

**Avant V1** : sans watch, Annatar avertissait (« no active glorfindel watch detected »), attaquait
quand même, et le run finissait en `detection: unknown`. Gothmog ne vérifiait rien.

**Depuis V1**, avant chaque run, campagnes comprises, et **avant tout appel au cloud** :
- Annatar et Gothmog lisent le battement de la watch : `watch_channel.alive(read_heartbeat())` sur
  le canal retour, ou le fichier local sur le même hôte.
- Sans battement, ils refusent, et disent depuis quand date le dernier.
- `--without-glorfindel` permet un run de développement. Le rapport l'inscrit (« detection not
  measured, by choice »), `run_report_refusal` l'accepte au tirage, et la console l'affiche à part
  de `unknown`.

**Mutants** : la vérification retirée ; la vérification placée après le premier appel ; la
dérogation absente du rapport — pour chaque injecteur (M720–M739, `docs/design/preuves.md`).

**Coût** : 1 à 1,5 jour, pour les sessions Annatar et Gothmog, avec Orodruin pour les cibles Make.

Le tirage des rapports reste dans la watch de Glorfindel, qui est toujours là.

## 3. La console

### Sections et adresses

```
/                        Overview           /?token=… once, then the cookie
/glorfindel              Glorfindel         ?card=<id> highlights that card in TO JUDGE
/annatar                 Annatar            ?run=<id> · ?campaign=<id>
/gothmog                 Gothmog            ?run=<id>
/config                  Config
/runs/<run_id>           → 302 to /annatar?run=… or /gothmog?run=…, by the injector of its window
/atelier[?…]             → 308 /[?…]
/api/exercises?injector=  /api/campaigns[/<id>]  /api/catalog?kind=  /api/channel[/detections/<id>]
                         GET only — the former /api/atelier/*, which redirects (308) until 1.0
/api/sections            GET: Glorfindel, and each injector active or greyed, and why
/api/* of Glorfindel     unchanged (state, to-judge, report, actions…)
```

### Règles

1. **Un registre de sections.** Chaque section déclare son identifiant, son libellé, son rôle (au
   survol et dans le titre), son test de disponibilité, ses routes, sa page et sa page
   d'installation. La console n'est qu'un registre, un en-tête commun et un accueil.
2. **Glorfindel est toujours actif.** S'il n'est pas encore configuré (ni `glorfindel-config.yaml`,
   ni état dans `~/.glorfindel/`, ni battement), sa page dit ce qu'il manque pour commencer.
3. **Annatar et Gothmog sont actifs** si `runs/` contient un rapport, une fenêtre ou une campagne de
   cet injecteur. Un canal des exercices configuré ne suffit pas : il ne dit pas lequel des deux
   tourne, et la page grisée le signale (« Found here »). C'est réévalué à chaque page, avec un
   cache de quelques secondes ; leurs routes ne font que lire.
4. **`--sections annatar` ou `EREGION_CONSOLE_SECTIONS`** fixe les injecteurs actifs, même sans
   données (« no run yet »). Glorfindel ne s'enlève pas.
5. **Un injecteur grisé** mène à sa page d'installation : ce qu'il ajoute, ce qu'il demande, comment
   l'ajouter, ce qui a été trouvé sur cet hôte. Dans un SaaS, cette page présenterait le pack.
6. **L'accueil** a la ligne de Glorfindel, puis une ligne par injecteur, actif ou grisé. Le bandeau
   d'observation y figure, comme sur Glorfindel : c'est la première page vue.
7. **Config** est une page : Azure, le bloc de Glorfindel (modèle, autonomie), et les canaux si un
   injecteur est actif.
8. **L'en-tête commun** (`console.js`, `console.css`), le même sur toutes les pages : à gauche les
   onglets (le nombre de cartes à juger sur celui de Glorfindel) ; à droite le battement de la watch,
   le canal retour si un injecteur est actif, ⚙ Config (à droite, comme dans la War Room) et
   l'horloge en UTC. Ce qui n'appartient qu'à une page reste dans la page : le point « live » du
   fil est sur la colonne LIVE FEED (Jonathan, 26/10).
9. **Les corrections du §1** :
   - le verdict seulement dans TO JUDGE ;
   - les liens carte ↔ run dans les deux sens ;
   - « read-only » réservé aux droits Azure, et les pages d'injecteurs qui disent « This page never
     launches a run » ;
   - les comptes sur l'accueil, chacun avec son sens ;
   - le filtre des fenêtres borné à 7 jours (les campagnes gardent 30 jours et « all ») ;
   - le nom de la VM, avec l'identifiant au survol ;
   - `Cache-Control: no-cache` sur les pages ;
   - la page du jeton en anglais.

### Les cinq indicateurs (UI-2, #206)

Ils sont en tête de l'accueil, au-dessus des lignes des sections. Leur source est
`GET /api/indicators`, calculée par `eregion_console/indicators.py`.

**Sur 30 jours, à partir de ce que l'hôte garde** : les rapports de run (`runs/<id>.json`, et ceux
des campagnes publiées), les cycles de la watch (`runs/*_debug.jsonl`), les cartes avec leurs
verdicts, et le catalogue. Jamais à partir des fenêtres d'exercice, vidées 7 jours après leur fin.

**La décision d'un run** est l'enregistrement de la watch pour la détection que le run a comptée :
- même technique ;
- vu à l'heure de l'attaque plus la latence mesurée par le run, à 5 secondes près.

Le rapport d'un run ne nomme pas sa VM, et sa fenêtre a disparu après une semaine. Mais cette
latence, Annatar l'a mesurée sur ce même enregistrement.

**Rien n'est inventé** : ce qui ne se mesure pas vaut `None`, et la case dit pourquoi.

**Définitions décidées par Jonathan le 27/10**, question par question :

| Indicateur | Ce qui s'affiche | En observation (`human_only`) |
|---|---|---|
| Temps pour contenir | de l'attaque à l'action vérifiée, médiane de ce que Glorfindel a contenu seul ; à côté, les médianes de la détection et de la décision, sur les attaques détectées | « — nothing contained alone », avec la détection et la décision |
| Part contenue seule | les isolations et blocages exécutés et vérifiés seuls, parmi les attaques détectées ; à côté, la part **shadow** : les attaques où Glorfindel a recommandé d'isoler ou de bloquer au-dessus du seuil de confiance, sans verdict « wrong » | « 0 of N », et « shadow: K of N would have been » |
| Actions disruptives à tort | isolations et blocages jugés faux parmi ceux jugés, sur le trafic réel, exercices écartés (`observation_report`) ; 30 jours, les 7 jours du résumé du lundi à côté | — |
| Couverture | les techniques détectées par un run d'attaque, sur les implémentées, puis sur tout le catalogue (prévues comprises) ; les pannes à part (runs, PASS) | — |
| Âge de la dernière preuve | le plus récent run d'attaque détecté **et** dont la décision est rattachée (détection et réponse) ; vert sous 21 jours, jaune jusqu'à 30, rouge au-delà ou aucune ; au survol, chaque technique, la moins récemment prouvée d'abord | — |

**Sans injecteur**, la couverture et la dernière preuve disent qu'il n'y a rien sur 30 jours.

**Plus loin** : la matrice de C1 trouvera sa place dans Annatar et dans Gothmog, avec son résumé sur
l'accueil.

## 4. Maquettes

Les valeurs sont illustratives. L'onglet actif est entre crochets, l'onglet grisé entre `░`.

**Overview, tous les composants**

```
EREGION  [Overview]  Glorfindel 3  Annatar  Gothmog    ● watch · 12s ago  ● return channel · 18s ago  ⚙ Config  16:51 UTC
────────────────────────────────────────────────────────────────────────────────────────────────────────────
Observation — Glorfindel detects and recommends; nothing is executed. The mode is locked to human-only by
the deployment (read-only credentials), not by this page.
────────────────────────────────────────────────────────────────────────────────────────────────────────────
┄┄ UI-2 ┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄
 TIME TO CONTAIN      CONTAINED ALONE     WRONG DISRUPTIVE    COVERAGE · 30 d     LAST PROOF
 — human-only         — observation       0% of 13 judged     5 / 6 detected      2h ago · T1136.001
 detect 1m47 · decide 2m05 (median, 7)    real traffic, 7 d   faults: 1, held     ✓ under 30 days
┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄
GLORFINDEL   3 to judge ▸            wrong 0% of 13 judged (7 d)          mode OBSERVE-ONLY · human-only
ANNATAR      last run   T1136.001 account-creation   2h ago   PASS · detected +2m09 → snapshot 40%, held ▸
             last campaign   20261023T081120Z   4/4 executed · 4 detected ▸
GOTHMOG      last run   vm-shutdown   1h ago   PASS · nothing disruptive, as expected ▸
CHANNELS     exercise channel on · newest window 1h05 ago · live windows: none · published beat 18s ago
```

**Overview, Glorfindel seul**

```
EREGION  [Overview]  Glorfindel 3  ░Annatar░  ░Gothmog░                 ● watch · 12s ago  ⚙ Config  16:51 UTC
────────────────────────────────────────────────────────────────────────────────────────────────────────────
GLORFINDEL   3 to judge ▸            wrong 0% of 13 judged (7 d)          mode OBSERVE-ONLY · human-only
ANNATAR      not set up — no attack has tested Glorfindel here (what it adds ▸)
GOTHMOG      not set up — no fault has tested Glorfindel here (what it adds ▸)
PROOF        none yet: Glorfindel's detection and response are unproven on this infrastructure
```

**Page d'installation, `/annatar` grisé**

```
ANNATAR — attacks run against Glorfindel                                                 not set up here
What it adds    Proof that Glorfindel detects real techniques: each attack, when Glorfindel saw it and
                what it decided, and the coverage of the catalogue.
What it needs   Glorfindel's watch running (it measures the detection); Orodruin, armed; target VMs
                enrolled (eregion-target, eregion-zone); the exercise channel to this host.
How             Guide ▸   then, on Orodruin: annatar run <scenario>
Found here      no Annatar run, window or campaign in runs/; no exercise channel configured.
                To show this section anyway: eregion console --sections annatar
```

**Glorfindel, `/glorfindel`**

```
EREGION  Overview  [Glorfindel 3]  Annatar  Gothmog    ● watch · 12s ago  ● return channel · 18s ago  ⚙ Config  16:51 UTC
────────────────────────────────────────────────────────────────────────────────────────────────────────────
Observation — Glorfindel detects and recommends; nothing is executed. …
────────────────────────────────────────────────────────────────────────────────────────────────────────────
TO JUDGE · 3                         │ INFRASTRUCTURE                         mode OBSERVE-ONLY · human-only
 Block 203.0.113.7:22  82%    2m ago │           DETECT       PROTECT       RECOVER
 vm-…-bree · ssh-brute-force · T1110 │    ┌ vm-celebrimbor-bree ───────┐ ┌ vm-celebrimbor-gondolin ───┐
 [note……]  ✓ Right  ✗ Wrong  ? Unsure│    │ HUMAN-ONLY          ✓✓✓✓   │ │ HUMAN-ONLY  EXERCISE       │
 Snapshot  40%               17s ago │    │ Block IP 82% — pending     │ │ Snapshot 40%               │
 ⚑ exercise · run …150000Z ▸ annatar │    │ ▸ Approve & execute   Ack  │ │ Ack   Cmd     to judge ▸   │
 [note……]  ✓ Right  ✗ Wrong  ? Unsure│    │ Cmd             to judge ▸ │ └────────────────────────────┘
LIVE FEED ● live                     │    └────────────────────────────┘
```

**Annatar, `/annatar`** (Gothmog suit le même plan, avec FAULTS et le tableau des sondes avant et
après)

```
EREGION  Overview  Glorfindel 3  [Annatar]  Gothmog    ● watch · 12s ago  ● return channel · 18s ago  ⚙ Config  16:51 UTC
────────────────────────────────────────────────────────────────────────────────────────────────────────────
ANNATAR — attacks run from Orodruin, armed, and what Glorfindel did. This page never launches a run.
EXERCISES · 11          windows [7 days ▾] │ CAMPAIGNS · 1    [30 days ▾] │ TECHNIQUES · 5 implemented
▾ CLOSED T1136.001 account-creation 16:31  │ ▸ DONE 20261023T081120Z      │ T1041      detected    3d
  ⚔ detected +2m09 → snapshot 40%          │   4/4 executed · 4 detected  │ T1110.001  detected    3d
    held (human_only)          1 card ▸    │                              │ T1136.001  detected    2h
  WINDOW run 20261026T153109Z → vm-…-gondolin                             │ T1486      —
  GLORFINDEL 1 cycle … · CARDS 16:34 low_confidence ▸ · RUN REPORT PASS   │
```

## 5. Plan

### Ce qui change

| Où | Changement | Qui |
|---|---|---|
| `eregion_console/` | `api.py` (l'ancien `glorfindel/api.py`, déplacé tel quel puis complété : pages, redirections, jeton, `/api/sections`) ; `sections.py` (le registre) ; `cli.py` (`eregion console [--sections]`) ; `static/` : `overview.html`, `glorfindel.html` (ex-`index.html`, sert aussi `/config`), `injector.html` (ex-`atelier.html`, une seule page pour Annatar et Gothmog, filtrée par le chemin, qui montre aussi la vue « non installé »), `exercises.js`, `console.js`, `console.css`. Un module par section reste possible plus tard : comme Glorfindel est toujours là, aucune route n'a besoin d'être enregistrée sous condition | War Room |
| Jeton | `EREGION_CONSOLE_TOKEN` s'il n'est pas vide, sinon `GLORFINDEL_WARROOM_TOKEN` ; avertissement si les deux diffèrent. Cookie inchangé | War Room |
| Dans la même PR, hors périmètre | `pyproject.toml` : le paquet, le script `eregion`, l'extra `console` (`war-room` gardé), les pages en données du paquet (aucune n'est déclarée aujourd'hui : un `pip install` sans `-e` les perdrait). Le Dockerfile de Glorfindel : `COPY eregion_console/`. Depuis M-3, il installe les dépendances verrouillées (`requirements/glorfindel.txt`, avec FastAPI et uvicorn), puis le paquet sans dépendances : l'extra `console` reprend celles de `war-room`, à vérifier contre le verrou. `docker-compose.yml` : le montage de `static` et la commande. L'import de `glorfindel/cli.py`. Les imports des tests et de `scripts/mutation_check.py`, dont 5 mutants visent `glorfindel/api.py` | War Room, avec l'accord de General et de Glorfindel |
| Glorfindel (UI-1b) | l'alias caché `glorfindel war-room` ; les textes « War Room » d'`agent.py`, `readiness.py` et `jobs.py`. Vérifier qu'aucun n'entre dans ce que voit le modèle | Glorfindel |
| General (UI-1c) | Makefile, `status.sh`, `host_env.py`, `host.env.example` (les deux noms du jeton) ; `CLAUDE.md` (table des sessions, index des docs) et le fichier de rôle (une session « Console » ?) ; profils de la 1.0 et D1 dans la feuille de route ; doc hors console | General |
| Plus tard (UI-1d) | le service compose `console`, nommé aussi dans `infra/glorfindel-host/deploy.sh` (`up -d watch war-room bot`) et `status.sh` ; la sortie Terraform `war_room_tunnel` au prochain apply de H0 | General et Jonathan |
| Doc | README, `docs/glorfindel.md`, `operations.md`, `fichiers-cles.md`, `architecture.md`, `azure.md`, `design/preuves.md`, `observation.md`, `infra/glorfindel-host/README.md`. Le CHANGELOG passé et `historique.md` restent tels quels | War Room pour la console, General pour le reste |

### Pièges

- **L'alias du jeton.** Compose passe `${VAR:-}` : la variable est toujours définie, vide si elle
  n'est pas posée. Une lecture « la nouvelle si elle existe » couperait le jeton sur H0. La règle
  est : la nouvelle si elle n'est pas vide.
- **Le service compose renommé.** L'ancien conteneur garde `127.0.0.1:7007`, et le nouveau ne démarre
  pas. Il faut `up -d --remove-orphans` une fois, mesuré en local d'abord. D'où UI-1d, à part.
- **Les branches ouvertes.** Le déplacement d'`api.py` entre en conflit avec toute branche qui le
  touche. Aucune n'était ouverte le 26/10 : il faut revérifier avant UI-1.
- **L'ordre des lots.** Avant le lot de la vérification avant d'agir, un run peut encore partir sans
  watch et finir en `unknown`. UI-1 l'affiche comme aujourd'hui.

### Tests et mutants d'UI-1

**Redirections et jeton**
- `/atelier?since=30d` → `/?since=30d` ; `/api/atelier/exercises?since=7d` →
  `/api/exercises?since=7d`.
- `/runs/<id>` mène à la section de son injecteur, et refuse `..`.
- Chaque page est derrière le jeton : une page 401 pour un navigateur, un 401 JSON sinon.
- Les routes d'exercices, de campagnes, du catalogue et des canaux sont des GET.
- Le jeton : sous son nouveau nom, sous l'ancien, une nouvelle variable vide avec l'ancienne posée,
  et les deux qui diffèrent.

**Sections**
- Glorfindel reste actif sans configuration, et `--sections annatar` ne l'enlève pas.
- La disponibilité suit l'injecteur des fichiers de `runs/`.
- `--sections` l'emporte sur la détection.

**Commande et rendu**
- `eregion console --help` répond, et `glorfindel war-room` appelle toujours `serve`.
- Rendu dans Chromium headless à 1440 et 1600 px : chaque page, avec et sans données, pour trois
  combinaisons (tout, Glorfindel seul, Glorfindel + un injecteur). C'est la leçon de #198.

**Mutants M400–M407**
- M400 : `/atelier` ne redirige plus.
- M401 : la redirection de l'API perd la requête.
- M402 : une nouvelle variable vide coupe le jeton.
- M403 : une route d'exercices accepte POST.
- M404 : une nouvelle page échappe au jeton.
- M405 : `/runs/<id>` accepte `..`.
- M406 : `--sections` enlève Glorfindel.
- M407 : `--sections` est ignoré.

### Lots et ordre

| Lot | Qui | Jours |
|---|---|---|
| UI-1 (#205) : le socle, les sections modulaires, les corrections | War Room | 4 à 5,5 |
| UI-1b : l'alias, les textes | Glorfindel | 0,25 |
| UI-1c : le déploiement, `CLAUDE.md`, la feuille de route | General | 0,5 |
| La vérification avant d'agir | Annatar, Gothmog | 1 à 1,5 |
| UI-2 (#206) : les cinq indicateurs | War Room, avec General et Glorfindel pour les définitions | 2 à 3 |
| UI-1d, optionnel | General et Jonathan | 0,25 |

- UI-1 se déploie seul : sur H0, la détection voit tous les composants, et l'alias du jeton suffit.
- Les autres lots sont indépendants, sauf UI-2, qui suit UI-1.
- H0 est en pré-observation jusqu'au 13/11 environ. Chaque redéploiement se fait avec Jonathan,
  `.envrc` chargé, sur une référence épinglée (`make glorfindel-host-start REF=<commit>`, M-3).

## 6. Hors périmètre

- **La place de TO JUDGE** sur la page Glorfindel : à revoir à l'usage.
- **Les boutons de lancement** : par le contrat d'Orodruin, jamais par une route de la console.
- **Les rôles** : avec le multi-opérateur.
- **Un statut d'Orodruin** : le registre lui garde une place.
- **Les packs d'un SaaS** : la page d'installation en est l'emplacement.
- **Une Content-Security-Policy** : à mesurer, car les `onclick` en ligne la limitent.
  `frame-ancestors 'none'` et `connect-src 'self'` serviraient dès maintenant.
