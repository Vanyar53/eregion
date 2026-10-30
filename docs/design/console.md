# La console d'Eregion

Conception du 26/10/2026, session War Room. **Décidé par Jonathan le 26/10**, question par question.
**UI-1 construit et déployé sur H0 le 26/10** (#209, #210, #212, #216) ; **UI-2 construit le 27/10** (#206), définitions décidées le 27/10.
**Dagorlad (§7) : conception du 30/10**, ses trois questions tranchées par Jonathan le 30/10 ; **le Board construit le 30/10** (DG-a, première partie).
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
| Carte sur un NSG (#248) | **une tuile NSG**, dans la rangée des VM : son nom, son groupe de ressources, ses cartes ; ni mode, ni sauvegarde, ni Snapshot | sous le nœud PROTECT ; garder la tuile de VM |
| Ce que Glorfindel a fait seul (#248) | **une ligne verte sur la tuile, 24 h** : la note d'une carte qu'il a résolue lui-même (A3 : règle orpheline retirée) | dans le fil en direct ; rien dans la console |

**Choisi par défaut, sans objection :**
- `/atelier` redirige vers `/`.
- L'API de l'atelier perd son préfixe (`/api/exercises`…). L'ancien redirige jusqu'à la 1.0.
- Le cookie s'appelait encore `glorfindel_warroom` après le renommage (il est invisible) ; SEC1 l'a remplacé par `eregion_console_<port>`, une session dérivée du jeton : l'ancien n'est plus lu.
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
8. **L'en-tête commun** (`console.js`, `console.css`), le même sur toutes les pages : à gauche le
   logo et, à côté, ce qui tourne (le tag déployé, sinon la version et le commit court ; `EREGION_REF`
   et `EREGION_REVISION` passés au build par `deploy.sh`), puis les onglets (le nombre de cartes à juger sur celui de Glorfindel) ; à droite le battement de la watch,
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
| Temps pour contenir | de l'attaque à l'action vérifiée — sa relecture sur Azure, `outcome.verified_at` depuis BL1 —, médiane de ce que Glorfindel a contenu seul ; à côté, les médianes de la détection et de la décision, sur les attaques détectées | « — nothing contained alone », avec la détection et la décision |
| Part contenue seule | les isolations et blocages exécutés dans le cycle, vérifiés et qui ont tenu (la définition de BL1, `analysis/containment.py`), parmi les attaques détectées ; à côté, la part **shadow** : les attaques où Glorfindel a recommandé d'isoler ou de bloquer au-dessus du seuil de confiance, sans verdict « wrong » ; le nombre de runs d'attaque de la période, ratés compris ; les pannes prises pour une attaque (une décision d'isoler ou de bloquer sur la VM d'une panne, pendant elle), en rouge | « 0 of N », et « shadow: K of N would have been » |
| Actions disruptives à tort | isolations et blocages jugés faux parmi ceux jugés, sur le trafic réel, exercices écartés (`observation_report`) ; 30 jours, les 7 jours du résumé du lundi à côté | — |
| Couverture | les techniques détectées par un run d'attaque, sur les implémentées, puis sur tout le catalogue (prévues comprises) ; les pannes à part (runs, PASS) | — |
| Âge de la dernière preuve | le plus récent run d'attaque détecté **et** dont la décision est rattachée (détection et réponse) ; vert sous 21 jours, jaune jusqu'à 30, rouge au-delà ou aucune ; au survol, chaque technique, la moins récemment prouvée d'abord | — |

**Sans injecteur**, la couverture et la dernière preuve disent qu'il n'y a rien sur 30 jours.

**La matrice de C1 (#80, 30/10)** a trouvé sa place dans Annatar et dans Gothmog, avec son résumé
sur l'accueil. La colonne de droite de chaque page (« COVERAGE · TECHNIQUES », « COVERAGE ·
FAULTS ») est la matrice (`GET /api/coverage?kind=…`, `eregion_console/coverage.py`) : une ligne
par entrée du catalogue, ses derniers résultats (✓ ✗ ? ·), l'âge de sa dernière preuve, son état ;
en tête, l'évolution sur douze semaines. Une ligne ouverte donne le dernier run et la dernière
preuve (date, détecté ou non, temps de détection, décision, temps pour contenir). Une technique
prouvée avant et ratée depuis est rouge (`REGRESSED`) : c'est la non-régression. Sur l'accueil,
la couverture dit les régressions (rouge, lien vers la page) et les preuves périmées ; l'âge de la
dernière preuve se lit désormais sur toute l'histoire que l'hôte garde — au-delà de 30 jours il
est dit, rouge, au lieu de « none in 30 d ». Les fenêtres ne servent pas : la matrice lit les
rapports de run, gardés, et les cycles de la watch. Détail : `docs/glorfindel.md`, « Matrice de
couverture » ; le run au format commun : `docs/architecture.md`, « Le run, unifié ».

### Les cartes (#248)

Après I1F, AL1, C2 et A3 (27/10) :
- **Chaque type de carte a un libellé** (`ESC_LABELS`) et, s'il n'est pas lié à une action, un titre
  (`_ESC_TITLES`) : `quarantine_altered`, `control_plane_change`, `identity_change`, `posture_gap`.
  Un test le vérifie contre `escalations._ESCALATION_LABELS`.
- **Une carte ancrée** (`control_plane_change`, `identity_change`, `unattributed_signal`, les
  `_ANCHORED_TYPES` du bot) porte sur une VM que la détection ne nomme pas. Elle n'a ni « 🔄 Restore »
  ni commande visant cette VM (seulement `glorfindel ack`), et la console dit « ⚓ filed on …, not about
  it ».
- **Détection seule** (AL1, C2) : la décision vient du code, sans action ni confiance. La carte et
  TO JUDGE donnent son titre, sa règle et sa sévérité (`critical` en rouge) ; le fil dit « escalate →
  control plane » (`held_by` de la ligne de debug).
- **TO JUDGE laisse de côté** les cartes qui ne sont pas des décisions, comme Glorfindel
  (`escalations._NOT_DECISIONS`, quarantaine modifiée comprise).
- **Une tuile NSG** pour une carte dont la ressource est un NSG ; seul PROTECT la relie, et elle ne
  compte pas parmi les VM « unprotected » de RECOVER.
- **`/api/state` donne `handled`** : les cartes résolues avec une note dans les dernières 24 h. Une carte
  qu'un humain acquitte n'a pas de note et n'y figure pas. Limite : une carte que Glorfindel ferme parce
  que la règle n'est plus orpheline (souvent un humain qui a lancé la commande de la carte) y figure aussi ;
  la note dit laquelle.
- **Le détail d'une carte échappe tout ce qui vient d'Azure ou du modèle** (raison, étapes, requête
  proposée) : un nom d'application Entra ID ou de règle NSG choisi par un attaquant ne s'exécute pas dans la page.

**Mutants M570–M575** (`tests/unit/test_console.py`) :
- M570 : un type sans libellé.
- M571 : une carte du plan de contrôle retrouve Restore.
- M572 : la quarantaine modifiée demande un verdict.
- M573 : le fil perd `held_by`.
- M574 : une résolution reste sur la tuile au-delà de 24 h.
- M575 : un acquittement passe pour un geste de Glorfindel.

### Ce qui vient du dehors (#254)

Une carte, une règle, une ligne du fil, une erreur : du texte d'Azure (le nom d'une ressource, d'une
application Entra ID), du modèle, d'une règle, ou d'un rapport de run tiré du canal d'exercice (un hôte
moins sûr que la console). Écrit brut dans `innerHTML`, il s'exécute dans la console et peut appeler ses
routes. Deux défenses : l'échappement (#254), et la CSP `script-src 'self'` (#257), qui refuse tout script
que la console n'a pas servi en fichier.

- **Rien du dehors n'est écrit brut**, nombres compris : le serveur relaie des rapports dont le type
  n'est pas garanti. Dans le texte de la page ou un attribut entre guillemets doubles : `_attr`
  (glorfindel.js) ou `esc` (`Console.esc`, les autres pages) ; `_attr` accepte toute valeur
  (`String(s ?? '')`) et échappe `& " ' < >`.
- **Aucun gestionnaire `on…` ni script en ligne** (#257) : les scripts des pages sont des fichiers
  (`glorfindel.js`, `overview.js`, `injector.js`, après `console.js` et `exercises.js`). Un élément
  nomme son action : `${_on('click', 'showEscModal', vm)}` écrit `data-on-click="showEscModal"` et ses
  arguments en JSON dans `data-click-args`, échappés par `_attr`. Un écouteur par événement, sur le
  document et en phase de capture, appelle l'action dans `ACTIONS`, une table fermée (un nom qui n'y
  est pas ne fait rien, jamais `window[nom]`). L'élément le plus proche prend l'événement, comme le
  faisait `event.stopPropagation()` pour un bouton dans une carte ; `data-on-click="stop"` sert aux
  éléments qui ne faisaient que l'arrêter. Le glisser-déposer et le survol des NSG passent par le même
  chemin (`dragVm`, `dropOn`, `_glowNsgVms`…). `_js` a disparu : un argument n'est plus du JavaScript.
  Le nom d'une action est toujours un littéral de la page : la valeur d'un `data-on-*` n'admet rien
  d'autre (ni une donnée, ni une donnée échappée), et `setAttribute`/`dataset` ne l'écrivent pas.
- **Ce que la CSP laisse** : un élément injecté malgré tout, avec un `data-on-click` qui nomme une action
  de la table, s'exécute (vu dans Chromium : `<b data-on-click="refreshBackups">`). Il ne peut faire que ce
  que fait un bouton de la page, et le répartiteur borne ce que l'élément porte :
  - les arguments sont des chaînes, des nombres, des booléens ou `null`, jamais un objet — sinon
    `doApproveAction(id, vm, {scope, ip})` sauterait la fenêtre de portée ;
  - le mode d'une VM ou le mode par défaut ne se lit que dans un `<select>` de la page
    (`modeChange`, `defaultMode`) ;
  - les gestes qui écrivent gardent leur confirmation ou passent par le serveur, qui refuse en lecture
    seule et refuse une carte trop vieille ou non attribuée.

  L'échappement reste la première défense ; la CSP retire seulement l'exécution de code.
- **La CSP** : `script-src 'self'; object-src 'none'` en plus de #222. Une `<img onerror>` injectée de
  force, au-delà de tout échappement, ne s'exécute plus. Les styles en ligne restent permis : une
  injection de style est bien moins grave, et `style="…${_attr(x)}"` n'en sort pas.
- **Le début d'une URL** (`href="${…}"`, et après un `/` de tête : `/${x}` avec x = `/hôte` mène à un
  autre site) ne prend que `encodeURIComponent` : un `javascript:` échappé en HTML en reste un. Un
  attribut s'écrit entre guillemets doubles ; `srcdoc` ne prend aucune valeur.
- **`scripts/console_escaping.py` le vérifie** (`python scripts/console_escaping.py` : où, quoi, d'où).
  Il lit les scripts de chaque page et suit ce que peut contenir chaque `${…}` d'un gabarit HTML et
  chaque valeur donnée à `innerHTML`. Il suit les branches d'un ternaire, `||` et `+`, une variable
  jusqu'à sa déclaration et ses affectations, un `push` ou une `Map`, une fonction de la page jusqu'à
  ses `return`, un paramètre jusqu'aux arguments de ses appels ou aux éléments de son tableau
  (`.map`). Le champ d'un objet que la page a écrit est lu par sa clé. Une valeur est propre quand
  c'est un littéral, un nombre calculé, une table de la page ou un échappement reconnu par sa
  déclaration (une variable locale nommée `esc` n'en est pas un). Le reste est brut : un champ de ce
  qu'a envoyé le serveur, l'argument d'un callback ou d'une fonction d'`ACTIONS`, une erreur, la barre
  d'adresse. Un `.length` n'est un nombre que sur un tableau, une chaîne ou un `Set` que la page a faits :
  d'un objet du serveur, il passe par `Number(…)`. Une concaténation se lit comme un gabarit : la place
  d'une valeur se déduit des chaînes avant elle.
  Il refuse aussi, où qu'ils soient écrits : un gestionnaire `on…`, un `<script>`, une URL
  `javascript:`, `srcdoc`, et les API qui écrivent du HTML ou du code hors d'`innerHTML` et qu'il ne
  suit pas (`document.write`, `el['innerHTML']`, `Object.assign(el, {innerHTML})`,
  `createContextualFragment`, `DOMParser`, `setAttribute` d'un gestionnaire ou d'une URL, `.href =`,
  `eval`, `new Function`, une chaîne donnée à `setTimeout`). Il compte les `${…}` qu'il lit, et le test
  les compare à un décompte fait à part : un gabarit sauté ne passe pas inaperçu.
  `ALLOWED` nomme, avec sa raison, ce que le lecteur ne sait pas suivre ; il est vide.
- **Vérifié dans Chromium** (28/10) : une console locale sur des cartes, une isolation, un fil et des
  actifs piégés, chaque élément `onclick` cliqué. Sur `main`, 14 images injectées et des charges
  exécutées, au chargement comme au clic ; avec #254, aucune, aucune erreur JS, et les arguments
  arrivent intacts aux fonctions.

**Mutants M580–M599** (`tests/unit/test_console_escaping.py`) : douze endroits de la console réécrits
bruts (fil, fenêtre et ligne d'une règle, décisions, titres de carte, configuration, un gestionnaire,
l'IP à bloquer), `_attr` et `_js` affaiblis, l'accueil, et le lecteur lui-même (`||`, les attributs
`on…`, une `Map`, l'argument d'un callback de promesse). Le test vérifie aussi le lecteur sur de petites
pages écrites pour lui.

**#257** (28/10, avec S1–S8 de la relecture de #256) : vérifié dans Chromium sur la même console
piégée, `main` en regard. Bouton par bouton, chaque élément déclare le même appel, avec les mêmes
arguments (89 sur 89 ; le Cancel de la fenêtre est une propriété). Le glisser-déposer d'une carte sur une
autre fait le même `dropOnSlot`, et la fenêtre s'ouvre et se ferme comme avant. La bulle des capacités
reste ouverte. Aucune violation de CSP venue de la page, aucune erreur JS. Une `<img onerror>` injectée de
force s'exécute sur `main` ; avec #257, la CSP la bloque. **Mutants M1080–M1099** : la CSP, un gestionnaire
ou un script en ligne de retour, le répartiteur (table fermée, élément le plus proche, phase de capture),
les arguments non échappés, une action absente de la table, et le lecteur pour S1, S2, S4, S5, S6, S8.

### La frontière de la console (SEC1, #272, 0.4.3)

La console agit sur Azure ; elle ne répond qu'à ses propres pages et aux scripts qui ont son jeton.
Tout se joue dans un seul middleware ASGI (`_TokenAuthMiddleware`, `eregion_console/api.py`), avant
toute route, WebSocket du fil compris. Dans l'ordre :

1. **Le nom d'hôte** : un nom de la boucle locale (`localhost`, `127.0.0.1`, `[::1]`) ou un nom de
   `EREGION_CONSOLE_HOSTS`, quel que soit le port — un tunnel (`ssh -L`) ou la console d'une équipe
   (`EREGION_CONSOLE_PORT`) publient un autre port que celui où la console écoute. Sinon 403.
2. **L'origine d'une modification** (POST, PUT, PATCH, DELETE, le WebSocket) : celle de la console,
   schéma et `Host` exacts (le port compte : une autre page de `localhost` est une autre origine). Sinon 403.
3. **Le jeton, toujours** : celui du déploiement (`EREGION_CONSOLE_TOKEN`, ou son ancien nom), sinon
   celui que la console a tiré à son premier démarrage, gardé dans `~/.glorfindel/console_token`
   (mode 600) et affiché une fois au démarrage avec l'URL. Aucun mode sans jeton, les tests compris
   (le conftest en pose un). Le cookie est une session dérivée du jeton (HMAC), jamais le jeton,
   nommé par le port que le navigateur a joint (`eregion_console_<port>` : un navigateur partage ses
   cookies entre les ports d'un hôte) ; `Secure` en HTTPS. Le fichier n'est jamais lu à travers un lien.
4. **Une modification d'un navigateur** (par le cookie) porte son `Origin`.
5. **Une modification porte un objet JSON** (`Content-Type: application/json`) : sinon 415 ou 400.

Côté pages, `_post(url, body, method)` envoie chaque modification en JSON, et `_seg(nom)` encode
chaque segment de chemin construit avec un nom (VM, carte). Restore n'est plus qu'une restauration de
carte : le serveur refuse une carte ancrée, comme la page et le bot. Et il demande son moment
(SEC4c) : la fenêtre pré-remplit le champ (`GET /api/restore/plan/<vm>`), montre les points d'avant ce
moment en lecture seule (« ↺ Points before this moment » les relit pour un autre moment), envoie
`before` ; le serveur refuse sans lui. Un refus de la commande revient sur la carte (« ✗ Restore
refused or failed »), échappé. Vérifié dans Chromium (29/10, chrome-headless-shell, console locale
sur un HOME jetable, points et commande remplacés, un point et une sortie piégés `<img onerror>`) :
le champ, la raison, les points, la relecture pour un autre moment, l'envoi avec `--before`, le
refus sur la carte ; aucune image injectée, aucune erreur JS ni violation de CSP. Config reçoit les identifiants
Azure masqués. En-têtes : la CSP prend `default-src 'self'`, `style-src 'self' 'unsafe-inline'` et
`img-src 'self'` (aucune ressource bloquée dans Chromium), `X-Content-Type-Options: nosniff`,
`Referrer-Policy: no-referrer` ; ni schéma OpenAPI ni `/docs`.

**Vérifié dans Chromium** (28/10, chrome-headless-shell, console locale sur un HOME jetable, réseau
limité à la boucle locale, connecteur Azure et commande `glorfindel` remplacés) : par un relais local
qui joue le tunnel (`http://localhost:<port>/?token=…`, port publié différent du port d'écoute), la
page du jeton puis son formulaire, `?token=` une fois, chaque page (aucune violation de CSP, aucune
erreur JS, aucune requête refusée, le fil en WebSocket ouvert), et chaque bouton de Glorfindel et de
Config (Release, Restore, Cmd, Snapshot, Approve & execute, les verdicts, le mode par défaut) : chaque
modification part en JSON et répond 200. Deux fois : jeton tiré au premier démarrage, puis jeton du
déploiement (le mode de H0).

**Mutants M1170–M1189** (`tests/unit/test_console.py`) : le nom d'hôte ignoré ou lu comme une
sous-chaîne, l'origine ignorée, le WebSocket hors des modifications, le port de l'origine ignoré, la
modification d'un navigateur sans origine, aucun jeton qui ouvre tout, aucun jeton tiré, le fichier du
jeton lisible par tous, le jeton dans le cookie ou accepté comme cookie, `Secure` jamais posé, une
modification d'un autre type ou sans corps, les en-têtes et `default-src` retirés, le schéma servi,
l'abonnement entier dans Config, une carte ancrée restaurée, un nom de VM brut dans un chemin.
M404, M568, M1080–M1082 suivent le nouveau code.

**Relecture (5.5)** : en lecture seule, les boutons qui écrivent sont de nouveau grisés (le garde lisait
`onclick`, disparu avec #257) ; un cookie par console ; le fichier du jeton jamais lu à travers un lien ;
l'URL écrite sans tampon (un conteneur n'a pas de terminal) et `make console-url` ; compose passe
`EREGION_CONSOLE_HOSTS`. Mutants M1300–M1305.

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
| `eregion_console/` | `api.py` (l'ancien `glorfindel/api.py`, déplacé tel quel puis complété : pages, redirections, jeton, `/api/sections`) ; `sections.py` (le registre) ; `cli.py` (`eregion console [--sections]`) ; `static/` : `overview.html`, `glorfindel.html` (ex-`index.html`, sert aussi `/config`), `injector.html` (ex-`atelier.html`, une seule page pour Annatar et Gothmog, filtrée par le chemin, qui montre aussi la vue « non installé »), `exercises.js`, `console.js`, `console.css` ; depuis #257, le script de chaque page est un fichier (`overview.js`, `glorfindel.js`, `injector.js`). Un module par section reste possible plus tard : comme Glorfindel est toujours là, aucune route n'a besoin d'être enregistrée sous condition | War Room |
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
| Finitions (#222) : CSP, README, textes, `--version` | Console | 0,5 |
| Les cartes (#248) : I1F, AL1, C2, A3 | Console | 0,5 |
| UI-1d, optionnel | General et Jonathan | 0,25 |

- UI-1 se déploie seul : sur H0, la détection voit tous les composants, et l'alias du jeton suffit.
- Les autres lots sont indépendants, sauf UI-2, qui suit UI-1.
- H0 est en pré-observation jusqu'au 13/11 environ. Chaque redéploiement se fait avec Jonathan,
  `.envrc` chargé, sur une référence épinglée (`make glorfindel-host-start REF=<commit>`, M-3).

## 6. Hors périmètre

- **La place de TO JUDGE** sur la page Glorfindel : à revoir à l'usage.
- **Les boutons de lancement** : par le contrat d'Orodruin, jamais par une route de la console.
  Conçus dans Dagorlad (§7, phase b) : la console écrit une demande, Orodruin juge et lance.
- **Les rôles** : avec le multi-opérateur.
- **Un statut d'Orodruin** : le registre lui garde une place.
- **Les packs d'un SaaS** : la page d'installation en est l'emplacement.
- **Une Content-Security-Policy complète** : `frame-ancestors 'none'`, `connect-src 'self'`,
  `base-uri 'none'` et `form-action 'self'` sont en place depuis #222. Un `script-src` attendra que
  les gestionnaires `onclick` en ligne de la page Glorfindel disparaissent.

## 7. Dagorlad, le terrain d'exercice

Conception du 30/10, session Console, d'après la maquette de Jonathan et de l'orchestre (hors du
dépôt, comme les captures : écran 1, préparer ; écran 2, exercice en cours). **Étape 1, sans code.**
La phase (a) se construit après le choix de Jonathan, et après la fusion de C1 (#80), qui touche les
pages que Dagorlad remplace (`injector.html`, `injector.js`).

**Le nom** (Jonathan, 30/10) : **Dagorlad**, « la Plaine de la Bataille », devant la Porte Noire,
où la Dernière Alliance des Elfes et des Hommes affronta l'armée de Sauron. Annatar est Sauron
déguisé : c'est le terrain où l'on fait face à ses forces. Un nom de lieu, comme Eregion, pour la
page qui réunit deux agents face au troisième ; l'onglet garde le nom seul, le rôle au survol (§0).
Écartés : « Exercises », qui désigne déjà les fenêtres d'exercice du code (`runs/exercises/`, la
source `exercise`, le canal) ; « Playground », un bac à sable sans conséquence, alors que la
phase (b) fait lancer de vraies attaques.

### Ce que c'est

Une page, `/dagorlad`, qui remplace `/annatar` et `/gothmog`. À gauche, les **cartes rouges** : les
techniques d'Annatar, les pannes de Gothmog. À droite, les **cartes bleues** : Glorfindel, et les
cibles que Celebrimbor a inscrites, avec leur zone et leur mode d'autonomie. Les deux côtés ne se
connaissent pas. L'opérateur tire un fil d'une carte rouge vers une ou plusieurs cartes bleues ; le
serveur dit si chaque fil est valide, et ce qu'on doit en attendre.

| Phase | La page | Elle écrit |
|---|---|---|
| (a) Préparer | un plan et sa simulation | rien |
| (b) Demander | une demande pour Orodruin, qui juge et lance | la demande, jamais sur le cloud |
| (c) Suivre | le run en direct, depuis ses signaux | rien |

```
EREGION  Overview  Glorfindel 3  [Dagorlad]            ● watch · 12s ago  ● Orodruin · armed  07:52 UTC
───────────────────────────────────────────────────────────────────────────────────────────────────────
EXERCISES  Plan only — this page launches nothing. Glorfindel is never told.
RED · TECHNIQUES & FAULTS                                              BLUE · ENROLLED TARGETS
┌ T1110.001 Brute Force: SSH ────┐                                    ┌ GLORFINDEL ● watching ──────┐
│ Atomic · proven 6d             ●━━━ detected ~2 min · card ━━━━━━━━━│ 12 rules · never told       │
│ non-destructive · ssh-brute-…  │╲                                   └─────────────────────────────┘
└────────────────────────────────┘ ╲━━ detected · isolate alone ━━━━●┌ vm-…-bree  BENCH  HUMAN-ONLY ┐
┌ T1486 Data Encrypted ──────────┐                                   └──────────────────────────────┘
│ DESTRUCTIVE · bench only       ●━━━ type the VM name to run ━━━━━━●┌ vm-…-gondolin BENCH NON-DISR.┐
└────────────────────────────────┘╌╌╌ ✕ zone_forbids: production ╌╌●┌ vm-sentinel PRODUCTION SHADOW┐
┌ vm-shutdown (fault) ───────────┐                                   ┌╌ Entra ID · blind until ID1 ╌┐
│ Chaos Studio · nothing disrupt.●┅┅┅ fault · nothing disruptive ┅┅┅●  (gondolin)
PLAN · 4 wires · 1 refused   ✓ watch live  ? Orodruin unknown here  ✓ enrolled, zone read  ✓ catalog
```

### Les cartes

**Carte rouge** : une entrée du catalogue, technique ou panne.

| Ce qu'elle montre | D'où |
|---|---|
| identifiant, nom, tactique | `technique_catalog.yaml` (`/api/catalog`) |
| injecteur et moteur (Annatar, Atomic Red Team ; Gothmog, Chaos Studio) | le catalogue (`engine`) : une technique est à Annatar, une panne à Gothmog |
| type de cible (`azure_vm`, `azure_storage`, `entra_id`) | le catalogue (`resource_types`) |
| destructive ou non | le catalogue, seul : jamais le navigateur, jamais une demande |
| implémentée ou prévue | le catalogue (`status`) : une entrée prévue est grisée, sans poignée |
| ce qu'on attend : la règle et le délai ; pour une panne, rien de disruptif | voir « Le résultat attendu » |
| dernière preuve et état de sa ligne (`proven`, `aging`, `stale`, `regressed`, `never`) | la matrice de C1 (`eregion_console/coverage.py`), sur tout ce que l'hôte garde — avec la vue Runs, après la fusion de C1 |

Un injecteur absent laisse ses cartes grisées, avec ce qu'il ajouterait (la page d'installation
d'aujourd'hui, §3, règle 5).

**Carte Glorfindel**, une seule, en tête des bleues : battement de la watch, règles chargées (base et
couche du client), workspaces lus, mode par défaut, lecture seule du déploiement. Elle dit ce que
l'opérateur sait et qu'elle ignore : « never told what the red side plans ». Aucun fil n'y arrive.

**Carte cible** : une ressource inscrite.

| Ce qu'elle montre | D'où |
|---|---|
| nom, l'identifiant au survol | les VM du périmètre du banc (`Scope` d'O0, groupes `rg-celebrimbor*`), lues par l'identité de la console (Reader sur le banc, sur H0) |
| inscription et zone (`bench`, `twin`, `production`) | ses tags et ceux de son groupe, lus par la même identité et jugés par `inscription.enrollment`, comme la watch les lit (`TagEnrollment`, H-1) |
| allumée ou désallouée | la même lecture |
| vue par Glorfindel, et depuis quand | la découverte (`AssetRegistry`, Heartbeat) |
| mode d'autonomie effectif, et ce qui le retient | `/api/state` (`autonomy_modes`, `autonomy_holds`, `read_only`) |
| isolée, adresses bloquées | `/api/state` |
| règles qui s'appliquent | les règles liées au backend qui la voit |
| sauvegarde | l'audit (`/api/audit/<vm>`, en cache) |
| dernières preuves sur elle | la matrice de C1 (les runs dont la fenêtre ou le fait de campagne nomment la cible) |

- Une VM du périmètre qui n'est pas inscrite n'a pas de carte : bree, la VM à vraie charge, n'y
  apparaît jamais (H-1, SEC5).
- Un type de cible sans cible inscrite, ou que Glorfindel ne lit pas encore (le journal d'activité,
  Entra ID avant ID1), a une carte en pointillés, sans fil possible.
- Le mode ne se change pas ici : c'est un geste de la page Glorfindel, avec la préparation (L6).

### Le fil : valide ou refusé

**Le navigateur n'envoie que deux identifiants** : celui de la carte rouge, celui de la cible. Le
serveur relit et juge tout le reste : le caractère destructif, la zone, l'inscription, le type.

Le verdict d'un fil est une fonction pure du cœur partagé (`eregion_core/exercise_plan.py`), bâtie sur
`inscription.check_target` : les règles qu'Orodruin applique à chaque injection, sur les données lues
maintenant. D1 tient : la console, Annatar et Gothmog liront la même fonction, sans s'importer. Le
verdict de la console conseille ; celui d'Orodruin, à l'exécution, décide.

**Refus.** Chacun a un code stable et sa phrase, comme `orodruin-check`, et le premier qui tient
l'emporte :

| Code | Refusé quand | Règle |
|---|---|---|
| `unknown_experiment` | l'identifiant n'est pas au catalogue | E1 |
| `not_implemented` | l'entrée est `planned` | E1 |
| `wrong_target_type` | la cible n'est pas du type de l'entrée | catalogue |
| `outside_scope` | hors du périmètre du banc (`Scope.check`) | O0 |
| `not_enrolled` | `eregion-target` absent, vide ou d'un autre banc ; zone absente, ou en désaccord avec le groupe | O0 (`enrollment`) |
| `zone_forbids` | une panne en `production` ; une technique destructive, ou que personne n'a déclarée non destructive, en `production` | règle de production (`check_zone`) |
| `no_watch` | aucun battement vivant de la watch, ou celui d'un autre périmètre : tous les fils | V1, SEC5 (`watch_gate`) |
| `no_engine` | une panne dont aucune expérience Chaos Studio ne vise cette VM | les cibles de l'expérience, lues comme `gothmog preflight` les lit |
| `over_cap` | plus d'injections que le plafond d'Orodruin, ou plus de 2 h en tout | `EREGION_MAX_INJECTIONS` ≤ 20, `EREGION_MAX_RUN_S` ≤ 2 h |

**Avertissements.** Le fil reste valide, et sa pastille le dit :
- `typed_name` : une technique destructive, ou dont personne n'a déclaré qu'elle ne l'est pas (A0 :
  un inconnu n'est jamais pris pour inoffensif, comme en production). En (b), le nom de la cible sera tapé.
- `isolated_now` : la cible est isolée, ou des adresses y sont bloquées. Le run mesurerait
  l'isolation, pas la détection (la tâche B, 30/07).
- `not_seen` : Glorfindel ne voit pas la VM en ce moment (désallouée, ou hors de ses workspaces).
  Annatar la démarre avant d'agir. Si elle ne remonte pas, le run finit en `unknown` : c'est un échec
  fermé, jamais un raté.
- `no_rule` : Glorfindel n'a aucune règle pour cette technique sur ce backend. Il est aveugle : le run
  doit finir en `missed`, et la boucle violette proposer une règle.
- `engine_unknown` : une panne dont cet hôte ne lit pas les cibles du moteur (l'image de H0 ne porte
  pas Gothmog). Le preflight de Gothmog en décide, sur Orodruin.

L'état du contrat d'Orodruin, inconnu sur cet hôte tant qu'il ne le publie pas (« Ce qui manque
ailleurs »), est dit une fois, dans les vérifications du plan, plutôt que sur chaque fil.

**Jamais sans Glorfindel.** `--without-glorfindel` n'est pas proposé par la page. Un run de
développement reste un geste sur Orodruin.

### Le résultat attendu

Pour chaque fil valide, la pastille et le plan disent ce qu'on doit voir. C'est calculé par le code, à
partir de la configuration : **aucun appel au modèle**, et rien n'est écrit (« Glorfindel reste
aveugle »).

**Une technique.**
- **La règle qui détecte** : les règles de Glorfindel (base et couche du client, sans les règles
  désactivées) de la même technique, liées au backend qui voit la cible. Aucune → `no_rule`.
- **Le délai** : le `expected_latency_s` de la règle, sinon celui du catalogue (P99). À côté, ce qui a
  été mesuré : la médiane des runs détectés de la technique, et le dernier sur cette cible (C1).
- **Ce que fera Glorfindel**, selon le mode effectif de la cible. C'est une enveloppe : ce que ses
  gardes lui permettent au plus, jamais une prédiction de sa décision.

  | Mode effectif | Attendu |
  |---|---|
  | déploiement en lecture seule (H0) | il détecte et recommande ; rien n'est exécuté |
  | `human_only`, ou `non_disruptive` retenu par la préparation | une carte à juger ; un humain agit |
  | `non_disruptive`, prête | il isole ou bloque seul si chaque garde passe (confiance, signal caractérisé et attribué, télémétrie lue, tirages d'accord), puis vérifie sur Azure ; sinon une carte qui nomme la garde |
  | zone `production` | l'enveloppe de son mode : Glorfindel ne lit pas encore la zone ; J1 y forcera le mode ombre (détection seule) |

  Une action destructive (restaurer) n'est jamais autonome, quel que soit le mode. Pour une technique
  destructive, la ligne le rappelle : T1486 donne au plus une isolation et un instantané, la
  restauration attend un humain.
- **L'historique de la paire**, par la matrice de C1 : l'état de la ligne, les dix derniers résultats,
  le dernier temps pour contenir.

**Une panne** : rien de disruptif. Glorfindel ne doit ni isoler ni bloquer sur ce bruit (G0, G1).
L'état normal est relu avant et après (les sondes de Gothmog : `vm-running`, `guest-agent-ready`,
`heartbeat`), et le retour est vérifié, avec son temps (G3).

### Les trois phases

#### (a) Préparer, en lecture seule

- La page charge les deux colonnes (`GET /api/dagorlad/board`). À chaque fil tracé, elle demande le
  plan (`GET /api/dagorlad/plan?wire=<carte rouge>@<cible>&wire=…`). Deux GET : aucune route POST
  n'est ajoutée, et M403 le tient déjà pour les routes d'exercices.
- **Le plan**, le panneau du bas, donne :
  - les fils valides, ceux qui portent un avertissement, ceux qui sont refusés ;
  - ce qu'Orodruin vérifiera avant d'agir (son contrat armé, la watch vivante, l'inscription relue,
    le catalogue qui décide du destructif) ;
  - l'ordre des fils, la durée totale, et les fenêtres d'exercice qui s'ouvriraient.
- **La simulation**, c'est ce plan rejoué sur les mêmes gardes, avec les données de maintenant :
  aucun appel à Orodruin, aucune fenêtre ouverte, aucun appel au modèle. Ce n'est pas un essai à
  blanc d'Annatar (`--dry-run` tourne sur Orodruin).
- Les fils tracés restent dans le navigateur (`localStorage`, une commodité de l'opérateur), jamais
  sur le serveur.
- La bannière le dit : « Plan only — this page launches nothing. » Les boutons de la maquette
  (« Request run from Orodruin », « Save as campaign ») n'existent pas en (a).
- **Le tracé** : on tire une poignée à la souris, ou, au clavier, on choisit une carte rouge puis
  des cibles. Les courbes sont un SVG calculé par la page, à partir de ses seuls nombres.
- **Ce qui vient du dehors** : un nom de VM, un tag, un champ de rapport. Tout passe par `esc` (#254).
  Chaque geste nomme son action par le répartiteur (`data-on-*`, la table `ACTIONS`, #257).

#### (b) Demander : une demande écrite pour Orodruin

- **La console n'appelle jamais le cloud pour lancer.** Elle écrit une demande. Orodruin la lit,
  vérifie son contrat (`armed`), relit l'inscription et la zone à chaque injection (O0), et lance
  avec sa propre identité. S'il refuse, il le dit avec les mêmes codes.
- **Ce que porte une demande** :
  - un identifiant et son heure ;
  - pour chaque fil : l'expérience, la cible, son rang.

  Jamais un nom tapé : la console n'en garde aucun (le point suivant).

  Rien d'autre : ni zone, ni « destructive », ni résultat attendu, ni mode de la cible. Orodruin
  recalcule tout. Annatar et Gothmog restent aveugles à Glorfindel, comme Glorfindel l'est à eux (la
  boucle aveugle, 30/06).
- **Un fil destructif exige le nom de la cible, tapé dans la commande, jamais dans la console**
  (relecture 5.5 de #338, 30/10). La commande **affiche les fils de la demande**, puis fait taper à
  l'opérateur, sur son poste, le nom de la cible de chaque fil destructif (le nom de la VM, tel
  qu'Azure l'écrit) ; Orodruin le compare au nom qu'il lit de la cible. Un nom tapé que la console
  aurait gardé ne prouverait rien : une demande forgée sur un H0 compromis passerait sous le geste
  humain sans être vue. La page peut montrer ce qui sera demandé, elle ne le recueille pas.
- **Une fenêtre d'exercice par fil.** L'injecteur l'ouvre quand il touche sa cible, comme
  aujourd'hui. Elle porte l'identifiant de la demande : c'est ce qui relie le fil à son run.
- **Les fils tournent l'un après l'autre** (Jonathan, 30/10, question 2), dans l'ordre où ils sont
  tirés, une fenêtre à la fois, comme le runner de campagne d'Annatar. Un seul run vit à la fois, et
  le temps pour contenir n'est mêlé à rien. Il en découle trois règles :
  - **une panne et une technique ne se chevauchent jamais sur une VM** (X1, l'attaque pendant une
    panne, est en 1.x). Après une panne, la technique part quand le retour de la VM est vérifié. Elle
    n'attend pas la fin de la grâce : BL1 rattache d'abord une détection à son incident (`taken`),
    et elle ne passe donc jamais pour une panne prise pour une attaque ;
  - **un fil dont la VM a été isolée** par un fil précédent attend sa levée, par un humain ou par la
    reprise, jusqu'à un délai. Ensuite il est sauté, et c'est dit. Un injecteur ne défait jamais ce
    que Glorfindel a fait ;
  - **le plafond d'Orodruin** (20 injections, 2 h) porte sur la demande entière.

  Écarté : en parallèle d'une VM à l'autre, plus rapide, mais plusieurs fenêtres vivantes à la fois.
- **« Stop all »** passe par l'arrêt d'urgence d'Orodruin (`orodruin-kill`). Il révoque l'identité,
  annule le chaos, arrête la VM et ferme les fenêtres. La console ne peut pas révoquer une identité,
  et ne doit pas le pouvoir. Le bouton donne donc la commande, puis :
  - ce qu'elle arrêtera : les fenêtres vivantes et leurs cibles ;
  - ce qui restera en vol (M-1).
- **Le transport : une commande portée par l'opérateur** (Jonathan, 30/10, question 1). La console
  écrit la demande dans son propre répertoire (`~/.eregion/console/requests/`, hors de `runs/` et
  de `~/.glorfindel/`), et donne une commande : `make orodruin-exercise REQUEST=<id>`. Elle part du
  poste de l'opérateur, comme les autres cibles d'Orodruin : elle tire la demande de l'hôte de la
  console (sur H0, par SSH, comme `make glorfindel-host-*`), l'affiche, fait taper les noms (le point
  précédent), puis la copie sur Orodruin par SSH, comme `orodruin-push`, et l'y lance. À la fiche de
  DG-b d'en fixer le détail. Ce choix garde trois choses :
  - rien de neuf dans le canal ;
  - aucun droit de plus pour l'identité de H0, qui reste un observateur ;
  - un geste humain entre la console et Orodruin.

  « Stop all » est aussi une commande (`make orodruin-kill`). Écarté : un conteneur de demandes, où
  l'identité de H0 aurait pu faire agir Orodruin.
- **Le modèle de menace** : la console devient une page qui fait agir sur le cloud. Sa frontière (la
  première) le dira au lot de la phase (b), avec ce qui le tient : le jeton, l'origine et le corps
  JSON de SEC1 ; le contrat d'Orodruin, l'inscription, la zone et le nom tapé.

#### (c) Suivre, en direct

Chaque fil devient une ligne de la chronologie (écran 2), tirée de ce qui arrive déjà sur l'hôte :

| Étape | D'où |
|---|---|
| demandée | la demande, sur l'hôte de la console ; acceptée ou refusée, Orodruin le dit à l'opérateur dans la commande portée, et la page le voit quand la première fenêtre arrive |
| lancée : la fenêtre et son run | la fenêtre d'exercice (tirée du canal sur H0), qui porte l'identifiant de la demande |
| T0 | le début de la fenêtre en direct ; à la fin, l'heure de l'attaque du rapport de run |
| détectée, et quand | un cycle de la watch sur la cible dans la fenêtre (`covering_runs`), ou une détection livrée au run (canal retour) |
| la décision | ce cycle : action, confiance, mode, la garde qui l'a retenue |
| contenue, vérifiée sur Azure | le cycle exécuté et vérifié ; l'isolation ne compte que si elle tient jusqu'à la fin de la fenêtre (BL1) |
| la carte | les cartes qui portent ce run (`exercise_run`), et le lien vers TO JUDGE |
| le verdict | le rapport du run, tiré sur l'hôte (#193) |

- **Les mesures du run** suivent les définitions de BL1 (`analysis/containment.py`) : le temps pour
  contenir, la part contenue seule, et les actions disruptives à tort pendant une panne (« une
  panne prise pour une attaque »).
- **Les mêmes fonctions** servent les indicateurs : `run_report.timeline` de C1. Un run ne se mesure
  pas autrement sur cette page que sur l'accueil.
- **Les cartes bleues** prennent l'état de leur cible : isolée et vérifiée, une carte à juger.
- **Rien n'est écrit** en (c) : comme les pages d'aujourd'hui, elle ne fait que lire.

### La vie d'un fil

Décidée par Jonathan le 30/10, question par question. Tirer un fil ne lance rien : on en tire autant
qu'on veut, plusieurs vers une même cible compris, puis **un seul geste, « Lancer », fait partir tous
les fils du plan** en une demande, l'un après l'autre.

| État | Ce qu'on voit | Ce qu'on peut faire |
|---|---|---|
| **Brouillon** (phase a) | le fil, son verdict et ce qu'on doit en attendre | le retirer par le ✕ de sa pastille, sur le tracé, ou de sa ligne du plan ; « Clear wires ». Re-tirer une paire déjà tirée ne la retire pas : la page dit « already drawn » |
| **Demandé, en cours** (b, c) | les fils figés en une demande `r-…`, leur rang ; chacun dit où il en est (en file, lancé, détecté, contenu) | rien sur un fil : ils sont verrouillés jusqu'à la fin de la demande, et l'on n'en tire pas d'autres. Pour arrêter, « Stop all », l'arrêt d'urgence d'Orodruin, arrête tout. La console n'a pas de canal pour dire à Orodruin de sauter un fil (la commande portée, question 1) |
| **Fini** (c) | les fils déverrouillés gardent leur dernier résultat sur la pastille (« ✓ detected +1m47 · contained 2m31 », « ✗ missed ») et un lien « run ▸ » vers Runs | les retirer, en ajouter, tout effacer, ou **relancer la même demande** d'un geste — ce qui garde la dernière preuve sous 30 jours |

Écartés : des fils figés avec un brouillon de la demande suivante à côté (deux états mêlés sur le
tableau) ; retirer un fil encore en file (il faudrait un canal vers Orodruin) ; des fils qui
disparaissent ou pâlissent une fois la demande finie ; sélectionner un fil puis le supprimer.

### Les drills

Un **drill** : des attaques et des pannes tirées vers des cibles, qu'on garde et qu'on rejoue. C'est
un exercice qu'on répète pour rester prêt, et qui garde la dernière preuve sous 30 jours. Son
exécution reste une **demande** (`r-…`), et chacun de ses fils, un run.

Le mot (Jonathan, 30/10, sur une analyse hors du dépôt). Écartés :
- « jeu » : ludique en anglais (« game »), l'écueil de « Playground » ;
- « campagne » : aujourd'hui une exécution, et liée à Annatar ;
- « muster » : peu connu.

Les cinq décisions, prises une à une le 30/10 :

1. **Un objet de l'instance**, distinct d'Annatar et de Gothmog, avec un nom et un auteur :
   l'opérateur, Annatar ou Eregion. Son format vit dans le cœur partagé (D1), comme le verdict
   d'un fil.
2. **En couches**, comme les règles depuis P1 :
   - **livrés** : `drills/<nom>.yaml` dans le dépôt, relus en PR — les drills de référence ;
   - **instance** : ceux du client, dans le répertoire propre à la console (`~/.eregion/console/drills/`),
     **hors de `~/.glorfindel/` et de `runs/`** — un drill porte le plan rouge, que la décision ne
     lit jamais (« Glorfindel reste aveugle ») —, jamais écrasés par une mise à jour, comme la couche
     de règles du client (en SaaS, le magasin du tenant). Dagorlad les enregistre (« Save as
     drill »), les liste et les charge sur le tableau ;
   - **session** : le brouillon, dans le navigateur (déjà le cas) ;
   - **export** : le même YAML, pour Git chez le client, le jumeau, ou proposer un drill à la base.

   L'enregistrement est la première écriture de Dagorlad. Elle tient dans la frontière de la
   console (SEC1 : jeton, origine, corps JSON) et n'écrit qu'un fichier de l'instance, jamais sur le
   cloud.
3. **Les campagnes d'Annatar deviennent des drills dont Annatar est l'auteur.**
   - Son planificateur propose : « Ask Annatar for a drill » trace une chaîne en brouillon sur le
     tableau. L'opérateur la corrige, la lance, la garde.
   - Rejouer relance la même chaîne, et D-2 compare deux demandes du même drill.
   - `annatar campaign plan` et `run` continuent, en écrivant un drill et une demande ; les
     manifestes déjà écrits restent lisibles (l'index de D-2, la vue Runs).
   - La boucle reste aveugle : le planificateur lit le catalogue et la cible, jamais les règles ni
     les modes de Glorfindel.
4. **Les cibles** : par nom dans un drill du client, par sélecteur (zone, rôle) dans un drill livré.
   Jamais par l'identifiant de la ressource, qui change quand Celebrimbor reconstruit le banc. Au
   lancement, la console résout un sélecteur en VM inscrites et montre la liste ; Orodruin rejuge
   chaque fil.
5. **Le partage** : un drill appartient à l'instance. Son auteur et sa dernière modification sont
   notés, tous les opérateurs le voient, le lancent et le modifient. Des drills privés attendront les
   rôles (1.x), comme le veut le choix assumé de la console : un jeton, tous les droits.

Lancer un drill : `make orodruin-exercise DRILL=<nom>`, ou la demande que Dagorlad prépare.

### Glorfindel reste aveugle

Une demande n'entre jamais dans ce que lit la décision. Ce qui le tient :
1. **La demande n'est jamais là où la watch lit.** Elle n'est ni dans `runs/` (signaux, journaux de
   debug), ni dans `runs/exercises/`, ni dans `~/.glorfindel/` (état, escalades), ni dans la mémoire.
   Elle a son propre répertoire, celui de la console : `~/.eregion/console/` (`requests/`,
   `drills/`). Pas `~/.eregion/` entier : il porte aussi `analysis/`, que la watch monte en écriture,
   `teams/`, `cosign/`, `h0_known_hosts`, `host-backups/`. Ce qui l'établit :
   - aucun module de `glorfindel/` ne nomme ce répertoire — déjà en place :
     `test_glorfindel_never_names_the_consoles_own_directory` ;
   - DG-b : seul le service de la console monte `~/.eregion/console/` ; aucun service watch ni bot ne
     monte `~/.eregion` ni ces sous-répertoires (`test_profiles.py`) ;
   - un cycle de `decide` rejoué avec une demande présente envoie au modèle le même message, à l'octet
     près.
2. **Le résultat attendu n'est écrit nulle part.** Il est calculé à la demande de la page, sans
   appel au modèle. Il ne part ni dans la demande, ni dans la fenêtre, ni dans un fichier.
3. **Glorfindel apprend l'exercice comme aujourd'hui**, par la fenêtre que l'injecteur ouvre en
   touchant sa cible. La fenêtre ne sert qu'à étiqueter le cycle (`exercise`) : l'étiquette n'abaisse
   aucune garde, et le modèle ne la voit pas (B2). Elle ne porte que l'identifiant de la demande,
   rien de ce que la demande attend.
4. **La console n'avertit pas la watch** : ni route, ni signal.
5. **Le raisonnement ne change pas** : ni `_SYSTEM_PROMPT`, ni `few_shot_examples.yaml`, ni
   `_build_user_message()`.

**Mutants**, ajoutés par la phase qui les introduit :
- la demande écrite sous `runs/` ;
- le résultat attendu écrit dans la fenêtre ;
- un champ de la demande dans le message du modèle ;
- un fil destructif accepté sans nom tapé ;
- le verdict lu dans la requête du navigateur ;
- une panne acceptée en `production`.

### Ce que deviennent les pages Annatar et Gothmog

**Un onglet Runs dans Dagorlad** (Jonathan, 30/10, question 3, choisie sur une page de schémas et
de pour et contre). `/dagorlad` a deux vues :
- **Board** (`/dagorlad`) : les fils, le plan, le run en cours (phases a à c). Le tableau entier tient
  à 1440 × 900 sans défiler : rouges, fils, bleues et plan ;
- **Runs** (`/dagorlad?view=runs`) : les fenêtres et les campagnes des deux injecteurs, dans une
  liste, avec un filtre par injecteur et leur détail d'aujourd'hui (cycles, cartes, rapport, sondes,
  canal retour). Une demande qui mêle une technique et une panne y reste ensemble. Un run fini quitte
  le Board et arrive ici.

Les adresses, jusqu'à la 1.0 comme `/atelier` :
- `/annatar` mène à `/dagorlad?view=runs&injector=annatar`, et `/gothmog` de même ;
- `/runs/<id>` mène à `/dagorlad?view=runs&run=<id>`, et `?campaign=<id>` se garde.

L'en-tête n'a plus que trois onglets : Overview, Glorfindel, Dagorlad. Dagorlad est actif si Annatar
ou Gothmog l'est ; grisé, il mène à la page d'installation. Le catalogue ne s'affiche qu'une fois, en
cartes rouges, et une carte rouge mène à son dernier run dans Runs.

Écartées : l'historique sous le tableau (il passe sous le bas de l'écran, et la page saute à chaque
rafraîchissement) ; garder les deux pages (cinq onglets, le catalogue deux fois, une demande mixte
lue sur deux pages).

### Ce qui manque ailleurs (routé à l'orchestre)

- **Orodruin** :
  - publier le verdict de son contrat (`armed` ou `passive`, les codes, l'heure ; ni abonnement, ni
    identifiant) là où la console le lit. Sans cela, la page dit « Orodruin: unknown here ». C'est la
    place que le registre lui gardait (§6) ;
  - en (b), lire une demande, la juger avec les mêmes codes, publier son statut.
- **Annatar et Gothmog**, en (b) :
  - lancer depuis une demande, dans le run unifié de C1 ;
  - écrire l'identifiant de la demande dans la fenêtre ;
  - comparer le nom tapé.
- **Gothmog** : rendre lisibles, sans Orodruin, les VM que vise chaque expérience (pour `no_engine`).

### Questions à Jonathan

Posées une à une. La réponse est reportée ici avec sa date.

1. **Le transport de la demande** (phase b) : une commande que l'opérateur porte sur Orodruin, ou un
   conteneur de demandes dans le compte du canal ? **La commande portée** (30/10).
2. **L'ordre des fils d'une demande** : l'un après l'autre, ou en parallèle d'une VM à l'autre ?
   **L'un après l'autre** (30/10).
3. **L'historique** (fenêtres, campagnes) : un onglet dans Dagorlad, sous le tableau, ou les deux
   pages gardées en historique ? **Un onglet Runs** (30/10).

### Lots

| Lot | Contenu | Après |
|---|---|---|
| DG-a | `/dagorlad` en lecture seule : Board (tableau, plan, simulation) et Runs (les listes d'aujourd'hui, les deux injecteurs ensemble) ; `eregion_core/exercise_plan.py` ; redirections ; tests sans Azure ni modèle, mutants | C1 fusionné, pour Runs et les redirections |
| DG-b | la demande, le nom tapé, « Stop all » ; Orodruin, Annatar, Gothmog ; le modèle de menace | DG-a, la question 1, BL1 |
| DG-c | le suivi en direct | DG-b, BL1 |
| DG-d | les drills : leur format (cœur partagé), « Save as drill », la liste et le chargement dans Dagorlad, `make orodruin-exercise DRILL=`, les premiers drills de référence | C1, DG-b |
| DG-e | Annatar : `campaign plan` et `run` écrivent un drill et une demande ; « Ask Annatar for a drill » dans Dagorlad | DG-d, avec la session Annatar |

### Construit : le Board (DG-a, première partie, 30/10)

- **Le cœur** : `eregion_core/exercise_plan.py`, le verdict d'un fil (`judge`) et d'une demande (`plan`,
  les fils dans l'ordre tracé, une fois par paire, refusés au-delà des plafonds d'Orodruin), bâti sur
  `Scope.check`, `enrollment` et `check_zone` d'O0. Les cibles se lisent par
  `inscription.TagEnrollment.vms` : les VM des groupes du banc, avec leurs tags et ceux du groupe, par
  l'identité de la console, en cache une minute ; une lecture en échec est dite, jamais un banc vide.
- **La console** : `eregion_console/board.py` (cartes, avertissements du côté de Glorfindel, attendu),
  `GET /api/dagorlad/board`, `GET /api/dagorlad/plan` (100 fils au plus), la page `/dagorlad`
  (`dagorlad.html`, `dagorlad.js`). Les règles sont celles que la watch charge, base et couche du
  client : sans backend configuré, aucune n'est active, et chaque fil d'une technique dit « no rule ».
- **La page** : on choisit une carte rouge puis une ou plusieurs cibles (au clavier aussi), ou l'on
  glisse sa poignée sur une cible. Les fils sont un SVG calculé par la page, leurs pastilles ne se
  chevauchent pas. Le panneau du plan liste chaque fil, son rang, son verdict ou ce qu'on doit
  attendre, ses avertissements, et un ✕ pour le retirer — sur sa pastille comme sur sa ligne ; re-tirer
  une paire ne la retire pas (« already drawn »). Les fils restent dans le navigateur
  (`localStorage`). Rien du dehors n'est écrit brut, chaque geste passe par le répartiteur
  (`data-on-*`, la table `ACTIONS`) ; le lecteur (`scripts/console_escaping.py`) lit la page.
- **Vérifié dans Chromium** (chrome-headless-shell, console locale sur un HOME jetable, cibles, règles
  et watch remplacées, une VM au nom piégé `<img onerror>`) à 1440 et 1600 px : six fils tirés, cinq au
  clic et un à la souris ; aucune erreur JS, aucune violation de CSP, aucune image injectée.
- **La relecture 5.5 (30/10)** a fait corriger :
  - une technique au caractère destructif non déclaré demande aussi le nom tapé (A0) ;
  - une zone hors des trois (« Production », « prod ») est épinglée par un test ;
  - `isolated_now` et la carte d'un déploiement en lecture seule sont testés ;
  - la page suivante d'une liste ARM n'est suivie que vers ARM ;
  - le plafond en nombre est testé (le temps vient d'abord) ;
  - la carte de Glorfindel sans âge de battement, et « MAY RUN · ? » pour une panne au moteur illisible.

  Mutants M2000–M2004.
- **Mutants M1980–M1994** (`tests/unit/test_exercise_plan.py`, `test_console_dagorlad.py`) : la règle de
  production sautée, le caractère destructif pris pour faux, un fil sans watch, une cible non inscrite
  ou hors du périmètre, une entrée prévue, une panne hors des cibles de son moteur, le nom à taper
  oublié, les plafonds ignorés, une carte pour une VM non inscrite, un déploiement en lecture seule
  montré capable de contenir, la route du plan qui accepte POST, une action hors de la table de la
  page, un nom de VM écrit brut, une technique sans règle non dite aveugle.
- **Reste pour DG-a**, après la fusion de C1 : la vue Runs, les redirections de `/annatar`, `/gothmog`
  et `/runs/<id>`, l'onglet (Dagorlad n'est pas encore dans l'en-tête : on l'ouvre par son adresse),
  la dernière preuve sur les cartes rouges.
