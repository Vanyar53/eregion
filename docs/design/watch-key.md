# La clé de la watch (SEC19, N-03 ; SEC21, SEC21b) — et ce que FS1 en reprendra

La garde « jamais sans Glorfindel » (V1) lit un battement. Avant SEC19, ce battement était
**lié** (SEC5 : le condensé de l'abonnement que la watch lit) mais pas **authentifié** : qui
pouvait écrire le fichier des injecteurs ou le blob du canal retour pouvait écrire un battement
que la garde croyait. Depuis SEC19, la garde ne croit qu'un battement signé par la clé de la watch,
vérifié avec une clé publique épinglée du côté de l'injecteur. Depuis SEC21 (#530), il en va de même
de chaque détection que la watch publie sur le canal retour : ce que les injecteurs mesurent. Depuis
SEC21b (#535), le battement signé dit aussi quelles détections il couvre.

Code : `eregion_core/watch_key.py` (la clé, la signature, la vérification), `eregion_core/watch_gate.py`
(la garde), `eregion_core/watch_channel.py` (le battement du canal), `glorfindel/cli.py` (la copie
pour les injecteurs, la commande `glorfindel watch-key`), `annatar/runner/engine.py` (la détection
crue ou refusée). Tests : `tests/unit/test_watch_key.py`, `tests/unit/test_watch_gate.py`,
`tests/unit/test_signed_detections.py` (SEC21), `tests/unit/test_beat_covers.py` (SEC21b).

## La clé

- **Une paire Ed25519**, tirée par la watch à son premier démarrage sans clé. La moitié privée :
  `~/.eregion/watch-key/watch_ed25519`, 32 octets bruts, mode 0600, son répertoire 0700, écrite en
  entier dans un fichier à part puis publié par un lien (`os.link`) : un disque plein ne laisse
  jamais une clé vide sous son nom, et deux watches qui démarrent ensemble n'en écrivent jamais
  deux. Une clé d'une autre taille est refusée, le geste dit : l'effacer, puis épingler la nouvelle.
- **Un répertoire que seule la watch monte** (`docker-compose.yml`, le service `watch` ; `make
  glorfindel-watch`). Jamais dans `~/.glorfindel` : la console et le bot le montent, les injecteurs
  en montent une partie. Jamais sous `runs/`. La watch refuse une clé placée là, une clé lisible par
  d'autres, un lien, un autre propriétaire, un fichier d'une autre taille : elle ne signe pas, et le
  dit dans son journal. Ses battements partent alors sans signature, et les injecteurs les refusent.
- **Le répertoire est créé avant les services**, au nom de l'opérateur (`make glorfindel-start`,
  `-restart`, `-dev`, `team-start`, `deploy.sh` sur H0). Laissé à docker, il serait à root, et la
  watch ne pourrait pas tirer sa clé. `make glorfindel-shell` ne la monte pas : une watch lancée
  dans ce shell tirerait une clé éphémère, refusée par les injecteurs.
- **La moitié publique s'épingle** : `make watch-key` (la watch de ce poste) ou
  `make glorfindel-host-watch-key` (celle de H0, lue dans son conteneur par SSH, clé d'hôte épinglée)
  donnent `export EREGION_WATCH_KEY=ed25519:<base64 de 32 octets>` et l'empreinte
  (`SHA256:…`, la forme d'une empreinte SSH). Jamais la clé privée.

## Le battement signé

La watch signe ce qu'elle écrit pour les injecteurs (`~/.glorfindel/injectors/watch_heartbeat`) et
dans le canal retour (`heartbeat.json`). Elle y ajoute trois champs :

- `seq`, un compteur qui ne fait que monter : les millisecondes de sa date, un de plus que le
  dernier quand deux tombent dans la même ;
- `key`, l'empreinte de sa clé — dite, jamais crue : la vérification se fait avec la clé épinglée ;
- `sig`, la signature Ed25519 de **`eregion.watch-beat/1`, un saut de ligne, puis le JSON canonique
  de tous les autres champs** (clés triées, sans espace) : la date, le périmètre, et sur le canal
  `since`, `windows` et `covers` (SEC21b) aussi.

Le canal local des verdicts (SEC18, `runs/verdicts/heartbeat.json`) n'est pas signé : il porte
exactement ses champs, et la garde ne le lit jamais.

## Ce que l'injecteur refuse, avant tout appel au cloud

La clé publique vient de **`EREGION_WATCH_KEY`, l'environnement de l'injecteur**, et de rien
d'autre : `orodruin.env` sur Orodruin, l'environnement de l'opérateur sur un poste (`.envrc`, passé
aux conteneurs par le compose et le Makefile). Jamais du canal, jamais du battement. L'ordre de la
garde : le battement frais (sinon son âge est dit), puis signé, puis lié au même abonnement (SEC5).
Sont refusés, la raison dite :

| Cas | Ce que dit le refus |
|---|---|
| aucune clé épinglée, ou pas une clé | `no watch key pinned (EREGION_WATCH_KEY)` et le geste (`make watch-key`, `make glorfindel-host-watch-key`, `orodruin.env`) |
| un battement sans signature (une watch d'avant SEC19, une main qui écrit là, une watch sans clé) | `unsigned` |
| signé d'une autre clé | `signed by another key`, les deux empreintes |
| une signature qui ne tient pas (un champ changé après la signature, l'empreinte d'une autre clé recopiée, une signature faite pour un autre usage) | `its signature does not hold` |
| un compteur sous celui déjà vu (un battement plus ancien rejoué après un plus récent) | `not above one already seen` |

**Le compteur vu** est gardé par clé dans `runs/orodruin/.watch_seen.json`, le répertoire des
injecteurs (SEC18). Le même battement relu (avant chaque action d'un run) n'est pas un rejeu. Un
fichier qu'on ne peut pas écrire n'est pas un refus : ce qui est lu est vérifié quand même. La
console montre la garde comme un injecteur la lit (Dagorlad) sans tenir ce compteur.

`--without-glorfindel` reste la dérogation de développement, inscrite au rapport (V1) : elle ne lit
aucun battement.

## Les détections signées (SEC21, #530)

Le battement dit qu'une watch vit ; les détections disent ce qu'elle a vu d'un run, et c'est ce que
mesure un injecteur. Depuis WC1 (#523), d'autres identités que H0 peuvent écrire le canal retour :
non signée, une détection pouvait fausser la mesure d'un run, dans un sens comme dans l'autre.

**Ce que la watch signe.** Chaque blob `detections/<run_id>/<signal_id>.json` porte deux champs de
plus (`eregion_core/watch_key.py`, `sign_detection` ; `eregion_core/watch_channel.py`,
`Publisher._signed_detection`) :

- `key`, l'empreinte de sa clé — dite, jamais crue ;
- `sig`, la signature Ed25519 de **`eregion.watch-detection/1`, un saut de ligne, puis le JSON
  canonique de tous les autres champs** : le run (`exercise_run`), le signal (`signal_id`), ce qui
  a été vu (`event`, `ttp`, `resource_id`, `rule`, `watch_run_id`) et quand (`detected_at`).

La même clé que le battement, sous un autre domaine : une signature de battement ne se lit jamais
comme une détection, ni l'inverse. Pas de compteur : ce qui lie une détection, c'est son run et son
signal, que l'injecteur compare au blob qu'il lit. Une watch sans clé publie ses détections sans
signature et le dit une fois dans son journal ; les injecteurs ne les comptent pas.

**Ce que l'injecteur refuse.** Annatar ne compte une détection pour « vu » que si la clé épinglée
(`EREGION_WATCH_KEY`, jamais une clé lue dans le canal) l'a signée sous ce domaine, pour le run
qu'il lit, sous le nom de son propre signal (`watch_channel.vouched_detections`,
`watch_key.detection_refusal`). Sinon, elle est refusée :

| Cas | Ce que dit le refus |
|---|---|
| aucune clé épinglée | les mots de SEC19, `no watch key pinned (EREGION_WATCH_KEY)` et le geste — la garde a déjà refusé le run avant tout appel au cloud |
| une détection sans signature (une watch d'avant SEC21, une main qui écrit là, une watch sans clé) | `unsigned`, et le geste : mettre Glorfindel à jour |
| signée d'une autre clé | `signed by another key`, les deux empreintes |
| une signature qui ne tient pas : un champ changé, ajouté, retiré ou d'un autre type après la signature, l'empreinte de la clé épinglée recopiée, une signature faite pour un battement | `its signature does not hold` |
| recopiée d'un autre run | `a detection of another run (…) copied here` |
| recopiée sous le nom d'un autre signal | `a detection of another signal (…) copied under this name` |

Une détection refusée **n'est jamais comptée pour « vu »**. Elle est dite, une fois par blob :
dans la console du run, dans le journal d'Orodruin (`detection_refused`, la ligne du run,
`Session.declare`) et dans le rapport du run (`metrics.detection_refused`, chacune bornée). Les
vingt premières du run seulement (`MAX_REFUSED`, pour le run entier, pas pour chaque lecture) : un
rédacteur qui ferait tourner ses blobs n'inonde ni le journal ni le rapport. Les autres sont
comptées : `metrics.detection_refused_total`, le plus grand nombre de refus dans une lecture du
canal (chaque lecture liste tous les blobs du run), et la sortie du run dit ce nombre. L'empreinte
qu'un blob prétend (`key`) n'est dite qu'en ASCII imprimable, pour une détection comme pour un
battement : jamais une séquence d'échappement vers le terminal ni le rapport. Un run dont aucune détection n'est crue et qui en a vu de refusées est **`unknown`, jamais
`missed`** : un `detection_missed` ferait proposer une règle pour une technique peut-être détectée.
Une détection signée à côté d'une refusée compte, et le refus est dit.

**Le battement qui prouve un « missed »** est vérifié comme celui de la garde. Un run conclut à un
miss seulement sur le battement de fin d'attente (`miss_unprovable`, #159). Sur le canal de stockage,
ce battement n'est cru que signé par la clé épinglée (`watch_gate.miss_proof`, la preuve même de la
garde). Non signé, d'une autre clé, à la signature qui ne tient pas, ou au compteur déjà dépassé
(un rejeu) : le run est `unknown`, la raison dite, sans `detection_missed`. Un « missed » ne vient
donc lui aussi que de la watch, quel que soit le nombre de rédacteurs du canal. Le canal local des verdicts
(SEC18, `runs/verdicts/`) ne change pas : ses verdicts gardent leurs champs exacts, sans signature ;
seule la watch de ce poste l'écrit, le rouge le lit en lecture seule, et il ne sert qu'en l'absence
de canal de stockage.

**Le passage d'une version à l'autre.** Aucune option ne fait croire une détection non signée.

- **Une watch à jour, des injecteurs d'avant** : les deux champs de plus sont ignorés, la détection
  compte comme avant. Rien ne casse ; rien n'est encore vérifié.
- **Une watch d'avant, des injecteurs à jour** : chaque détection est refusée (`unsigned … update
  Glorfindel`) ; le run est `unknown`, jamais `missed` ni `detected`, et le dit. La garde, elle,
  passe toujours : le battement est signé depuis SEC19.
- **L'ordre** : la release publiée, le CD de H0 la déploie (la watch de H0 signe ses détections) ;
  puis Orodruin, par OI3 ou `make orodruin-push REF=<tag>`. Une watch de poste ou d'équipe (WC1) :
  `make glorfindel-restart` après la mise à jour. Aucune clé nouvelle, aucune épingle nouvelle :
  `EREGION_WATCH_KEY` reste celle de SEC19.

## Ce que le battement couvre (SEC21b, #535)

Avec SEC21, un « missed » ne reposait que sur un battement signé. Mais ce battement ne disait pas
quelles détections il couvrait. Une détection retirée du canal, sous un vrai battement, ne se voyait
donc pas : le run concluait « missed » au lieu de « detected ». Aucune action n'en dépendait, seule
la mesure.

**Ce que la watch écrit.** Le battement du canal porte un champ de plus, `covers`
(`eregion_core/watch_channel.py`, `Publisher._covers`). Pour chaque fenêtre qu'il nomme dans
`windows`, c'est la liste triée des `signal_id` de chaque détection livrée pour elle, une fenêtre
sans détection a une liste vide. Par exemple : `"covers": {"20261104T101500Z": ["rule-t1136-001-v1-ab12cd34"]}`.
- **Livrée** veut dire écrite et acquittée par le stockage avant ce battement, à ce tour ou à un
  tour d'avant : chaque battement suivant liste encore ce qui a été livré avant lui. Chaque fenêtre
  ne liste que ses propres détections. La watch ne bat jamais tant qu'une détection attend : chaque
  détection listée était donc dans le canal avant que le battement y soit.
- **Sous la signature existante**, sans changer de domaine (`eregion.watch-beat/1`). Retirer une
  détection de la liste, ou retirer le champ, défait la signature. Un domaine nouveau aurait fait
  refuser tout battement par la garde des injecteurs d'avant, donc tout run.
- **Borné** : 256 détections par fenêtre au plus (`MAX_COVERED`). Au-delà, la fenêtre reste dans
  `windows` mais sort de `covers` : son run ne peut pas conclure à un « missed ». Un run du banc en
  voit quelques-unes ; une liste vaut une quarantaine d'octets par détection.
- **Un budget pour toutes les fenêtres** : `covers`, tel qu'écrit, pèse au plus la moitié de ce
  qu'un injecteur lit d'un blob (`MAX_COVERS_BYTES = MAX_BLOB_BYTES / 2`, 512 Kio). Au-delà, la
  watch retire les fenêtres les plus lourdes d'abord, et le dit une fois dans son journal. Leurs runs
  sont `unknown`, et le run le dit. Sans ce budget, vers 64 fenêtres pleines, le battement aurait
  dépassé 1 Mio : le lecteur le refuserait, et la garde V1 refuserait tout run.
- **La watch garde ce qu'elle a livré** aussi longtemps qu'une fenêtre peut vivre : elle oublie une
  détection après `KEEP_S` (deux heures plus la grâce), la plus longue vie d'une fenêtre.
- **Le canal local des verdicts (SEC18) ne change pas** : son battement garde exactement
  `BEAT_FIELDS`, sans `covers`, et un run qui le lit ne fait pas cette comparaison.

**Ce que le lecteur compare.** Annatar ne compare qu'à la fin de l'attente, sur le canal de
stockage, et seulement si aucune détection n'a été vue (`annatar/runner/engine.py`,
`_settle_through_channel` ; `watch_channel.uncovered`). Le battement de fin d'attente doit d'abord
tenir : SEC21, puis `miss_unprovable`. **L'ordre est fixe** : le battement d'abord, puis la liste
des détections. Chaque détection que le battement couvre doit être dans cette liste, signée par la
clé épinglée (`vouched_detections`).

| Ce que le run lit | Ce qu'il conclut |
|---|---|
| chaque détection couverte, relue | un silence est un « missed », comme avant |
| une détection relue que le battement ne liste pas (livrée après lui) | admise : rien ne manque |
| une détection couverte absente (retirée, ou remplacée par un blob refusé) | `unknown`, jamais `missed` ; le blob manquant dit |
| un battement sans `covers` (une watch d'avant ce lot) | `unknown`, avec la raison et le geste : mettre Glorfindel à jour |
| un battement qui ne liste pas le run (plus de 256 détections, ou au-delà du budget) | `unknown`, et c'est dit |
| un `covers` réécrit par une main | la signature ne tient pas (SEC21) : `unknown` |

**Une détection manquante est dite à trois endroits :**
- dans la sortie du run ;
- dans le journal d'Orodruin, par la ligne du run (`detection_missing`) ;
- dans son rapport (`metrics.detection_missing`, et `metrics.detection_missing_total` pour le
  nombre entier).

Chaque blob n'est dit qu'une fois, et seulement les vingt premiers (`MAX_MISSING`) ; les autres sont
comptés. Une détection couverte remplacée par un blob refusé est dite deux fois : refusée (SEC21)
et manquante. La raison du run dit le refus d'abord, puis le manque. Le règlement de fin d'attente
conclut lui-même à `unknown`, sans compter sur une conversion par l'appelant. Le nom d'un signal n'y est dit qu'en caractères de nom de blob, jamais une séquence
d'échappement. Une détection du run relue et vouchée donne toujours « detected », même si une autre
couverte manque : une preuve du « vu » n'est jamais retirée.

**L'ordre, et pourquoi.** Lu dans l'autre sens, la liste puis le battement, une détection livrée
entre les deux serait couverte sans avoir été lue : un `unknown` à tort, jamais un faux « missed ».
Dans l'ordre retenu, la comparaison est exacte, et l'ordre est tenu par un mutant (M3746).

**Le passage d'une version à l'autre.** Il est strict. Aucune option ne fait prouver un « missed »
par un battement qui ne dit pas ce qu'il couvre.
- **Une watch à jour, des injecteurs d'avant** : le champ de plus est ignoré, la signature tient.
  Rien ne casse, mais rien n'est encore comparé.
- **Une watch d'avant, des injecteurs à jour** : un silence donne `unknown`, avec la raison (« the
  heartbeat does not say which detections it covers ») et le geste. Un « detected » n'est pas
  touché. La garde passe toujours.
- **Le passage est borné par la mise à jour de la watch** :
  - la release publiée, le CD de H0 la déploie d'abord ;
  - puis Orodruin, par OI3 ou par `make orodruin-push REF=<tag>` ;
  - une watch de poste ou d'équipe (WC1) se met à jour par `make glorfindel-restart`.
- **Aucune clé nouvelle, aucune épingle nouvelle.**
- **Un vieux battement rejoué ne rouvre pas le passage.** Il faut un battement écrit après la fin de
  l'attente, et une watch à jour n'en écrit plus sans `covers`. Seul un retour arrière de la watch
  elle-même le rouvre, et il donne `unknown`.

## Ce que cela prouve, et ce que non

**Prouvé** : la watch qui détient cette clé a écrit ce battement, pour cet abonnement, il y a moins
de 90 s, et l'injecteur n'en a pas vu de plus récent. **Pas prouvé** : que les workspaces de la watch
voient la cible, ni sa santé au-delà de sa boucle de battement. **Ce qui reste** : qui lit la clé
privée (root sur l'hôte de la watch, l'utilisateur de la watch) signe comme elle ; un battement
capturé reste rejouable dans sa fenêtre de 90 s tant qu'aucun plus récent n'a été lu par cet
injecteur.

**Pour une détection (SEC21)** : prouvé, la watch qui détient cette clé l'a publiée, pour ce run et
ce signal, telle qu'elle est lue — un « vu » ne vient plus que d'elle, quelle que soit l'identité
qui écrit le canal ; un « missed » ne repose que sur un battement qu'elle a signé.

**Pour un « missed » (SEC21b)** : prouvé, la watch a signé un battement, écrit après l'attente, qui
nomme chaque détection qu'elle a livrée pour ce run, et le run les a toutes relues après lui. Une
détection retirée du canal sous un battement vrai donne `unknown`, dite, jamais `missed`.

**Fermé** (SEC21b, #535) : le battement dit ce qu'il couvre, et une détection retirée se voit.

**Ce qui reste** :
- une détection que la watch n'a jamais notée (sa règle n'a pas tiré, l'ingestion a dépassé
  l'attente) : un vrai raté, mesuré comme tel ;
- une détection livrée entre le battement que le run lit et sa liste des détections, puis retirée
  avant cette liste : le battement lu ne la couvre pas, son retrait ne se voit pas. La fenêtre dure
  le temps entre deux lectures (moins d'une seconde), et la détection doit être arrivée après la fin
  de l'attente ;
- le canal local des verdicts (SEC18) : ni signé ni couvert, le répertoire de la seule watch du
  poste, que le rouge monte en lecture seule ;
- qui lit la clé privée signe comme la watch, comme avant.

## FS1 reprend cette clé (#413)

La file d'actions signée de FS1 signera avec **la même clé**, pour un autre usage. Ce qui sépare
les usages, c'est **le domaine**, le préfixe de ce qui est signé :

- un battement : `eregion.watch-beat/1\n` + le JSON canonique ;
- une détection du canal retour (SEC21) : `eregion.watch-detection/1\n` + le JSON canonique ;
- une action de la file (FS1) : `eregion.action-queue/1\n` + le JSON canonique de l'action.

Une signature faite pour un usage ne se lit jamais comme un autre
(`tests/unit/test_watch_key.py::test_a_signature_under_another_domain_never_reads_as_a_heartbeat`,
`tests/unit/test_signed_detections.py::test_a_detection_s_signature_never_reads_as_a_heartbeat`).
FS1 ajoute son domaine à `watch_key.py`, signe par `Signer.sign(domain, body)` et vérifie par la même
clé épinglée ; il ne tire pas de seconde clé. Changer de clé (une clé lisible par d'autres, une VM
reconstruite) se fait une fois pour les deux usages : la retirer, laisser la watch en tirer une
autre, épingler la nouvelle chez les injecteurs.
