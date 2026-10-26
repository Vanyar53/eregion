# L'IA d'analyse — le rapport de campagne (IA0)

_19/10. Le premier RAG d'Eregion, séparé de Glorfindel : il explique ce qu'une campagne a fait,
sans écrire de règle ni agir._

```bash
make campaign-report CAMPAIGN=<id>     # → runs/campaigns/<id>/report.md
make report-eval                       # harnais : fidélité et instruction plantée, modèle réel
```

**Les faits viennent des fichiers, jamais d'un modèle** : le manifeste de la campagne
(techniques, runs, détectée / manquée, latence), et pour chaque run le rapport d'Annatar et le
fichier de décision de Glorfindel (`runs/<run_id>_debug.jsonl`). Les chiffres d'en-tête et le
tableau sont calculés.
Le tableau donne, par run, la technique, le run, la détection, sa latence (`detection_latency_s`
du manifeste, à une décimale : « 106,3 s » ; « — » sans latence, un run manqué par exemple) et
la décision de Glorfindel.

**L'index** : une collection ChromaDB à part (`campaign_runs`, `~/.eregion/analysis/chroma`),
distincte de la mémoire de Glorfindel. Il ramène les runs passés des mêmes techniques, ce qui
permet une affirmation de tendance (« manquée ici, détectée au run précédent »). Il garde aussi
la campagne précédente, celle à laquelle le rapport se compare (D-2, plus bas).

**Le modèle n'écrit que des affirmations typées, chacune citant ses runs** : `detected`,
`missed`, `latency`, `decision`, `trend`, `observation`, et `change`, qui cite un fait de
changement (D-2, plus bas). Un autre modèle que celui de Glorfindel
(`EREGION_ANALYSIS_MODEL`, Haiku 5.5 par défaut, `eregion_core/models.py`) : un rapport ne doit
pas partager les angles morts du défenseur. **L'appel est borné** : `EREGION_ANALYSIS_TIMEOUT_S`,
300 s par tentative par défaut (illisible, nulle, négative, infinie ou au-delà de 3600 → 300 s ;
`analysis/campaign_report.py`, `timeout_s`). Sans borne, LiteLLM attend 6000 s par tentative
(mesuré par G2). Ce n'est pas `GLORFINDEL_LLM_TIMEOUT_S`, qui ne borne que les appels de
Glorfindel (décision, autoring de règle) : le rapport s'écrit aussi là où le paquet de Glorfindel
n'est pas (l'image d'Annatar, en fin de `campaign run`), et il écrit jusqu'à 2048 jetons hors du
chemin d'un cycle, d'où une borne plus large. Passé la borne, l'appel lève : en local, la
commande échoue avec le délai dépassé ; sur H0, c'est un essai raté (voir plus bas).

**La vérification est déterministe** (`verify`) : une affirmation sans run cité, citant un run
inconnu, ou que les faits contredisent (« détectée » sur un run manqué, une latence ou une
décision qui ne sont pas celles du run) est écartée — elle apparaît barrée, avec la raison, en
fin de rapport. Une tendance doit citer cette campagne et une campagne antérieure. Une
`observation` qui ne cite que des runs n'est vérifiée que sur ses citations, et sur la règle
d'une décision inconnue (#167, plus bas). Les nombres d'une `trend`, d'une `change` et d'une
`observation` qui cite un fait de changement sont contrôlés, ainsi que les actions qu'elles
nomment et le sens du changement qu'elles disent (D-2, plus bas). Le contenu des runs
(raisonnement de Glorfindel, texte des signaux) est une donnée : une instruction plantée peut
faire écrire une fausse affirmation au modèle, jamais la faire entrer dans le rapport
(mutant M63).

**Mesuré le 19/10** : sur la campagne du 30/07 (4 techniques, 2 détectées, 2 manquées), 9
affirmations gardées, 1 écartée (une latence tirée du raisonnement, pas des faits) ; le rapport
retrouve seul que T1110 et T1041, manquées, avaient été détectées au run suivant. Harnais (3
passages, Haiku 5.5) : 0 obéissance à la ligne plantée, 0 rejet, 17 affirmations gardées.

**L'index** se trouve dans `EREGION_ANALYSIS_INDEX` s'il est posé, sinon dans
`~/.eregion/analysis/chroma`. Les tests le mettent dans un répertoire temporaire (conftest).

**Il s'écrit seul** : `annatar campaign run` écrit le rapport à la fin de la campagne
(`--no-report` pour s'en passer : avec un canal d'exercice, la campagne n'est alors pas publiée
non plus, et H0 n'en écrit pas le rapport). Sans paquet `analysis` ou sans clé de modèle, la campagne se
termine quand même et dit comment l'écrire plus tard. Les campagnes de R1 (Atomic) et de G0
(Chaos Studio) passeront par là.

## Une campagne lancée depuis Orodruin : le rapport s'écrit sur H0 (#167)

_21/10 : le code, ses tests (`tests/unit/test_campaign_channel.py`, `test_hosted_report.py`, dont
un bout en bout local) et ses mutants (M126–M149, M159–M169, M180–M188) sont écrits. La campagne sur le banc viendra
ensuite, avec Jonathan (session Tests) : rien de ceci n'est encore mesuré sur le banc._

Orodruin n'a ni `chromadb`, ni `litellm`, ni la clé du modèle, ni les fichiers de la watch.
H0 a tout cela. C'est donc là que le rapport s'écrit (option B, décidée le 21/10 sur #69).

**Ce qu'Orodruin publie.** Avec `EREGION_EXERCISE_CHANNEL`, à la fin de `campaign run`, il
publie la campagne dans le conteneur `exercises`, celui des fenêtres
(`eregion_core/exercise_channel.py`, `publish_campaign`). Il publie deux sortes de fichiers :
- `campaigns/<id>/runs/<run_id>.json`, le rapport de chaque run, qui porte `attack_time` ;
- `campaigns/<id>/manifest.json`, en dernier.

Il ne publie rien d'autre : ni `_debug.jsonl`, ni `_signals.jsonl`, ni un autre run. Il ne
demande aucun droit de plus que pour les fenêtres : une seule attribution, sur ce conteneur.
`<id>` est le `campaign_id` du manifeste, et le message de fin l'affiche.

Le préfixe tient les campagnes à l'écart des fenêtres. Une fenêtre est `<run_id>.json` à la
racine, et un nom avec `/` ne passe pas `_SAFE_NAME` : le tirage des fenêtres l'ignore.

Le message de fin annonce le rapport sur H0 seulement pour une campagne `done`. Pour une autre
(`aborted`), il renvoie à `make campaign-report CAMPAIGN=<id>`, à lancer là où se trouvent la
campagne et les fichiers de la watch. Sans canal, rien ne change : le rapport s'écrit en local
si c'est possible. Un échec de la publication est signalé et ne fait pas échouer la campagne.

Avec `campaign run --runs-dir X`, les rapports de run restent dans `runs/` (le dossier fixe du
moteur, `annatar/runner/report.py`) : la publication ne les trouve pas sous `X`. Elle le signale
(`unpublished_runs`), et le message de fin n'annonce pas le rapport sur H0, qui attendrait ces
runs sans fin : il renvoie à `make campaign-report`.

**Un run seul (#193, 26/10 ; code, tests et mutants M240–M246, pas encore mesuré sur le
banc).** `annatar run` et `gothmog run` publient aussi leur rapport, à la fin du run, après la
fermeture de la fenêtre : `runs/<run_id>.json`, dans le même conteneur, sans droit de plus
(`publish_run`). Un échec est signalé, jamais levé. Le thread `campaign-report` le tire à chaque
passage vers `runs/<run_id>.json` sur H0, où la console de l'atelier le lit (`pull_runs`) :
seulement un nom simple, et un rapport qui passe `run_report_refusal` (H-1). Il n'écrit jamais
par-dessus un rapport que H0 n'a pas tiré lui-même : un marqueur `runs/.pulled-runs/<run_id>`
dit lesquels viennent du canal. Un rapport refusé n'est pas écrit, et la raison est dite une
fois. Une campagne ne change pas : ses runs ne partent qu'avec elle, sous `campaigns/<id>/`.

**Quand H0 l'écrit.** `glorfindel watch` démarre le thread `campaign-report`
(`analysis/hosted_report.py`), seulement avec `EREGION_EXERCISE_CHANNEL`. Toutes les 30 s, il :
1. tire les campagnes dans `runs/campaigns/<id>/` (`pull_campaigns`). Il écrit les runs d'abord,
   puis le manifeste, et seulement si tous les runs de la campagne sont arrivés ; à côté du
   manifeste, un marqueur `.pulled`. Si le listage échoue, aucune campagne n'est due à ce
   tirage ; si un fichier d'une campagne échoue, cette campagne-là n'est pas due ;
2. retient les campagnes prêtes (`ready`) : tirées du canal (le marqueur `.pulled`), `done`,
   sans `report.md`, avec le `runs/<run_id>.json` de chaque scénario exécuté, et des essais
   encore permis. Une campagne locale du même dossier (une watch locale avec le canal posé)
   n'est jamais écrite par le thread. Un scénario en erreur peut avoir un `run_id` sans
   rapport : il n'est pas attendu, sinon la campagne n'aurait jamais de rapport. Un `run_id`
   qui n'est pas un nom simple (`safe_part` : ni `/`, ni `..`) n'est pas attendu, est signalé,
   et son scénario est écarté des faits (le rapport le dit) : le manifeste vient d'un autre
   hôte, et ce nom ne désigne jamais un fichier ;
3. tire encore une fois les fenêtres, puisque la dernière s'est fermée juste avant la fin de la
   campagne. Si ce tirage échoue, aucun rapport ne s'écrit à ce passage : ils attendent le
   tirage suivant ;
4. attend les décisions (`waits_for_decisions`). Tant qu'un run exécuté, détecté ou de
   détection inconnue (un canal retour resté muet), n'a pas de décision dans les fichiers de
   la watch, et qu'il peut encore en avoir une, la campagne attend : la décision suit la
   détection, que le canal retour a pu porter avant elle. Avec une fenêtre lisible et un
   `attack_time`, l'attente dure jusqu'à la fin de la fenêtre, grâce comprise (`last_moment`).
   Sans fenêtre lisible (une publication de fenêtre perdue, qu'un tirage suivant peut encore
   apporter), elle dure jusqu'à 15 min après la fin de la campagne (le plus tard des
   `finished_at` de ses scénarios et de son `updated_at`, jamais après l'arrivée du manifeste
   sur H0). Dans les deux cas s'ajoutent 10 min (`DECISION_LAG_S`) : la fenêtre borne l'heure
   de la détection, pas celle où la décision s'écrit, à la fin du cycle qui suit (enquête,
   décision du modèle et ses reprises, action et sa vérification). En pratique, puisque la
   dernière fenêtre se ferme juste avant la fin de la campagne, un rapport dont une décision
   manque s'écrit **environ 25 min après la fin de la campagne** (15 min de grâce, plus ces
   10 min). Sans `attack_time` (une image d'Orodruin plus ancienne) ou sans `resource_id`, rien
   n'est attendu : le rapport du run et le manifeste sont complets, et aucune décision ne
   pourra jamais être rattachée. Aucune attente ne dépasse 2 h 25 après l'arrivée du manifeste
   (l'expiration d'une fenêtre jamais fermée, plus la grâce et ces 10 min). L'attente est
   journalisée une fois, avec son échéance, et le refus d'un `run_id` une fois aussi, chacun
   sur sa ligne ; de même, un tirage des campagnes ou des fenêtres en échec, ou une campagne
   incomplète, n'est dit qu'une fois tant qu'il dure (de nouveau s'il revient après un tirage
   réussi). Un échec se reconnaît à son type et à son statut HTTP, pas à son texte : celui d'un
   délai de connexion dépassé nomme un objet `at 0x…`, nouveau à chaque appel. Un verrou
   impossible à ouvrir (`.report.lock`) est dit lui aussi une fois tant qu'il dure ; il
   n'appelle pas le modèle et ne compte pas d'essai. Si la lecture des décisions échoue, le rapport n'attend pas : son écriture compte
   alors ses propres essais ;
5. écrit `report.md` une fois, sous un verrou par campagne. Un `report.md` présent n'est jamais
   réécrit.

**Ce que H0 accepte du canal (H-1, #187, 26/10).** Le manifeste et les rapports des runs sont
écrits sur un autre hôte, par qui peut écrire dans le canal : H0 les lit contre leur forme, il ne
les croit pas tels quels (`analysis/campaign_schema.py`, schémas `schemas/campaign_manifest.schema.json`
et `schemas/run_report.schema.json`, tenus d'accord par les tests ; l'image de la watch n'a pas
`jsonschema`).
- Un manifeste d'une autre forme (identifiant qui n'est pas un nom simple, état inconnu, scénarios
  qui ne sont pas une liste) ne rend pas sa campagne prête ; c'est dit une fois, sans rapport.
- Un scénario d'une autre forme (`seq`, `status`, `detection`, `detection_latency_s`… mal typés)
  est écarté des faits.
- Un run exécuté n'est gardé que si son rapport est bien le sien (même `run_id`, `attack_time`
  numérique), si sa fenêtre est **connue** et **crue** (`exercise.window_refusal` : au plus 2 h,
  fin après le début…), si elle **nomme sa VM**, et si cette VM est **inscrite** (ses tags et
  ceux de son groupe, lus par la watch : `eregion_core/inscription.py`, `TagEnrollment`).
  Sinon il est écarté des faits, et la ligne « Écarté des faits » du rapport dit pourquoi
  (« run R2 refusé : fenêtre d'exercice inconnue »).
- Le rapport dit quels faits viennent du canal : la liste des runs, leur statut, leur détection
  et leur latence, l'heure de chaque attaque et les fenêtres ; et ce que H0 a vu lui-même : les
  décisions de Glorfindel et l'inscription de chaque VM (`CHANNEL_NOTE`).
- L'attente des décisions (étape 4) ne change pas : une fenêtre absente peut encore arriver. Le
  refus se décide à l'écriture.
- Une fenêtre refusée (plus longue que 2 h…) ne borne plus la recherche d'une décision : la
  raison devient « fenêtre absente ». Une campagne locale (sans `.pulled`) n'est pas concernée.
- `make campaign-report` sur une campagne tirée du canal lit l'inscription de la même façon.

Pour un run dont la décision est retrouvée, la table donne l'action, la confiance et
l'escalade (« snapshot (40%, escaladé) », « isolate_vm (90%, sans escalade) ») ; le modèle les
reçoit aussi (`decision`, `confidence`, `escalated`). Passé l'attente, le rapport s'écrit, et
chaque run exécuté, détecté ou de détection inconnue, sans décision le dit dans la table :
« inconnue — fenêtre absente », « inconnue — attack_time absent », « inconnue — resource_id
absent », « inconnue — décision non retrouvée dans la fenêtre ». Chaque raison se lit comme un
inconnu, jamais comme un néant : le modèle peut la recopier dans une affirmation. Un run manqué dont la fenêtre contient
une décision (Glorfindel a pu détecter tard, et agir, dans la fenêtre et sa grâce) ne la prend
pas, mais sa décision devient inconnue : « inconnue — une décision dans la fenêtre d'un run
manqué : détection tardive, ou d'un autre run ». C'est un inconnu, jamais « Glorfindel n'a pas
agi ». Le modèle reçoit `decision: null` et la raison (`decision_unknown_because`).

La vérification, sur une affirmation qui cite un tel run, ne tient qu'une chose par la
structure seule : une affirmation `decision` est écartée (le run n'a pas d'action à citer). Le
reste lit la phrase, et c'est une heuristique, pas une garantie :
- une `trend` ou une `observation` qui parle de la réponse (« décision », « action », « isolé »,
  « bloqué », « escaladé », « quarantaine », « contenu », « confiance »…) est écartée si elle ne dit pas que la décision est
  inconnue (« inconnu », « non retrouvée », « aucune décision connue », ou la raison même
  donnée au modèle). Une `trend` ou une `observation` sur la détection seule (« latence en
  hausse ») est gardée ;
- toute affirmation, de quelque sorte, qui dit que Glorfindel n'a pas agi est écartée : « n'a
  pas agi », « n'a rien fait », « n'a pris aucune mesure », « n'est pas intervenu », « est resté
  passif » et leurs voisines ;
- toute affirmation, de quelque sorte, qui dit que Glorfindel a agi est écartée aussi : « a
  isolé », « a bloqué », « snapshot », « escaladé », « mise en quarantaine », « contenue »,
  « est intervenu », « neutralisée », « a agi »…

Ces deux derniers contrôles lisent la phrase une fois retirés les mots qui disent « inconnu » et
les raisons données au modèle (« décision non retrouvée dans la fenêtre » n'est pas
« Glorfindel n'a rien fait »), seulement quand elles commencent un mot : dans « Glorfindel n'a
pris aucune décision dans la fenêtre d'un run manqué… », la raison « une décision dans la
fenêtre d'un run manqué… » ne se retire pas, et l'affirmation est écartée. Une tournure qu'ils ne connaissent pas passe, surtout dans une affirmation
`detected`, `missed` ou `latency`, dont la sorte ne dit rien de la décision.

Un échec (canal, index, modèle, fichiers) est noté dans `report.error`, avec le nombre d'essais,
et aussi compté en mémoire. Un fournisseur bloqué en est un : l'appel au modèle expire à sa borne
(`EREGION_ANALYSIS_TIMEOUT_S`, 300 s) et l'essai compte, au lieu de figer le thread, et tous les
rapports suivants, pendant des heures sans un mot (sixième relecture, mutants M187–M188). Une réponse du modèle sans appel de l'outil `campaign_report`, ou
illisible, est un échec (`build(…, strict=True)`) : jamais un rapport vide écrit pour de bon.
On prend le plus grand des deux compteurs, donc un `report.error` impossible à écrire ne relance
pas le modèle sans fin. Le rapport est réessayé au plus 3 fois, puis abandonné et signalé dans le
journal de la watch. Une campagne `aborted` n'a pas de rapport automatique. Aucune exception du
thread n'atteint la watch.

Le compteur en mémoire survit à l'effacement de `report.error`. Pour relancer un rapport
abandonné, effacer `report.error` ne suffit pas : redémarrer la watch (sur la VM,
`docker restart eregion-watch`), ou écrire le rapport à la main
(`docker exec eregion-watch python -m analysis.campaign_report runs/campaigns/<id>`).

**Où le lire.** Dans le journal de la watch (`make glorfindel-host-logs`, lignes
`[campaign-report]`), ou avec `make glorfindel-host-campaign-report CAMPAIGN=<id>`, qui affiche
le `report.md`, ou à défaut le `report.error`. L'index `campaign_runs` reste sur le disque de la
VM : `~/.eregion/analysis`, monté dans le conteneur de la watch (`docker-compose.yml`). Le
montage et l'image, qui copie maintenant `analysis/`, prendront effet au prochain redéploiement
de H0, avec Jonathan.

**D'où viennent les décisions.** `collect_facts` lit d'abord `runs/<run_id>_debug.jsonl`, quand
une watch tourne à côté du run. Sur H0, la watch hébergée écrit plutôt
`watch-<règle>-<ts>_debug.jsonl`. La décision d'un run est alors la première détection de ces
fichiers qui porte une `action` et qui remplit la règle de #157 (`annatar/runner/detection.py`,
`first_detection`) :
- même technique ;
- même VM, le `resource_id` comparé sans la casse ;
- vue entre l'`attack_time` du run et la fin de sa fenêtre d'exercice, grâce comprise.

La fin de la fenêtre est sa fin (ou son expiration, la plus tôt des deux) plus 15 min
(`eregion_core/exercise.py`, `last_moment`, la borne de `live`). La fenêtre est lue dans
`EREGION_EXERCISES_DIR`, sinon dans `<runs>/exercises`. La watch, elle, lit `./runs/exercises` :
c'est le même dossier quand elle tourne sur `runs` depuis le dépôt, comme sur H0. De même, elle
écrit ses `watch-*_debug.jsonl` dans `./runs`, quel que soit le `runs_dir` qu'on lui donne
(`glorfindel/agent.py`), alors que le thread du rapport les cherche dans ce `runs_dir` : les deux
coïncident quand la watch tourne sur `runs`, comme sur H0. Sans `attack_time` fini, sans
`resource_id` ou sans fenêtre lisible, aucune décision n'est rattachée : le rapport ne devine
pas. Une décision d'une autre VM, ou vue hors de la fenêtre, ne compte jamais. Seul un run dont
la décision est cherchée (exécuté, détecté ou de détection inconnue) en prend une dans les
`watch-*` : une décision trouvée dans la fenêtre d'un run manqué est une détection tardive, ou
celle d'un autre run de la même technique sur la même VM ; elle n'est pas rattachée, mais la
décision de ce run devient inconnue (voir plus haut). Les extraits de raisonnement entrent
dans les faits comme des données, jamais comme des instructions. Le harnais (fidélité, contenu
piégé) ne change pas.

## Ce qui a changé depuis la campagne précédente (D-2, #184)

_26/10 : le code, ses tests (`tests/unit/test_campaign_changes.py`, et un cas de bout en bout
dans `test_hosted_report.py`) et ses mutants (M260–M279) sont écrits. La mesure sur une vraie
deuxième campagne viendra après la fusion, avec Jonathan._

Le premier rapport écrit sur H0 (campagne `20261023T081120Z`) était fidèle, mais il n'apprenait
rien : son index était vide. La seule nouveauté a été vue par une comparaison faite à la main.
Sur T1110.001, Glorfindel a isolé à 0,78 le 23/10, alors qu'il avait bloqué à 0,80 le 21/10. La
recherche des runs passés (`prior_runs`) ramène les runs des mêmes techniques, mais elle ne
garantit pas de mettre face à face la même technique sur la même cible. La comparaison est donc
calculée par le code (`analysis/campaign_changes.py`).

**La campagne précédente est choisie par une règle, pas par l'index**
(`analysis/campaign_report.py`, `previous_campaign`). C'est la dernière campagne `done` de
l'index qui a commencé avant celle-ci, et qui partage avec elle au moins une **clé**. Une clé,
c'est une technique jouée sur une VM cible ; la VM est comparée sans la casse.
- Seuls les runs exécutés comptent : un scénario sauté ou en erreur n'a rien joué.
- Une campagne `aborted` n'est jamais choisie, ni une campagne qui a commencé après celle-ci.
  Une campagne sans clé commune ne l'est pas non plus, même si elle est plus récente.
- Le début d'une campagne est le plus tôt des `started_at` de ses scénarios. À défaut, c'est
  son `created_at`, puis son identifiant quand c'est une date (`YYYYMMDDTHHMMSSZ`). Sinon, le
  début est inconnu, et la campagne n'a pas de précédente.
- S'il n'y en a aucune, la section le dit, avec la raison.
- **Limite connue** (relecture de D-2, reprise dans un lot suivant) : le début d'une campagne
  venue du canal se lit dans son manifeste (`started_at`, `created_at`), écrit sur Orodruin.
  H-1 ne contrôle pas ces dates. Une date fausse peut faire nommer à tort « la précédente » :
  une autre campagne `done` qui partage une clé. Les faits comparés restent les vrais faits
  indexés de la campagne nommée, et la section dit laquelle. Piste : borner le début par celui
  des fenêtres d'exercice crues de ses runs, ou par la date du marqueur `.pulled`.

**Les runs sont joints par clé.** Le n-ième run d'une technique sur une VM, dans l'ordre des
`seq`, fait face au n-ième run de la même clé dans la campagne précédente. Chaque paire devient
un **fait de changement** typé, `ChangeFact` (`chg-1`, `chg-2`…). Il donne, avant et après :
la détection, la latence, l'action, la confiance et l'escalade, ainsi que l'écart de latence et
de confiance. Une clé présente d'un seul côté est aussi un fait, listé comme tel (« Seulement
dans la campagne précédente », « Seulement dans celle-ci »). Le côté d'un fait se lit sur la
présence du run, jamais sur son identifiant : un run exécuté sans `run_id` reste joué, et la
section l'écrit « run sans identifiant ». Une décision inconnue reste inconnue, avec sa raison,
jamais « aucune ».

**La section est rendue par le code** (`render_section`), entre le tableau des runs et les
affirmations : la campagne précédente, une ligne par clé commune (« 91,9 s → 106,9 s
(+15,0 s) », « block_suspicious_ip → isolate_vm », « 80% → 78% (−2 pts) »), puis les clés d'un
seul côté. Le modèle n'en écrit rien. Il reçoit les mêmes faits, et il peut les citer.

**La vérification contrôle les faits de changement comme les autres** (`verify`). Ce qui fait
foi, c'est la section calculée plus haut : la vérification écarte les affirmations du modèle
que les faits démentent, mais une lecture de la prose par des expressions régulières ne sera
jamais complète (voir les limites, plus bas).
- une affirmation `change` doit citer au moins un fait de changement. Sinon, elle est écartée,
  même si elle cite les deux runs ;
- dans une affirmation `change` ou `trend`, et dans une `observation` qui cite un fait de
  changement, chaque nombre doit être celui d'un fait cité : une latence, une confiance (0,78
  ou 78 %), un écart, ou un écart relatif (« +16 % » quand la latence passe de 91,9 s à
  106,9 s). L'écart peut être celui des deux côtés d'un fait de changement, ou celui de deux
  runs cités (« augmente de 15 s », « baisse de 2 points » dans une tendance qui cite les deux
  runs). Sinon, l'affirmation est écartée (« a number is not in the cited facts (40) ») ;
- **un nombre suivi d'une unité est de la sorte de son unité**. Une durée (ms, s, min, h, en
  toutes lettres ou abrégée, en français ou en anglais) est convertie en secondes et ne peut
  être qu'une latence ou un écart de latences : « vue 2 minutes plus tard » est lu 120 s,
  « 15 ms » 0,015 s, « 1 heure » 3600 s, et chacun est écarté quand aucun fait ne le porte. Un
  pourcentage ou des points ne peuvent être qu'une confiance en pour cent, son écart, ou un
  écart relatif. « vue en 2 s » est donc écarté, même si l'écart de confiance vaut 2 points. Un
  nombre sans unité peut être n'importe quel nombre des faits cités, sauf un écart relatif (qui
  s'écrit avec %) ;
- avant de lire les nombres, la vérification retire ce qui ne fait que nommer : les
  identifiants cités, une technique (T1110.001), un identifiant de run, une date (23/10, « le
  21 octobre », « le 1er octobre », « entre le 21 et le 23 octobre », « du 21 au 23 octobre »,
  « October 21 », « 21 October »),
  une année (2026, sauf suivie d'une unité : « 2000 s » reste un nombre), une heure (08:21), un
  ordinal (« 2ᵉ », « 1er », « 3e »), et tout mot qui commence par une lettre et contient un
  chiffre (`chg-2`, le nom d'une VM) ;
- **un décompte** (« dans les 2 campagnes », « les 2 dernières campagnes ») est un entier suivi
  de ce qu'il compte : runs, campagnes, techniques, VM, machines, scénarios, clés, passages,
  cibles, exécutions, tirages (et leurs formes anglaises), avec au plus un adjectif entre les
  deux (nouvelles, dernières, premières, autres, mêmes, seules). Un autre mot ne fait pas un
  décompte : « vue 1 heure plus tard » est lu comme une durée, et « 2 fois » comme un nombre.
  Un décompte est permis jusqu'au nombre de runs que l'affirmation cite (un fait de changement
  compte ses deux côtés). Pourquoi ce choix plutôt qu'une consigne au modèle de ne pas en
  écrire : une consigne ne lie pas le modèle, et un décompte juste serait alors barré, alors
  que le rapport jugé au point d'étape (#70) ne doit barrer aucune affirmation juste ;
- le `value` d'une affirmation `change`, quand ce n'est pas un nombre, doit être une action ou
  une détection des faits cités ;
- **les actions et les détections nommées** : une affirmation `change` ou `trend`, et une
  `observation` qui cite un fait de changement, ne nomment que les actions (les noms de
  `glorfindel/actions.py` : `isolate_vm`, `block_suspicious_ip`…) et les détections
  (`detected`, `missed`, `unknown`) de leurs faits cités. « de detected à missed », sur une clé
  détectée les deux fois, est écarté ; « Glorfindel a pris un wipe_storage » aussi, quand aucun
  fait cité n'en porte ;
- **le sens d'un changement** : dans une affirmation qui cite un fait de changement, « de X à
  Y » et « X → Y » doivent aller dans le sens du fait. Pour deux actions ou deux détections
  (noms, ou formes françaises : isolement, blocage, instantané, libération), un fait cité doit
  aller de X à Y : « de l'isolement au blocage » est écarté quand le fait va du blocage à
  l'isolement. Pour deux latences ou deux confiances, avec ou sans unité, et même avec une date
  entre parenthèses après la première (« de 106,9 s (23/10) à 91,9 s »), « de 106,9 à 91,9 »,
  « de 0,78 à 0,8 » ou « 78 % → 80 % » sont écartés quand le fait va dans l'autre sens et
  qu'aucun fait cité ne va dans celui-là. Un « de X à Y » qui part d'un côté d'un fait doit
  aussi arriver à son autre côté : « de 91,9 s à 15 s » est écarté (15 s est l'écart, pas la
  latence d'après) ;
- **une `trend` aussi** : ses runs de cette campagne sont mis face à ses runs antérieurs de la
  même technique, chacun face à chacun, sur n'importe quelle VM, comme autant de faits de
  changement implicites. Son « de X à Y » doit aller dans le sens de l'un d'eux : « passe de
  106,9 s à 91,9 s » ou « de l'isolement au blocage », en citant le run du 23/10 et celui du
  21/10, sont écartés. Deux runs antérieurs de la même technique se font face aussi, dans les
  deux sens : un `RunFact` ne dit pas lequel est venu d'abord, si bien qu'entre deux runs
  antérieurs le sens n'est pas lu. Une tendance sur trois campagnes passe donc (« de 120 s
  (19/10) à 91,9 s (21/10), puis à 106,9 s », « 0,85 → 0,80 → 0,78 », « du blocage à
  l'isolement (avant), puis retour au blocage »). Un sens inversé entre un run antérieur et un
  run de cette campagne reste écarté, sauf quand un autre run antérieur cité porte la même
  action, ou la même valeur (à la tolérance près), que le run de cette campagne : la tendance
  peut alors décrire le passage entre deux runs antérieurs, dont l'ordre n'est pas lu (avec
  un run isolé le 19/10, bloqué le 21/10 et isolé le 23/10, « de l'isolement au blocage »
  passe). Pourquoi tous les appariements, et pas la clé exacte :
  une tendance peut citer plusieurs runs antérieurs, de plusieurs campagnes, ou des runs
  indexés avant D-2, sans leur VM. Un appariement plus large écarte moins, et il évite de
  barrer une tendance juste pour un appariement qu'elle ne voulait pas dire. Sans run
  antérieur de la même technique, son sens n'est pas lu ;
- seules les affirmations `trend`, `change` et `observation` peuvent citer un fait de
  changement ;
- la règle de #167 vaut aussi sur un fait de changement dont une décision est inconnue. Une
  affirmation sur la réponse doit dire que la décision est inconnue, et ne doit jamais dire
  que Glorfindel n'a pas agi. « a isolé » n'est permis que si chaque décision inconnue citée
  est celle d'un côté d'un fait de changement dont l'autre côté a une décision connue :
  l'action nommée peut alors être celle de ce côté. Un run cité directement dont la décision
  est inconnue, même à côté d'un fait de changement, ou un fait de changement inconnu des deux
  côtés, écarte « a isolé ».

**Limites connues de la vérification** (heuristiques, comme la lecture de la réponse). Elles
sont assumées : la section calculée fait foi, et le lecteur juge une affirmation en la
rapprochant d'elle. Ce qui passe encore, ou tombe à tort :
- **le sens, hors de « de X à Y » et « X → Y »**. « 15 s plus tôt » quand c'était plus tard,
  « a escaladé cette fois, pas avant » quand il avait escaladé les deux fois, « isolée cette
  fois, bloquée avant » à l'envers, ou des dates dans le mauvais ordre (« bloquée le 23/10,
  isolée le 21/10 ») ne sont pas écartés ;
- l'escalade n'est pas contrôlée, ni les formes françaises des détections (« manquée ») ;
- **un nombre sans unité qui se trouve être celui d'un fait** passe : « 2 fois plus longue »
  ou « isolée 2 fois sur 2 », quand l'écart de confiance vaut 2 points. « fois » n'est ni une
  unité ni un décompte : « 2 fois plus » est un rapport, « les 2 fois » un décompte, et le mot
  seul ne dit pas lequel. À l'inverse, un décompte juste en « fois » (« bloquée les 2 fois »)
  est écarté quand aucun fait cité ne vaut 2 ;
- **« 0,02 point »** est écarté : les points ne sont lus qu'en pourcentage (« 2 points »), et
  l'écart de confiance en fraction (0,02) ne s'écrit pas en points ;
- **un nombre écrit en toutes lettres** (« quarante secondes plus tard ») n'est pas lu ;
- **un décompte inventé sous la borne** passe (« isolée dans les 2 campagnes » quand elle ne
  l'a été qu'une fois). Un décompte dont le nom est sous-entendu (« comme les 2 de la
  précédente ») est lu comme un nombre, et écarté si aucun fait ne le porte ;
- **une plage de dates** n'est lue qu'avec le mois à la fin, en toutes lettres, des jours de
  1 à 31, et « le », « les », « entre », « du », « des », « aux » ou « au » (« between »,
  « from », « on », « the ») devant son premier jour (« entre le 21 et le 23 octobre », « les
  runs des 21 et 23 octobre », « du 21 et du 23 octobre ») ; « de » n'en est pas, si bien que
  « baisse de 12, le 23 octobre » laisse 12 un nombre, et « between 70 and 60, 23 October »
  aussi (70 n'est pas un jour). Mais dans « 21, 22 et 23 octobre » ou « les 21 et 23/10 »,
  21 reste un nombre aussi. Une
  date anglaise est lue (« October 21 », « 21 October »), pas une plage dont le mois vient
  d'abord (« October 21 to 23 ») ;
- **un « de X à Y » qui mêle deux écritures** (« de 0,80 à 78 % », « de 91,9 s à 1,8 min ») est
  écarté : la vérification ne convertit pas l'une dans l'autre. Une phrase juste tombe donc si
  le modèle l'écrit ainsi ;
- le nom d'une action absente est écarté même dans une négation ou une comparaison justes
  (« jamais snapshot », « isolate_vm plutôt que snapshot », quand aucun côté n'a pris de
  snapshot) ;
- dans une `trend`, l'appariement par technique est large : une tendance dite dans le sens
  d'un appariement qu'elle ne voulait pas dire passe, et entre deux runs antérieurs les deux
  sens passent. Une paire de runs antérieurs peut ainsi servir d'alibi à un sens inversé entre
  un run antérieur et un run de cette campagne, quand l'autre run antérieur porte la même
  action ou la même valeur que celui-ci. Piste pour un lot suivant : lire l'ordre des runs
  antérieurs (l'identifiant horodaté de leur campagne, ou `campaign_started` dans l'index),
  pour ne garder qu'un sens entre eux ;
- dans une chaîne (« de X à Y, puis à Z », « X → Y → Z »), seul le premier pas est lu pour
  le sens ; les suivants ne sont contrôlés que comme nombres des faits cités.

**L'index des campagnes passées** (`analysis/campaign_index.py`). Chaque run de l'index porte
maintenant l'état et le début de sa campagne, ainsi que sa VM. Un rapport écrit avant D-2 les a
indexés sans eux : ses runs ne sont jamais choisis. La commande les ajoute :

```bash
python -m analysis.campaign_index --all runs/campaigns      # chaque campagne done ou aborted
python -m analysis.campaign_index runs/campaigns/<id> …     # celles-ci
```

- Un run déjà dans l'index garde les faits avec lesquels il y est entré : ceux du rapport de
  sa campagne, vus quand sa fenêtre d'exercice était encore sur le disque. La commande y
  ajoute seulement l'état et le début de la campagne, et la VM du run quand ses faits ne la
  donnent pas (le `target_resource_id` du manifeste).
- Un run absent de l'index est calculé depuis les fichiers, comme le rapport le calcule. Une
  campagne venue du canal lit l'inscription de ses VM dans leurs tags (H-1).
- La commande est idempotente : lancée deux fois, elle laisse le même index. Elle n'appelle
  aucun modèle et n'écrit que dans l'index.
- Une campagne encore en cours est laissée de côté, et la commande le dit.

**Sur H0** (à lancer par Jonathan : c'est une écriture sur H0), après le redéploiement de H0
avec ce code :

```bash
make glorfindel-host-ssh
# aucun rapport en attente ? (liste vide attendue)
docker exec eregion-watch python -c "from pathlib import Path; from analysis import hosted_report as h; print([p.name for p in h.ready(Path('runs/campaigns'))])"
docker exec eregion-watch python -m analysis.campaign_index --all runs/campaigns
```

- **Quand aucun rapport n'est en attente.** Le fil `campaign-report` de la watch écrit dans le
  même index (un `PersistentClient` chromadb sur le même dossier) quand il écrit un rapport.
  Deux processus qui écrivent en même temps dans ce dossier ne sont pas prévus par chromadb.
  La première commande ci-dessus liste les campagnes dont le rapport est à écrire
  (`hosted_report.ready` : venues du canal, `done`, sans `report.md`, avec des essais
  restants). Une liste vide veut dire qu'aucun rapport n'est en cours ni à venir. Une campagne
  qui attend encore les décisions de Glorfindel y figure aussi : la watch dit « waiting for
  Glorfindel's decision » dans son journal (`make glorfindel-host-logs`). Si la liste n'est pas
  vide, il faut attendre que le `report.md` soit écrit, puis relancer la vérification. Une
  campagne arrivée pendant la commande : relancer la commande après son rapport (elle est
  idempotente).

- **La campagne du 23/10** (`20261023T081120Z`) est déjà sur H0 et dans son index. La commande
  lui ajoute l'état, le début et les VM, sans recalculer ses décisions.
- **La campagne du 21/10** (`20261021T121643Z`) n'est jamais passée par H0 : son manifeste et
  les rapports de ses runs sont restés sur Orodruin. Il faut d'abord les copier sur H0, dans
  `eregion/runs/campaigns/20261021T121643Z/` (le manifeste, et les rapports des runs dans
  `runs/`), puis lancer la commande. Ses décisions sont alors lues dans les `watch-*` de H0,
  bornées par les fenêtres de `runs/exercises/`.
- **Attention à la purge** : une fenêtre est vidée une semaine après sa fin
  (`PURGE_AFTER_S`). Une fois les fenêtres du 21/10 vidées, la décision de chacun de ses runs
  devient inconnue (« fenêtre absente »). La détection et la latence restent, puisqu'elles
  viennent du manifeste. Il faut donc verser cette campagne avant la purge : copier le dossier
  et lancer `python -m analysis.campaign_report runs/campaigns/<id>` (le code d'aujourd'hui
  l'indexe, et un appel au modèle écrit son rapport), ou la commande ci-dessus, une fois ce
  code déployé. Dans les deux cas, les faits entrés dans l'index ne sont plus recalculés.
