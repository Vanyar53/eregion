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

**L'index** : une collection ChromaDB à part (`campaign_runs`, `~/.eregion/analysis/chroma`),
distincte de la mémoire de Glorfindel. Il ramène les runs passés des mêmes techniques, ce qui
permet une affirmation de tendance (« manquée ici, détectée au run précédent »).

**Le modèle n'écrit que des affirmations typées, chacune citant ses runs** : `detected`,
`missed`, `latency`, `decision`, `trend`, `observation`. Un autre modèle que celui de Glorfindel
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
fin de rapport. Une tendance doit citer cette campagne et une campagne antérieure. Les
`trend` et `observation` ne sont vérifiées que sur leurs citations. Le contenu des runs
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
