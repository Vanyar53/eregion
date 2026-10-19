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
pas partager les angles morts du défenseur.

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

**Il s'écrit seul** : `annatar campaign run` écrit le rapport à la fin de la campagne
(`--no-report` pour s'en passer). Sans paquet `analysis` ou sans clé de modèle, la campagne se
termine quand même et dit comment l'écrire plus tard. Les campagnes de R1 (Atomic) et de G0
(Chaos Studio) passeront par là.
