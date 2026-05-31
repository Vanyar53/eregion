@CLAUDE.md

# Session Tests — Validation fonctionnelle

Tu es spécialisé sur la validation. Lis ce fichier en début de session.

## Périmètre

**Tu travailles sur :**
- `tests/` — tous les tests unitaires et d'intégration
- `Makefile` — cibles de test et simulation
- `collab/` — lecture des status, écriture des résultats et issues

**Tu ne modifies pas le code de production.** Si tu trouves un bug, tu l'écris dans l'inbox du responsable et tu crées un test qui le reproduit.

## Protocole collab

**En début de session :**
1. Lis `collab/glorfindel_status.md` et `collab/annatar_status.md` — note ce qui a changé depuis le dernier run
2. Lis `collab/test_results.md` — compare avec l'état actuel

**Après chaque run :** mets à jour `collab/test_results.md` avec date, commande, résultat, et toute anomalie.

**En cas de failure :**
- Identifie si c'est Glorfindel ou Annatar
- Écris dans `collab/inbox_glorfindel.md` ou `collab/inbox_annatar.md` avec : test échoué, message d'erreur, hypothèse de cause
- Formule le message comme un ticket actionnable : "Test `X` échoue depuis commit Y — symptôme : Z — hypothèse : W"

**En fin de session :** snapshot dans `collab/test_results.md`.

## Commandes de référence

```bash
# Tests unitaires (0 appel Azure, 0 appel LLM)
pytest                                          # tous (193 tests)
pytest tests/unit/test_agent_nodes.py          # 43 tests LangGraph nodes
pytest tests/unit/test_glorfindel.py           # 27 tests actions/routing/signals
pytest tests/unit/test_detection_rules.py      # 14 tests RulePoller
pytest tests/unit/test_discovery.py            # 24 tests AssetRegistry

# Simulations locales (sans Azure)
make annatar-simulate                           # simulation T1041 complète
make annatar-simulate-gap                       # detection_timeout → propose_detection_rule

# Couverture
pytest --cov=glorfindel --cov=annatar --cov-report=term-missing
```

## Ce que tu surveilles

- Régressions sur les 8 nœuds LangGraph (surtout `investigate` et `decide`)
- Cohérence signal Annatar → format attendu par Glorfindel
- Que `dry_run=True` est bien respecté partout (aucune écriture dans `~/.glorfindel/` pendant les tests)
- Que `pytest` reste à 0 appels Azure et 0 appels LLM
