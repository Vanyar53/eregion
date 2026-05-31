@CLAUDE.md

# Session Annatar — Agent offensif

Tu es spécialisé sur l'agent offensif. Lis ce fichier en début de session.

## Périmètre

**Tu travailles sur :**
- `annatar/` — tout le code de l'agent offensif
- `annatar/scenarios/azure/` — scénarios MITRE ATT&CK
- `schemas/scenario.schema.json` — validation schema des scénarios

**Tu lis mais ne modifies pas :**
- `rules/azure/detection_rules.yaml` — pour comprendre ce que Glorfindel détecte (et ce qu'il ne détecte pas encore)
- `glorfindel/signals/schema.py` — pour t'assurer que tes signaux sont bien formés

**Tu ne touches pas :**
- `glorfindel/` (sauf lecture des interfaces)

## Protocole collab

**En début de session :** lis `collab/inbox_annatar.md` — traite les messages en attente avant de commencer.

**Après chaque changement significatif :** mets à jour `collab/annatar_status.md` (scénarios ajoutés/modifiés, changements de format signal).

**Si tu ajoutes un scénario ou changes le format du signal émis :** écris un message dans `collab/inbox_glorfindel.md` avec le TTP ciblé, les indicateurs que Glorfindel devrait voir, et si une règle de détection est nécessaire.

**En fin de session :** snapshot de l'état dans `collab/annatar_status.md`.

## Contexte technique rapide

- `annatar run <scenario.yaml>` : setup → integrity check → attack → emit `attack_started`
- Preflight check automatique : VM running + pas de règles `glorfindel-isolation-*` en place
- Signal `attack_started` : `{T0, query, workspace_id}` via `annatar/signals/emitter.py`
- Thread daemon feedback : poll `runs/<run_id>_debug.jsonl` → émet `detection_missed` si timeout (déclenche propose_detection_rule dans Glorfindel)
- Scénarios : `detection.hints` alimentent `propose_detection_rule` — soigner les `expected_indicators` et `failure_candidates`
- `--dry-run` disponible, `--skip-preflight` pour bypasser le check VM
