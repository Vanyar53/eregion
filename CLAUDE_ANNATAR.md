@CLAUDE.md

# Session Annatar — Agent offensif

Tu es spécialisé sur l'agent offensif. Lis ce fichier en début de session.

## Périmètre

**Tu travailles sur :**
- `annatar/` — tout le code de l'agent offensif
- `annatar/scenarios/azure/` — scénarios MITRE ATT&CK
- `schemas/scenario.schema.json` — validation schema des scénarios
- `tests/unit/test_annatar*.py` — tests unitaires Annatar

**Tu lis mais ne modifies pas :**
- `glorfindel/rules/azure/detection_rules.yaml` — pour comprendre ce que Glorfindel détecte (et ce qu'il ne détecte pas encore)
- `annatar/signals/schema.py` — pour t'assurer que tes signaux sont bien formés

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

## Huitième passe (13/10) — ce qui change pour Annatar

- **Plus de logique offensive maison** : Annatar devient des adaptateurs vers des bibliothèques
  publiques, version épinglée. `annatar/executors/` devient l'interface d'injecteur (préparer,
  injecter, revenir, nettoyer).
- **R1 (0.3)** : adaptateur Stratus Red Team (cycle `warmup`, `detonate`, `revert`, `cleanup`),
  seulement les techniques `implemented` au catalogue, sur cibles inscrites, depuis Orodruin ;
  `attack_started` et `detection_missed` inchangés. Question ouverte (ROADMAP) : Stratus attaque
  le plan de contrôle (Activity Logs, que Glorfindel ne lit pas) et crée sa propre VM — R2 avant
  R1, ou R1 avec l'ingestion des Activity Logs.
- **R2 (0.x)** : adaptateur Atomic Red Team (tests dans la VM).
- **O0 (0.3)** : `annatar/campaign/scope.py` et `annatar/safety/guard.py` fusionnent dans un
  module d'inscription partagé ; tag `eregion-target` (`annatar-test` lu pendant la migration) ;
  zone `bench` / `twin` / `production` ; en `production`, seulement `kind: technique` et
  `destructive: false`.
- **E1 (0.3)** : schéma d'expérience commun ; les scénarios actuels deviennent `kind: technique`,
  `engine: local-script`, sans changement de comportement.
- Le planificateur génératif existant n'est pas étendu.
