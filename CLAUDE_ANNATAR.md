@CLAUDE.md

# Session Annatar — Agent offensif

Tu es spécialisé sur l'agent offensif. Lis ce fichier en début de session.

**Docs de ton périmètre** (`CLAUDE.md` n'en garde que l'essentiel) : [`docs/historique.md`](docs/historique.md) (TTPs validés, boucle purple team), [`docs/operations.md`](docs/operations.md) (CLI, workflows de run), [`docs/fichiers-cles.md`](docs/fichiers-cles.md), [`docs/architecture.md`](docs/architecture.md) (inscription, zones, cycle d'une expérience).

## Périmètre

**Tu travailles sur :**
- `annatar/` — tout le code de l'agent offensif
- `annatar/scenarios/azure/` — scénarios MITRE ATT&CK
- `schemas/scenario.schema.json` — validation schema des scénarios
- `tests/unit/test_annatar*.py` — tests unitaires Annatar

**Tu lis mais ne modifies pas :**
- `glorfindel/rules/azure/detection_rules.yaml` — pour comprendre ce que Glorfindel détecte (et ce qu'il ne détecte pas encore)
- `eregion_core/signals.py` — le contrat des signaux (D1 : sorti d'Annatar), pour t'assurer que tes signaux sont bien formés

**Tu ne touches pas :**
- `glorfindel/` (sauf lecture des interfaces)

## Protocole collab

**En début de session :** lis `collab/inbox_annatar.md` — traite les messages en attente avant de commencer.

**Après chaque changement significatif :** mets à jour `collab/annatar_status.md` (scénarios ajoutés/modifiés, changements de format signal).

**Si tu ajoutes un scénario ou changes le format du signal émis :** écris un message dans `collab/inbox_glorfindel.md` avec le TTP ciblé, les indicateurs que Glorfindel devrait voir, et si une règle de détection est nécessaire.

**En fin de session :** snapshot de l'état dans `collab/annatar_status.md`.

## Contexte technique rapide

- **Jamais sans Glorfindel (V1, #214)** : avant chaque run et avant tout appel au cloud, `eregion_core/watch_gate.refusal()` (canal retour s'il est configuré, sinon `~/.glorfindel/watch_heartbeat`) ; sans battement vivant, refus. `--without-glorfindel` = run de développement, inscrit au rapport (« detection not measured, by choice »), sans rapport IA0 pour une campagne. Tout nouveau point d'entrée de run passe par `watch_gate` avant `arm`. Exception assumée : `annatar clean` (préparation).
- `annatar run <scenario.yaml>` : setup → integrity check → attack → emit `attack_started`
- Preflight check automatique : VM running + pas de règles `glorfindel-isolation-*` en place
- Signal `attack_started` : `{T0, query, workspace_id}` via `annatar/signals/emitter.py`
- Thread daemon feedback : poll `runs/<run_id>_debug.jsonl` → émet `detection_missed` si timeout (déclenche propose_detection_rule dans Glorfindel)
- Scénarios : `detection.hints` alimentent `propose_detection_rule` — soigner les `expected_indicators` et `failure_candidates`
- `--dry-run` disponible, `--skip-preflight` pour bypasser le check VM
- Fin de `annatar run` seul (#193) : avec `EREGION_EXERCISE_CHANNEL`, le rapport part vers H0
  (`runs/<run_id>.json` dans `exercises`, `Engine(publish_report=True)`, la CLI seulement) ;
  la watch hébergée le tire s'il passe `run_report_refusal`. Garder la forme de `RunReport`

## Huitième passe (13/10) — ce qui change pour Annatar

- **Plus de logique offensive maison** : Annatar devient des adaptateurs vers des bibliothèques
  publiques, version épinglée. `annatar/executors/` devient l'interface d'injecteur (préparer,
  injecter, revenir, nettoyer).
- **R1 (0.3)** : adaptateur Atomic Red Team (décision du 15/10 : avant Stratus). Atomics en
  version épinglée, un test appelé par son identifiant (`engine: atomic`, `engine_ref`), exécuté
  dans la VM cible par Run Command, puis sa commande de nettoyage ; seulement les techniques
  `implemented` au catalogue, sur cibles inscrites, depuis Orodruin ; `attack_started` et
  `detection_missed` inchangés.
- **R2 (0.x)** : adaptateur Stratus Red Team (cycle `warmup`, `detonate`, `revert`, `cleanup`),
  avec l'ingestion des Activity Logs : Stratus attaque le plan de contrôle, que Glorfindel ne lit
  pas encore, et son `warmup` crée sa propre VM.
- **Marquage des exercices (B2, ✅ côté stockage 16/10)** : `Engine.run` ouvre une fenêtre
  (`eregion_core/exercise.py`, `runs/exercises/<run_id>.json`) avant le setup et la ferme dans
  un `finally` ; Glorfindel en tire la source de chaque cycle (`exercise` / `real`). Tout futur
  injecteur (adaptateur Atomic de R1, Gothmog) fait de même — mutants M57–M61.
- **O0 (0.3, ✅ 14/10)** : le périmètre et le garde-fou de cible vivent dans
  `eregion_core/inscription.py` (`annatar/safety/guard.py` supprimé, `annatar/campaign/scope.py`
  ne garde que `Budget`). Tags `eregion-target=<banc>` + `eregion-zone` sur la VM ET son groupe
  (`annatar-test=true` vaut zone `bench` pendant la migration) ; en `production`, seulement
  `kind: technique` et `destructive: false` — `scenario_destructive()` lit le champ du scénario,
  puis le catalogue ; inconnu = refusé en production. `run` et `clean` passent par
  `check_target(resource_id, rg_tags, vm_tags, kind=, destructive=)`.
- **E1 (0.3)** : schéma d'expérience commun ; les scénarios actuels deviennent `kind: technique`,
  `engine: local-script`, sans changement de comportement.
- Le planificateur génératif existant n'est pas étendu.
