# Eregion — Contexte projet pour Claude Code

## Concept
Plateforme OSS (Apache 2.0) de défense active cloud : un SOC pour les charges cloud des équipes sans SOC, prouvé par l'attaque et par la panne. Trois agents en boucle :
- **Glorfindel** (bleu) — **le produit** : détecte, répond de façon autonome, vérifie, apprend via ChromaDB
- **Annatar** (rouge) simule des attaques réelles sur l'infra cloud (MITRE ATT&CK) ; devient des adaptateurs vers des bibliothèques publiques (R1 Atomic Red Team, R2 Stratus Red Team)
- **Gothmog** (pannes, G0 ✅ 19/10) : pannes déclarées en code, par un moteur public (Chaos Studio d'abord) ; éprouve d'abord Glorfindel (bruit bénin, dépendances, reprise)

L'atelier autour : **Celebrimbor** (`infra/terraform/`) construit et inscrit le banc ; **Orodruin** (`infra/orodruin/`, O1 ✅ 19/10) héberge les injecteurs, contrat de garde-fous vérifié au démarrage — **un injecteur n'agit que depuis un Orodruin armé** ; ailleurs (un poste d'opérateur), il reste passif.

**Direction — huitième passe (13/10)** (détail : `ROADMAP.md`, « Vers la 1.0 ») :
- **Finalité** : les incidents cloud courants contenus seuls, en quelques minutes, réversibles et vérifiés ; le reste à un humain, trié et expliqué ; la preuve à tout moment. Cinq indicateurs : temps pour contenir, part contenue seule, actions disruptives à tort, couverture des techniques cloud, âge de la dernière preuve (< 30 jours).
- **Règle de production** (codée dès O0) : jamais de panne ni d'action destructive sur une charge réelle ; en production, techniques non destructives sur VM inscrites + chaîne complète sur une VM sentinelle vide ; destructif et pannes sur le banc ou le jumeau. Zones d'inscription : `bench`, `twin`, `production`.
- **Jalon 0.3 — la boucle tourne** : socle O0 → E1 → O1 → R1 → G0, et H0 (Glorfindel sur une VM dédiée, pré-observation) ; piste IA B2 (élargi à la mémoire), IA0 ; B1 après la 0.3. **A1 (découpage d'`actions.py`, avec MC0) différé en 0.4+.** O1, H0, R1, G0 (infra réelle) se font avec Jonathan ; décisions du 15/10 dans `ROADMAP.md` ; `v0.2.0` publiée le 15/10.
- Le SaaS vient plus tard (1.x) ; Eregion tourne en local ou dans une VM.

**Repo** : https://github.com/Vanyar53/eregion
**Local** : `/home/jonathan/eregion/`, branch `main`, venv `.venv/` (créé par `make install`), `.envrc` charge les creds
**Stack** : Python 3.12 (≥ 3.11 supporté — CI GitHub Actions sur 3.11 et 3.12), Azure SDK, LangGraph, LiteLLM (Anthropic défaut, OpenAI, Azure, Ollama, self-hosted), ChromaDB, Click, pytest
**Docker** : `make build` → `eregion-annatar` + `eregion-glorfindel`. `make annatar-shell` (alias `ar`) / `make glorfindel-shell` (alias `gf`). State persisté dans `~/.annatar/` et `~/.glorfindel/`, cache ChromaDB dans `~/.cache/chroma/`. **Images non-root** : `make build` injecte l'UID/GID de l'opérateur (`id -u`/`id -g`) en build-arg → le container écrit le state bind-monté comme l'opérateur, pas root (sinon la CLI locale ne peut pas muter ce que le container a écrit → `PermissionError` sur `reset`/`unblock`). HOME reste `/root` (chowné), aucun chemin de mount ne change. Une seule fois après upgrade depuis l'ancienne image root : `make fix-state-ownership` (`chown` des fichiers root legacy).

---

## Où trouver quoi

`CLAUDE.md` ne garde que ce qui sert à chaque session : le concept, les règles de sûreté, les conventions, les sessions. Le détail est dans `docs/` — lis ce qui touche ton lot.

| Sujet | Où |
|---|---|
| Glorfindel : watch, graphe LangGraph (RulePoller, `investigate`, gardes de `decide`), raisonnement LLM, modes d'autonomie, exposition de la War Room, observe-only, vérification après action, IncidentRegistry, escalades, alertes | [docs/glorfindel.md](docs/glorfindel.md) |
| Azure : NSG, quarantaine, préséance, sessions, restore, sauvegarde, SDK, pièges opérateur | [docs/azure.md](docs/azure.md) |
| Fichiers clés et état local (`~/.glorfindel/`, `~/.annatar/`) | [docs/fichiers-cles.md](docs/fichiers-cles.md) |
| CLI, workflows opérateur, variables d'environnement, packaging, coûts | [docs/operations.md](docs/operations.md) |
| TTPs validés en réel, boucle purple team, historique des passes (troisième passe … A0, B2) | [docs/historique.md](docs/historique.md) |
| Priorités, jalons, lots | [ROADMAP.md](ROADMAP.md) |
| Architecture en schémas, vocabulaire commun, zones | [docs/architecture.md](docs/architecture.md) |
| Preuves : invariants, mutation | [docs/design/preuves.md](docs/design/preuves.md) |
| Isolation compatible IaC | [docs/design/module-isolation-iac.md](docs/design/module-isolation-iac.md) |
| Contrat d'Orodruin | [docs/design/orodruin-contract.md](docs/design/orodruin-contract.md) |
| elrond, sous-agents par lot | [docs/elrond.md](docs/elrond.md) |
| Observation : verdicts et rapport | [docs/observation.md](docs/observation.md) |
| IA d'analyse : le rapport de campagne (IA0) | [docs/analysis.md](docs/analysis.md) |

---

## Architecture — boucle complète

```
Annatar
  setup (nettoie résidus) → integrity check → attaque → attack_started {T0}

Glorfindel (watch ou respond)
  poll_detection Azure Monitor (10s) → detection ou detection_timeout
  → decide (LangGraph + LLM via LiteLLM + RAG ChromaDB 3 cycles similaires)
  → execute autonomous action (isolate_vm / block_suspicious_ip / snapshot)
  → verify (Azure NSG API) → store_cycle (ChromaDB + debug.jsonl)

Humain
  glorfindel restore <resource_id> --yes   # --before auto-détecté depuis signals JSONL
  → restore Azure Backup (~20min) → recovery_complete
  → Glorfindel release_isolation (autonome) → verify → store
```

---

## Règles d'autonomie strictes

```python
AUTONOMOUS_ACTIONS = ["isolate_vm", "release_isolation", "snapshot", "block_suspicious_ip"]
# revoke_temp_access retirée le 2026-10-06 : annoncée au LLM, jamais implémentée
HUMAN_APPROVAL_REQUIRED = ["restore_from_backup", "delete_resource", "wipe_storage", ...]
```

Actions inconnues proposées → escalade automatique, humain valide et codifie.

---

## Tests

```bash
pytest                    # ~870 tests (~30s ; 60 séquences d'invariants, 500 en CI ~1 min), 0 appel Azure, 0 appel LLM, 0 écriture ~/.glorfindel/
                          # Hermétique par construction (conftest) : TOUS les chemins ~/.glorfindel redirigés
                          # vers tmp, et le glorfindel-config.yaml local ignoré (avant : avec une config locale,
                          # les tests de graphe lançaient de vraies requêtes KQL via `investigate`, suite 5× plus lente).
                          # CI : .github/workflows/ci.yml — ruff + pytest, Python 3.11 et 3.12.
                          # ruff figé (0.15.14, extra dev) + règles explicites dans pyproject
                          # ([tool.ruff.lint] select E4/E7/E9/F) : un ruff plus récent aux règles par
                          # défaut plus larges avait fait 450 constats de style au 1er run CI.
pytest tests/unit/test_agent_nodes.py        # LangGraph nodes (incl. investigate + confidence gate)
pytest tests/unit/test_glorfindel.py         # actions/routing/signals
pytest tests/unit/test_detection_rules.py    # RulePoller + load_rules + status + recently_matched
pytest tests/unit/test_proposed_rules.py     # record/pending/approve/reject + routing
pytest tests/unit/test_detection_authoring.py # catalogue + getschema + author_rule + propose-rules
pytest tests/unit/test_audit.py              # NSG/backup/compute/IAM readiness
pytest tests/unit/test_config.py             # GlorfindelConfig + ExceptionConfig
pytest tests/unit/test_inscription.py        # O0 : périmètre, inscription, zones, règle de production
pytest tests/unit/test_orodruin.py           # O1 : contrat armed/passive, audit avant appel, plafond, kill, module Terraform
pytest tests/unit/test_experiment_schema.py  # E1 : schéma d'expérience (technique/panne) + catalogue validés
pytest tests/unit/test_docs_budget.py        # DX1 : CLAUDE.md ≤ 25 Ko, liens de l'index et des fichiers de rôle valides
pytest tests/unit/test_provider_boundary.py # MC0 (A1) : aucun SDK de fournisseur hors de son adaptateur (aussi étape CI), capacités déclarées
pytest tests/unit/test_actions_split.py     # A1 : la façade glorfindel.actions reste un seul espace de noms ; aucun module > 500 lignes
pytest tests/unit/test_discovery.py          # AssetRegistry + DiscoveryService + eviction
pytest tests/unit/test_invariants.py         # L24/L26 : invariants (Hypothesis, machine à états) sur un faux Azure
                          # en mémoire (tests/unit/fake_azure.py : évaluation NSG comme Azure, politiques, régions,
                          # noms insensibles à la casse, 429/crash avant ou après une écriture, API throttlée,
                          # 403 persistant, disque plein) et un monde client qui bouge (règles, IP, NSG supprimé,
                          # VM supprimée ou créée, tags, config illisible, règles de Glorfindel retournées, autre hôte,
                          # anciennes isolations, horloge). 14 propriétés (I1–I12, L1, U1 — docstring du fichier),
                          # oracles tirés du journal du test, jamais des marqueurs du code (A0).
                          # GLORFINDEL_INVARIANT_EXAMPLES (défaut 60 ; push 500, nuit 10 000), _STEPS (30),
                          # _DB (base Hypothesis : rejoue les échecs mémorisés), _STATS=1 -s, _NO_SHRINK=1.
pytest tests/unit/test_invariant_regressions.py  # séquences trouvées par la machine, figées (L26, L27)
pytest tests/unit/test_locks.py               # L27 : _vm_lock / _quarantine_lock entre vrais processus (flock)
python scripts/mutation_check.py [--examples 500 --rounds 2 --jobs 8]   # mesure des invariants par
                          # mutation : 41 bugs réels réinjectés un par un + les 6 de la spécification d'O0 (M42–M47,
                          # mesurés par tests/unit/test_inscription.py + test_engine.py, table TESTS) + les 2 de DX1 (M48–M49, un mutant peut
                          # renommer un fichier : RENAME) ; chaque lundi (mutants.yml). scripts/check_paragraphs.py : rien de perdu dans un découpage.
                          # --control : les 16 mutants du jeu de contrôle (jamais utilisés pour orienter la génération)
```

---

## Conventions

- **À chaque commit** : mettre à jour la doc concernée (README, `docs/`, CHANGELOG) + générer résumé claude.ai ; `CLAUDE.md` seulement quand une règle ou une convention change — il reste sous 25 Ko (`tests/unit/test_docs_budget.py` échoue au-delà), le détail va dans `docs/`
- `target:` = ressource attaquée, `detection:` = infra surveillance (workspace_id ici)
- `prerequisites:` = KQL vérification + instructions setup dans chaque scénario
- `setup_testdata.sh` uniquement dans T1486
- RunCommand : 5 retries (15s, 30s, 60s, 90s, 120s) — pas de SSH, pas d'IP publique requise pour Annatar (Azure VM Agent via Wire Protocol)
- `dry_run=True` dans tous les tests — jamais d'appel Azure ou LLM dans les tests
- **SDK d'un fournisseur** (azure, boto3, google-cloud) : importé seulement dans son adaptateur — `glorfindel/providers/<nom>/` pour Glorfindel (A1, MC0). `glorfindel/actions.py` n'est plus qu'une façade d'import : le code est dans `glorfindel/response/` (cœur neutre) et `glorfindel/providers/azure/` (un module par préoccupation)
- `tests/unit/conftest.py` : fixture `autouse` redirige `escalations._STORE` → `tmp_path/escalations.jsonl` (les tests n'écrivent jamais dans `~/.glorfindel/`)
- `AZURE_SUBSCRIPTION_ID` obligatoire dans l'env (plus d'auto-détection via SubscriptionClient)
- **Dépendances verrouillées** (M-3) : `requirements/dev.txt` (CI, `make install`) et `requirements/glorfindel.txt` (image), uv + empreintes. Une dépendance ajoutée à `pyproject.toml` → `make lock` dans la même PR ; une montée de versions → PR + harnais (`make llm-compare`, par Jonathan) avant de redéployer H0 (`docs/operations.md`). H0 ne déploie qu'un tag ou un commit (`make glorfindel-host-start REF=…`)
- **Edit de `few_shot_examples.yaml`, `_SYSTEM_PROMPT` ou `_build_user_message()`** : requiert un run end-to-end T1486 + au moins un autre TTP avant merge. Ces trois zones contrôlent ce que le LLM voit et comment il raisonne — les tests unitaires (LLM mocké, dry_run=True) ne peuvent pas valider le comportement résultant. Un edit mal calibré peut introduire un raccourci critique (ex: ransomware non-isolé 20min, faux positif T1041, cycle 1 sauté). Voir c6fe0d0, 740659a.
- **`past_cycles` ChromaDB = historique uniquement** : ne jamais inférer l'état courant de la VM depuis les cycles passés. `_build_user_message()` injecte `## État actuel de la VM` depuis `~/.glorfindel/isolation/<vm>.json` — c'est la source de vérité. Voir commit 740659a (bug : LLM voyait `isolate_vm` dans past_cycles → concluait "VM déjà isolée" → sautait le cycle 1).

---

## Sessions Claude spécialisées (multi-agents)

7 sessions spécialisées (dont Orodruin et Gothmog, créées le 13/10 pour la 0.3) + 2 sessions transversales, coordonnées via `collab/`.

| Session | Fichier de rôle | Périmètre |
|---------|----------------|-----------|
| Glorfindel | `CLAUDE_GLORFINDEL.md` | `glorfindel/`, `rules/azure/`, tests unitaires Glorfindel |
| Annatar | `CLAUDE_ANNATAR.md` | `annatar/`, `annatar/scenarios/`, tests unitaires Annatar |
| Tests | `CLAUDE_TESTS.md` | Chef d'orchestre — tests fonctionnels bout en bout sur Azure réel |
| War Room | `CLAUDE_WARROOM.md` | UI/UX `glorfindel/static/index.html` + `glorfindel/api.py` |
| Infra | `CLAUDE_INFRA.md` | `infra/terraform/` — module Celebrimbor : infra Azure modulaire, namespacée, jetable + topos de validation |
| Orodruin | `CLAUDE_ORODRUIN.md` | `infra/orodruin/` — hôte d'exécution jetable des injecteurs, état Terraform séparé, contrat vérifié au démarrage (O1, O2) |
| Gothmog | `CLAUDE_GOTHMOG.md` | `gothmog/` — pannes déclarées, moteur Chaos Studio d'abord (G0–G4, X1 avec Annatar) |
| Review | `CLAUDE.md` (base) | Design review, architecture critique, BA sprint — ad hoc |
| General | `CLAUDE.md` (base) | Coordination inter-sessions, inbox routing, CLAUDE.md/README/ROADMAP |

**Démarrer une session :**
```
# Session Glorfindel
"Lis CLAUDE_GLORFINDEL.md pour tes instructions de session, puis commence par ton inbox."

# Session Annatar
"Lis CLAUDE_ANNATAR.md pour tes instructions de session, puis commence par ton inbox."

# Session Tests
"Lis CLAUDE_TESTS.md pour tes instructions de session, puis commence par ton inbox."

# Session War Room
"Lis CLAUDE_WARROOM.md pour tes instructions de session, puis commence par ton inbox."

# Session Infra
"Lis CLAUDE_INFRA.md pour tes instructions de session, puis commence par ton inbox."

# Session Orodruin
"Lis CLAUDE_ORODRUIN.md pour tes instructions de session, puis commence par ton inbox."

# Session Gothmog
"Lis CLAUDE_GOTHMOG.md pour tes instructions de session, puis commence par ton inbox."

# Session Review (ad hoc — challenge design et implémentations)
"Tu es la session Review d'Eregion. Lis CLAUDE.md. Ta mission : challenger les décisions architecturales, les implémentations critiques et les choix de sécurité. Commence par lire inbox_review.md."

# Session General (coordination)
"Tu es la session General d'Eregion. Lis CLAUDE.md. Ta mission : coordonner les sessions spécialisées, router les items cross-cutting, mettre à jour CLAUDE.md/README.md/ROADMAP.md. Commence par lire inbox_general.md."
```

**Protocole :** chaque session lit son inbox (`collab/inbox_<role>.md`) en début de tâche, met à jour son status (`collab/<role>_status.md`) après chaque changement significatif, et écrit dans l'inbox de l'autre si un changement a un impact cross-cutting.

**Mode orchestré, elrond** (`.claude/skills/elrond/`, documenté dans `docs/elrond.md`). Pour dérouler les lots de la feuille de route, une session principale lance `/elrond run`.
- Chaque lot part dans un sous-agent Opus 5.5, dans son propre worktree (`.claude/worktrees/`, ignoré par Git).
- Le journal palantir note les bascules de modèle.
- Tout travail fait pendant une bascule est relu en Opus 5.5.
- Les sous-agents lisent les `CLAUDE_<RÔLE>.md` de leur lot et n'écrivent pas dans `collab/` : c'est la session principale qui route leurs impacts transverses.

---

## Conventions scénarios Annatar

```yaml
# Structure minimale après refactoring :
detection:
  timeout: "300s"       # Annatar feedback watcher
  time_max: "180s"      # SLA déclaré (optionnel)
  prerequisites:        # ce qu'il faut vérifier avant de lancer
    - name: ...
      why: ...
      verify: "KQL ou commande az"
  hints:                # contexte pour propose_detection_rule
    log_source: Perf
    attack_commands_summary: >
      ...
    expected_indicators: [...]
    failure_candidates: [...]
```

Supprimés des scénarios : `cleanup`, `recovery`, `source`, `workspace_id`, `query` (tout dans Glorfindel).

---

## Ce qu'on ne fait PAS

- Pas compliance-oriented (NIS2, DORA)
- Pas d'agent en roue libre sur actions destructives
- Jamais de panne ni d'action destructive sur une charge réelle ; pas de tests sur infra prod sans consentement explicite
- Pas de logique offensive maison — des bibliothèques publiques, version épinglée
- Pas de dashboard monitoring — ce n'est pas le rôle de Glorfindel
- Pas de fine-tuning LLM — RAG ChromaDB suffit ; aucune donnée d'un client n'entraîne un modèle
- Pas de multi-cloud avant que la boucle Azure soit solide (sauf MC0, l'interface de fournisseur)
- Pas de modèle économique SaaS avant la 1.x — Eregion tourne en local ou dans une VM
