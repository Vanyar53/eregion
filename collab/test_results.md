# Tests — Résultats

_Mis à jour par la session Tests après chaque run._

## Analyse — session 2026-05-31

### Bilan historique des runs (depuis signals JSONL)

| TTP | Runs avec `detection` | Runs avec `detection_missed` / `detection_timeout` | Méthode de détection |
|-----|----------------------|---------------------------------------------------|----------------------|
| T1486 | ✅ Multiples (2026-05-24/27/28/29) | ~15 detection_timeout (2026-05-25/27/28) | RulePoller ✅ |
| T1041 | ✅ 1 (2026-05-24T170013Z) | ❌ 2 detection_missed (2026-05-29) | Ancien format query embedded uniquement |
| T1110.001 | ✅ 2 (2026-05-24, 2026-05-25) | ❌ 1 detection_missed (2026-05-29) | Ancien format query embedded uniquement |
| T1548.003 | ✅ 1 (2026-05-25T113643Z) | ❌ 4 detection_missed consécutifs (2026-05-30) | Ancien format query embedded uniquement |

### Bugs identifiés

#### Bug 1 — `_find_rule_for_ttp` : workspace_id vide (Glorfindel/agent.py)

**Fichier** : `glorfindel/agent.py:315-331` (`_find_rule_for_ttp`)

**Symptôme** : Quand `attack_started` n'embarque pas `detection_query` (nouveau format post-refactoring), `resolve_attack_started` appelle `_find_rule_for_ttp` qui fait `load_rules(path)` sans `glorfindel_cfg`. Toutes les règles `auto_apply` ont `workspace_id=""`. Le détecteur Azure Monitor reçoit un workspace_id vide, toutes les requêtes échouent silencieusement → detection_timeout après 300s.

**Impact** : T1041, T1110.001, T1548.003 — le noeud `poll_detection` ne peut jamais détecter.

**Fix** : Passer `glorfindel_cfg` à `_find_rule_for_ttp` et `load_rules`.

#### Bug 2 — DCR log_levels trop restrictif (infra/terraform/monitoring.tf)

**Fichier** : `infra/terraform/monitoring.tf:45`

**Symptôme** : `log_levels = ["Warning", "Error", "Critical", "Alert", "Emergency"]` — exclut Notice et Info. Les messages sudo (auth.notice) et SSH Failed password (auth.info/notice) ne sont pas ingérés dans LAW. Le RulePoller est correctement configuré (workspace_id OK via `glorfindel_cfg`), mais les tables Syslog sont vides pour ces événements.

**Impact** : T1548.003 et T1110.001 non détectables par le RulePoller, quelle que soit la query.

**Fix** : Ajouter `"Notice", "Info"` aux log_levels du DCR auth, ou remplacer par `["Debug"]` pour tout capturer. Terraform apply requis.

**Note** : Les validations historiques (2026-05-25) utilisaient l'ancien format avec query embedded + workspace_id embarqué dans le signal — elles ne testaient pas le chemin RulePoller.

### État actuel des pré-conditions (2026-05-31)

- ✅ VM `vm-annatar-victim` : running
- ✅ NSG : aucune isolation ou IP bloquée (glorfindel list clean)
- ✅ Tests unitaires : 193/193 passent
- ⚠️ 3 proposed rules en attente (`glorfindel pending`) — T1041, T1110.001, T1548.003

### Conclusion

**T1486 est le seul TTP validé end-to-end avec la nouvelle architecture** (RulePoller). Les 3 autres TTPs ont des bugs bloquants. Aucun nouveau run n'a de sens avant les corrections.

Ordre recommandé :
1. Fix Bug 1 (agent.py) → Glorfindel session
2. Fix Bug 2 (monitoring.tf) + terraform apply → opérateur
3. Re-run T1548.003 pour valider la détection Syslog
4. Re-run T1041 et T1110.001

## Historique

| Date | Scénario | Résultat | Méthode | Notes |
|------|----------|----------|---------|-------|
| 2026-05-25 | T1548.003 | detection_time_s=40 ✅ | query embedded (ancien format) | Ne valide pas le nouveau chemin |
| 2026-05-25 | T1110.001 | detection_time_s=41 ✅ | query embedded (ancien format) | Ne valide pas le nouveau chemin |
| 2026-05-24 | T1041 | detection_time_s=229 ✅ | query embedded (ancien format) | StorageBlobLogs query spécifique au storage account |
| 2026-05-27→29 | T1486 | detection ✅ / timeout (×15) | RulePoller | Perf > 50MB/s fiable ; timeouts = VM isolée ou arrêtée |
| 2026-05-30 | T1548.003 | detection_missed ×4 ❌ | Nouveau format, no query | Bug 1 + Bug 2 bloquants |

## Issues ouvertes

| # | TTP | Type | Assigné à | Statut |
|---|-----|------|-----------|--------|
| 1 | T1041/T1110/T1548 | Bug code — workspace_id vide dans _find_rule_for_ttp | Glorfindel | ✅ fixé (196 tests OK) |
| 2 | T1548.003/T1110.001 | Bug infra — DCR log_levels exclut Notice/Info | Opérateur (terraform) | ✅ résolu — Notice+Info déjà actifs dans Azure, diagnostic initial incorrect |

## Prêt pour re-run (2026-05-31)

Infra clean, Bug 1 corrigé. Re-run dans l'ordre : T1548.003 → T1110.001 → T1041.
