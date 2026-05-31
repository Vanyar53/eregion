# Glorfindel — Status

_Mis à jour par la session Glorfindel après chaque changement significatif._

## État courant

- **Version** : 0.2.0
- **Dernière activité** : 2026-05-31 — fix Bug 1 (workspace_id vide dans `_find_rule_for_ttp`)
- **Tests** : 196/196 ✅ (+3 nouveaux tests couvrant le bug fix)

## Fix appliqué — Bug 1

**Fichiers modifiés** :
- `glorfindel/agent.py` : `load_glorfindel_config` importé au niveau module (l.11) ; `_find_rule_for_ttp` accepte maintenant `glorfindel_cfg=None` et le passe à `load_rules` ; `resolve_attack_started` appelle `_find_rule_for_ttp(ttp, glorfindel_cfg=load_glorfindel_config())`
- `tests/unit/test_agent_nodes.py` : 3 nouveaux tests (`test_find_rule_for_ttp_with_glorfindel_cfg_resolves_workspace_id`, `test_find_rule_for_ttp_without_glorfindel_cfg_has_empty_workspace_id`, `test_resolve_attack_started_passes_glorfindel_cfg_to_find_rule`)

**Impact** : T1041, T1110.001, T1548.003 — le chemin `attack_started` sans `detection_query` embedded peut maintenant résoudre le workspace_id depuis `glorfindel-config.yaml` via le backend de la règle.

**Bug 2 reste ouvert** : DCR log_levels exclut Notice/Info → T1548.003 et T1110.001 non ingérés dans LAW. Fix = opérateur (terraform apply). Hors périmètre Glorfindel.

## Interfaces exposées à Annatar

- **Format signal entrant** : voir `annatar/signals/schema.py` — champs requis : `event`, `ttp`, `resource_id`, `context.run_id`, `raw_signal.first_result_row`
- **detection_rules.yaml** : `rules/azure/detection_rules.yaml` — source de vérité pour les queries KQL

## À faire savoir à Annatar

_(rien — le fix est interne à Glorfindel, aucune interface Annatar modifiée)_
