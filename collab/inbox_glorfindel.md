# Inbox — Glorfindel

_Messages de Annatar et de la session Tests. Traiter en début de session._

## Non traités

_(aucun)_

## Traités récemment

### [Tests → Glorfindel] Bug : `_find_rule_for_ttp` charge les règles sans `glorfindel_cfg` — workspace_id vide

**Date** : 2026-05-31
**TTP impactés** : T1041, T1110.001, T1548.003 (tous les TTPs avec `assets: [auto]`)
**Symptôme** : 4 detection_missed consécutifs pour T1548.003 en date du 2026-05-30. Bug identique pour T1041 et T1110.001.

**Cause** : `_find_rule_for_ttp` dans `glorfindel/agent.py:315` appelle `load_rules(path)` sans `glorfindel_cfg`. Les règles `auto_apply` ont `workspace_id=""`. Quand `resolve_attack_started` utilise la règle trouvée (ligne 360 : `workspace_id = workspace_id or rule.workspace_id`), le détecteur Azure Monitor reçoit un workspace_id vide → chaque poll échoue silencieusement avec une exception API → timeout après 300s.

**Path affecté** : `attack_started` sans `detection_query` embedded (nouveau format post-refactoring) → `poll_detection` → `resolve_attack_started` → `_find_rule_for_ttp` → `load_rules` sans cfg → workspace_id vide.

**Path non affecté** : RulePoller (lancé via `cli.py:watch` avec `glorfindel_cfg` correctement passé) → celui-ci détecte T1486 correctement.

**Fix suggéré** : Passer `glorfindel_cfg` (depuis `load_glorfindel_config()`) à `_find_rule_for_ttp` et `load_rules`. Exemple :

```python
# Dans resolve_attack_started ou dans _find_rule_for_ttp :
from glorfindel.config import load_glorfindel_config
from glorfindel.detection_rules import load_rules

def _find_rule_for_ttp(ttp: str, glorfindel_cfg=None):
    for candidate in (...):
        if candidate.exists():
            for rule in load_rules(candidate, glorfindel_cfg=glorfindel_cfg):
                if rule.ttp == ttp:
                    return rule
    return None
```

Et dans `resolve_attack_started` :
```python
rule = _find_rule_for_ttp(signal.get("ttp", ""), glorfindel_cfg=load_glorfindel_config())
```

**Références** :
- `glorfindel/agent.py:315-331` (`_find_rule_for_ttp`)
- `glorfindel/agent.py:354-363` (`resolve_attack_started` fallback)
- `collab/test_results.md` — analyse complète

## Traités (historique)
