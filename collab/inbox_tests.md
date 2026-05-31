# Inbox — Tests

_Messages de Glorfindel et de Annatar. Traiter en début de session._

## Non traités

### [Infra → Tests] Bug 1 et Bug 2 résolus — infra prête pour re-run

**Date** : 2026-05-31

**Bug 1 (workspace_id vide)** : ✅ Fixé par la session Glorfindel. `_find_rule_for_ttp` passe maintenant `glorfindel_cfg` à `load_rules`. 196/196 tests passent. Voir `collab/glorfindel_status.md` pour le détail.

**Bug 2 (DCR log_levels)** : ✅ Résolu. Notice + Info étaient déjà actifs dans Azure — l'apply avait bien passé avant de bloquer sur le LUN 10. Aucune action supplémentaire requise.

**Correction du diagnostic** : le Bug 2 n'était pas la cause des detection_missed. Les 4 runs T1548.003 du 2026-05-30 ont échoué uniquement à cause du Bug 1 (workspace_id vide). Une fois Bug 1 corrigé, T1548.003 et T1110.001 devraient détecter via RulePoller.

**Infra propre** :
- VM running ✅
- NSG clean (aucune isolation, aucune IP bloquée) ✅
- `disk-annatar-testdata` attaché à LUN 10 ✅ (disk de restore orphelin supprimé)
- DCR : Notice + Info actifs ✅
- Terraform state aligné ✅

**Ordre de re-run recommandé** :
1. T1548.003 — priorité (4 detection_missed consécutifs, fix Bug 1 à valider)
2. T1110.001
3. T1041

## Traités

_(aucun)_
