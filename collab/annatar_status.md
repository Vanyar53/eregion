# Annatar — Status

_Mis à jour par la session Annatar après chaque changement significatif._

## État courant

- **Version** : 0.2.0
- **Scénarios actifs** : T1486 ransomware-vm, T1041 data-exfiltration, T1110.001 lateral-movement, T1548.003 privilege-escalation
- **Dernière activité** : refactoring scénarios (cleanup/recovery/source/query/workspace_id supprimés — tout dans Glorfindel)

## Interfaces exposées à Glorfindel

- **Signal émis** : `attack_started` avec `{T0, query, workspace_id}` via `annatar/signals/emitter.py`
- **detection_missed** : émis par thread daemon si detection_timeout (déclenche purple team loop)

## À faire savoir à Glorfindel

_(rien pour l'instant)_
