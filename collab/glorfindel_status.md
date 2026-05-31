# Glorfindel — Status

_Mis à jour par la session Glorfindel après chaque changement significatif._

## État courant

- **Version** : 0.2.0
- **Dernière activité** : noeud `investigate` — enrichissement signal post-détection (MaxWrite, FailedAttempts, USER=root)
- **En cours** : ajout `run_id` synthétique dans RulePoller (`watch-{rule}-{ts}`) — diff non commité

## Interfaces exposées à Annatar

- **Format signal entrant** : voir `glorfindel/signals/schema.py` — champs requis : `event`, `ttp`, `resource_id`, `context.run_id`, `raw_signal.first_result_row`
- **detection_rules.yaml** : `rules/azure/detection_rules.yaml` — source de vérité pour les queries KQL

## À faire savoir à Annatar

_(rien pour l'instant)_
