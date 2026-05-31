@CLAUDE.md

# Session Glorfindel — Agent défensif

Tu es spécialisé sur l'agent défensif. Lis ce fichier en début de session.

## Périmètre

**Tu travailles sur :**
- `glorfindel/` — tout le code de l'agent défensif
- `tests/unit/` — tests unitaires (ton code, pas Annatar)
- `rules/azure/detection_rules.yaml` — queries KQL
- `glorfindel-config.yaml` — config infra locale

**Tu lis mais ne modifies pas :**
- `annatar/signals/schema.py` — pour comprendre le format signal entrant
- `annatar/scenarios/azure/` — pour comprendre ce que tu dois détecter

**Tu ne touches pas :**
- `annatar/runner/`, `annatar/scenarios/` (sauf lecture)

## Protocole collab

**En début de session :** lis `collab/inbox_glorfindel.md` — traite les messages en attente avant de commencer.

**Après chaque changement significatif :** mets à jour `collab/glorfindel_status.md` (ce qui a changé, impact éventuel sur Annatar ou les tests).

**Si tu changes une interface partagée** (format signal attendu, schema detection_rules.yaml, API du `watch`) : écris un message dans `collab/inbox_annatar.md` avec le détail du changement.

**En fin de session :** snapshot de l'état dans `collab/glorfindel_status.md`.

## Contexte technique rapide

- LangGraph 8 nœuds : `load_context → poll_detection → investigate → decide → execute_action → verify_action → store_cycle` (+ `escalate_to_human`)
- `investigate` : enrichit le signal avec des requêtes KQL contextuelles avant `decide`
- `decide` : LLM via LiteLLM + few-shot + RAG ChromaDB — pas de routing table TTP→action
- RulePoller : polling continu des règles `detection_rules.yaml`, émet un signal structuré avec `run_id` synthétique (`watch-{rule}-{ts}`)
- Tests : `pytest` — 0 appel Azure, 0 appel LLM, `dry_run=True` partout
