# Elrond : dérouler des lots avec des agents Claude Code

Eregion avance par lots : O1, R1, G0… Chaque lot a sa fiche, ses mutants et ses critères « Fini quand ». **elrond** est un skill Claude Code livré dans le dépôt (`.claude/`). Il déroule ces lots avec des sous-agents et garde la trace de quel modèle a fait quoi.

Le contenu d'Eregion touche à la sécurité offensive : techniques d'attaque, rançongiciel, injection. Sur ce terrain, les protections cyber de Claude peuvent arrêter une réponse d'Opus 5.5 et la faire reprendre par un autre modèle, Opus 4.8. elrond ne l'empêche pas. Il fait trois choses :
- il garde la session principale en Opus 5.5 ;
- il isole chaque lot dans son propre sous-agent ;
- il fait relire en Opus 5.5 tout travail produit pendant une bascule.

```
session principale (Opus 5.5)        ne lit que l'index : ~/.claude/elrond/<dépôt>/plan.md
 ├─ elrond-planner    documents de pilotage → plan.md + une fiche par lot
 ├─ elrond-worker     un lot = un worktree (.claude/worktrees/) + une branche lot/<id>-…
 │                    lit CLAUDE_<RÔLE>.md de son lot ; lots indépendants en parallèle
 └─ elrond-reviewer   relecture Opus 5.5, d'abord les fichiers écrits pendant une bascule
palantir.py          lit les transcripts : quel modèle a répondu, arrêts des protections,
                     étape en cours, fichiers écrits pendant une bascule → journal
```

## Prérequis

- Claude Code, git, et Python 3.11 ou plus récent (comme le dépôt).
- L'accès au modèle `claude-opus-5-5`. Il est épinglé dans `.claude/agents/elrond-*.md` ; à changer là si besoin.
- Un abonnement adapté au parallélisme. Chaque sous-agent recharge `CLAUDE.md` et sa fiche :
  - sur **Claude Pro**, garder `Parallel: 1` ;
  - sur **Claude Max**, monter à `Parallel: 2` ou `3`.

## Démarrer

Dans le dépôt, depuis une session Claude Code :

1. `/elrond init <feuille de route> <mandat du codeur>`. Le planificateur écrit le plan dans `~/.claude/elrond/eregion/`. Les lots déjà livrés sont repérés grâce au `CHANGELOG.md` et à `git log`, et marqués `merged`.
2. Relire l'index proposé et ajuster l'en-tête de `plan.md` (`Parallel`, `Review policy`). Puis donner le feu vert.
3. `/elrond run` lance les prochains lots prêts ; `/elrond run O1 R1` lance des lots précis.
4. `/elrond status` donne l'avancement. `/elrond review <lot>` force une relecture.

Chaque lot produit une branche locale `lot/<id>-…`. elrond ne pousse rien et n'ouvre aucune PR sans demande explicite dans la session. Pour les lots que Jonathan délègue, la session principale pousse, ouvre la PR et fusionne après une CI verte et une relecture Opus 5.5 « ok » ([sessions.md](sessions.md)). La PR suit le modèle du dépôt, qui indique le modèle et le verdict de relecture.

## Le plan et le journal

- **Le plan est personnel.** Il vit dans `~/.claude/elrond/<dépôt>/` et ne va jamais dans le dépôt :
  - `plan.md` contient l'en-tête et l'index ;
  - `lots/<ID>.md` contient une fiche par lot, recopiée fidèlement des documents.
- **Le journal est dans `~/.claude/elrond/journal/<session>.md`.** Pour chaque tâche, il note :
  - les modèles qui ont répondu ;
  - chaque arrêt des protections, avec l'heure, la catégorie et l'étape en cours ;
  - chaque épisode de repli, avec sa période, ses actions et les fichiers écrits. Ces fichiers sont ceux des outils d'édition : si l'épisode a lancé une commande shell, ce qu'elle a écrit ne peut pas se lire dans le transcript. L'épisode le dit (`files_complete: false`, avec ses commandes), et le relecteur relit alors tout le diff.
- **Pour lire le journal à la main :**
  - `python3 .claude/skills/elrond/palantir.py session` : la dernière session ;
  - `python3 .claude/skills/elrond/palantir.py agent "elrond R1"` : une tâche précise.

## Relecture et bascule de modèle

- **La bascule est automatique** quand `switchModelsOnFlag` est actif, ce qui est le cas par défaut. Une requête signalée passe à Opus 4.8 pour ce tour seulement. Avec `false`, la session se met en pause et demande à un humain : à réserver aux runs surveillés.
- **Politique `after-fallback`, la valeur par défaut.** Un lot dont au moins un tour a été servi par un autre modèle est relu par Opus 5.5. Le relecteur reçoit la liste des fichiers écrits pendant la bascule et les lit en premier.
- **Politique `always`.** Tout lot est relu. C'est réaliste sur Claude Max.
- **Si la relecture bascule elle aussi**, le lot est marqué `not-obtained` et signalé. Il n'y a pas de relance automatique.

### Ce qu'elrond ne fait pas

Il ne cherche pas ce qui déclenche les protections et ne reformule rien pour les éviter : il observe, puis fait relire.

Pour travailler en Opus 5.5 sur du contenu cyber défensif, la voie officielle est le [Cyber Verification Program](https://support.claude.com/en/articles/14604842-real-time-cyber-safeguards-on-claude). Le journal fournit des cas datés à l'appui d'une demande.

## Avec les sessions spécialisées

elrond ne remplace pas les sessions par composant (`CLAUDE_<RÔLE>.md`, coordonnées par `collab/`) : il les complète pour dérouler la feuille de route.
- Chaque fiche indique les sessions concernées.
- L'exécutant lit les fichiers de rôle de ces sessions, ainsi que leur inbox, en lecture seule.
- Parmi les agents d'elrond, seule la session principale écrit dans `collab/` ; les exécutants n'y écrivent pas. Elle y range les impacts transverses qu'ils remontent.
- Les sessions spécialisées font relire et fusionner leurs PR par la session principale, l'Orchestre : [sessions.md](sessions.md).

## À plusieurs

Chacun a son plan local, et les documents de pilotage restent la source commune. Pour ne pas prendre deux fois le même lot, on l'annonce avant de le lancer : une PR brouillon `lot/<id>` ou un ticket assigné. Le sujet de la PR suit la convention des commits, et son modèle demande les critères, les tests, les mutants et la relecture.

## Hooks (facultatif)

`bash scripts/elrond-hooks.sh install` modifie **votre** `~/.claude/settings.json` :
- palantir sur les hooks `Stop` et `SubagentStop` : le journal se met alors à jour seul, et seulement pour les sessions qui ont utilisé elrond ;
- `scripts/agents_discord.py hook` sur `PreToolUse` (`Agent`, `SendMessage`, `SubagentHandback`, `AskUserQuestion`), `PostToolUse`, `SubagentStop`, `Notification` et `Stop` : les lots partent dans Discord. Lancé, relancé, rendu (avec le rapport), verdict et repli vont dans le fil du lot ; `#agents` tient le tableau de ce qui vous attend, avec un ping effacé une fois réglé (N1, N3, [atelier-discord.md](atelier-discord.md)). Sans sa configuration, ce hook n'envoie rien.

`uninstall` les retire, en laissant les autres hooks en place. Ces hooks restent en dehors du dépôt, car ils s'exécuteraient chez chaque contributeur. Chaque commande finit par `|| true` : un hook qui sort en 2 bloquerait l'outil ou retiendrait l'agent. Sans ces hooks, elrond lance de toute façon palantir après chaque sous-agent.

## Dépannage

| Symptôme | Piste |
|---|---|
| Git refuse d'extraire `lot/…` : branche déjà tenue par un autre worktree | `git worktree list` : travailler dans ce dossier, ou `git worktree remove` puis `git worktree prune` |
| Des dossiers traînent dans `.claude/worktrees/` | Ils sont ignorés par Git. `git worktree list`, puis `git worktree remove <chemin>` |
| Un agent refuse de démarrer à cause du modèle | Le modèle épinglé n'est pas disponible sur ce compte : changer `model:` dans `.claude/agents/elrond-*.md` |
| Le journal est vide | Hooks non installés : `palantir.py session` le reconstruit à la demande |
