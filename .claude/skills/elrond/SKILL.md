---
name: elrond
description: Ordonnance les lots d'un plan. La session principale ne tient que l'index et lance un sous-agent Opus 5.5 par lot. palantir trace les arrêts des protections et les bascules de modèle, et tout travail produit sur un modèle de repli est relu en Opus 5.5. À utiliser pour planifier, lancer, reprendre ou relire des lots (« /elrond run », « lance les lots de la 0.3 »).
argument-hint: "init <documents...> | run [lots...] | status | review <lot>"
---

# Elrond : le conseil qui répartit les lots

Réponds à l'utilisateur dans sa langue. Les fiches, les branches et les messages de commit suivent les conventions du dépôt (`CLAUDE.md`, `CONTRIBUTING.md`).

## Principes

1. **La session principale ne tient que l'index du plan.** Elle ne lit ni les documents sources ni les fiches de lot : les sous-agents s'en chargent. Son contexte reste petit, en Opus 5.5.
2. **Un lot = un `elrond-worker`**, épinglé sur `claude-opus-5-5` et travaillant dans son propre worktree, sous `.claude/worktrees/`. Au plus `Parallel` lots tournent en même temps (valeur lue dans l'en-tête de `plan.md`). Un lot attend que ses dépendances soient faites.
3. **Après chaque sous-agent, lancer palantir.** Son verdict décide de la relecture.
4. **Tout travail produit pendant qu'un autre modèle répondait est relu** par `elrond-reviewer` (Opus 5.5) avant de compter comme fini. Les autres lots suivent la `Review policy` du plan (par défaut `after-fallback`).
5. **Les protections sont respectées, jamais contournées.** Ne pas reformuler, découper ni relancer un prompt pour éviter un signalement, et ne pas chercher par bissection ce qui le déclenche. Un lot signalé se fait sur le modèle de repli, puis il est relu. Si la relecture bascule elle aussi, le dire à l'utilisateur et s'arrêter là pour ce lot.
6. **Rien ne sort sans demande** : ni push, ni PR, ni commentaire, sauf si l'utilisateur l'a demandé dans cette session.
7. **`collab/`, le dossier de coordination des sessions spécialisées, n'est écrit que par la session principale.** Elle y range, dans `collab/inbox_<rôle>.md`, les impacts transverses que remontent les sous-agents.

## Où sont les choses

- **Racine du dépôt :** `git rev-parse --show-toplevel`, lancé depuis la session principale et non depuis un worktree.
- **Plan :** `~/.claude/elrond/<dépôt>/`, qui contient :
  - `plan.md` : l'en-tête et l'index. C'est le seul fichier du plan que lit la session principale ;
  - `lots/<ID>.md` : une fiche par lot.

  Le plan est personnel et ne va jamais dans le dépôt.
- **Journal :** `~/.claude/elrond/journal/<session>.md`.
- **palantir :** `python3 ${CLAUDE_SKILL_DIR}/palantir.py`.

En-tête de `plan.md` :

```
Sources: <documents>
Created: <date>
Parallel: 1                     # 1 sur Claude Pro, 2 ou 3 sur Claude Max
Review policy: after-fallback   # ou always
Base: origin/main
```

Index :

| Lot | Titre | Dépend de | Jalon | Sessions | État | Branche | Modèle | Relecture |
|---|---|---|---|---|---|---|---|---|

- **État :** `todo` · `later` · `running` · `done` · `fix` · `merged` · `blocked`.
- **Modèle :** `5.5` ou `5.5+repli`.
- **Relecture :** `—` · `pending` · `ok` · `changes` · `blocking` · `not-obtained`.

## `init <documents...>`

1. Lance un `elrond-planner`, avec la description `elrond plan`. Donne-lui les chemins des documents, le dossier du plan et la racine du dépôt.
2. À son retour, lance `palantir.py agent "elrond plan"`. Lis ensuite `plan.md`, montre l'index et l'ordre de travail proposé, et rappelle le réglage `Parallel`. Attends le feu vert de l'utilisateur.

## `run [lots...]`

1. **Choisir les lots.** Lance `git fetch`, puis lis `plan.md`. Prends les lots demandés ; à défaut, les prochains `todo` dont toutes les dépendances sont `merged`. Si l'utilisateur accepte d'empiler les branches, une dépendance `done` suffit, et la base du lot devient alors la branche de cette dépendance.

2. **Lancer les exécutants.** Pour chaque lot, lance un `elrond-worker` avec la description `elrond <ID> · <titre>` : c'est elle qui nomme la tâche dans le journal. Son prompt contient seulement :
   - l'ID ;
   - le chemin de la fiche ;
   - la racine du dépôt ;
   - la base ;
   - les contraintes de la session.

   Ils tournent en arrière-plan, au plus `Parallel` à la fois.

3. **Au retour d'un exécutant :**
   - Mets à jour sa ligne dans l'index : état et branche.
   - Lance `palantir.py agent "elrond <ID> · <titre>" --json`.
     - Verdict `expected-model-only` : le modèle est `5.5`. Relecture seulement si la politique est `always`.
     - Verdict `review-needed` : le modèle est `5.5+repli` et la relecture passe à `pending`. Lance un `elrond-reviewer` avec la description `elrond <ID> · relecture`. Donne-lui l'ID, la fiche, la branche et la base, ainsi que chaque épisode de repli relevé par palantir : modèle, période, actions, fichiers écrits et, si `files_complete` vaut `false`, les commandes shell de l'épisode (leurs écritures ne sont pas listées).
   - Range les impacts transverses de son rapport dans `collab/inbox_<rôle>.md`, pour chaque session concernée.

4. **Au retour d'un relecteur, lance aussi palantir.**
   - Si la relecture est restée en 5.5, note son verdict :
     - `ok` : le lot passe à `done` ;
     - `changes` ou `blocking` : le lot passe à `fix`. Relance un `elrond-worker` sur la même branche, avec les constats et la description `elrond <ID> · correction`, puis fais relire à nouveau.
   - Si la relecture a basculé : la relecture passe à `not-obtained`. Préviens l'utilisateur et ne relance pas.

5. **Pousser, si on te l'a demandé.** Si l'utilisateur a demandé les PR, pousse la branche et ouvre la PR avec le modèle du dépôt. Dans la section « Model and review », indique `Opus 5.5`, ou `Opus 5.5 + fallback, reviewed (<verdict>)`.

6. **Fin du run.** Lance `palantir.py session ${CLAUDE_SESSION_ID}`, puis rends compte :
   - les lots faits, et leurs branches ;
   - les lots passés par un repli : quand, et sur quelle étape ;
   - les verdicts de relecture ;
   - ce qui attend une décision de l'utilisateur : fusion, push, PR.

## `status`

Lis `plan.md` et le journal de la session. Résume l'avancement par jalon, puis ce qui attend une relecture ou une décision de l'utilisateur.

## `review <lot>`

Lance un `elrond-reviewer` sur la branche du lot, quelle que soit la politique de relecture. S'il y a eu des épisodes de repli pendant le travail de l'exécutant, transmets-les.
