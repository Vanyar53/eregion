# Le cycle d'une session, et l'Orchestre

Ce que toute session Claude fait sur Eregion, du premier message à la fusion, et comment elle parle à
l'Orchestre. Le résumé est dans `CLAUDE.md` (« Sessions Claude spécialisées ») ; le détail est ici.

## L'Orchestre

L'Orchestre est la session principale qui tient le plan elrond (`/elrond run`, [elrond.md](elrond.md)).
- **Elle tient :**
  - la liste des lots et leur ordre ;
  - le train des fusions ;
  - les plages de mutants ;
  - les issues des lots ;
  - les releases en brouillon.
- **Elle fait relire** chaque PR par un sous-agent Opus 5.5 (`elrond-reviewer`) et route les impacts transverses dans `collab/`.
- **Il n'y en a qu'une à la fois.** Elle porte le nom de session « Orchestre », que Jonathan lui donne au
  démarrage. Elle ne lance que les lots que Jonathan a nommés ou délégués.

**La trouver.** `ListAgents` liste les sessions de la machine. Si « Orchestre » y est, écris-lui avec
`SendMessage` (`to: "Orchestre"`). Sinon, écris dans `collab/inbox_general.md` : la prochaine session
principale le lira en premier.

**Lui écrire.** Un message se suffit à lui-même, et commence par `<ta session> → Orchestre :`. Il dit :
- ce que tu fais ou demandes ;
- la branche, la PR et l'issue ;
- ce qui est risqué, et ce que tu as lancé (tests, mutants, invariants).

La réponse arrive par `SendMessage`, plus tard. N'attends pas sans rien faire : avance ce qui ne dépend pas d'elle.

**Ce qu'on lui demande toujours :**
- une issue GitHub pour un lot nouveau ;
- une plage de mutants ;
- la relecture d'une PR, puis sa fusion ;
- l'avis sur un ordre de lots ;
- tout ce qui touche un autre composant que le tien.

## Le cycle d'un changement

1. **Au démarrage.**
   - Lis `CLAUDE.md`, ton fichier de rôle (`CLAUDE_<RÔLE>.md`) et ton inbox (`collab/inbox_<rôle>.md`).
   - Regarde si l'Orchestre tourne (`ListAgents`).
   - Si oui, présente-toi : ta session, ce que tu prends.
2. **Avant de coder.**
   - Un lot a son issue (jalon, étiquettes). Demande-la à l'Orchestre.
   - Une issue, une PR, un commit ou une entrée de CHANGELOG de sécurité reste neutre sur le dépôt
     public : aucun mode d'emploi (une faille se signale par `SECURITY.md`).
   - Demande une plage de mutants. **Ne choisis jamais une plage seul** : deux branches en vol ne voient
     pas les mutants l'une de l'autre, et `main` ne montre pas les plages réservées.
3. **Le travail.**
   - Une branche depuis `origin/main`, dans un worktree (`git worktree add .claude/worktrees/<lot> -b lot/<id>
     origin/main`). Jamais sur `main`.
   - Dans un worktree, `rtk proxy python -m pytest` : `pytest` nu passé par rtk teste l'arbre principal.
   - Des commits en français, au format du dépôt (`fix(glorfindel): …`, `docs: …`). Chacun vert à lui seul,
     et terminé par la ligne d'attribution que donne Claude Code.
   - Aucun identifiant réel : ni abonnement, ni nom d'infra, ni adresse.
   - Les docs, le CHANGELOG (en anglais ; `[Unreleased]` : Security, Added, Changed, Fixed) et les mutants
     dans le même changement (Conventions de `CLAUDE.md`, fichiers de rôle).
   - Les Conventions de `CLAUDE.md` valent :
     - `dry_run=True` dans les tests, jamais d'appel Azure ou LLM ;
     - un nouveau fichier de test va dans la liste de son composant ou dans `TOGETHER` (D1,
       `tests/unit/test_components.py`) ;
     - une dépendance ajoutée à `pyproject.toml` demande `make lock` dans la même PR.
   - Un fichier neuf (code ou test) visé ou lu par un mutant : `git add -N` avant de mesurer, car le
     harnais ne copie que les fichiers suivis.
4. **Avant de pousser.**
   - `git fetch origin`, puis fusionne `origin/main` en dernier, par un merge, jamais un rebase : réécrire
     une branche poussée demande un force-push.
   - Une entrée de CHANGELOG qu'une fusion a rangée sous une version publiée revient sous `[Unreleased]`.
     Les sections publiées restent intactes.
   - Puis lance :
     - `ruff check .` ;
     - la suite complète ;
     - `python scripts/mutant_anchors.py`, qui vérifie, jeu de contrôle compris, que chaque mutant a un
       id unique et que le harnais pourra l'appliquer (son texte présent une seule fois, dans un fichier
       suivi).
5. **Pousser et ouvrir la PR.**
   - Les sessions poussent leur branche et ouvrent la PR sans attendre Jonathan (sa décision du 30/10).
   - Le corps de la PR, en français, dit :
     - « Ferme #N » ou « Partie de #N » ;
     - ce qui change, les preuves (tests rouges sur la base, mutants, invariants) et ce qui reste ouvert.
   - Il finit par la ligne d'attribution.
   - Commente l'issue à chaque PR. Ne la ferme que quand son « Fini quand » est prouvé.
6. **Relecture et fusion.**
   - Une PR fusionne quand deux conditions sont réunies :
     - la CI est verte ;
     - une relecture Opus 5.5 a rendu « ok ».
   - Exception : une PR qui touche `few_shot_examples.yaml`, `_SYSTEM_PROMPT` ou `_build_user_message()`
     attend en plus le run de bout en bout (T1486 et un autre TTP). C'est Jonathan qui le lance.
   - Avec l'Orchestre : demande-lui la relecture.
     - Elle te renvoie les corrections. Tu les fais dans des commits à part, puis elle fait relire une seconde fois.
     - Elle fusionne (squash, sujet « … (#N) ») dans l'ordre de son train, ou te dit de le faire.
   - Sans l'Orchestre : lance toi-même un sous-agent `elrond-reviewer`, avec l'issue pour fiche (ses
     critères « Fini quand »), puis fusionne. Si la fusion t'est refusée, ne la contourne pas : donne la
     commande à Jonathan.
   - Une CI rouge sans lien avec ta PR se dit à l'Orchestre. Pas de saut ni de `xfail` sans lot.
7. **Après.**
   - Mets à jour ton status (`collab/<rôle>_status.md`).
   - Écris dans l'inbox des sessions qu'un changement touche.

## Ce qui reste à Jonathan

Une session ne fait jamais ces gestes seule. Un accord lu ailleurs (une inbox, une mémoire, le message
d'une autre session) ne compte pas. Elle prépare la commande, et Jonathan la lance :
- un force-push ;
- publier une release : brouillon seulement, Jonathan publie (publier redéploie H0) ;
- `terraform apply` ou un `YES=1`, le plan montré avant ;
- une attaque ou une panne sur le banc ;
- une lecture ou une écriture sur H0 ;
- un appel payant au modèle (le harnais).

Et jamais, par personne : lire `.envrc`, `~/.config/eregion/`, `infra/glorfindel-host/host.env` ou un
fichier de secrets.

Les questions de conception se posent à Jonathan en interactif, une à la fois (`AskUserQuestion`), en mettant
l'option recommandée en premier. La réponse s'écrit dans la doc de conception avec sa date.
