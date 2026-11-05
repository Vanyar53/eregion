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
   - Les docs, l'entrée de CHANGELOG et les mutants dans le même changement (Conventions de `CLAUDE.md`,
     fichiers de rôle). **Chacun dans un fichier à soi** (CI5, #512) : deux PR en vol n'écrivent plus
     aux mêmes lignes, et la fusion de l'une ne met plus l'autre en conflit.
     - **L'entrée de CHANGELOG** va dans `changes/<lot>.md`, jamais sous `[Unreleased]` de
       `CHANGELOG.md`. En anglais, ses sections en titres `### Security`, `### Added`, `### Changed`,
       `### Fixed` : le texte même que la version recevra (`changes/README.md`, la forme).
       `make release` les assemble sous `[X.Y.Z]`, dans cet ordre de sections, et les retire.
       `tests/unit/test_release.py` refuse un fragment mal formé dans la PR même.
     - **Les mutants** vont dans `scripts/mutants/<lot>.py` : `MUTANTS`, `TESTS` (ses ids seulement),
       au besoin `TESTS_ALSO` (des tests ajoutés au mutant d'un autre) ; ses chemins en chaînes, sans
       rien importer du harnais. `scripts/mutation_check.py` les charge avant sa garde ;
       `scripts/mutants/CI5.py` sert d'exemple. Les blocs déjà dans le harnais y restent.
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
   - Une entrée qu'une branche plus ancienne avait encore écrite sous `[Unreleased]` (avant CI5) et
     qu'une fusion a rangée sous une version publiée en sort : elle va dans `changes/<lot>.md`. Les
     sections publiées restent intactes. Un fragment ne bouge jamais à la fusion : c'est son intérêt.
   - Puis lance :
     - `ruff check .` ;
     - la suite complète ;
     - `python scripts/mutant_anchors.py`, qui vérifie, jeu de contrôle compris, que chaque mutant a un
       id unique et que le harnais pourra l'appliquer (son texte présent une seule fois, dans un fichier
       suivi), et que la garde `if __name__ == "__main__"` reste la dernière instruction de
       `scripts/mutation_check.py`. Il lit les deux endroits : les blocs du harnais et chaque
       `scripts/mutants/<lot>.py`. Un id pris deux fois est une faute qui nomme chaque fichier ; un
       fichier de lot sans mutant, ou dont `TESTS` nomme le mutant d'un autre, aussi. Un fichier de lot
       neuf : `git add -N` d'abord. Ce qui suivrait la garde du harnais n'est jamais mesuré (54 mutants
       l'étaient le 02/11, MCG) ; `tests/unit/test_mutant_anchors.py` échoue alors. Une raison
       illisible aussi est une faute (CI6e).
   - **Tes mutants, tous attrapés.** Depuis CI6e (#553), la porte de release et la mesure du lundi sont
     rouges dès qu'un mutant compté survit à un tour sans raison que le harnais lit. Une raison commence
     par `EQUIVALENT:`, `MULTI-HOST:` ou `TIMING:`, et doit être vraie, vérifiable à la lecture du code ;
     jamais une raison pour faire passer la porte. Un survivant se tue d'abord par un test. Un run
     `--only` sur tes mutants sort en 1 s'il en reste un.
   - **La plage de mutants** se demande toujours à l'Orchestre : deux fichiers de lot ne se gênent plus
     dans le texte, mais un même id pris deux fois reste une faute, vue à la fusion seulement.
5. **Pousser et ouvrir la PR.**
   - Les sessions poussent leur branche et ouvrent la PR sans attendre Jonathan (sa décision du 30/10),
     sous l'identité de l'App des sessions, jamais sous la sienne (plus bas, « L'identité des sessions »).
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
   - **Le verdict se publie sur la PR, avant la fusion** (SEC12, #418). Quiconque fusionne, l'Orchestre
     ou toi, publie chaque verdict de relecture (`ok`, `changes`, `blocking`) en commentaire, et ne
     fusionne que le commit relu. Ce commit se note **au lancement du relecteur**,
     `git fetch origin`, puis `reviewed=$(git rev-parse origin/<branche>)` pour une branche poussée
     (`git rev-parse <branche>` pour une branche locale). Cela vaut pour toute relecture, la première comme
     chaque relance après des corrections. Il lui est donné, et son rapport le redit (« Commit relu »).
     Ce n'est jamais la tête lue au moment de publier : un push entre la relecture et la publication
     passerait pour relu.
     ```
     python3 scripts/review_verdict.py body --lot <ID> --verdict ok --head "$reviewed" --report <rapport> \
       | gh pr comment <n> --body-file -
     gh pr view <n> --json headRefOid,comments \
       | python3 scripts/review_verdict.py check --reviewed "$reviewed" --author eregion-agents --author grootcyber
     gh pr merge <n> --squash --match-head-commit "$reviewed"
     ```
     `check` ne lit que les commentaires des auteurs nommés, l'App des sessions et le mainteneur : sur
     une PR publique, n'importe qui peut commenter. Les deux noms le font marcher avant comme après la
     bascule des sessions sur l'App. Il échoue si la tête de la PR n'est pas
     `$reviewed` (un push après la relecture : une autre relecture), ou si le dernier verdict publié
     pour ce commit n'est pas `ok`. Le verdict est **tracé**, pas authentifié : il dit qui l'a publié
     (l'App), pas qu'un relecteur l'a rendu.
   - Une CI rouge sans lien avec ta PR se dit à l'Orchestre. Pas de saut ni de `xfail` sans lot.
7. **Après.**
   - Mets à jour ton status (`collab/<rôle>_status.md`).
   - Écris dans l'inbox des sessions qu'un changement touche.

## Le cycle d'une release (CI6, #514)

Décision de Jonathan du 04/11 : une release a toujours eu la mesure la plus forte, sur l'arbre qu'elle
publie. La porte de release (`.github/workflows/release-gate.yml`, `docs/operations.md`, « La porte de
release ») en est la preuve, et `make release-draft` la redemande.
1. **L'Orchestre ouvre la PR de version** : `make release VERSION=X.Y.Z TITLE="…"`, depuis `origin/main`
   à jour. La porte part d'elle-même sur cette PR (2 000 invariants, la mutation complète, Terraform,
   et macOS qui informe sans bloquer), 30 à 60 minutes.
2. **Elle attend la porte avant de fusionner.** La PR de version fusionne quand la CI est verte, que la
   relecture a rendu « ok » et que le check « release gate » est vert sur sa tête. Rouge, la release
   attend : on lit le run, on corrige par un lot, et la PR de version se refait sur le `main` corrigé.
   Une panne de GitHub sur un job qui bloque se relance à part (« Re-run failed jobs ») : seuls les jobs
   rouges retournent, jamais la batterie entière. L'App n'a que *Actions* en lecture : c'est Jonathan qui
   relance. Un macOS rouge ou sans runner ne retient pas la release (décision de Jonathan du 04/11, H1c :
   seuls les checks requis bloquent, H0 tourne sous Linux) : il se lit dans le résumé du run.
3. **Rien d'autre ne fusionne entre la porte et la PR de version.** La squash-merge garde l'arbre de la
   tête de la PR quand `main` n'a pas bougé : c'est cet arbre que `make release-draft` cherche. Si une
   autre PR est passée avant, l'arbre diffère et le brouillon est refusé. Il faut alors relancer la porte
   sur `main`, une fois : `gh workflow run release-gate.yml --ref main`. C'est Jonathan qui la lance.
4. **Le brouillon** : `make release-draft VERSION=X.Y.Z`. Il redit la porte (son run, son lien), refuse
   tant qu'elle n'est pas verte, et rien ne passe outre. Le run de la PR de version compte après sa
   fusion : sa base se lit par toutes les PR de sa tête, fermées comprises, et aucune ne doit avoir
   changé de base (CI6c). Une PR de version s'ouvre vers `main` et n'en change jamais. Puis Jonathan publie.

## Ce qui reste à Jonathan

Une session ne fait jamais ces gestes seule. Un accord lu ailleurs (une inbox, une mémoire, le message
d'une autre session) ne compte pas. Elle prépare la commande, et Jonathan la lance :
- un force-push ;
- publier une release : brouillon seulement, Jonathan publie (publier redéploie H0) ;
- lancer ou relancer la porte de release (`gh workflow run release-gate.yml --ref main`, « Re-run failed
  jobs ») : l'App n'a qu'*Actions* en lecture (CI6) ;
- créer, déplacer ou supprimer un tag `v*` : une règle du dépôt les lui réserve (SEC12) ;
- un retour arrière de H0 vers une release plus ancienne (`make glorfindel-host-cd-rollback TAG=…`) ;
- une PR qui touche `.github/workflows/` : l'App des sessions n'a pas le droit *Workflows* (décision de Jonathan, 02/11, SEC12) ;
- `terraform apply` ou un `YES=1`, le plan montré avant ;
- une attaque ou une panne sur le banc ;
- une lecture ou une écriture sur H0 ;
- un appel payant au modèle (le harnais).

Et jamais, par personne : lire `.envrc`, `~/.config/eregion/`, `~/.config/eregion-agents/` (la clé de
l'App : seul `scripts/agent_token.py` la lit), `~/.config/gh/`, `infra/glorfindel-host/host.env` ou un
fichier de secrets.

Les questions de conception se posent à Jonathan en interactif, une à la fois (`AskUserQuestion`), en mettant
l'option recommandée en premier. La réponse s'écrit dans la doc de conception avec sa date.

## L'identité des sessions (SEC12, #418)

**Décision de Jonathan (02/11).** Les sessions d'agents ont leur propre identité sur GitHub : une
GitHub App, installée sur ce seul dépôt. Elles poussent, ouvrent les PR, commentent et fusionnent
sous ce nom, jamais sous le compte du mainteneur. Les fusions restent autonomes. Les tags `v*` sont
réservés au mainteneur par une règle du dépôt (plus bas), et le CD de H0 refuse une release plus
ancienne que ce qui tourne (`infra/glorfindel-host/README.md`, « Le CD de H0 »).

**Ce qui la tient.** `scripts/agent_token.py` tire un jeton d'installation d'une heure, limité à ce
dépôt, et le met en cache (`~/.cache/eregion-agents/`, 0600) jusqu'à 5 minutes de son expiration.
Deux emballages, dans `scripts/agent-bin/` :
- `gh` lance le vrai `gh` avec ce jeton (`GH_TOKEN`) et un dossier de config à part
  (`~/.config/eregion-agents/gh`). Il ne lit jamais celui du mainteneur. Sans jeton, il n'appelle rien ;
- `git-credential-eregion-agent` est l'assistant d'identifiants de `git`. Il ne répond que pour
  `https://github.com/grootcyber/eregion`, et ne dit rien pour tout autre hôte ou dépôt.

L'App a les droits que lui donne Jonathan, jamais plus. **Décision de Jonathan (02/11) : pas de
droit *Workflows*.** Ses droits : *Contents*, *Pull requests* et *Issues* en écriture ; *Actions*,
*Checks* et *Commit statuses* en lecture ; *Metadata* en lecture (imposé). Rien d'autre : ni
administration, ni secrets, ni environnements, ni paquets. Sans *Workflows*, une branche qui touche
`.github/workflows/` est refusée au push de l'App : Jonathan pousse et fusionne ce changement lui-même.
Les workflows tiennent les jetons OIDC (publication des images, canari) et les secrets. Sans ce droit,
une session ne change pas ce qui tourne avec eux. La clé de l'App est lisible par les sessions : elles
tournent sous le même utilisateur Unix. Elle ne donne que les droits de l'App.

### L'App (fait, 02/11)

Jonathan a créé l'App `eregion-agents` (son nom est le login que lit `review_verdict.py check
--author`), sans webhook, installable sur son compte seul. Il l'a installée sur le seul dépôt
`eregion`. Sa clé est dans `~/.config/eregion-agents/app.pem` (600), et son ID dans
`~/.config/eregion-agents/app_id`. **L'App ID est un identifiant réel** : il ne va jamais dans le
dépôt (ni code, ni test, ni doc). Le script le lit à l'exécution, dans `EREGION_AGENTS_APP_ID`, sinon
dans `app_id`. `agent_token.py` refuse une clé lisible par d'autres, ou qui n'est pas une clé RSA.
Une clé perdue ou exposée se révoque dans les réglages de l'App (Private keys), et une autre se génère.

### Basculer les sessions (Jonathan)

Rien ne change pour ton propre terminal, ni pour tes autres projets : seules les sessions de Claude
Code lancées dans `~/eregion` basculent. Ce sont tes fichiers : une session ne les écrit pas.

0. **Avant tout : SEC12 fusionné, et `~/eregion` à jour sur `main`** (`git -C ~/eregion switch main &&
   git -C ~/eregion pull --ff-only`). Les emballages de `scripts/agent-bin/` et `agent_token.py` sont
   lus depuis ce checkout.
1. **La config `git` des sessions**, `~/.config/eregion-agents/gitconfig`. Elle reprend la tienne,
   puis passe GitHub en https avec l'assistant de l'App :
   ```
   [include]
   	path = ~/.gitconfig
   [url "https://github.com/"]
   	insteadOf = git@github.com:
   	insteadOf = ssh://git@github.com/
   [credential]
   	helper =
   [credential "https://github.com"]
   	helper =
   	helper = /home/<toi>/eregion/scripts/agent-bin/git-credential-eregion-agent
   	useHttpPath = true
   ```
   Le `helper =` vide efface les assistants hérités (le tien ne sert jamais aux sessions).
   `useHttpPath` fait passer le chemin du dépôt : l'assistant ne répond que pour celui-ci.
2. **L'environnement des sessions de ce projet seul**, dans `~/eregion/.claude/settings.local.json`,
   bloc `env`. Ce fichier est ignoré par Git (`.gitignore`) et ne vaut que pour ce projet : jamais dans
   `~/.claude/settings.json`, qui vaudrait pour tous.
   ```
   {
     "env": {
       "EREGION_AGENT_SESSION": "1",
       "GIT_CONFIG_GLOBAL": "/home/<toi>/.config/eregion-agents/gitconfig",
       "GIT_TERMINAL_PROMPT": "0",
       "GH_CONFIG_DIR": "/home/<toi>/.config/eregion-agents/gh"
     }
   }
   ```
   S'il existe déjà, ajoute le bloc `env` à ce qu'il contient. `GH_CONFIG_DIR` ferme la porte : un
   `gh` lancé sans l'emballage ne trouve pas ton jeton. Il n'est pas authentifié et échoue sur toute
   écriture. Les worktrees des lots héritent de l'environnement de la session qui les lance.
3. **Un aiguilleur `gh`, pour ces sessions seules**, dans `~/.local/bin/gh` (qui passe avant `/usr/bin`
   dans le PATH). Il regarde la variable du projet **au moment de chaque commande** : Claude Code
   prépare son shell avant d'appliquer le bloc `env`, si bien qu'une condition dans `~/.zshrc` ne la
   voit jamais (mesuré le 02/11). `EREGION_AGENT_GH` dit à l'emballage où est le vrai `gh`, pour qu'il
   ne se rappelle pas lui-même :
   ```
   cat > ~/.local/bin/gh <<'EOF'
   #!/bin/sh
   # SEC12 : dans une session Claude Code d'eregion, gh agit sous l'App ; ailleurs, c'est le gh du système.
   if [ -n "$EREGION_AGENT_SESSION" ]; then
     EREGION_AGENT_GH=/usr/bin/gh exec /home/<toi>/eregion/scripts/agent-bin/gh "$@"
   fi
   exec /usr/bin/gh "$@"
   EOF
   chmod +x ~/.local/bin/gh
   ```
   `git`, lui, n'en a pas besoin : la config des sessions nomme l'assistant par son chemin.
4. **Relance les sessions d'eregion**, puis vérifie depuis l'une d'elles :
   - `echo $EREGION_AGENT_SESSION` donne `1`. Vide, la session n'a pas lu
     `~/eregion/.claude/settings.local.json` (c'est le cas d'une session lancée directement dans un
     worktree, ou depuis un autre dossier) : elle n'a ni l'emballage ni la config `git` de l'App, et
     retombe sur tes identifiants. Lance les sessions depuis `~/eregion` ;
   - `command -v gh` donne `~/.local/bin/gh`, l'aiguilleur. Dans ton terminal ou un autre projet, il passe au `gh` du système ;
   - `python3 ~/eregion/scripts/agent_token.py whoami` donne `jeton de l'App <ID> : grootcyber/eregion ;
     expire dans 59 min` (code 1 si le jeton atteint un autre dépôt) ;
   - `gh api /installation/repositories -q '.repositories[].full_name'` donne `grootcyber/eregion`, seul ;
   - `gh api graphql -f query='{viewer{login}}'` donne `eregion-agents[bot]` (mesuré le 02/11). `gh api user` répond 403 (« Resource not accessible by integration ») : c'est le cas
     d'un jeton d'installation, la preuve que ce n'est plus ton compte ;
   - `git ls-remote --get-url origin` et `git remote get-url --push origin` donnent l'URL en `https://` ;
   - `git push` d'une branche de lot passe, et la PR ouverte porte le nom de l'App.
5. **Les gestes qui restent les tiens** (publier une release, un tag `v*`, une PR qui touche
   `.github/workflows/`, les réglages du dépôt) passent par l'interface web, ou par un `gh` qui tient
   ton jeton dans ton terminal, hors des sessions.

**Ce que la bascule ne ferme pas seule** : une session qui n'a pas lu `settings.local.json` (lancée
dans un worktree, ou ailleurs) agit encore sous ton compte, tant que tes identifiants sont sur ce
poste. Seul leur retrait, ci-dessous, ferme ce cas : sans eux, une telle session n'a plus aucune
identité sur GitHub, et ses écritures échouent.

### Retirer tes identifiants du poste des sessions (Jonathan)

Les sessions tournent sous ton utilisateur Unix : tout ce que tu peux lire, elles le peuvent aussi.
Une fois la bascule vérifiée :
- **`gh auth logout --hostname github.com`** dans ton terminal. Ton jeton quitte `~/.config/gh/hosts.yml`.
  Pour un geste de mainteneur en ligne de commande (une PR qui touche `.github/workflows/`, une
  release), passe un jeton le temps d'une commande, tiré de ton gestionnaire de mots de passe :
  `GH_TOKEN=$(<gestionnaire> …) gh pr merge …`. Jamais le jeton en clair sur la ligne : il resterait
  dans l'historique du shell. Pour pousser la branche d'une telle PR, l'interface web, ou ta clé SSH ;
- **ta clé SSH pour GitHub** : une clé qui demande un toucher (`ssh-keygen -t ed25519-sk`), ou une
  phrase de passe sans agent chargé pendant les sessions. Sinon, retire-la de GitHub (Settings → SSH
  and GPG keys) et pousse par l'interface web. La clé de H0 et d'Orodruin n'est pas concernée ;
- **ce qui reste ouvert** : tant que tes identifiants sont sur ce poste, une session peut les lire.
  La séparation complète serait un utilisateur Unix propre aux sessions (`docs/design/modele-de-menace.md`,
  frontière 7).

## Les règles du dépôt (SEC12, Jonathan)

**Settings → Rules → Rulesets → New ruleset**, deux fois. Les rulesets s'ajoutent à la protection
classique de `main`, sans la remplacer. **Ne retire la protection classique qu'une fois les cinq checks
ci-dessous présents dans le ruleset « main »** : sans eux, une PR rouge deviendrait fusionnable.

1. **« tags v* » (New tag ruleset).**
   - Enforcement status : **Active** ;
   - Bypass list : **Repository admin**, mode **Always** (toi seul) ;
   - Target tags : **Include by pattern** `v*` ;
   - Rules : **Restrict creations**, **Restrict updates**, **Restrict deletions**.

   Publier une release crée son tag : tu passes par ta dérogation, l'App est refusée. Une release
   en brouillon ne crée pas de tag : les sessions en préparent toujours.

   **Si le rôle « Repository admin » n'est pas proposé dans la Bypass list** (le cas possible d'un dépôt
   personnel), n'active pas la règle telle quelle : elle te bloquerait toi-même, et plus aucune release
   ne se publierait. Laisse-la en **Evaluate** le temps de trouver la dérogation qui te nomme, puis
   passe-la en Active.
2. **« main » (New branch ruleset).**
   - Enforcement status : **Active** ;
   - Bypass list : **Repository admin**, mode **For pull requests only** (une urgence passe par une PR,
     jamais par un push) ;
   - Target branches : **Include default branch** ;
   - Rules :
     - **Restrict deletions** et **Block force pushes** ;
     - **Require a pull request before merging** : 0 approbation requise (un seul mainteneur, et
       l'App ne peut pas approuver sa propre PR), méthode **Squash** ;
     - **Require status checks to pass**, les **cinq** checks, source GitHub Actions (macOS n'en est
       plus depuis CI5 : il ne tourne plus sur une PR, `docs/operations.md`, « La CI, plus rapide ») :
       - `lint + tests (py3.11)` ;
       - `lint + tests (py3.12)` ;
       - `terraform test (mock providers)` (CI4, `docs/operations.md`) ;
       - `image (glorfindel)` ;
       - `image (annatar)`.

   **Le CD de H0 bloque une release sur ces cinq checks**, et sur `publish (glorfindel)`, l'image
   qu'il tire (H1c, #518) : un autre check rouge ou annulé, macOS compris, est dit dans `#deploy`,
   sans retenir H0. L'agent installé tient sa propre copie de la liste (`REQUIRED_CHECKS`, jamais lue
   dans le dépôt) : un check ajouté ou retiré ici demande un `make glorfindel-host-cd-install`, et
   `tests/unit/test_host_cd.py` garde les deux listes égales (`infra/glorfindel-host/README.md`,
   « Le CD de H0 »).

**Vérifier :**
- avec ton identité : `gh api repos/grootcyber/eregion/rulesets` liste les deux règles, et
  `gh api repos/grootcyber/eregion/rulesets/<id>`, pour chacune, montre `bypass_actors` avec le rôle
  admin (`"actor_type": "RepositoryRole"`, et `"actor_id": 5`, l'id habituel du rôle admin : à confirmer à la lecture). `gh api repos/grootcyber/eregion/rules/branches/main`
  donne les règles actives sur `main`, dont les cinq checks ;
- **un essai de la dérogation, depuis le web** : publie une release d'essai (`v0.0.0-sec12-essai`, une
  pré-version, sur `main`), vérifie qu'elle passe, puis supprime-la, avec son tag (la page de la
  release, puis Tags). Le CD de H0 ne la suit pas : une pré-version n'est pas la dernière release ;
- **ce que voit H0, sans jeton** : `curl -s 'https://api.github.com/repos/grootcyber/eregion/rulesets?targets=tag'`,
  puis `curl -s https://api.github.com/repos/grootcyber/eregion/rulesets/<id>`. Le CD lit la règle
  ainsi. GitHub ne dit pas si ces routes répondent sans jeton : c'est l'hypothèse à mesurer. Puis
  `make glorfindel-host-cd-status` dit, à la ligne « règle des tags », « 🔒 … réservé par la règle « tags v* » »
  — lue sans jeton, mesuré le 02/11 —, ou « la règle des tags n'a pas pu être lue » (`cd-check` ne la lit pas
  quand la release tourne déjà) ;
- **depuis une session, après la bascule** :
  - `git tag v0.0.0-sec12 && git push origin v0.0.0-sec12` est refusé (« repository rule violations »),
    puis `git tag -d v0.0.0-sec12` ;
  - `gh release create v0.0.0-sec12 --notes x`, **sans** `--draft`, est refusé : publier crée le tag.
    S'il passait, efface aussitôt la release et son tag (toi, depuis l'interface), puis revois la règle ;
  - `git push origin HEAD:main` est refusé : une PR est requise.
