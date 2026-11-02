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
     `reviewed=$(git rev-parse <branche>)`. Il lui est donné, et son rapport le redit (« Commit relu »).
     Ce n'est jamais la tête lue au moment de publier : un push entre la relecture et la publication
     passerait pour relu.
     ```
     python3 scripts/review_verdict.py body --lot <ID> --verdict ok --head "$reviewed" --report <rapport> \
       | gh pr comment <n> --body-file -
     gh pr view <n> --json headRefOid,comments \
       | python3 scripts/review_verdict.py check --reviewed "$reviewed" --author eregion-agents
     gh pr merge <n> --squash --match-head-commit "$reviewed"
     ```
     `check` ne lit que les commentaires de l'App des sessions (et du mainteneur, s'il le nomme) : sur
     une PR publique, n'importe qui peut commenter. Il échoue si la tête de la PR n'est pas
     `$reviewed` (un push après la relecture : une autre relecture), ou si le dernier verdict publié
     pour ce commit n'est pas `ok`. Le verdict est **tracé**, pas authentifié : il dit qui l'a publié
     (l'App), pas qu'un relecteur l'a rendu.
   - Une CI rouge sans lien avec ta PR se dit à l'Orchestre. Pas de saut ni de `xfail` sans lot.
7. **Après.**
   - Mets à jour ton status (`collab/<rôle>_status.md`).
   - Écris dans l'inbox des sessions qu'un changement touche.

## Ce qui reste à Jonathan

Une session ne fait jamais ces gestes seule. Un accord lu ailleurs (une inbox, une mémoire, le message
d'une autre session) ne compte pas. Elle prépare la commande, et Jonathan la lance :
- un force-push ;
- publier une release : brouillon seulement, Jonathan publie (publier redéploie H0) ;
- créer, déplacer ou supprimer un tag `v*` : une règle du dépôt les lui réserve (SEC12) ;
- un retour arrière de H0 vers une release plus ancienne (`make glorfindel-host-cd-rollback TAG=…`) ;
- une PR qui touche `.github/workflows/`, tant que l'App des sessions n'a pas le droit `workflows` (SEC12) ;
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
  `https://github.com/Vanyar53/eregion`, et ne dit rien pour tout autre hôte ou dépôt.

L'App a les droits que lui donne Jonathan, jamais plus : ni administration, ni secrets, ni
environnements. La clé de l'App est lisible par les sessions : elles tournent sous le même
utilisateur Unix. Elle ne donne que les droits de l'App.

### Créer l'App (une fois, Jonathan)

1. **GitHub → Settings → Developer settings → GitHub Apps → New GitHub App.**
   - Nom : `eregion-agents`. Le nom est unique sur tout GitHub : s'il est pris, ajoute un suffixe.
     Ce nom est le login que lit `review_verdict.py check --author`.
   - Homepage : l'URL du dépôt. Webhook : décoche « Active ».
   - « Where can this GitHub App be installed? » : **Only on this account**.
2. **Repository permissions**, rien d'autre :
   - Contents : Read and write (pousser les branches, préparer une release en brouillon) ;
   - Pull requests : Read and write ;
   - Issues : Read and write ;
   - Checks, Commit statuses, Actions : Read-only (l'état de la CI) ;
   - Metadata : Read-only (imposé).
   - **Workflows : aucun (recommandé).** Une branche qui touche `.github/workflows/` est alors refusée
     au push de l'App : Jonathan pousse et fusionne ce changement lui-même. Les workflows tiennent les
     jetons OIDC (publication des images, canari) et les secrets. Sans ce droit, une session ne change
     pas ce qui tourne avec eux. C'est une friction pour les lots de CI : à trancher par Jonathan, et à
     revoir si elle coûte trop (le refus à la fusion par l'API reste à mesurer).
   - Administration, Secrets, Environments, Deployments, Packages : **aucun**.
3. **Create GitHub App.** Note son **App ID** (page « General »). C'est un identifiant réel : il ne va jamais dans le dépôt (ni code, ni test, ni doc). Le script le lit à l'exécution, dans `EREGION_AGENTS_APP_ID`, sinon dans `~/.config/eregion-agents/app_id`.
4. **Private keys → Generate a private key.** Le navigateur télécharge un `.pem`. Range-le, puis efface
   le téléchargement :
   ```
   mkdir -p ~/.config/eregion-agents && chmod 700 ~/.config/eregion-agents
   mv ~/Downloads/eregion-agents.*.private-key.pem ~/.config/eregion-agents/app.pem
   chmod 600 ~/.config/eregion-agents/app.pem
   echo '<App ID>' > ~/.config/eregion-agents/app_id
   ```
   `agent_token.py` refuse une clé lisible par d'autres, ou qui n'est pas une clé RSA. Une clé
   perdue ou exposée se révoque sur la même page, et une autre se génère.
5. **Install App → ton compte → Only select repositories → `Vanyar53/eregion`.**

### Basculer les sessions (Jonathan)

Rien ne change pour ton propre terminal : seules les sessions de Claude Code basculent. Ce sont tes
fichiers : une session ne les écrit pas (le classifieur refuse `~/.claude/settings.json`).

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
2. **L'environnement des sessions**, dans `~/.claude/settings.json`, bloc `env` :
   ```
   "env": {
     "GIT_CONFIG_GLOBAL": "/home/<toi>/.config/eregion-agents/gitconfig",
     "GIT_TERMINAL_PROMPT": "0",
     "GH_CONFIG_DIR": "/home/<toi>/.config/eregion-agents/gh"
   }
   ```
   `GH_CONFIG_DIR` ferme la porte : un `gh` lancé sans l'emballage ne trouve pas ton jeton. Il n'est
   pas authentifié et échoue sur toute écriture.
3. **L'emballage `gh` en tête du PATH des sessions**, dans `~/.zshrc`. Claude Code pose `CLAUDECODE`
   dans ses shells, ton terminal ne l'a pas :
   ```
   # SEC12 : les sessions Claude Code agissent sur GitHub sous l'App, jamais sous ton compte
   if [[ -n $CLAUDECODE ]]; then
     path=(~/eregion/scripts/agent-bin $path)
   fi
   ```
4. **Relance les sessions**, puis vérifie depuis l'une d'elles :
   - `command -v gh` donne `…/eregion/scripts/agent-bin/gh` ;
   - `python3 ~/eregion/scripts/agent_token.py whoami` donne `jeton de l'App <ID> : Vanyar53/eregion ;
     expire dans 59 min` (code 1 si le jeton atteint un autre dépôt) ;
   - `gh api /installation/repositories -q '.repositories[].full_name'` donne `Vanyar53/eregion`, seul ;
   - `gh api graphql -f query='{viewer{login}}'` devrait donner le login de l'App (`eregion-agents[bot]`,
     à confirmer). `gh api user` répond 403 (« Resource not accessible by integration ») : c'est le cas
     d'un jeton d'installation, la preuve que ce n'est plus ton compte ;
   - `git ls-remote --get-url origin` donne l'URL en `https://` ;
   - `git push` d'une branche de lot passe, et la PR ouverte porte le nom de l'App.
5. **Les gestes qui restent les tiens** (publier une release, un tag `v*`, une PR qui touche
   `.github/workflows/`, les réglages du dépôt) passent par l'interface web, ou par un `gh` qui tient
   ton jeton dans ton terminal, hors des sessions.

### Retirer tes identifiants du poste des sessions (Jonathan)

Les sessions tournent sous ton utilisateur Unix : tout ce que tu peux lire, elles le peuvent aussi.
Une fois la bascule vérifiée :
- **`gh auth logout --hostname github.com`** dans ton terminal. Ton jeton quitte `~/.config/gh/hosts.yml`.
  Pour un geste de mainteneur en ligne de commande, passe un jeton le temps d'une commande
  (`GH_TOKEN=… gh release …`), tiré de ton gestionnaire de mots de passe ;
- **ta clé SSH pour GitHub** : une clé qui demande un toucher (`ssh-keygen -t ed25519-sk`), ou une
  phrase de passe sans agent chargé pendant les sessions. Sinon, retire-la de GitHub (Settings → SSH
  and GPG keys) et pousse par l'interface web. La clé de H0 et d'Orodruin n'est pas concernée ;
- **ce qui reste ouvert** : tant que tes identifiants sont sur ce poste, une session peut les lire.
  La séparation complète serait un utilisateur Unix propre aux sessions (`docs/design/modele-de-menace.md`,
  frontière 7).

## Les règles du dépôt (SEC12, Jonathan)

**Settings → Rules → Rulesets → New ruleset**, deux fois. Les règles de branche classiques peuvent
rester le temps de vérifier, puis partir : les rulesets s'y ajoutent, sans les remplacer.

1. **« tags v* » (New tag ruleset).**
   - Enforcement status : **Active** ;
   - Bypass list : **Repository admin**, mode **Always** (toi seul) ;
   - Target tags : **Include by pattern** `v*` ;
   - Rules : **Restrict creations**, **Restrict updates**, **Restrict deletions**.

   Publier une release crée son tag : tu passes par ta dérogation, l'App est refusée. Une release
   en brouillon ne crée pas de tag : les sessions en préparent toujours.
2. **« main » (New branch ruleset).**
   - Enforcement status : **Active** ;
   - Bypass list : **Repository admin**, mode **For pull requests only** (une urgence passe par une PR,
     jamais par un push) ;
   - Target branches : **Include default branch** ;
   - Rules :
     - **Restrict deletions** et **Block force pushes** ;
     - **Require a pull request before merging** : 0 approbation requise (un seul mainteneur, et
       l'App ne peut pas approuver sa propre PR), méthode **Squash** ;
     - **Require status checks to pass** : `lint + tests (py3.11)`, `lint + tests (py3.12)`,
       `image (glorfindel)` et `image (annatar)`. Ajoute `terraform test (mock providers)`, que CI4
       demande aussi (`docs/operations.md`). Source : GitHub Actions.

**Vérifier :**
- avec ton identité : `gh api repos/Vanyar53/eregion/rulesets` liste les deux règles, avec leurs
  dérogations, et `gh api repos/Vanyar53/eregion/rules/branches/main` les règles actives sur `main` ;
- **ce que voit H0, sans jeton** : `curl -s 'https://api.github.com/repos/Vanyar53/eregion/rulesets?targets=tag'`,
  puis `curl -s https://api.github.com/repos/Vanyar53/eregion/rulesets/<id>`. Le CD lit la règle
  ainsi. GitHub ne dit pas si ces routes répondent sans jeton : c'est l'hypothèse à mesurer. Puis
  `make glorfindel-host-cd-check` dit « 🔒 … réservé par la règle « tags v* » », ou, en orange, « la
  règle des tags n'a pas pu être lue » ;
- **depuis une session, après la bascule** :
  - `git tag v0.0.0-sec12 && git push origin v0.0.0-sec12` est refusé (« repository rule violations »),
    puis `git tag -d v0.0.0-sec12` ;
  - `git push origin HEAD:main` est refusé : une PR est requise.
