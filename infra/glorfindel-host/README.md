# Glorfindel hébergé (H0)

Une petite VM, dans le groupe `rg-glorfindel`, où Glorfindel tourne en continu, la console
d'Eregion (`eregion console`, l'ancienne War Room) et le bot Discord compris : le `docker compose`
de la racine (`watch`, `war-room` — le service de la console, qui garde son nom jusqu'à UI-1d —,
et `bot` par son profil), sur la même image et le même état. Premier usage : la **pré-observation** sur le banc
(`ROADMAP.md`, lot H0 ; `docs/observation.md`) — bree allumée en continu avec une vraie
charge, Glorfindel qui décide, toi qui juges chaque carte.

## Ce que la VM est, et n'est pas

- **Un observateur.** Son identité managée a `Reader` sur le groupe du banc et
  `Log Analytics Reader` sur son workspace, rien d'autre. `GLORFINDEL_READ_ONLY=1` et une
  config forcée en `human_only` au push (`host_config.py`) : elle ne décide jamais seule et
  ne peut rien écrire. Les droits d'écriture viendront avec les exercices de R1 et G0.
- **Pas une cible.** Hors du groupe du banc, sans tag `eregion-target`, sans DCR vers le
  Log Analytics du banc : la découverte (Heartbeat) ne la voit pas, Glorfindel ne peut pas
  l'isoler. Elle n'est pas non plus sur Orodruin (côté rouge).
- **Fermée.** Entrée : SSH depuis ton IP seulement (`operator_cidr`, jamais `0.0.0.0/0`).
  La console écoute sur `127.0.0.1` de la VM et s'ouvre par un tunnel SSH, jeton en plus.
  Alertes : Discord ou webhook, en sortie.
- **Sans secret dans Terraform.** La clé du modèle et les jetons sont dans `host.env`
  (ignoré par git), copié à la main sur la VM. Aucun secret Azure : l'identité managée.

Coût : D2als_v6 (2 vCPU, 4 Go), environ 61 € par mois en continu (API de tarifs Azure, 16/10) — 27 € en B2als_v2 si le quota Basv2 est accordé —, plus
le disque et l'IP publique.

## Déroulé

```bash
make glorfindel-host-plan            # lecture seule ; OPERATOR_CIDR=<ip>/32, sinon ton IP du moment
make glorfindel-host-up              # crée la VM (confirmation demandée) ; cloud-init installe Docker et clone le dépôt
make glorfindel-host-env             # host.env depuis ton .envrc chargé (ou : copier host.env.example et remplir)
make glorfindel-host-push            # host.env → ~/eregion/.env, config locale en human_only
make glorfindel-stop                 # arrête le Glorfindel local : deux watch = cartes en double
make glorfindel-host-start [REF=…]   # un tag ou un commit (défaut : dernier tag v*), détaché ; construit l'image, lance watch + console (war-room) + bot
make glorfindel-host-tunnel          # affiche l'URL de la console avec son jeton, puis tient le tunnel (Ctrl+C)
make glorfindel-host-url             # l'URL de la console avec son jeton, seule
make glorfindel-host-logs            # vérifier « heartbeat → N VM(s) » et l'absence d'erreur d'identité
make glorfindel-host-status          # tout tourne ? VMs, sauvegardes, services, erreurs 24 h, cartes à juger
make glorfindel-host-report          # rapport d'observation (SINCE=4w pour la période)
make glorfindel-host-pull            # copie locale de ~/.glorfindel (verdicts, mémoire) — chaque semaine
make glorfindel-host-down            # détruit la VM et son état (mémoire comprise)
```

Au quotidien : `make glorfindel-host-status` (lecture seule, une vue), puis `make glorfindel-host-tunnel`, l'URL qu'il affiche, puis les boutons **✓ Right** / **✗ Wrong** des cartes de la console (TO JUDGE, page Glorfindel)
(`docs/observation.md`) ; chaque semaine, `make glorfindel-host-report`. Rien à faire sur la
VM elle-même.

Les escalades arrivent dans Discord par le bot, qui tourne sur la VM (un fil par VM, avec
ses boutons) ; le webhook garde les notifications d'action. Un seul bot par
`DISCORD_BOT_TOKEN` : n'en lance pas d'autre en local.

## La console d'Eregion (UI-1, #205)

La War Room est devenue la console d'Eregion : `eregion console` (`docs/design/console.md`). Une
**Vue d'ensemble** (`/` : les cartes à juger, la part d'isolations et de blocages jugés faux, le
dernier run et la dernière campagne de chaque injecteur, les canaux), puis une page par agent :
**Glorfindel** (`/glorfindel`, l'ancienne War Room : TO JUDGE, le fil, la carte de l'infra),
**Annatar** et **Gothmog** (`/annatar`, `/gothmog`, en lecture seule), et **Config** (`/config`).
Glorfindel est toujours là ; un injecteur est actif dès que l'hôte tient un de ses runs (une
fenêtre, un rapport, une campagne) — sur H0, ceux qui viennent d'Orodruin par le canal —, sinon
son onglet est grisé. Les anciennes adresses (`/atelier`, `/api/atelier/*`) redirigent.

- **L'URL** : `make glorfindel-host-tunnel` l'affiche avec son jeton (« Console → http://localhost:7007/?token=… »),
  puis tient le tunnel ; `make glorfindel-host-url` l'affiche seule. Le jeton est posé une fois en
  cookie ; l'URL n'a plus à être rouverte avec lui.
- **Le jeton, sous ses deux noms.** `EREGION_CONSOLE_TOKEN`, ou son ancien nom,
  `GLORFINDEL_WARROOM_TOKEN` : la console prend le nouveau s'il n'est pas vide, sinon l'ancien
  (compose lui passe les deux, vides quand ils manquent). Le `host.env` de H0 n'a que l'ancien :
  **rien à renommer**, il reste valide. Un nouvel hôte (`make glorfindel-host-env`) reçoit le
  nouveau. `make glorfindel-host-url`, `-tunnel` et `-status` suivent la même règle : ils lisent
  le jeton sous l'un ou l'autre nom (`host.env` sur le poste, `~/eregion/.env` sur la VM), comme
  compose lit le fichier (la dernière ligne d'une clé l'emporte ; `# …` après la valeur et un
  blanc est un commentaire — mais `KEY=   # note` vaut « # note », pas une valeur vide, mesuré
  avec `docker compose config`). `glorfindel-host-status` ne l'affiche jamais et ne le met sur
  aucune ligne de commande (curl le lit sur son entrée) ; il dit « jeton refusé » si la console
  le refuse, « aucun jeton » s'il n'y en a pas. `make glorfindel-host-push` vérifie d'abord le
  `host.env` (`host_env.py --check`) : il dit sous quel nom est le jeton, sans sa valeur, et
  refuse un fichier sans jeton (la console tournerait sans) ou dont le jeton est un commentaire.
- **Avant UI-1** : une référence antérieure (`v0.3.0` et avant) ne lit que
  `GLORFINDEL_WARROOM_TOKEN`. Un `host.env` neuf, qui n'a que `EREGION_CONSOLE_TOKEN`, se déploie
  donc avec une référence qui contient UI-1 (`REF=<commit>` ou un tag postérieur) : sinon la War
  Room de l'ancienne image démarrerait sans jeton (sur la boucle locale de la VM, mais sans jeton).
- **Le service compose** garde son nom, `war-room` (conteneur `eregion-war-room`) :
  `glorfindel-host-status` l'affiche « console  eregion-war-room ». Le renommer (`console`) est
  UI-1d, avec Jonathan : l'ancien conteneur garde le port 7007 tant qu'il n'est pas retiré.

### Ce que change le prochain redéploiement de H0

UI-1c ne change que le poste (`Makefile`, `status.sh`, `host_env.py`) : rien à redéployer pour
lui. Si H0 tourne encore une référence d'avant UI-1 (`make glorfindel-host-status` → « référence
déployée »), le prochain `make glorfindel-host-start REF=<tag ou commit avec UI-1>` (avec Jonathan,
`.envrc` chargé) :

- **la watch et le bot ne changent pas** : mêmes commandes (`glorfindel watch`, `glorfindel bot`),
  mêmes variables, même état ;
- **la console redémarre sous `eregion console`**, dans le même conteneur (`eregion-war-room`), sur
  le même port (`127.0.0.1:7007`), avec le même jeton (l'ancien nom suffit) ;
- `host.env` ne change pas (pas de `make glorfindel-host-env` : il tirerait un nouveau jeton) ;
  `make glorfindel-host-push` seulement si autre chose y a changé.

Vérifier : `make glorfindel-host-status` → « ✓ console  eregion-war-room », « à juger : N » (et non
« jeton refusé » ni « pas de réponse ») ; `make glorfindel-host-tunnel`, puis l'URL affichée : la
Vue d'ensemble, l'onglet Glorfindel ; un ancien favori `/atelier` mène à `/`.

## Ce que la VM exécute (M-3, #183)

- **Une référence nommée, jamais une branche.** `make glorfindel-host-start REF=v0.3.1` (un tag)
  ou `REF=<commit>` (7 à 40 chiffres hexadécimaux) ; sans `REF`, le dernier tag `v*` dans l'ordre
  des versions. `main`, `origin/main`, `HEAD` sont refusés : une branche bouge, et la VM
  exécutait jusque-là ce qui venait d'être fusionné (`git pull` sur `main`). `REF` se donne sur
  la ligne de commande : une variable `REF` de l'environnement (un nom générique, exporté pour
  autre chose) est refusée, jamais déployée en silence (`REF=` sur la ligne de commande : le
  dernier tag) ; une `REF` qui commence par `-` aussi (elle serait une option du script). Le script
  (`deploy.sh`, celui du poste, envoyé par ssh) fait `git fetch --tags`, un checkout détaché,
  puis construit l'image avec deux étiquettes, `org.opencontainers.image.version` (la référence)
  et `org.opencontainers.image.revision` (le commit complet). Un fichier suivi modifié sur la VM
  arrête le déploiement (il partirait dans l'image), `glorfindel/rules/` compris depuis P1 : les
  conteneurs ne l'écrivent plus (montage en lecture seule), une règle approuvée va dans la couche
  du client, `~/.glorfindel/client_rules.yaml`, qu'aucun checkout ne touche ; un fichier de règles
  modifié tient des règles approuvées avant P1, à migrer (« Migrer les règles approuvées vers la
  couche du client », plus bas). `make glorfindel-host-status` relit les
  étiquettes sur le conteneur de la watch : « ✓ référence déployée : v0.3.1 (abc…) », ⚠ si le
  checkout a bougé depuis, si la VM est sur une branche, ou si l'image n'a pas d'étiquette (une
  image d'avant M-3). Revenir en arrière : `REF=<le tag précédent>`.
- **Des dépendances verrouillées.** L'image s'installe depuis `requirements/glorfindel.txt`
  (versions et empreintes, `pip --require-hashes`) : une construction ne prend plus la dernière
  version de chaque bibliothèque. Mettre à jour le verrou : `docs/operations.md`, « Verrou des
  dépendances ».
- **Un environnement par conteneur.** `host.env` reste un seul fichier (`~/eregion/.env` sur la
  VM), que docker compose lit pour remplir `docker-compose.yml` ; chaque conteneur ne reçoit que
  les variables de sa liste. La clé du modèle : la watch seule. Le jeton du bot : le bot seul.
  Le jeton de la console : la console seule. L'URL du webhook (elle porte un jeton) : la watch
  et la console. Les réglages sans secret (abonnement, modèle affiché, canaux, lecture seule,
  `DISCORD_CHANNEL_ID`) : les trois. Pourquoi pas trois fichiers : compose ne passe à un
  conteneur que sa liste, et trois fichiers sur le même disque, au même propriétaire, ne
  protégeraient rien de plus ; la répartition est tenue par `tests/unit/test_glorfindel_host.py`.
  La watch et la console n'ont plus le jeton du bot : compose leur dit seulement qu'il est posé
  (`GLORFINDEL_DISCORD_BOT`, « 1 » ou vide, jamais la valeur). Avec lui et `DISCORD_CHANNEL_ID`,
  le bot poste les cartes et leur webhook se tait ; un salon sans jeton, le webhook poste.
- **Des boutons qui vérifient qui clique.** `DISCORD_ALLOWED_USERS` (ids d'utilisateurs) et
  `DISCORD_ALLOWED_ROLES` (ids de rôles), séparés par des virgules. Un clic d'un autre est refusé,
  avec un message visible de lui seul, et journalisé (« Button refused: user … »). **Fermé par
  défaut** : sans liste, tous les boutons refusent. Les boutons jugent, acquittent et lancent des
  restaurations, et Discord les montre à quiconque lit le salon : un oubli ne doit pas les
  ouvrir à tout le serveur ; la console, derrière son jeton, juge toujours les cartes. Au
  démarrage, le bot dit combien d'utilisateurs et de rôles il autorise, ou avertit que tout est
  fermé.

## Redéployer H0 après M-3 (avec Jonathan)

À faire une fois, après la fusion. Pré-observation en cours jusqu'au ~13/11 : rien sans Jonathan,
`.envrc` chargé.

1. **Ton id Discord.** Discord → Paramètres → Avancés → Mode développeur ; puis clic droit sur
   ton nom → « Copier l'identifiant de l'utilisateur ». (Pour un rôle : Paramètres du serveur →
   Rôles → clic droit → « Copier l'identifiant ».)
2. **host.env, sur le poste** (`infra/glorfindel-host/host.env`, pas besoin de le régénérer ni de
   le séparer — le jeton de la War Room ne change pas) : ajouter
   ```
   DISCORD_ALLOWED_USERS=<ton id>
   ```
   (ou `DISCORD_ALLOWED_ROLES=<id du rôle>`). Vérifier que `DISCORD_BOT_TOKEN` et
   `DISCORD_CHANNEL_ID` y sont tous deux : ensemble, ils font taire le webhook de la watch et de
   la War Room (le bot poste les cartes) ; l'un sans l'autre, le webhook poste. Rien à retirer :
   les variables ne changent pas de nom, compose les répartit.
3. **Une référence à déployer.** Le dernier tag, `v0.3.0`, est antérieur à M-3 (et à tout ce qui
   a été fusionné depuis) : sans `REF`, c'est lui qui serait déployé. Poser un tag sur le commit de
   fusion (`git tag v0.3.1 <commit> && git push origin v0.3.1`, ou une release), ou passer le
   commit : `REF=<commit de fusion>`.
4. **Le harnais — obligatoire, avant l'étape 5.** L'image prend désormais les versions du
   verrou (résolution du 26/10), nettement plus récentes que celles des postes et de la CI
   jusqu'ici : anthropic 0.104 → 2.3, fastapi 0.136 → 0.162, langgraph 1.2.1 → 1.2.17 (LiteLLM
   reste 1.86.1) ; celles de l'image qui tourne sur H0 dépendent du jour où elle a été construite
   (`docker exec eregion-watch pip list` sur la VM). Sans le harnais, on ne sait pas si les
   décisions de H0 restent les mêmes : `make llm-compare MODELS=<modèle en service> RUNS=3`
   (appels payants, Jonathan) ; les décisions doivent rester celles d'avant. Sinon, ne pas
   redéployer : ouvrir une PR qui ramène le verrou (`docs/operations.md`, « Verrou des
   dépendances »).
5. **Pousser, puis déployer** :
   ```bash
   make glorfindel-host-push                 # host.env (avec DISCORD_ALLOWED_USERS) → ~/eregion/.env
   make glorfindel-host-start REF=v0.3.1     # ou REF=<commit>
   ```
   La première fois, la VM est sur la branche `main` (clone de cloud-init) : le déploiement la
   passe en checkout détaché. S'il refuse pour « fichiers suivis modifiés », regarder
   (`make glorfindel-host-ssh`, puis `git -C eregion status --short`) avant de toucher quoi que ce
   soit. S'il refuse pour « modifié sur la VM (règles approuvées avant P1) » : « Migrer les
   règles approuvées vers la couche du client », plus bas. Dans les deux cas, rien n'a bougé :
   l'ancienne image tourne toujours.
6. **Vérifier** : `make glorfindel-host-status` → « ✓ référence déployée : v0.3.1 (…) », les trois
   conteneurs ✓, aucune erreur ; `make glorfindel-host-logs` → le bot dit « Boutons : 1
   utilisateur(s) … » (et non « fermé par défaut ») ; un clic sur ✓ Right d'une carte dans Discord
   passe. Que chaque conteneur n'a que ses secrets, sans en afficher la valeur :
   ```bash
   make glorfindel-host-ssh
   for c in eregion-watch eregion-war-room eregion-bot; do echo "$c: $(docker exec $c env | cut -d= -f1 | grep -E 'KEY|TOKEN|SECRET|WEBHOOK' | grep -v '^GPG_KEY$' | sort | tr '\n' ' ')"; done
   ```
   (`GPG_KEY` vient de l'image `python:3.12-slim` : l'empreinte publique de la clé qui signe
   Python, pas un secret ; la commande l'écarte.) Attendu : la watch, `ANTHROPIC_API_KEY` (et les
   autres clés de modèle, vides), `AZURE_CLIENT_SECRET` (vide), `GLORFINDEL_WEBHOOK_URL` ; la War
   Room (la console depuis UI-1), `GLORFINDEL_WARROOM_TOKEN` (et `EREGION_CONSOLE_TOKEN` depuis
   UI-1, l'un des deux vide), `AZURE_CLIENT_SECRET`, `GLORFINDEL_WEBHOOK_URL` ; le bot,
   `DISCORD_BOT_TOKEN`, `AZURE_CLIENT_SECRET`. Aucune autre. La watch et la War Room ont aussi
   `GLORFINDEL_DISCORD_BOT=1` (le jeton du bot est posé, sans sa valeur).
7. **En cas de problème** : `make glorfindel-host-start REF=<commit déployé avant>` (affiché par
   l'ancien `glorfindel-host-status`, « commit déployé ») revient à l'image d'avant — sans
   étiquette, le statut le dira « inconnue ».

### Règles approuvées : la couche du client (P1)

Depuis P1, une règle approuvée (`glorfindel approve-rule`, ou « Approve » dans la console)
s'écrit dans la couche du client, `~/.glorfindel/client_rules.yaml` sur la VM (monté dans les
trois conteneurs), chargée par-dessus la base livrée, `glorfindel/rules/azure/detection_rules.yaml`.
La base est montée en lecture seule : aucun conteneur ne l'écrit plus, et un redéploiement, quelle
que soit la référence, ne touche jamais la couche du client. `docker exec eregion-watch glorfindel
rules` montre chaque règle et sa couche ; au démarrage, la watch dit ce que la couche du client
fait à la base (une règle remplacée, une désactivée). Revenir à une référence d'avant P1 : elle
ne lit pas la couche — les règles du client manquent à la détection (rien n'est perdu, le
fichier reste), jusqu'au retour à une référence avec P1.

### Migrer les règles approuvées vers la couche du client

À faire une fois, avec Jonathan, au premier déploiement d'une référence avec P1. Avant P1, les
règles approuvées s'écrivaient dans `glorfindel/rules/azure/detection_rules.yaml`, un fichier
suivi : `deploy.sh` refuse maintenant un fichier de règles modifié sur la VM (« … modifié sur la
VM (règles approuvées avant P1) : rien n'est déployé »), l'ancienne image tourne toujours.
**Jamais `git checkout -- glorfindel/rules`** (ni `git reset --hard`) : ils effacent les règles
approuvées. La procédure est rejouée telle qu'écrite, sur un dépôt local, par
`tests/unit/test_host_deploy.py::test_the_migration_procedure_of_the_readme_runs_as_written`.

**Les règles approuvées avant P1 étaient inertes ; après la migration, elles détectent — à
surveiller les premiers jours.** Avant P1, une approbation écrivait la règle avec son workspace
en ligne, sans `assets` ni backend (`rule_from_proposal` lisait un champ que `DetectionRule`
n'a pas) : chargée comme « toutes les VM d'aucun backend », elle ne s'appliquait à aucune VM
découverte, sans rien dire. `migrate-rules` lie une telle règle au backend de
`glorfindel-config.yaml` qui surveille son workspace (`assets: [auto]`) : elle tourne alors sur
toutes les VM de ce backend. Une règle approuvée pour une détection manquée peut se révéler
bruyante : regarder ses détections et ses cartes les premiers jours (`make glorfindel-host-logs`,
la console), et la désactiver au besoin (`disable: [<nom>]` dans la couche).

1. **Sur la VM** (`make glorfindel-host-ssh`, puis `cd eregion`) : mettre de côté le fichier
   modifié et la base d'où il vient, dans `~/.glorfindel` (que les conteneurs voient), puis
   rendre le checkout propre (le stash garde une seconde copie) :

   ```bash
   mkdir -p ~/.glorfindel/migration-p1
   cp glorfindel/rules/azure/detection_rules.yaml ~/.glorfindel/migration-p1/approved.yaml
   git show HEAD:glorfindel/rules/azure/detection_rules.yaml > ~/.glorfindel/migration-p1/base.yaml
   git diff --stat -- glorfindel/rules
   git stash push -m regles-approuvees-p1 -- glorfindel/rules
   ```

2. **Depuis le poste** : `make glorfindel-host-start REF=<tag avec P1>`. Il passe ; la watch
   démarre avec la base seule, sans les règles approuvées (quelques minutes, jusqu'à l'étape 3).
3. **Sur la VM** : ce qui part dans la couche (à sec), puis pour de bon, puis redémarrer la watch
   (elle lit les règles au démarrage ; la console les relit à chaque rafraîchissement) :

   ```bash
   docker exec eregion-watch glorfindel migrate-rules --from /root/.glorfindel/migration-p1/approved.yaml --base /root/.glorfindel/migration-p1/base.yaml --dry-run
   docker exec eregion-watch glorfindel migrate-rules --from /root/.glorfindel/migration-p1/approved.yaml --base /root/.glorfindel/migration-p1/base.yaml
   docker compose restart watch
   docker exec eregion-watch glorfindel rules
   ```

   `migrate-rules` met dans la couche ce que `approved.yaml` a de plus que `base.yaml` : une
   règle ajoutée telle quelle ; une règle de base modifiée sur la VM, sous son nom (elle remplace
   celle de la base, et la watch le dit) ; une règle de base supprimée sur la VM, dans `disable`.
   Une règle au workspace en ligne est liée à son backend (« bound … monitoring_backends:
   [<backend>], assets: [auto] ») ; si aucun backend unique de `glorfindel-config.yaml` ne
   surveille son workspace, elle part telle quelle et `migrate-rules` le dit (⚠ : elle reste
   inerte — à lier à la main dans la couche). Un fichier illisible : rien n'est écrit, et c'est dit.
   Relancé, il ne change plus rien. `glorfindel rules` doit montrer chaque règle approuvée avec la
   couche `client` et, en `assets`, `auto (<backend>)` — `auto (aucun backend : inerte)` dit une
   règle restée inerte, avec sous le tableau la note « ne s'applique à aucune VM découverte ».
4. **Une fois vérifié** (la règle dans `glorfindel rules`, la watch sans erreur dans
   `make glorfindel-host-logs`), sur la VM, jeter le stash (le premier de la liste doit être
   `regles-approuvees-p1`) ; la copie reste dans `~/.glorfindel/migration-p1/` :

   ```bash
   git stash list
   git stash drop
   ```

**Disque** : chaque `make glorfindel-host-start` reconstruit l'image ; les couches des anciennes images restaient dans containerd (Docker 29), jusqu'à 87 % d'un disque de 32 Go le 20/10, 25 Go récupérables. Le redéploiement purge maintenant les images orphelines (`docker image prune -f`), et `glorfindel-host-status` affiche l'occupation du disque. Depuis H1, chaque image est aussi étiquetée par sa référence (`eregion-glorfindel:v0.4.0`). Le ménage garde les trois plus récentes, plus celle qui tourne et celle d'avant : revenir à la précédente est un `docker tag`, pas une reconstruction. Le CD ne fait ce ménage qu'une fois la santé verte ; jamais à la bascule, pour que l'image du retour arrière reste.

Les verdicts de l'observation et la mémoire ne vivent que sur le disque de la VM : `make glorfindel-host-pull` en garde une copie sur le poste (`~/.eregion/host-backups/`, les 30 dernières), et `make glorfindel-host-status` signale une copie de plus de 7 jours. Une VM éteinte (gondolin entre deux exercices) reste une semaine sur la carte (`GLORFINDEL_DISCOVERY_RETENTION_H=168` dans `host.env`, 8 h par défaut).

La mémoire (ChromaDB) part vide sur la VM : la mémoire locale ne contient que des cycles
d'exercice non marqués (B2), qui n'ont rien à faire dans une observation.

## Le CD de H0 (H1, #244)

**Publier une release, c'est déployer H0.** Un timer sur la VM la tire toutes les 5 minutes. Il la vérifie, la construit à côté, la préflighte, bascule, et revient en arrière si la santé échoue. H0 reste fermé : il ne fait que sortir, vers l'API publique de GitHub (sans jeton) et vers le webhook de `#deploy`.

**Les sessions ne publient jamais une release** : elles la préparent en brouillon (`gh release create --draft`), et Jonathan clique « Publish ».

### Installer (une fois, Jonathan)

1. **Le webhook de `#deploy`.** Dans Discord, Paramètres du salon → Intégrations → Webhooks (par exemple « H0 »). Mets son URL dans `~/.config/eregion/discord.env` (`EREGION_DISCORD_WEBHOOK_DEPLOY=…`), à côté de `EREGION_DISCORD_MENTION`.
2. **`make glorfindel-host-cd-install`.** La commande :
   - copie l'agent dans `~/.eregion-cd/` sur la VM, avec `deploy.sh`, `notify_discord.py` et `chat_text.py` (l'échappement de SEC6, pour ce que `#deploy` dit d'une règle, H2), jamais dans le checkout qu'il déploie ;
   - y écrit `discord.env` en 600, avec le webhook et la mention seulement, passés par stdin. Le jeton du bot Eregion ne va jamais sur H0 ;
   - installe les unités systemd avec sudo, **timer désactivé**.
3. **`make glorfindel-host-cd-check`, à blanc.** La commande vérifie la dernière release, construit la candidate à côté et passe le préflight, dont **la config de H0 sous la lecture stricte d'A3**. Elle ne bascule pas, et dit le résultat dans le terminal et dans `#deploy`. Si la dernière release tourne déjà (le cas quand H0 a été redéployé à la main sur elle), elle la reconstruit à côté (`check-<tag>`, effacée ensuite) et la préflighte : le vrai Docker de H0 est éprouvé quand même.
4. **Si c'est vert, `make glorfindel-host-cd-enable`.** Le passage suivant déploie.

### Un passage

0. **Un passage interrompu après sa bascule** (redémarrage de la VM, délai de systemd) est repris d'abord. La bascule est inscrite avant d'avoir lieu, et le passage suivant regarde ce qui tourne :
   - la watch est sur la release : la santé, puis la release est gardée ou c'est le retour arrière ;
   - elle est encore sur la version d'avant, ou absente (coupé avant ou pendant le `compose up`) : H0 est remis d'aplomb sur la version d'avant, et la bascule est dite « interrompue », pas malade ; elle est retentée au passage suivant. Interrompue une deuxième fois, elle est refusée, avec ta mention ;
   - elle tourne sur autre chose (redéployé à la main entre-temps) : le CD n'y touche pas.
   `make glorfindel-host-cd-retry` garde une bascule interrompue.
1. **La dernière release**, sur l'API publique (les brouillons et les pré-versions n'y figurent pas). Rien à faire si elle tourne déjà sur les trois conteneurs, ou si elle a déjà échoué ou été refusée. Un tag déjà vu sur un autre commit est refusé : un tag publié ne se réécrit pas.
   Si seule une partie des conteneurs tourne sur la release, `#deploy` le dit une fois.
2. **Vérifier.** Son tag est sur `origin/main`, et jamais plus ancien que ce qui tourne. Tous les check-runs de son commit, sur toutes leurs pages, sont terminés et aucun n'est rouge. Celui de la CI principale (`lint + tests`) doit être parmi eux : absent, le CD l'attend une heure, puis refuse. Si la CI tourne encore, le CD attend le passage suivant et le dit une fois.
3. **Garde du verrou.** Si `requirements/glorfindel.txt` a changé depuis ce qui tourne, `requirements/harness.json` doit porter sur ce verrou (son sha256) et sur le modèle de H0 (celui de `.env`, sinon celui par défaut de la release). Il doit aussi montrer 3 runs, une intégration et un jugement complets, et aucune erreur surconfiante.
4. **La candidate** `eregion-glorfindel:<tag>`, construite dans un worktree à part (`~/.eregion-cd/build`, `deploy.sh --build-only`). L'image qui tourne et le checkout de `~/eregion` ne bougent pas.
5. **Le préflight, dans la candidate :**
   - `glorfindel --version` dit exactement le tag ;
   - la watch, le bot et la console s'importent ;
   - la config que compose monte (`EREGION_CONFIG` du `.env`, sinon `glorfindel-config.yaml`) passe la lecture stricte d'A3 ;
   - `docker compose config` accepte le fichier de la release avec le `.env` de H0.
6. **La bascule** (`deploy.sh --activate`). Avant, l'image qui tourne doit être étiquetée par sa référence, sinon c'est un refus : pas de bascule sans retour possible. `--activate` tolère un `git fetch` en échec, pour que le retour arrière ne dépende pas du réseau. Si un tag désigne un autre commit que celui dont l'image a été construite (tag réécrit), il extrait le commit de l'image et le dit : jamais le compose ou les règles d'un commit avec l'image d'un autre. Si la VM n'a pas ce commit, il refuse. Le checkout est détaché, et refusé si un fichier suivi a été modifié sur la VM. Puis le retag et les trois services relancés.
7. **La santé, pendant 3 minutes :**
   - les trois conteneurs tournent, sans redémarrage, et sur l'image du tag ;
   - `~/.glorfindel/watch_heartbeat` a été réécrit après la bascule ;
   - la console répond (son jeton est lu dans `.env` et ne paraît sur aucune ligne de commande) ;
   - **les règles détectent, et la release n'en a cassé aucune** (H2, #266) : dès que les trois premiers points tiennent, chaque règle que la release charge (la base livrée, la couche du client, les règles approuvées) lance sa requête **une fois**, en lecture seule, sur son backend, dans le conteneur de la watch candidate et avec son identité (Log Analytics Reader) : `docker exec eregion-watch glorfindel rules check --live --json`. Aucun appel au modèle, aucune écriture, aucune action. Elle tient dans ce qui reste de la santé (`EREGION_CD_HEALTH_S`) : au plus `EREGION_CD_RULES_S` (90 s, borné à 1–3600) pour la vérification, `EREGION_CD_RULE_QUERY_S` (20 s, borné à 1–600) par requête, plus `EREGION_CD_RULES_MARGIN_S` (15 s) pour que la commande démarre. Une watch saine seulement au dernier regard lui laisse une seconde. Après la vérification, les conteneurs sont regardés une fois de plus : le dernier regard n'est jamais d'avant elle.
     - **La même vérification, avant la bascule, dans ce qui tourne** (décision de Jonathan, 29/10 : ne revenir en arrière que sur une régression). Elle se place juste avant `deploy.sh --activate`, hors du budget de santé de la candidate : l'ancienne version sert pendant ce temps, et la candidate garde toute sa santé. Elle prend au plus `EREGION_CD_RULES_S` + `EREGION_CD_RULES_MARGIN_S` (105 s par défaut), le plus souvent quelques secondes (le journal dit combien). Son résultat est inscrit avec la bascule : un passage coupé le relit.
     - **Retour arrière seulement sur une régression** : une règle en erreur **durable** dans la candidate — requête invalide, table ou colonne absente, backend non lié (le défaut silencieux corrigé par P1), accès refusé (403), workspace introuvable (404) — qui était ok, ou absente, avant la bascule. Aussi : un chargement refusé, aucune règle chargée, ou une réponse illisible, quand la version d'avant, elle, a pu être vérifiée. Santé rouge tout de suite, **retour arrière**, et `#deploy` le dit avec ta mention : le nom de la règle, le genre d'erreur et son code (`SYN0002`, `SEM0100`, `403`), jamais les mots de l'erreur (le journal les garde), échappés pour Discord (SEC6), cinq règles au plus.
     - **Une règle déjà en erreur avant** (une table absente du workspace — les règles C2 lisent `AuditLogs` et `AADServicePrincipalSignInLogs`, peut-être pas branchées sur H0 —, une règle cassée de la couche du client, un rôle retiré) : la release est gardée, et `#deploy` le dit en orange, avec ta mention.
     - **Une erreur qui peut passer n'est jamais une erreur** : un 429, un 5xx, un 401 ou une identité indisponible (IMDS), le réseau ou le DNS, un résultat partiel, une erreur inconnue, un délai dépassé, une vérification coupée à son budget. La règle est dite « non prouvée », en orange, sans mention ; jamais un retour arrière, jamais un nouvel essai. Le CD ne revient en arrière que pour les genres d'une liste explicite, quoi que dise la commande.
     - **Zéro ligne n'est pas une erreur** : c'est la réponse habituelle d'une règle.
     - **Une version d'avant H2 dans ce qui tourne** (sa CLI n'a pas `glorfindel rules check`) : rien à comparer, aucune règle ne fait revenir en arrière ; « non comparé » dans le message de succès, ou en orange avec ta mention si la candidate a une règle en erreur durable.
     - **Une release d'avant H2** (code 2 de click, et ses mots : « No such command », « No such option ») est gardée, « règles non vérifiées » dans le message de succès. Un autre code 2 (une option refusée) est dit en orange.
     - Le retour arrière ne relance pas les règles : la version d'avant n'a peut-être pas la commande.
     - Les mots complets de chaque erreur (ceux d'Azure, d'A3) vont sur la sortie d'erreur de la commande, que le CD recopie dans son journal (privé, `make glorfindel-host-cd-status`), jamais dans `#deploy`.
   Le message de succès dit combien de règles ont répondu.
8. **Si la santé est verte, le ménage des images** : la nouvelle et celle d'avant restent. **Si elle échoue, retour à ce qui tournait.** Son image est gardée : c'est un retag. Avant de basculer, le CD l'étiquette par sa référence si elle ne l'est pas encore (une image construite avant H1, comme celle de v0.3.1). La release est marquée et n'est plus retentée seule.
9. **`#deploy`.** Le début, le succès et l'attente de la CI sont silencieux. Le refus, le retour arrière, un retour arrière raté, H0 dépareillé et une erreur de l'agent portent ta mention. Le détail d'un refus (les mots d'A3, de compose, d'un build) reste dans le journal, `make glorfindel-host-cd-status`, parce qu'il peut nommer l'infrastructure.

### Au quotidien

- **`make glorfindel-host-cd-status`** : ce qui tourne, la dernière release, les derniers résultats, le journal du jour.
- **Une release refusée ou revenue en arrière** ne se retente pas d'elle-même. Corriger, puis publier une nouvelle release, ou `make glorfindel-host-cd-retry`.
- **Un nouveau verrou.** `make llm-compare MODELS=<modèle de H0> RUNS=3 ATTEST=1` (appels payants, Jonathan) écrit `requirements/harness.json`, à commiter dans la PR du verrou.
- **Un déploiement à la main** (`make glorfindel-host-start REF=…`) reste possible. Il partage le verrou du CD (`~/.eregion-deploy.lock`) et est refusé pendant un passage. Pour mettre le CD en pause : `make glorfindel-host-cd-disable`.
- **L'agent ne se remplace jamais lui-même.** `make glorfindel-host-cd-install` note le commit d'où il l'installe (`~/.eregion-cd/installed-from`). Après un déploiement, si la release est plus récente que ce commit et porte un autre `eregion_cd.py`, `deploy.sh`, `notify_discord.py` ou `chat_text.py`, `#deploy` le dit ; `make glorfindel-host-cd-install`, depuis un checkout à jour, le met à jour. Une release plus ancienne (v0.4.1, d'avant H1) ne dit rien : réinstaller depuis elle casserait le CD (`deploy.sh` sans `--activate`). Une installation de cet agent sans `installed-from` valable (copiée à la main, ou dont le `git rev-parse` a échoué), ou installée hors de main (une branche de lot : le dépôt fusionne en squash, aucune release n'en descendra), le dit une fois dans `#deploy`, sans mention : elle ne saura pas dire quand se mettre à jour. L'agent installé sur H0 avant ce correctif (le code de H1) n'a pas ce filtre : au passage de la 0.4.2, c'est lui qui dira « 🔧 … eregion_cd.py », à juste titre.
- **Les règles, à la main** (après un `make glorfindel-host-push`, une règle approuvée, un doute) : sur la VM, `docker exec eregion-watch glorfindel rules check --live` — chaque règle une fois, en lecture seule, le détail complet de chaque erreur au terminal (`docs/operations.md`).
- **H2 change l'agent** (`eregion_cd.py`, et `chat_text.py` en plus) : la première release qui le porte est déployée par l'agent d'avant, sans la vérification des règles, puis `#deploy` demande `make glorfindel-host-cd-install`. **Avant de le lancer**, la release H2 tourne déjà sur H0 : `docker exec eregion-watch glorfindel rules check --live` (sur la VM, `make glorfindel-host-ssh`) montre les règles déjà en erreur — une table absente du workspace, une règle de la couche du client. Elles ne feront pas revenir H0 en arrière, mais `#deploy` les redira à chaque release : à corriger, ou à désactiver dans la couche du client (`disable:`). Une fois réinstallé, les releases suivantes ont leurs règles vérifiées.
- **Le retirer** : `make glorfindel-host-cd-uninstall` (les unités ; `~/.eregion-cd/` reste).

Reste à mesurer : le premier passage réel — la première release publiée après celle qui tourne sur H0 (redéployé à la main le 28/10). Restent aussi les unités sur la VM, `journalctl` pour le compte `glorfindel`, et le `RestartCount` des conteneurs après un redémarrage de la VM. Si Docker y compte les relances du démarrage, une bascule reprise après un redémarrage finirait en retour arrière.

## Changer de modèle

Le modèle qui décide est un réglage du déploiement, jamais de la console (qui l'affiche
seulement, avec sa provenance) : changer de modèle, c'est changer qui décide.

1. Le comparer au harnais : `make llm-compare MODELS=anthropic/<actuel>,anthropic/<candidat> RUNS=3`.
2. Le faire tourner de bout en bout sur le banc (T1486 et un autre TTP) avant toute autonomie.
3. `make glorfindel-host-model MODEL=anthropic/<candidat>` — le pose dans `host.env` et sur
   la VM, redémarre Glorfindel, affiche le modèle en service ; Config dans la console dit
   « set at deployment (GLORFINDEL_LLM_MODEL) ». `MODEL=default` revient au défaut du code.
   Il dit aussi si l'IA d'analyse raisonne encore avec un autre modèle (IA1 ; le contrôle ne
   fait jamais échouer la cible) : le modèle de Glorfindel est refusé pour les rapports de
   campagne. S'ils se croisent, poser
   `EREGION_ANALYSIS_MODEL=<un autre>` dans `host.env` et dans `~/eregion/.env` sur la VM, puis
   `docker compose up -d watch` (`docs/analysis.md`).

Sans la variable, le défaut du code (`eregion_core/models.py`, une seule définition). Depuis
le 19/10, la VM d'observation tourne sur `claude-sonnet-5-5` (issue #139 pour en faire le défaut).

## SSH : la clé d'hôte épinglée (V-32, SEC7)

Chaque commande du poste vers H0 (`glorfindel-host-push`, `-start`, `-status`, `-tunnel`, `-ssh`,
`-cd-*`…) passe d'abord par `glorfindel-host-known` (`infra/glorfindel-host/known_host.sh`) :

- **avec `HOST_SSH_FINGERPRINT`** (dans ton environnement, jamais dans le dépôt) : un `known_hosts`
  dédié, `HOST_KNOWN_HOSTS` (défaut `~/.eregion/h0_known_hosts`, mode 600), est écrit à partir de la
  clé que présente la VM seulement si elle a cette empreinte ; ssh et scp n'acceptent ensuite que
  ce fichier (`StrictHostKeyChecking=yes`, `ssh-ed25519`). Une clé d'une autre empreinte, présentée
  ou enregistrée, refuse avant que rien ne parte ;
- **sans elle** : `accept-new` reste (la clé acceptée au premier contact, un changement refusé), et
  chaque commande le dit.

Relever l'empreinte **sur la VM** (une session SSH déjà sûre : la console série d'Azure, ou la
première connexion vérifiée autrement), une fois, et la poser dans `.envrc` :

```bash
ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub     # → 256 SHA256:… root@… (ED25519)
export HOST_SSH_FINGERPRINT=SHA256:…                  # la deuxième colonne
```

La VM reconstruite (`glorfindel-host-down` puis `-up`) a une autre clé : relever la nouvelle,
la poser, retirer `~/.eregion/h0_known_hosts`. Le CD de H0 (H1) n'est pas concerné : il tourne
sur la VM et ne se connecte à aucun hôte par SSH. Orodruin garde `accept-new` (`SSH_OPTS`).

## Ce que SEC7 change au prochain déploiement de H0

- **Les conteneurs durcis (V-34)** : `cap_drop: [ALL]`, `no-new-privileges`, la racine en lecture
  seule et `/tmp` en tmpfs, sur la watch, la console et le bot. Le CD n'a rien à faire de plus :
  son préflight relit le compose de la candidate (`docker compose config -q`) avec le `.env` de H0,
  et ses `docker run` de vérification ne passent pas par le compose. À vérifier au premier
  déploiement : `docker compose version` sur la VM (la valeur par défaut imbriquée,
  `${A:-${B:-}}`, est lue par compose v2 ; mesuré en 5.5), puis `make glorfindel-host-status` (les
  trois conteneurs `Up`, aucune erreur) et `make glorfindel-host-logs` sans « Read-only file
  system » ; `docker inspect eregion-watch --format '{{.HostConfig.ReadonlyRootfs}}
  {{.HostConfig.CapDrop}}'` → `true [ALL]`.
- **Les identités (V-17)** : rien. Les variables de chaque service sont vides sur H0 ; ses trois
  conteneurs gardent l'identité managée de la VM, lectrice.

## Mesuré au premier démarrage (16/10)

- **Identité managée** : prise par `DefaultAzureCredential` seulement depuis le correctif de la
  CLI (`_drop_empty_service_principal_env`). Avant, docker compose passait `AZURE_CLIENT_ID=""`,
  qu'azure-identity prend pour une variable définie : `ClientSecretCredential("")` levait et
  la découverte échouait (« client_id should be the id of a Microsoft Entra application »).
- **Droits** : `Reader` + `Log Analytics Reader` suffisent — découverte (bree vue), audit
  complet (NSG, calcul, coffre, détection, règles : « All remediation capabilities confirmed »),
  règles. Seuls rôles de l'identité : ces deux-là.
- **Inscription (H-1, mesuré le 26/10)** : avec ces mêmes droits, l'identité managée lit
  l'inscription du banc (tags `eregion-target`/`eregion-zone`) — gondolin inscrite, bree non,
  donc jamais en exercice. Pour relire ça à la main dans un conteneur, préfixer la commande par
  `env -u AZURE_CLIENT_ID -u AZURE_CLIENT_SECRET -u AZURE_TENANT_ID` : compose passe ces
  variables vides et `DefaultAzureCredential` échoue sinon (la CLI `glorfindel` les retire déjà).
- **Image** : construite en 2 min 44 s sur la VM (1,3 Go), 4 Go de RAM suffisent.
- **Accès** : SSH depuis l'IP de l'opérateur seulement ; War Room injoignable en direct ; par le
  tunnel, 401 sans jeton ou avec un faux, 200 avec le bon.
- **Chaîne complète** : un compte créé puis supprimé sur bree → règle T1136 → décision (confiance
  0,35 : snapshot recommandé, escalade) → carte dans le fil Discord de bree, en ~2 min ; rien
  d'exécuté (`human_only`, lecture seule, aucun snapshot créé).
- **Clé SSH** : celle de `admin_ssh_public_key` ; si ton agent SSH en propose une autre,
  `HOST_SSH_KEY=~/.ssh/<clé>` sur les cibles `glorfindel-host-*`.
- **Taille** : B2s sans capacité en francecentral, aucun quota Basv2 (B2als_v2) sur
  l'abonnement : la VM tourne en D2als_v6 (défaut de `vm_size`, ~61 €/mois) ; B2als_v2 quand le quota sera accordé.

L'état Terraform est local (`infra/glorfindel-host/terraform.tfstate`, ignoré par git),
séparé de celui de Celebrimbor.
