# Glorfindel hébergé (H0)

Une petite VM, dans le groupe `rg-glorfindel`, où Glorfindel tourne en continu, War Room et
bot Discord compris : le `docker compose` de la racine (`watch`, `war-room`, et `bot` par son
profil), sur la même image et le même état. Premier usage : la **pré-observation** sur le banc
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
  La War Room écoute sur `127.0.0.1` de la VM et s'ouvre par un tunnel SSH, jeton en plus.
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
make glorfindel-host-start [REF=…]   # un tag ou un commit (défaut : dernier tag v*), détaché ; construit l'image, lance watch + war-room + bot
make glorfindel-host-tunnel          # affiche l'URL avec son jeton, puis tient le tunnel (Ctrl+C)
make glorfindel-host-url             # l'URL de la War Room avec son jeton, seule
make glorfindel-host-logs            # vérifier « heartbeat → N VM(s) » et l'absence d'erreur d'identité
make glorfindel-host-status          # tout tourne ? VMs, sauvegardes, services, erreurs 24 h, cartes à juger
make glorfindel-host-report          # rapport d'observation (SINCE=4w pour la période)
make glorfindel-host-pull            # copie locale de ~/.glorfindel (verdicts, mémoire) — chaque semaine
make glorfindel-host-down            # détruit la VM et son état (mémoire comprise)
```

Au quotidien : `make glorfindel-host-status` (lecture seule, une vue), puis `make glorfindel-host-tunnel`, l'URL qu'il affiche, puis les boutons **✓ Right** / **✗ Wrong** des cartes de la War Room
(`docs/observation.md`) ; chaque semaine, `make glorfindel-host-report`. Rien à faire sur la
VM elle-même.

Les escalades arrivent dans Discord par le bot, qui tourne sur la VM (un fil par VM, avec
ses boutons) ; le webhook garde les notifications d'action. Un seul bot par
`DISCORD_BOT_TOKEN` : n'en lance pas d'autre en local.

## Ce que la VM exécute (M-3, #183)

- **Une référence nommée, jamais une branche.** `make glorfindel-host-start REF=v0.3.1` (un tag)
  ou `REF=<commit>` (7 à 40 chiffres hexadécimaux) ; sans `REF`, le dernier tag `v*` dans l'ordre
  des versions. `main`, `origin/main`, `HEAD` sont refusés : une branche bouge, et la VM
  exécutait jusque-là ce qui venait d'être fusionné (`git pull` sur `main`). Le script
  (`deploy.sh`, celui du poste, envoyé par ssh) fait `git fetch --tags`, un checkout détaché,
  puis construit l'image avec deux étiquettes, `org.opencontainers.image.version` (la référence)
  et `org.opencontainers.image.revision` (le commit complet). Un fichier suivi modifié sur la VM
  arrête le déploiement (il partirait dans l'image), sauf `glorfindel/rules/`, que les conteneurs
  écrivent (règles approuvées) : gardé, et dit. `make glorfindel-host-status` relit les
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
  Le jeton de la War Room : la War Room seule. L'URL du webhook (elle porte un jeton) : la watch
  et la War Room. Les réglages sans secret (abonnement, modèle affiché, canaux, lecture seule,
  `DISCORD_CHANNEL_ID`) : les trois. Pourquoi pas trois fichiers : compose ne passe à un
  conteneur que sa liste, et trois fichiers sur le même disque, au même propriétaire, ne
  protégeraient rien de plus ; la répartition est tenue par `tests/unit/test_glorfindel_host.py`.
  La watch et la War Room savent que le bot poste les cartes par `DISCORD_CHANNEL_ID` (leur
  webhook se tait), puisqu'elles n'ont plus le jeton.
- **Des boutons qui vérifient qui clique.** `DISCORD_ALLOWED_USERS` (ids d'utilisateurs) et
  `DISCORD_ALLOWED_ROLES` (ids de rôles), séparés par des virgules. Un clic d'un autre est refusé,
  avec un message visible de lui seul, et journalisé (« Button refused: user … »). **Fermé par
  défaut** : sans liste, tous les boutons refusent. Les boutons jugent, acquittent et lancent des
  restaurations, et Discord les montre à quiconque lit le salon : un oubli ne doit pas les
  ouvrir à tout le serveur ; la War Room, derrière son jeton, juge toujours les cartes. Au
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
   (ou `DISCORD_ALLOWED_ROLES=<id du rôle>`). Vérifier que `DISCORD_CHANNEL_ID` y est bien : c'est
   lui, désormais, qui fait taire le webhook de la watch et de la War Room. Rien à retirer : les
   variables ne changent pas de nom, compose les répartit.
3. **Une référence à déployer.** Le dernier tag, `v0.3.0`, est antérieur à M-3 (et à tout ce qui
   a été fusionné depuis) : sans `REF`, c'est lui qui serait déployé. Poser un tag sur le commit de
   fusion (`git tag v0.3.1 <commit> && git push origin v0.3.1`, ou une release), ou passer le
   commit : `REF=<commit de fusion>`.
4. **Le harnais**, puisque l'image prend les versions du verrou (résolution du 26/10, peut-être
   plus récentes que celles de la dernière image de H0) : `make llm-compare MODELS=<modèle en
   service> RUNS=3` (appels payants) ; les décisions doivent rester celles d'avant.
5. **Pousser, puis déployer** :
   ```bash
   make glorfindel-host-push                 # host.env (avec DISCORD_ALLOWED_USERS) → ~/eregion/.env
   make glorfindel-host-start REF=v0.3.1     # ou REF=<commit>
   ```
   La première fois, la VM est sur la branche `main` (clone de cloud-init) : le déploiement la
   passe en checkout détaché. S'il refuse pour « fichiers suivis modifiés », regarder
   (`make glorfindel-host-ssh`, puis `git -C eregion status --short`) avant de toucher quoi que ce
   soit.
6. **Vérifier** : `make glorfindel-host-status` → « ✓ référence déployée : v0.3.1 (…) », les trois
   conteneurs ✓, aucune erreur ; `make glorfindel-host-logs` → le bot dit « Boutons : 1
   utilisateur(s) … » (et non « fermé par défaut ») ; un clic sur ✓ Right d'une carte dans Discord
   passe. Que chaque conteneur n'a que ses secrets, sans en afficher la valeur :
   ```bash
   make glorfindel-host-ssh
   for c in eregion-watch eregion-war-room eregion-bot; do echo "$c: $(docker exec $c env | cut -d= -f1 | grep -E 'KEY|TOKEN|SECRET|WEBHOOK' | sort | tr '\n' ' ')"; done
   ```
   Attendu : la watch, `ANTHROPIC_API_KEY` (et les autres clés de modèle, vides), `AZURE_CLIENT_SECRET`
   (vide), `GLORFINDEL_WEBHOOK_URL` ; la War Room, `GLORFINDEL_WARROOM_TOKEN`, `AZURE_CLIENT_SECRET`,
   `GLORFINDEL_WEBHOOK_URL` ; le bot, `DISCORD_BOT_TOKEN`, `AZURE_CLIENT_SECRET`. Aucune autre.
7. **En cas de problème** : `make glorfindel-host-start REF=<commit déployé avant>` (affiché par
   l'ancien `glorfindel-host-status`, « commit déployé ») revient à l'image d'avant — sans
   étiquette, le statut le dira « inconnue ».

**Disque** : chaque `make glorfindel-host-start` reconstruit l'image ; les couches des anciennes images restaient dans containerd (Docker 29), jusqu'à 87 % d'un disque de 32 Go le 20/10, 25 Go récupérables. Le redéploiement purge maintenant les images orphelines (`docker image prune -f`), et `glorfindel-host-status` affiche l'occupation du disque.

Les verdicts de l'observation et la mémoire ne vivent que sur le disque de la VM : `make glorfindel-host-pull` en garde une copie sur le poste (`~/.eregion/host-backups/`, les 30 dernières), et `make glorfindel-host-status` signale une copie de plus de 7 jours. Une VM éteinte (gondolin entre deux exercices) reste une semaine sur la carte (`GLORFINDEL_DISCOVERY_RETENTION_H=168` dans `host.env`, 8 h par défaut).

La mémoire (ChromaDB) part vide sur la VM : la mémoire locale ne contient que des cycles
d'exercice non marqués (B2), qui n'ont rien à faire dans une observation.

## Changer de modèle

Le modèle qui décide est un réglage du déploiement, jamais de la War Room (qui l'affiche
seulement, avec sa provenance) : changer de modèle, c'est changer qui décide.

1. Le comparer au harnais : `make llm-compare MODELS=anthropic/<actuel>,anthropic/<candidat> RUNS=3`.
2. Le faire tourner de bout en bout sur le banc (T1486 et un autre TTP) avant toute autonomie.
3. `make glorfindel-host-model MODEL=anthropic/<candidat>` — le pose dans `host.env` et sur
   la VM, redémarre Glorfindel, affiche le modèle en service ; Config dans la War Room dit
   « set at deployment (GLORFINDEL_LLM_MODEL) ». `MODEL=default` revient au défaut du code.

Sans la variable, le défaut du code (`eregion_core/models.py`, une seule définition). Depuis
le 19/10, la VM d'observation tourne sur `claude-sonnet-5-5` (issue #139 pour en faire le défaut).

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
