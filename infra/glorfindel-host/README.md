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
make glorfindel-host-start           # git pull, construit l'image, lance watch + war-room
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

Les verdicts de l'observation et la mémoire ne vivent que sur le disque de la VM : `make glorfindel-host-pull` en garde une copie sur le poste (`~/.eregion/host-backups/`, les 30 dernières), et `make glorfindel-host-status` signale une copie de plus de 7 jours. Une VM éteinte (gondolin entre deux exercices) reste une semaine sur la carte (`GLORFINDEL_DISCOVERY_RETENTION_H=168` dans `host.env`, 8 h par défaut).

La mémoire (ChromaDB) part vide sur la VM : la mémoire locale ne contient que des cycles
d'exercice non marqués (B2), qui n'ont rien à faire dans une observation.

## Mesuré au premier démarrage (16/10)

- **Identité managée** : prise par `DefaultAzureCredential` seulement depuis le correctif de la
  CLI (`_drop_empty_service_principal_env`). Avant, docker compose passait `AZURE_CLIENT_ID=""`,
  qu'azure-identity prend pour une variable définie : `ClientSecretCredential("")` levait et
  la découverte échouait (« client_id should be the id of a Microsoft Entra application »).
- **Droits** : `Reader` + `Log Analytics Reader` suffisent — découverte (bree vue), audit
  complet (NSG, calcul, coffre, détection, règles : « All remediation capabilities confirmed »),
  règles. Seuls rôles de l'identité : ces deux-là.
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
