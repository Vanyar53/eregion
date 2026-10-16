# Glorfindel hébergé (H0)

Une petite VM où Glorfindel tourne en continu, War Room comprise : le `docker compose` de la
racine (`watch` + `war-room`), sur la même image et le même état. Premier usage : la
**pré-observation** sur le banc (`ROADMAP.md`, lot H0 ; `docs/observation.md`) — gondolin
allumée en continu avec une vraie charge, Glorfindel qui décide, toi qui juges chaque carte.

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

Coût : B2s, environ 31 € par mois en continu (API de tarifs Azure, westeurope, 16/10), plus
le disque et l'IP publique.

## Déroulé

```bash
make glorfindel-host-plan            # lecture seule ; OPERATOR_CIDR=<ip>/32, sinon ton IP du moment
make glorfindel-host-up              # crée la VM (confirmation demandée) ; cloud-init installe Docker et clone le dépôt
cp infra/glorfindel-host/host.env.example infra/glorfindel-host/host.env   # remplir
make glorfindel-host-push            # host.env → ~/eregion/.env, config locale en human_only
make glorfindel-stop                 # arrête le Glorfindel local : deux watch = cartes en double
make glorfindel-host-start           # git pull, construit l'image, lance watch + war-room
make glorfindel-host-tunnel          # puis http://localhost:7007/?token=<GLORFINDEL_WARROOM_TOKEN>
make glorfindel-host-logs            # vérifier « heartbeat → N VM(s) » et l'absence d'erreur d'identité
make glorfindel-host-down            # détruit la VM et son état (mémoire comprise)
```

La mémoire (ChromaDB) part vide sur la VM : la mémoire locale ne contient que des cycles
d'exercice non marqués (B2), qui n'ont rien à faire dans une observation.

## À mesurer au premier démarrage

Rien de ceci n'est encore constaté (lecture de code et de doc = hypothèse) :

- `DefaultAzureCredential` prend bien l'identité managée quand `AZURE_CLIENT_ID` est vide ;
- `Reader` + `Log Analytics Reader` au niveau du groupe du banc suffisent à la découverte, à
  l'audit (NSG, sauvegarde, calcul) et aux règles ;
- la construction de l'image tient dans les 4 Go d'une B2s.

L'état Terraform est local (`infra/glorfindel-host/terraform.tfstate`, ignoré par git),
séparé de celui de Celebrimbor.
