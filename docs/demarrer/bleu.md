# Observer en lecture seule, en 15 minutes

[← README](../../README.md) · le guide suivant : [le banc complet](banc.md) · ce qui reste à rejouer sur Azure : [a-rejouer.md](a-rejouer.md)

**Pour qui.** Un ingénieur infra ou sécurité qui ne connaît pas Eregion, avec un abonnement Azure, Docker et un terminal.

**Ce que tu obtiens.** Glorfindel branché sur ton espace Log Analytics, avec un principal qui ne peut que lire. Il détecte, enquête et décide sur tes vrais signaux, mais il **retient chaque action** : tu lis dans la console ce qu'il aurait fait. Il ne peut rien changer sur Azure : ni rôle d'écriture, ni API d'écriture appelée (`GLORFINDEL_READ_ONLY=1`). Les journaux, eux, partent chez le fournisseur du modèle : voir [ce qui part de la machine](#7-ce-qui-part-de-la-machine).

**Le chemin : Docker, par `make profile-discover`.** Un seul chemin, celui-ci, pour quatre raisons :
- **une commande** démarre la watch et la console ensemble, comme sur l'hôte de référence (H0, le même `docker-compose.yml`) ;
- **les conteneurs sont durcis** : racine en lecture seule, aucune capacité, et chacun ne reçoit que ses propres secrets (le modèle pour la watch seule) ;
- **les dossiers d'état sont créés à ton nom** avant le démarrage, et le jeton de la console n'apparaît jamais dans les journaux (`make console-url`) ;
- la CLI demande davantage : un venv (`make install`), deux terminaux (la watch et la console), et une autre paire de variables (`AZURE_CLIENT_*`, que seul le venv lit).

Les durées sont celles d'un poste déjà équipé, hors téléchargement de l'image de base.

## 0. Les prérequis (2 min)

- **Sur le poste.**
  - Docker et son greffon compose ;
  - `git`, `make` et `python3` 3.11 ou plus : `make doctor` et le démarrage l'appellent, hors de Docker ;
  - Azure CLI (`az`), connecté : `az login`.
- **Sur Azure.**
  - Le droit de créer un principal de service et de lui attribuer un rôle sur l'abonnement : `Owner` ou `User Access Administrator`.
  - Un espace Log Analytics qui reçoit le `Heartbeat` de tes VM (l'agent Azure Monitor et sa règle de collecte). Glorfindel découvre les VM par ce `Heartbeat` : une VM qui n'y écrit pas reste invisible.
  - Pour les règles livrées : `Syslog` (facilité auth), `Perf` (écritures disque) et, pour l'exfiltration, `StorageBlobLogs`. Sans elles, ces règles ne voient rien. Rien ne casse, mais rien n'est détecté.
- **Un modèle.** Une clé Anthropic (le défaut), ou un modèle local par Ollama pour que rien ne parte : voir l'étape 2.

```bash
git clone https://github.com/grootcyber/eregion && cd eregion
make doctor            # les outils doivent être verts ; le reste se règle aux étapes suivantes
```

`make doctor` ne contacte ni Azure ni le modèle. Il lit la présence de chaque variable, jamais sa valeur. Chaque point rouge dit la commande qui le corrige.

## 1. Le principal Reader (3 min)

Aucun droit d'écriture, nulle part :

```bash
SUB=$(az account show --query id -o tsv)
az ad sp create-for-rbac --name eregion-glorfindel-eval --role Reader --scopes /subscriptions/$SUB
#  → appId, password (affiché une seule fois), tenant
az role assignment create --assignee <appId> --role "Log Analytics Reader" --scope /subscriptions/$SUB
```

## 2. `.envrc` : l'abonnement, le principal, le modèle (3 min)

```bash
cp .envrc.example .envrc
```

Remplis dans `.envrc` (`.envrc` est ignoré par git) :

```bash
export AZURE_SUBSCRIPTION_ID=<az account show --query id -o tsv>
export AZURE_TENANT_ID=<tenant>
export GLORFINDEL_AZURE_CLIENT_ID=<appId>              # la watch
export GLORFINDEL_AZURE_CLIENT_SECRET=<password>
export EREGION_CONSOLE_AZURE_CLIENT_ID=<appId>         # la console : le même principal Reader
export EREGION_CONSOLE_AZURE_CLIENT_SECRET=<password>
export GLORFINDEL_READ_ONLY=1                          # aucune API d'écriture n'est appelée
export ANTHROPIC_API_KEY=<ta clé>                      # le modèle par défaut (eregion_core/models.py)
```

- Ces lignes **remplacent** celles de l'exemple, qui sont actives avec des valeurs factices (`xxxxxxxx-…`, `sk-ant-...`). `make doctor` les reconnaît et les refuse.
- **Pour rester en local**, avec Ollama et un modèle qui sait appeler des outils (`qwen2.5`, `command-r7b` ; le tableau du README) :

  ```bash
  export GLORFINDEL_LLM_MODEL=ollama/qwen2.5
  export GLORFINDEL_LLM_BASE_URL=http://host.docker.internal:11434
  ```

  - Dans le conteneur de la watch, `localhost` est le conteneur lui-même : l'adresse doit être celle de l'hôte vue du conteneur. `host.docker.internal` existe sous Docker Desktop. Sous Linux, mets l'adresse de l'hôte sur le pont docker, et un Ollama qui écoute sur elle. **Non vérifiée** : aucun Ollama n'a été rejoué dans ce guide.
  - Retire alors la ligne `ANTHROPIC_API_KEY`.

Puis charge le fichier dans le terminal : `direnv allow`, ou sans direnv `set -a; . ./.envrc; set +a`. `make profile-discover` refuse de démarrer si `AZURE_SUBSCRIPTION_ID` est vide.

## 3. `glorfindel-config.yaml` : l'espace Log Analytics (2 min)

```bash
cp glorfindel-config.yaml.example glorfindel-config.yaml
az monitor log-analytics workspace show -g <groupe> -n <espace> --query customerId -o tsv
```

Dans `glorfindel-config.yaml` :
- **`monitoring_backends[0].workspace_id`** : ce GUID. Il est lu ici seulement : il n'y a pas de variable `AZURE_WORKSPACE_ID`, et sans lui la watch ne lit aucun journal.
- **`action_backends`** : ton coffre Recovery Services, ou `action_backends: []` si tu n'en as pas. L'exemple nomme un coffre `rsv-annatar` qui n'existe pas chez toi. Glorfindel lit l'état des sauvegardes dans ce coffre : un coffre faux fait des cartes de posture « sauvegarde absente » pour chaque VM (lu dans `glorfindel/posture.py`, non rejoué sur Azure).
- **Le reste** : laisse-le tel quel. Chaque VM est en `human_only` par défaut (`autonomy.default`), et rien n'agit seul.

**Créer le fichier avant de démarrer.** Sans lui, docker crée à sa place un *dossier* `glorfindel-config.yaml` au nom de root : la watch démarre sans espace, et `make doctor` le dit. Pour corriger : `rmdir glorfindel-config.yaml`, puis `cp`.

## 4. Couper la règle bruyante, avant la première semaine (1 min)

`data-exfiltration-blob` se déclenche sur toute écriture de blob depuis une adresse privée (`PutBlobCount >= 1`, RFC 1918) : trop bavarde sur une vraie charge. Coupe-la dans **ta couche de règles**, jamais dans la base livrée (une mise à jour la remplace) :

```bash
mkdir -p ~/.glorfindel
printf 'disable: [data-exfiltration-blob]\n' >> ~/.glorfindel/client_rules.yaml
```

La watch lit les règles à son démarrage. Ce geste se fait donc avant l'étape 5, ou il est suivi de `docker compose restart watch`. Pour vérifier : `docker exec eregion-watch glorfindel rules`, où la règle n'apparaît plus. Les autres règles peuvent rester.

## 5. Vérifier, puis démarrer (3 à 5 min la première fois)

```bash
make doctor            # tout vert : « Tout est prêt. »
make profile-discover  # construit l'image eregion-glorfindel (~1 min 15), démarre la watch et la console
```

La cible finit par l'URL de la console, avec son jeton. Tu la retrouves par `make console-url`.
- La console écoute sur `127.0.0.1:7007` seulement, et demande toujours ce jeton.
- Le port est pris ? `EREGION_CONSOLE_PORT=<port> make profile-discover`, puis `EREGION_CONSOLE_PORT=<port> make console-url`.
- La watch redémarre en boucle ? `make glorfindel-logs` dit pourquoi. Le cas le plus courant : « glorfindel-config.yaml refusé ». La watch ne démarre pas sur une configuration mal écrite, et le message nomme chaque clé fautive. Sans le venv, `make doctor` ne lit le fichier que pour son `workspace_id` ; après `make install`, il le lit comme la watch.

## 6. Ce que tu dois voir, et quand

| Quand | Où | Quoi |
|---|---|---|
| au démarrage | `make glorfindel-logs` | `Autonomy: default = human_only`, `Credentials: read_only`, `Observe-only deployment: detection + recommendations, no writes.` ; l'avertissement `human_only mode active but no alerting configured` est attendu : ici, ton alerte est la console |
| moins d'une minute | les journaux | `discovery: backend <nom> heartbeat → N VM(s)`, refait chaque minute |
| moins d'une minute | la console, page **Glorfindel** | tes VM, chacune en `human_only` ; le badge `OBSERVE-ONLY` |
| quelques minutes | page **Glorfindel** | les premières cartes de **posture** : ce qui empêcherait de défendre une VM (sauvegarde, NSG), avec la commande `az` qui le corrige |
| à la première détection (des heures, des jours, ou jamais) | page **Glorfindel** | une carte par détection : l'action retenue (`mode_hold`), la confiance, les étapes d'enquête ; à juger **✓ Right** / **✗ Wrong** |

Le reste de la console :
- **Overview, Glorfindel et Config** sont actifs.
- **Annatar et Gothmog sont grisés** : rien ne les a lancés.
- **La preuve dit « none yet »** : rien n'a encore éprouvé Glorfindel, c'est le rôle du [banc](banc.md).

Ces textes sont lus dans le code (`glorfindel/cli.py`, `glorfindel/discovery.py`, `eregion_console/static/overview.js`). Les durées des cartes, elles, se vérifient sur Azure : voir [a-rejouer.md](a-rejouer.md).

## 7. Ce qui part de la machine

« Lecture seule sur Azure » ne veut pas dire « rien ne part » :
- **Vers le fournisseur du modèle** (Anthropic par défaut), à chaque décision : les lignes de la détection, avec le nom de la VM, son id de ressource, les adresses, les noms d'utilisateur et de processus tels que les journaux les portent. Partent aussi les résultats de l'enquête, le contexte de l'incident, quelques décisions passées de la mémoire locale (moins de 90 jours) et l'état d'isolation de la VM.
- **Vers ton canal d'alerte**, si tu en poses un (webhook, bot Discord) : chaque carte.
- **Nulle part ailleurs** : la mémoire (ChromaDB) et son modèle d'embedding tournent sur le poste. Le modèle d'embedding est téléchargé une fois dans `~/.cache/chroma`. Eregion n'envoie aucune télémétrie à lui.

Avec Ollama (étape 2), les journaux restent chez toi. Le détail : le [README](../../README.md#evaluate-on-your-infrastructure--read-only-on-azure) et le [modèle de menace](../design/modele-de-menace.md).

## 8. Arrêter, et tout retirer

```bash
make glorfindel-stop                     # arrête la watch et la console (docker compose down)
docker rmi eregion-glorfindel
rm -rf ~/.glorfindel ~/.cache/chroma ~/.eregion runs/   # l'état local : cartes, mémoire, jeton, clé de la watch
az role assignment delete --assignee <appId> --role "Log Analytics Reader" --scope /subscriptions/$SUB
az role assignment delete --assignee <appId> --role Reader --scope /subscriptions/$SUB
az role assignment list --assignee <appId> --all -o table   # vide
az ad sp delete --id <appId> && az ad app delete --id <appId>
```

- **Avant d'effacer `~/.eregion`**, vérifie qu'il ne tient rien d'autre : une instance d'équipe (`~/.eregion/teams/`) y vit aussi.
- **En lecture seule, Glorfindel n'a rien isolé ni bloqué.** Hors lecture seule, `glorfindel list` doit d'abord être vide : voir « Remove Eregion » dans le [README](../../README.md#remove-eregion).
- **La clé du modèle** se révoque chez son fournisseur.

## Et ensuite

- **Juger les cartes** pendant une semaine : [`docs/observation.md`](../observation.md).
- **Donner de l'autonomie à une VM**, une à la fois, une fois ses décisions jugées : le README, « Autonomy model ». Il faut alors un principal qui écrit : [`docs/operations.md`](../operations.md), « Identités Azure ».
- **Savoir si une attaque réelle serait vue** : [le banc complet](banc.md).
