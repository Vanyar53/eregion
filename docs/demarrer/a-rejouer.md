# Ce qui reste à rejouer sur Azure

[← le guide bleu](bleu.md) · [le banc](banc.md)

**Pour Jonathan.** Le guide bleu a été rejoué de zéro le 04/11 (GS1, #520), dans un conteneur jetable : `docker run --rm python:3.12`, un clone de la branche, aucun montage de l'hôte. Le rejeu s'est arrêté là où il faudrait Azure, un modèle payant ou un démon Docker. Voici ce qui reste, dans l'ordre des guides, et ce qu'on doit y voir. Une étape vue telle quelle se coche ici, dans la PR qui la mesure.

## Ce que le rejeu a couvert

Trois rejeux du guide bleu, en utilisateur non root (uid 1000), et un de `make doctor PROFILE=bench` :

- **Le clone, puis `make doctor` avant toute variable.** Huit points rouges, chacun avec sa commande : docker, az, l'abonnement, le tenant, le principal de la watch, `GLORFINDEL_READ_ONLY`, la clé du modèle, la configuration.
- **`.envrc` rempli de valeurs factices**, `glorfindel-config.yaml` avec un espace et `action_backends: []`. `make doctor` est vert sur les variables, le modèle, la configuration, les dossiers et le port. Restent rouges ce que le conteneur n'a pas : az et le démon Docker.
- **Le CLI de Docker et son greffon compose, sans démon.**
  - `docker compose config` rend la watch avec `GLORFINDEL_READ_ONLY=1` et la clé du modèle. La console a la même lecture seule, sans la clé du modèle, et publie le port 7007 seulement.
  - `make profiles-check` est vert.
  - `make -n profile-discover` montre la construction de l'image à l'UID de l'opérateur, les dossiers créés, puis `docker compose up -d`.
- **`make install` en 54 à 58 s.** `make doctor` lit alors la configuration comme la watch la lit.
- **La règle bruyante coupée** dans `~/.glorfindel/client_rules.yaml` : `glorfindel rules` la dit « désactivée par la couche du client ».
- **La console de démonstration**, sans aucune variable d'Azure (`eregion console`).
  - Elle répond en 3 s. Son jeton est tiré dans `~/.eregion/console/token` (mode 600), et `make console-url` le donne.
  - `/` sans jeton répond 401. `/api/state` répond 200, avec `read_only: true` et `autonomy_default: human_only`.
  - `make doctor` voit alors le port pris, par une console lancée hors de docker.
- **Annatar, sans Azure.** `annatar list`, `annatar validate --all` (6 sur 6) et `annatar run … --dry-run` passent. Un `annatar run` sans `--dry-run` sur le poste est refusé avant tout appel : « no live Glorfindel watch ». L'indice renvoie maintenant au guide du banc.
- **`make doctor PROFILE=bench`** sur un clone neuf : les outils du banc, les empreintes et les trois fichiers du banc, chacun avec sa commande ; `PROFILE=prod` est refusé, code 2.

**Les accrocs trouvés, et corrigés.**
- `docker info --format` sort en 0 sans démon : `make doctor` disait « docker répond ». Il exige maintenant une version du serveur (M3629).
- Le bot, que le profil ne lance pas, était dit absent.
- Sur le banc, la configuration se corrigeait par l'exemple, et non par `make celebrimbor-output`.
- Le refus d'un run sur le poste ne disait pas où une attaque part.
- Côté documentation : l'étape rouge du README et le lien cassé de `decouvrir.md` (avant le rejeu).

## Le guide bleu, sur Azure

| Étape | Le geste | Ce qu'on doit voir |
|---|---|---|
| 1 | `az ad sp create-for-rbac … --role Reader`, puis `Log Analytics Reader` | un `appId`, un `password` ; `az role assignment list --assignee <appId> --all` : ces deux rôles seulement |
| 2–3 | `.envrc`, `glorfindel-config.yaml` avec le vrai espace | `make doctor` : « Tout est prêt. », code 0 |
| 5 | `make profile-discover` sur un poste avec Docker | l'image construite (~1 min 15), deux conteneurs `eregion-watch` et `eregion-war-room` ; l'URL de la console à la fin |
| 6 | `make glorfindel-logs` | `Autonomy: default = human_only`, `Credentials: read_only`, `Observe-only deployment` ; puis, en moins d'une minute, `discovery: backend … heartbeat → N VM(s)` |
| 6 | la console, page Glorfindel | les VM de l'espace, chacune en `human_only`, le badge `OBSERVE-ONLY` ; Annatar et Gothmog grisés ; l'accueil dit « PROOF none yet » |
| 6 | quelques minutes plus tard | les cartes de posture : leur nombre, et leurs textes avec `action_backends: []` (le guide ne les a pas vues) |
| 4 | `docker exec eregion-watch glorfindel rules` | `data-exfiltration-blob` désactivée par la couche du client |
| 2 | **Ollama** : `GLORFINDEL_LLM_MODEL=ollama/qwen2.5` et `GLORFINDEL_LLM_BASE_URL` vers l'hôte, depuis le conteneur | une décision rendue ; sous Linux, l'adresse de l'hôte que le conteneur joint (le guide ne l'a pas mesurée) |
| 8 | `make glorfindel-stop`, `docker rmi`, `rm -rf …`, `az ad sp delete` | plus aucun conteneur, plus rien sous `~/.glorfindel`, plus de principal |

## Le guide du banc, sur Azure

Rien de ce guide n'a été rejoué de zéro. Les mesures citées sont celles des sessions de banc.

| Étape | Le geste | Ce qu'on doit voir |
|---|---|---|
| 0 | `make doctor PROFILE=bench` sur un poste neuf | les outils verts ; les fichiers du banc absents, chacun avec sa commande |
| 1 | `make celebrimbor-up`, puis `make celebrimbor-output` | le plan relu, ~5 min ; le fragment copié tel quel dans `glorfindel-config.yaml` est accepté par la watch |
| 2 | les quatre rôles de `infra/identities/` | quatre définitions ; un second abonnement du même tenant refuse le nom (`docs/operations.md`) |
| 3 | `make glorfindel-host-up` | **sa durée** jusqu'à `~/.eregion-host-ready` (jamais notée) ; le dépôt cloné par la redirection de l'ancien nom (`eregion_repo`) |
| 4 | `orodruin-up`, `-fingerprint`, `-lock` | l'empreinte lue par Run Command, puis `orodruin-ssh` accepté ; `orodruin-lock` referme la sortie |
| 5 | `glorfindel-host-env` avec les deux canaux exportés, `-push`, `-start REF=<tag>` | `make glorfindel-host-logs` : `Canal retour : https://…/watch`, `Clé de la watch : SHA256:…` |
| 5 | `make glorfindel-host-watch-key`, la ligne dans `orodruin.env`, `make orodruin-push REF=<tag>`, `make orodruin-check` | `armed` ; `make doctor PROFILE=bench` tout vert |
| 7 | `orodruin-campaign-plan … CAMPAIGN_DECLARED=…bl1-reponse.yaml`, `orodruin-campaign-run` | `executed=1 detected=1` ; la carte de la détection sur H0, l'action retenue (`human_only`) |
| 7 | ~25 min après : `make glorfindel-host-campaign-report CAMPAIGN=<id>` | le rapport ; la page Annatar de la console ; la preuve de T1136.001 datée sur l'accueil |
| 8 | `orodruin-down`, `glorfindel-host-down`, `celebrimbor-down CONFIRM=default`, les rôles supprimés | plus aucun des trois groupes ; `az role definition list --custom-role-only true` sans les rôles d'Eregion |

## Le cas sans H0

Ce n'est pas une étape à rejouer, c'est un trou : une watch du poste ne peut pas écrire le canal retour d'Orodruin ([banc.md](banc.md#le-cas-sans-h0--un-trou)). Un lot à part le codera, puis le mesurera ici.
