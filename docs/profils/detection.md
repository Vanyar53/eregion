# Profil « ma détection marche-t-elle ? » : Glorfindel + Annatar

[← Les profils](README.md)

**Pour qui.** Une équipe qui veut savoir si une attaque réelle sur ses charges cloud est vue, en combien de temps, et ce que Glorfindel en fait. Annatar joue des techniques MITRE ATT&CK tirées de bibliothèques publiques, en version épinglée (Atomic Red Team d'abord, R1). Glorfindel détecte, ou il manque l'attaque. Un raté devient une règle proposée : c'est la boucle violette.

**Ce qui tourne.**
- **Glorfindel** : sur ton poste (`make glorfindel-start`) ou hébergé (H0, [`infra/glorfindel-host/`](../../infra/glorfindel-host/README.md)).
- **Annatar** : depuis **Orodruin**, l'hôte jetable des injecteurs ([`infra/orodruin/`](../../infra/orodruin/README.md)). Il n'y agit que si son contrat est `armed`, et seulement sur des cibles inscrites au banc.

## Installer

```bash
make profile-detection        # Glorfindel (watch + console) + l'image d'Annatar
```

`make profile-detection` crée d'abord, à ton nom, `~/.glorfindel`, `~/.cache/chroma` et `~/.annatar`, que les services montent. Lance Annatar **après** elle : sinon docker crée ces dossiers au nom de root.

**Sur ton poste, rien ne touche le cloud.** Le contrat d'Orodruin y est `passive`, et Annatar refuse d'agir. Ce que tu peux faire sans risque :

```bash
docker compose --profile annatar run --rm annatar list
docker compose --profile annatar run --rm annatar validate annatar/scenarios/azure/ransomware-vm.yaml
docker compose --profile annatar run --rm annatar run annatar/scenarios/azure/ransomware-vm.yaml --dry-run
```

**Les vraies attaques partent d'Orodruin.** La procédure est dans [`infra/orodruin/README.md`](../../infra/orodruin/README.md) :

```bash
make orodruin-up && make orodruin-lock && make orodruin-push && make orodruin-check   # armed ?
make orodruin-campaign-plan CAMPAIGN_TARGET=<resource_id de la VM inscrite>
make orodruin-campaign-run CAMPAIGN=<id>
```

## Jamais sans Glorfindel

**Le service compose.** `annatar` dépend de la watch : le lancer la démarre, mais sans attendre son battement. Dans la première minute, le temps que la watch publie son premier battement, Annatar peut refuser d'agir : relance-le un peu plus tard. Il lit ce battement dans `~/.glorfindel`, en lecture seule. Il partage aussi `runs/` avec la watch, et c'est là qu'elle lit l'`attack_started`.

**Depuis Orodruin.** Annatar lit le battement de la watch hébergée sur le canal retour, `EREGION_WATCH_CHANNEL`. Sans battement vivant, il refuse avant tout appel au cloud.

**La dérogation.** `--without-glorfindel` (Make : `WITHOUT_GLORFINDEL=1`) permet un run de développement. Le rapport le dit : « detection not measured, by choice ». Voir [`docs/operations.md`](../operations.md).

**Ses identifiants.** Le service compose reçoit le principal d'Annatar (`ANNATAR_AZURE_CLIENT_ID` et `…_SECRET`), jamais celui de Glorfindel. Il reçoit aussi la clé du modèle, mais seulement pour le planificateur de campagne (`--llm`).

## Ce que montre la console

- **L'onglet Annatar s'active** dès que l'hôte porte un de ses runs : une fenêtre d'exercice, un rapport de run ou une campagne. Chaque run y est lié à ce que Glorfindel en a fait.
- **Gothmog reste grisé.**
- **Le rapport de campagne** (IA0) s'écrit seul sur H0 : [`docs/analysis.md`](../analysis.md).

## Limites

- Les techniques jouées sont celles du catalogue marquées `implemented`.
- En zone `production`, seules les techniques non destructives sont jouées.
- Le plan de contrôle (Activity Logs, Stratus Red Team) vient avec R2.
