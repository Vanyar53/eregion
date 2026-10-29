# Les profils d'usage

Lot D1 (#81). Eregion est auto-hébergé : il tourne sur ton poste, ou dans une VM à toi.

**Glorfindel est toujours présent.** C'est le produit, décision du 26/10 ([`docs/design/console.md`](../design/console.md), §2). Un profil est une combinaison : Glorfindel seul, puis ce qu'on lui ajoute. Annatar et Gothmog ne tournent jamais sans lui (V1, #214) : avant d'agir, ils lisent le battement de sa watch, et refusent s'il n'y en a pas.

| Profil | Pour qui, quelle question | Ce qui tourne | Commencer | Page |
|---|---|---|---|---|
| Découvrir | être défendu d'abord, en observation | Glorfindel (watch + console) | `make profile-discover` | [decouvrir.md](decouvrir.md) |
| Ma détection marche-t-elle ? | savoir si une attaque réelle est vue | + Annatar | `make profile-detection` | [detection.md](detection.md) |
| Mon infra tient-elle ? | savoir si une panne est bien vécue, par l'infra et par Glorfindel | + Gothmog | `make profile-resilience` | [resilience.md](resilience.md) |
| Défense éprouvée | prouver la défense, en continu (comme H0) | tout | `make profile-proven` | [eprouvee.md](eprouvee.md) |
| Plusieurs équipes | une défense par équipe, sans rien mélanger | un Glorfindel par équipe | `make team-start TEAM=<nom>` | [equipes.md](equipes.md) |

## Ce que chaque profil installe

- **Docker compose.** Glorfindel démarre sans profil : la watch et la console (`docker compose up -d`). Les profils compose ajoutent les autres services :
  - `bot` : le bot Discord ;
  - `annatar` et `gothmog` : les injecteurs. Ils sont lancés à la demande, par `docker compose --profile annatar run --rm annatar …`, et ne restent pas en service.

  Lance un injecteur **après `make profile-…`**. La cible crée d'abord, à ton nom, les dossiers que les services montent : `~/.glorfindel`, `~/.cache/chroma`, et `~/.annatar` pour Annatar. Sans elle, docker les crée au nom de root, et ta CLI ne peut plus y écrire.

  Chaque injecteur dépend de la watch (`depends_on`). Le lancer démarre donc Glorfindel, s'il ne tourne pas encore, mais n'attend pas son battement. Dans la première minute, le temps que la watch démarre et publie son premier battement, l'injecteur peut refuser d'agir (V1) : relance-le un peu plus tard. Le battement porte le périmètre de la watch (un condensé de son abonnement, SEC5) : l'injecteur refuse aussi une watch vivante d'un autre abonnement, et relit le garde avant chaque action d'un run, `annatar clean` compris.
- **Cibles Make.** Il y en a une par profil, listées dans `make help`, section « Profils d'usage ». Chacune démarre Glorfindel (`glorfindel-start`), puis prépare ce que le profil ajoute.
- **Une page par profil** : pour qui, ce qui tourne et où, comment l'installer, ce que la console en montre, les limites.

## Où agissent les injecteurs

Un injecteur n'agit que depuis un **Orodruin armé** ([contrat](../design/orodruin-contract.md)). Sur ton poste, son contrat est `passive` : il ne touche à rien. Ce qu'il peut y faire sans risque :
- valider un scénario ;
- lister les scénarios ;
- un `--dry-run` ;
- `gothmog preflight`, qui donne le verdict sans rien écrire.

Les vraies attaques et les vraies pannes partent d'Orodruin, sur des cibles inscrites au banc. En zone `production`, seules les techniques non destructives sont permises, et aucune panne.

## Chaque composant tourne seul

« Chaque composant tourne seul » est une **séparation technique** : un adaptateur se développe et se teste à part. Ce n'est pas un produit vendu seul.

La CI le prouve ([`components.yml`](../../.github/workflows/components.yml)). Glorfindel, Annatar, Gothmog et le cœur partagé (`eregion_core/`) passent chacun ses tests avec les autres composants **absents** de l'interpréteur. Pour un injecteur, les dépendances de Glorfindel sont absentes aussi : LangGraph, ChromaDB, le bot, la console.

```bash
make components-check                     # les quatre ; COMPONENT=annatar pour un seul
python scripts/component_check.py --list  # chaque fichier de test, et son composant
make profiles-check                       # chaque profil compose rend ses services (docker, rien ne démarre)
```

Deux choses sont permises entre composants : le contrat que tous lisent, qui vit dans le cœur (les signaux, `eregion_core/signals.py`, sortis d'Annatar par D1), et les passerelles listées avec leur raison (`scripts/component_check.py`, `BRIDGES` et `CROSSINGS`). [`tests/unit/test_components.py`](../../tests/unit/test_components.py) refuse toute autre importation d'un composant par un autre.

L'IA d'analyse (`analysis/`) n'est pas un composant testé seul, mais la watch la charge (IA0) : son code est lu par la même règle. Le rapport de campagne lit les détections d'un run avec le lecteur d'Annatar (`annatar.runner.detection`), dès son chargement : c'est une passerelle listée. Sur un Glorfindel installé sans Annatar, la watch importe ce rapport avant de lancer le thread des rapports : elle démarre donc sans eux, et le dit une fois au démarrage (« Rapports de campagne désactivés »).

Pour contribuer un adaptateur, voir [`CONTRIBUTING.md`](../../CONTRIBUTING.md).
