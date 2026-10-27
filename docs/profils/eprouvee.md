# Profil « défense éprouvée » : tout

[← Les profils](README.md)

**Pour qui.** Une équipe qui veut la preuve à tout moment : Glorfindel défend, Annatar l'attaque, Gothmog le casse, et les cinq indicateurs de la finalité se lisent sur l'accueil de la console. Le premier indicateur est le temps pour contenir. Le dernier est l'âge de la dernière preuve, qui doit rester sous 30 jours. C'est le profil de H0, la VM de Glorfindel du banc.

**Ce qui tourne.**

| Où | Quoi | Doc |
|---|---|---|
| Une VM à toi (ou ton poste) | Glorfindel : watch, console, bot Discord | [`infra/glorfindel-host/README.md`](../../infra/glorfindel-host/README.md) |
| Orodruin, jetable | Annatar et Gothmog, contrat `armed` | [`infra/orodruin/README.md`](../../infra/orodruin/README.md) |
| Le banc (Celebrimbor), ou un jumeau | les cibles inscrites | [`infra/terraform/`](../../infra/terraform/) |

## Installer

**En local** (Glorfindel sur ton poste) :

```bash
make profile-proven           # Glorfindel + l'image des injecteurs
```

**Hébergé**, comme H0. Une référence se déploie, jamais une branche :

```bash
make glorfindel-host-up && make glorfindel-host-push && make glorfindel-host-start REF=<tag>
```

Puis Orodruin, comme dans [detection.md](detection.md) et [resilience.md](resilience.md).

**Les deux canaux relient les hôtes.**
- **Le canal des fenêtres d'exercice** (`EREGION_EXERCISE_CHANNEL`) va d'Orodruin vers la watch. Il porte les fenêtres d'exercice et les rapports.
- **Le canal retour** (`EREGION_WATCH_CHANNEL`) va de la watch vers Orodruin. Il porte le battement de la watch et ses détections.

## La règle de production

Jamais de panne ni d'action destructive sur une charge réelle :
- **En production :** techniques non destructives sur les VM inscrites, et la chaîne complète sur une VM sentinelle vide.
- **Banc ou jumeau :** le destructif et les pannes.

L'inscription (O0) l'impose avant tout appel.

## Ce que montre la console

- **Tous les onglets sont actifs.**
- **L'accueil** porte les cinq indicateurs, les cartes à juger, le dernier run de chaque injecteur et l'état de la watch.

## Limites

Les profils sont auto-hébergés. Le SaaS viendra en 1.x, avec Glorfindel de base et des packs.
