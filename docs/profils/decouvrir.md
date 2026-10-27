# Profil « découvrir » : Glorfindel seul, en observation

[← Les profils](README.md)

**Pour qui.** Une équipe qui veut d'abord être défendue, et voir ce que Glorfindel ferait sur ses vraies charges, avant de lui laisser une seule action. C'est l'entrée d'Eregion : chaque autre profil commence par celui-ci.

**Ce qui tourne.** La watch de Glorfindel (détection, enquête, décision, escalade) et la console d'Eregion. Rien d'autre : aucun injecteur, aucune attaque, aucune panne.

## Installer

```bash
cp .envrc.example .envrc                               # abonnement, principal de service (Reader suffit)
cp glorfindel-config.yaml.example glorfindel-config.yaml   # l'espace Log Analytics : monitoring_backends
direnv allow                                           # ou : set -a; . ./.envrc; set +a
export GLORFINDEL_READ_ONLY=1                          # aucune API d'écriture n'est appelée
make profile-discover                                  # = make glorfindel-start → http://localhost:7007
```

La cible refuse de démarrer si `AZURE_SUBSCRIPTION_ID` est vide : la watch serait aveugle. Pour une démo sans Azure, ajoute `ALLOW_NO_AZURE=1`.

Le pas à pas en lecture seule est dans le [README](../../README.md#evaluate-on-your-infrastructure--read-only-zero-risk) : le principal Reader, l'espace de travail, et la règle bruyante à couper la première semaine.

## Observer

Chaque VM est en mode `human_only` par défaut ([modes d'autonomie](../glorfindel.md)). Glorfindel détecte, enquête et décide, mais il **retient** l'action avant tout appel au cloud. L'escalade porte :
- l'action qu'il aurait prise ;
- sa confiance ;
- les étapes d'enquête.

Avec `GLORFINDEL_READ_ONLY=1` et un principal Reader, rien ne peut écrire, même par erreur.

## Ce que montre la console

- **Overview, Glorfindel et Config** sont actifs.
- **Annatar et Gothmog sont grisés.** Chaque onglet mène à ce que l'injecteur ajouterait.
- **La preuve dit « Proof: none yet »** : rien n'a encore éprouvé Glorfindel. Les cinq indicateurs de la finalité se remplissent avec les cartes jugées.

## Limites

- Une seule souscription par instance. Pour plusieurs équipes ou abonnements, voir [equipes.md](equipes.md).
- Sans injecteur, on ne sait pas encore si une attaque réelle serait vue. C'est le profil suivant, [detection.md](detection.md).
