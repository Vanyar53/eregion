# Profil « découvrir » : Glorfindel seul, en observation

[← Les profils](README.md)

**Pour qui.** Une équipe qui veut d'abord être défendue, et voir ce que Glorfindel ferait sur ses vraies charges, avant de lui laisser une seule action. C'est l'entrée d'Eregion : chaque autre profil commence par celui-ci.

**Ce qui tourne.** La watch de Glorfindel (détection, enquête, décision, escalade) et la console d'Eregion. Rien d'autre : aucun injecteur, aucune attaque, aucune panne.

## Installer

Le pas à pas, rejoué de zéro, est le guide [« Observer en lecture seule en 15 minutes »](../demarrer/bleu.md) : le principal Reader, `.envrc` avec la clé du modèle (ou Ollama), l'espace de travail, la règle bruyante à couper la première semaine, et `make doctor` avant de démarrer. En bref :

```bash
cp .envrc.example .envrc                               # abonnement, principal de service (Reader suffit), clé du modèle
cp glorfindel-config.yaml.example glorfindel-config.yaml   # l'espace Log Analytics : monitoring_backends
direnv allow                                           # ou : set -a; . ./.envrc; set +a
export GLORFINDEL_READ_ONLY=1                          # aucune API d'écriture n'est appelée
make doctor                                            # les prérequis, sans appeler ni Azure ni le modèle
make profile-discover                                  # = make glorfindel-start → http://localhost:7007
```

- **La clé du modèle** : `ANTHROPIC_API_KEY` pour le modèle par défaut, ou `GLORFINDEL_LLM_MODEL=ollama/<modèle>` et `GLORFINDEL_LLM_BASE_URL` pour que les journaux restent chez toi.
- **Sans `AZURE_SUBSCRIPTION_ID`**, la cible refuse de démarrer : la watch serait aveugle. Pour une démo sans Azure, ajoute `ALLOW_NO_AZURE=1`.
- **Ce qui part de la machine** : le [README](../../README.md#evaluate-on-your-infrastructure--read-only-on-azure).

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
