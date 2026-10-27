# Profil « plusieurs équipes » : un Glorfindel par équipe

[← Les profils](README.md)

**Pour qui.** Plusieurs équipes : chacune a ses abonnements, son salon d'escalade et ses juges. Elles partagent un hôte, mais ne doivent rien mélanger :
- aucune carte d'une équipe chez une autre ;
- aucune isolation décidée avec les identifiants d'une autre ;
- aucune mémoire partagée.

**La réponse d'aujourd'hui : une instance de Glorfindel par équipe.** Chacune a sa watch, sa console sur son port, son bot si elle veut, et son état. Le tout tient dans un dossier :

```
~/.eregion/teams/<équipe>/
  team.env                 ses identifiants et réglages (chmod 600), lus pour elle seule
  glorfindel-config.yaml   ses espaces Log Analytics, ses modes d'autonomie
  runs/                    ses runs et ses signaux
  .glorfindel/             son état : isolations, escalades, incidents, mémoire (ChromaDB)
  .cache/chroma/  .eregion/analysis/
```

## Installer

```bash
make team-init  TEAM=bleue        # crée le dossier, copie team.env.example et la config d'exemple
$EDITOR ~/.eregion/teams/bleue/team.env ~/.eregion/teams/bleue/glorfindel-config.yaml
make team-start TEAM=bleue        # sa watch + sa console → http://localhost:<son port>
make team-start TEAM=bleue BOT=1  # avec son bot Discord (son jeton)
make team-logs  TEAM=bleue
make team-stop  TEAM=bleue
```

**Le nom.** Minuscules, chiffres et tirets. Il nomme le dossier, le projet compose (`eregion-<équipe>`) et les conteneurs (`eregion-<équipe>-watch`, `-war-room`, `-bot`).

**Les refus de `team-start`.**
- **Sans `AZURE_SUBSCRIPTION_ID`**, son Glorfindel serait aveugle. `ALLOW_NO_AZURE=1` permet une démo.
- **Sans `EREGION_CONSOLE_PORT`**, il refuse aussi : un port par équipe. 7007 reste celui de `make glorfindel-start`.
- **Deux équipes au même port** : `team-start` ne le vérifie pas. La seconde échoue au `up` de docker compose, car le port est déjà pris.

**Ce qu'une équipe ne reçoit pas.** `make team-start` lance docker compose sous `env -i`. Ton shell n'atteint donc jamais l'instance d'une équipe : ni ton `.envrc`, ni ton abonnement, ni tes clés. docker compose préfère l'environnement au fichier `--env-file`, alors sans `env -i`, ton abonnement l'emporterait sur le sien. Seuls passent le `PATH` et l'accès à docker (`DOCKER_CONFIG`, `DOCKER_HOST`, `DOCKER_CONTEXT`).

**Ce que chaque conteneur reçoit.** Dans l'instance d'une équipe, chaque conteneur ne reçoit que sa part de `team.env`, comme partout (M-3). `make team-config TEAM=<équipe>` affiche ce que reçoit l'instance, valeurs comprises : ne le colle nulle part.

**Les injecteurs.** Ils restent par banc, depuis l'Orodruin de l'équipe ([detection.md](detection.md), [resilience.md](resilience.md)). Ils lisent le battement de la watch de leur équipe sur son canal retour (`EREGION_WATCH_CHANNEL` dans son `team.env`).

## Ce que montre la console

Chaque équipe a sa console, son jeton (`EREGION_CONSOLE_TOKEN` dans son `team.env`) et ses onglets. Aucune console ne montre deux équipes.

## Limites

- **Un hôte porte autant de watches que d'équipes**, chacune avec sa mémoire. Il n'y a pas de vue commune.
- **La console multi-locataire et la mémoire partagée** sont pour le SaaS (1.x).
- **Une équipe, un abonnement.** Une watch ne surveille qu'un abonnement (`AZURE_SUBSCRIPTION_ID`).
