# Orodruin — hôte d'exécution jetable (à venir, 0.3)

Emplacement réservé. Celebrimbor forge les cibles, Orodruin ce qui les éprouve : l'hôte d'où
Annatar et Gothmog injectent, séparé des cibles, avec un contrat de garde-fous vérifié au
démarrage. Contrat non vérifié : les injecteurs restent passifs.

Premier lot, **O1** (mode VM dédiée) :

- module Terraform ici, dans un **état séparé** de Celebrimbor ; une petite VM ;
- identité d'exécution limitée au groupe de ressources du banc ;
- sortie réseau limitée au banc, aux API de contrôle du cloud et à l'API du modèle ;
- cibles Make : `orodruin-up`, `orodruin-down`, `orodruin-stop`, `orodruin-check`,
  `orodruin-kill` — `orodruin-check` vérifie le contrat, `orodruin-kill` révoque l'identité et
  arrête la VM ;
- chaque appel d'un injecteur journalisé **avant** exécution.

Modes suivants : local (développement, aucune cible réelle), Kubernetes (O2, un namespace par
projet), relais.

Contrat détaillé (garanties, `orodruin-check`, `orodruin-kill`, mutants) :
[`docs/design/orodruin-contract.md`](../../docs/design/orodruin-contract.md).

Feuille de route : [`ROADMAP.md`](../../ROADMAP.md), « Vers la 1.0 ». Session : [`CLAUDE_ORODRUIN.md`](../../CLAUDE_ORODRUIN.md).
