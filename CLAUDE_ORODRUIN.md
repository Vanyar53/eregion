@CLAUDE.md

# Session Orodruin — Hôte d'exécution jetable

Tu construis Orodruin : l'hôte d'où les injecteurs (Annatar, Gothmog) agissent, séparé des
cibles, avec un contrat de garde-fous vérifié au démarrage. Celebrimbor forge les cibles,
Orodruin ce qui les éprouve. Lis ce fichier en début de session, puis ton inbox.

**Docs de ton périmètre** (`CLAUDE.md` n'en garde que l'essentiel) : [`docs/design/orodruin-contract.md`](docs/design/orodruin-contract.md) (le contrat), [`docs/azure.md`](docs/azure.md), [`docs/architecture.md`](docs/architecture.md) (composants, zones).

## Périmètre

**Tu travailles sur :**
- `infra/orodruin/` — module Terraform d'Orodruin, **état séparé** de Celebrimbor
- `Makefile` — cibles `orodruin-up`, `orodruin-down`, `orodruin-stop`, `orodruin-check`, `orodruin-kill`
- le contrôle du contrat au démarrage (code partagé avec l'inscription d'O0) et ses tests

**Tu lis mais ne modifies pas :**
- `infra/terraform/` — Celebrimbor (groupes du banc, tags d'inscription)
- le module d'inscription partagé (O0) — Orodruin le consomme
- `glorfindel/readiness.py` — modèle du contrat (droits lus sans écrire)

**Tu ne touches pas :** `glorfindel/`, `annatar/` (hors lecture des interfaces).

## Lots

- **O1 — mode VM dédiée (0.3).** Une petite VM ; identité d'exécution limitée au groupe de
  ressources du banc — une identité managée attachée à la VM (décision du 15/10, pas de
  secret ; la révoquer = retirer son attribution de rôle) ; sortie réseau limitée au banc, aux API de contrôle du cloud et à l'API du
  modèle ; contrat non vérifié → injecteurs passifs ; `orodruin-kill` révoque l'identité et arrête
  la VM ; chaque appel d'un injecteur journalisé **avant** exécution. Mutants : contrat non vérifié
  mais mode actif ; journal écrit après l'appel ; arrêt d'urgence qui oublie la révocation.
  Fini quand : le contrat est vérifié au démarrage d'un vrai run ; l'arrêt d'urgence est prouvé
  par un test.
- **O2 — mode Kubernetes (1.x).** Un namespace par projet ; mêmes tests de contrat sur les deux modes.

Le contrat (garantie → vérifiée par) : périmètre réseau → une connexion hors périmètre échoue ;
identité limitée → lecture des droits effectifs ; cibles inscrites → refus sans inscription ;
plafond → configuration effective ; arrêt d'urgence → essai à blanc en CI ; audit → écriture
avant l'appel.

## Règles

- Rien sur Azure sans Jonathan : O1 crée de l'infra réelle (VM, identité, état Terraform).
- Jamais de `terraform apply` sur l'état de Celebrimbor depuis cette session ; jamais de
  `make celebrimbor-down`.
- Règle de production : jamais de panne ni d'action destructive sur une charge réelle ; Orodruin
  n'injecte que sur des cibles inscrites, et la zone de l'inscription décide (O0).
- Chaque lot ajoute ses mutants au harnais avant d'être fusionné.

## Protocole collab

**En début de session :** lis `collab/inbox_orodruin.md`.
**Après chaque changement significatif :** mets à jour `collab/orodruin_status.md`.
**Si le contrat ou l'identité change :** préviens `collab/inbox_annatar.md`, `collab/inbox_gothmog.md`
et `collab/inbox_infra.md`.

Contrat (ce que `orodruin-check` vérifie, `orodruin-kill`, l'audit avant appel, les 3 mutants) :
`docs/design/orodruin-contract.md` — **lis-le avant de commencer O1**.

Feuille de route : `ROADMAP.md`, « Vers la 1.0 ». Emplacement : `infra/orodruin/README.md`.
