@CLAUDE.md

# Session Gothmog — Pannes déclarées

Tu construis Gothmog, le troisième agent : Annatar attaque, Gothmog casse, Glorfindel détecte
et répond. Ses pannes éprouvent d'abord Glorfindel. Lis ce fichier en début de session, puis ton inbox.

**Docs de ton périmètre** (`CLAUDE.md` n'en garde que l'essentiel) : [`docs/architecture.md`](docs/architecture.md) (composants, zones, cycle d'une expérience), [`docs/glorfindel.md`](docs/glorfindel.md) (ce que Glorfindel doit faire face à une panne), [`docs/azure.md`](docs/azure.md).

## Périmètre

**Tu travailles sur :**
- `gothmog/` — paquet calqué sur `annatar/` : exécuteur, moteurs, signaux, rapport
- les expériences de panne (schéma d'expérience E1, `kind: fault`) et les pannes de `technique_catalog.yaml`
- `tests/unit/test_gothmog*.py`

**Tu lis mais ne modifies pas :**
- `annatar/` — modèle à suivre (exécuteur, signaux, rapport)
- le module d'inscription partagé (O0) — toute panne passe par lui
- `infra/terraform/` — Celebrimbor inscrit les cibles auprès de Chaos Studio
- `glorfindel/` — pour savoir ce que Glorfindel doit voir, et comment il doit (ne pas) réagir

**Tu ne touches pas :** `glorfindel/`, `infra/orodruin/`.

## Lots

- **G0 — Gothmog v0, moteur natif du banc (0.3).** Moteur Chaos Studio ; signal `fault_started` ;
  sondes d'état normal avant, pendant et après. Fini quand : un arrêt de VM tourne sur le banc,
  l'état normal est vérifié avant et après, le retour à l'état initial est vérifié, le run est
  enregistré comme ceux d'Annatar.
- **G1 — bruit bénin (0.x).** Écritures disque, CPU, redémarrages ; taux de recommandations
  disruptives fausses publié.
- **G2 — pannes des dépendances (0.x).** Modèle, API du cloud, télémétrie, configuration ;
  chaque panne : échec fermé, test et mutant.
- **G3 — exercice de reprise (0.x).** VM détruite puis restaurée ; temps de reprise dans le README.
- **G4 — moteurs Kubernetes puis générique (1.x).** Chaos Mesh ou LitmusChaos, Chaos Toolkit.
- **X1 — attaque pendant une panne (1.x)**, avec Annatar : détecte ou escalade, jamais à l'aveugle.

## Règles

- **Aucune panne en zone `production`** — refusée par l'inscription (O0). Banc ou jumeau seulement.
- Exécution depuis Orodruin ; rien sur Azure sans Jonathan (Chaos Studio, cibles, identité).
- **Jamais sans Glorfindel (V1, #214)** : `gothmog run` et `preflight` refusent sans battement vivant de la watch (étape 0, avant `arm`, `eregion_core/watch_gate.py`) ; `--without-glorfindel` = run de développement, inscrit au rapport.
- Une panne est déclarée en code, réversible, et son retour à l'état initial est vérifié.
- Chaque lot ajoute ses mutants au harnais avant d'être fusionné.

## Protocole collab

**En début de session :** lis `collab/inbox_gothmog.md`.
**Après chaque changement significatif :** mets à jour `collab/gothmog_status.md`.
**Si une panne demande un comportement de Glorfindel** (échec fermé, retenue) : écris dans
`collab/inbox_glorfindel.md` ce que la panne fait et ce qui est attendu.

Feuille de route : `ROADMAP.md`, « Vers la 1.0 ». Emplacement : `gothmog/README.md`.
