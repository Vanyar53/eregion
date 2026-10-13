# Gothmog — pannes déclarées (à venir, 0.3)

Emplacement réservé. Gothmog est le troisième agent de la boucle : Annatar attaque, Gothmog
casse, Glorfindel détecte et répond. Il éprouve d'abord Glorfindel :

- **bruit bénin** (écritures disque, CPU, redémarrages) — Glorfindel ne doit pas isoler (G1) ;
- **pannes de ses dépendances** (modèle, API du cloud, télémétrie, configuration) — il doit
  échouer fermé (G2) ;
- **reprise** (VM détruite puis restaurée) — temps de reprise mesuré (G3).

Premier lot, **G0** : un paquet calqué sur `annatar/` (exécuteur, moteurs, signaux, rapport), le
moteur natif du banc (Azure Chaos Studio, cibles inscrites par Celebrimbor), un signal
`fault_started`, des sondes d'état normal avant, pendant et après ; un arrêt de VM sur le banc,
retour à l'état initial vérifié, run enregistré comme ceux d'Annatar.

Règles : aucune panne en zone `production` (inscription, lot O0) ; exécution depuis Orodruin ;
chaque lot ajoute ses mutants au harnais.

Feuille de route : [`ROADMAP.md`](../ROADMAP.md), « Vers la 1.0 ». Session : [`CLAUDE_GOTHMOG.md`](../CLAUDE_GOTHMOG.md).
