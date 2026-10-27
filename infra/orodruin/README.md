# Orodruin — l'hôte d'où les injecteurs agissent (O1)

Celebrimbor forge les cibles, Orodruin ce qui les éprouve : une petite VM, groupe
`rg-orodruin`, d'où Annatar (puis Gothmog) injecte sur le banc. Elle ne s'arme que si son
contrat tient ; sinon les injecteurs restent passifs et ne touchent rien.

Contrat (garanties, vérifications, kill, mutants) :
[`docs/design/orodruin-contract.md`](../../docs/design/orodruin-contract.md). Code :
[`eregion_core/orodruin.py`](../../eregion_core/orodruin.py).

## Ce que ce module pose

- **État Terraform séparé** (ici, local) : un apply ou un down de Celebrimbor ou de Glorfindel
  ne touche jamais Orodruin, et inversement.
- **Identité managée** de la VM, sans secret. Un rôle personnalisé sur `rg-celebrimbor` avec
  les seules actions que demandent les injecteurs (lire les groupes et les VMs, démarrer une
  VM, Run Command, lire les NSG) — la liste est celle d'`eregion_core/orodruin.py`, un test les
  garde identiques — plus `Log Analytics Reader` sur l'espace de logs du banc.
- **Sortie fermée** hors périmètre : API de contrôle d'Azure, Entra ID, API du modèle
  (`160.79.104.0/23`), DNS et IMDS ; le reste d'Internet refusé. Pas de peering avec le banc :
  Run Command passe par l'API de contrôle.
- **Entrée** : SSH depuis ton IP seulement.
- Pas de tag `eregion-target` : Orodruin n'est pas une cible.
- **Le canal des fenêtres d'exercice** : un conteneur `exercises` (compte `storodruin…`, sans clé
  partagée). Orodruin y écrit, le Glorfindel hébergé le lit (`watch_principal_id`, lu dans l'état
  de `infra/glorfindel-host`). Dans `orodruin.env` : `EREGION_EXERCISE_CHANNEL` (`terraform output
  channel_url`) et `EREGION_CHANNEL_SCOPE` (`channel_scope`). Dans le `host.env` de Glorfindel :
  `EREGION_EXERCISE_CHANNEL`. L'opérateur (qui applique ce module) y écrit aussi, pour que
  `orodruin-kill` ferme les fenêtres restées ouvertes (`channel_operator`, M-1).
- **Le canal retour** (#159) : un conteneur `watch` dans le même compte. Le Glorfindel hébergé y
  écrit son battement de cœur et ses détections des VM d'une fenêtre ouverte ou en grâce ;
  Orodruin le lit, et le contrat refuse tout rôle d'écriture d'Orodruin à cette portée. Dans
  `orodruin.env` : `EREGION_WATCH_CHANNEL` (`watch_channel_url`) et `EREGION_WATCH_CHANNEL_SCOPE`
  (`watch_channel_scope`). Dans le `host.env` de Glorfindel : `EREGION_WATCH_CHANNEL`. Canal
  coupé → le run écrit `detection: unknown`, jamais `missed` (`docs/design/orodruin-contract.md`).

## Déroulé (avec Jonathan — c'est lui qui lance les apply)

```bash
# 0. Lecture seule : quota de la famille, SKU, prix → vm_size (repli : D2als_v6)
make orodruin-plan                 # relire le plan
make orodruin-up YES=1             # 1er apply, sortie ouverte : la VM installe Docker
make orodruin-ssh                  # attendre ~/.orodruin-ready, puis exit
make orodruin-lock YES=1           # 2e apply : la sortie se referme (YES=1 : sans confirmation)
cp infra/orodruin/orodruin.env.example infra/orodruin/orodruin.env   # abonnement, plafond
make orodruin-push                 # image d'Annatar (docker save | ssh) + orodruin.env ; dépendances du verrou requirements/annatar.txt (HY1)
make orodruin-check                # le contrat lu depuis la VM : armed ou passive
```

Un run se lance ensuite depuis la VM (`make orodruin-ssh`, puis `docker run … annatar run …`) :
le moteur relit le contrat au démarrage, journalise chaque appel dans `~/runs/orodruin/audit.jsonl`
avant de l'exécuter, et s'arrête au plafond déclaré.

Entre les sessions : `make orodruin-stop` (désalloue), `make orodruin-start`.

**Urgence** : `make orodruin-kill` — depuis ton `az login`, quel que soit son abonnement
courant. Le kill révoque toutes les attributions de rôle de l'identité **sur l'abonnement du
contrat** (`AZURE_SUBSCRIPTION_ID` d'`orodruin.env`). Il annule ensuite les expériences de chaos
en cours sur le banc, désalloue la VM et ferme les fenêtres d'exercice encore ouvertes. Enfin, il
dit ce qui reste en vol : Run Command déjà parti, nettoyage atomic à rejouer, VM qu'une panne
peut laisser arrêtée. Il sort en 1 si une étape a échoué.
- `DRY_RUN=1` montre les commandes.
- `PRINCIPAL=`, `VM_ID=`, `SUBSCRIPTION=`, `CHANNEL=` servent si l'état Terraform ou
  `orodruin.env` est illisible.
- Pour fermer les fenêtres, l'opérateur écrit sur le conteneur `exercises` (`channel_operator`,
  posé par `make orodruin-lock YES=1`).

Le kill retire les droits hors de Terraform : `make orodruin-lock` les repose. Retirer un rôle ne
prend pas effet à l'instant (cache du plan de contrôle) : c'est pour ça que la VM s'arrête aussi.
**Mesuré le 26/10** pendant une `vm-shutdown` : révocation, annulation, fenêtre fermée et tirée par
H0 en 11 s ; gondolin redémarrée par Chaos Studio. Après le réarmement, `orodruin-check` dit
`armed` tout de suite, mais Log Analytics a refusé Gothmog encore quelques minutes :
`make gothmog-preflight` avant de relancer une panne.
Détail : [« L'arrêt d'urgence arrête ce qui tourne »](../../docs/design/orodruin-contract.md).

## À mesurer sur le banc (O1, partie B)

1. ~~L'identité peut-elle lire ses attributions au niveau de l'abonnement avec ses seuls droits
   sur le banc ?~~ **Non, mesuré le 19/10** : Azure ne liste que ce qu'elle peut lire, et le
   premier `armed` était aveugle. `contract_reader` est vrai par défaut (une lecture
   d'attributions, rien d'autre) et le contrat refuse une liste qu'il ne voit pas en entier.
2. ~~La sortie~~ **Mesurée le 19/10** : le hors-périmètre échoue ; l'API de contrôle, Entra ID,
   l'API du modèle et IMDS passent, depuis l'hôte et depuis le conteneur.
3. ~~Le délai entre `orodruin-kill` et le premier refus~~ **Mesuré le 19/10** : premier 403
   moins de 3 s après le début de la révocation, avant l'extinction de la VM (une mesure).
4. ~~Un vrai run~~ **Fait le 19/10** : sortie rouverte exprès → `passive` ; attribution hors du
   banc → `passive` ; refermé → `armed`. T1136.001 sur gondolin : audit écrit 0,6 s avant le
   Run Command, appelant = l'identité d'Orodruin.

Modes suivants : Kubernetes (O2, un namespace par projet), relais.
