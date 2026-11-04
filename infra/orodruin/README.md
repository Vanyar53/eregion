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
- **Identité managée** de la VM, sans secret. Trois rôles personnalisés, les seules actions que
  demandent les injecteurs — les listes sont celles d'`eregion_core/orodruin.py`, un test les
  garde identiques : lire le groupe, les VM, les NSG et les expériences, sur `rg-celebrimbor` ;
  démarrer une VM et Run Command, **sur chaque VM inscrite** (tag `eregion-target`) ; démarrer et
  annuler une expérience, sur chaque expérience (SEC5, #182). Jamais d'écriture sur le groupe
  entier : bree, jamais inscrite, reste hors d'atteinte. Plus `Log Analytics Reader` sur l'espace
  de logs du banc. Rien d'autre : le contrat tient une liste de ce que chaque portée peut porter,
  et tout autre droit le rend passif (SEC11, `docs/design/orodruin-contract.md`). Une VM inscrite plus tard : `make orodruin-lock` (son plan relu, puis confirmé) lui donne ses droits.
- **Le compte du canal derrière son pare-feu** (SEC5) : seuls les sous-réseaux d'Orodruin et de
  H0 (points de terminaison de service) et les IP d'Orodruin, de H0 et de l'opérateur y entrent.
  Appliquer `infra/glorfindel-host` d'abord (le point de terminaison de H0), puis ce module.
- **Sortie fermée** hors périmètre : API de contrôle d'Azure, Entra ID, API du modèle
  (`160.79.104.0/23`), DNS et IMDS ; le reste d'Internet refusé. Pas de peering avec le banc :
  Run Command passe par l'API de contrôle.
- **Entrée** : SSH depuis ton IP seulement.
- Pas de tag `eregion-target` : Orodruin n'est pas une cible.
- **Le canal des fenêtres d'exercice** : un conteneur `exercises` (compte `storodruin…`, sans clé
  partagée). Orodruin y écrit, le Glorfindel hébergé le lit (`watch_principal_id`, lu dans l'état
  de `infra/glorfindel-host` ; cet état illisible sur le poste, `orodruin-plan`, `-up` et `-lock`
  refusent : le plan retirerait à la watch l'accès au canal — `NO_WATCH=1` pour un Orodruin sans
  Glorfindel hébergé, SEC7). Dans `orodruin.env` : `EREGION_EXERCISE_CHANNEL` (`terraform output
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
make orodruin-plan                 # relire le plan : il est calculé sortie FERMÉE (egress_locked=true),
                                   # celui du 2e apply, pas celui du 1er
make orodruin-up                   # 1er apply, il OUVRE la sortie (egress_locked=false), le temps que la VM
                                   # installe Docker : son plan est montré, relu, confirmé (jamais YES=1 ici :
                                   # le plan relu au-dessus n'est pas celui qu'il applique)
make orodruin-fingerprint          # l'empreinte de sa clé d'hôte, lue sur la VM par Azure (Run Command) :
                                   # export ORO_SSH_FINGERPRINT=SHA256:… dans ton environnement (V-32)
make orodruin-ssh                  # attendre ~/.orodruin-ready, puis exit
make orodruin-lock                 # 2e apply, il REFERME la sortie : son plan montré, relu, confirmé
cp infra/orodruin/orodruin.env.example infra/orodruin/orodruin.env   # abonnement, plafond
make orodruin-push                 # l'image d'Annatar publiée (CI3) : digest, signature et provenance vérifiés ici, archive tirée des blobs du registre (OI1) | ssh docker load ; + orodruin.env
                                   # REF=<tag|commit> (défaut : le dernier tag v* — tant qu'il est d'avant CI3, il n'a pas d'image
                                   # publiée et la cible échoue : donner REF=<un commit de main d'après CI3>)
                                   # make orodruin-push-dev : construite ici, non vérifiée (développement)
make orodruin-check                # le contrat lu depuis la VM : armed ou passive ; avant lui, l'image en
                                   # service et la dernière release (plus ancienne : un avertissement, OI3)
```

**SSH : la clé d'hôte épinglée (V-32, SEC14).** Chaque commande du poste vers Orodruin
(`orodruin-push`, `-check`, `-ssh`, `-exercise`, `-campaign-*`, `gothmog-*`) passe d'abord par
`orodruin-known` (`infra/glorfindel-host/known_host.sh`, comme H0) : un `known_hosts` dédié,
`ORO_KNOWN_HOSTS` (défaut `~/.eregion/orodruin_known_hosts`, mode 600), écrit à partir de la clé que
présente la VM seulement si elle a l'empreinte `ORO_SSH_FINGERPRINT` ; ssh et scp n'acceptent ensuite
que ce fichier (`StrictHostKeyChecking=yes`, `ssh-ed25519`). **Sans l'empreinte, rien ne part** :
jamais `accept-new` pour ce qui fait agir Orodruin, ni pour y porter `orodruin.env` ou les noms tapés.
L'empreinte se lit par le plan de contrôle d'Azure, jamais par le SSH qu'elle vérifie :
`make orodruin-fingerprint` (ton `az login`, Run Command : `ssh-keygen -lf
/etc/ssh/ssh_host_ed25519_key.pub` sur la VM) affiche la ligne `export` à poser. Une VM reconstruite
a une autre clé : la relire, la poser, retirer `~/.eregion/orodruin_known_hosts`. **À mesurer sur
Azure réel, avec Jonathan** : la sortie de Run Command telle que la cible la lit (écrite et testée
contre une réponse simulée seulement).

**Les conteneurs durcis (V-34, SEC14).** Chaque `docker run` d'un injecteur sur Orodruin tourne comme
le compose : racine en lecture seule, `/tmp` en tmpfs, aucune capacité, aucun gain de privilège
(`ORO_HARDEN`). Il n'écrit que dans son répertoire de `~/runs` (SEC18, N-05) : Annatar dans
`~/runs/annatar`, Gothmog dans `~/runs/gothmog`, l'un et l'autre dans `~/runs/orodruin` (le journal
avant chaque appel, le verrou « un run à la fois », les statuts des demandes) ; le lanceur d'une demande
monte les trois, puisqu'il lance les deux. Aucun ne monte `~/runs` entier : seule la migration de
l'ancienne disposition le fait, une fois, à `make orodruin-push` (`ORO_MIGRATE`, `eregion_core/runs_layout.py`).

Un run se lance ensuite depuis la VM (`make orodruin-ssh`, puis `docker run … annatar run …`) :
le moteur relit le contrat au démarrage, journalise chaque appel dans `~/runs/orodruin/audit.jsonl`
avant de l'exécuter, et s'arrête au plafond déclaré.

Entre les sessions : `make orodruin-stop` (désalloue), `make orodruin-start`.

**À jour au démarrage (OI3, #522).** Après une publication, `make orodruin-start` suffit : une fois
la VM démarrée et qu'elle répond en SSH, il lit l'image en service (docker qui répond, le tag
`eregion-annatar:orodruin` et le commit de son étiquette, `~/.eregion-image`, en lecture seule, par la
clé d'hôte épinglée) et la compare, sur le poste, à la dernière release (le plus haut tag `v*` par
ordre de version, puis par commit dans l'histoire de git). Un marqueur vérifié dont le tag dit un
autre commit est illisible : la release est poussée.

```bash
make orodruin-start                # plus ancienne, absente ou illisible : il le dit, puis make orodruin-push
                                   # REF=<la dernière release> (vérifiée, run de contrôle compris) ;
                                   # égale : rien, en une ligne ; plus récente (un commit de main poussé à
                                   # la main, orodruin-push-dev) : gardée, et la commande pour revenir est dite
make orodruin-start NO_UPDATE=1    # démarrée sans rien lire ni changer
make orodruin-start REF=v0.5.4     # une autre release visée que la dernière
make orodruin-update [REF=…]       # la même mise à jour, la VM déjà démarrée
```

Une erreur (la VM qui ne répond pas en 2 min, docker qui ne répond pas sur Orodruin, la lecture, une
`REF` hors d'`origin/main`, le push, sa vérification, son run de contrôle) : un code non nul, la cause
dite, rien d'armé, et la VM reste démarrée (c'est dit : `make orodruin-stop` pour l'éteindre). `REF`
et `NO_UPDATE` se donnent sur la ligne de commande (`NO_UPDATE=1`, ou rien), validés avant tout,
jamais développés par make ; avant `az vm start` aussi, `ORO_SSH_FINGERPRINT` (sauf `NO_UPDATE=1`) et
`ORO_CHECK_TIMEOUT`. `make -n orodruin-start` montre ses lignes et n'en lance aucune. Rien ne change au réseau
d'Orodruin ni à son contrat : la mise à jour est le même `orodruin-push`, depuis le poste. Le détail :
`docs/design/orodruin-contract.md`, « L'image des injecteurs », « À jour au démarrage ».

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
  posé par `make orodruin-lock`).

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
