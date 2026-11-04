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
  et tout autre droit le rend passif (SEC11, `docs/design/orodruin-contract.md`). Une VM inscrite plus tard : `make orodruin-lock YES=1` lui donne ses droits.
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
- **Qui écrit le canal retour** (WC1, #523) : par défaut la watch de H0 seule, comme avant. Sans H0,
  la watch d'un poste ou d'une équipe : `WATCH_PRINCIPALS=<id>[,<id>…]` (la variable
  `watch_principal_ids`), voir ci-dessous.

## Sans H0 : la watch d'un poste ou d'une équipe (WC1)

Une watch qui tourne sur ton poste (`make glorfindel-start`, `make profile-discover`) ou pour une
équipe (`make team-start`) publie son battement signé et ses détections sur le canal retour par le
même chemin que H0 (`eregion_core/watch_channel.py`), sous **son** principal de service
(`GLORFINDEL_AZURE_CLIENT_*`, jamais `ANNATAR_AZURE_CLIENT_*`). Il lui faut deux droits, et rien
d'autre : lire `exercises` (les fenêtres) et écrire `watch`.

- **L'identité** : l'*object id* du principal de service de la watch (l'application d'entreprise),
  pas son *client id* : `az ad sp show --id <GLORFINDEL_AZURE_CLIENT_ID> --query id -o tsv`. C'est
  toi qui la nommes : Terraform ne connaît pas l'identité d'Annatar, il donne le droit à celle que
  tu lui donnes. Le plan refuse seulement l'identité d'Orodruin et la tienne (celle qui applique).
- **Le plan** : `make orodruin-plan WATCH_PRINCIPALS=<object id> NO_WATCH=1`. `NO_WATCH=1` dit
  qu'il n'y a pas de Glorfindel hébergé (SEC7). Avec H0, sa watch ne garde le canal que si son
  identité est dans la liste (`terraform -chdir=infra/glorfindel-host output principal_id`) ;
  sinon le Makefile refuse, sauf `NO_WATCH=1`.
- **Chaque apply redonne la liste** : à chaque `orodruin-up` et `orodruin-lock` (une VM inscrite
  plus tard, la sortie refermée), la même `WATCH_PRINCIPALS`, et `NO_WATCH=1` sans H0. Sans elles,
  le plan retire ses droits à la watch du poste.
- **Ce que le Makefile vérifie** : `WATCH_PRINCIPALS` se donne sur la ligne de commande (jamais de
  l'environnement), des GUID séparés par des virgules, sans espace, aucun deux fois ; jamais
  développée par make. Le plan refuse aussi ce qui n'est pas un GUID, une identité nommée deux fois,
  et l'identité d'Orodruin (un injecteur n'écrit jamais ce que dit la watch).
- **Le réseau** : le pare-feu du compte admet déjà l'IP de l'opérateur (l'arrêt d'urgence). Une
  watch sur ton poste passe par là ; ton IP a changé depuis le dernier apply, elle n'atteint plus le
  canal, et les runs sont refusés (aucun battement frais). Une watch sur un autre hôte n'y entre pas.
- **Sur le poste de la watch** : `EREGION_WATCH_CHANNEL` (`terraform output watch_channel_url`) et
  `EREGION_EXERCISE_CHANNEL` (`channel_url`) dans ton environnement, ou dans le `team.env` de
  l'équipe.
- **Sur Orodruin** : la clé de cette watch épinglée dans `orodruin.env`, `EREGION_WATCH_KEY`
  (`make watch-key` sur son poste), puis `make orodruin-push`. Un battement d'une autre clé, celui
  de H0 compris, reste refusé (SEC19).
- **Une watch à la fois** : le battement est un seul blob (`heartbeat.json`). Deux watches qui
  publient en même temps l'écrasent tour à tour, et la garde refuse celle dont la clé n'est pas
  épinglée. Plusieurs identités servent à passer de l'une à l'autre, pas à les faire tourner ensemble.
- **Les détections ne sont pas encore signées** : chaque identité listée, même une watch dont la clé
  n'est pas épinglée, peut fausser le verdict d'un run, `detected` comme `missed`. C'est la mesure
  qui est touchée, jamais une action : un injecteur n'agit que sur le battement signé. Les signer :
  SEC21.

Tests : `infra/orodruin/tests/watch_writers.tftest.hcl` (`terraform test`, fournisseur mocké),
`tests/unit/test_makefile_bench.py`, `tests/unit/test_watch_key.py`. Mesure au banc : un run depuis
Orodruin, la watch sur le poste, à faire avec Jonathan.

## Déroulé (avec Jonathan — c'est lui qui lance les apply)

```bash
# 0. Lecture seule : quota de la famille, SKU, prix → vm_size (repli : D2als_v6)
make orodruin-plan                 # relire le plan
make orodruin-up YES=1             # 1er apply, sortie ouverte : la VM installe Docker
make orodruin-fingerprint          # l'empreinte de sa clé d'hôte, lue sur la VM par Azure (Run Command) :
                                   # export ORO_SSH_FINGERPRINT=SHA256:… dans ton environnement (V-32)
make orodruin-ssh                  # attendre ~/.orodruin-ready, puis exit
make orodruin-lock YES=1           # 2e apply : la sortie se referme (YES=1 : sans confirmation)
                                   # sans H0 (WC1) : à chaque -up et -lock, la même WATCH_PRINCIPALS=<id> NO_WATCH=1,
                                   # sinon le plan retire ses droits à la watch du poste
cp infra/orodruin/orodruin.env.example infra/orodruin/orodruin.env   # abonnement, plafond
make orodruin-push                 # l'image d'Annatar publiée (CI3) : digest, signature et provenance vérifiés ici, archive tirée des blobs du registre (OI1) | ssh docker load ; + orodruin.env
                                   # REF=<tag|commit> (défaut : le dernier tag v* — tant qu'il est d'avant CI3, il n'a pas d'image
                                   # publiée et la cible échoue : donner REF=<un commit de main d'après CI3>)
                                   # make orodruin-push-dev : construite ici, non vérifiée (développement)
make orodruin-check                # le contrat lu depuis la VM : armed ou passive
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
