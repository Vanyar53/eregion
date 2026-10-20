# Orodruin — le contrat de garde-fous vérifié au démarrage

_Conception — 2026-10-14, relue en Opus 5.5 le 2026-10-15 — statut : **implémenté et mesuré sur le banc le 19/10** (O1 : `eregion_core/orodruin.py`,
`infra/orodruin/`, mutants M64–M70), canal des fenêtres d'exercice compris (voir « Le canal
des fenêtres d'exercice ») ; canal retour de la watch (#159, M109–M113) le 20/10._

## Ce qu'Orodruin est, et ce qu'il n'est pas

Orodruin est l'hôte d'où les injecteurs (Annatar, puis Gothmog) agissent : une VM jetable,
séparée des cibles, dont les droits et la sortie réseau sont bornés, et qui **ne s'arme que si
son contrat tient**. Contrat non vérifié ⇒ mode passif : les injecteurs ne touchent rien.

Orodruin n'est pas un garde-fou de cible — c'est `eregion_core/inscription.py` (O0) qui décide
si une ressource est inscrite et si sa zone autorise l'expérience. Orodruin est la couche en
dessous : même si un injecteur essayait d'agir hors cible inscrite, l'identité et le réseau
d'Orodruin ne le lui permettraient pas. Les deux sont indépendants et se cumulent.

```
inscription (O0)   « cette cible est-elle à moi, sa zone permet-elle ceci ? »  — logique
contrat Orodruin   « cet hôte a-t-il le droit, et seulement le droit, d'agir ? » — infra
```

## Le contrat

Six garanties. Chacune a un mécanisme, et une vérification qui ne demande **aucune écriture**
(elle lit l'état effectif, ou tente une action qui doit échouer).

| Garantie | Mécanisme | Vérifiée par |
|---|---|---|
| Périmètre réseau | sortie limitée au banc, aux API de contrôle du cloud et à l'API du modèle | une connexion hors périmètre échoue |
| Identité limitée | identité d'exécution restreinte au groupe de ressources du banc | lecture de ses attributions de rôle, à toutes les portées, et de ses droits effectifs sur le banc |
| Cibles inscrites | l'inscription est revérifiée à chaque injection | refus sans inscription (O0, déjà en place) |
| Plafond | limite de l'orchestrateur, ou quota | configuration effective lue |
| Arrêt d'urgence | révoquer l'identité, tout arrêter | essai à blanc en CI |
| Audit | chaque appel d'un injecteur journalisé **avant** exécution | l'écriture précède l'appel |

### `orodruin-check` — la porte

`orodruin-check` vérifie le contrat et rend un verdict à code stable, comme la préparation de
Glorfindel (`readiness.py`) : `armed` (tout tient) ou `passive` (au moins une garantie manque),
avec la liste des manques. Rien n'est écrit. Tant que le verdict n'est pas `armed`, tout
injecteur lancé depuis Orodruin reste passif — il ne touche aucune cible.

Lectures du contrat, sans écriture :

- **identité**, deux lectures, parce qu'il faut prouver une absence autant qu'une présence :
  - ses **attributions de rôle, à toutes les portées** (`Microsoft.Authorization/roleAssignments`,
    filtrées sur le principal de l'identité) : chacune doit être contenue dans le groupe du banc.
    Une attribution plus large (l'abonnement, un autre groupe) = manque. C'est ce qui prouve
    qu'elle n'a **aucun** droit ailleurs ;
  - ses **droits effectifs sur le groupe du banc** (`Microsoft.Authorization/permissions`, toutes
    les pages) : elle peut faire ce que les injecteurs demandent. La brique existe dans l'audit de
    Glorfindel (`check_permissions`), mais elle prouve la **présence** d'un droit sur une portée
    donnée, jamais son absence ailleurs — d'où la première lecture.

  Non couverts par ces lectures, à mesurer sur le banc à l'implémentation : les droits venus d'un
  groupe Entra ID dont l'identité serait membre, les deny assignments, PIM.
- **réseau** : une tentative de connexion vers une adresse hors périmètre doit échouer (timeout
  ou refus). Le périmètre autorisé : le banc, l'API de contrôle du cloud, l'API du modèle.
- **plafond** : la configuration effective de l'orchestrateur (ou le quota) est lue et comparée
  à la limite déclarée.

Un contrat qui ne peut pas être lu (API injoignable, droits insuffisants pour lire les droits)
→ `passive`, jamais `armed` par défaut : on échoue fermé.

### L'ordre d'un run

```
orodruin-check → armed ?
  non  → passif : l'injecteur ne touche rien, dit pourquoi
  oui  → pour chaque injection :
           journaliser l'appel (qui, quoi, quand, cible)   ← AVANT
           inscription O0 (check_target)                   ← refus si hors cible/zone
           exécuter
```

Le journal précède l'exécution, toujours. Un run interrompu entre le journal et l'appel laisse
une trace « on allait faire ceci » — jamais un appel sans trace.

### `orodruin-kill` — l'arrêt d'urgence

`orodruin-kill` **révoque l'identité d'exécution** puis arrête la VM, dans cet ordre : révoquer
d'abord, pour qu'un injecteur en cours perde ses droits même si l'arrêt de la VM traîne. Un kill
qui arrêterait la VM sans révoquer l'identité serait un faux arrêt (l'identité survit à un
redémarrage). L'essai à blanc en CI vérifie que l'ordre tient et que la révocation est bien
tentée avant l'arrêt.

## Les cibles Make

| Cible | Fait |
|---|---|
| `orodruin-up` | crée la VM et l'identité, état Terraform **séparé** de Celebrimbor |
| `orodruin-check` | vérifie le contrat, affiche le verdict, n'écrit rien |
| `orodruin-stop` | éteint la VM sans la détruire (pause) |
| `orodruin-down` | détruit la VM et l'identité |
| `orodruin-kill` | révoque l'identité, puis arrête la VM (urgence) |

État Terraform séparé : Orodruin ne partage pas le `terraform.tfstate` de Celebrimbor, pour
qu'un `apply` ou un `down` de l'un ne touche jamais l'autre (même règle que les topologies).

## Mutants d'O1 (à ajouter au harnais avant la fusion)

La spécification d'O1 nomme trois bugs. Chacun aura son mutant dans `scripts/mutation_check.py`,
mesuré par les tests d'Orodruin (table `TESTS`, comme O0) :

1. **contrat non vérifié mais mode actif** : `orodruin-check` échoue (ou n'est pas lancé) et les
   injecteurs agissent quand même → un run doit rester passif.
2. **journal écrit après l'appel** : l'ordre est inversé → un appel sans trace préalable.
3. **arrêt d'urgence qui oublie la révocation** : `orodruin-kill` arrête la VM sans révoquer
   l'identité → l'identité survit.

## L'implémentation (19/10)

- **La porte, c'est le contrat lui-même.** Le moteur d'Annatar (`run`) et `clean` appellent
  `arm()` avant de lire la cible. Il n'y a pas de drapeau « je suis sur Orodruin » : sur un poste
  d'opérateur (droits sur tout l'abonnement, sortie ouverte), les mêmes lectures échouent, donc
  l'injecteur y reste passif.
- **Un seul point de passage pour l'audit** : `AzureVMExecutor._before_call`, appelé avant tout
  appel qui écrit sur la cible (le démarrage d'une VM arrêtée compris). Sans session armée, il
  refuse (`Passive`). La ligne est écrite sur disque (fsync) avant l'appel ; au-delà du plafond,
  une ligne `refused_cap` et l'appel n'a pas lieu.
- **Qui je suis** : l'`oid` du jeton de l'API de contrôle, pas un réglage qui pourrait dériver.
- **Plafond** : `EREGION_MAX_INJECTIONS` (≤ 20) et `EREGION_MAX_RUN_S` (≤ 2 h, la durée maximale
  d'une fenêtre d'exercice), déclarés dans `orodruin.env`. Absent ou au-dessus du plafond →
  `passive`.
- **Réseau** : deux sondes TCP vers des adresses hors périmètre (`1.1.1.1:443`, `9.9.9.9:443`),
  par adresse (le DNS reste autorisé).
- **Kill** : `infra/orodruin/kill.py`, depuis le `az login` de l'opérateur. Il supprime toutes
  les attributions de l'identité (filtrées sur `principalId`, à toutes les portées), puis
  désalloue la VM sans attendre.
- **Sortie** : règles NSG séparées, avec le refus d'Internet posé par `egress_locked` (vrai par
  défaut). Le premier apply le lève, le temps d'installer Docker. L'image d'Annatar arrive
  ensuite par SSH.

**Mesuré sur le banc le 19/10** (VM D2als_v6, francecentral) :
- **Sortie** : depuis l'hôte et depuis le conteneur, `1.1.1.1`, GitHub et PyPI sont
  injoignables. L'API de contrôle (400), Entra ID (200), l'API du modèle (401, sans clé) et le
  jeton IMDS de l'identité (200) passent. `api.anthropic.com` se résout d'abord en IPv6 ; sans
  IPv6 dans le VNet, curl retombe sur IPv4.
- **Lecture de l'identité — la première vérification était aveugle.** Avec ses seuls droits (rôle
  injecteur sur le banc, `Log Analytics Reader` sur le workspace), la liste filtrée
  `assignedTo(oid)` au niveau de l'abonnement renvoyait **une** attribution, celle du workspace,
  et cachait celle du banc. Azure ne liste que ce que l'appelant peut lire, et le rôle injecteur
  n'a pas de lecture d'attributions. Le premier `orodruin-check` disait donc `armed` alors qu'une
  attribution ailleurs, sans droit de lecture associé, aurait été invisible. Correctif : la
  liste ne prouve une absence que si l'identité lit les attributions sur tout l'abonnement
  (droits effectifs relus au niveau de l'abonnement) ; sinon `identity_unprovable` → `passive`.
  `contract_reader` passe à vrai par défaut. Mutant M67.
- **Le contrat tombe quand on le casse** : un `Reader` ajouté sur `rg-orodruin` →
  `identity_outside_bench` ; la sortie rouverte (`egress_locked = false`) → `network_open`.
  Chaque fois, refermé → `armed`.
- **Kill réel** : une sonde sur la VM lisait le groupe du banc toutes les 3 s. La suppression
  des attributions a commencé à 12:50:10,5 UTC ; dernier 200 à 12:50:08, **premier 403 à
  12:50:11**, soit une révocation effective en moins de 3 s (une seule mesure). La VM s'est
  éteinte vers 12:50:25 (désallocation terminée à 12:50:45). Dans le kill, c'est donc la
  révocation qui coupe d'abord, et l'arrêt suit.
- **Vrai run** (T1136.001, gondolin, lancé par Jonathan depuis Orodruin) : contrat `armed` au
  démarrage ; ligne d'audit `about_to_call` à 12:58:06,54 UTC, Run Command démarré à
  12:58:07,18 (journal d'activité, appelant : l'identité d'Orodruin), réussi à 12:58:28.
- Limites qui restent : une autre souscription du même tenant, les groupes Entra ID, les deny
  assignments, PIM.

Décisions du 19/10 (go de Jonathan sur le plan) :
- la porte est stricte partout ;
- pas de peering avec le banc ;
- le canal des fenêtres B2 vers la watch hébergée (un conteneur de stockage dans
  `rg-orodruin`, lu par Glorfindel) vient après la mesure ;
- le rôle de lecture au niveau de l'abonnement (`contract_reader`) seulement si la mesure
  l'exige — elle l'a exigé (ci-dessus).

## Le canal des fenêtres d'exercice (O1, partie C — 19/10)

Les fenêtres B2 (`eregion_core/exercise.py`) disent à Glorfindel quels cycles sont des
exercices. Avec Glorfindel hébergé (H0) et les injecteurs sur Orodruin, elles changent d'hôte
par un conteneur de stockage à Orodruin (`eregion_core/exercise_channel.py`) :

- **Côté Orodruin** : `open_window` et `close_window` publient la fenêtre
  (`<run_id>.json`). Un échec ne casse jamais le run : la fenêtre reste locale, et les cycles
  du run seront étiquetés « real ».
- **Côté watch** : `load_windows` copie les fenêtres nouvelles ou changées dans
  `runs/exercises/`, au plus toutes les 30 s. Seuls les noms simples sont acceptés, jamais un
  chemin. Si le canal est injoignable, les fenêtres locales comptent toujours.
- **Droits** : Orodruin a `Storage Blob Data Contributor`, Glorfindel `Storage Blob Data
  Reader`, tous les deux **à la portée du conteneur**. L'accès passe par Entra ID uniquement,
  sans clé partagée.
- **Le contrat** accepte cette attribution hors du banc **seulement** si sa portée est le
  conteneur déclaré (`EREGION_CHANNEL_SCOPE`) **et** que la déclaration a bien la forme d'une
  portée de conteneur. Une portée plus large déclarée comme canal (abonnement, groupe, compte)
  n'autorise rien (M68).
- **Sortie** : `Storage.FranceCentral` en 443. Le tag couvre tous les comptes de la région :
  c'est une voie de sortie possible, bornée à la région. À resserrer par un point de
  terminaison privé si Orodruin quitte le banc.

**Mesuré le 19/10** :
- avec `EREGION_CHANNEL_SCOPE` déclarée, `armed` ; sans elle, `passive`
  (`identity_outside_bench` sur le conteneur) ;
- une fenêtre publiée depuis Orodruin a été listée et lue (200) par l'identité du Glorfindel
  hébergé, dont l'écriture est refusée (403) ;
- la création du compte sans clé partagée a attendu environ 4 minutes sur la vérification du
  data plane par le provider, d'où `features.storage.data_plane_available = false`.

## Le canal retour : la watch hébergée parle au run (#159 — 20/10)

Un run lancé depuis Orodruin ne voit pas la watch de H0 : ni son battement de cœur ni ses
fichiers `watch-*` (premier run R1 sur le banc, 20/10 : `detection: unknown`). Une watch sur
Orodruin ne détecterait pas : `api.loganalytics.io` est hors de sa sortie. Le canal retour est
le canal des fenêtres dans l'autre sens : un conteneur `watch` dans le même compte
(`eregion_core/watch_channel.py`).

- **Deux sortes de blobs.**
  - `heartbeat.json`, réécrit toutes les 60 s : `at`, `since` (démarrage de la watch),
    `windows` (les `run_id` des fenêtres ouvertes ou en grâce que la watch connaît). Ce sont les
    `run_id` d'Orodruin, rien du parc.
  - `detections/<run_id>/<signal_id>.json` : `ttp`, `resource_id`, `detected_at`, `rule`,
    `watch_run_id`. Un blob par couple (fenêtre, détection), seulement pour une VM à laquelle la
    watch a attribué la détection et qu'une fenêtre couvre à son heure. Jamais le reste du parc,
    jamais une ligne non attribuée.
- **Côté watch** : le RulePoller note chaque détection en mémoire (aucune écriture, rien qui
  puisse échouer). Un thread tire les fenêtres, publie les couples pas encore livrés, puis écrit
  le battement de cœur **seulement quand plus rien n'attend** : un battement de cœur garantit que
  tout ce qui le précède a été livré. Une détection vue avant sa fenêtre est publiée quand la
  fenêtre arrive. Une détection qui n'a pas pu être notée avance `since`, comme un redémarrage.
- **Côté run** (Annatar, après #157) : l'attente de la détection lit le battement de cœur et
  liste `detections/<run_id>/` ; les détections passent par le même test que les fichiers
  locaux.
- **Échec vers `unknown`.** `detected` exige un blob de détection, que seule la watch peut
  écrire. `missed` exige un battement de cœur écrit **après la fin de l'attente**, par une watch
  **démarrée avant l'attaque**, qui **connaît la fenêtre du run**, et une liste lue sans erreur
  (`miss_unprovable`). Tout le reste donne `unknown` : canal absent, injoignable ou refusé,
  battement de cœur périmé, fenêtre jamais reçue par la watch (le canal des fenêtres en panne :
  elle n'aurait rien publié), watch redémarrée, détection en attente de livraison.
- **Droits.** La watch (`watch_principal_id`) a `Storage Blob Data Contributor` sur `watch`
  seulement, et reste en lecture partout ailleurs. Orodruin a `Storage Blob Data Reader` sur
  `watch`. **Le contrat** accepte cette attribution hors du banc seulement à la portée déclarée
  (`EREGION_WATCH_CHANNEL_SCOPE`, même contrôle de forme que M68) et **seulement si le rôle est
  en lecture** : actions et dataActions contenues dans celles de Storage Blob Data Reader.
  Un rôle d'écriture, ou un joker, à cette portée → `identity_outside_bench` → `passive` (M113) :
  un injecteur n'écrit jamais ce que dit la watch. Ce contrôle passe avant celui du canal des
  fenêtres : déclarés sur le même conteneur, le rédacteur reste refusé. `REQUIRED_ACTIONS` et le
  rôle `injector` ne changent pas ; `orodruin-kill` supprime toutes les attributions de
  l'identité, celle-ci comprise.
- **Sortie** : rien ne change (`Storage.FranceCentral` pour Orodruin ; la sortie de H0 n'est pas
  filtrée). `GLORFINDEL_READ_ONLY` porte sur l'infra observée, pas sur le stockage d'Eregion.
- **Mutants** : M109 (battement de cœur sur une détection en attente), M110 (une VM hors fenêtre
  publiée), M111 (une fenêtre inconnue de la watch prouve un miss), M112 (une watch redémarrée
  prouve un miss), M113 (le contrat accepte un rôle d'écriture sur `watch`).

**Mesuré le 20/10** : la définition de Storage Blob Data Reader lue sur Azure (`az role
definition list`) est exactement l'ensemble accepté ; Contributor y ajoute `blobs/write`,
`blobs/delete`, `blobs/add/action`, `blobs/move/action`, refusés.

## Questions ouvertes (pour Jonathan, à l'implémentation)

- **Identité d'exécution** : ~~une identité managée ou un principal de service dédié ?~~
  **Tranché le 15/10 : une identité managée attachée à la VM Orodruin**, avec un rôle limité au
  groupe du banc. Pas de secret à gérer ; `orodruin-kill` retire son attribution de rôle (voir
  « Révocation »).
- **Périmètre réseau** : un NSG sur la VM Orodruin qui n'autorise en sortie que le banc + les
  préfixes des API du cloud (service tags `AzureResourceManager`, `AzureActiveDirectory`) + l'API
  du modèle ? Les service tags couvrent les API de contrôle ; l'API du modèle est une adresse
  externe à autoriser nommément.
- **Coût** : la VM Orodruin s'ajoute au banc (~5–9 €/mois d'après la ROADMAP). `orodruin-stop`
  entre les sessions, comme Celebrimbor.
- **Révocation** : révoquer une identité managée = retirer son attribution de rôle ; révoquer un
  principal de service = désactiver le principal ou retirer son attribution. L'essai à blanc en CI
  doit pouvoir simuler la révocation sans toucher à une vraie identité (mock de l'appel).

## Ce que ce document ne décide pas

- Le mode Kubernetes (O2) et le mode relais (SaaS) — plus tard. Ce document couvre le mode VM
  dédiée (O1).
- Rien n'est mesuré ici : c'est une conception. Les comportements Azure (révocation effective,
  périmètre réseau réel) seront **mesurés sur le banc** à l'implémentation, comme l'exige la règle
  « certitude par la mesure ».
