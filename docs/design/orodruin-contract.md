# Orodruin — le contrat de garde-fous vérifié au démarrage

_Conception — 2026-10-14, relue en Opus 5.5 le 2026-10-15 — statut : **implémenté et mesuré sur le banc le 19/10** (O1 : `eregion_core/orodruin.py`,
`infra/orodruin/`, mutants M64–M70), canal des fenêtres d'exercice compris (voir « Le canal
des fenêtres d'exercice ») ; canal retour de la watch (#159, M109–M115) le 20/10 ; arrêt
d'urgence revu et mesuré sur le banc le 26/10 (M-1, M191–M194) ; droits par VM inscrite, journal
hors de l'hôte, pare-feu du canal, tirages bornés et garde V1 lié à la watch le 29/10 (SEC5, #276,
M1260–M1279 — **Terraform écrit et validé, pas encore appliqué**)._

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
| Identité limitée | identité d'exécution qui lit le groupe du banc et n'écrit que sur chaque VM inscrite et chaque expérience (SEC5) ; ce qu'elle tient est une liste d'autorisations (SEC11) | lecture de ses attributions de rôle, à toutes les portées, et de ses droits effectifs sur le banc ; une écriture sur le groupe entier = manque ; un droit hors de la liste de sa portée = manque ; sans expérience dans le groupe (Chaos Studio non enregistré sur l'abonnement : `MissingSubscriptionRegistration` ou `NoRegisteredProviderFound`, quel que soit le statut — SEC7, à mesurer), les droits du chaos ne sont pas demandés |
| Cibles inscrites | l'inscription est revérifiée à chaque injection | refus sans inscription (O0, déjà en place) |
| Plafond | limite de l'orchestrateur, ou quota | configuration effective lue |
| Arrêt d'urgence | révoquer l'identité, tout arrêter | essai à blanc en CI |
| Audit | chaque appel d'un injecteur journalisé **avant** exécution, sur l'hôte puis dans le canal (SEC5) | l'écriture précède l'appel |

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

Depuis M-1 (26/10), le kill arrête aussi ce qui tourne sans l'identité d'Orodruin : il annule
les expériences de chaos en cours et ferme les fenêtres d'exercice ouvertes, puis dit ce qui
reste en vol. Voir « L'arrêt d'urgence arrête ce qui tourne ».

## Les cibles Make

| Cible | Fait |
|---|---|
| `orodruin-up` | crée la VM et l'identité, état Terraform **séparé** de Celebrimbor |
| `orodruin-check` | vérifie le contrat, affiche le verdict, n'écrit rien |
| `orodruin-stop` | éteint la VM sans la détruire (pause) |
| `orodruin-down` | détruit la VM et l'identité |
| `orodruin-kill` | révoque l'identité, annule le chaos en cours, arrête la VM, ferme les fenêtres ouvertes (urgence) |

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
  désalloue la VM sans attendre. Revu par M-1 (26/10) : l'abonnement du contrat, pas celui de
  la CLI, et ce qui tourne encore (section dédiée plus bas).
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
  `runs/glorfindel/exercises/` (son répertoire, SEC18), au plus toutes les 30 s. Seuls les noms simples sont acceptés, jamais un
  chemin. Si le canal est injoignable, les fenêtres locales comptent toujours.
- **Le même conteneur porte aussi** une campagne finie (`campaigns/<id>/…`, #167) et le
  rapport d'un run seul (le blob `runs/<run_id>.json`, #193), sous un préfixe que le tirage des
  fenêtres ignore. Rien ne change au contrat : même conteneur, même attribution, même portée.
  Seule la watch hébergée lit ces préfixes ; l'arrêt d'urgence ne relit que les fenêtres.
- **Le lecteur ne croit pas la fenêtre sur parole (H-1, 26/10)** : qui écrit dans le conteneur
  pourrait faire passer une vraie attaque pour un exercice. La watch refuse une fenêtre de plus
  de 2 h, déclarée pour plus tard (plus de 5 min après son écriture), ou nommée comme un run du
  RulePoller ; elle ne marque une VM que si elle la lit inscrite, dans ses tags (droit Reader
  sur le banc) ; elle purge une fenêtre une semaine après son dernier moment, en gardant une
  pierre tombale pour que le tirage ne la ramène pas. Une carte d'exercice reste devant
  l'opérateur, marquée. Une campagne tirée du canal est lue contre sa forme, et ses runs ne
  sont gardés qu'avec une fenêtre connue nommant une VM inscrite (`docs/analysis.md`).
- **Droits** : Orodruin a `Storage Blob Data Contributor`, Glorfindel `Storage Blob Data
  Reader`, tous les deux **à la portée du conteneur**. L'accès passe par Entra ID uniquement,
  sans clé partagée.
- **Le contrat** accepte cette attribution hors du banc **seulement** si sa portée est le
  conteneur déclaré (`EREGION_CHANNEL_SCOPE`) **et** que la déclaration a bien la forme d'une
  portée de conteneur. Une portée plus large déclarée comme canal (abonnement, groupe, compte)
  n'autorise rien (M68).
- **Sortie** : `Storage.FranceCentral` en 443. Le tag couvre tous les comptes de la région :
  c'est une voie de sortie possible, bornée à la région. Côté compte, depuis SEC5, son pare-feu
  n'admet qu'Orodruin et H0 (voir « SEC5 »).

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
- **Côté run** (`annatar/runner/engine.py`, `_wait_and_emit_feedback`) : sans watch locale, un
  battement de cœur frais dans le canal compte comme une watch active ; pendant l'attente, les
  détections de `detections/<run_id>/` passent par la règle de #157 (`detection_latency` : même
  TTP, même VM sans la casse, vue à partir de l'attaque, latence depuis `attack_time`). À la
  fin, sans détection, le run attend jusqu'à 130 s un battement de cœur écrit après l'attente,
  puis relit les détections une dernière fois (une détection vue tout à la fin, livrée après,
  compte encore).
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
- **Qui est « la watch » (WC1, #523, 04/11)** : `watch_principal_ids`, une ou plusieurs identités ;
  par défaut (`null`) celle de H0 seule, `watch_principal_id`, comme avant — mêmes attributions, aux
  mêmes adresses de l'état : le plan de H0 et d'Orodruin ne change pas. Sans H0, l'*object id* du
  principal de service d'une watch de poste ou d'équipe (`GLORFINDEL_AZURE_CLIENT_*`), passé par
  `make orodruin-plan WATCH_PRINCIPALS=<id>[,<id>…] NO_WATCH=1`. Chacune reçoit exactement ce que
  reçoit H0 : `Storage Blob Data Reader` sur `exercises`, `Storage Blob Data Contributor` sur
  `watch`, à la portée du conteneur, `principal_type = ServicePrincipal`. Le plan refuse un
  non-GUID, une identité nommée deux fois, l'identité d'Orodruin et celle de l'opérateur qui
  applique (`azurerm_client_config`) ; le Makefile refuse une valeur venue de l'environnement, et
  une liste qui retire le canal à H0 quand son état se lit, sauf `NO_WATCH=1`. Celle d'Annatar,
  Terraform ne la connaît pas : c'est l'opérateur qui nomme l'identité, et lui seul la tient hors de
  la liste. Chaque `orodruin-up` et `orodruin-lock` redonne la même liste, sinon le plan retire ses
  droits à la watch du poste. Le contrat d'Orodruin ne change pas : il ne lit que ses propres
  attributions. La garde non plus : elle ne croit qu'un battement signé par la clé épinglée dans
  `orodruin.env` (SEC19) — un rédacteur de plus n'y fait pas croire une autre clé. Les détections,
  elles, ne sont pas encore signées : toute identité qui écrit `watch` peut fausser le verdict d'un
  run, `detected` comme `missed` — la mesure, jamais une action (les signer : SEC21). Une watch à la
  fois : le battement est un seul blob, deux watches l'écraseraient tour à tour
  (`infra/orodruin/README.md`, « Sans H0 »).
- **Sortie** : rien ne change (`Storage.FranceCentral` pour Orodruin ; la sortie de H0 n'est pas
  filtrée). `GLORFINDEL_READ_ONLY` porte sur l'infra observée, pas sur le stockage d'Eregion. Une
  watch de poste entre par l'IP de l'opérateur, que le pare-feu du compte admet déjà (WC1).
- **Mutants** : M109 (battement de cœur sur une détection en attente), M110 (une VM hors fenêtre
  publiée), M111 (une fenêtre inconnue de la watch prouve un miss), M112 (une watch redémarrée
  prouve un miss), M113 (le contrat accepte un rôle d'écriture sur `watch`), M114 (le run conclut
  à un miss sans demander au canal), M115 (un canal illisible lu comme un miss).

**Mesuré le 20/10** : la définition de Storage Blob Data Reader lue sur Azure (`az role
definition list`) est exactement l'ensemble accepté ; Contributor y ajoute `blobs/write`,
`blobs/delete`, `blobs/add/action`, `blobs/move/action`, refusés.

## L'arrêt d'urgence arrête ce qui tourne (M-1 — 26/10)

La neuvième passe a trouvé deux trous dans le kill du 19/10 :
- `az role assignment list --all` ne liste que l'abonnement **courant** de la CLI. Dans un autre
  contexte, la liste revenait vide : le kill disait « no role assignment left » et sortait en 0,
  sans rien révoquer.
- La révocation ne coupe que ce qui passe par l'identité d'Orodruin. Une expérience de chaos agit
  avec sa propre identité ; un Run Command déjà parti tourne sur sa VM ; une fenêtre d'exercice
  restée ouverte fait étiqueter « exercice » ce que ses cibles font, jusqu'à son expiration plus
  la grâce (2 h 15).

Le kill a maintenant quatre étapes, dans cet ordre (`eregion_core.orodruin.kill`, toutes
requises). Une étape qui échoue n'arrête pas les suivantes. Elle est rapportée, et le kill sort
en 1.

| Étape | Fait | Pourquoi à ce rang |
|---|---|---|
| `revoke` | supprime les attributions de l'identité sur l'**abonnement du contrat** (`--subscription`, l'`AZURE_SUBSCRIPTION_ID` d'`orodruin.env`), et sur celui de la VM s'il diffère | d'abord : l'injecteur perd ses droits même si le reste traîne |
| `cancel` | annule chaque expérience du groupe du banc dont une exécution n'est pas terminée | une expérience survit à la révocation |
| `stop` | désalloue la VM, sans attendre | ceinture et bretelles, comme avant |
| `close` | ferme les fenêtres encore ouvertes du canal (`end` = maintenant, `closed_by: orodruin-kill`) | en dernier : plus rien d'Orodruin ne peut en rouvrir une |

« Rien à révoquer » ne se conclut que d'une liste de l'abonnement du contrat, **relue après la
suppression**. Si elle était vide dès le départ, le kill vérifie aussi que le principal donné est
bien l'identité de la VM. Un `PRINCIPAL=` mal tapé ne passe donc pas pour « déjà révoqué ». Sans
abonnement connu, rien n'est prouvé : échec.

**Ce qui reste en vol**, dit à la fin, parce qu'aucune étape ne l'arrête. Le kill le tire des
fenêtres qu'il a fermées : chaque injecteur ouvre la sienne avant de toucher sa cible.
- Annatar : un Run Command déjà envoyé va au bout sur sa VM. Le nettoyage de l'atomic peut ne pas
  avoir tourné ; `annatar run <scénario> --dry-run` l'affiche, à rejouer à la main.
- Gothmog : une panne annulée peut laisser sa VM arrêtée (`az vm start`). Une exécution encore
  en `Cancelling` après l'annulation est signalée.
- Une fenêtre fermée étiquette encore ses cibles pendant sa grâce (15 min, le décalage de
  détection), et non plus jusqu'à 2 h 15.

**Qui ferme les fenêtres.** L'identité d'Orodruin vient d'être révoquée. Le compte du canal n'a
pas de clé partagée, et l'opérateur n'avait aucun droit sur ses données. D'où une attribution de
plus : `channel_operator`, Storage Blob Data Contributor sur le seul conteneur `exercises`, pour
celui qui applique `infra/orodruin` (`azurerm_client_config`), déjà propriétaire de l'abonnement.
Jamais sur `watch`. Le contrat d'Orodruin ne la voit pas : elle n'est pas à son identité. Avant
cet apply, le kill dit que les fenêtres n'ont pas pu être fermées, et quand elles expirent. Un
rédacteur de plus sur le canal : c'est la surface que H-1 (#180) borne côté lecteur.

**Rien d'imprimé ne nomme l'abonnement** (commandes, erreurs), comme les cibles Make (M124).

**Mutants** : M191 (la liste dans le contexte courant de la CLI : le bug d'origine), M192 (une
expérience en cours laissée en cours), M193 (les fenêtres ouvertes laissées ouvertes), M194 (ce
que montre le contrat nomme l'abonnement) ; M66 suit la nouvelle boucle. Tests : `tests/unit/test_orodruin_kill.py`, avec un faux `az` dont le
contexte courant est un autre abonnement.

**Mesuré sur le banc le 26/10** (kill lancé pendant une `vm-shutdown` de gondolin) :

| Heure (UTC) | Événement |
|---|---|
| 14:57:13 | l'expérience démarre ; gondolin éteinte à 14:58:00 |
| 14:58:23–14:58:31 | les 5 attributions d'Orodruin supprimées ; la liste relue juste après est vide |
| juste après | annulation demandée ; l'exécution est encore `Running` (le kill le dit) |
| 14:58:37 | la fenêtre fermée par le kill (`closed_by: orodruin-kill`) |
| 14:58:48 | la watch de H0 a tiré la fenêtre fermée (11 s) |
| 14:58:56 | Orodruin désallouée |
| 14:59:19 | gondolin redémarrée **par Chaos Studio** : l'annulation ramène la VM, sans `az vm start` |
| 14:59:25 | l'exécution passe à `Cancelled` |

Le kill est sorti en 0. Ce qu'il disait en vol était juste. Un premier kill, lancé en même temps
que la panne (14:44), était passé avant son démarrage. La révocation a gagné : le démarrage de
l'expérience a été refusé, et la fenêtre fermée par le run une seconde après son ouverture.

**Au réarmement** (`make orodruin-lock YES=1`, attributions recréées à 14:53:20) :
`orodruin-check` dit `armed` tout de suite. Mais la requête Log Analytics de Gothmog (heartbeat,
par ARM) était encore refusée 76 s plus tard (HTTP 502 `InsufficientAccessError`), et acceptée
moins de 4 min après. Après un kill, `make gothmog-preflight` dit quand on peut relancer une
panne. Un `orodruin-check` refusé affichait l'abonnement dans l'URL de la liste : ce que montre
le contrat le masque désormais (M194).

Non mesuré au banc : le mauvais contexte CLI lui-même (un seul abonnement utilisé). C'est le
test `test_a_wrong_cli_context_never_concludes_nothing_to_revoke` qui le couvre.

Limites : un Run Command ne se liste pas (action, pas ressource) : le kill le déduit des fenêtres,
il ne le voit pas. Une expérience hors du groupe du banc n'est pas lue : l'identité d'Orodruin
n'agit que sur le banc.

## SEC5 — les injecteurs et leurs canaux (#276, 29/10)

L'audit externe du 27/10 et son contre-audit du 28/10 ont trouvé onze points sur les injecteurs
et leurs canaux. Ce qui change pour le contrat et ce qu'il porte :

**Les droits par VM inscrite (V-29, #182).** L'identité d'Orodruin avait le rôle injecteur sur
tout le groupe du banc : Run Command sur bree, la VM de la pré-observation, jamais inscrite,
était à sa portée. Désormais trois rôles (`infra/orodruin/main.tf`) :

| Rôle | Actions | Portée |
|---|---|---|
| `injector_read` | lire le groupe, les VM, les NSG, les cartes réseau et les sous-réseaux (DG-b), les expériences et leurs exécutions | le groupe du banc |
| `injector_vm` | `start`, `runCommand` | chaque VM qui porte `eregion-target=<banc>` (`data "azurerm_resources"`, `required_tags`) |
| `injector_chaos` | démarrer, annuler une expérience | chaque expérience du groupe |

Le contrat (`assess_identity`) le relit : les lectures doivent être effectives sur le groupe, chaque
écriture accordée sur au moins une ressource de son type dans le groupe, et **aucune écriture sur le
groupe entier** — ni dans les attributions listées, ni dans les droits effectifs relus sur le
groupe (`identity_group_wide` → `passive`). Une VM inscrite après l'apply — ou toutes, après une
reconstruction de Celebrimbor (les attributions portent l'id des VM) — n'a pas de droit tant que
`make orodruin-lock YES=1` ne l'a pas relue. Le tag cherché est tiré du groupe du banc
(`rg-celebrimbor` → `celebrimbor`, `rg-celebrimbor-<instance>` → `celebrimbor-<instance>`, comme
Celebrimbor le pose), sauf `bench_id` donné. Les droits de chaos ne sont demandés que si le groupe
contient une expérience (le contrat liste les expériences du groupe ; le chaos de Celebrimbor est
éteint par défaut) : sans elle, Annatar reste armé, et Gothmog ne trouve rien à lancer. À mesurer après l'apply : que les droits effectifs relus sur
le groupe n'incluent pas ceux accordés sur ses VM (sinon le contrat dirait `identity_group_wide`
à tort, et resterait passif — l'échec est fermé). Le contrat ne relit pas lui-même l'inscription
des VM sur lesquelles l'identité écrit : c'est Terraform qui la tire des tags, et l'inscription
(O0) reste revérifiée à chaque run.

**Le journal hors de l'hôte (V-29).** Chaque ligne du journal (`Session`) est écrite sur le disque
d'Orodruin (fsync), puis ajoutée au blob d'ajout `audit/<run_id>.jsonl` du conteneur `exercises`
(même attribution, même portée : rien ne change au contrat), avant l'appel. Au mieux : un envoi qui
échoue est écrit au journal local (`offhost_failed`) et dit, et l'appel se fait (le refuser pourrait
laisser une cible à moitié nettoyée). Ce que cela donne : la trace survit à la perte ou à
l'effacement de l'hôte. Ce que cela ne donne pas : une défense contre un hôte compromis, qui peut
cesser d'envoyer, ou effacer ce que son identité a écrit (Contributor sur le conteneur). Aucun
tirage ne lit `audit/` : celui des fenêtres ne liste plus que la racine du conteneur.

**Le pare-feu du compte du canal (V-31).** Le point de terminaison public reste, fermé par défaut
(`network_rules`, `default_action = "Deny"`, rien ne contourne). Entrent : les sous-réseaux
d'Orodruin et de H0, par un point de terminaison de service `Microsoft.Storage` (gratuit) — une
règle d'IP n'a pas d'effet pour un client de la même région que le compte, ce qui est leur cas
(francecentral) —, et les IP publiques d'Orodruin, de H0 (si l'un d'eux change de région) et de
l'opérateur (l'arrêt d'urgence ferme les fenêtres depuis son poste ; une IP qui a changé depuis le
dernier apply : le kill dit que les fenêtres n'ont pas été fermées, et quand elles expirent ; depuis
WC1, la watch d'un poste passe par cette même IP, rien n'est ouvert de plus). Un
point de terminaison privé n'est pas gratuit : 0,0088 € l'heure l'un (API publique des prix
d'Azure, compteur « Standard Private Endpoint », 29/10), environ 6,4 € par mois, plus le trafic ;
il en faudrait deux, les VNet n'étant pas appairés. À mesurer après l'apply : `orodruin-check`,
une fenêtre publiée et tirée par H0, le kill qui la ferme.

**Le garde « jamais sans Glorfindel » (N-03, N-04).** Ce qu'il prouve : que la watch qui détient
sa clé a écrit ce fichier (ou ce blob), pour l'abonnement de l'injecteur, il y a moins de 90 s
(SEC19, [`watch-key.md`](watch-key.md)). Le battement est signé par la clé Ed25519 de la watch ;
l'injecteur le vérifie avec la clé publique épinglée de son côté, `EREGION_WATCH_KEY` dans
`orodruin.env` (`make glorfindel-host-watch-key` la donne) — jamais lue dans le canal ni dans le
battement. Sans clé épinglée, sans signature, d'une autre clé, à la signature qui ne tient pas ou au
compteur rejoué : refusé avant tout appel au cloud, la raison dite. Le contrat d'Orodruin, lui, ne
change pas : la clé épinglée n'est pas une de ses vérifications, c'est la garde qui la lit. Avant
SEC19, le garde prouvait seulement que quelqu'un qui peut écrire là avait écrit un battement frais
de ce périmètre. Le battement porte un condensé de l'abonnement que la watch
lit (`perimeter`, 16 hex du sha256 ; jamais l'abonnement lui-même), que l'injecteur compare au
sien : l'abonnement plutôt que l'hôte, parce que c'est ce que les deux côtés savent des mêmes
cibles (un nom d'hôte ne se compare à rien : Orodruin et H0 sont deux hôtes, les conteneurs locaux
deux autres) ; le condensé lie, la signature authentifie. Ce qu'il ne prouve pas : que les
workspaces de la watch voient la cible, ni sa santé au-delà de sa boucle de battement ; et qui lit
la clé privée de la watch (root sur son hôte) signe comme elle. Le garde est relu avant chaque action d'un
run (chaque étape, la commande de l'atomic, le démarrage de la panne) ; `annatar clean` y passe.
`--without-glorfindel` est refusé en zone `production`, et écrit au journal (`declared`).

**Les fenêtres d'exercice (V-20).** Une fenêtre tirée du canal porte la date de création de son
blob (`channel_created`, ce que dit la liste, écrit par-dessus ce que la fenêtre dirait, et gardé
depuis son premier tirage) : elle ne peut pas commencer plus de 5 min avant. MAX_DURATION_S la
plafonne toujours. Sur une VM en zone `production` (ses tags, lus par la watch), une fenêtre ne
marque rien, sauf une technique non destructive (`kind: technique`, `destructive: false`, que
l'injecteur écrit d'après le catalogue). Une fenêtre déjà tirée ne peut revenir que fermée : tous
ses champs tels qu'ils étaient, `end` qui passe de null à une date pas antérieure à son début
(`closed_by` à côté, celui du kill) ; toute autre réécriture (une cible ajoutée, un début déplacé,
une expiration repoussée, `end` retiré ou déplacé) est refusée, la copie tirée d'abord gardée, et
c'est dit une fois ; une copie locale qui ne se lit plus (corrompue, pas une fenêtre) n'est jamais remplacée (SEC7) — une copie effacée sur l'hôte revient comme neuve, bornée par la création de son blob. À mesurer : qu'Azure garde la date de création d'un blob réécrit (sinon, une
fenêtre vue pour la première fois déjà fermée serait refusée : ses cycles restent « real », le
sens sûr).

**Une fenêtre écrite sur l'hôte même** (sans canal : la watch et l'injecteur partagent `runs/`) est
bornée de la même façon (SEC14, V-20), par ce que la watch en a vu : la première fois qu'elle la lit,
elle note quand, dans son propre état (`~/.glorfindel/exercise_seen.json`, jamais dans `runs/`
qu'écrit l'injecteur, et qu'aucun conteneur d'injecteur ne monte, SEC3). La fenêtre ne peut pas
commencer plus de 5 min avant ce moment, et, une fois vue, ne peut revenir que fermée, comme par le
canal. La watch relit ses fenêtres chaque minute (le ménage de `glorfindel watch`) : une fenêtre
d'injecteur est vue moins d'une minute après son écriture, et aucun run ne part sans watch vivante
(V1). Un registre illisible ne fait croire aucune fenêtre : leurs cycles restent « real ».
Le mtime d'un fichier ne borne rien (qui écrit le fichier écrit aussi sa date). **Une fenêtre n'est
« tirée du canal » que si le registre le dit** (relecture de SEC14) : le tirage y note chaque fenêtre
qu'il écrit, avec la création de son blob et ce qu'elle dit (`note_pulled`) ; un `channel_created` que
le fichier porte seul est la parole de qui l'a écrit, et la fenêtre est alors locale. Le registre est
lu, changé et écrit sous un `flock`, par un fichier temporaire à lui (`mkstemp`) : la watch,
`glorfindel respond` et la console peuvent lire les fenêtres en même temps. Une watch arrêtée plus de
5 min pendant un run local voit sa fenêtre en retard : refusée, ses cycles comptent comme réels, le
sens sûr. **La transition** : une copie tirée avant cette version (une fenêtre encore ouverte au
déploiement) n'est pas au registre. Le tirage la retire une fois, par `rewrite_refusal` comme toute
autre, la date de la création que donne la liste — jamais celle que porte la copie —, puis la note :
la fenêtre redevient celle du canal, et un exercice à cheval sur un déploiement reste mesuré. Ce
téléchargement unique est borné par `MAX_DOWNLOADS` et la borne cumulée du tirage. Une copie qui
n'est plus celle du canal (réécrite sur l'hôte) reste refusée, donc locale.

Limites qui restent, assumées : une suite de fenêtres neuves, chacune écrite au moment où elle
commence, couvre une VM aussi longtemps que son rédacteur le veut — par le canal comme sur l'hôte ;
la console montre les fenêtres telles que leurs fichiers les disent (`window_refusal`), sans ce
registre, que seule la watch tient ; en production, la règle repose sur le `destructive` que l'injecteur écrit d'après le catalogue — un
rédacteur du canal qui mentirait là ne ferait marquer qu'une technique non destructive, sur une
VM inscrite.

**Les canaux bornés (V-21, N-15).** Un tirage lit en flux, coupé au-delà de sa borne (jamais lu en
entier puis contrôlé) : un blob au plus `MAX_BLOB_BYTES` (1 Mio), une page de liste au plus
`MAX_LISTING_BYTES` (8 Mio), au plus `MAX_BLOBS` noms listés (2 000) et `MAX_DOWNLOADS` blobs
téléchargés (200) par tirage ; ce qui dépasse est dit, laissé au tirage suivant ou écarté, jamais
écrit. Et en cumul (SEC14) : un tirage lit au plus `MAX_PULL_BYTES` (32 Mio), ses pages de liste et
ses blobs ensemble — chaque tirage (fenêtres, campagnes, rapports de run, mots d'Orodruin) a le sien ;
au-delà, il s'arrête là, le dit, et le reste attend le tirage suivant (une campagne dont la liste est
coupée n'est pas écrite). Le jeton de stockage ne part que vers `https://<compte>.blob.core.windows.net` (ou
`.blob.core.chinacloudapi.cn`, `.blob.core.usgovcloudapi.net`), port 443, sans utilisateur dans
l'URL : toute autre URL est refusée avant qu'un jeton soit demandé. Et vers le seul compte déclaré
(SEC17) : les URL des deux canaux (`EREGION_EXERCISE_CHANNEL`, `EREGION_WATCH_CHANNEL`) et, sur
Orodruin, les portées de leurs conteneurs que lit le contrat (`EREGION_CHANNEL_SCOPE`,
`EREGION_WATCH_CHANNEL_SCOPE`) — toutes des sorties Terraform de ce module — nomment un même
compte ; une URL d'un autre compte, ou des déclarations qui ne s'accordent pas, sont refusées et
dites, aucun jeton envoyé. Sans aucune déclaration dans l'environnement, l'URL reste la parole de
l'opérateur (le modèle de menace, §5). Une rétention sur le compte
(`azurerm_storage_management_policy`, gratuite) tient la liste sous ces bornes : la liste est
alphabétique et les run_id sont des horodatages, si bien qu'au-delà de 2 000 noms ce sont les
fenêtres les plus récentes qui ne seraient plus tirées. Les blobs de bloc (fenêtres, campagnes,
rapports de run, détections) partent 9 jours après leur dernière écriture (la purge de la watch,
7 jours après le dernier moment d'une fenêtre, plus 2 h 15 et une marge) ; le journal d'Orodruin
(`audit/`) reste 90 jours, le temps de revenir sur un incident.

**Les scripts locaux (V-19, SEC14).** Le catalogue se porte garant du contenu d'un script, pas de son
chemin : chaque entrée qui nomme un `reference_script` ou des `setup_scripts` porte leur sha256
(`script_sha256`). Un script dont le contenu n'est pas celui-là n'est plus « ce que le catalogue a dit »
(`catalog_destructive` : inconnu, donc destructif, refusé en production), et `run_script` ne l'envoie
pas à la VM : le fichier est lu une fois, son empreinte comparée, puis ce contenu-là envoyé. Un script
changé change son empreinte dans le même commit (`tests/unit/test_injector_guards.py`).

**Les atomics (V-30).** Le sha256 de chaque atomic est relu contre `PIN` à chaque run. `PIN` est
rangé à côté des YAML, dans la même image : une modification qui touche les deux à la fois n'est
pas vue. Cela attrape un fichier dérivé ou à moitié modifié, pas une image hostile (sa
provenance : M-3).

**Le déploiement, avec Jonathan, dans cet ordre** — un injecteur neuf refuse le battement d'une
watch sans périmètre, un contrat neuf sur l'ancien rôle de groupe dit `identity_group_wide`, et un
pare-feu posé avant le point de terminaison de H0 lui coupe le canal :

1. la release publiée ; le CD de H0 la déploie ; vérifier que `heartbeat.json`, dans le conteneur
   `watch`, porte `perimeter` ;
2. `make glorfindel-host-plan` : une seule mise à jour en place, celle du sous-réseau
   (`service_endpoints`), et l'output `subnet_id` — rien qui remplace la VM (`custom_data`) ;
   puis `make glorfindel-host-up YES=1` ;
3. `make orodruin-plan` : deux sous-réseaux dans `network_rules`, les rôles et attributions
   ci-dessus, la politique de rétention ; puis `make orodruin-lock YES=1`, sans run en cours ;
4. `make orodruin-push` (l'image des injecteurs, publiée et vérifiée depuis CI3, et son contrat) ;
5. `make orodruin-check` : `armed`.

Un retour en arrière du CD de H0 vers une version sans SEC5 rend un battement sans périmètre :
tous les injecteurs neufs refusent (« names no perimeter »), le sens fermé — redéployer la
version SEC5 ; `--without-glorfindel` reste possible hors production. En profil local, un vieil
injecteur (une image d'avant SEC5) lit la copie de la watch neuve, devenue du JSON, comme une date
illisible, et refuse aussi : `make build`.

## SEC11 — une liste d'autorisations, pas une liste de refus (#417, 02/11)

Le contrat refusait quatre écritures (démarrer une VM, Run Command, démarrer ou annuler une
expérience) sur le groupe entier, et laissait passer le reste : un rôle large qui n'en contient
aucune — `Network Contributor` sur le groupe du banc, par exemple — armait encore Orodruin.
Désormais, ce que l'identité **tient** dans le banc est une liste, par genre de portée
(`eregion_core/orodruin.py`, `allowed_at`) :

| Portée de l'attribution | Ce qu'un rôle peut y tenir | Pourquoi |
|---|---|---|
| le groupe du banc | les lectures des injecteurs (`READ_ACTIONS`) | Annatar lit la VM, ses NSG, cartes et sous-réseaux ; Gothmog lit les expériences |
| une VM du groupe | ces lectures, `start`, `runCommand` (`VM_ACTIONS`) | Annatar démarre une VM arrêtée et y lance son script |
| une expérience du groupe | ces lectures, démarrer et annuler (`CHAOS_ACTIONS`) | Gothmog lance la panne et peut l'arrêter |
| l'espace de logs du banc | ces lectures, `Log Analytics Reader` tel qu'Azure le définit (`LOGS_READER_ACTIONS` : `*/read`, les deux actions de requête, `Microsoft.Support/*` ; `LOGS_READER_DATA_ACTIONS` : son action de données, `workspaces/jobs/export/action`, que la lecture marque `data:` ; son `notAction`, les clés partagées, ne fait que le restreindre) | Gothmog relit l'effet de sa panne dans les logs, par l'API de contrôle. À cette portée, ces droits n'atteignent que l'espace de logs : un ticket de support relève de l'abonnement |

Chaque action d'un rôle doit y figurer **telle qu'elle est écrite** : un joker n'est pas déplié
(`Microsoft.Compute/virtualMachines/*` sur une VM refuse), une action de données refuse, un rôle
illisible refuse, une portée plus bas qu'une VM (une extension) n'a que les lectures. Sur le
groupe, les droits effectifs relus (qui comptent aussi une attribution au-dessus du banc, ou une
que la liste n'a pas montrée) ne peuvent être que ces lectures et la lecture des attributions du
contrat (`contract_reader`, sur l'abonnement). Le reste → `identity_unlisted_right` → `passive`,
avec l'action et la portée dans le détail. Les attributions hors du banc ne changent pas : la
lecture des attributions, les deux conteneurs des canaux.

Ce que `infra/orodruin/main.tf` donne tient dans cette liste sans changement : les trois rôles
d'injecteur et `Log Analytics Reader` sur l'espace de logs. Un test lie la liste à ce rôle, et un autre relit sa définition publiée (JSON exact, action de données comprise) par la vraie lecture du contrat (`read_identity`) : `armed`.
**À constater après le prochain `orodruin-check`** : `armed`. Si Azure définissait `Log Analytics
Reader` autrement que la liste, le contrat dirait `identity_unlisted_right` en nommant l'action en
trop — l'échec est fermé, et il se corrige dans la liste, après lecture de la définition
(`az role definition list --name "Log Analytics Reader"`). Mutants M2883–M2887.

## L'image des injecteurs (CI3, #267, 29/10)

Avant CI3, `make orodruin-push` construisait l'image d'Annatar sur le poste de l'opérateur et
l'envoyait par SSH : rien ne liait ce qu'Orodruin exécute à ce que la CI avait éprouvé (P-02).

**Maintenant, `make orodruin-push [REF=<tag|commit>]`** (sans `REF`, le dernier tag `v*` ; jusqu'à la 0.5.3, c'est la v0.5.2, signée par l'ancien nom du dépôt et refusée : `REF=<sha de la fusion de REN1>`) :
1. **Sur le poste**, `scripts/published_image.py fetch annatar` : le commit de `REF`, qui doit être
   sur `origin/main` ; le digest de `ghcr.io/grootcyber/eregion-annatar:sha-<commit>`, lu sans jeton ;
   sa **signature** et sa **provenance** vérifiées par cosign (épinglé par son sha256) — le workflow
   `.github/workflows/publish.yml` de ce dépôt, sur `main`, déclenché par un push, **à ce commit** —,
   la provenance relue. Un échec à n'importe quelle étape : rien n'est envoyé.
2. **L'archive, construite à partir des blobs du registre** (OI1, `published_image.py archive`), lus
   sans jeton comme le manifeste : le manifeste linux/amd64 sous le digest prouvé (lui-même, ou celui
   que son index nomme), puis sa configuration et ses couches, chacune **par son digest**. Avant le
   premier octet, le manifeste est lu : un média attendu (un manifeste OCI ou docker v2, une
   configuration, des couches tar, gzip ou zstd — jamais une couche « étrangère », servie
   d'ailleurs), une taille bornée (4 Mo la configuration, 2 Go une couche, 4 Go toutes, 128 couches).
   Chaque blob est ensuite vérifié **par son sha256 et sa taille** contre le manifeste **avant
   d'entrer** dans l'archive ; la configuration doit dire le commit (son étiquette
   `org.opencontainers.image.revision`), linux/amd64, un utilisateur autre que root. Un blob absent,
   une empreinte fausse, une taille démesurée, un média inattendu : rien n'est envoyé, la cause est
   dite, `~/.eregion-image` et l'image d'Orodruin n'ont pas bougé. L'archive est celle qu'écrit `docker
   save` : `oci-layout`, `index.json` (qui la nomme `eregion-annatar:incoming`), le `manifest.json` de
   docker et `blobs/sha256/…` — le manifeste dans ses propres octets, sa configuration, ses couches.
   Avec elle, `expect.json` : ce qu'Orodruin devra relire. Un répertoire temporaire du poste, retiré à
   la fin. Le registre répond à un blob par une redirection vers son stockage
   (`pkg-containers.githubusercontent.com`) : le jeton du registre ne la suit pas sur un autre hôte,
   comme le client de docker.
3. **Par SSH**, `docker load` de cette archive, **sous un tag d'attente** (`eregion-annatar:incoming`) :
   **la sortie d'Orodruin reste fermée**, et l'image en service ne bouge pas encore. `~/.eregion-image`
   est effacé juste avant, et un reste d'`incoming` d'un envoi précédent retiré.
4. **Sur Orodruin, l'image arrivée est relue** (`docker image inspect`, tout son JSON), puis comparée
   sur le poste (`published_image.py loaded`) à ce qu'annoncent le manifeste prouvé et sa
   configuration : son **identifiant** (celui du manifeste au magasin containerd de docker, le digest
   de sa configuration au magasin classique — l'un des digests sous le digest vérifié), les **couches**
   et l'**utilisateur** de sa configuration, sa plateforme, son commit. **Une image sans sa
   configuration se relit sans couches ni utilisateur, ou pas du tout : refusée.** (La CLI de docker
   applique `-f` de son côté : `docker image inspect -f {{.Id}}` et `docker image inspect` passent par
   le même `GET /images/{name}/json`. L'issue a mesuré que `-f {{.Id}}` répondait pour l'image
   incomplète : l'API rend alors un JSON partiel, l'identifiant sans configuration ni couches.)
5. **Un run de contrôle, avant le tag** (OI2, #490) : l'image relue, et seulement elle, démarre une
   fois sur Orodruin —
   `timeout -k 10 120 docker run --rm --read-only --tmpfs /tmp --cap-drop ALL --security-opt
   no-new-privileges:true --pull never --network none --no-healthcheck --name eregion-annatar-check
   --entrypoint true eregion-annatar:incoming`. Créer un conteneur demande ses couches, présentes et
   dépaquetées : ce que la relecture ne dit pas (voir plus bas). S'il échoue, ou dépasse 120 s
   (`ORO_CHECK_TIMEOUT=<s>` sur la ligne de commande : des chiffres, au moins 1 s, sans zéro en tête
   — `timeout 00` ne borne rien —, validés avant tout envoi et jamais développés par make, comme
   `REF`), son conteneur (`timeout 30 docker rm -f`) et `incoming` sont retirés, la cause est dite
   (les mots de docker, puis les nôtres : le délai, docker qui n'a pas pu créer le conteneur — « une
   couche absente ou non dépaquetée ? » —, `true` qui ne s'exécute pas, ssh, ou le code),
   `eregion-annatar:orodruin` n'a pas changé et `~/.eregion-image` reste absent. Un conteneur de
   contrôle laissé par un envoi coupé est retiré au début du suivant, avec l'`incoming` qui restait.

   Alors seulement elle devient `eregion-annatar:orodruin`, le tag d'attente est retiré, et
   `~/.eregion-image` est écrit (« commit digest »). Sinon elle est retirée,
   `eregion-annatar:orodruin` n'a pas changé, et `~/.eregion-image` reste absent : il ne nomme jamais
   l'ancienne image comme si elle était la nouvelle.

**Pourquoi l'archive ne vient plus du `docker save` du poste** (OI1, #488, mesuré le 03/11). Sous
Docker Desktop, avec le magasin d'images containerd, `docker save` d'une image **tirée** rend son
index et son manifeste, sans configuration ni couches : environ 10 Ko pour environ 630 Mo, même après
un `docker pull` complet (une image construite sur le poste s'exporte entière). Orodruin chargeait
cette image incomplète ; son identifiant relu était bien l'un des attendus, et seul le `docker tag`
qui suivait l'arrêtait (« failed to read config content: NotFound »), en laissant `incoming` sur
Orodruin. Les blobs du registre ne dépendent ni du docker du poste, ni de son magasin. **Hypothèse, à
confirmer** : le magasin containerd jette le contenu des couches compressées une fois décompressées,
et l'exporteur de moby saute alors un manifeste dont les blobs manquent. OI1 n'en dépend pas.
**Le digest de la configuration, au magasin containerd** : `docker image inspect` n'y donne pas le
digest de la configuration, seulement celui du manifeste (l'identifiant). Les `diff_ids` et
l'utilisateur ne suffiraient pas à eux seuls : une autre configuration peut porter les mêmes, avec
une autre commande ou un autre environnement. Le lien est ailleurs : l'identifiant est le digest du
**manifeste prouvé**, et containerd adresse le contenu — il lit la configuration par le digest que ce
manifeste nomme, et refuse un blob dont le digest ne correspond pas. Les `diff_ids` et l'utilisateur
relus prouvent alors que cette configuration-là est présente et lisible.

**Ce que la relecture ne dit pas, et le run de contrôle** (OI2, #490). `docker image inspect` ne dit
pas si les couches sont présentes ni dépaquetées : au magasin containerd, `RootFS.Layers` vient de la
configuration, et `docker tag` ne lit qu'elle. Une couche perdue **après** un chargement réussi
passait la relecture et le tag, et ne se voyait qu'au premier run (dans les faux, la migration
d'`orodruin-push` : `make` sortait en erreur, `:orodruin` déjà remplacée). Le run de contrôle
(étape 5) crée un conteneur : docker doit alors monter chaque couche de la configuration, et refuse
s'il en manque une. Le risque restait faible : l'archive porte toutes les couches, vérifiées une à
une, ses fichiers d'index sont écrits en dernier (une archive tronquée ne se charge pas), et le reste
d'un envoi précédent est retiré avant.

**Le run de contrôle au regard du contrat : il reste dans la surface permise.** Les six garanties,
une à une :
- **Périmètre réseau** : `--network none` ne donne au conteneur que sa boucle locale, aucune
  interface vers l'extérieur — moins que la sortie fermée du contrat, qui admet le banc, le cloud et
  le modèle. `--pull never` : une image absente n'est jamais demandée à un registre (docker
  tenterait Docker Hub, hors périmètre ; la sortie fermée refuserait, mais rien ne part).
- **Identité limitée** : l'identité managée ne se lit que par IMDS (`169.254.169.254`), donc par le
  réseau : sans réseau, le conteneur ne peut pas obtenir de jeton. Aucune attribution, aucun droit
  ne change.
- **Cibles inscrites, plafond** : rien n'est injecté. `--entrypoint true` remplace la commande de
  l'image : ni Python, ni Annatar, ni Gothmog ne démarrent, aucune cible n'est lue ni touchée, rien
  ne compte au plafond.
- **Audit** : aucun appel au cloud, donc rien à journaliser avant ; le journal (`~/runs/orodruin`)
  n'est pas monté.
- **Arrêt d'urgence** : rien ne tourne au-delà du délai borné (120 s, puis `KILL` 10 s après) ; le
  conteneur est retiré (`--rm`, et `docker rm -f`, lui-même borné à 30 s, sur un échec) ; aucun
  healthcheck de l'image ne tourne (`--no-healthcheck`).
- Et ce qu'il ne prend pas de l'hôte : aucun montage (`-v`), ni `orodruin.env` (l'abonnement, la
  clé du modèle, le canal), ni variable d'environnement ; la racine en lecture seule, `/tmp` en
  tmpfs, aucune capacité, aucun gain de privilège — `ORO_HARDEN`, le durcissement de tout `docker
  run` d'un injecteur sur Orodruin (V-34) — et l'utilisateur de l'image, non root (relu à l'étape 4).

Il ne démarre **que l'image relue comme celle du manifeste prouvé** : jamais avant l'étape 4 (une
image d'un autre digest, d'un autre utilisateur ou sans sa configuration n'est jamais lancée), sur
une image dont chaque blob a été vérifié par son sha256 sur le poste, signée et attestée par
`publish.yml`. Le seul code de l'image qui s'exécute est son `/bin/true`, et il s'exécute dans une
surface plus étroite que les vrais runs qui suivent le tag : la migration (`ORO_MIGRATE`), avec le
réseau du contrat et `~/runs` monté ; puis les injecteurs, avec `orodruin.env`. Le run de contrôle n'ajoute donc rien à ce
qu'Orodruin peut faire ; il avance seulement, dans un conteneur qui ne peut rien, le premier
démarrage de l'image. Le contrat (`orodruin-check`) n'est pas lu avant : il dit si un injecteur peut
agir, et rien n'agit ici. Il se mesure au réel, avec Jonathan (`make orodruin-push REF=…`, voir
`docs/operations.md`).

**Pourquoi Orodruin ne tire pas lui-même.** Le contrat garantit une sortie limitée au banc, aux API
de contrôle du cloud et à l'API du modèle, vérifiée par une connexion hors périmètre qui échoue.
Tirer depuis GHCR demanderait `ghcr.io` et `pkg-containers.githubusercontent.com`, où ses blobs sont
servis : un nom de `*.githubusercontent.com`, le domaine que GitHub donne aussi pour le contenu de ses
utilisateurs (`api.github.com/meta`, `domains.packages`, lu le 29/10), et un NSG ne filtre que par
adresse, pas par nom. L'ouvrir ouvrirait un chemin de sortie bien
plus large que l'image. Vérifier sur le poste, puis relire l'image sur Orodruin (son identifiant, ses
couches, son utilisateur, depuis OI1), garde la garantie et prouve l'image. Aucun changement Terraform n'est donc nécessaire pour CI3 (le
commentaire du `custom_data` seul a changé : il est hors du heredoc, un plan ne montre rien).

**Le chemin de développement**, dit comme tel : `make orodruin-push-dev` construit l'image sur le
poste, **non vérifiée**, pour essayer une branche avant sa fusion ; `~/.eregion-image` dit
`dev <commit>`. Le contrat ne lit pas ce fichier : c'est une trace pour l'opérateur, pas une garde.
Il passe encore par `docker save` : une image construite sur le poste s'exporte entière (mesuré le
03/11), seule une image tirée perdait sa configuration et ses couches.

**Ce qui reste ouvert** : l'image n'est vérifiée que sur le poste qui l'envoie ; un poste compromis
enverrait autre chose et la relecture de l'image, comparée sur ce même poste, ne le verrait
pas. Le contrat (`orodruin-check`) ne lit pas encore la provenance de l'image qu'il exécute —
planifié.

## La demande de Dagorlad (DG-b, #348, 30/10)

La console de Dagorlad écrit une demande ; Orodruin la juge et la lance. Rien ne change au
contrat : ni droit, ni attribution, ni sortie réseau, ni canal. Conception :
[`docs/design/console.md`](console.md), §7, phase (b). Pas à pas : [`docs/operations.md`](../operations.md).

**Le transport, porté par l'opérateur.** `make orodruin-exercise REQUEST=<id>`, depuis son poste :
- la demande est tirée de H0 par SSH, la clé d'hôte vérifiée ;
- elle est affichée, et les noms des cibles destructives sont tapés sur le poste ;
- elle est copiée par SSH dans `~/requests/` d'Orodruin, avec les noms tapés à part
  (`<id>.typed.json`) ;
- elle est lancée dans l'image des injecteurs : `python -m eregion_core.exercise_runner`, `~/requests`
  monté en lecture seule. Les noms tapés sont retirés d'Orodruin quand le lancement se termine,
  quelle que soit sa fin (un `trap` du shell distant, sur `EXIT`, `HUP`, `INT` et `TERM`) ; là où il
  le peut (un répertoire qui n'est pas en lecture seule), le lanceur les retire lui-même dès qu'il
  les a lus (SEC14, R-11).

Orodruin ne tire rien et n'écoute rien : la commande vient de l'opérateur.

**Une demande se joue une fois, et fraîche** (SEC14, R-11). Sous le verrou, avant tout jugement :
- son identifiant est cherché dans le registre des demandes jouées
  (`runs/orodruin/requests/played.jsonl`) : déjà là, elle est refusée (`replayed`) ; un registre qui
  ne se lit pas ne laisse rien jouer ;
- elle doit avoir été écrite il y a moins de 6 h (`MAX_AGE_S`), et pas plus de 5 min dans le futur
  de l'horloge d'Orodruin : sinon, `expired` — une nouvelle demande se fait dans la console ;
- puis son identifiant est inscrit au registre, sur le disque avant le jugement : refusée ensuite
  (contrat passif, un fil refusé) ou coupée par un crash, elle ne rejoue jamais ici.

Ni `replayed` ni `expired` ne publient de statut : celui de la première fois reste le sien (ici, ou sur
un Orodruin d'avant celui-ci). Le registre vit sur le disque d'Orodruin : un Orodruin reconstruit le
perd, et c'est la limite de 6 h qui borne alors le rejeu.

**Le jugement** (`eregion_core/exercise_runner.py`). Il se fait dans cet ordre, et rien ne part si
un fil est refusé :
1. La demande est relue par son seul lecteur (`exercise_request.read`) : un champ de plus la refuse.
2. Le contrat : `check()`. S'il est `passive`, la demande est refusée (`passive`, puis les codes de ce
   qui manque).
3. Chaque fil est jugé avec les codes de la console (`exercise_plan.plan`) :
   - le périmètre, l'inscription et la zone, relus par l'identité d'Orodruin (O0) ;
   - la règle de production ;
   - la watch (V1) ;
   - les cibles du moteur d'une panne (`gothmog targets`, lues sans Orodruin) ;
   - le plafond déclaré (`EREGION_MAX_INJECTIONS`, `EREGION_MAX_RUN_S`), au lieu du seul plafond
     absolu.
4. Le nom tapé est comparé au nom qu'Orodruin lit de la VM (`typed_name`), pour chaque fil qui le
   demande : un fil destructif, technique ou panne, ou que personne n'a déclaré inoffensif (A0).
   `vm-shutdown` (`destructive: false`) n'en demande pas. Gothmog le recompare au nom qu'il lit,
   avant de démarrer une panne destructive ; une lecture d'Azure qui échoue là est un refus dit
   (`typed_name: the target's name unreadable…`), inscrit au rapport, jamais une exception (#358).

**Les fils, l'un après l'autre.** Chacun est un run de son injecteur, dans son propre processus (D1) :
`annatar wire <technique> <vm> --request <id> [--typed-name <nom>]`, `gothmog run <panne> --yes
--request <id> --target <vm>`. Avant chaque fil :
- le plafond **restant à la demande entière** : ses appels journalisés depuis son début (chaque ligne
  du journal nomme la demande, `Session.request`), et son temps. L'injecteur reçoit ce reste comme
  son propre plafond ;
- la watch, relue ;
- la cible relue et rejugée, et son nom (O0, à chaque injection) ;
- une VM dont une panne n'a pas vérifié son retour ne prend plus de fil (`not_returned`) : une panne
  et une technique ne se chevauchent jamais ;
- une VM tenue par Glorfindel est attendue `WAIT_ISOLATION_S` (20 min) au plus, puis son fil est
  sauté (`isolated`). Un injecteur ne défait jamais ce que Glorfindel a fait. « Tenue » se lit
  dans `eregion_core/held.py`, la même règle que le preflight d'Annatar :
  - une règle `glorfindel-iso…` ou `glorfindel-quarantine-` ;
  - sur le NSG de chaque carte de la VM et de chaque sous-réseau de ces cartes, lus depuis son
    `networkProfile`, quel que soit leur groupe ;
  - ce qui ne se lit pas vaut « tenue » (A0) ;
  - chaque chemin lu sur Azure est celui d'une ressource, tel qu'ARM l'écrit (`held.safe_path`) : ni
    requête, ni fragment, ni échappement, ni segment `.` ou `..`, ni caractère non imprimable (un
    contrôle, une inversion bidirectionnelle, un caractère de largeur nulle), ni barre oblique
    inverse (`\`, envoyée `%5C`). Un chemin refusé ne se lit pas : la VM est tenue (#358).

  Avant la relecture de DG-b, le preflight d'Annatar ne lisait que l'ancien nom fixe
  (`glorfindel-isolation-`), et dans le seul groupe de la VM : les isolations d'aujourd'hui
  (`glorfindel-iso-<vm>-<carte>-<empreinte>`) passaient. Lire les cartes et les sous-réseaux demande
  deux lectures de plus au rôle `injector_read` (`networkInterfaces/read`,
  `virtualNetworks/subnets/read`, sur le groupe du banc). Un NSG hors du banc ne se lit pas : la VM
  est tenue, et son fil sauté.

Chaque injecteur garde toutes ses gardes : Annatar compare aussi le nom tapé au nom de la VM qu'il lit
avant toute écriture, et Gothmog refuse une VM que la panne ne déclare pas. **Un fil, une VM** (relecture
de DG-b) : Gothmog compare la cible du fil aux VM de l'expérience par leur identifiant complet, jamais
par leur seul nom (la VM homonyme du jumeau n'est pas celle du banc). Une panne dont l'expérience
agit sur plusieurs VM est refusée (`no_engine`), dès le jugement : elle ne tourne jamais plus large
que ce que l'opérateur a vu et tapé. La fenêtre de chaque run
porte l'identifiant de la demande, ainsi que son rapport (`metrics.request`).

**Un run à la fois** (relecture de DG-b, point 5 ; #358 ; SEC14, R-10). Un seul verrou exclusif,
jamais attendu (`flock` sur un seul fichier, `exercise_runner.lock_path()`, pris par
`exercise_runner.request_lock`). Toute commande qui agit sur une cible le prend :
- une demande, le temps de tous ses fils ;
- chaque fil d'une demande (`annatar wire`, `gothmog run --request`), sous la prise de sa demande ;
- une campagne lancée à la main (`annatar campaign run`, `make orodruin-campaign-run`), quel que
  soit son `--runs-dir` : elle mettrait une technique sur une VM qu'un fil tient, ou sous sa panne ;
- un run lancé à la main (`annatar run <scénario>`), pour la même raison : rien de lancé à la
  main ne tourne pendant une demande ;
- un nettoyage (`annatar clean`) : il réécrit un disque ;
- une panne lancée à la main (`gothmog run <panne>`, après G1).

Un aperçu (`--dry-run`) ne lance rien et ne le prend pas ; `gothmog preflight` n'écrit rien et ne le
prend pas non plus.

**Un fil tient la prise de sa demande.** Le lanceur de la demande transmet son descripteur au
processus de l'injecteur qu'il lance (`pass_fds`, nommé par `EREGION_RUN_LOCK_FD`). Le fil reprend
ce même fichier ouvert : c'est la prise de la demande, son nom reste celui de la demande, et le fil
ne la relâche jamais. Un descripteur que la demande n'a pas transmis (un autre fichier, ou une autre
ouverture du verrou) n'est pas cette prise : un fil lancé à la main est refusé (`busy`) tant que
quelque chose tourne, et prend le verrou lui-même sinon.

Le premier écrit ce qui le tient (« request r-… », « campaign … », « run <scénario> »,
« clean <scénario> », « fault <panne> », « wire r-… ») ; le suivant est refusé (`busy`) sans
rien lancer ni ratifier, et dit lequel. Le verrou part avec le processus, un crash compris ; à une
sortie normale, le nom s'efface aussi. Le nom n'est qu'une indication : un refusé peut lire, le temps
de quelques microsecondes, un nom périmé ou à moitié écrit, et n'en montre que les caractères
imprimables.

**Où est le verrou.** Un seul fichier, quel que soit le répertoire où une commande écrit ses runs :
`EREGION_RUN_LOCK` s'il est posé, sinon `runs/orodruin/requests/.lock` depuis le répertoire de
travail. Sur Orodruin, c'est `/app/runs/…`, le même `$HOME/runs` que montent tous les conteneurs des
injecteurs (`make orodruin-exercise`, `make orodruin-campaign-run`, `make gothmog-run`). Une campagne
lancée avec un autre `--runs-dir` prend ce même verrou.

**La limite qui reste** : un fil prend le verrou (SEC14, R-10) ; son `--request` ne le dispense de
rien. Restent deux gestes d'un shell sur Orodruin : faire passer à la main le descripteur d'un verrou
qu'il tient lui-même (il ne tient alors que ce qu'il aurait pris), ou lancer un injecteur hors de
`/app` avec un autre `EREGION_RUN_LOCK` — un autre fichier, que rien ne voit. Le verrou évite un
chevauchement par mégarde ; il ne protège pas d'un opérateur qui le veut.

**Ce qu'Orodruin publie pour la console.** Dans le conteneur des fenêtres, sous `orodruin/` : même
conteneur, même attribution, rien de neuf.
- `orodruin/contract.json` : `armed` ou `passive`, les codes, l'heure ; ni détail, ni abonnement, ni
  identifiant. Il est écrit par `orodruin-check` et à chaque jugement d'une demande.
- `orodruin/requests/<id>.json` : le statut de la demande (jugée, refusée avec ses codes, en cours,
  finie) et, par fil, son rang, son état, son code, ses runs. Jamais l'expérience ni la cible : les
  fenêtres le disent déjà, comme avant.

La watch de H0 les tire dans `runs/orodruin/` avec les rapports de run. Chaque blob est relu contre sa
forme (`read_contract`, `read_status`) : un blob refusé n'est pas écrit. La console les relit à son
tour. Sans eux, elle dit « Orodruin: unknown here ».

**« Stop all »** reste `make orodruin-kill`, depuis le poste. La console donne la commande, les
fenêtres ouvertes qu'il fermera et leurs cibles, et ce qui reste en vol (voir plus haut, M-1).

**Mutants** M2010–M2039 (`scripts/mutation_check.py`). Tests :
- `tests/unit/test_exercise_request.py`, `test_exercise_runner.py`, `test_orodruin_word.py` ;
- `test_makefile_exercise.py`, avec de faux `ssh` et `scp` ;
- `test_annatar_wire.py`, `test_gothmog.py` ;
- `test_exercise_e2e.py` : de la console aux deux injecteurs, sur les faux.

**À éprouver au banc, avec Jonathan** :
- `make orodruin-lock YES=1` avant d'envoyer l'image : le contrat exige les deux lectures nouvelles,
  et un Orodruin sans elles dit `identity_missing_right`, donc `passive` ;
- le premier exercice réel ;
- la lecture des cartes, des sous-réseaux et de leurs NSG par l'identité d'Orodruin ;
- le blob `orodruin/` tiré par H0.

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
