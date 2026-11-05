# La file d'actions signée (FS1, #413) — conception

> **Statut : conception, 04/11 ; décisions de Jonathan le 04/11 (fin du document). FS1a fait le
> 05/11 (#551, §7) : le format et sa vérification, sans changement de comportement. FS1b fait le
> 05/11 (#563, §8) : la watch relève la file, la console et le bot y déposent — derrière
> `EREGION_ACTION_QUEUE=1`, faux par défaut : sans lui, rien ne change.** Ce document
> prépare FS1, le dernier prérequis de sûreté avant toute VM hors du banc (ROADMAP, « Critères de
> la 1.0 »).
>
> **Règle de lecture.** Ce qui est lu dans le code est une affirmation, avec son fichier et sa
> ligne (au commit `8710dba7`). Ce qui est dit d'Azure vient de la documentation : c'est une
> **hypothèse**, à mesurer sur le banc (§5).

## 0. En bref

- **Aujourd'hui**, la console et le bot écrivent sur Azure eux-mêmes : dans leur processus, ou par
  la CLI qu'ils lancent dans leur conteneur, sous leur propre identité. Sur H0, cette identité est
  celle de la VM, partagée par les trois conteneurs.
- **Avec FS1**, ils ne font plus que **déposer une demande**. Elle est signée par la clé du service,
  porte un verbe d'une liste fermée, une cible, une date d'expiration et un nonce, et s'écrit dans
  le répertoire de `runs/` de son service.
- **La watch** vérifie la demande avant tout appel au cloud : la signature, la fraîcheur, le rejeu.
  Elle la rattache ensuite à une proposition qu'elle a elle-même signée sur la carte, avec sa clé
  SEC19 sous `eregion.action-queue/1`. Elle rejoue les gardes du geste, puis exécute avec le même
  code et le même verrou de VM que pour ses propres actions.
- **Le résultat** revient dans un reçu, que seule la watch écrit et qu'elle signe. La console et le
  bot le lisent.
- **Ensuite**, la console et le bot deviennent lecteurs. Seule la watch tient le rôle d'écriture.
- **Le gain réel**, c'est le rétrécissement. Une console compromise ne tient plus un jeton
  d'écriture libre, ni `runCommand` : elle ne peut plus demander que des verbes fermés, sur des
  cartes que la watch a proposées, et chaque demande repasse les gardes. La signature ne prouve pas
  l'humain : la clé vit dans le service.

---

## 1. L'état actuel, lu dans le code

### 1.1 Les identités

| Service | Identité (compose) | Rôles (`docs/operations.md`, « Identités Azure ») |
|---|---|---|
| la watch | `GLORFINDEL_AZURE_CLIENT_*` → `AZURE_CLIENT_*` (`docker-compose.yml:76-78`, service `watch` : `:142-143`) | `Reader`, `Log Analytics Reader`, **Response**, **Session Drain** VM par VM |
| la console | `EREGION_CONSOLE_AZURE_CLIENT_*` (`docker-compose.yml:85-88`, service `war-room` : `:246`) | `Reader`, `Log Analytics Reader`, **Response**, **Restore**, **Session Drain** VM par VM, **Restore Neutralize** VM par VM |
| le bot | `GLORFINDEL_BOT_AZURE_CLIENT_*` (`docker-compose.yml:90-93`, service `bot` : `:200`) | `Reader`, **Response**, **Restore**, **Restore Neutralize** VM par VM |
| **H0** | les trois vides : l'identité managée de la VM, `SystemAssigned` (`infra/glorfindel-host/main.tf:147-149`) | `Reader` et `Log Analytics Reader` (`main.tf:189-199`) ; **Response** sur le groupe du banc, posée à la main (`docs/banc-bl1.md`, étape 3), hors de l'état ; **Session Drain** VM par VM (`main.tf:218-223`) ; jamais le restore (`main.tf:283-284`) |

`docs/operations.md` dit déjà la frontière qui reste : « la console et le bot écrivent sur Azure
avec leur propre identité […] Les rendre lecteurs seuls, c'est confier l'action approuvée à la
watch […] — planifié. »

Sur H0, le dépôt affirme que « le point de jeton de la VM répond à chacun [des conteneurs] » :
c'est la raison pour laquelle « une identité par conteneur ne s'y sépare pas ».

### 1.2 Les gestes d'écriture de la console (`eregion_console/api.py`)

Chaque route passe d'abord la frontière de SEC1 : l'hôte, l'origine, le jeton, un corps JSON
(`docs/design/console.md`, « La frontière de la console »).

| Geste (bouton) | Route | Chemin jusqu'à Azure | Sous quelle identité |
|---|---|---|---|
| Approve & execute, `isolate_vm` | `POST /api/action/approve/{esc_id}` (`:1416`) | `_approval_refusal` (`:1381`), puis `connector.isolate_vm` dans le processus (`:1449`), puis `_verify_approved` (`:1320`) : la vérification, le geste noté, une carte si la vérification échoue | la console, avec la coupure des sessions |
| Approve, `block_suspicious_ip` (scope `vm` ou `subnet`, IP saisie si la carte n'en a pas) | idem | `single_host_ip`, puis `connector.block_suspicious_ip` dans le processus (`:1491`), puis `_verify_approved` | la console |
| Approve, `snapshot` | idem | `action_snapshot` (`:1603`) → `jobs.start_snapshot` dans le processus (`:1620`) | la console |
| Approve, `release_isolation` | idem | `action_release` → la CLI `glorfindel release` en sous-processus (`:1132-1143`) | la console (la CLI tourne dans son conteneur) |
| Release | `POST /api/action/release/{vm}` (`:1132`) | la CLI `release <rid> --yes` | la console |
| Reset (ex-Revert) | `POST /api/action/revert/{vm}` (`:1146`) | la CLI `reset <rid> --yes` (`glorfindel/cli.py:2033`, `_do_reset` `:1965`) | la console |
| Extend to subnet (CON-K) | `POST /api/action/block-promote/{vm}?ip=` (`:1549`) | `_vm_block` (`:1508`), puis `connector.block_suspicious_ip(…, "subnet", True)` dans le processus (`:1569`) | la console |
| Unblock (CON-K) | `POST /api/action/unblock/{vm}?ip=` (`:1579`) | `_vm_block`, puis la CLI `unblock --yes -- <ip> <rid>` | la console |
| Snapshot | `POST /api/action/snapshot/{vm}` (`:1603`) | `jobs.start_snapshot` dans le processus | la console |
| Restore | `POST /api/action/restore/{vm}` (`:1683`) | `_restore_refusal` (`:1631`), puis `_bg_restore` en tâche de fond (`:2087`) : la CLI `restore --before` | la console (rôle Restore, neutralisation) |

La page grise ces boutons en lecture seule (`_WRITE_HANDLERS`, `eregion_console/static/glorfindel.js:2352`).
Le drapeau vient de `read_only_requested()` (`api.py:1220-1224`), c'est-à-dire de l'environnement
de la console.

### 1.3 Les gestes du bot (`glorfindel/bot.py`)

Chaque bouton passe d'abord `ButtonPolicy` (`:361`) : il est autorisé par l'id Discord de
l'utilisateur ou par un rôle, et fermé par défaut. La carte est relue au clic (`_still_waits`,
`:266`).

| Geste | Où | Chemin | Identité |
|---|---|---|---|
| Revert, sur une carte `verification_failed` | `_make_action_button` (`:685-703`) → `_ExecuteButton` (`:440`) | `_run_cli(["revert", rid, "--yes"])` (`:482-490`) : la CLI `reset` en sous-processus | le bot |
| Restore | `_RestoreButton` (`:549`) → formulaire → `_RestoreConfirmView.confirm` (`:642`) | `_run_cli(restore_args(…))` (`:671`) | le bot (Restore, neutralisation) |

Les autres boutons (Acknowledge `:769-777`, les verdicts `:711-732`) écrivent en local.
Command (`:793`) n'écrit rien : il montre la commande.

### 1.4 La watch, seule

La watch agit seule dans le graphe : `execute_action` (`glorfindel/agent.py:1761`), sous le mode
de la VM (`_apply_autonomy_mode`, `agent.py:1356`). La liste des actions autonomes est fermée et
réversible (`AUTONOMOUS_ACTIONS`, `glorfindel/response/policy.py:10`). Elle agit aussi hors cycle,
quand elle retire une règle orpheline, toujours dans le mode de la VM touchée
(`glorfindel/orphans.py`, `_ALONE`). Une action et une autre sur la même VM se sérialisent par
`_vm_lock` (`glorfindel/response/locks.py:61`), un `flock` entre processus.

### 1.5 Ce que la console et le bot écrivent en local, et qui oriente la watch

La console, le bot et la watch montent tous trois `~/.glorfindel` en écriture
(`docker-compose.yml:160`, `:213`, `:265`). La console y écrit :
- le mode d'une VM (`/api/activate` `:1234`, `/api/autonomy` `:1266`, le défaut `:1294`) ;
- les règles approuvées (`approve-rule` `:1953`, la couche du client) ;
- les acquittements et les verdicts (`:1702`, `:1709`).

Les CLI qu'elle lance y écrivent aussi l'état d'isolation et de blocage.

SID1 dit ce que cela ouvre : « tout conteneur qui l'écrit (watch, console, bot) peut y écrire une
coupure » (`glorfindel/providers/azure/own_run_command.py:39-45`). De même, une carte se forge dans
`escalations.jsonl`, et l'original d'une quarantaine se forge dans l'état d'isolation.

### 1.6 Ce qui en découle

1. **Une console ou un bot compromis tient un jeton d'écriture libre.** Le code écrit la commande
   d'avance ; avec le jeton, l'attaquant fait ce qu'il veut. Sur H0, c'est aussi `runCommand`, en
   root, sur gondolin et bree (modèle de menace, §5).
2. **Même avec une file**, la watch ne doit pas croire ce que la console peut écrire : une carte,
   un état. Sinon, une console compromise forge la carte, puis l'approuve.
3. **Sur H0, rendre la console lectrice exige de séparer les identités** d'un même hôte. C'est le
   seul vrai problème d'Azure de FS1 (Q3).
4. **Le restore n'est pas une action de la watch.** Elle ne restaure jamais, par décision (SEC7 :
   « même un bogue ou une décision détournée ne le pourrait pas »). Et les identités de la console
   et du bot doivent devenir lectrices (Q2).

---

## 2. Le modèle

### 2.1 Vue d'ensemble

```
console (jeton SEC1)          bot (ButtonPolicy)
   │ clé du service              │ clé du service
   ▼                             ▼
runs/console/queue/<id>.json   runs/bot/queue/<id>.json        ← un répertoire par écrivain (SEC18)
   └──────────────┬──────────────┘   (montés en lecture seule chez la watch)
                  ▼
watch : lire (borné) → forme → signature (clé épinglée) → fraîcheur → nonce (registre de la watch)
      → verbe permis à ce service → rattachement (proposition signée par la watch, ou son état)
      → gardes du geste → _vm_lock → exécution (le code de la watch) → vérification → noté
                  ▼
runs/glorfindel/queue/<id>.json  ← reçu signé par la watch (eregion.action-queue/1)
   ▲ lu par la console (déjà montée) et par le bot (montage ajouté, lecture seule)
```

### 2.2 Les verbes : une liste fermée

| Verbe | Rattaché à | Console | Bot |
|---|---|---|---|
| `isolate_vm` | une carte, et sa proposition | oui | non |
| `block_ip` (`scope` : `vm` ou `subnet`) | une carte ; l'IP de la proposition, ou celle de l'humain si la proposition n'en a pas (`api.py:1480-1487`) | oui | non |
| `snapshot` | une carte, ou une VM du périmètre de la watch | oui | non |
| `release_isolation` | une carte (`release_hold`), ou une isolation que la watch tient | oui | non |
| `reset` | une isolation ou des blocages que la watch tient ; pour le bot, une carte `verification_failed` | oui | oui |
| `unblock_ip` | un blocage de cette IP sur cette VM, que la watch tient (`_vm_block`) | oui | non |
| `promote_block` | idem, `scope` `vm` | oui | non |

Un verbe hors de cette liste est refusé, et le restore n'y est pas (Q2). Les verbes permis à
chaque service sont fixés dans le code de la watch, jamais lus dans la demande.

### 2.3 La demande

Un fichier JSON par demande, `<id>.json`. Il est écrit à côté, puis renommé
(`channel_reader.write_file`), en 0600, jamais à travers un lien.

```json
{
  "v": 1,
  "kind": "request",
  "id": "<128 bits aléatoires, hex : le nonce et le nom du fichier>",
  "service": "console",
  "by": {"via": "console-token", "user": "", "name": "", "session": "<8 hex de la session>"},
  "verb": "isolate_vm",
  "resource_id": "/subscriptions/…/virtualMachines/<vm>",
  "ip": "",
  "scope": "",
  "card": {"id": "<id de la carte>", "proposal": "sha256:<condensé de la proposition signée>"},
  "issued_at": "2026-11-04T10:00:00.000+00:00",
  "expires_at": "2026-11-04T10:02:00.000+00:00",
  "key": "SHA256:<empreinte de la clé du service>",
  "sig": "<Ed25519, base64>"
}
```

- **Les champs sont exacts.** Aucun de plus, aucun de moins, chacun de son type. Hors carte, `card`
  vaut `null`. C'est le principe de `eregion_core/exercise_request.py:94-96` : un champ de plus
  refuse la demande. La taille est bornée à 4 Ko.
- **Ce qui est signé** : `eregion.action-request/1`, un saut de ligne, puis le JSON canonique de
  tous les champs sauf `sig`. C'est `watch_key.message(domain, body)` (`eregion_core/watch_key.py:83-87`),
  sous un autre domaine. Une signature de demande ne se lit donc jamais comme un battement, ni comme
  ce que signe la watch.
- **`expires_at`** tombe au plus 120 s après `issued_at`. La console et la watch partagent l'hôte ;
  l'écart d'horloge toléré est de 30 s.
- **`by`** nomme l'humain, comme le service l'a authentifié (§2.7). C'est une parole du service,
  gardée au journal. Ce n'est pas une preuve.

### 2.4 La proposition, signée par la watch

C'est là que FS1 reprend la clé de la watch, comme SEC19 l'a prévu (`docs/design/watch-key.md`,
« FS1 reprend cette clé »). Quand la watch écrit une carte qui retient une action
(`glorfindel/escalations.py:130`, `record`), elle y joint une **proposition** :

```json
"proposal": {"v": 1, "kind": "proposal", "card": "<id>", "action": "isolate_vm",
             "resource_id": "…", "ip": "", "port": null, "escalation_type": "mode_hold",
             "issued_at": "…", "seq": 1730714400000, "key": "SHA256:…", "sig": "…"}
```

Elle la signe sous `eregion.action-queue/1`, avec `Signer.sign` (`watch_key.py:109-110`) et son
compteur `next_seq` (`:104-107`). Le champ `kind` est signé, si bien qu'une proposition ne se lit
jamais comme un reçu. La watch re-signe la proposition quand la carte se rafraîchit (`last_seen`).

La demande nomme le condensé de la proposition. À l'exécution, la watch :
- vérifie sa propre signature avec la moitié publique de sa clé en mémoire, et non avec une valeur
  lue sur le disque ;
- vérifie le condensé ;
- vérifie que la carte est encore en attente ;
- vérifie que la proposition n'a pas déjà servi : une proposition, une exécution, et la watch tient
  ce registre.

**Ce que cela ferme** : une carte forgée dans `escalations.jsonl` n'a pas de proposition qui tienne.
La console ne peut donc approuver que ce que la watch a proposé. Une carte écrite avant FS1, sans
proposition, est refusée (`proposal_missing`) : il faut la CLI, ou attendre que la détection se
reproduise.

**Une nuance (relecture de FS1a).** La dédup de `record` fond une détection dans la carte en attente
de même action, même cible et même type : une carte forgée qui attend reçoit donc la proposition de
la watch si la watch décide ensuite cette même action sur cette même VM. Ce qu'elle signe alors est
sa propre décision (l'action, la cible, le type), sauf le port, que la carte forgée a pu écrire dans
`action_params` et que la proposition reprend. Le texte de la carte forgée, lui, n'est pas signé.

### 2.5 Où la demande est déposée

**Dans le répertoire de `runs/` de son écrivain** (SEC18, `eregion_core/runs_layout.py:1-30`) :
- `runs/console/queue/` pour la console. La watch monte déjà `runs/console` en lecture seule
  (`docker-compose.yml:151`).
- `runs/bot/queue/` pour le bot. C'est un **nouvel écrivain**, `bot`, ajouté à `WRITERS`
  (`runs_layout.py:49`). Aujourd'hui, le bot écrit dans `runs/console/` avec la console
  (`runs_layout.py:9`). Avec un répertoire à lui, le répertoire dit l'écrivain, et la clé doit être
  celle de ce répertoire.

Pourquoi pas ailleurs :
- Pas `~/.glorfindel` : les trois services l'écrivent.
- Pas `~/.eregion/console/` : la watch ne doit jamais le monter, parce que le plan rouge de Dagorlad
  y vit (modèle de menace, §1, ligne « I »).

La watch ne vide jamais le répertoire d'un autre : elle le monte en lecture seule. La console et le
bot retirent leurs demandes une fois le reçu lu, ou au bout d'une heure.

**Le registre de la watch** (les nonces vus et les propositions consommées) vit dans un répertoire
que seule la watch monte : `~/.eregion/watch-queue/`, à côté de `~/.eregion/watch-key/`
(`docker-compose.yml:166`). Il n'est jamais sous `~/.glorfindel` ni sous `runs/`, comme la clé
(`watch_key.py:113-123`). Chaque entrée est gardée jusqu'à `expires_at` plus l'écart d'horloge ; une
proposition consommée l'est tant que sa carte vit.

### 2.6 Qui signe, avec quelle clé, et comment la watch la connaît

**Une paire Ed25519 par service** (Q1, l'option recommandée). La clé est tirée au premier démarrage
du service, dans le répertoire que lui seul monte : `~/.eregion/console/queue_ed25519`, à côté du
jeton de SEC10, et `~/.eregion/bot/queue_ed25519`, un répertoire nouveau. Les règles sont celles de
`watch_key.load_or_create` (`:184-229`) :
- 32 octets, en 0600 ;
- tirée dans un fichier à part, puis publiée par un lien ;
- jamais lue à travers un lien, ni quand elle appartient à un autre utilisateur ;
- refusée si elle est lisible par d'autres.

Ce mécanisme se factorise, sans être copié.

**La watch épingle les clés publiques**, comme l'injecteur épingle la sienne (SEC19). Elle les lit
dans **son environnement**, et nulle part ailleurs :
`EREGION_QUEUE_KEYS=console=ed25519:…,bot=ed25519:…`. Le geste est
`make queue-keys` (ce poste), ou `make glorfindel-host-queue-keys` (H0, par SSH, la clé d'hôte
épinglée). Il donne la ligne à poser dans `.envrc` ou dans `host.env`. Sans épinglage, la watch
refuse chaque demande de ce service, le geste dit, et la console grise ses boutons d'écriture en le
disant (§2.10).

Le reste suit :
- **Une clé tournée** est refusée avec les deux empreintes, comme un battement d'une autre clé
  (`watch_key.py:307-310`).
- **La watch ne tire pas de seconde clé** : SEC19 le voulait ainsi, et cela reste vrai. Les clés de
  la console et du bot sont celles d'autres signataires. Elles ne remplacent pas la sienne.

Une clé par humain, ou par session, est écartée pour FS1 (Q1) :
- **par session** : la clé vivrait dans le même processus, sans aucun gain ;
- **par humain** (une passkey dans le navigateur, WebAuthn) : c'est le seul choix qui ferme une
  console compromise. Mais il demande des comptes, ce que le modèle de menace écarte avant la 1.x
  (§1, « Choix assumé »), et le bot ne peut pas le porter.

### 2.7 L'humain

- **La console** : le jeton de SEC1 et sa session de 12 h. La demande porte
  `by.via = "console-token"` et un identifiant court de la session, une HMAC de sa date d'émission
  et jamais le jeton. Cela sépare deux navigateurs au journal. Il n'y a ni comptes ni rôles avant la
  1.x.
- **Le bot** : l'id Discord de l'utilisateur, autorisé par `ButtonPolicy` (`bot.py:361-385`). La
  demande porte `by.via = "discord"`, `by.user` (l'id) et `by.name` (son nom affiché, gardé tel quel
  au journal, échappé à l'affichage). La watch relit aussi `by.user` contre **sa propre copie** de
  `DISCORD_ALLOWED_USERS` et `DISCORD_ALLOWED_ROLES`, sans secret. Cela attrape un bot mal réglé,
  pas un bot compromis, qui peut nommer n'importe quel utilisateur autorisé : c'est écrit au §3.2.

### 2.8 La vérification par la watch

Un fil de la watch relève les deux répertoires chaque seconde. Chaque demande suit cet ordre, du
moins cher au plus cher : **aucun appel au cloud avant l'étape 9**, comme la garde V1.

1. **Lire** : un fichier ordinaire, sans lien, sans blocage, borné (le lecteur commun, SEC8 et
   SEC15). Sinon : `malformed`.
2. **La forme** : les champs exacts, leurs types, `kind = "request"`, `v = 1`. Sinon : `malformed`.
3. **Une signature** : sans `sig`, `unsigned`.
4. **La clé** : `key` doit être l'empreinte de la clé épinglée pour **ce répertoire**. Aucune
   épinglée : `no_key_pinned`, le geste dit. Une autre : `unknown_key`, les deux empreintes dites.
5. **La signature tient**, sous `eregion.action-request/1`. Sinon : `bad_signature`.
6. **`service`** est celui du répertoire et de la clé. Sinon : `wrong_service`.
7. **Le temps** :
   - `issued_at` plus de 30 s devant : `not_yet_valid` ;
   - `expires_at − issued_at` au-delà de 120 s : `too_long` ;
   - `expires_at` passée : `expired`.
8. **Le nonce** : `id` déjà vu, `replayed`. Le registre est écrit **avant** l'exécution, et un
   registre illisible ou qu'on ne peut écrire refuse : `seen_store_unavailable`. Pour une action,
   c'est l'inverse du compteur de SEC19, où un fichier qu'on ne peut écrire n'est pas un refus
   (`watch_key.py:335-339`) : ici, on ferme.
9. **Le verbe** : hors liste, `unknown_verb` ; hors des verbes de ce service, `verb_not_allowed`.
   Le débit est borné par service (30 demandes par minute) : au-delà, `rate_limited`.
10. **Le rattachement** : la proposition (§2.4), ou l'état que la watch tient pour cette VM ou cette
    IP. Sinon : `proposal_missing`, `proposal_mismatch`, `proposal_consumed`, `card_not_pending`
    ou `nothing_to_undo`.
11. **Les gardes du geste** (§2.9). Sinon : `guard`, avec la raison.
12. **La posture** : une watch en lecture seule (`GLORFINDEL_READ_ONLY`) refuse, `read_only`.

### 2.9 L'exécution : les gardes rejouées

**Une demande signée n'est jamais un passe-droit.** Une fois la demande vérifiée, la watch rejoue
les gardes que la console et le bot appliquent aujourd'hui. Elles passent du côté de la watch, et
le code est partagé, jamais recopié :
- l'approbation en un clic : les types de carte approuvables (`_APPROVABLE_TYPES`, `api.py:1362`),
  l'âge de la carte (`GLORFINDEL_APPROVAL_MAX_AGE_H`), un restore survenu après la carte
  (`_approval_refusal`, `api.py:1381`) ;
- aucune carte ancrée (`_ANCHORED_TYPES`, `api.py:1628` et `bot.py:65`) ;
- une IP qui est une seule adresse, hors de `never_block` (`blockable_ip`, `policy.py:143-157`) ;
  un `scope` qui vaut `vm` ou `subnet` ;
- une VM résolue sans ambiguïté (`AmbiguousVM`) et dans le périmètre de la watch ;
- pour `unblock_ip` et `promote_block`, le blocage de cette IP sur cette VM, jamais le premier venu
  (`_vm_block`, CON-K) ;
- pour le Revert du bot, une carte `verification_failed` en attente (`bot.py:697-703`).

**Les gardes du modèle ne s'appliquent pas** : la porte de confiance, les tirages qui s'accordent,
le mode. C'est le sens même d'une approbation humaine, et c'est déjà le cas aujourd'hui. Le mode
`human_only` retient l'action autonome, pas l'action qu'un humain approuve. Le destructif n'est
dans aucun verbe.

**L'exécution** se fait sous `_vm_lock`, avec les fonctions de la watch : celles d'`execute_action`
(`agent.py:1761`), et pour la levée, le reset et le déblocage, celles de la CLI, sorties de
`cli.py` en fonctions appelables. Ensuite, la vérification (ce que fait `_verify_approved`
aujourd'hui), le geste noté au fil, une carte `verification_failed` si la vérification n'est pas
`True`, et la carte réglée. Une demande en vol n'est jamais coupée au milieu.

### 2.10 Le retour : le reçu

La watch écrit `runs/glorfindel/queue/<id>.json`, en le remplaçant à chaque étape : `accepted`,
puis `done` ou `failed`, ou `refused` dès la vérification. Elle le signe sous
`eregion.action-queue/1`, `kind = "receipt"`.

Le reçu porte :
- la demande (son `id`, son verbe, sa cible) ;
- l'état, le code et la raison ;
- le résultat et la vérification ;
- l'heure.

Il ne porte jamais la signature de la demande, et jamais rien de ce qu'elle ne nomme pas.

- **La console** monte déjà `runs/glorfindel` en lecture seule (`docker-compose.yml:260`). La route
  d'approbation dépose la demande, puis attend le reçu `accepted` ou `refused` jusqu'à 10 s, et le
  rend. La page suit `done` ou `failed` par `GET /api/queue/<id>` : une levée multi-NIC prend des
  minutes (`api.py:1141`). Une demande expirée sans reçu se dit : « la watch n'a pas pris la demande
  en 120 s ».
- **Le bot** reçoit `runs/glorfindel/queue` en lecture seule, ce seul sous-répertoire, et dit le
  reçu dans le fil de la VM. La carte reste ouverte tant que le reçu n'est pas `done` (SEC4c).
- **L'état de la file** : la watch publie `runs/glorfindel/queue/status.json`, signé. Il dit sa
  posture (écriture ou lecture seule), les empreintes qu'elle épingle par service, et depuis quand
  elle relève la file. La console grise les boutons d'écriture quand ce statut manque, est périmé,
  ou ne connaît pas sa clé, et elle dit pourquoi. Le drapeau `read_only` de la page vient donc de la
  watch, et non plus de l'environnement de la console.
- **La signature des reçus** est une défense en profondeur. Sur un même hôte, le montage suffit ;
  la console ou le bot sur un autre hôte la vérifieraient avec la clé de la watch épinglée
  (`EREGION_WATCH_KEY`), comme un injecteur.

### 2.11 Les refus

| Code | Cas | Dit où | Carte |
|---|---|---|---|
| `malformed` | illisible, trop grand, un lien, un champ de plus ou de moins, un type faux | reçu, journal de la watch, compté | — |
| `unsigned` | sans signature | idem | **critique** : quelqu'un écrit dans la file de ce service |
| `no_key_pinned` | aucune clé épinglée pour ce service | reçu, statut (le geste) | — |
| `unknown_key` | signée d'une autre clé (une clé tirée de nouveau, ou une autre main) | reçu, avec les deux empreintes | **critique** |
| `bad_signature` | un champ changé après la signature, une signature faite pour un autre domaine | reçu | **critique** |
| `wrong_service` | la clé de la console dans le répertoire du bot, ou l'inverse | reçu | **critique** |
| `not_yet_valid`, `too_long`, `expired` | la fraîcheur (`expired` : la watch était arrêtée ou lente) | reçu | — |
| `replayed` | le nonce déjà vu | reçu | **critique** |
| `seen_store_unavailable` | le registre de la watch illisible ou qu'on ne peut écrire | reçu, journal | une carte (pas critique) |
| `unknown_verb`, `verb_not_allowed` | hors liste, ou hors des verbes du service | reçu | `verb_not_allowed` : **critique** |
| `rate_limited` | plus de 30 demandes par minute | reçu (le premier), compté | — |
| `proposal_*`, `card_not_pending`, `nothing_to_undo` | le rattachement | reçu | — |
| `guard` | une garde du geste (§2.9) | reçu, avec la raison | — |
| `read_only` | la watch en lecture seule | reçu, statut | — |

Les cartes critiques sont décidées par le code, comme celles d'AL1 et de SID1 : ni modèle, ni
action. Il y en a au plus une par service et par heure. Une demande refusée ne laisse jamais de
trace sur Azure. Chaque refus est compté, comme `channel_refusals.json` (SEC3).

### 2.12 Ce qui ne passe pas par la file

- **La CLI de l'opérateur** (Q4) : c'est un geste à la main sur l'hôte, dans le conteneur de la
  watch sur H0 (`docker exec`), ou avec le principal de la watch sur un poste (`AZURE_CLIENT_*`,
  `.envrc.example`). Elle garde l'appel direct : c'est l'issue de secours, et elle tient l'identité
  de la watch. « Seule la watch tient le rôle d'écriture » reste vrai. Lancée dans le conteneur de
  la console, la CLI y échoue, et c'est voulu.
- **Le restore** (Q2) : hors de la file, et hors de la console et du bot.
- **La demande de Dagorlad** (DG-b) : elle ne touche pas Glorfindel. Orodruin la juge, et
  l'opérateur la porte.

### 2.13 La watch arrêtée

Sans watch, aucune action humaine ne part de la console ni du bot : les demandes expirent, et c'est
dit. Il reste la CLI, dans un conteneur de la watch lancé pour l'occasion
(`docker compose run --rm watch glorfindel …`). C'est une perte de disponibilité, assumée : une
console qui tombe n'empêche déjà pas la watch d'agir (modèle de menace, §1, ligne « D ») ; une watch
qui tombe, la console ne la remplace plus.

---

## 3. Les menaces

### 3.1 Ce que FS1 ferme

- **Une console ou un bot compromis n'écrit plus sur Azure.** Son identité est lectrice : le jeton
  qu'il tire ne permet ni d'écrire un NSG, ni de lancer `runCommand`. C'est le point de SID1 : la
  commande libre, en root, sur une VM défendue.
- **Il ne peut demander que des verbes fermés** : sur des cartes que la watch a signées, ou sur ce
  que la watch tient. La watch rejoue chaque garde.
- **Une carte forgée ne s'approuve pas** : la proposition ne tient pas.
- **Une demande forgée par un autre écrivain, rejouée ou périmée est refusée**, et c'est dit.
- **SID1 se resserre** : seule l'identité de la watch peut lancer `runCommand`. Un `runCommand` sous
  une autre identité de Glorfindel devient un 403 sur Azure, et plus une coupure qu'on rattache.

### 3.2 Ce qu'il laisse ouvert

- **Une console compromise signe comme la console.** Elle peut demander toute levée, tout reset et
  tout déblocage de ce que la watch tient, et donc défaire un confinement. Elle peut approuver toute
  carte en attente. La signature lie le service, pas l'humain. Seule une clé par humain fermerait ce
  point (Q1, l'option 2, en 1.x).
- **Le bot nomme l'humain** ; il ne le prouve pas.
- **La watch compromise, root sur l'hôte, ou la clé SSH de H0** : l'identité d'écriture est à leur
  portée. C'est le même périmètre qu'aujourd'hui, en moins de conteneurs.
- **L'état local que la console et le bot écrivent encore** (`~/.glorfindel`) : l'original d'une
  quarantaine, que la levée réassocie, une coupure enregistrée, un mode d'autonomie, une règle
  approuvée, un acquittement. Une console compromise s'en sert pour faire agir la watch.
  **FS1f le ferme** (Q5) : ces écritures passent par la file, et la console et le bot montent
  `~/.glorfindel` en lecture seule.
- **La CLI** garde l'appel direct (Q4).
- **Sur H0, la séparation des identités** repose sur ce que l'option retenue au Q3 tient : un
  pare-feu, ou un montage. Elle se mesure (§5).

### 3.3 La mise à jour du modèle de menace

Le lot qui ferme FS1 (FS1e) écrit ces changements dans `docs/design/modele-de-menace.md` :
- **§5, la ligne « E »** de l'identité de réponse partagée : « Seule la watch tient l'écriture. La
  console et le bot sont lecteurs, et une action humaine est une demande signée, vérifiée, puis
  rejouée par les gardes (FS1) » ; SID1 y reste, resserré.
- **§5, « Ouvert »** : « l'action approuvée confiée à la watch seule, par une file signée —
  planifié : #413 » passe dans « ce qui tient ». « L'identité unique de H0, partagée par la watch,
  la console et le bot » se ferme selon le Q3. « Une identité managée par conteneur » reste
  ouverte.
- **§5, l'encadré de la posture de H0** : « un clic d'approbation dans la console, ou un bouton du
  bot, écrit sur le banc » devient « dépose une demande que la watch juge ».
- **§2** : les nouveaux répertoires, `runs/console/queue/` et `runs/bot/queue/`, le registre de la
  watch, les reçus. S et T : une demande forgée, rejouée, d'un autre écrivain. E : une carte ou un
  état forgés.
- **§3, la ligne « E »** (« un bouton exécute plus que prévu ») : il dépose une demande, et la watch
  la juge.
- **§1** : la ligne « E » d'une console compromise ; le choix assumé (« un jeton, tous les droits de
  la console ») se lit désormais comme « tous les verbes de la file ».

---

## 4. La migration

### 4.1 L'ordre

1. **La file à côté de l'appel direct** (FS1a, FS1b). La watch relève la file et l'exécute. La
   console et le bot ne déposent une demande que si `EREGION_ACTION_QUEUE=1` ; sinon, l'appel
   direct reste. Rien ne change par défaut.
2. **La file par défaut** (FS1c). On la mesure au banc avec Jonathan, puis l'appel direct ne reste
   que derrière `EREGION_ACTION_QUEUE=0`, le temps d'une release.
3. **Les identités lectrices** (FS1d). Les rôles de la console et du bot sont retirés, et H0 est
   séparé (Q3). À partir de là, l'appel direct échoue sur un 403, et c'est dit.
4. **Le retrait de l'appel direct** (FS1e). Plus aucun appel d'écriture dans `eregion_console/` ni
   dans le bot, prouvé par un test. Le modèle de menace passe au « tenu ».
5. **Les écritures locales** (FS1f, selon le Q5).

### 4.2 Les gestes de Jonathan

- **L'épinglage** : `make glorfindel-host-queue-keys`, puis la ligne `EREGION_QUEUE_KEYS` dans
  `host.env`. Sur un poste : `make queue-keys`, puis `.envrc`.
- **Les copies de la liste Discord** dans l'environnement de la watch (§2.7).
- **Au banc, avec FS1c** : une approbation d'isolation sur gondolin par la file, puis sa levée, et
  un Revert du bot. On y vérifie les reçus et les cartes critiques (une demande non signée déposée
  à la main).
- **Les identités, avec FS1d, dans cet ordre**, pour qu'aucune approbation ne reste sans
  exécutant :
  1. la file par défaut, mesurée ;
  2. le plan de H0 relu, sans `YES` ;
  3. la séparation de H0 appliquée (Q3) ;
  4. sur un poste, `az role assignment delete` de **Response**, **Session Drain**, **Restore** et
     **Restore Neutralize** pour la console et le bot ; `session_drain_principals` vidé ;
     `restore_principals` selon le Q2 ;
  5. `az role assignment list --assignee <principal> --all` ne montre plus que `Reader` (et
     `Log Analytics Reader` pour la console).
- **Une release** : la release de FS1c doit être publiée avant FS1d.

### 4.3 Les tests

Ni Azure ni modèle, avec un `HOME` jetable, comme toute la suite.
- **`tests/unit/test_action_queue.py`** : le format, la signature, un refus par code du §2.11, et
  l'ordre de la vérification (une demande non signée n'atteint jamais le faux connecteur).
  S'y ajoutent :
  - un registre illisible, qui refuse ;
  - un même nonce, accepté une fois ;
  - une proposition consommée ;
  - une signature de demande lue comme proposition, ou de battement lue comme demande, toutes deux
    refusées, comme `test_a_signature_under_another_domain_never_reads_as_a_heartbeat`.
- **`tests/unit/test_action_queue_watch.py`** : le fil de la watch sur le faux Azure. Une demande
  acceptée exécute une fois, se vérifie et écrit son reçu. Une carte forgée, sans proposition, est
  refusée. Les gardes de `_approval_refusal` sont rejouées. Le Revert du bot passe, son isolate est
  refusé.
- **Le bout en bout** : `tests/unit/console_client.py`. Un clic d'approbation donne une demande,
  puis la watch, puis le reçu, puis la réponse de la route. Et le bot donne la même chose.
- **La machine à invariants** (`tests/unit/test_invariants.py`, le faux Azure) : une action
  « demande de la console » s'ajoute. Une propriété nouvelle : toute écriture sur Azure est faite
  par l'identité de la watch (le faux Azure note l'appelant), et aucune écriture ne suit une demande
  refusée.
- **Les montages** (`test_runs_mounts.py`, `test_profiles.py`) : la watch monte `runs/console` et
  `runs/bot` en lecture seule. Le bot monte `runs/glorfindel/queue` en lecture seule, et rien d'autre
  de `runs/glorfindel`. Aucun service ne monte `~/.eregion/watch-queue/` sauf la watch, et aucun ne
  monte les clés d'un autre.
- **La frontière du code** (FS1e), un test statique comme `test_provider_boundary.py` : aucun module
  de la console ni du bot n'appelle une écriture du connecteur, ni la CLI d'écriture.
- **Les mutants** : un par contrôle de la vérification, et un par garde rejouée. Une quarantaine en
  tout. La plage se demande à l'Orchestre, jamais choisie seul.

### 4.4 Les lots et leurs estimations

En jours de travail effectif, à ±50 %, comme la ROADMAP.

| Lot | Contenu | Sessions | Estimation |
|---|---|---|---|
| **FS1a** ✅ 05/11 | Le format et sa vérification : `eregion_core/action_queue.py` (forme, domaines, signature, fraîcheur, nonce, les refus), la clé de service tirée (factorisée avec `watch_key`), la proposition signée sur les cartes par la watch. Tests et mutants. Aucun changement de comportement. | Glorfindel | 2–3 j |
| **FS1b** ✅ 05/11 | La watch relève la file : le fil, le registre, le rattachement, les gardes rejouées (sorties de la console en code partagé), l'exécution sous `_vm_lock`, les reçus et le statut signés, les cartes critiques. La console et le bot déposent, derrière `EREGION_ACTION_QUEUE=1`. Le nouvel écrivain `runs/bot/`, les montages. | Glorfindel, Console, bot | 4–5 j |
| **FS1c** | La file par défaut. Les routes d'approbation deviennent asynchrones (`GET /api/queue/<id>`, la page suit le reçu), le bot dit le reçu, les boutons grisés selon le statut de la watch. La mesure au banc avec Jonathan. | Console, bot, Tests | 2–3 j |
| **FS1d** | Les identités lectrices : le compose, `docs/operations.md` « Identités Azure », le Terraform de H0 selon le Q3, les rôles de la console et du bot, `GLORFINDEL_OWN_CALLERS`, la préparation (`check_permissions`) qui dit une console qui écrit encore. Les gestes de Jonathan. | H0 (Infra), Glorfindel | 2–3 j + gestes |
| **FS1e** | Le retrait de l'appel direct, le test de frontière du code, le modèle de menace (§3.3), SID1 resserré. | Glorfindel, Console | 1–2 j |
| **FS1f** | Selon le Q5 : le mode, les règles approuvées, les acquittements et les verdicts passent par la file ; la console et le bot montent `~/.glorfindel` en lecture seule. | Glorfindel, Console, bot | 3–4 j |
| FS1g | Seulement si le Q2 retient l'option 2 : un exécuteur de restore à part. | Glorfindel, H0 | 3–4 j |

**Total** : de 11 à 16 j pour FS1a–e. Avec FS1f, de 14 à 20 j. FS1g en sus.

---

## 5. Les hypothèses à mesurer (Azure, Docker)

Elles sont tirées de la documentation, jamais mesurées ici. Chacune se mesure au banc avant d'être
écrite comme un fait.
1. Le point de jeton de la VM (IMDS, `169.254.169.254`) répond à tout processus de la VM qui le
   joint, conteneurs en réseau `bridge` compris, sans autre preuve que l'en-tête `Metadata: true`.
   Le dépôt l'affirme pour H0 (`docs/operations.md`), sans mesure citée.
2. Une identité managée attribuée par l'utilisateur, ajoutée à la VM, est servie par le même point
   à quiconque le joint et donne son `client_id`. Ajouter une identité ne sépare donc pas les
   conteneurs.
3. Une règle de la chaîne `DOCKER-USER` qui coupe `169.254.169.254` à un réseau Docker coupe le
   point de jeton à ses conteneurs, et à eux seuls. Un conteneur sans `NET_ADMIN` (`cap_drop: [ALL]`)
   ne peut pas la défaire (Q3, l'option recommandée).
4. Un principal à certificat dont la clé est tirée sur l'hôte, seul le certificat public étant
   téléversé (`az ad app credential reset --cert`), s'utilise par `EnvironmentCredential`
   (`AZURE_CLIENT_CERTIFICATE_PATH`) sans que la clé privée quitte l'hôte. Mais une fois volé, il
   s'utilise **hors de la VM**, contrairement à un jeton d'identité managée.
5. Une écriture refusée (403) d'une identité lectrice apparaît dans le journal d'activité. Si c'est
   le cas, une règle d'AL1 et de SID1 pourrait la dire.

---

## 6. Questions pour Jonathan

Une à la fois, l'option recommandée en premier.

**Q1. Qui signe la demande ?**
1. **Une clé par service (console, bot)**, épinglée chez la watch, et la watch signe ses
   propositions *(recommandé)*. Raison : le gain de FS1 est dans le rétrécissement (§3.1), et la
   signature lie la demande à son écrivain, indépendamment des montages. Le code de SEC19 sert
   presque tel quel. Ce que ça change : deux clés à épingler (un geste par hôte), et une console
   compromise signe encore comme la console (§3.2).
2. **Une clé par humain** (une passkey WebAuthn dans le navigateur), la console ne faisant que
   relayer. Ce que ça change : ferme la console compromise, mais demande des comptes et un
   enrôlement (le « choix assumé » du §1, avant la 1.x). Le bot ne la porte pas : ses boutons
   deviendraient un lien vers la console. Environ +5 à 8 j.
3. **Aucune clé côté service** : la provenance vient du seul répertoire (SEC18), et la proposition
   reste signée par la watch. Ce que ça change : aucun geste d'épinglage, mais la demande n'est plus
   « signée » au sens de #413, et un montage mal réglé suffit à la forger.

**Q2. Le restore, qui n'est pas une action de la watch ?**
1. **Hors de la file, et hors de la console et du bot** *(recommandé)*. Leurs boutons Restore
   montrent le plan (le moment, les points) et la commande. Le restore part de la CLI d'un poste,
   avec un principal de restore qu'on prend pour cette seule commande. C'est le principal de la
   console, renommé `EREGION_RESTORE_AZURE_CLIENT_*`, qui tient **Restore** et **Restore
   Neutralize** ; `restore_principals` le nomme. Raison : ainsi, la watch ne restaure jamais (SEC7),
   les services longs deviennent lecteurs, et le destructif reste un geste à la main. Ce que ça
   change : un clic de moins dans la console et le bot, et rien sur H0, qui ne restaure déjà pas.
2. **Un exécuteur de restore à part**, un quatrième service qui ne relève que les demandes de
   restore signées et ne tient que Restore. Ce que ça change : le bouton reste, mais il faut une
   identité de plus à séparer (sur H0, le même problème que le Q3) et le lot FS1g (+3 à 4 j).
3. **La watch restaure, sur une demande signée.** Ce que ça change : c'est le plus simple, mais cela
   défait la décision de SEC7, et une watch compromise pourrait écraser des disques. Déconseillé.

**Q3. Sur H0, comment séparer l'identité de la watch de celle de la console et du bot ?**
1. **L'identité managée reste à la watch, et le point de jeton est coupé à la console et au bot**
   par une règle du pare-feu de l'hôte (`DOCKER-USER`, posée par `deploy.sh`, sur un réseau Docker à
   eux) *(recommandé)*. Ils lisent avec un principal lecteur, dont le secret ou le certificat est
   dans `host.env`. Au démarrage, chacun vérifie qu'il ne joint **pas** le point de jeton, et refuse
   de démarrer s'il le joint. Raison : l'identité d'écriture reste liée à la VM, et ce qui peut fuir
   n'est qu'un lecteur. Ce que ça change : une règle de pare-feu à mesurer (hypothèse 3), un
   principal de plus, et `deploy.sh` qui a besoin de `sudo`.
2. **L'identité managée devient lectrice, et la watch écrit avec un principal à certificat** dont la
   clé est tirée sur H0, dans un répertoire qu'elle seule monte, comme sa clé de SEC19. Ce que ça
   change : pas de pare-feu, et des montages déjà testés en CI. Mais un certificat volé écrit
   **depuis n'importe où**, jusqu'à sa révocation (hypothèse 4), et il expire.
3. **Deux VM** : la watch seule sur l'une, la console et le bot sur l'autre. Ce que ça change : la
   séparation la plus nette, mais l'état de `~/.glorfindel` est aujourd'hui partagé entre eux, ce
   qui fait une refonte, et une VM à payer.

**Q4. La CLI de l'opérateur ?**
1. **Elle garde l'appel direct**, sous l'identité de la watch *(recommandé)*. C'est le geste à la
   main sur l'hôte et l'issue de secours quand la watch est arrêtée (§2.13). Raison : qui tient un
   shell sur l'hôte tient déjà l'identité. Ce que ça change : rien pour l'opérateur, mais la CLI
   reste un chemin hors de la file, dit au modèle de menace.
2. **Elle passe aussi par la file**, avec une clé « opérateur ». Ce que ça change : un seul chemin
   et un seul journal, mais plus d'issue de secours sans watch, et une troisième clé.

**Q5. Les écritures locales qui orientent la watch (le mode, les règles approuvées, les
acquittements), et l'état que la console écrit encore ?**
1. **Elles passent par la file dans FS1f, et FS1f fait partie du prérequis** avant toute VM hors du
   banc *(recommandé)*. Raison : sans lui, une console compromise forge l'original d'une quarantaine
   ou une coupure, puis la watch agit dessus avec son identité d'écriture (§3.2). Ce que ça change :
   +3 à 4 j avant la sortie du banc, et la console et le bot montent `~/.glorfindel` en lecture
   seule.
2. **FS1f après la sortie du banc**, le point dit ouvert au modèle de menace. Ce que ça change : on
   sort du banc plus tôt, mais avec un chemin connu d'une console compromise vers les écritures de
   la watch.
3. **Pas de FS1f.** Ce que ça change : la file ne protège que les gestes sur Azure, et l'état local
   reste le maillon faible.

## Les décisions de Jonathan (04/11)

| Question | Décision |
|---|---|
| Q1, qui signe | Une clé Ed25519 par service (console, bot), épinglée chez la watch ; la watch signe ses propositions sous `eregion.action-queue/1`. |
| Q2, le restore | **Un exécuteur de restore à part** (FS1g). Le bouton reste dans la console et le bot : en pleine urgence, l'opérateur n'écrit pas de commande. Le clic dépose une demande signée ; l'exécuteur, seul à tenir Restore et Restore Neutralize, la vérifie, rejoue les gardes et restaure. La watch ne restaure jamais (SEC7). C'est aussi la seule voie propre vers un restore autonome encadré, si on le veut un jour. |
| Q3, H0 | IMDS coupé à la console, au bot et à l'exécuteur par une règle `DOCKER-USER` que pose `deploy.sh`. L'identité managée reste à la watch ; les autres ont leur principal (lecteur, ou restore pour l'exécuteur) ; un conteneur qui joint IMDS refuse de démarrer. À mesurer au banc. |
| Q4, la CLI | L'appel direct reste, sous l'identité de la watch : c'est l'issue de secours. Le modèle de menace le dit. |
| Q5, l'état local | FS1f fait partie du prérequis avant toute VM hors du banc. |

Les lots, dans l'ordre : FS1a, FS1b, FS1c, FS1d, FS1e, FS1f, FS1g (17 à 24 jours estimés).

## 7. FS1a, fait (05/11, #551)

Le format et sa vérification sont dans le code. **Personne ne lit encore la file pour agir** : la
console et le bot gardent l'appel direct, aucune file n'est relevée, aucune demande n'est déposée.

- **`eregion_core/action_queue.py`** : la demande (§2.3, `REQUEST_FIELDS`, 4 Ko au plus,
  `new_request`), la proposition (§2.4, `PROPOSAL_FIELDS`, `sign_proposal`, `digest`), les deux
  domaines (`eregion.action-request/1` pour ce que signe un service, `eregion.action-queue/1` pour
  ce que signe la watch : proposition, puis reçu et statut, séparés par `kind`, signé), la liste
  fermée des verbes (`VERBS`, `SERVICE_VERBS` : la console tous, le bot `reset` seul ; ouverte à
  l'extension par ces seules constantes) et celle des refus (`REFUSALS`, chacun avec sa raison ;
  `CRITICAL`, les refus qui feront une carte critique).
- **La vérification** (§2.8, étapes 1 à 9), `verify_request`, sans réseau ni appel au cloud :
  lire borné (`read_request`, le lecteur commun : jamais un lien, jamais bloquant), la forme exacte
  (un champ en double refusé aussi), la signature, la clé épinglée pour ce répertoire, la signature
  qui tient, le service, le temps (`not_yet_valid` au-delà de 30 s d'avance, `too_long` au-delà de
  120 s de vie, `expired` à partir de `expires_at`), le nonce (le registre écrit avant toute
  exécution ; illisible ou qu'on ne peut écrire, il refuse : `SeenFile`, sous
  `~/.eregion/watch-queue/seen.json`), le verbe et le débit (`Rate`, 30 par minute et par service).
  Une demande signée par la clé épinglée d'un autre service est `wrong_service`, pas
  `unknown_key`. Le rattachement à la carte (étape 10) : `proposal_refusal` (la carte attend, sa
  proposition est celle de cette watch, inchangée depuis — action, cible, adresse, **port**, type —,
  celle que la demande nomme, pour ce verbe, cette cible et cette adresse, jamais exécutée).
- **Une signature, une seule écriture** (relecture de FS1a) : `watch_key.signature_bytes` n'admet
  que la forme canonique du base64 (86 caractères et `==`, lus en entier, sans saut de ligne, sans
  bit inutilisé du dernier caractère). Avant, 16 écritures d'une même signature tenaient, donc 16
  condensés d'une même proposition, et le registre des propositions consommées se contournait. La
  même règle vaut pour le battement et les détections (SEC19, SEC21) : la watch n'écrit que cette
  forme (`base64.b64encode`), un test le vérifie.
- **Les clés des services** : `load_service_key` tire et charge la clé de la console
  (`~/.eregion/console/queue_ed25519`) et celle du bot (`~/.eregion/bot/queue_ed25519`) par le code
  même de la watch (`watch_key.load_or_create`, sous un autre nom de fichier) : un seul code de
  tirage, deux usages. La clé de la watch, sa place, ses messages et ce qu'elle signe ne changent
  pas (`tests/unit/test_action_queue.py`, une signature connue calculée avant FS1a). Personne ne
  tire encore une clé de service : FS1b, au premier dépôt. L'épinglage : `EREGION_QUEUE_KEYS`
  (`pinned_keys`), lu dans l'environnement de la watch seulement.
- **La proposition sur les cartes** : la watch (`glorfindel watch`, sa clé de SEC19) joint sa
  proposition signée à chaque carte qu'elle écrit et qui retient une action qu'un humain peut lancer
  (`proposable` : un type approuvable en un clic avec son action, ou `verification_failed` pour son
  reset), et la signe de nouveau quand la carte se rafraîchit. Une carte écrite par la console, le
  bot ou la CLI n'en porte pas. Une clé indisponible ou une signature qui échoue n'empêche jamais
  la carte d'être écrite.
- **Tests** : `tests/unit/test_action_queue.py` (un test par refus, un par domaine, la fraîcheur
  aux bornes, le rejeu, le registre, la clé factorisée), `tests/unit/test_action_proposal.py` (la
  proposition sur les cartes, son contrôle). Mutants M3865–M3879 et M3945–M3954
  (`scripts/mutants/FS1a.py`).

**Pour FS1b.**
- **L'âge d'une carte** : la `issued_at` signée de la proposition remplace `last_seen` (que la
  console peut écrire) pour l'âge de l'approbation (`GLORFINDEL_APPROVAL_MAX_AGE_H`).
- **Ne re-signer qu'au-delà d'un âge.** Re-signée à chaque rafraîchissement, la proposition change
  de condensé : une demande déposée juste avant qu'une détection qui dure ne rafraîchisse sa carte
  nomme l'ancienne et est refusée (`proposal_mismatch`). FS1b ne re-signe qu'une proposition plus
  vieille qu'un seuil, assez court pour que l'âge reste juste.
- **La console importe `action_queue.APPROVABLE_TYPES`** au lieu de sa copie `_APPROVABLE_TYPES`
  (aujourd'hui, un test les garde égales).
- **`deploy.sh` et le Makefile créent `~/.eregion/bot`** au nom de l'opérateur, avant les services,
  comme `~/.eregion/watch-key` : laissé à docker, il serait à root, et le bot ne tirerait pas sa clé.
- **Un registre durable** : `SeenFile.claim` écrit sans `fsync` ; après un crash de l'hôte, un nonce
  réclamé peut être perdu et sa demande rejouée dans sa fenêtre. FS1b synchronise le fichier et son
  répertoire avant de rendre la main.
- **Borner les réclamations par service** : le débit n'est compté qu'après la réclamation du nonce.
  Une clé de service compromise remplit `seen.json` de nonces valides (un déni de service du
  registre, qui refuse alors tout). FS1b borne les réclamations par service et par minute avant le
  registre, ou borne le registre par service.
- **L'adresse et la portée** : une proposition sans adresse laisse la demande en nommer une
  (`block_ip`, l'IP saisie par l'humain) ; `ip` et `scope` ne sont pas validés ici. Les gardes de
  FS1b les jugent avant tout appel : une seule adresse, hors de `never_block` (`blockable_ip`), et
  `scope` qui vaut `vm` ou `subnet`.
- **Les verbes sans carte** (`snapshot` d'une VM du périmètre, `release_isolation`, `reset`,
  `unblock_ip`, `promote_block` sur ce que la watch tient) se rattachent à l'état de la watch :
  `nothing_to_undo`, `guard` et `read_only` ont leur code ici, leur contrôle sera dans FS1b.
- **Les propositions consommées** : `proposal_refusal` prend leur ensemble (`consumed`) ; leur
  registre est à FS1b, à côté de `seen.json`.

## 8. FS1b, fait (05/11, #563)

**Derrière `EREGION_ACTION_QUEUE=1` seulement**, lu par les trois services (`action_queue.enabled` :
« 1 », rien d'autre) ; vide, le défaut, rien ne change — aucune file n'est lue, aucune demande
écrite, l'appel direct reste (`tests/unit/test_action_queue_watch.py` le prouve pour la watch, la
console et le bot). Chaque point du §7 « Pour FS1b » est tenu :

- **La watch relève la file** (`glorfindel/queue_watch.py`, lancé par `glorfindel watch`) dans un fil
  à elle, chaque seconde, au plus 16 demandes par service et par passage ; une demande acceptée
  s'exécute dans un fil de travail (4 au plus), sous `_vm_lock`, jamais coupée au milieu : ni la
  boucle ni le battement n'attendent. Sans sa clé, rien n'est relevé, et c'est dit.
- **L'ordre** : le nom du fichier doit être son nonce ; un reçu `received` d'abord ; puis §2.8,
  étapes 1 à 9 (`verify_request`) ; l'étape 10 (`proposal_refusal`, ou ce que la watch tient pour un
  verbe sans carte : `nothing_to_undo`) ; l'étape 11, les gardes ; l'étape 12, `read_only` ; la
  proposition consommée ; le reçu `accepted` ; l'exécution ; `done` ou `failed`.
- **Les gardes rejouées** sont sorties de la console en code partagé (`glorfindel/approval.py`,
  appelé par la console et par la watch, jamais recopié) : l'approbation en un clic
  (`approval_refusal`), dont **l'âge se lit sur l'`issued_at` signé de la proposition**, jamais sur
  `last_seen` ; une adresse seule hors de `never_block` (`blockable_ip`) et une portée `vm` ou
  `subnet` ; la VM du périmètre de la watch (découverte, ou tenue, ou d'une carte en attente) ; le
  blocage de cette IP sur cette VM ; pour le bot, son humain relu contre la copie de
  `DISCORD_ALLOWED_USERS` et `DISCORD_ALLOWED_ROLES` de la watch (un rôle n'est lisible que par le
  bot : listé, il suffit). La console importe `action_queue.APPROVABLE_TYPES`.
- **L'exécution** : les fonctions de la watch — le connecteur, et pour la levée et le reset celles de
  la CLI, sorties de `cli.py` en `glorfindel/gestures.py` (`release_needed`, `reset_targets`,
  `reset_apply`, que la CLI appelle aussi) ; puis `approval.verify_approved` (une carte
  `verification_failed` si la vérification n'est pas `True`) et la carte réglée.
- **Le registre** (`~/.eregion/watch-queue/`, que seule la watch monte) : les nonces (`seen.json`) et
  les propositions consommées (`consumed.json`, 30 jours), **écrits durablement** (`fsync` du fichier,
  puis du répertoire, `channel_reader.write_file(…, sync=True)`) ; **le débit compté avant le
  registre** (le contrôle de `Rate` passe avant la réclamation : une clé prise ne le remplit pas) ;
  **illisible, sous quelque forme, il refuse et ne lève jamais** (`seen_store_unavailable`, une
  carte `queue_unavailable`). Une proposition, une exécution : un échec la consomme aussi.
- **Un arrêt brutal entre la réclamation et l'exécution** : le reçu `received` ou `accepted` reste ;
  au démarrage, la watch le dit `failed` (`interrupted`) et ne rejoue jamais la demande — sans ce
  reçu, la relecture aurait dit `replayed`, une carte critique pour son propre arrêt.
- **Les reçus et le statut**, signés sous `eregion.action-queue/1` (`kind` `receipt`, `status`) :
  `runs/glorfindel/queue/<service>-<id>.json` (le nom du service devant le nonce : les deux services
  ne partagent pas l'espace des noms) et `status.json` (la posture, les empreintes épinglées, depuis
  quand, les refus comptés). Un reçu ne porte jamais la signature de la demande. Ils sont gardés 2 h
  et retirés une fois leur demande partie.
- **Les cartes critiques** (`queue_tampered`, le groupe `CRITICAL`) : décidées par le code, sans action,
  au plus une par service et par heure, ancrées sur `~/runs/<service>/queue` (aucune VM).
- **La console et le bot déposent** (`action_queue.ask` : la clé du service tirée au premier usage,
  la demande écrite dans son répertoire en 0600, le reçu attendu, la demande retirée une fois
  répondue, les oubliées au bout d'une heure) : les routes d'écriture de la console
  (`eregion_console/action_requests.py`, `docs/design/console.md`), le Revert du bot (`reset`, sa
  carte `verification_failed` et sa proposition, `by.via = "discord"`). La console note le geste
  dans `runs/console/manual_actions.jsonl` à partir du reçu.
- **Le nouvel écrivain `runs/bot/`** (`runs_layout.BOT`), ses montages : la watch monte `runs/bot` en
  lecture seule ; le bot monte `runs/bot`, `runs/glorfindel/queue` en lecture seule (ce seul
  sous-répertoire) et `~/.eregion/bot` ; la watch, `~/.eregion/watch-queue` et `EREGION_QUEUE_KEYS`.
  `deploy.sh` et le Makefile créent `~/.eregion/bot`, `~/.eregion/watch-queue` et
  `runs/glorfindel/queue` au nom de l'opérateur, avant les services.
- **La proposition re-signée au-delà d'un âge seulement** : une carte revue garde la sienne tant
  qu'elle tient (cette clé, la carte inchangée) et a moins de 10 min (`escalations.RESIGN_AFTER_S`,
  `action_queue.proposal_fresh`).
- **Les clés à épingler** : `make queue-keys` (ce poste) et `make glorfindel-host-queue-keys` (H0),
  préparés, pas lancés (`docs/operations.md`, « La file d'actions signée »).
- **Tests** : `tests/unit/test_action_queue_watch.py` (le bout en bout sur le faux Azure, chaque refus,
  le rejeu, la carte forgée, la clé d'un autre service, le drapeau absent, un registre illisible,
  un arrêt entre la réclamation et l'exécution, les gardes rejouées, la console et le bot, les
  montages) ; mutants M3975–M4014 (`scripts/mutants/FS1b.py`).

**Pour FS1c** (relecture de FS1b) :
- **Le bot écrit encore `runs/console`** (`manual_actions.jsonl`, la CLI qu'il lance) : un bot
  compromis peut remplacer ou noyer les demandes de la console — rien ne s'exécute, mais la carte
  critique désigne la console à tort. Les gestes du bot dans `runs/bot/`, ou la file de la console
  dans un répertoire que le bot ne monte pas.
- **L'attente de `_queued` dans la console** : un sémaphore, ou un exécuteur à elle, pour qu'une
  rafale de clics n'occupe pas tous les fils du serveur pendant 600 s.
- **Un reçu présent mais non signé par la clé épinglée** se distingue d'« aucun reçu »
  (`read_receipt` rend `None` dans les deux cas) : le dire, plutôt que « la watch n'a pas pris la
  demande ».
- **Le texte de `proposal_consumed` après un échec** : dire que l'exécution précédente a échoué et
  qu'il faut une nouvelle détection, ou la CLI.
- **Le `signal_id` de la carte `verification_failed` née de la file** (`approve-<carte>` aujourd'hui,
  celui de la console) : lui donner celui de la demande.
- **Les tests sans drapeau** des routes release, revert, unblock, promote et snapshot (celle
  d'approbation l'a déjà).

**Ce qui reste** : FS1c (la file par défaut, les routes asynchrones, les boutons selon le statut, la
mesure au banc), FS1d (les identités lectrices), FS1e (le retrait de l'appel direct, le modèle de
menace au « tenu », §3.3), FS1f (les écritures locales), FS1g (l'exécuteur de restore). La machine à
invariants ne connaît pas encore l'action « demande de la console » (§4.3) : FS1c.
