# Inbox — Session War Room

Messages en attente pour la session UI/UX War Room.

---

## Non traités

### [Glorfindel → War Room] Réponse — constantes /api/config stables + import paths — 2026-06-12 ✅ Traité

**Traité 2026-06-13** (commit `c7223c8`) : popover de capacité livré. `/api/state` expose `capability` (autonomous/gated/allow_destructive/confidence_threshold) importé de `actions.py` ; badges autonomie cliquables → popover 3 tiers. Seuil lu depuis l'env (pas hardcodé). Read-only caveat ajouté comme tu l'as suggéré. 283 tests OK.

Réponse à ton heads-up « matrice de capacité d'autonomie ». Les 4 sont **stables, aucun plan de changement** — importe-les telles quelles :

- `from glorfindel.actions import AUTONOMOUS_ACTIONS, HUMAN_APPROVAL_REQUIRED` — `set[str]`, **source unique dans `actions.py`** (agent.py les ré-importe ; importe depuis `actions`, pas `agent`).
- `allow_destructive` : `load_glorfindel_config().autonomy.allow_destructive` (`list[str]`, vide par défaut — axe séparé du mode, pas contrôlé par human_only/non_disruptive).
- Seuil confiance : **pas une constante exportée** — c'est `float(os.environ.get("GLORFINDEL_CONFIDENCE_THRESHOLD", "0.7"))`. Lis l'env avec défaut `"0.7"` côté api.py (ne hardcode pas 0.7, l'opérateur peut l'override).

**Sémantique des tiers pour le popover** (stable) :
- `AUTONOMOUS_ACTIONS` → réversible : **autonome** en non_disruptive, **retenu (mode_hold)** en human_only.
- `HUMAN_APPROVAL_REQUIRED` → destructif : **toujours gaté**, quel que soit le mode (la gate destructive ne dépend pas du mode).
- Gate confiance → une action autonome avec `confidence < seuil` est escaladée (⚠) même en non_disruptive.
- Note read-only : sous `GLORFINDEL_READ_ONLY=1`, même une action « autonome » échoue à l'exécution → `write_blocked`. Si tu veux être exact, le popover pourrait griser « autonome » quand `read_only` est actif (déjà exposé dans `/api/state`).

Je te préviens avant si je touche à l'une de ces constantes/sémantiques.


### [Jonathan → War Room] Surfacer la CAPACITÉ d'autonomie, pas juste le mode — TODO demain 2026-06-13 ✅ Livré

**Livré 2026-06-13** (commit `c7223c8`) : badge autonomie cliquable (header + cartes) → popover capacité contextuel au mode résolu, exactement comme la proposition ci-dessous. À valider visuellement.

**Date** : 2026-06-12 (noté pour demain)

**Constat** : le badge/tooltip dit *qu'*il agit seul (`non_disruptive`) mais pas *ce qu'*il a le droit de faire seul. Le tooltip actuel (« New discovered assets act autonomously ») ne lève pas la vraie question de confiance de l'opérateur : « si je mets non-disruptive, qu'est-ce que Glorfindel exécute SANS me demander ? ».

**Modèle de capacité réel (3 tiers)** :
1. **Autonome** (s'exécute sans demander, en `non_disruptive`) — TOUS réversibles : `isolate_vm`, `block_suspicious_ip`, `snapshot`, `release_isolation`, `revoke_temp_access`.
2. **Toujours gaté** (escalade quel que soit le mode) — irréversibles : `restore_from_backup`, `delete_resource`, `wipe_storage`, `modify_network_rule`, `escalate_permissions`.
3. **Gate de confiance** : toute action autonome avec `confidence < 0.7` (GLORFINDEL_CONFIDENCE_THRESHOLD) → escaladée quand même.

Le mode ne change QUE le tier 1 : `human_only` → tier 1 aussi escaladé (rien ne s'exécute) ; `non_disruptive` → tier 1 s'exécute (sous gate confiance) ; tier 2 toujours gaté. `allow_destructive` (config) = axe séparé, vide par défaut.

**Proposition UI** : rendre le badge autonomie **cliquable** → petit popover « capacité » contextuel au mode résolu :
```
NON-DISRUPTIVE — agit seul
✅ Sans demander (réversible) : isolate · block IP · snapshot · release · revoke
🔒 Demande toujours (irréversible) : restore · delete · wipe · modify NSG
⚠ + confiance < 70 % → escalade quand même
```
```
HUMAN-ONLY — recommande seulement
👁 N'exécute rien — toute action escaladée (même réversible)
```
- Popover du badge **header** = capacité du défaut global ; popover du badge **carte** = capacité résolue de CETTE VM (override + allow_destructive pris en compte).

**Dépendance backend** (à faire avant le front) : exposer la matrice dans `/api/config` (ou `/api/state`) — `autonomous_actions`, `gated_actions` (HUMAN_APPROVAL_REQUIRED), `allow_destructive`, `confidence_threshold`. Les listes vivent dans `agent.py`/`actions.py` ; `api.py` (périmètre War Room) peut les importer. Coordination Glorfindel si les constantes bougent.

**Pourquoi ça compte** : c'est la décision de confiance centrale du produit (« jusqu'où je le laisse agir »). Aujourd'hui l'opérateur doit lire le code ou `glorfindel-config.yaml.example` pour savoir. À surfacer dans l'UI.

---

### [Tests → War Room] Lot UX « posture » — grisage read-only + indicateurs + régime/autonomie — 2026-06-12

**Réponse Tests 2026-06-12** : les 4 axes validés visuellement sur run live OBSERVE-ONLY. **#2 — ta déviation est acceptée, tu as raison** : ma prémisse « watch active = doublon du point GLORFINDEL » était fausse. Une fois le point GLORFINDEL = agrégat de santé des 3 modules, `watch active` (moteur tourne) et la santé backends sont deux questions distinctes (le moteur peut processer pendant qu'un backend est en erreur). Ta résolution est supérieure à ma proposition — `watch active` reste, je ne demande pas son retrait. **2 angles non couverts par ce run read-only, à confirmer au prochain run ACTIVE** (non bloquant) : (1) régime bascule en ⚡ ACTIVE ambre sans le flag ; (2) boutons write non grisés en active (`_applyReadOnlyGuards` ne déborde pas). Rien d'autre à corriger.

---

**Date** : 2026-06-12 — **Traité** : 2026-06-12 (les 4 axes) — retours Jonathan post-validation observe-only. Le fil rouge : l'UI ne communique pas clairement la **posture** de Glorfindel (peut-il agir ? agit-il seul ?) et disperse des indicateurs redondants. 4 axes, le #1 est décidé, les #2–4 sont des propositions à challenger.

---

**#1 — Griser les boutons d'action write en read-only (DÉCIDÉ — implémenter).**

Contexte : sous `read_only` (déjà exposé par `/api/state`, c'est ce qui allume OBSERVE-ONLY + `_guardReadOnly()`), cliquer une action write → toast d'erreur (réactif). On veut du **préventif**.

- **Griser (disabled + tooltip)** les boutons qui font un **write Azure** : `Approve & execute`, `Snapshot`, `Release`, `Reset`, `Restore`, `Unblock`. Tooltip : « Read-only credentials (observe-only) — write actions disabled ».
- **Garder ACTIFS** : `Ack` (purement local, `escalations.jsonl`, aucun appel Azure — le pair observe-only doit pouvoir clore ce qu'il a lu, sinon `pending` gonfle à l'infini) et `Cmd` (affiche juste la commande CLI).
- **Ne PAS cacher** les boutons : en observe-only, voir « Isolate VM (88%) recommandée » + le bouton grisé EST la proposition de valeur (montrer ce que Glorfindel aurait fait). Cacher = retirer l'info.
- Base de décision = `read_only` de `/api/state` (le flag déclaré). Le cas « Reader sans flag » (Test 2) reste géré par le `write_blocked` réactif — complémentaire, pas redondant.

---

**#2 — Indicateurs verts redondants (proposition).**

Plusieurs points verts répondent à la **même question** « le système tourne ? » : `watch active` (header), `live` (header), et le point de la carte GLORFINDEL. Règle : un indicateur = une question distincte. Il y a 3 questions réelles :
- moteur en marche ? (watch heartbeat frais)
- vue à jour ? (WS connecté = `live`)
- backends sains ? (DETECT/PROTECT/RECOVER)

Proposition : `watch active` et le point GLORFINDEL font doublon → en garder **un** comme santé moteur (le point de la carte GLORFINDEL devient l'**agrégat** des 3 modules : vert si tout ok, ambre si un dégradé). `live` reste (fraîcheur UI, info distincte). Les points par backend gardent leur valeur.

---

**#3 — Régime observe/active asymétrique et terne (proposition — le plus important).**

Aujourd'hui on matérialise observe-only (faiblement), mais le mode **actif (read-write) n'est pas matérialisé du tout** → l'absence de badge = actif. L'info la plus critique de l'UI (Glorfindel peut-il toucher mon infra ?) est implicite dans un de ses deux états. Dangereux.

Proposition : **indicateur de régime permanent**, toujours présent, qui bascule explicitement avec couleur + icône + label :
- **👁 OBSERVE-ONLY** — couleur calme (cyan/bleu) — « observation, aucune action »
- **⚡ ACTIVE** — couleur capacité d'agir (ambre/vert vif) — « Glorfindel peut exécuter »

Placement proéminent près du titre (statut de sécurité = position d'autorité), pas en bout de ligne. La symétrie tue le piège « pas de badge = j'oublie que je suis en actif ».

---

**#4 — Mode d'autonomie : remonter le défaut global + exergue par déviation (proposition).**

Le défaut global est enterré dans Config alors que c'est le mode que prendra **tout nouvel asset découvert**. → Le remonter dans le header, à côté du régime #3 (les deux forment un « panneau de posture »).

Cartes VM : garder le mode par carte, mais **mettre en exergue uniquement ce qui dévie du défaut** (évite le sapin de Noël) :
- VM au défaut global → badge discret
- VM avec override per-asset → badge marqué + couleur selon l'escalier de confiance (human_only calme → non_disruptive ambre)

L'opérateur scanne et repère immédiatement les exceptions.

---

**Vue d'ensemble — 2 axes orthogonaux à exposer ensemble dans le header :**

| Axe | Question | États |
|---|---|---|
| Régime credentials (#3) | peut-il toucher Azure ? | observe-only ↔ active |
| Mode d'autonomie (#4) | agit-il seul ? | human_only ↔ non_disruptive |

```
GLORFINDEL · War Room    👁 OBSERVE-ONLY  ·  default: human_only        ● live    [Run ▾][▶][⚙]  20:05
                         └─ régime (couleur) ─┘   └─ autonomie ─┘
```

**Bonus cohérence (raffinement, hors scope immédiat)** : observe-only **+** un asset en non_disruptive = contradiction (le mode dit « agis », les creds disent « tu ne peux pas » → c'est le `write_blocked`). L'UI pourrait le signaler discrètement.

**Priorités** : #1 décidé (à faire). #3 = le plus de valeur (sécurité/lisibilité). #2 et #4 = qualité de vie. À toi de challenger les propositions #2–4, c'est ton périmètre.

---

### [Tests → War Room] Feed — dédupliquer les events d'escalade identiques — 2026-06-12

**Date** : 2026-06-12 — **Traité** : 2026-06-12 — observé au Test 2 (run ~19:11 UTC)

Le live feed War Room affiche deux entrées `escalate → isolate_vm` (88% et 92%) à 3s d'écart, correspondant à deux cycles indépendants (Annatar `attack_started` + RulePoller) qui ont tous deux escaladé la même action sur la même VM. `escalations.jsonl` ne contient qu'**une seule entrée** — le dedup Glorfindel fonctionne. Le doublon est dans le feed UI uniquement.

**Fix suggéré** : dans le feed, collapser les events `escalate` avec même `action` + `resource_id` + `escalation_type` arrivant dans une fenêtre courte (~5s), ou afficher une annotation "(x2)" plutôt que deux lignes identiques. L'opérateur voit une seule vraie escalade dans `pending` — le feed ne doit pas laisser croire qu'il y en a deux.

---

### [Glorfindel → War Room] Nouveau type `action_failed` + fin du faux ISOLATED — 2026-06-11

**Date** : 2026-06-11 — **Traité** : 2026-06-12 — commit `b2a41c3`

Deux choses pour l'UI :

1. **Nouveau type d'escalade `action_failed`** (en plus de `write_blocked`) : échec Azure non-auth pendant l'exécution d'une action (transitoire / config). Même traitement UI que `write_blocked` côté rendu (action recommandée + erreur), mais message « échec d'exécution » plutôt que « credentials lecture seule ». Si tu as un mapping label par type, ajoute-le.

2. **Faux positif ISOLATED corrigé** : `isolate_vm` n'écrit plus l'état `~/.glorfindel/isolation/<vm>.json` quand l'appel NSG échoue (403). Donc la War Room n'affichera plus `ISOLATED` / « 1 isolation active » pour une VM dont l'isolation a en réalité échoué. Rien à changer côté UI — c'est juste que `/api/state` ne te remontera plus ce faux état.


### [Glorfindel → War Room] Nouveau type d'escalade `write_blocked` — 2026-06-11

**Date** : 2026-06-11 — **Traité** : 2026-06-12 — commit `902951a`

Quand Glorfindel tente une action mais que les credentials sont read-only (ou IAM 403), l'escalade porte maintenant `escalation_type: "write_blocked"` (en plus des `mode_hold`/`low_confidence`/`destructive_action` existants). C'est un **capability gap**, pas un choix de politique.

**UI** : si tu as un rendu/label par type d'escalade, ajoute `write_blocked` → message du genre « Action recommandée mais impossible : credentials lecture seule ». Le bouton « Approuver & exécuter » sur ce type **échouera aussi** (même cause) → soit le griser pour `write_blocked`, soit afficher l'erreur claire au clic. Cohérent avec la note read-only précédente. Le payload porte `action` (recommandée) + `confidence` + `suggested_steps` comme les autres.


### [Tests → War Room] Subtitle escalade — "detection timeout" affiché pour event detection — 2026-06-09

**Date** : 2026-06-09 — **Traité** : 2026-06-09 — commit `19ec3b8`

**Constaté** : War Room carte VM affiche `T1136.001 · medium · detection timeout` pour une escalade `low_confidence` générée depuis un event `detection` (21s). Le run 20260609T114747Z est bien un `event: detection`, pas `detection_timeout`.

**Root cause probable** : le subtitle de la carte (ou esc-item) hardcode le label "detection timeout" pour le type `low_confidence`, parce qu'historiquement toutes les `low_confidence` T1136.001 venaient de `detection_timeout`. Depuis `expected_latency_s` (dd48b12), T1136.001 détecte via `detection` mais génère toujours une escalade `low_confidence` (confidence 35% < gate 0.7).

**Fix attendu** : le subtitle doit afficher l'event type réel depuis l'escalade, pas le inférer depuis `escalation_type`. Source à utiliser : champ `signal.event` ou `event` dans le payload de l'escalade (probablement dans `raw_signal.event` ou le signal stocké avec l'escalade).

- `event: "detection"` → afficher "detection" (ou le TTP + severity suffit)
- `event: "detection_timeout"` → afficher "detection timeout"
- `escalation_type: "low_confidence"` n'implique plus un event particulier

---

### [Tests → War Room] Modal escalade — titre stale + bouton Snapshot manquant — 2026-06-09

**Date** : 2026-06-09 — **Traité** : 2026-06-09 — commit `10f4ef5`

Suite du fix `e810fab`. Deux éléments manquants dans la **modal** d'escalade (pas la carte) :

1. **Titre modal** : affiche toujours "Forensic snapshot created" alors que la carte affiche correctement "Snapshot recommended". Le même fix `executed: false → "recommended"` doit être appliqué au titre de la modal.

2. **Bouton Snapshot dans la modal** : la carte a le bouton 📸, la modal n'en a pas (juste Ack + Cmd). L'opérateur lit les suggested_steps dans la modal et décide là d'agir — c'est le bon endroit pour le bouton. Même comportement que sur la carte (`POST /api/action/snapshot/<vm>` + badge jobs.py).

---

### [Tests → War Room] Escalade low_confidence snapshot — label trompeur + bouton manquant — 2026-06-09

**Date** : 2026-06-09 — **Traité** : 2026-06-09 — commit `e810fab`

**Problème** : quand Glorfindel escalade avec `action_pending: snapshot, executed: false` (confidence < 0.7), la carte VM affiche "Forensic snapshot created" — ce qui est faux. Le snapshot n'a pas été pris.

**Double fix nécessaire :**

1. **Label** : distinguer `executed: true` vs `executed: false` dans le rendu du titre de la carte.
   - `executed: true` → "Forensic snapshot created" ✅ (correct, c'est fait)
   - `executed: false` + `action_pending: snapshot` → "Forensic snapshot recommended" ou "Snapshot pending"

2. **Bouton manquant** : quand `action_pending: snapshot` et `executed: false`, ajouter un bouton **📸 Snapshot** sur la carte d'escalade. L'humain doit pouvoir déclencher le snapshot depuis la War Room sans chercher la commande CLI.
   - Bouton appelle `POST /api/action/snapshot/<vm>` (endpoint existant)
   - Après clic → badge "Snapshot in progress..." (jobs.py déjà implémenté)

**Contexte** : pour T1136.001 (création de compte, confidence 35%), Glorfindel recommande un snapshot forensique mais ne l'exécute pas (confiance trop faible pour agir seul). L'opérateur War Room voit "created" et pense que c'est fait. C'est un faux sentiment de sécurité.

---

### [Glorfindel → War Room] jobs.py livré — `/api/jobs/<vm>` à implémenter — 2026-06-08

**Date** : 2026-06-08 — commit `10ae917` — **Traité** : 2026-06-08 — commit `ae81e23`

`jobs.py` partagé est livré. `~/.glorfindel/active_jobs/<vm>.json` est écrit dès que CLI lance un snapshot ou restore (non-bloquant par défaut).

**Format du fichier job** :
```json
{
  "job_id": "snapshot-vm-annatar-victim-20260608T123456Z",
  "type": "snapshot|restore",
  "resource_id": "/subscriptions/.../vm-annatar-victim",
  "vault": "rsv-annatar",
  "snap_id": "rsv:vault/rg/job123",        // snapshot uniquement
  "restore_job_name": "restore-job-abc",    // restore uniquement
  "rg": "rg",                              // restore uniquement
  "status": "InProgress|Completed|Failed",
  "started_at": "2026-06-08T12:34:56+00:00",
  "completed_at": null
}
```

**À implémenter dans `api.py`** : endpoint `/api/jobs/<vm>` qui lit `~/.glorfindel/active_jobs/<vm>.json` via `jobs.get_job(vm_name)`. Retourne `null` si pas de job actif.

**À implémenter dans `index.html`** :
- Poller `/api/jobs/<vm>` toutes les 5s (ou inclure dans `/api/state`)
- Badge sur la carte VM : `🔄 Restoring...` (type=restore, status=InProgress) ou `📸 Snapshot in progress...` (type=snapshot)
- Badge disparaît automatiquement quand `status=Completed` ou `Failed`
- Si `Failed` : badge rouge

**Note** : `jobs.start_snapshot()` et `jobs.start_restore()` sont les fonctions à appeler depuis `api.py` pour les boutons War Room existants — ça unifie CLI et UI sur le même backend.

---

---

## Traités récemment

### [General → War Room] Clarification Review — UX légitime, drag-and-drop non — 2026-06-05

**Date** : 2026-06-05 — **Traité** : 2026-06-05

**Correction d'un message précédent** : j'ai suggéré de "pauser le polish UX" — c'était une mauvaise lecture. La War Room n'est pas du polish cosmétique : c'est Jonathan qui opère et teste le produit en tant qu'utilisateur de profil cible. La lisibilité pendant un incident n'est pas négociable, et la War Room a surfacé des bugs (case-sensitive resource_id, resolve après restore, dedup) que des tests unitaires n'auraient pas détectés. Le travail UX est de la validation fonctionnelle.

**Ce qui reste à challenger** :

**Drag-and-drop** : seule feature qui n'est pas défendable par "je l'utilise moi-même pour opérer ou tester". Aucun scénario d'incident identifié où le drag-and-drop apporte quelque chose. À garder dans le backlog uniquement si un usage concret émerge.

**Deux trous ouverts** (runs Azure, pas UX) :
- T1548 solo avec `ago(10m)` : valide si la fenêtre était le problème (vs contention DCR)
- T1486 backup actif vs ransomware : valide que `investigative_context` influence `decide`

Pas de blocage sur les développements War Room — juste ces deux runs à faire en parallèle.

---

### [Tests → War Room] Mode d'autonomie global dans le panneau ⚙ Config — 2026-06-11

**Date** : 2026-06-11 — **Traité** : 2026-06-11

Dropdown `human_only` / `non_disruptive` ajouté dans la section Autonomy du panneau ⚙ Config. Lit `_state.autonomy_default`, appelle `PATCH /api/config/autonomy/default` → `set_default_mode()` dans `config.py` → écrit `autonomy.default` dans `glorfindel-config.yaml`. Hot-pickup au cycle suivant (même mécanique que par-asset). Note visible sous le dropdown : "Per-asset overrides are set from each VM card."

---

### [Glorfindel → War Room] Dropdown mode = hot-pickup, plus de restart requis — 2026-06-11

**Date** : 2026-06-11 — **Traité** : 2026-06-11 — commit `b7af4cc`

Aucun changement UI nécessaire. Pas de message "restart requis" dans le code War Room — vérifié. Le badge de mode par carte lit `_state.autonomy_modes[vm]` (fourni par `/api/state`) qui est calculé via `load_glorfindel_config().autonomy.resolve(vm)` à chaque poll → reflète le YAML live.

---

### [Glorfindel → War Room] approve-rule/reject-rule CLI — même comportement que War Room (commit a43f14c)

**Date** : 2026-06-05 — **Traité** : 2026-06-05

Le CLI `glorfindel approve-rule` et `reject-rule` appelaient `proposed_rules.approve()`/`reject()` mais ne résolvaient pas l'escalade `proposed_rule` associée. Fix dans `escalations.resolve_by_proposal(proposal_id)` + appel depuis `cli.py`. Le comportement est maintenant identique aux boutons War Room.

**Rien à faire côté War Room** — parité CLI/UI atteinte.

### [Tests → War Room] Fix improve_detection buttons manquants (commit 9eac322)

**Date** : 2026-06-04 — **Traité** : 2026-06-04

Fix de ea9b9a2 : les `myDetEscs` étaient rendus avec un template simplifié sans boutons ni onclick. Remplacé par `_groupEscs(myDetEscs).map(_renderEscGroup).join('')` — donne les boutons Ack + Approve + Reject + le click → `showEscModal` avec query complète.

---

### [Tests → War Room] Deux bugs dec-row (commit ea9b9a2)

**Date** : 2026-06-04 — **Traité** : 2026-06-04

**Bug 1 — "Isolation lifted" stale** : `release_isolation` n'était pas filtrée dans les state-coupled actions. Après un cycle release → nouvelle isolation, l'ancienne `release_isolation` restait visible dans la carte. Fix : `if (a.action === 'release_isolation' && isIsolated) return false`.

**Bug 2 — improve_detection invisible en mode étendu** : Les `myDetEscs` étaient comptées dans le badge (`totalEscs`) mais jamais rendues dans le `expandedBody`. La carte affichait "1 escalation" mais la section était vide. Fix : section "Amélioration détection" ajoutée en bas du body étendu avec aperçu raison + TTP.

**Rien à faire** — fix déjà mergé. À noter si tu retouches `_renderAssetNode` ou le rendering des escalations.

---

### [Glorfindel → War Room] Fix restore T1486 — _find_resource_id (commit 2b8f125)

**Date** : 2026-06-04 — **Traité** : 2026-06-04

**Bug root cause** : pour T1486, Glorfindel escalade `restore_from_backup` sans isoler la VM. `_find_resource_id` ne cherchait que dans `active_isolations()` et `active_blocks()` → retournait `None` → `/api/action/restore/{vm}` retournait immédiatement `{"error": "Resource ID not found"}` sans démarrer le restore ni appeler `resolve_by_resource`. C'est pourquoi les escalades restaient pending.

**Fix** : deux fallbacks ajoutés dans `_find_resource_id` :
1. Escalades pending (couvre `restore_from_backup` sans isolation préalable)
2. Registry découvert (couvre tout asset connu)

Le bouton Restore War Room devrait maintenant fonctionner pour T1486 — à valider sur le prochain run.

---

### [Glorfindel → War Room] Réponse design : Ack sans Restore — comportement confirmé

**Date** : 2026-06-04 — **Traité** : 2026-06-04

**Réponses aux 2 questions** :

**1. Ack sans Restore laisse-t-il la VM isolée ?**

Non. Pour T1486 (ransomware), Glorfindel décide `restore_from_backup` avec `escalate=True`. `execute_action` ne touche rien quand `escalate=True` sur une action destructive — la VM n'est jamais isolée automatiquement dans ce cas. Un Ack sans Restore laisse la VM dans l'état qu'elle avait avant l'intervention : running, disk potentiellement chiffré, mais aucune règle NSG ajoutée par Glorfindel.

Si l'opérateur a décidé de gérer manuellement (Azure Portal), il n'a pas besoin de `glorfindel release` après — aucune isolation à lever.

**2. `resolve_by_resource` — appelé quand ?**

Uniquement dans `glorfindel restore` (cli.py:513) après restauration réussie. `release_isolation` ne l'appelle pas. Les deux sont indépendants :
- `restore` → auto-resolve les escalades `restore_from_backup` + émet `recovery_complete` → Glorfindel décide `release_isolation`
- `release` seul → lève le NSG, ne touche pas les escalades

**Validation du layout actuel** :

`[🔄 Restore]  [✓ Ack]  [📋 Cmd]` — correct. Les 3 cas d'usage War Room sont valides :
- Faux positif (backup légitime) → Ack, rien à faire sur Azure
- Manuel via Portal → Ack, puis `glorfindel release` si une isolation a été posée par ailleurs
- Délégation → Ack, la personne qui prend en charge lancera `glorfindel restore`

_(aucun)_

---

## Traités récemment

### [Glorfindel → War Room] Fix escalades dupliquées à la source (commit b86fae2)

**Date** : 2026-06-04 — **Traité** : 2026-06-04

Fix backend appliqué dans `escalations.record()` (dedup par `action + resource_id + escalation_type`). Grouping UI (commit e898eef) conservé en couche défensive. Rien à changer côté War Room.

### [Tests → War Room] Bug fix : showIsolationModal — cache stale au click (commit d305d10)

**Date** : 2026-06-04 — **Traité** : 2026-06-04

Fix déjà présent dans d305d10 (async + force-fetch sur cache miss). Complété dans 300de44 : refreshActionsData passe en Promise.all + await dans refreshState → reasoning disponible dès le premier render après détection.

---

### [Glorfindel → War Room] Design UX : ARM Discovery — coverage gaps

**Date** : 2026-06-02 — **Traité** : 2026-06-04

Vision transmise dans warroom_status.md :
- Badges inline `⚠ no monitoring` (orange) / `⚠ no backup` (rouge) sur les node-asset
- VM éteinte : filtrer si gap < 8h, sinon badge gris "possible VM offline"
- Bouton "Fix" informatif (commande `az` copiable), pas d'action directe

Pas d'implémentation avant que le backend soit finalisé.

---

### [Glorfindel → War Room] Fix audit RSV timeout (commit 1c28c74)

**Date** : 2026-06-02 — **Traité** : 2026-06-04

Fix asyncio.to_thread() noté. Si "Azure API error" persiste après `make glorfindel-ui` → problème IAM (SP sans Backup Reader sur le vault RSV). Commande de vérification dans le ticket.
