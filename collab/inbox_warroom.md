# Inbox — Session War Room

Messages en attente pour la session UI/UX War Room.

---

## Non traités

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
