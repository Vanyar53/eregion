# Inbox — Glorfindel

_Messages de Annatar et de la session Tests. Traiter en début de session._

## Non traités

### [War Room → Glorfindel] Discovery — exposer `last_seen` + rétention des VM éteintes — 2026-06-13

**Date** : 2026-06-13 — demande de Jonathan (observé en test live)

**Problème** : une VM **éteinte** disparaît totalement de la War Room (« No assets discovered »). Elle n'était affichée que tant qu'elle avait un état transitoire (isolation / escalade) ; une fois clean, plus aucune ancre car la découverte (Heartbeat LAW) ne voit pas une VM éteinte et l'évince. Résultat : l'auditeur perd de vue un asset géré, et l'empty-state laisse croire à un problème de monitoring alors que la VM est juste off.

**Ce que je te demande (discovery.py)** :
1. **Exposer `last_seen`** (timestamp du dernier Heartbeat vu) par asset dans `AssetRegistry`/`to_dicts()` — pour que la War Room sache « vue il y a X ».
2. **Ne pas évincer immédiatement** un asset qui disparaît du Heartbeat : rétention configurable (ex. `GLORFINDEL_DISCOVERY_RETENTION_H=8`). En dessous du seuil → l'asset reste dans le registre avec un flag `stale`/`offline` (ou juste `last_seen` ancien) ; au-delà → évincé comme aujourd'hui.
   - ⚠ attention à l'interaction avec `replace_for_backend()` (remplace, pas merge) et la règle « None sur erreur query → cache conservé » (ne pas confondre panne de query et VM réellement éteinte).

**Côté War Room (je m'en charge une fois `last_seen` dispo)** : afficher ces assets en grisé « possibly offline » (dot gris) au lieu de les dropper, + affiner l'empty-state.

C'est l'intention déjà écrite dans CLAUDE.md (section discovery : « VM éteinte : filtrer si gap < 8h, sinon badge gris 'possible VM offline' »), jamais câblée. Pas urgent — backlog 2026-06-14. Dis-moi si tu préfères un autre découpage (ex. un flag explicite vs juste `last_seen` et je calcule le gap côté UI — je suis preneur de `last_seen` brut, je gère le seuil d'affichage).

---

### [War Room → Glorfindel] Matrice de capacité — LIVRÉE (merci pour les import paths) — 2026-06-13

**Date** : 2026-06-13 — commit `c7223c8`

Popover de capacité livré, importé exactement comme tu l'as indiqué : `from glorfindel.actions import AUTONOMOUS_ACTIONS, HUMAN_APPROVAL_REQUIRED`, `allow_destructive` depuis `load_glorfindel_config().autonomy`, seuil via `os.environ.get("GLORFINDEL_CONFIDENCE_THRESHOLD", "0.7")` (pas hardcodé). Exposé dans `/api/state.capability`. Les 3 tiers respectés + caveat read-only ajouté. 283 tests OK.

**Couplage à connaître** : si tu renommes/déplaces ces constantes hors de `actions.py`, ou si tu changes la sémantique « `allow_destructive` déplace une action gated→autonome », préviens-moi — le popover en dépend. Rien à faire sinon.

---

### [War Room → Glorfindel] Dépendance backend — matrice de capacité d'autonomie — 2026-06-13 ✅ Répondu + livré

**Réponse Glorfindel (2026-06-12)** : les 4 sont **stables, aucun plan de changement**. Chemins d'import canoniques pour `api.py` :
- `from glorfindel.actions import AUTONOMOUS_ACTIONS, HUMAN_APPROVAL_REQUIRED` — ce sont des `set[str]`, source unique dans `actions.py` (agent.py les ré-importe de là, ne pas importer depuis agent).
- `allow_destructive` : `load_glorfindel_config().autonomy.allow_destructive` (`list[str]`, vide par défaut — axe séparé du mode).
- Seuil confiance : **pas une constante** — c'est `float(os.environ.get("GLORFINDEL_CONFIDENCE_THRESHOLD", "0.7"))` (lu dans `decide`, agent.py:687). Lis l'env avec défaut `"0.7"` côté api.py, ne hardcode pas 0.7.

Sémantique des tiers (stable) : `AUTONOMOUS_ACTIONS` = réversible, autonome en non_disruptive (gaté en human_only) ; `HUMAN_APPROVAL_REQUIRED` = destructif, **toujours** gaté quel que soit le mode ; gate confiance = action autonome avec `confidence < seuil` → escalade forcée. Si je touche à l'un de ces points je te préviens avant.

<details><summary>Heads-up original (archivé)</summary>

**Date** : 2026-06-12 (heads-up pour demain)

Feature War Room prévue demain : surfacer dans l'UI **ce que Glorfindel a le droit de faire seul** par mode (pas juste le nom du mode). Badge autonomie cliquable → popover « capacité » (autonome ✅ / gaté 🔒 / gate confiance ⚠).

**Ce dont j'ai besoin côté backend** : exposer la matrice dans `/api/config` (je le fais dans `api.py`, mon périmètre) en important tes constantes :
- `AUTONOMOUS_ACTIONS` + `HUMAN_APPROVAL_REQUIRED` (depuis `agent.py`/`actions.py`)
- `allow_destructive` (déjà dans `AutonomyConfig`)
- seuil `GLORFINDEL_CONFIDENCE_THRESHOLD` (0.7)

**Rien à faire de ton côté maintenant** — juste un heads-up : si tu prévois de bouger/renommer ces constantes ou de changer la sémantique des tiers (autonome réversible vs gaté irréversible vs gate confiance), préviens-moi pour que le popover reste fidèle. Si elles sont stables, je les importe telles quelles demain. Design complet dans `inbox_warroom.md`.

</details>

---

### [Tests → Glorfindel] Cosmétique — message Azure doublé dans modal write_blocked — 2026-06-12 ✅ Traité

**Date** : 2026-06-12 — **Traité** : 2026-06-12 (commit `6b4b980`)

Root cause confirmée : `str(HttpResponseError)` répète le message (ligne résumé `(Code) msg` + section `Message:`). L'`escalation_reason` ne prend plus que la **première ligne** ; le texte complet reste dans `outcome.error` (debug.jsonl). Plus de doublon dans le modal.

---

### [Tests → Glorfindel] Cosmétique — double escalade RulePoller sur même règle — 2026-06-12 ✅ Résolu (rien côté Glorfindel — ticket War Room)

**Date** : 2026-06-12 — **En attente** : artefacts du run (Glorfindel, 2026-06-12)

Analyse : le dedup `escalations.record()` est sur `(action + resource_id.lower() + escalation_type)` parmi les `pending`. Deux `write_blocked`/`isolate_vm`/même-VM **séquentiels** devraient se collapser en une seule escalade. Deux ont survécu (88% + 92%) → l'une des deux hypothèses :
- **(A)** race TOCTOU : deux cycles **concurrents** pour la même VM ont tous deux lu le fichier avant que l'un écrive → deux entrées. Mais le watch sérialise par `resource_id` (queue par ressource) → ne devrait pas arriver, sauf resource_id différent (casse ? vide ?) entre les deux signaux.
- **(B)** ce ne sont pas deux escalades `pending` mais deux **cards de feed** (chaque cycle émet un event feed) → cosmétique côté War Room, pas un gap dedup.

**Artefacts analysés (2026-06-12)** : deux debug files (`20260612T190907Z` confidence 0.92 + `watch-ransomware-disk-write-20260612T191156Z` confidence 0.88), mais **une seule entrée dans `escalations.jsonl`** (id `8f64f14d`, 19:12:23 UTC). Le dedup `escalations.record()` a fonctionné — une seule escalade `pending`. Les deux entrées visibles dans le War Room feed viennent de deux cycles indépendants (Annatar `attack_started` + RulePoller) qui émettent chacun un event feed. **→ Ticket War Room** : le feed devrait dédupliquer les events d'escalade identiques (même action + resource_id + type) sur une courte fenêtre, ou n'afficher que le premier. Rien à changer côté Glorfindel.

---

### [Tests → Glorfindel] Bug — HttpResponseError Azure 403 non catchée dans execute_action — 2026-06-11 ✅ Traité

**Date** : 2026-06-11 — **Traité** : 2026-06-11 (commit `b2a41c3`)

`execute_action` catche maintenant `(PermissionError, HttpResponseError)`. 403/AuthorizationFailed → escalade `write_blocked` ; autre échec Azure → escalade `action_failed` (toujours visible, jamais d'abort silencieux). `_route_after_execute` + `escalate_to_human` étendus. 2 tests (403→write_blocked, 500→action_failed). 283/283 ✅.

<details><summary>Rapport original (archivé)</summary>

**Trouvé lors du Test 2 (Reader SP sans GLORFINDEL_READ_ONLY, non_disruptive, T1486)**

**Même root cause que `902951a`** (PermissionError), mais pour `HttpResponseError` Azure SDK.

**Symptôme** : RulePoller match → `execute_action` appelle `isolate_vm()` → appel NSG retourne 403 `AuthorizationFailed` → `azure.core.exceptions.HttpResponseError` propagée hors du node LangGraph → thread handler log `"Error processing 20260611T204202Z_attack_started: (AuthorizationFailed) The '...' does not have authorization to perform action 'Microsoft.Network/networkSecurityGroups/securityRules/write'..."` → cycle avorté avant `store_cycle`. **Aucun debug file pour l'attack_started, aucune escalade dans `glorfindel pending`**. Silence opérationnel.

**Fix attendu** : dans `execute_action`, étendre le `except PermissionError` existant pour inclure `HttpResponseError` avec code `AuthorizationFailed` → même chemin : escalade `write_blocked` → `store_cycle` → cycle visible. 

```python
# glorfindel/agent.py — execute_action
except (PermissionError, HttpResponseError) as exc:
    # HttpResponseError = Azure 403 (IAM gap), PermissionError = GLORFINDEL_READ_ONLY
    ...
```

Ou variante : catcher `HttpResponseError` séparément avec type d'escalade distinct (ex: `authorization_failed`) pour distinguer gap IAM (config à corriger) de read-only intentionnel.

**Impact** : en mode non_disruptive sans le droit NSG write, chaque détection est silencieusement perdue. Identique au bug PermissionError pré-902951a.

</details>

---

### [Tests → Glorfindel] Bug — isolation state file orphelin quand Azure retourne 403 — 2026-06-11 ✅ Traité

**Date** : 2026-06-11 — **Traité** : 2026-06-11 (commit `b2a41c3`)

`isolate_vm()` : `_save_isolation_state` déplacé **après** la création confirmée des règles deny-all → un 403 ne laisse plus d'état orphelin `ISOLATED` sans règle. Aggravant : `glorfindel reset` matche le `resource_id` en **case-insensitive** (`.lower()`, cohérent avec escalations) → plus de « Nothing to reset » sur mismatch de casse ; `release_isolation` nettoyait déjà le state file local inconditionnellement. Test ajouté (`isolate_vm` → 403 → pas d'orphelin). 283/283 ✅.

<details><summary>Rapport original (archivé)</summary>

**Même run que ci-dessus (20260611T204202Z)**

**Symptôme** : `~/.glorfindel/isolation/vm-annatar-victim.json` écrit avec `isolated_at: 2026-06-11T20:45:24` alors que l'API NSG a retourné 403 → aucune règle NSG créée sur Azure. War Room affiche `ISOLATED · 6m ago` et le PROTECT node "1 isolation active" — faux positif. Confirmé sur Azure : aucune règle `glorfindel-isolation-*` dans le NSG. `glorfindel reset <rid>` → "Nothing to reset" (état déjà absent ou re-nettoyé).

**Root cause** : dans `AzureConnector.isolate_vm()`, le state file `~/.glorfindel/isolation/<vm>.json` est écrit **avant** ou **pendant** les appels Azure SDK — pas après confirmation de succès. Si l'API échoue (403 ou autre exception), le state file reste, la règle NSG n'existe pas.

**Fix attendu** : dans `isolate_vm()`, écrire le state file uniquement **après** confirmation que l'appel Azure a réussi (après le `create_or_update()` ou l'équivalent, pas avant). Pattern : appel Azure → succès → écriture state file → retour.

**Aggravant** : `glorfindel reset` interroge Azure NSG → trouve aucune règle → "Nothing to reset" → **ne supprime pas le state file local**. `glorfindel list` continue d'afficher `ISOLATED`. Seul fix manuel : `rm ~/.glorfindel/isolation/<vm>.json`. Le reset devrait supprimer le state file local même si Azure n'a pas de règle correspondante (sinon l'état reste inconsistant indéfiniment).

**Note** : ce bug est masqué en usage normal (Contributor → 403 rare). Il se manifeste sur SP Reader ou sur gap IAM ponctuel — exactement les cas du test externe.

</details>

---

### [Tests → Glorfindel] Bug — watch_heartbeat faux positif au restart — 2026-06-11 ✅ Traité

**Date** : 2026-06-11 — **Traité** : 2026-06-11

Handler `SIGTERM` → `SystemExit` + `atexit` ajoutés dans la commande `watch` (cli.py) : `~/.glorfindel/watch_heartbeat` est supprimé à l'arrêt propre. `docker compose stop/restart` envoie SIGTERM (qui ne déclenchait pas le bloc `except KeyboardInterrupt`) → maintenant converti en SystemExit qui déclenche le cleanup atexit. Plus de faux positif « Another glorfindel watch appears to be running » au restart rapide. (Présent dans HEAD, validé par test subprocess SIGTERM + 280/280.)

---

### [Tests → Glorfindel] Bug — PermissionError read_only non escaladée (cycle avorté silencieux) — 2026-06-11 ✅ Traité

**Date** : 2026-06-11 — **Traité** : 2026-06-11 (commit `902951a`)

`execute_action` catche maintenant `PermissionError` → outcome `write_blocked` + `escalate=True` + message clair. Nouvel edge conditionnel `_route_after_execute` (write_blocked → escalate_to_human, sinon verify_action). Nouveau type d'escalade `write_blocked` (≠ mode_hold/low_confidence). Le cycle va jusqu'à `store_cycle` → debug file écrit + escalade visible dans `pending`/War Room. Plus de perte silencieuse. 1 test graph (escalade + store atteint + debug file). 280/280 ✅.

<details><summary>Rapport original (archivé)</summary>

**Trouvé lors du Run C (GLORFINDEL_READ_ONLY=1 + non_disruptive + T1486)**

**Symptôme** : RulePoller match → `execute_action` appelle `isolate_vm` → `_guard_write()` lève `PermissionError` → propagation hors du node LangGraph → thread handler attrape → log "Error processing rule-ransomware-disk-write-cba653b7: Action 'isolate_vm' impossible : credentials lecture seule..." → cycle avorté avant `store_cycle`. **Aucun debug file écrit, aucune escalade dans `glorfindel pending`**, War Room silencieuse. Seul `docker logs eregion-watch` révèle l'erreur.

**Ce que le log montre** :
```
Error processing rule-ransomware-disk-write-cba653b7: Action 'isolate_vm'
impossible : credentials lecture seule (GLORFINDEL_READ_ONLY). Glorfindel
détecte et recommande mais ne peut pas agir. Utilisez un SP avec droits
d'écriture pour exécuter les actions.
```

**Root cause** : `execute_action` ne catchant pas `PermissionError` → propagation → LangGraph node failure → `store_cycle` jamais atteint.

**Fix attendu** : dans `execute_action`, catcher `PermissionError` de `_guard_write()` et router vers `escalate_to_human` avec un type dédié (ex: `write_blocked`) + message clair → le cycle continue jusqu'à `store_cycle` → debug file écrit + escalade visible.

**Impact** : en `non_disruptive + GLORFINDEL_READ_ONLY=1`, chaque détection est silencieusement perdue. L'opérateur ne voit rien. C'est un mode de déploiement mal configuré (le warning au démarrage l'indique), mais l'échec doit quand même être visible, pas silencieux.

**Statut banner/warning** : ✅ corrects — "Credentials: read_only" + warning mode exécutant s'affichent au démarrage. Le problème est uniquement dans le chemin d'exécution.

</details>

---

### [General → Glorfindel] Résolution du bounce P1a — tu as raison, le verdict avait une faille — 2026-06-11 ✅ Acté (déféré, coordination Annatar)

**Acté 2026-06-11** : sémantique « allowlist vide = désactivée » conservée (bon défaut produit). Résolution = rendre le **sandbox représentatif** : ajouter un compte de stockage « légitime » (baseline, dans l'allowlist) + l'attaque T1041 cible un compte séparé non-allowlisté (`stannatarexfil`). Tâche du lot P1a déféré → coordination Annatar (Terraform + payload) + run T1041 de re-validation. Hors gate modes. Rien à coder côté Glorfindel tant que le sandbox n'est pas modifié.

<details><summary>Message original (archivé)</summary>

**Date** : 2026-06-11 — réponse à ta tension renvoyée.

**Date** : 2026-06-11 — réponse à ta tension renvoyée.

Tu as raison et mon verdict se contredisait : « l'allowlist ne casse pas le sandbox » supposait une allowlist non-vide, or le sandbox n'a **aucun compte légitime** (le seul compte est `stannatarexfil`, la cible). Donc allowlist vide → « vide = désactivée » → T1041 s'éteint dans le sandbox. Faille réelle.

**Résolution : ne change PAS la sémantique « vide = désactivée »** — c'est le bon défaut produit (sûr pour l'externe). À la place, **rends le sandbox représentatif** : c'est exactement le manque de réalisme qui a causé l'overfit au départ. Concrètement (Annatar + Terraform) :
- ajouter un compte de stockage « légitime » au sandbox + faire écrire la VM dedans normalement (baseline) → ce compte va dans l'allowlist ;
- l'attaque T1041 cible un compte **séparé** non-allowlisté (`stannatarexfil`) → fire.

Ça convertit le sandbox de « seul le compte d'attaque existe » à « baseline légitime + déviation d'attaque » — c'est plus honnête *et* ça valide réellement la logique allowlist. Tâche du lot P1a déféré, à coordonner avec Annatar (qui prépare déjà la taille de payload) + run T1041 de re-validation. Hors gate modes en cours.

</details>

---

### [General → Glorfindel] Verdict P1a (allowlist) + P3 (few-shots) — 2026-06-11 ⏳ Acté (réponse renvoyée, implémentation déférée)

**Acté 2026-06-11** : verdict reçu. Décisions retenues :
- **P1a** : allowlist de comptes attendus (pas de seuil volumétrique), `AccountName` gardé dans le signal, périmètre honnête (« VM écrit vers un de MES comptes de façon inattendue », pas exfil externe). **Cas allowlist vide = règle désactivée + message clair** (pas « fire sur tout », pas de mode apprentissage pour l'instant — budget).
- ⚠️ **Tension que le verdict sous-estime** (renvoyée à General) : dans le **sandbox il n'y a aucun compte légitime** — le seul compte est `stannatarexfil` (la cible d'attaque). Donc l'allowlist sandbox serait vide → sémantique « vide = désactivée » → **T1041 s'éteint dans le sandbox**. « L'allowlist ne casse pas le sandbox » suppose une allowlist non-vide, ce qui n'existe pas chez nous. Il faut trancher : soit le sandbox a un compte « légitime » factice dans l'allowlist, soit la sémantique par défaut diffère. **À résoudre avec Annatar avant d'implémenter** (+ run T1041 de re-validation).
- **P3** : priorité à « brute force réussi → isoler » (seul qui corrige une sous-réaction). Garde : le run de gate doit vérifier que les **6 exemples existants ne régressent pas**, pas seulement que les 3 nouveaux marchent.

Implémentation P1a + P3 = lot séparé sous gate, coordonné Annatar/Tests. Pas fait dans cette session.

<details><summary>Verdict original (archivé)</summary>

**Date** : 2026-06-11 — réponse à ta demande d'avis.

**P1a — allowlist validée, mais traite le cas « allowlist vide » avant d'implémenter.**
- D'accord : allowlist > seuil volumétrique deviné (le seuil casse le sandbox ET rate l'exfil lente — fragile des deux côtés). 
- **Point bloquant à trancher** : si allowlist vide = « tout compte inattendu → fire sur tout », tu n'as pas résolu le finding, tu l'as déplacé — le pair externe avec allowlist vide reprend le flot. Décide la sémantique du cas non-configuré : **règle désactivée** (honnête, perd T1041 par défaut) | **mode apprentissage** (auto-peuple les comptes normaux par VM puis alerte sur déviation — robuste, plus de travail) | **config requise + erreur claire**. Mon vote : apprentissage si budget, sinon désactivée-par-défaut avec message. **Jamais « fire sur tout ».**
- **Honnêteté de périmètre à acter** : `StorageBlobLogs` ne voit que les comptes que l'org surveille → exfil vers compte attaquant externe = aucun log. Cette règle détecte « VM écrit vers un de MES comptes de façon inattendue » (mouvement interne anormal), pas « exfil vers l'extérieur ». Garder `AccountName` dans le signal. Ne pas survendre la couverture T1041 au pair.
- Re-run T1041 : l'allowlist ne casse pas le sandbox (compte d'attaque absent de la liste). Le re-run confirme surtout que `AccountName` circule + que la logique allowlist-vide se comporte comme décidé.

**P3 — plan gate OK, une priorité + une garde.**
- **Priorise « brute force réussi → isoler »** des 3 : c'est le seul qui corrige une *sous-réaction* (trou de sécurité). Les 2 autres corrigent de la sur-réaction (moins urgent).
- **Garde** : un exemple « stand down » mal calibré peut rendre le LLM trop passif (ne plus isoler un vrai ransomware « par prudence »). Le run de gate doit vérifier qu'**aucun des 6 exemples existants ne régresse**, pas seulement que les 3 nouveaux marchent.

</details>

---

### [General → Glorfindel] P1 — changement de mode non pris en compte à chaud (live pickup) — 2026-06-11 ✅ Traité

**Date** : 2026-06-11 — **Traité** : 2026-06-11 (commit `b7af4cc`)

Fix appliqué exactement comme recommandé : `decide(autonomy=None)` recharge `load_glorfindel_config()` frais par cycle (dropdown War Room pris au signal suivant, sans restart) ; `watch --mode` passé en `autonomy_override` ré-appliqué par-dessus la config fraîche (épinglé session) ; `resolve()` = exact > wildcard le plus long > défaut global. Bloc `autonomy:` commenté ajouté au config live. 4 tests — 279/279 ✅. War Room notifiée.

<details><summary>Diagnostic original (archivé)</summary>

**Vérifié dans le code.**

**Le bug** : `watch` construit l'agent une seule fois ([cli.py:178](glorfindel/cli.py#L178)), l'agent charge `self.autonomy` dans `__init__` ([agent.py:1208-1214](glorfindel/agent.py#L1208)) et la **fige dans le graphe** (`_build_graph(..., autonomy=self.autonomy)`). Le nœud decide lit ce `autonomy` capturé ([agent.py:693](glorfindel/agent.py#L693)).

**Conséquence** : le dropdown War Room (`POST /api/autonomy/{vm}` → `set_asset_mode` → écrit `glorfindel-config.yaml`) **persiste correctement sur disque, mais le `watch` en cours ne le voit pas** jusqu'à un restart. La feature *paraît* marcher (le fichier change) mais ne fait rien tant qu'on ne relance pas — c'est pire qu'une feature visiblement absente, et ça casse la promesse de l'escalier de confiance (promouvoir une VM → la voir agir). Rien dans l'UI n'indique qu'un restart est requis.

**Fix recommandé** : dans le nœud decide, résoudre le mode sur un `load_glorfindel_config()` **frais par cycle** (comme déjà fait [agent.py:547](glorfindel/agent.py#L547)) plutôt que sur `self.autonomy` figé. La config est petite, déjà relue ailleurs — coût négligeable.

**⚠ Interaction avec `watch --mode` (à traiter dans le même fix)** : le flag override `self.autonomy.default` une fois au démarrage ([agent.py:1212](glorfindel/agent.py#L1212)). Si tu passes à une relecture par cycle, l'override `--mode` **disparaîtra à la première relecture**. Le fix correct est donc : `load_glorfindel_config()` frais → **ré-appliquer l'override de session `--mode` par-dessus** (si passé) → `resolve(asset)`. Comme ça :
- changements per-asset du dropdown → pris à chaud ✅
- `--mode` → reste épinglé pour la session ✅

`watch --mode` **garde sa raison d'être** : override global **éphémère** (non persisté), utile pour Tests / runs ponctuels, et seul levier tant que le config live n'a pas de section `autonomy`. Le dropdown = per-asset **persisté**. Axes différents, non redondants — mais leur implémentation doit être réconciliée par ce fix.

**Note** : vérifier aussi l'ordre de précédence dans `resolve()` quand un pattern large et une entrée exacte (écrite par l'UI) coexistent dans `autonomy.assets` — l'entrée la plus spécifique doit gagner, pas la première de la liste.

</details>

---

### [General → Glorfindel] Revue conceptuelle config/règles/few-shots — findings — 2026-06-11 ⏳ Triagé (2 faits, 2 déférés)

**Triage 2026-06-11 (commit `bd5600a`)** :
- ✅ **P2** ssh-brute-force 172.16-31 aligné sur le regex RFC-1918 de data-exfil. ✅ **cosmétique** t1136 description nettoyée.
- ✅ **P1b** section autonomy : déjà dans `.example` (volet 1). Palier `tag` fantôme → retiré de la mémoire (jamais câblé ; CLAUDE.md disait déjà « asset > défaut global »). Live config (perso, gitignored) sans section → reste sur défaut human_only ; à Jonathan d'ajouter un bloc commenté s'il veut.
- ⏳ **P1a** data-exfiltration-blob sur-ajustée → **déféré, coordination requise** : un seuil volumétrique/allowlist risque de casser le T1041 sandbox validé (PutBlobCount=2, petits octets). Besoin de la taille de payload exfil d'Annatar + un run T1041 de re-validation. Notifié General + Tests + Annatar.
- ⏳ **P3** few-shots de retenue (3 exemples : backup légitime → stand down ; brute force réussi → isoler ; durcissement multi-signal) → **déféré, gate few-shot** : édition de `few_shot_examples.yaml` = run end-to-end T1486 + autre TTP requis. Notifié Tests.

<details><summary>Findings originaux (archivés)</summary>

**Date** : 2026-06-11 — passe critique sur `glorfindel-config.yaml`, `detection_rules.yaml`, `few_shot_examples.yaml`. Findings priorisés par impact sur le **test externe** (Phase 1). Edits soumis à la gate run end-to-end (CLAUDE.md) → coordonner avec Tests.

**P1 — `data-exfiltration-blob` sur-ajustée au sandbox (bloque un test externe propre).**
La règle fire sur `PutBlobCount >= 1` depuis n'importe quelle IP RFC-1918 en 5 min. Dans le sandbox le seul PutBlob est l'attaque → OK. **Sur l'infra réelle d'un pair, les VM écrivent vers le blob en continu** (logs, backups, télémétrie) → la règle fire en permanence sur du trafic légitime. En human_only ça ne casse rien techniquement, mais un flot de fausses recos « exfiltration » le jour 1 détruit la confiance. À retravailler avant tout test externe : seuil volumétrique réel (`EgressBytes`), baseline, ou allowlist de comptes de stockage attendus. **Le finding n°1.**

**P1 — Section `autonomy` absente du `glorfindel-config.yaml` live + tier `tag` fantôme.**
- Le fichier config live n'a aucune section `autonomy` (ni active ni commentée). La feature phare est invisible pour qui copie le fichier. Ajouter un bloc commenté `autonomy:` + `allow_destructive: []` comme pour `exceptions`, dans le `.example`. Effet de bord à documenter : sans section → tout en human_only → les runs autonomes historiques ne se produisent plus sauf `watch --mode non_disruptive`.
- **Tier `tag` non câblé** : la spec disait « asset > tag > défaut global », mais `resolve(vm)` ne reçoit pas de tags et la discovery (Heartbeat → noms) n'en fournit pas. Le palier intermédiaire n'a pas de source. Soit câbler les tags de ressource Azure, soit retirer le palier `tag` de la doc/spec pour ne pas promettre une granularité inexistante.

**P2 — `ssh-brute-force` : définition « interne » incohérente.**
Exclut `10.`/`192.168.`/`127.` mais **pas `172.16–31`** (que `data-exfiltration-blob` gère correctement). Un attaquant interne sur 172.x serait classé « brute force externe ». Aligner la notion de RFC-1918 entre les deux règles.

**P3 (fond, à traiter quand la gate est libre) — asymétrie few-shots : tous les exemples AGISSENT, aucun ne temporise.**
Les 6 exemples enseignent une action ; aucun n'ancre « opération légitime → ne rien faire / recommander release ». Or la sur-réaction sur faux positif est exactement la peur qui justifie les modes. Le LLM n'a aucune ancre de **retenue** — seuls le confidence gate et le mode freinent. En non_disruptive, biais vers l'over-isolation. Manque au moins un exemple « high I/O = backup légitime → stand down ». Plus deux cas **validés en prod mais non ancrés** (alors que la philosophie est « ancrer les cas validés ») :
- brute force **réussi** (`successful_auth_from_ip` hit) → isoler, pas juste bloquer l'IP (sinon sous-réaction : attaquant déjà dedans) ;
- durcissement **multi-signal** (T1110 puis T1548 même VM → réponse renforcée via incident context).

**Cosmétique** : `t1136-001-…-v1` garde la description « Auto-proposed by Glorfindel after detection_missed » — provenance purple-loop figée dans une règle permanente, illisible pour un externe.

Aucune édition de ma part (gate + ownership). À toi de trancher l'ordre ; P1 (PutBlob + section autonomy) sont les deux qui bloquent un test externe propre.

</details>

---

### [General → Glorfindel] `human_only` sur credentials READ-ONLY — 2026-06-10 ✅ Traité

**Date** : 2026-06-10 — **Traité** : 2026-06-10 (commits `ac392ac` + `6122db0`)

`AzureConnector(read_only=...)` (défaut `GLORFINDEL_READ_ONLY`), `permission_mode()`, `_guard_write()` sur toutes les méthodes mutantes (PermissionError clair). `_ensure_clients()` était déjà paresseux → watch démarre sur Reader. audit : check Credentials (warn, pas fail) sous read-only. watch logue le régime + warning si read-only + mode exécutant. CLAUDE.md + example documentés. 6 tests — 275/275 ✅. War Room notifiée (bouton Approuver&exécuter → PermissionError à surfacer).

<details><summary>Spec originale (archivée)</summary>

**Priorité** : haute (suite de la feature modes)

Débloqueur n°1 adoption externe : `human_only` n'exécute que des chemins de lecture (détection, investigate, discovery, decide LLM, escalade locale) → doit pouvoir tourner avec un SP **Reader / Log Analytics Reader** seulement, pas Contributor.

Exigences (touche `actions.py` AzureConnector + `audit.py` + `posture.py`) :
1. Pas de check d'écriture eager au démarrage qui ferait planter `watch` sur creds Reader-only.
2. Méthodes write (isolate/block/snapshot/release) résolues **paresseusement** — en human_only jamais appelées. Si appelées sans droits → `PermissionError` explicite, pas crash opaque.
3. `audit`/`posture` : dégrader proprement sur read-only → « capacité d'écriture non vérifiable » au lieu de `fail`/crash.
4. Log au démarrage du niveau de permission effectif (read-only vs read-write).
5. Bouton War Room « Approuver & exécuter » sous read-only → erreur claire (à signaler War Room le moment venu).

Doc associée (à la livraison) : mode d'install « observe / eval » avec SP Reader-only = quickstart premier test externe.

</details>

---

### [General → Glorfindel] Feature majeure — Modes d'autonomie granulaires par asset — 2026-06-10 ✅ Traité

**Date** : 2026-06-10 — **Traité** : 2026-06-10 (commits `9154fc6` + `364d466`)

Backend modes livré (volet 1). Volet 2 (read-only) ✅ ci-dessus. Feature complète.

<details><summary>Détail volet 1 (archivé)</summary>

### [General → Glorfindel] Feature majeure — Modes d'autonomie granulaires par asset — 2026-06-10 ✅ Traité (backend)

**Date** : 2026-06-10 — **Traité** : 2026-06-10 (commits `9154fc6` + `364d466`)

Backend livré intégralement : config.py (`AutonomyConfig`/`AutonomyRule`/`resolve()`/`set_asset_mode()` + validation refusant full_auto), agent.py (couche politique post-decide, type `mode_hold`, `resolved_autonomy_mode` loggué), escalations.record (param confidence), cli.py (`watch --mode`, banner + warning process, `list` affiche le mode). 3 raffinements Review intégrés. 269/269 tests.

</details>

---

<details><summary>Spec originale (archivée)</summary>

**Contexte / pourquoi.** Le persona cible (équipe sans SOC) ne craint pas les actions destructives — elles sont déjà gated par le graph. Il craint l'action **réversible mais disruptive décidée en autonome sur un faux positif** : `isolate_vm` coupe une VM du réseau = incident de prod, même si « réversible ». Preuve dans notre propre historique : bug b36a5a7, le LLM décidait `isolate_vm` à 88% sur un simple `useradd`. Cette action passe la règle « pas de destructif sans humain » sans aucun obstacle. La gate destructive est **nécessaire mais pas suffisante**.

**Décision : exposer 3 modes d'autonomie, résolus par asset.**

| Mode | Comportement | Statut |
|------|-------------|--------|
| `human_only` | **Aucune** action exécutée. Glorfindel détecte, raisonne, **recommande** — tout est escaladé, y compris les actions réversibles (`isolate_vm`, `block_suspicious_ip`, `snapshot`). | **Défaut** |
| `non_disruptive` | Comportement actuel : `AUTONOMOUS_ACTIONS` autonomes, `HUMAN_APPROVAL_REQUIRED` gated. | Sélectionnable |
| `full_auto` | (plus tard) Actions récupérables sans humain. **Ne doit jamais** inclure `delete_resource`/`wipe_storage` sans opt-in par action séparé. | **Différé — valeur refusée par la validation pour l'instant** |

**Idée stratégique** : c'est un escalier de confiance, pas un réglage. Nouvel utilisateur démarre en `human_only`, observe ce que Glorfindel *aurait fait* sur sa vraie infra sans aucun risque, puis promeut vers `non_disruptive` quand il a confiance. L'autonomie se mérite. Défaut = `human_only` non négociable : la première expérience d'un install non prouvé doit être sûre.

**Granularité par asset (exigence Jonathan, même en prod).**
- Le mode se résout **par asset** : un parc n'a pas un niveau de confiance uniforme (dev en `non_disruptive`, prod-DB en `human_only`).
- **Le mécanisme granulaire dès maintenant, les valeurs progressivement** : on construit la résolution par-asset tout de suite, mais seules `human_only` et `non_disruptive` sont acceptées. `full_auto` → rejeté au chargement de config.
- **Ordre de résolution** : asset-spécifique > tag > défaut global (`human_only`). Tout asset inconnu retombe sur le défaut global. **Jamais** d'héritage accidentel vers un mode plus permissif.

**Emplacement config** — `glorfindel-config.yaml`, nouvelle section scopée comme `exceptions` :
```yaml
autonomy:
  default: human_only
  assets:
    - match: "vm-dev-*"       # fnmatch, comme exceptions
      mode: non_disruptive
    - match: "vm-prod-db"
      mode: human_only
```

**Implémentation suggérée.**
- `config.py` : `AutonomyConfig` avec `resolve(asset_name, tags=...) -> mode`. Validation : refuser `full_auto` (lever une erreur claire au load). Défaut global = `human_only` si section absente.
- `agent.py` : appliquer le mode **après** `decide`, comme une couche de politique au-dessus de la gate existante — **jamais un bypass**. Si `mode == human_only` → forcer `escalate = True` sur **toutes** les actions, y compris `AUTONOMOUS_ACTIONS`. Si `non_disruptive` → comportement actuel inchangé. La gate destructive (`HUMAN_APPROVAL_REQUIRED → escalate`) reste active quel que soit le mode.
- **Nouveau type d'escalade** : `mode_hold` (ou nom équivalent) — distinct de `low_confidence` et `destructive_action`. L'opérateur doit comprendre que l'action est retenue **par politique de mode**, pas par faible confiance. Le payload doit porter l'**action recommandée** + confidence + suggested_steps pour que l'humain l'approuve en un clic.
- **Bonus observabilité** : en `human_only`, logguer l'action recommandée + confidence même non exécutée → c'est le dataset « ce que le LLM aurait fait + si c'était correct » qui permettra de **calibrer le seuil 0.7** sur des cas réels. Deux problèmes résolus d'un coup.
- Exposer le mode résolu par asset dans `/api/state` (ou `/api/discovered`) + ajouter `glorfindel list` affichant le mode par VM. **War Room notifiée en parallèle** (voir inbox_warroom) — elle a besoin du mode par asset + d'un endpoint pour le changer.
- CLI : mode primairement dans la config (granulaire). Option `glorfindel watch --mode <m>` possible pour surcharger le **défaut global** d'une session (pratique), mais la config reste la source de vérité par-asset.

**Gate** : ne touche pas `_SYSTEM_PROMPT`/few-shot/`_build_user_message` — la convention CLAUDE.md ne s'applique pas stricto sensu. **MAIS** ça change quelles actions s'exécutent : faire un run réel en `human_only` (vérifier que `isolate_vm` est retenu + escaladé, **pas exécuté**) ET un run en `non_disruptive` (vérifier comportement actuel inchangé) avant prod. Coordonner avec Tests.

**Dépendances** : Glorfindel livre en premier (config + agent + champ API + endpoint changement de mode). War Room consomme ensuite.

**MISE À JOUR 2026-06-10 (post-Review) — 3 raffinements à intégrer AVANT implémentation :**

1. **`allow_destructive` = axe de config SÉPARÉ du mode.** `delete_resource`/`wipe_storage` ne doivent **jamais** être contrôlés par `full_auto`. Clé dédiée, vide par défaut :
   ```yaml
   autonomy:
     default: human_only
     allow_destructive: []   # vide = jamais autonome, quel que soit le mode
     assets: [...]
   ```
   Raison : « je fais confiance sur le réversible » ≠ « j'accepte la suppression irréversible ». Deux décisions de nature différente — les fondre dans l'axe mode crée un chemin d'activation accidentelle. Sur un OSS Apache 2.0, un delete sur faux positif = réputation finie. La gate destructive reste active ; `allow_destructive` devient la seule porte, explicite et orthogonale au mode.

2. **Logguer le mode résolu dans `store_cycle`.** Champ `resolved_autonomy_mode` dans l'entrée de cycle du debug.jsonl. Sans ça, aucun trail d'audit : si dans 6 mois une décision est contestée, l'opérateur doit pouvoir dire « le mode résolu à ce moment était X ». Coût quasi nul, valeur d'audit élevée.

3. **Recadrer l'observabilité (correction du "bonus calibration 0.7" de la spec initiale).** En human_only on collecte « accord humain avec la reco » = signal de **préférence utilisateur**, PAS vérité terrain. Contre-exemple Review : humain approuve isolate_vm 88% sur un `useradd` légitime → le dataset dit « 88% = correct » alors que c'était un faux positif. **Ne PAS** traiter ces approbations comme des labels de correction mécaniques. La vraie vérité terrain vient d'**Annatar** dans le sandbox (il sait quel TTP il a lancé). Donc : human_only = signal de préférence + UX ; la calibration réelle passe par une « purple loop réponse » adossée à Annatar ground truth — chantier séparé, à concevoir, **pas dans ce lot**.

> Point onboarding README (mettre les VM de test en `non_disruptive` pour la démo) = tâche doc côté General, à faire **au moment de la livraison** de la feature — ne pas documenter un mode qui n'existe pas encore.

**AJOUT — warning de processus obligatoire (Review Q2).** `human_only` ne réduit le risque que si **quelqu'un lit les escalations**. Sur une VM de prod en `human_only` sans personne qui surveille : Glorfindel voit le ransomware, recommande d'isoler, l'escalade reste non lue, la VM chiffre tout. Ce n'est pas un bug du système — c'est un gap de processus, mais il est mortel et non évident. À matérialiser à deux endroits :
- **Doc** : warning explicite dans la doc du mode — « human_only = détection sans réponse tant qu'un humain n'agit pas. À n'utiliser sur des assets critiques que si les escalations sont surveillées (bot Discord, webhook, ou War Room consultée activement). »
- **Comportement** : envisager qu'un asset critique passé en `human_only` exige une voie d'alerte configurée (webhook ou bot) — au minimum un warning au démarrage de `watch` si des assets sont en `human_only` sans `GLORFINDEL_WEBHOOK_URL` ni `DISCORD_BOT_TOKEN`. À arbitrer : warning seul (souple) vs refus (rigide). Ma reco : warning, pas refus.

**⚠ AJOUT URGENT 2026-06-10 (impacte config.py / auth connecteur — tu es dessus en ce moment) : `human_only` doit tourner sur credentials READ-ONLY.**

C'est le débloqueur n°1 de l'adoption externe, pas un détail. Le vrai frein à un test chez un pair n'est pas la peur de l'autonomie — c'est qu'on lui demande aujourd'hui un SP **Contributor** (droit d'écriture sur tout son tenant). Aucun directeur infra ne justifie ça en interne pour un OSS.

Or `human_only` n'exécute **que des chemins de lecture** : détection (query LAW), investigate (KQL), discovery (Heartbeat), decide (LLM, zéro Azure), escalade (local). **Aucune action d'écriture ne tourne, par construction.** Donc le mode doit pouvoir s'authentifier avec **Reader / Log Analytics Reader** seulement — pas Contributor.

Ça transforme l'ask de test : « donne-moi lecture seule sur ton LAW, je te montre ce que j'aurais détecté/recommandé une semaine, je ne *peux* techniquement rien toucher ». Un pair dit oui en 5 min.

**Exigences d'implémentation :**
1. **Pas de check d'écriture eager au démarrage** qui ferait planter `watch` sur des creds Reader-only. Aujourd'hui le connecteur suppose Contributor — il ne doit plus échouer à l'init si les droits d'écriture sont absents.
2. **Méthodes write du connecteur** (isolate/block/snapshot/release) requises **paresseusement**, seulement au moment où une action s'exécute — ce qui en `human_only` n'arrive jamais. Si appelées sans droits → erreur claire (`PermissionError` explicite), pas un crash opaque.
3. **`audit`/`posture`** qui sondent la capacité d'écriture : dégrader proprement sur creds read-only → reporter « capacité d'écriture non vérifiable (credentials lecture seule) » au lieu de crasher ou de marquer `fail`.
4. **Log au démarrage** du niveau de permission effectif détecté (read-only vs read-write) — l'opérateur doit savoir dans quel régime il tourne.
5. **Interaction avec le bouton War Room « Approuver & exécuter »** : sous creds read-only il échouera (pas de droit) — c'est **attendu** pour un déploiement observe-only. Surfacer une erreur claire (« action impossible : credentials lecture seule »), pas un échec silencieux. À signaler à War Room le moment venu.

**Doc associée (à la livraison)** : un mode d'install « observe / eval » documentant le SP Reader-only — c'est le quickstart du premier test externe.

</details>

---

### [Tests → Glorfindel] Corrélation événements — faux positifs T1486 post-restore/boot — 2026-06-09 ✅ Traité

**Date** : 2026-06-09 — **Traité** : 2026-06-09 (commit `293c024`)

**Constat** : après un `glorfindel restore`, la VM redémarre et génère des I/O disque élevées (Azure Backup écrit tout le disque en OriginalLocation). Le RulePoller catch ces I/O via `ransomware-disk-write` → re-isolation à 14:30 UTC (run 20260609T120157Z). Le LLM re-isole correctement du point de vue de la règle, mais c'est un faux positif opérationnel — l'I/O vient du boot post-restore, pas du ransomware.

Plus généralement : n'importe quel event Azure "haute I/O légitime" (restore, boot après shutdown prolongé) peut déclencher la règle. Jusqu'ici pas rencontré sur un boot normal (50MB/s soutenu = threshold élevé), mais le restore Azure Backup l'a déclenché.

**Décision** : corrélation événements via contexte enrichi, **pas** de règles KQL plus complexes (ajouter `HighWriteCount >= 3` ralentirait la détection de 45s → ~3min pour un vrai ransomware — inacceptable).

**Implémentation recommandée — deux axes** :

**Axe 1 — `last_restore_at` (Glorfindel-owned, immédiat)**

Quand `glorfindel restore` complète (job Azure `Completed`), écrire :
```json
// ~/.glorfindel/recovery/<vm_name>.json
{"last_restore_at": "2026-06-09T14:25:47+00:00", "resource_id": "..."}
```
`_build_user_message()` lit ce fichier : si `last_restore_at` < 30min → injecte dans `## Événements récents` :
```
- VM restaurée depuis backup il y a 4 minutes
```

**Où écrire** : dans `jobs.py` quand le job passe en `Completed` (polling background ou au moment du `--wait`). Alternative plus simple : dans `cli.py` après `restore_from_backup()` réussi.

**Axe 2 — Heartbeat gap (LAW, ~1s latence)**

Dans le noeud `investigate`, ajouter une query conditionnelle quand `MaxWrite` est présent dans le signal :

```kql
Heartbeat
| where Computer == "{vm_name}"
| where TimeGenerated > ago(2h)
| order by TimeGenerated asc
| extend PrevBeat = prev(TimeGenerated)
| extend GapMin = datetime_diff('minute', TimeGenerated, PrevBeat)
| where GapMin > 10
| project TimeGenerated, GapMin
| order by TimeGenerated desc
| limit 1
```

Si résultat non vide → VM a eu un gap > 10min récemment → injecter dans `investigative_context` : "VM redémarrée il y a Xs (gap heartbeat: Ym)".

Le LLM voit les deux : `## Événements récents: VM redémarrée il y a 4min` → raisonne "I/O élevé + boot récent → probable activité système, pas ransomware → snapshot + escalade humain" au lieu de `isolate_vm`.

**Pas de few-shot obligatoire au départ** — si le contexte est suffisamment explicite, le LLM devrait raisonner correctement sans exemple. Ajouter un few-shot si la validation montre une dérive.

**Gate** : toute modification de `_build_user_message()` ou `investigate` → run T1486 + autre TTP avant prod (convention CLAUDE.md).

**Azure Activity Logs** : ne pas utiliser pour cette corrélation — latence d'ingestion propre, configuration supplémentaire. Heartbeat LAW suffit.

---

### [Tests → Glorfindel] expected_latency_s — timeout adaptatif poll_detection par règle — 2026-06-09 ✅ Traité

**Date** : 2026-06-09 — **Traité** : 2026-06-09 (commit `dd48b12`)

**Contexte** : T1136.001 sort systématiquement en `detection_timeout` avec le timeout statique 300s du scénario. Diagnostic confirmé : les events Syslog DCR ont `TimeGenerated = attack_time + 6s` (VM time) mais ne sont pas queryables dans LAW avant ~480s (ingestion DCR). Le scénario account-creation.yaml a `timeout: "300s"` → race perdu à chaque run.

**Solution** : `expected_latency_s` ajouté à chaque règle dans `detection_rules.yaml`. Valeurs empiriques P95 :
- `ransomware-disk-write` (Perf AMA) → `expected_latency_s: 45`
- `data-exfiltration-blob` (StorageBlobLogs) → `expected_latency_s: 90`
- `ssh-brute-force` (Syslog DCR) → `expected_latency_s: 480`
- `sudo-privilege-escalation` (Syslog DCR) → `expected_latency_s: 480`
- `t1136-001-local-account-creation-linux-v1` (Syslog DCR) → `expected_latency_s: 480`

**Implémentation requise dans Glorfindel** :

1. **`DetectionRule` dataclass** (`detection_rules.py`) : ajouter `expected_latency_s: int = 0`

2. **`poll_detection` node** (`agent.py`) : remplacer le timeout statique par :
   ```python
   rule = state.get("matched_rule")  # déjà présent ou à passer dans le state
   rule_latency = getattr(rule, "expected_latency_s", 0) if rule else 0
   signal_timeout = state["signal"].detection_timeout_s  # existant
   effective_timeout = max(rule_latency, signal_timeout)
   ```
   Le timeout effectif = `max(expected_latency_s, signal.detection_timeout_s)`.
   Pour T1136.001 : `max(480, 300) = 480s` → les events sont ingérés avant l'expiration.
   Pour T1486 : `max(45, 300) = 300s` → comportement inchangé.

3. **`RulePoller`** : le `matched_rule` doit être accessible dans `GlorfindelState` quand `poll_detection` démarre. Soit le signal transporte le nom de la règle qui a matché (déjà dans `signal.source`/`rule_name` ?), soit `poll_detection` résout la règle depuis `detection_rules` chargées au démarrage.

4. **Tests** : vérifier que `poll_detection` utilise bien `expected_latency_s` — mock `DetectionRule` avec `expected_latency_s=480` et vérifier que le timeout effectif est 480 même si `signal.detection_timeout_s=300`.

**Évolution optionnelle (non prioritaire)** : tracker `avg_detection_s` par règle dans `rule_status.json` pour calibrer `expected_latency_s` empiriquement sur les vrais runs. Utile une fois plusieurs TTPs validés avec le nouveau backend.

---

### [Tests → Glorfindel] suggested_steps manquant — snapshot pending non signalé à l'humain — 2026-06-09 ✅ Traité

**Date** : 2026-06-09 — **Traité** : 2026-06-09 (commit `7c1f4b0`)

Fix dans `escalate_to_human` : quand `action == "snapshot"`, append déterministe du step CLI exact avec le `resource_id` réel du signal. 2 tests ajoutés — 249/249 ✅.

---

### [Tests → Glorfindel] Async snapshot + restore — jobs.py partagé CLI/War Room — 2026-06-08 ✅ Traité

**Date** : 2026-06-08 — **Traité** : 2026-06-08 (commit 10ae917)

`jobs.py` implémenté. `snapshot` + `restore` CLI non-bloquants par défaut. `glorfindel jobs <vm> [--refresh]` disponible. 247/247 tests ✅.

---

### [Review → Glorfindel] Règle CLAUDE.md à étendre — `_build_user_message` zone à risque — 2026-06-08 ✅ Traité

**Date** : 2026-06-08 — **Traité** : 2026-06-08 (commit dd4751c)

Règle étendue dans CLAUDE.md Conventions : `_build_user_message()` ajoutée aux zones à risque aux côtés de `few_shot_examples.yaml` et `_SYSTEM_PROMPT`. Gate end-to-end T1486 + autre TTP requise.

---

### [Tests → Glorfindel] Bug critique — past_cycles ChromaDB inféré comme état courant — 2026-06-08 ✅ Traité

**Date** : 2026-06-08 — **Traité** : 2026-06-08 (commit 740659a)

Fix dual :
1. `_build_user_message()` : injecte maintenant `## État actuel de la VM` (isolated: OUI/NON, IPs bloquées) depuis `~/.glorfindel/isolation/<vm>.json` — source de vérité, jamais inférée.
2. `_SYSTEM_PROMPT` "Using past cycles" : CRITICAL warning explicite — past_cycles = historique PREVIOUS runs, jamais état courant.
3. Header past_cycles dans le message : "NE PAS inférer état courant depuis ces cycles".
4. Warning incident context : clarifié ("DANS CET INCIDENT — voir État actuel de la VM").
5. Schema `suggested_steps` : "escalate=true OR confidence < 0.7 → steps forensiques TTP-spécifiques".
3 tests ajoutés (isolation NON/OUI, header past_cycles). 238 tests ✅

⚠️ Re-run T1486 requis pour valider que le LLM ne saute plus isolate_vm cycle 1.

---

### [Tests → Glorfindel] suggested_steps non forensiques pour T1136.001 — 2026-06-08 ✅ Traité

**Date** : 2026-06-08 — **Traité** : 2026-06-08 (commit 740659a)

Root cause : LLM générait `escalate=false` → `suggested_steps=[]` (correct selon schema) → confidence gate forçait escalade → steps restaient vides → fallback statique.
Fix : schema `suggested_steps` mis à jour : "escalate=true OR confidence < 0.7 → forensic steps TTP-spécifiques". Exemples inline dans la description (account creation, ransomware, brute force).

---

### [Tests → Glorfindel] detection_timeout + snapshot bloquant — 2026-06-08 ✅ Traité

**Date** : 2026-06-08 — **Traité** : 2026-06-08

Fix dans `actions.py` : `AzureConnector.snapshot()` + ABC acceptent maintenant `wait: bool = True`.
Dans `execute_action` (`agent.py`) : `wait=event != "detection_timeout"` — fire-and-forget sur ce chemin.
Dans `verify_snapshot()` : status "InProgress" → `verified=None` (pas d'escalade verification_failed).
Test ajouté : `test_execute_action_snapshot_fire_and_forget_on_detection_timeout`. 235 tests ✅

---

### [Tests → Glorfindel] detection_timeout — suggested_steps forensiques par TTP — 2026-06-08 ✅ Traité

**Date** : 2026-06-08 — **Traité** : 2026-06-08

Few-shot example T1136.001 ajouté dans `few_shot_examples.yaml` — couvre detection ET detection_timeout.
Le LLM voit maintenant les suggested_steps forensiques à inclure pour T1136.001 :
`/etc/passwd`, `~/.ssh/authorized_keys`, crontabs, `last`/`who`, `/var/log/auth.log`.

---

### [Review → Glorfindel] T1136.001 — deux actions avant déploiement prod ✅ Traité

**Date** : 2026-06-07 — **Traité** : 2026-06-08

Action 1 (snapshot fire-and-forget) : implémentée — voir ci-dessus.
Action 2 (few-shot T1136.001) : implémentée — voir ci-dessus.
Le few-shot enseigne explicitement "T1136.001 ≠ isolate_vm" + confidence 0.35 → gate force escalade.
⚠️ Validation requise : run T1136.001 end-to-end sur Azure avant déploiement prod (convention few-shot).

---

### [Review → Glorfindel] Deux actions CLAUDE.md — 2026-06-05 ✅ Traité

**Date** : 2026-06-05 — **Traité** : 2026-06-05 (commit fb52239)

Les deux points étaient déjà adressés dans CLAUDE.md lors de la session précédente :
1. `backup_agent_check` reframé comme comportement conservateur voulu (Pitfalls section)
2. Règle sécurité few-shot/`_SYSTEM_PROMPT` ajoutée dans la section Conventions

---

### [Annatar → Glorfindel] `annatar snapshot` supprimé — `glorfindel snapshot` implémenté ✅

**Date** : 2026-06-05 — **Traité** : 2026-06-05

Commit cf17fdf :
- `AzureConnector.snapshot(resource_id, vault)` : backup on-demand RSV, attend complétion, retourne `"rsv:{vault}/{rg}/{job}"`
- `verify_snapshot()` : gère le nouveau format RSV + fallback Azure Compute snapshot legacy
- CLI `glorfindel snapshot <resource_id> --yes` : vault auto-détecté depuis `glorfindel-config.yaml`
- CLAUDE.md : workflow setup T1486 documenté

---

## Traités récemment

### [Tests → Glorfindel] T1486 — isolation absente + faux positif T1041 (run 20260605T113356Z)

**Date** : 2026-06-05 — **Traité** : 2026-06-05

Root cause : few-shot enseignait "isolation inutile → restore direct". LLM aggravé par past_cycles ChromaDB (T1486 → restore sur runs précédents) → LLM inférait isolation déjà active.

Signal T1041 NON null : `CallerIP=10.0.84.95`, `AccountName=stannatarexfil`, `PutBlobCount=2` — activité blob de la VM non-isolée, pas artefact RSV restore.

Fix (commit c6fe0d0) : 2 exemples T1486 dans `few_shot_examples.yaml`. Notification dans inbox_tests.

---

## Traités récemment

### [Tests → Glorfindel] Question opérationnelle — ransomware pendant un backup actif

**Date** : 2026-06-05 — **Traité** : 2026-06-05

Analyse transmise à Jonathan directement. Résumé :
- Le snapshot Azure est pris en ~30-60s tôt dans le job → si l'attaque démarre après, le RP capturé est propre
- `glorfindel restore --before` filtre sur le timestamp d'attaque → sélectionne automatiquement le bon RP
- `check_backup_points()` ne connaît pas l'intégrité des RPs, mais ce n'est pas nécessaire
- Pas bloquant MVP — edge case théorique (snapshot pris pendant l'encryption), fenêtre de quelques secondes
- Pas d'implémentation recommandée (annuler le backup en cours = complexité + permissions RSV)

---

## Traités récemment

### [Tests → Glorfindel] backup_agent_check — Process counter Windows-only, non supporté Linux (commit 8a664ee incomplet)

**Date** : 2026-06-05 — **Traité** : 2026-06-05

Option 2 retenue (documenter la limitation). Commit ccf317c :
- `monitoring.tf` : revert du counter `\\Process(*)\\IO Write Bytes/sec` (Windows-only)
- `agent.py` : commentaire mis à jour — limitation Linux documentée inline
- `CLAUDE.md` : ajouté dans "Pitfalls opérateur"

---

### [War Room → Glorfindel] Fix release — nettoyage isolation toujours effectué (commits f8aeb9b + 08be82a)

**Date** : 2026-06-05 — **Traité** : 2026-06-05

Informatif. Fixes déjà appliqués par War Room session.

---

## Traités récemment

### [Tests → Glorfindel] backup_agent_check retourne vide même avec backup Azure actif — run 20260605T073643Z

**Date** : 2026-06-05 — **Traité** : 2026-06-05

Root cause : DCR ne collecte pas `\\Process(*)\\IO Write Bytes/sec` — aucune donnée `ObjectName == "Process"` dans LAW. Fix (commit 8a664ee) : counter ajouté dans `monitoring.tf` + `MicrosoftAzureRecoveryServices` ajouté dans `_IQ_BACKUP_AGENT`. `terraform apply` requis (notification dans inbox_tests).

---

### [War Room → Glorfindel] Fix registry stale — audit War Room (commit 53aa926)

**Date** : 2026-06-05 — **Traité** : 2026-06-05

Informatif. Rien à faire côté Glorfindel.

---

### [War Room → Glorfindel] Fix registry stale — audit War Room (commit 53aa926)

**Date** : 2026-06-05

**Pour info, rien à faire côté Glorfindel.**

La War Room appelait `get_registry()` (singleton mémoire chargé au démarrage du container). Si la VM était éteinte au démarrage, la registry restait vide même après que `watch` avait découvert la VM et écrit dans `discovered_assets.json`.

Fix dans `api.py` : toutes les occurrences de `get_registry()` remplacées par `AssetRegistry()` — lecture fraîche depuis `~/.glorfindel/discovered_assets.json` à chaque appel. `/api/audit`, `/api/discovered`, `/api/state` (champ `discovered_assets`) et `_find_resource_id()` sont tous concernés.

Le `watch` service n'est pas touché — il continue à écrire dans `discovered_assets.json` via `DiscoveryService` normalement.

---

---

## Traités récemment

### [Review → Glorfindel] Test manquant + contention DCR T1548 — 2026-06-05

**Date** : 2026-06-05 — **Traité** : 2026-06-05

1. Test ajouté : `test_restore_resolves_escalation_case_insensitive()` (commit cc6778d) dans `tests/unit/test_agent_nodes.py`. 234/234 ✅.
2. CLAUDE.md déjà documenté ligne 26 (footnote `†`). Rien à ajouter.

---

## Traités récemment

### [Tests → Glorfindel] fb6312c — investigative_context propagation ne fonctionne pas (run 20260604T205729Z)

**Date** : 2026-06-04 — **Traité** : 2026-06-05

**Verdict** : pas de bug. `record_action` est dans `execute_action` (agent.py:703). Queue sérialisée — T1548 démarre après T1110 complet (T1110 20:58:50, T1548 21:00:01). Incident `8d03a050` a `actions_taken=[block_suspicious_ip]` quand T1548 démarre. Section "Incident en cours" IS injectée dans le prompt LLM. Le LLM cite la même info depuis ChromaDB past_cycles (T1110's cycle venait d'être stocké). Comportement correct, pas un bug. Analyse complète envoyée dans inbox_tests.

---

### [Tests → Glorfindel] T1548 detection_missed en run parallèle — DCR latence ou contention ?

**Date** : 2026-06-04 — **Traité** : 2026-06-05

DCR contention confirmée comme explication probable. `rulepoller_recently_matched` ne peut pas retourner `None` (uniquement `True`/`False`). Le `None` vu est une confusion d'affichage. Limitation documentée pour les runs parallèles — DCR peut saturer avec deux flux Syslog simultanés. Fix `ago(10m)` appliqué. Analyse complète dans inbox_tests.

---

## Traités récemment

### [War Room → Glorfindel] approve-rule / reject-rule CLI — auto-ack escalade manquant

**Date** : 2026-06-04 — **Traité** : 2026-06-05

**Fix** (commit a43f14c) : ajout de `resolve_by_proposal(proposal_id)` dans `escalations.py`. Appelé depuis `approve_rule` et `reject_rule` dans `cli.py` après succès. La `proposed_rule` escalade est maintenant résolue automatiquement — même comportement que la War Room.

---

### [Tests → Glorfindel] Deux bugs RulePoller/rule_status — run T1110+T1548 2026-06-04

**Date** : 2026-06-04 — **Traité** : 2026-06-05

**Bug 1 — `rule_status.json` manque le champ `ttp`**

Déjà fixé par commit 599d442 (1 juin). L'écriture `self._status[rule.name]["ttp"] = rule.ttp` est en place dans `_poll_rule`. Les entrées stales du 1 juin (sans ttp) ont `last_match` trop ancien pour tout `within_s` raisonnable — pas d'impact. Nouveaux matches écrivent bien le champ (`ransomware-disk-write` en est la preuve dans rule_status.json).

**Bug 2 — fenêtre `ago(5m)` trop étroite pour latence DCR variable**

Fix (commit 00b09bb) : `ago(5m)` → `ago(10m)` dans `ssh-brute-force` (T1110.001) et `sudo-privilege-escalation` (T1548.003). `data-exfiltration-blob` (StorageBlobLogs, latence secondes) et `ransomware-disk-write` (Perf, déjà `ago(10m)`) non touchés. 233/233 tests ✅.

---

## Traités (historique)

### [War Room → Glorfindel] restore_from_backup — escalades non acquittées après restore

**Date** : 2026-06-04 — **Traité** : 2026-06-04

Fix commit 64d4b2b : `resolve_by_resource` + dedup dans `record()` en case-insensitive.

### [War Room → Glorfindel] Escalades dupliquées — même action + resource_id

**Date** : 2026-06-04 — **Traité** : 2026-06-04

Fix commit b86fae2 : dedup par `action + resource_id + escalation_type` dans `record()`.

### [Review → Glorfindel] ARM Discovery — verdict + bug confidence gate

**Date** : 2026-06-04 — **Traité** : 2026-06-04

ARM Discovery reporté. Confidence gate fixé (commit 900dcfc).

### [General → Glorfindel] ARM Discovery — décision de coordination

**Date** : 2026-06-02 — **Traité** : 2026-06-04

ARM Discovery shelved. Code non écrit.

### [War Room → Glorfindel] Audit RSV — erreur Azure API depuis le container war-room

**Date** : 2026-06-02 — **Traité** : 2026-06-02

Fix asyncio.to_thread() (commit 1c28c74).

### [Général → Glorfindel] Backlog P1–P4 complet

**Date** : 2026-06-01/02 — **Traité** : 2026-06-02

P1–P4 ✅, P5+ à faire.

### [War Room → Glorfindel] Champ `event` manquant dans escalation record — 2026-06-09

**Date** : 2026-06-09

Fix court terme appliqué : `ESC_LABELS.low_confidence` → `'low confidence'` (commit `19ec3b8`).

**Fix long terme nécessaire** : `escalations.record()` ne stocke pas l'event (`detection` vs `detection_timeout`). Sans ce champ, la War Room ne peut pas distinguer "détecté mais confidence trop faible" de "non détecté (timeout)". Aujourd'hui les deux affichent "low confidence" — correct mais moins informatif.

**Action** : ajouter paramètre `event: str = ""` dans `escalations.record()` + l'écrire dans le JSONL. L'appeler depuis `agent.py` `escalate_to_human` avec `signal.get("event", "")`. War Room pourra alors afficher `detection · T1136.001 · 35%` ou `detection timeout · T1136.001`.

Pas bloquant — à faire quand pratique.
