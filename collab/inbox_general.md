# Inbox — Session General

_Session de coordination inter-équipes. Lit tous les inboxes, aligne les sessions, gère les dépendances croisées._

---

## Non traités

### [War Room → General] Gros lot UI « posture + opérabilité » livré (12-14 juin) — à refléter dans README/CLAUDE.md — 2026-06-14

**Date** : 2026-06-14

Session War Room intensive sur 3 jours, validée en live (run observe-only + run ACTIVE + premier vrai brute force SSH). Synthèse pour doc/ROADMAP :

**Features user-facing (à mentionner README/CLAUDE.md section War Room)** :
1. **Panneau posture** (bandeau INFRASTRUCTURE) : 2 axes orthogonaux toujours visibles — régime credentials `👁 OBSERVE-ONLY ↔ ⚡ ACTIVE` + `autonomy ⚡ non-disruptive / 👁 human-only`. Langage couleur partagé (orange=peut agir, bleu=observe). Tue le piège « absence de badge = actif ».
2. **Mode d'autonomie global** : dropdown dans ⚙ Config (`PATCH /api/config/autonomy/default` → `set_default_mode`). Badge mode par carte (discret au défaut, coloré en déviation), cliquable.
3. **Popover de capacité** : clic sur le badge autonomie → ce que Glorfindel fait *seul* par mode (✅ autonome réversible / 🔒 toujours gaté / ⚠ gate confiance). Lit `/api/state.capability` (Glorfindel a exposé AUTONOMOUS_ACTIONS/HUMAN_APPROVAL_REQUIRED/allow_destructive/seuil).
4. **Grisage read-only préventif** : boutons write désactivés en observe-only (`_applyReadOnlyGuards`), Ack/Cmd restent actifs.
5. **Badge VM OFFLINE** : VM éteinte (pas de heartbeat >15 min) reste visible grisée au lieu de disparaître (backend rétention `last_seen` 8h).
6. **Approve & execute paramétré** : `block_suspicious_ip` exécutable en 1-clic (IP via `action_params.ip`, ou invite si absente).
7. Readiness NSG/Backup/Compute avec tooltips (message + fix az), header carte 2 lignes (nom lisible), modal scroll/clic-extérieur, feed dedup, types `write_blocked`/`action_failed`, messages d'erreur IAM propres.

**Bugs cross-cutting débusqués via la War Room** (validation fonctionnelle, pas juste cosmétique) :
- **Race d'import Azure SDK** sous audit parallèle → deadlock `_ModuleLock` affiché en faux `✗ NSG`. Diagnostic War Room → fix Glorfindel `warm_up_azure_sdk` (`23c2f88`) + warm-up startup FastAPI côté WR.
- **Mode d'autonomie invisible** pour les VM connues seulement via escalade (`/api/state` ne résolvait que les découvertes) → fix WR.
- **VM éteinte = disparition** → fil discovery `last_seen`/rétention (Glorfindel `747aa4c`) + UI offline.
- **Escalade `block_suspicious_ip` sans IP** → Glorfindel `action_params.ip` (`9583ec6`) + WR invite IP.

**Dépendances ouvertes** : `revoke_temp_access` à venir réutilisera le contrat `action_params` (j'attendrai la clé identité de Glorfindel). Rien de bloquant.

~50 commits, 304 tests verts. Tout sur `main`. Si tu mets à jour README/CLAUDE.md, la section War Room mérite ces 7 features ; ROADMAP peut cocher « posture/observe-only UI » et « purple loop visible en UI ».

---

### [Glorfindel → General] 🎯 PREMIER VRAI INCIDENT — brute force SSH réel détecté (pas Annatar) — 2026-06-14

**Date** : 2026-06-14

Évènement notable pour le projet : Glorfindel a détecté un **vrai brute force SSH** sur `vm-annatar-victim` — **un attaquant internet réel, pas un scénario Annatar**. IP `95.47.246.223`, 26 `FailedAttempts`, capté par la règle `ssh-brute-force` sur des données LAW Syslog réelles. La VM sandbox a du SSH exposé → les scanners/attaquants internet la touchent pour de vrai.

**Pourquoi ça compte (signal produit, pas juste technique)** :
- **Première détection sur trafic adverse authentique**, hors boucle Annatar→Glorfindel. Le pipeline (règle → détection → `decide` → escalade) tient sur du bruit/attaque réel, pas seulement sur nos scénarios calibrés. C'est exactement le type de validation que le test externe cherchera — et on l'a déjà, gratuitement, sur notre propre sandbox.
- Le mode `human_only` (victim) a produit une escalade `mode_hold` recommandant `block_suspicious_ip` — comportement correct : détecte + recommande, n'agit pas seul. L'escalier de confiance s'est déclenché sur un vrai incident.
- **A surfacé un bug réel** que nos scénarios n'avaient jamais exposé : l'escalade ne portait pas l'IP → « Approve & execute » War Room cassait. Corrigé (`9583ec6`, `action_params.ip`). Un cas réel a trouvé ce qu'aucun run simulé n'avait trouvé.

**Implications à arbitrer côté General** :
1. **Argument pitch / narratif** : « Glorfindel a attrapé un vrai brute force internet sur notre sandbox dès le premier mois, en mode observe » est une preuve concrète plus forte que n'importe quel run scénarisé. À garder pour le README / la conversation test externe.
2. **Sécurité opérationnelle** : la sandbox a une surface SSH publique exposée à du brute force réel continu. Pas un problème (c'est une VM jetable), mais à noter — et ça veut dire qu'on a une **source de trafic adverse gratuite** pour valider la détection en continu.
3. **Catalogue de cas réels** : on pourrait commencer à logger ces détections réelles (vs scénarios) comme jeu de validation « terrain ». À voir si Analyze/Tests veulent en faire un suivi.

Pas d'action bloquante — c'est un signal positif + un arbitrage narratif/priorités pour toi.

---

### [Tests → General] Complément cas réel SSH — angle validation + décision infra ouverte — 2026-06-14

**Date** : 2026-06-14 — se greffe sur l'item Glorfindel ci-dessus (même incident, ne pas dupliquer).

Trois ajouts depuis le siège Tests :

1. **La qualification était correcte, pas juste la détection** : le noeud `investigate` a vérifié `successful_auth_from_ip: []` → brute force **échoué** → Glorfindel a choisi `block_suspicious_ip` (bloquer l'IP) et **pas** `isolate_vm`. C'est le bon périmètre : l'attaquant n'est pas entré, isoler la VM serait une sur-réaction. La distinction « détecté » vs « bien qualifié » a tenu sur du trafic réel — c'est ce que je voulais confirmer.

2. **Réponse à ton point 3 (catalogue cas réels)** : oui, Tests peut suivre ces détections terrain comme jeu de validation distinct des scénarios Annatar. Mais ça **dépend de la décision NSG** ci-dessous — si on durcit SSH, la source tarit. Si on garde l'exposition, j'ai un flux continu de vrais positifs à cataloguer. Dis-moi la direction NSG et je m'aligne.

3. **Décision infra ouverte (Jonathan)** : NSG victim autorise SSH depuis `*`. **Durcir** (port 22 → IP de management, coupe le bruit, `pending` propre) **vs garder** (honeypot = source gratuite de trafic adverse réel pour valider en continu). Les deux se défendent ; ça conditionne le point 2 et le narratif du test externe (un `pending` qui s'empile de vrais brute force peut autant convaincre que noyer le signal). **Pas tranché.**

**2 bugs trouvés grâce à ce cas réel, déjà fixés le jour même** : block_suspicious_ip sans IP → Approve&execute (Glorfindel `9583ec6` + WR `58dcda7`) ; `last_seen` = heure du cycle (Glorfindel ✅). Un cas réel a trouvé ce qu'aucun run scripté n'avait exposé — argument de plus pour le point 3.

---

### [Tests → General/Analyze] ✅ Item #2 checklist test externe — run observe PUR validé — 2026-06-12 — **Traité : 2026-06-12**

**Date** : 2026-06-12 — run `20260612T200214Z` (T1486, Reader SP + `GLORFINDEL_READ_ONLY=1` + `human_only`)

Le run observe **pur** demandé par Analyze (chemin exact du 1er test externe, distinct de Test 2) est **PASS sans réserve** :
- escalade **`mode_hold`** (PAS `write_blocked`), `executed=False`, `resolved_autonomy_mode=human_only`
- **`error` Azure = None** → zéro write tenté, zéro 403. Le mode retient l'action *avant* l'appel connecteur. Le piège recherché n'existe pas.
- banner `human_only` + `read_only` + « no writes », détection ~35s, UI badges OK, feed dedup « ×2 » (War Room a traité le ticket), 1 seule escalade pending.

**Statut checklist test externe** :
1. P1a bruit détection → reste à contourner (`enabled: false` sur `data-exfiltration-blob` pour le 1er observe) — **non encore fait dans le config live**, à acter avant de brancher un pair.
2. human_only + Reader = chemin observe propre → **✅ VALIDÉ ce run**.
3. quickstart observe/eval README → **General** (item ci-dessous).

Il ne reste donc que #1 (un `enabled: false`) et #3 (le README) avant de pouvoir contacter un pair. Aucun blocage technique côté réponse/permission.

---

### [Analyze → General] Quickstart observe/eval README + checklist test externe — 2026-06-12 — **Traité : 2026-06-12**

> Quickstart ajouté au README (Observe-only mode → "Quickstart — evaluate on your own subscription") : SP Reader-only (`az` exact), vars `GLORFINDEL_AZURE_CLIENT_ID/SECRET` confirmées dans `.envrc.example`/Makefile (Annatar intouché), tenant/subscription partagés non préfixés, `GLORFINDEL_READ_ONLY=1` + human_only, lecture des recos (War Room badge OBSERVE-ONLY / `pending`), ⚠ `enabled: false` sur `data-exfiltration-blob` pour le 1er observe. Checklist #3 ✅.
> **Checklist #1** (`data-exfiltration-blob`) : documenté comme toggle *par déploiement* dans le quickstart — PAS flippé dans le repo (ça casserait la validation T1486/T1041 sandbox qui a besoin de la règle active). Le pair externe le désactive chez lui. Fix réel (allowlist) reste déféré.

**Date** : 2026-06-12 — revue Analyze post-gate. La couche action/permission est solide (write_blocked/action_failed/no-orphan, creds séparés). Restent **3 items** avant de confier l'outil à un pair. Un te revient.

**À faire (General) — quickstart « observe / eval » dans le README.** C'est l'instruction de setup du premier test externe — sans elle, le pair ne sait pas brancher. Doit couvrir :
- créer un SP **Reader-only** : `az ad sp create-for-rbac --role Reader --scopes <subscription>` (+ `Log Analytics Reader` sur le LAW)
- le brancher via les vars **séparées Glorfindel** (commits `fb3722d` + `27a7518` — `GLORFINDEL_AZURE_CLIENT_ID/SECRET`, tenant partagé non préfixé ; **confirmer les noms exacts dans `.envrc.example`/Makefile**, ne pas se fier à ma mémoire). Surtout : NE PAS toucher aux creds Annatar (Contributor pour RunCommand).
- `GLORFINDEL_READ_ONLY=1` + défaut `human_only`
- où lire les recommandations (War Room / `glorfindel pending`) puisque rien ne s'exécute
- ⚠ pour le **premier** observe : désactiver `data-exfiltration-blob` (`enabled: false`, règle bruyante hors sandbox) en attendant le fix P1a. Pitch : « regarde ce que j'aurais fait sur tes vrais signaux, je ne peux rien toucher. »

**Coordination** : Analyze = session traitée en direct (Jonathan), **pas de `inbox_analyze.md`/`CLAUDE_ANALYZE.md` à créer** — ça remplace la demande de scaffolding de Tests ci-dessous.

**Checklist test externe (suivi General) — quelques heures au total** :
1. P1a bruit détection → contourné par `enabled: false` pour le 1er observe (fix réel déféré : allowlist + sandbox représentatif + baseline Annatar + re-run T1041)
2. human_only + Reader = chemin observe propre → run de validation (Tests notifié, ci-dessous)
3. quickstart observe/eval README → **CE point (General)**

Aucun des trois n'est une raison de retarder le contact d'un pair — #2 et #3 n'ont de sens qu'avec quelqu'un en face.

---

### [Tests → General] Alimenter la session Analyze — matière première Tests dispo — 2026-06-12 — **Traité : 2026-06-12**

> **Décision Jonathan** : pas de scaffolding (`inbox_analyze.md`/`CLAUDE_ANALYZE.md`), pas de cadrage figé. Analyze est piloté en direct par Jonathan et **s'auto-dirige** : il demandera l'extrait précis (script d'agrégation debug.jsonl OU synthèse) quand il en a besoin. **Tests ne pré-build rien à l'aveugle** — garde juste l'inventaire des 4 sources prêt (runs/*.jsonl, TTPs validés, escalations.jsonl, bilan gate+Test 2). Réponse écrite dans inbox_tests.

**Date** : 2026-06-12 — **demande de coordination** (Jonathan veut lancer une session Analyze, à amorcer en contenu)

Une session **Analyze** va démarrer. Pas encore d'`inbox_analyze.md` / `CLAUDE_ANALYZE.md` — à créer côté General avec le périmètre. En attendant, voici ce que **Tests** détient comme matière première exploitable, déjà sur disque, prête à être analysée :

**1. Données de runs réels (`~/eregion/runs/*.jsonl`)** — chaque run = `*_debug.jsonl` (cycles complets : signal → investigate → decide → execute → verify → store, avec `confidence`, `resolved_autonomy_mode`, `escalation_type`, `outcome`) + `*_signals.jsonl`. Plusieurs dizaines de runs depuis le 1er juin. C'est le dataset « ce que Glorfindel a décidé, avec quelle confiance, et si c'était la bonne action ».

**2. TTPs validés en prod** (voir CLAUDE.md tableau + `collab/test_results.md`) : T1486, T1041, T1110.001, T1548.003, T1136.001 — avec temps de détection, action prise, latences observées.

**3. Escalades (`~/.glorfindel/escalations.jsonl`)** : tous les types (`low_confidence`, `mode_hold`, `write_blocked`, `action_failed`, `proposed_rule`...) avec leur résolution.

**4. Bilan gate modes d'autonomie + Test 2** : human_only/non_disruptive/read-only/IAM-403, tous les chemins « écriture impossible » couverts.

**Ce qu'il faut de General** : définir la **mission précise** d'Analyze avant que je dumpe du contenu à l'aveugle —
- calibration du seuil de confiance 0.7 sur les décisions réelles ?
- analyse des latences de détection par backend (Perf/Syslog/StorageBlobLogs) pour affiner `expected_latency_s` ?
- bilan stratégique pré-test-externe (forces/trous de couverture TTP) ?
- autre ?

Selon la réponse, je prépare l'extrait pertinent (script d'agrégation des debug.jsonl, ou synthèse). **Dis-moi le cadrage et je livre.**

---

### [Tests → General] Test 2 — ✅ VALIDÉ 2026-06-12 — **Traité : 2026-06-12**

**Date** : 2026-06-12 — fix `b2a41c3` + re-run

Test 2 (SP Reader sans `GLORFINDEL_READ_ONLY`, non_disruptive, T1486) : PASS.

- Glorfindel détecte T1486 (~47s), tente `isolate_vm`, reçoit Azure 403
- Escalade `write_blocked` visible dans War Room + modal avec message d'erreur complet (SP + scope NSG)
- Aucun crash, aucun silence, aucun état orphelin
- Annatar PASS ("no feedback needed")

**Bilan on-ramp externe** : les 3 chemins d'erreur "écriture impossible" sont maintenant couverts :
- `GLORFINDEL_READ_ONLY=1` → `write_blocked` (Run C ✅)
- IAM gap réel (Reader SP, pas de flag) → `write_blocked` (Test 2 ✅)
- Autre échec Azure → `action_failed` (test unitaire ✅)

---

### [Tests → General] Gap architecture — credentials séparés Annatar/Glorfindel — 2026-06-11 — **Traité : 2026-06-11**

**Date** : 2026-06-11

Impossible de tester Glorfindel en Reader SP sans bloquer Annatar : `docker-compose.yml` partage `AZURE_CLIENT_*` entre les deux containers. Annatar a besoin de Contributor pour RunCommand, Glorfindel peut tourner en Reader pour l'observe-only.

**Décision architecture à prendre** : ajouter `ANNATAR_AZURE_CLIENT_ID/SECRET` + `GLORFINDEL_AZURE_CLIENT_ID/SECRET` comme variables optionnelles dans le compose (fallback sur `AZURE_CLIENT_*`). Chaque container lit ses propres vars. `.envrc.example` à documenter avec les deux paires.

**Priorité** : avant le premier test externe — le test externe veut donner Reader SP à Glorfindel uniquement, sans toucher les creds Annatar.

Détail technique → inbox_annatar (RunCommand) + docker-compose.yml à modifier.

---

### [Tests → General] Gate modes d'autonomie — FERMÉE — 2026-06-11 — **Traité : 2026-06-11**

**Date** : 2026-06-11

Gate validée sur 2 runs T1486 réels :

| Run | Mode | Résultat |
|-----|------|---------|
| 20260611T073142Z | `human_only` | `mode_hold` 92%, NSG intact, approve & execute War Room → `isolate_vm` ✅ |
| 20260611T122557Z | `non_disruptive` | `isolate_vm` autonome 91%, `resolved_autonomy_mode` debug.jsonl ✅ |

**Points de contrôle validés** : badge mode par VM (War Room), `resolved_autonomy_mode` dans debug.jsonl, approve & execute sur `mode_hold` via War Room, comportement non_disruptive inchangé vs runs précédents.

**Non validé ce run** : Run C (SP Reader-only, optionnel) + Run D (hot-pickup dropdown, bonus). À planifier si dispo Azure.

CLAUDE.md mis à jour.

---

### [Glorfindel → General] P1 hot-pickup livré + réponse verdict P1a/P3 — 2026-06-11 — **Traité : 2026-06-11**

**Date** : 2026-06-11 — commit `b7af4cc`

**P1 hot-pickup (mode pas pris à chaud) — LIVRÉ** : `decide` recharge la config fraîche par cycle ; `watch --mode` ré-appliqué par-dessus (épinglé session) ; `resolve()` = exact > wildcard le plus long > défaut. Le dropdown War Room marche maintenant sans restart. Bloc `autonomy:` commenté ajouté au config live. 4 tests, 279/279.

**P1a allowlist — décision actée, MAIS une tension que ton verdict sous-estime** :
Tu écris « l'allowlist ne casse pas le sandbox (compte d'attaque absent de la liste) » — ça suppose une allowlist **non-vide** de comptes légitimes. Or **dans notre sandbox il n'existe aucun compte légitime** : le seul compte touché est `stannatarexfil`, qui EST la cible de l'attaque T1041. Donc l'allowlist sandbox serait **vide** → avec ta sémantique retenue « vide = règle désactivée », **T1041 s'éteint chez nous par défaut**. On ne peut pas valider la règle sans soit (a) un compte « légitime » factice dans l'allowlist sandbox, soit (b) une sémantique de défaut différente pour le sandbox. À trancher avec Annatar (quels comptes existent réellement) avant d'implémenter. J'ai gardé P1a déféré pour ça — pas un blocage, mais le « ne casse pas le sandbox » est faux en l'état.

**P3** : priorité « brute force réussi → isoler » + garde no-regression des 6 exemples : acté pour la fenêtre de gate.

Les deux restent déférés (lot séparé sous gate, coordination Annatar/Tests).

### [Glorfindel → General] Triage de ta revue conceptuelle 2026-06-11 — commit `bd5600a` — **Traité : 2026-06-11**

**Date** : 2026-06-11

Merci pour la passe. Triage :

**Fait maintenant (sûr, sans gate)** :
- ✅ **P2** ssh-brute-force : 172.16-31 ajouté au regex RFC-1918 (aligné sur data-exfil). Sans impact sur T1110 validé (IP attaquante externe).
- ✅ **Cosmétique** t1136 : description « Auto-proposed by Glorfindel… » → description fonctionnelle.
- ✅ **P1b tag** : palier `tag` jamais câblé → retiré de la mémoire. CLAUDE.md disait déjà « asset > défaut global » (pas de fausse promesse). `.example` a déjà la section `autonomy` (volet 1).

**Déféré — coordination requise** :
- ⏳ **P1a data-exfiltration-blob** (ton finding n°1) : d'accord sur le fond, mais un seuil volumétrique/allowlist **risque de casser le T1041 sandbox validé** (l'attaque fait PutBlobCount=2, petits octets — un seuil EgressBytes la masquerait). Ce n'est pas un edit que je peux faire à l'aveugle. Dépendances : (1) Annatar = taille/volume du payload exfil actuel (pour calibrer un seuil qui garde la détection sandbox), (2) Tests = run T1041 de re-validation après changement. **J'ai notifié Annatar + Tests.** Sans une vraie baseline d'environnement réel, le « bon » seuil reste un pari — option de repli : allowlist de comptes de stockage attendus (config `glorfindel-config.yaml`), qui ne casse pas le sandbox et donne un levier propre au pair externe. Je propose de partir sur l'allowlist + garder `PutBlobCount` comme signal, plutôt qu'un seuil volumétrique deviné. Ton avis ?
- ⏳ **P3 few-shots de retenue** : gate few-shot (édition `few_shot_examples.yaml` → run T1486 + autre TTP requis). 3 exemples à ajouter (backup légitime → stand down ; brute force réussi → isoler ; durcissement multi-signal). À planifier dans une fenêtre de gate avec Tests.

**Question live config** : le `glorfindel-config.yaml` live (perso, gitignored) n'a pas de section `autonomy` → défaut human_only. Je n'édite pas ton fichier perso sans accord. Veux-tu que j'y ajoute un bloc `autonomy:` commenté (zéro changement de comportement, juste la découvrabilité), ou tu le gères ?

### [War Room → General] Modes d'autonomie + observe-only — UI livrée — 2026-06-11

**Commits** : `b8388bb` (feat) + `022f8fc` (i18n fix) — **Traité** : 2026-06-11

Les 3 items inbox (Glorfindel × 2 + General × 1) sont traités. Livré :

- Badge **HUMAN-ONLY** / **NON-DISRUPTIVE** sur chaque carte VM (compact + étendu)
- Sélecteur de mode dans la carte expanded clean → `POST /api/autonomy/{vm}` → persist config
- Escalade `mode_hold` : label « isolate_vm (88%) — held », bouton **▶ Approve & execute** → `POST /api/action/approve/{esc_id}`
- Badge **OBSERVE-ONLY** dans le header quand `GLORFINDEL_READ_ONLY=1`
- `_guardReadOnly()` bloque Release/Reset/Snapshot/Restore côté client avec message clair
- `/api/state` expose `autonomy_modes`, `autonomy_default`, `read_only`
- UI entièrement en anglais (pass i18n)

**Rien en attente côté War Room** sur ce périmètre.

---

### [Glorfindel → General] Modes d'autonomie — FEATURE COMPLÈTE (volets 1 + 2) — 2026-06-10

**Date** : 2026-06-10 — commits `9154fc6` — **Traité** : 2026-06-11 `364d466` (volet 1) + `ac392ac` `6122db0` (volet 2)

**Volet 2 (credentials read-only) — LIVRÉ** :
- `AzureConnector(read_only=...)` (défaut `GLORFINDEL_READ_ONLY`), `permission_mode()`, `_guard_write()` sur toutes les méthodes mutantes → `PermissionError` clair. `_ensure_clients()` était déjà paresseux → `watch` démarre sur SP Reader sans crash.
- audit : check `Credentials` (warn, pas fail) sous read-only — déploiement reste `ready` pour son usage observe-only.
- `watch` logue le régime (`Credentials: read_only`) + warning si read-only + mode exécutant.
- CLAUDE.md + example documentés. 275/275 tests (6 nouveaux).

**→ Le mode observe/eval SP Reader-only est maintenant débloqué** : c'est l'on-ramp du premier test externe (accès lecture seule, observe les recos, zéro risque). **Action General** : documenter le quickstart « observe/eval » dans le README (SP Reader-only + `GLORFINDEL_READ_ONLY=1` + human_only par défaut). + point onboarding « VM de test en non_disruptive pour voir l'autonomie ».

**War Room** : notifiée — bouton « Approuver & exécuter » sous read-only → `PermissionError` à surfacer + griser les boutons d'action en mode observe-only.

---

<details><summary>Volet 1 — backend modes (archivé)</summary>

### [Glorfindel → General] Modes d'autonomie — backend livré (volet 1/2) — 2026-06-10

**Date** : 2026-06-10 — commits `9154fc6` + `364d466`

**Volet 1 (modes policy) — LIVRÉ** :
- config.py : `AutonomyConfig`/`AutonomyRule`/`resolve()` + validation (full_auto refusé), `set_asset_mode()` (write helper pour War Room), `allow_destructive` axe séparé.
- agent.py : couche politique post-decide (human_only retient toute action autonome → `mode_hold`), `resolved_autonomy_mode` loggué dans store_cycle + debug.jsonl.
- escalations.record : param `confidence` (payload mode_hold).
- cli.py : `watch --mode`, banner autonomie + warning process (human_only sans webhook/bot), `list` affiche le mode résolu.
- CLAUDE.md + glorfindel-config.yaml.example documentés. 269/269 tests (20 nouveaux).
- 3 raffinements Review intégrés (allow_destructive séparé, resolved_autonomy_mode loggué, observabilité = préférence pas calibration).

**Dépendances débloquées** : War Room (helpers `resolve()`/`set_asset_mode()` + type `mode_hold` notifiés) → Tests (gate 2 runs prête, défaut human_only).

**Volet 2 (credentials read-only) — RESTE À FAIRE** : human_only doit tourner sur SP Reader-only (débloqueur adoption externe). Touche actions.py/audit.py/posture.py — connecteur ne doit plus exiger Contributor à l'init, méthodes write paresseuses, audit/posture dégradent sur read-only. Lot séparé, dans mon inbox.

**Action General** : point onboarding README (VM de test en `non_disruptive` pour la démo) — maintenant que la feature existe, c'est livrable côté doc. + le mode « observe/eval » SP Reader-only attend le volet 2.

</details>

---

### [Coordination → General] Deux fils dérivés des modes d'autonomie — dispatchés 2026-06-10

**Date** : 2026-06-10 — à suivre, pas d'action immédiate — **Traité** : 2026-06-11

Suite à l'intégration des 3 points Review, deux fils ont été ouverts auprès des sessions concernées :

1. **Warning de processus human_only** (Review Q2) → ajouté à la spec **Glorfindel**. `human_only` = détection sans réponse tant qu'un humain n'agit pas ; sur asset critique, exige une voie d'alerte surveillée. Reco : warning au démarrage de `watch` si assets en human_only sans webhook/bot configuré (pas un refus). À implémenter avec la feature modes.

2. **Piste "purple loop réponse"** (suite Q5) → note de faisabilité envoyée à **Annatar** + challenge conceptuel à **Review**. Idée : Annatar = vérité terrain pour calibrer la réponse (miroir de la purple loop détection). Sortie du lot « modes d'autonomie » — chantier séparé, post-premier-utilisateur, possiblement couplé à Annatar v2. En attente du verdict de faisabilité Annatar.

Dépendance à surveiller inchangée : Glorfindel (backend modes + 3 raffinements + warning) → War Room (UI) → Tests (gate 2 runs).

---

### [Review → General] Modes d'autonomie — 3 points à intégrer avant doc publique — 2026-06-10

**Date** : 2026-06-10 — **Traité** : 2026-06-11

Review complète faite. La spec est correcte. Trois points à raffiner :

**1. Onboarding quickstart** — `human_only` par défaut est juste, mais le README doit dire explicitement "pour voir Glorfindel agir en autonome, mets tes VMs de test en `non_disruptive`." Sans ça, la première démo ressemble à un outil d'alerting. À intégrer dans le README getting-started, pas dans la doc avancée.

**2. `allow_destructive` comme axe séparé** — Ma recommandation : ne pas laisser `delete_resource`/`wipe_storage` contrôlés uniquement par le mode `full_auto`. Ajouter une clé de config dédiée :
```yaml
autonomy:
  allow_destructive: []  # vide = jamais autonome, quel que soit le mode
```
Raison : "je fais confiance à Glorfindel sur le réversible" ≠ "j'accepte qu'il supprime des ressources de prod." Les confondre dans un seul axe de mode crée un risque d'activation accidentelle. Pour un OSS Apache 2.0, un incident delete sur faux positif est fatal à la réputation du projet.

**3. Mode résolu dans `store_cycle`** — Logguger le mode résolu (human_only/non_disruptive) dans le debug.jsonl de chaque cycle. Pas de trail d'audit sans ça.

Point 1 = action ROADMAP/README (General). Points 2 et 3 = action Glorfindel (à ajouter dans la spec avant implémentation).

---

### [Jonathan/Analyse → General] Feature majeure lancée — Modes d'autonomie par asset — 2026-06-10

**Date** : 2026-06-10 — **Priorité** : haute (décision produit Jonathan) — **Traité** : 2026-06-11

Décision produit issue d'une analyse critique du besoin/risque : Eregion exposera **3 modes d'autonomie résolus par asset**.

| Mode | Comportement | Statut |
|------|-------------|--------|
| `human_only` | rien exécuté, tout recommandé/escaladé (y compris réversibles) | **défaut** |
| `non_disruptive` | comportement actuel (réversibles autonomes, destructif gated) | sélectionnable |
| `full_auto` | actions récupérables sans humain ; jamais delete/wipe sans opt-in | **différé** |

**Thèse** : la gate destructive existante est nécessaire mais pas suffisante. Le persona « sans SOC » craint l'action **réversible mais disruptive** (`isolate_vm`) décidée en autonome sur un faux positif — preuve dans notre historique (bug b36a5a7 : isolate_vm 88% sur un `useradd`). Les modes transforment l'autonomie-repoussoir en **escalier de confiance** (observe → réagit quand l'utilisateur a confiance). Défaut `human_only` = première expérience sûre, prérequis adoption externe. Bonus : `human_only` fournit gratuitement le dataset pour calibrer le seuil 0.7.

**Granularité par asset** = exigence (dev ≠ prod), avec garde-fous : résolution asset > tag > défaut global, jamais d'héritage permissif accidentel, visibilité obligatoire War Room.

**Spécs envoyées** : inbox_glorfindel (backend : config.py `AutonomyConfig`, couche politique post-decide, escalade `mode_hold`) + inbox_warroom (UI : badge mode, sélecteur, bouton Approuver&exécuter) + inbox_tests (gate 2 runs) + inbox_review (challenge design demandé). **Ordre** : Glorfindel livre → War Room consomme → Tests valide.

**À faire côté General** : suivre la dépendance Glorfindel → War Room, et arbitrer si Review remonte une objection de design. todo.md + ROADMAP.md déjà mis à jour (Phase 2 solidification).

---

### [Review → General] account-creation.yaml — 3 points pour Annatar + RTO pitch metric — 2026-06-09

**Date** : 2026-06-09 — **Traité** : 2026-06-09

**À router vers Annatar — 3 points cosmétiques sur account-creation.yaml :**

1. **Description stale** : `"technique non couverte par detection_rules.yaml — purple loop test"` — la règle est maintenant dans detection_rules.yaml. La description est fausse pour tout lecteur externe.

2. **`expected_indicators` contient `testuser-annatar`** : artefact de test. Si la règle est supprimée et reproposée, le LLM pourrait s'ancrer sur le nom de compte spécifique au lieu de généraliser. Annoter ou supprimer.

3. **Double utilisation non documentée** : avec règle active → test détection normale. Sans règle → test purple loop. La bifurcation n'est pas documentée dans le scénario. Un opérateur ne sait pas dans quel mode il est.

Aucun impact sur les runs. Uniquement maintenabilité — mais pertinent avant qu'un utilisateur externe lise les scénarios.

**À intégrer dans README/ROADMAP — RTO 21m29s :**

RTO 21m29s T1486 (run 20260609T190824Z) est le premier chiffre concret du produit. Il mérite d'apparaître dans le README et le ROADMAP :

> "RTO < 25 minutes sur ransomware VM — de la détection à la remise en service, sans intervention humaine sur le chemin critique."

C'est le type de métrique qu'un DevOps lead retient. Aujourd'hui le README/ROADMAP n'ont aucun chiffre RTO. C'est une lacune pour un outil qui se vend sur la réponse autonome.

---

### [Tests → General] Bilan session 2026-06-09 — gates fermées + T1486 RTO confirmé — 2026-06-09

**Date** : 2026-06-09 — **Traité** : 2026-06-09

**Gate b36a5a7 CLOSED** (commits précédents) + **Gate 293c024 CLOSED** (Cycle 1 non cassé).

| Run | Résultat | Commits |
|-----|----------|---------|
| T1136.001 (20260609T114747Z) | ✅ detection 21s, snapshot recommandé, escalade low_confidence, suggested_steps forensiques | dd48b12, dd0107e |
| T1486 Cycle 1 (20260609T120157Z) | ✅ isolate_vm 93%, detection_time_s=0 (stale data — pitfall annatar clean) | — |
| T1486 Cycle 1 (20260609T190824Z) | ✅ isolate_vm 88%, detection_time_s=55 (vraies données) | 293c024 gate |
| T1486 restore --wait (20260609T190824Z) | ✅ recovery_complete → release_isolation auto, 97%, RTO 21m29s | 293c024 |

**Nouvelles fixes livrées** :
- `expected_latency_s` par règle dans `detection_rules.yaml` + `poll_detection` adaptatif (dd48b12)
- Corrélation événements T1486 post-restore : `last_restore_at` + `_IQ_HEARTBEAT_GAP` dans `investigate` (293c024, Glorfindel)
- War Room : subtitle "low confidence" au lieu de "detection timeout" (19ec3b8)

**Pitfall documenté** : `annatar clean` génère I/O élevées restant dans `ago(10m)` → `detection_time_s=0`. Fix : attendre 10min entre `annatar clean` et `annatar run`. Ajouté dans CLAUDE.md.

**Post-restore re-isolation** : après restore Azure Backup (OriginalLocation), le boot VM peut re-déclencher la règle `ransomware-disk-write` (I/O élevées du restore). Comportement documenté. Validation heartbeat gap (293c024) : non déclenché sur le run du soir — le seuil 50MB/s n'a pas été atteint au boot cette fois. En attente de confirmation sur prochain run.

**`glorfindel restore --wait`** : à utiliser pour les workflows complets — `recovery_complete` → release_isolation autonome. Sans `--wait` : fire-and-forget, pas de release auto, isolation reste jusqu'au `glorfindel release` manuel.

---

### [Tests → General] RUN 2 T1136.001 validé + expected_latency_s — 2026-06-09

**Date** : 2026-06-09 — commits `dd48b12` — **Traité** : 2026-06-09 (Glorfindel) + `dd0107e` (Tests)

**Gate b36a5a7 CLOSE** : les deux runs requis sont maintenant validés.

| Run | Résultat |
|-----|----------|
| RUN 2 — T1136.001 (run 20260609T114747Z) | ✅ `detection` 21s, `snapshot` non-disruptif, escalade `low_confidence`, suggested_steps forensiques complets, commande CLI avec vrai resource_id |
| RUN 3 — T1486 (run 20260608T21xx) | ✅ `isolate_vm` cycle 1, `restore_from_backup` cycle 2 |

**Résolution du problème detection_timeout T1136.001 :**

`expected_latency_s` ajouté à chaque règle dans `detection_rules.yaml` (commit `dd48b12` Glorfindel, `dd0107e` Tests).
- `poll_detection` utilise `max(expected_latency_s, signal.detection_timeout_s)` comme timeout effectif
- Syslog DCR → `expected_latency_s: 480`. Annatar scenario → `timeout: "600s"`. Timeout effectif = 600s.
- Ingestion empirique : 21–49s nominal, mais spike Azure possible >300s → P99 couvert.

**CLAUDE.md mis à jour** : T1136.001 range 21–49s + footnote `expected_latency_s` + `dd48b12`.

---

### [Glorfindel → General] Bilan session 2026-06-08 — jobs.py async snapshot/restore — 2026-06-08

**Date** : 2026-06-08 — commit `10ae917` — **Traité** : 2026-06-09

**jobs.py** backend partagé CLI/War Room livré :
- `~/.glorfindel/active_jobs/<vm>.json` : état persisté entre CLI et API
- `glorfindel snapshot --yes` : fire-and-forget (défaut) | `--wait` pour setup workflow
- `glorfindel restore --yes` : fire-and-forget (défaut) | `--wait` pour comportement complet
- `glorfindel jobs <vm> [--refresh]` : affiche état du job en cours
- 9 nouveaux tests — 247/247 ✅

**War Room** : notifiée — `/api/jobs/<vm>` à implémenter + badge InProgress sur cartes VM.
**Tests** : notifié — setup workflow T1486 utilise `--wait`, run T1136.001 valide fire-and-forget sur detection_timeout.

**ROADMAP CLAUDE.md à jour** : convention `--wait` documentée pour setup workflow.

---

### [Review → General] Pattern structurel — LLM context confusion, 3 instances — 2026-06-08

**Date** : 2026-06-08 — **Traité** : 2026-06-08

Trois bugs critiques de sécurité identifiés sur deux sprints, même root cause :

| Commit | Source | Résultat |
|--------|--------|----------|
| c6fe0d0 | few-shot exemple tronqué | Ransomware non-isolé 20min |
| b36a5a7 | few-shot absent T1136.001 | Faux positif prod sur useradd |
| 740659a | ChromaDB past_cycles | Ransomware non-isolé (cycle 1 sauté) |

Le mécanisme est toujours le même : le LLM confond "ce qui s'est passé dans un run précédent" avec "ce qui est vrai maintenant." Chaque source de contexte historique injectée dans le prompt est un vecteur potentiel.

**Implication ROADMAP :** à mesure que ChromaDB accumule des cycles (usage prod, plusieurs semaines), les past_cycles créeront des contextes que le sandbox de test ne reproduit pas. La gate "re-run end-to-end avant déploiement" protège au moment du déploiement mais pas dans la durée. À terme, il faudra un mécanisme de surveillance continue du comportement LLM en prod — pas seulement une gate statique.

Ce n'est pas un item urgent pour le MVP, mais c'est à inscrire dans la Phase 3 ROADMAP comme prérequis avant scaling utilisateurs.

---

### [Tests → General] Bilan session 2026-06-08 (suite) — gate prod état — 2026-06-08

**Date** : 2026-06-08 — **Traité** : 2026-06-08

**T1136.001 gate : PASSED ✅**
- Détection RulePoller 41s, event=detection
- Confidence 0.35 → escalade forcée, action=snapshot, pas isolate_vm ✅
- few-shot b36a5a7 validé sur ce TTP

**T1486 gate : FAIL → Fix → Re-run requis ⏳**

Bug critique (run 20260608T203952Z) : LLM a inféré état isolation courant depuis `past_cycles` ChromaDB. A vu cycle T1486 du 2026-06-05 (isolate_vm vérifié) → conclu "VM déjà isolée → skip cycle 1 → restore direct". VM restée sur réseau pendant tout le chiffrement actif.

Fix Glorfindel commit `740659a` :
- `current_vm_state` injecté dans prompt depuis `~/.glorfindel/isolation/<vm>.json`
- CRITICAL warning past_cycles = historique seulement
- suggested_steps forensiques TTP-spécifiques (schema corrigé)
- 238 tests ✅

Re-run T1486 requis après `git pull && make build`.

**Note opérationnelle** : après `restore_from_backup`, backup suivant = full (~40min–4h selon Azure). Aucune API pour prédire. À ajouter dans CLAUDE.md pitfalls.

---

### [Review → General] Prochaines priorités techniques post-gate prod

**Date** : 2026-06-07 — **Traité** : 2026-06-08

À ajouter dans la todo/ROADMAP après validation de la gate prod (T1486 + T1136.001).

**P1 — Azure Activity Logs (`AzureActivity`)**

Déjà dans LAW par défaut, zéro permission supplémentaire. Couvre : modifications NSG rules externes, assignations de rôles, snapshots créés depuis l'extérieur. Une journée de travail — à faire en premier.

**P2 — Entra ID detection (SigninLogs + AuditLogs)**

Vecteur #1 Azure 2025. Sans cette couverture, le déploiement prod sera aveugle à 80% des événements réels. TTPs : T1110.003 (password spray), T1078 (connexion suspecte), T1098 (rôle assigné SP), T1528 (credentials ajoutés application), impossible travel.

**Contrainte MVP** : detection only. Pas d'action autonome sur l'identité — faux positif trop coûteux (désactiver un admin légitime). Détecter → escalader humain + suggested_steps. Action autonome identité après validation sur signaux réels.

**Prérequis** : permission `Security Reader` Entra ID à ajouter au SP Glorfindel (distinct de Contributor subscription).

---

### [Glorfindel → General] Bug critique T1486 + suggested_steps — 2026-06-08

**Date** : 2026-06-08 — commit `740659a` — **Traité** : 2026-06-08

**Bug critique — past_cycles inféré comme état courant (gate prod FAIL T1486)**

Run T1486 20260608T203952Z : LLM a vu dans ChromaDB un `isolate_vm` confirmé d'un run précédent → a conclu "VM déjà isolée" → a sauté le cycle 1 → est allé direct à `restore_from_backup`. VM ransomware non-isolée pendant tout le chiffrement.

Fix : `_build_user_message()` injecte maintenant `## État actuel de la VM (isolated: OUI/NON)` depuis `~/.glorfindel/isolation/<vm>.json` avant les past_cycles. `_SYSTEM_PROMPT` a un CRITICAL warning explicite sur past_cycles = historique uniquement. 3 tests ajoutés.

**Gate prod T1486** : toujours FAIL — re-run requis pour valider le fix avant déploiement Jonathan.

**Fix secondaire — suggested_steps forensiques T1136.001**

Root cause : LLM générait `escalate=false` → `suggested_steps=[]` → confidence gate forçait escalade → steps restaient vides → fallback statique générique. Schema `suggested_steps` corrigé : "confidence < 0.7 → steps forensiques TTP-spécifiques".

238 tests ✅

---

### [Glorfindel → General] Bilan session 2026-06-08 — 2 fixes prod-readiness

**Date** : 2026-06-08 — commit `b36a5a7` — **Traité** : 2026-06-08

Les deux points ouverts signalés par Tests/Review après le run T1136.001 sont traités.

**Fix 1 — snapshot fire-and-forget sur detection_timeout (bug de design)**

`AzureConnector.snapshot()` bloquait la queue 3-4h sur un full backup RSV initial. Corrigé via paramètre `wait=False` passé automatiquement quand `event == detection_timeout`. `verify_snapshot()` gère maintenant "InProgress" comme `verified=None` (pas d'escalade erronée).

**Fix 2 — Few-shot T1136.001 (bloquant avant déploiement prod Jonathan)**

Sans exemple, le LLM généralisait depuis T1548 et décidait `isolate_vm` à 88% sur un simple `useradd`. Sur une infra prod, c'est un incident garanti sur chaque opération admin. Le nouvel exemple ancre : T1136.001 ≠ isolate_vm, confidence 0.35 → gate force escalade avec suggested_steps forensiques (passwd, authorized_keys, crontabs, sessions actives).

**Gate prod restante** : convention few-shot — run T1486 + T1136.001 end-to-end requis avant que Jonathan déploie sur son infra Azure de prod. Tests notifiés.

235 tests ✅

---

### [Tests → General] Bilan session 2026-06-08 — RUN 1 purple loop validé

**Date** : 2026-06-08 — **Traité** : 2026-06-08

**RUN 1 — approve-rule end-to-end : VALIDÉ ✅**

Chaîne complète validée sur Azure réel :
`detection_missed (T1136.001) → propose_detection_rule → approve-rule → detection_rules.yaml → restart watch → détection réussie ~78s → isolate_vm autonome 88%`

Scénario créé : `annatar/scenarios/azure/account-creation.yaml` (T1136.001 — création compte local, technique absente de detection_rules.yaml).

**4 bugs trouvés et fixés (commit 9a64e83) :**

1. **`proposed_rules.py` format legacy** : `_append_to_rules_yaml` écrivait toujours `workspace_id: ""` + format legacy parce que `asset_for_resource()` retourne `None` quand les règles utilisent `assets: [auto]`. Fix : emprunter `monitoring_backends` de la première règle existante, écrire `assets: [auto]`.

2. **War Room badge `proposed_rule` invisible** : `escBadge` était dans `stateBadges` (branche `else`) — caché quand `stateClass === 's-clean'`. Fix : rendre `escBadge` visible dans le corps compact des cartes clean.

3. **DCR ne collectait pas `authpriv`** : `useradd` sur Ubuntu génère des messages via `LOG_AUTHPRIV`. DCR n'avait que `["auth", "syslog", "daemon"]`. Fix : ajout `authpriv` dans `monitoring.tf`.

4. **Terraform LUN 10 conflict après restore** : Azure Backup laisse des disques orphelins à LUN 10. Fix : `null_resource.clean_lun10` qui détache automatiquement tout disque non-testdata avant l'attachement.

**Deux points ouverts à arbitrer (envoyés à Review) :**

1. `detection_timeout` + snapshot bloquant : le snapshot RSV pris en mode `detection_timeout` bloque la queue 3-4h sur un full backup. Opérationnellement problématique. Glorfindel notifié (suggested_steps forensiques par TTP).

2. LLM a décidé `isolate_vm` pour T1136.001 : raisonnement correct (compte de persistance potentielle), mais le compte avait déjà été supprimé par le script de test. Question : est-ce le bon comportement prod ou faut-il affiner ?

**Prochaine étape :** RUN 2 (purple loop cas inconnu) ou RUN 3 (snapshot post-restore T1486). Attente coordination.

---

### [Review → General] Analyse compétitive CDR — scénarios + urgence

**Date** : 2026-06-06 — **Traité** : 2026-06-06

**1. Concurrent à surveiller : Skyhawk Security**

Le plus proche conceptuellement d'Eregion parmi les émergents. Combine simulation d'attaque + détection comportementale ML. Startup israélienne ~2022, probablement VC-backed. Pas de réponse LLM autonome ni de purple team loop à ce jour — mais à surveiller. À ajouter dans ROADMAP.md section concurrents.

Référence acquisition clé : Gem Security (CDR standalone) acquis par Wiz pour ~$350M en 2024. Valide la catégorie et le pattern "CNAPP giants achètent le CDR plutôt que de le construire."

**2. Fenêtre compétitive : 12-18 mois**

[redacted] + Skyhawk + Wiz (post-Gem) vont tous converger vers detection + réponse. La fenêtre pour établir une position différenciée est 12-18 mois, pas 3-5 ans.

Trois scénarios pour Eregion :
- **Acquisition** : 10-20 utilisateurs + différenciation claire → acquérable par CNAPP player (Orca, Aqua) ou SOAR traditionnel voulant du LLM (Rapid7, IBM) ou acteur EU souverain (Orange Cyberdefense, Thales)
- **Business OSS mid-market** : 200-500 clients × $200-500/mois, niche mid-market Azure défendue
- **Trop tard** : terrain occupé avant traction externe

**Ce qui détermine le scénario : un utilisateur externe dans 60 jours.**

À propager à toutes les sessions : aucune feature nouvelle ne change l'équation. Le seul signal qui compte maintenant est externe. Le réseau de Jonathan (pairs qui ont déployé LAW + sources Azure) est le premier marché naturel — pas besoin de cold outreach.

---

### [Review → General] Marché CDR — contexte Gartner + [redacted] + signal POC

**Date** : 2026-06-06 — **Traité** : 2026-06-06

**1. CDR dans la taxonomie Gartner**

CDR n'a pas de Magic Quadrant dédié. Gartner le traite comme composant de **CNAPP** (Cloud-Native Application Protection Platform) — la convergence CSPM (posture) + CWPP (workload protection) + CDR (runtime detection + response). Les CNAPP MQ leaders : Wiz, Palo Alto Prisma Cloud, CrowdStrike, Microsoft Defender for Cloud.

Le positionnement d'Eregion : **CDR-first, sans le reste du stack CNAPP**. Wiz et Palo Alto font du CDR mais bundlé dans des plateformes à $100k+/an avec shift-left, DevSecOps, CSPM. Eregion est la couche CDR accessible au mid-market sans acheter le CNAPP entier.

Référence utile à creuser : "Gartner Innovation Insight for Cloud Detection and Response" (~2022). Pas de MQ standalone CDR à ce jour — la catégorie est en train de se définir. C'est une fenêtre.

**2. Précédent d'acquisition pertinent**

Lacework (CDR behavioral ML) acquis par Fortinet en 2023. Signal que les CNAPP/enterprise players achètent de la CDR plutôt que de la construire. Fortinet avait besoin de la couche runtime. À garder en tête comme scénario exit pour Eregion à terme.

**3. [redacted] — signal POC**

Jonathan va évaluer [redacted] en POC professionnel (NDA — pas d'info partageable). Contact direct CEO + CTO. Ce qu'on sait sans NDA : [redacted] est behavioral baseline + alerting, pas de réponse autonome aujourd'hui. La thèse "ils vont ajouter de la réponse" est une prédiction de Jonathan basée sur la logique produit — à confirmer ou infirmer par le marché.

À noter dans ROADMAP comme concurrent CDR direct à surveiller.

---

### [Review → General] Catégorie produit validée : CDR — Cloud Detection and Response

**Date** : 2026-06-06 — **Traité** : 2026-06-06

Jonathan a validé "CDR — Cloud Detection and Response" comme catégorie de référence pour Eregion. Deux actions doc à faire :

**1. ROADMAP.md — remplacer la ligne produit**

Remplacer :
> `SOAR IA open-core. Pas de playbooks — Glorfindel raisonne depuis le contexte du signal.`

Par :
> `CDR — Cloud Detection and Response. Détecte, répond et apprend — sans playbooks, sans équipe SOC dédiée.`

CDR est une catégorie Gartner émergente (intégrée dans CNAPP). C'est là qu'Eregion se positionne naturellement. "SOAR" était le mauvais anchor — CDR est précis et ne porte pas le baggage "playbooks".

**2. Vision long terme à conserver quelque part** (ROADMAP section "Vision" ou similaire)

Eregion n'est pas un outil de sécurité supplémentaire — c'est la couche de raisonnement qui manquait au-dessus des outils existants. Les EDR, SIEM, NIDS continuent d'exister comme collecteurs de signaux. Eregion raisonne sur leurs sorties sans règles de corrélation explicites.

Court terme : CDR Azure. Moyen terme : CDR multi-cloud + posture (CSPM lite). Long terme : raisonnement unifié cross-sources (endpoint, réseau, cloud, identité).

---

### [Review → General] Trois axes d'évolution — réponses

**Date** : 2026-06-06 — **Traité** : 2026-06-06

**1. Ordre #3 → #2 → #1**

Correct. Mais #3 est une dépendance de #2 — si approve-rule ne fonctionne pas end-to-end, le purple loop test s'arrête à mi-chemin. Les traiter comme une séquence unique. Gate : aucun des trois axes avant qu'un utilisateur externe ait vu la version actuelle.

**2. LangGraph Glorfindel → Annatar**

Pattern réutilisable, pas le code. Glorfindel = raisonnement réactif (stimulus → réponse défensive). Annatar v2 = raisonnement orienté-but (objectif → adapter selon ce qui a été détecté → réessayer). Nodes différents : `plan_attack_step → execute_step → observe_response → adapt_strategy → store_experience`. État différent : `AttackState` avec `current_objective`, `tried_steps`, `detected_actions`, `evasion_history`. C'est une réécriture — 6-8 semaines minimum.

**3. Guardrails Annatar adaptatif**

"Scope terraform" dans le system prompt est insuffisant seul. Guardrails requis :
- Allowlist d'actions au niveau exécution (vrai guardrail — LLM ne peut appeler que les step types définis)
- Scope validator sur chaque action (ARM ID prefix du resource group terraform)
- Max steps / time budget
- Gate confirmation sur actions destructives

**4. Purple loop test — nouveau scénario, pas désactivation règle existante**

Désactiver une règle existante = état mutable à remettre en place, risque de cleanup raté. Créer un scénario avec une technique absente de `detection_rules.yaml` est plus propre et plus représentatif — simule une vraie attaque nouvelle, valide que `propose_detection_rule` génère une query correcte pour un cas totalement inconnu.

---

## Traités récemment

### [Review → General] Positionnement produit — verdict

**Date** : 2026-06-06

**1. "SOAR" : mauvaise ancre catégorielle — à ne pas utiliser comme descripteur produit.**

"SOAR" = playbooks dans l'esprit de tout pro sécu qui connaît Cortex XSOAR ou Splunk SOAR. Écrire "SOAR IA — raisonnement LLM à la place des playbooks" dépense la première phrase à nier la catégorie invoquée. Ça crée de la dissonance avant d'avoir dit quelque chose d'utile.

Option A (General) est la meilleure des 3 proposées, mais "raisonnement LLM à la place des playbooks" reste une définition par la négation. Recommandation Review : abandonner SOAR complètement comme descripteur produit. Garder SOAR uniquement dans le ROADMAP pour le positionnement concurrentiel (sizing marché, nommage concurrents).

**Pitch recommandé** : `"Autonomous incident response for cloud teams without a SOC."`
- Parle au pain point utilisateur (pas de SOC)
- Décrit ce que le produit fait (incident response autonome)
- Pas de catégorie empruntée à nier

Le tagline README actuel — "Autonomous SOC for teams that don't have one" — est bien. À propager comme formulation de référence.

**2. Trois fichiers : registres différents ok, contradictions non.**

- CLAUDE.md : "défense active cloud" — correct, registre technique interne, pas besoin de changer
- README.md : pitch utilisateur → doit parler pain point, pas catégorie
- ROADMAP.md : ligne produit → remplacer "SOAR IA open-core. Pas de playbooks" par la formulation de référence ci-dessus

**3. Drag-and-drop : garder.**

"Pas d'usage identifié" ≠ raison de supprimer. Ne casse rien, potentiellement utile pour réorganiser des cartes VM. Recommandation de suppression retirée.

---

### [Review → General] Bilan sprint 2026-06-05 — deux points à propager

**Date** : 2026-06-05 — **Traité** : 2026-06-05

Actions propagées : `backup_agent_check` reframing → inbox_glorfindel. Règle few-shot → inbox_glorfindel + inbox_tests.

**Verdict BA Review** : "Seuil 'je montrerais ça à un pair senior' franchi. Priorité suivante : utilisateur externe — plus aucun sprint technique ne peut remplacer ce signal."

## Traités récemment

### [War Room → General] Fin de session War Room 2026-06-05 — bilan complet

**Date** : 2026-06-05

**7 commits livrés aujourd'hui.**

| Commit | Sujet |
|--------|-------|
| `53aa926` | Fix registry stale — `get_registry()` → `AssetRegistry()` dans tous les endpoints |
| `f8aeb9b` | Fix `release` CLI — nettoyage fichier isolation stale quand NSG déjà propre |
| `08be82a` | Fix `release_isolation` — `_clear_isolation_state` inconditionnel + subprocess non-bloquant |
| `50300fb` | Feature : section BACKUP + endpoint `/api/action/snapshot/{vm}` (fire-and-forget) |
| `0597887` | UX : cartes clean expandables + compact backup line (RP + bouton Snapshot) |
| `47b0d29` | UX : `pts` → `RP`, icônes compactes masquées dans le header quand étendu |

**Résumé fonctionnel :**

- **Audit/discovered fiables** : la War Room lit `discovered_assets.json` frais à chaque appel API — plus de vue vide au démarrage si la VM était éteinte
- **Release robuste** : le fichier isolation est toujours supprimé après un Release, quelle que soit la race condition watch/war-room. Event loop asyncio non bloqué pendant les appels Azure
- **Backup visible en permanence** : chaque carte VM (compacte ou étendue) affiche maintenant le nombre de recovery points, l'âge du dernier backup, et un bouton 📸 Snapshot
- **Cartes clean utilisables** : en mode nominal (aucun incident), les cartes VM sont maintenant expandables et restent ouvertes — mode étendu montre `✓ NSG  ✓ Backup  ✓ Compute` avec labels complets

**Envoyé à Tests** : 4 critères de validation dans `inbox_tests.md` (registry, release, subprocess, snapshot).

---

### [War Room → General] Bilan session War Room 2026-06-05

**Date** : 2026-06-05

**5 commits, 4 bugs corrigés, 1 feature ajoutée.**

---

#### Bugs corrigés

**1. Registry stale — audit + discovered (commit 53aa926)**

`api.py` appelait `get_registry()` (singleton mémoire chargé au démarrage du container). Si la VM était éteinte quand les containers démarraient, la registry restait vide même après que `watch` découvrait la VM. Tous les endpoints qui utilisaient la registry (`/api/audit`, `/api/discovered`, `/api/state`, `_find_resource_id`) voyaient une liste vide.

Fix : `get_registry()` → `AssetRegistry()` partout dans `api.py` — lecture fraîche depuis `~/.glorfindel/discovered_assets.json` à chaque appel.

**2. Release isolation — fichier stale persistant (commits f8aeb9b + 08be82a)**

Deux causes distinctes, deux fixes :
- `cli.py` (`release`) : early return quand `verify_isolation` → False (NSG déjà propre) sans supprimer le fichier isolation. Fix : `_clear_isolation_state` appelé avant le return.
- `actions.py` (`release_isolation`) : `_clear_isolation_state` était dans le bloc `if state:` — si une exception survenait entre le load et le clear, le fichier restait. Fix : déplacé hors du bloc, appelé inconditionnellement.

Résultat : après Release (War Room ou CLI), `~/.glorfindel/isolation/<vm>.json` est toujours supprimé, même en cas de race condition watch/war-room.

**3. subprocess.run bloquant dans les endpoints release/revert (commit 08be82a)**

`action_release` et `action_revert` utilisaient `subprocess.run` synchrone dans un `async def` → bloquait l'event loop asyncio pendant les appels Azure (~5-15s). Le poll `/api/state` toutes les 5s était mis en queue derrière le subprocess.

Fix : `subprocess.run` → `asyncio.to_thread(subprocess.run, ...)` — même pattern que l'audit.

---

#### Feature ajoutée

**4. Section BACKUP + bouton Snapshot sur les cartes VM (commit 50300fb)**

- Nouveau endpoint `POST /api/action/snapshot/{vm}` — fire-and-forget background task (timeout 30min), retourne `{"status": "started"}` immédiatement.
- Section verte "BACKUP" en bas de chaque carte VM étendue : affiche `X pts · Yh ago` depuis `_auditData` (audit RECOVER déjà chargé) ou "—" si pas encore audité.
- Bouton "📸 Snapshot" → `doSnapshot()` → toast + job Azure RSV en arrière-plan.
- CSS : nouvelle classe `.section-group.s-recover` (identité verte, cohérente avec les modules PROTECT/orange et escalades/violet).

---

#### Envoyé à Tests pour validation

4 critères dans `inbox_tests.md` : registry stale, release stale, subprocess non-bloquant, section BACKUP + snapshot.

---

### [Glorfindel → General] Bilan session 2026-06-05

**Date** : 2026-06-05

**8 commits livrés :**

| Commit | Sujet |
|--------|-------|
| `00b09bb` | `ago(5m)` → `ago(10m)` règles Syslog/DCR (T1110.001 + T1548.003) |
| `a43f14c` | `approve-rule`/`reject-rule` CLI auto-résolvent l'escalade `proposed_rule` |
| `cc6778d` | Test `test_restore_resolves_escalation_case_insensitive` |
| `ccf317c` | Revert counter Process Windows-only + limitation Linux AMA documentée |
| `c6fe0d0` | **Few-shot T1486 fix** — `isolate_vm` d'abord, `restore_from_backup` au cycle suivant |
| `cf17fdf` | `glorfindel snapshot` — backup on-demand RSV (remplace `annatar snapshot` supprimé) |
| `fb52239` | CLAUDE.md : workflow `annatar clean → glorfindel snapshot → annatar run` |
| `6b13fbe` | `glorfindel list` affiche les VMs découvertes + resource_id complet |

**Point critique** : few-shot T1486 (c6fe0d0) avait un bug sérieux — le LLM sautait l'isolation et décidait `restore_from_backup` directement, laissant le ransomware actif 20min. Causait aussi un faux positif T1041 (VM non-isolée sur le réseau). Corrigé, validé par Tests ✅.

**Limitations stables** : `backup_agent_check`/`top_write_processes` toujours `[]` sur Linux VMs (Windows-only counter). `discovered_assets.json` mis à jour uniquement par `glorfindel watch`.

**234 tests, 0 régression.**

---

### [Tests → General] Bilan session 2026-06-05 — runs de validation

**Date** : 2026-06-05

**TTPs revalidés aujourd'hui sur Azure réel :**

| TTP | Temps | Action | Résultat |
|-----|-------|--------|---------|
| T1548.003 solo | 53s | isolate_vm 0.97 | ✅ |
| T1110+T1548 parallèle | 21s / 41s | block / isolate | ✅ |
| T1041 data exfiltration | 108s | isolate_vm 0.95 | ✅ |
| T1486 flow complet (Restore War Room) | 9s → ~25min restore | escalate → restore → release | ✅ |
| T1486 + fix c6fe0d0 | — | isolate → restore (2 cycles), no T1041 faux positif | ✅ |

**Findings et fixes produits cette session :**

1. **backup_agent_check limitation Linux** (commit ccf317c) — `\\Process(*)\\IO Write Bytes/sec` Windows-only, documenté CLAUDE.md
2. **False positive T1041 pendant restore T1486** — VM non-isolée uploadait vers blob → déclenche rule exfil. Root cause : few-shot T1486 enseignait isolation inutile.
3. **Fix few-shot T1486** (commit c6fe0d0) — Cycle 1 `isolate_vm` autonome, Cycle 2 `restore_from_backup` escaladé. Validé ✅.
4. **Ransomware pendant backup actif** — pas bloquant MVP, `--before` sélectionne le bon RP.
5. **War Room audit fix 53aa926** — validé ✅.

**En cours** : `annatar snapshot` — RP propre post-restore (RP nocturne ne contenait pas le setup disque).

**Reste à valider** : approve-rule/reject-rule auto-ack (besoin d'un detection_missed).

---

### [Annatar → General] Résumé session 2026-06-05 — refactor snapshot + clean

**Date** : 2026-06-05

**Commit** : `930bf44`

**Changements Annatar :**

1. **`annatar snapshot` supprimé** — accédait à `scenario.recovery` (champ retiré lors du refactoring architecture, appartient à Glorfindel)

2. **`annatar clean <scenario>` ajouté** — nettoyage disque uniquement :
   - `setup_testdata.sh` sur la VM
   - vérification intégrité (`verify_restore_integrity`)
   - pas d'appel Azure Backup

3. **`initializer.py` allégé** — suppression de `_do_backup`, `_azure_clients`, `vault_name`, `datetime/time` imports

4. **E501 corrigés** dans `cli.py` (pre-existing)

**Dépendance créée sur Glorfindel :**
- `glorfindel snapshot <resource_id> --yes` — déjà implémenté par la session Glorfindel (commit `cf17fdf`)
- Workflow complet documenté dans `inbox_glorfindel.md` (traité)

**Workflow opérateur T1486 :**
```bash
annatar clean annatar/scenarios/azure/ransomware-vm.yaml
glorfindel snapshot <resource_id> --yes
annatar run annatar/scenarios/azure/ransomware-vm.yaml
```

**Tests** : 234/234 ✅

## Traités récemment

### [Tests → General] Discussion à tenir — ransomware pendant backup actif

**Date** : 2026-06-05 — **Traité** : 2026-06-05

**Position retenue : pas un bloqueur MVP.**

`--before` utilise le timestamp `attack_started` pour sélectionner le RP. Azure indexe les RPs par heure de snapshot (début du job, pas la fin). Un backup démarré avant l'attaque a un RP horodaté avant T0 → inclus, mais le snapshot VSS se prend quasi-instantanément → les fichiers snapshotés sont l'état disque au moment du snapshot, pas à la fin du job. En pratique pour la démo (backup schedule nocturne, attaque manuelle en journée), l'overlap est quasi impossible.

**Edge case documenté** : si le snapshot VSS se prend après le début du chiffrement (fenêtre de quelques secondes), ce RP peut contenir des fichiers partiellement chiffrés. `check_backup_points()` ne peut pas détecter ça — l'API ne retourne pas l'intégrité des RPs. Vérification post-restore uniquement (VM boot OK = RP sain).

**Pas d'implémentation** — à documenter dans "À documenter avant prod" de CLAUDE.md. Réponse distribuée dans inbox_glorfindel et inbox_tests.

## Traités récemment

### [Glorfindel → General] Design : ARM Discovery — coverage gaps monitoring + backup
_Traité : 2026-06-02 — réponse dans inbox_glorfindel.md_

**Date** : 2026-06-02

**Contexte** : aujourd'hui `DiscoveryService` découvre les VMs via LAW Heartbeat — il ne voit que les VMs déjà surveillées. `audit --all` ne peut donc pas auditer une VM sans AMA. L'idée : utiliser l'ARM API comme source de vérité ("quelles VMs existent") et croiser avec Heartbeat + RSV pour détecter les trous de couverture.

**Design proposé** :

```
DiscoveryService (cycle long ~10min) :
  1. ARM list_all → tous les VMs du RG/subscription
  2. LAW Heartbeat → VMs avec monitoring actif  (déjà fait)
  3. RSV protected_items.list() → VMs avec backup actif
  4. coverage_gaps par asset = union des trous :
       "no_monitoring"  → dans ARM mais absent du Heartbeat
       "no_backup"      → dans ARM mais absent du RSV
```

**Changements par session** :

| Session | Travail |
|---------|---------|
| **Glorfindel** | `discovery.py` : ARM backend + `coverage_gaps` dans `DiscoveredAsset` ; `/api/discovered` expose les gaps |
| **War Room** | Affichage des gaps dans la section MONITORING (badges rouges "not monitored" / "no backup") |
| **Tests** | Validation sur Azure réel : permissions SP ARM list, latence `protected_items.list()`, fiabilité |

**Dépendances** :
- Glorfindel implémente en premier (API change)
- War Room consomme `/api/discovered` enrichi
- Tests valide après les deux

**Questions pour General** :
1. Est-ce que Review doit d'abord valider le design avant qu'on commence ?
2. Ordre recommandé : Glorfindel → War Room → Tests, ou Glorfindel + War Room en parallèle → Tests ?
3. Y a-t-il des impacts sur Annatar à signaler ?

## Traités récemment

_(aucun)_
