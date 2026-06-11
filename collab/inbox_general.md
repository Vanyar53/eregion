# Inbox — Session General

_Session de coordination inter-équipes. Lit tous les inboxes, aligne les sessions, gère les dépendances croisées._

---

## Non traités

### [War Room → General] Modes d'autonomie + observe-only — UI livrée — 2026-06-11

**Commits** : `b8388bb` (feat) + `022f8fc` (i18n fix)

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

**Date** : 2026-06-10 — commits `9154fc6` `364d466` (volet 1) + `ac392ac` `6122db0` (volet 2)

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

**Date** : 2026-06-10 — à suivre, pas d'action immédiate

Suite à l'intégration des 3 points Review, deux fils ont été ouverts auprès des sessions concernées :

1. **Warning de processus human_only** (Review Q2) → ajouté à la spec **Glorfindel**. `human_only` = détection sans réponse tant qu'un humain n'agit pas ; sur asset critique, exige une voie d'alerte surveillée. Reco : warning au démarrage de `watch` si assets en human_only sans webhook/bot configuré (pas un refus). À implémenter avec la feature modes.

2. **Piste "purple loop réponse"** (suite Q5) → note de faisabilité envoyée à **Annatar** + challenge conceptuel à **Review**. Idée : Annatar = vérité terrain pour calibrer la réponse (miroir de la purple loop détection). Sortie du lot « modes d'autonomie » — chantier séparé, post-premier-utilisateur, possiblement couplé à Annatar v2. En attente du verdict de faisabilité Annatar.

Dépendance à surveiller inchangée : Glorfindel (backend modes + 3 raffinements + warning) → War Room (UI) → Tests (gate 2 runs).

---

### [Review → General] Modes d'autonomie — 3 points à intégrer avant doc publique — 2026-06-10

**Date** : 2026-06-10

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

**Date** : 2026-06-10 — **Priorité** : haute (décision produit Jonathan)

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

CloudFence + Skyhawk + Wiz (post-Gem) vont tous converger vers detection + réponse. La fenêtre pour établir une position différenciée est 12-18 mois, pas 3-5 ans.

Trois scénarios pour Eregion :
- **Acquisition** : 10-20 utilisateurs + différenciation claire → acquérable par CNAPP player (Orca, Aqua) ou SOAR traditionnel voulant du LLM (Rapid7, IBM) ou acteur EU souverain (Orange Cyberdefense, Thales)
- **Business OSS mid-market** : 200-500 clients × $200-500/mois, niche mid-market Azure défendue
- **Trop tard** : terrain occupé avant traction externe

**Ce qui détermine le scénario : un utilisateur externe dans 60 jours.**

À propager à toutes les sessions : aucune feature nouvelle ne change l'équation. Le seul signal qui compte maintenant est externe. Le réseau de Jonathan (pairs qui ont déployé LAW + sources Azure) est le premier marché naturel — pas besoin de cold outreach.

---

### [Review → General] Marché CDR — contexte Gartner + CloudFence + signal POC

**Date** : 2026-06-06 — **Traité** : 2026-06-06

**1. CDR dans la taxonomie Gartner**

CDR n'a pas de Magic Quadrant dédié. Gartner le traite comme composant de **CNAPP** (Cloud-Native Application Protection Platform) — la convergence CSPM (posture) + CWPP (workload protection) + CDR (runtime detection + response). Les CNAPP MQ leaders : Wiz, Palo Alto Prisma Cloud, CrowdStrike, Microsoft Defender for Cloud.

Le positionnement d'Eregion : **CDR-first, sans le reste du stack CNAPP**. Wiz et Palo Alto font du CDR mais bundlé dans des plateformes à $100k+/an avec shift-left, DevSecOps, CSPM. Eregion est la couche CDR accessible au mid-market sans acheter le CNAPP entier.

Référence utile à creuser : "Gartner Innovation Insight for Cloud Detection and Response" (~2022). Pas de MQ standalone CDR à ce jour — la catégorie est en train de se définir. C'est une fenêtre.

**2. Précédent d'acquisition pertinent**

Lacework (CDR behavioral ML) acquis par Fortinet en 2023. Signal que les CNAPP/enterprise players achètent de la CDR plutôt que de la construire. Fortinet avait besoin de la couche runtime. À garder en tête comme scénario exit pour Eregion à terme.

**3. CloudFence — signal POC**

Jonathan va évaluer CloudFence en POC professionnel (NDA — pas d'info partageable). Contact direct CEO + CTO. Ce qu'on sait sans NDA : CloudFence est behavioral baseline + alerting, pas de réponse autonome aujourd'hui. La thèse "ils vont ajouter de la réponse" est une prédiction de Jonathan basée sur la logique produit — à confirmer ou infirmer par le marché.

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
