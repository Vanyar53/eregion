# Eregion — Contexte projet pour Claude Code

## Concept
Plateforme OSS (Apache 2.0) de défense active cloud. Deux agents IA en boucle :
- **Annatar** (rouge) simule des attaques réelles sur l'infra cloud (MITRE ATT&CK)
- **Glorfindel** (bleu) détecte, répond de façon autonome, vérifie, apprend via ChromaDB

**Repo** : https://github.com/Vanyar53/eregion
**Local** : `/home/jonathan/eregion/`, branch `main`, venv `.venv/` (créé par `make install`), `.envrc` charge les creds
**Stack** : Python 3.12 (≥ 3.11 supporté — CI GitHub Actions sur 3.11 et 3.12), Azure SDK, LangGraph, LiteLLM (Anthropic défaut, OpenAI, Azure, Ollama, self-hosted), ChromaDB, Click, pytest
**Docker** : `make build` → `eregion-annatar` + `eregion-glorfindel`. `make annatar-shell` (alias `ar`) / `make glorfindel-shell` (alias `gf`). State persisté dans `~/.annatar/` et `~/.glorfindel/`, cache ChromaDB dans `~/.cache/chroma/`. **Images non-root** : `make build` injecte l'UID/GID de l'opérateur (`id -u`/`id -g`) en build-arg → le container écrit le state bind-monté comme l'opérateur, pas root (sinon la CLI locale ne peut pas muter ce que le container a écrit → `PermissionError` sur `reset`/`unblock`). HOME reste `/root` (chowné), aucun chemin de mount ne change. Une seule fois après upgrade depuis l'ancienne image root : `make fix-state-ownership` (`chown` des fichiers root legacy).

---

## TTPs validés en réel (nouvelle architecture RulePoller — 2026-05-31)

| TTP | Scénario | Détection | Temps | Action |
|-----|----------|-----------|-------|--------|
| T1486 | Ransomware VM | Perf disk write | 55–71s | cycle 1 : `isolate_vm` (autonome en `non_disruptive`, retenu en `human_only` → `mode_hold`), `restore --wait` → `recovery_complete` → `release_isolation` auto → RTO ~21m29s |
| T1041 | Data exfiltration | StorageBlobLogs (RFC-1918, PutBlob ≥ 1) | ~79–108s* | `isolate_vm` (disk intact) |
| T1110.001 | SSH brute force | Syslog DCR | 58s | `block_suspicious_ip` |
| T1548.003 | Sudo priv esc | Syslog DCR | 40s | `isolate_vm` (root confirmé) |
| T1110+T1548 | Run parallèle | — | 41s/59s | block → isolate (incident context) |
| T1136.001 | Account creation (purple loop) | Syslog DCR (authpriv) | 21–49s‡ | `snapshot + escalade` (few-shot b36a5a7, confidence < 0.7 → gate) — règle proposée + approuvée via purple loop |

\* T1041 : latence StorageBlobLogs variable (ingestion Azure, pas la query). SLA fonctionnel, à surveiller.
† T1548 run parallèle (T1110+T1548) : detection_timeout possible si DCR saturé — contention infra Azure, pas un bug Glorfindel.
‡ T1136.001 : scénario créé spécifiquement pour valider le purple loop end-to-end (`detection_missed → propose_detection_rule → approve-rule → détection réussie`). Règle approuvée dans `detection_rules.yaml` lors du run 20260608T143312Z. Ingestion DCR Syslog empiriquement rapide (21–49s) mais peut monter à >300s sur spike Azure — `expected_latency_s: 480` dans la règle + `detection.timeout: 600s` dans le scénario couvrent le P99. Commit `dd48b12`.

⚠️ **Run Azure du 2026-10-05 — ce tableau est à relire** :
- Les temps de détection ci-dessus comptaient depuis la **réception** d'`attack_started`, émis par Annatar **après** l'étape d'attaque (42 s rapportés pour ~135 s réels). `detection_time_s` compte désormais depuis le début de l'attaque (`attack_time`, T0 d'Annatar).
- Ces détections passaient par le chemin `attack_started` (poll depuis T0). Le **RulePoller** — seul chemin en production — ne voyait **aucune** ligne ingérée avec plus de ~84 s de retard (fenêtre API de 60 s qui l'emportait sur le `ago(10m)` des règles) : `ransomware-disk-write` n'a rien matché le 05/10 (latence Perf 89–109 s). Corrigé (voir RulePoller ci-dessous) et **validé le soir même** : RulePoller seul à T0+114 s (latence Perf 72–124 s), un seul dispatch, pour la seule bonne VM sur 4 découvertes ; sessions SSH coupées 22 s après la pose des règles ; neutralisation avant restore → le disque restauré a rejoué la commande inoffensive, VM saine (`INTEGRITY_PASS`) à la levée ; RTO ≈ 23 min 10 hors décisions humaines (rapport `collab/test_run_2026-10-05_validation.md`).
- T1486 du 05/10 (chemin `attack_started`, gondolin en `human_only`) : `mode_hold` → approbation → isolation vérifiée, restore 19 min 47, **RTO 24 min 42**. Le disque restauré a **rejoué la dernière commande Run Command** au démarrage (le script de chiffrement) → corrigé par la neutralisation avant restore.

Glorfindel choisit la bonne action sans règles per-TTP explicites — raisonnement depuis le contexte signal + incident.

---

## Architecture — boucle complète

```
Annatar
  setup (nettoie résidus) → integrity check → attaque → attack_started {T0}

Glorfindel (watch ou respond)
  poll_detection Azure Monitor (10s) → detection ou detection_timeout
  → decide (LangGraph + LLM via LiteLLM + RAG ChromaDB 3 cycles similaires)
  → execute autonomous action (isolate_vm / block_suspicious_ip / snapshot)
  → verify (Azure NSG API) → store_cycle (ChromaDB + debug.jsonl)

Humain
  glorfindel restore <resource_id> --yes   # --before auto-détecté depuis signals JSONL
  → restore Azure Backup (~20min) → recovery_complete
  → Glorfindel release_isolation (autonome) → verify → store
```

---

## Architecture watch — parallèle + sérialisé

**Réaffirmation (lot L5, 2026-10-06)** : toutes les `GLORFINDEL_REASSERT_INTERVAL_S` (défaut 60 s, 0 = off ; jamais en dry-run ni read-only), le watch vérifie chaque isolation et blocage enregistrés (`glorfindel/reassert.py`). Règles **disparues** d'Azure (un `terraform apply` sur un NSG à règles en ligne, un retrait dans le portail) → reposées **une fois** + escalade `verification_failed` (l'heure d'isolation d'origine est gardée, `reasserted_at` noté) ; disparues **à nouveau** → escalade seule, Glorfindel ne se bat pas contre une suppression délibérée ou un pipeline. En `human_only`, jamais de repose : alerte seule. Un contournement (allow avant le deny) ou une liste illisible ne déclenche rien ici (la vérification les signale déjà). Les isolations/blocages `partial` sont laissés à l'opérateur. Chaque alerte de réaffirmation remplace la précédente pour la même VM/IP (nouvelle carte, nouvelle notification) : la dédup du store fusionnait « disparues à nouveau » dans la carte « reposées une fois », texte inchangé, sans notification. **Une alerte par disparition** (`drift_alerted_at`, effacé quand l'isolation/le blocage est de nouveau en place) : en `human_only`, chaque cycle de 60 s recréait une carte et une notification, et défaisait les acquittements (validation du 06/10). Le journal d'activité cité ne garde que les écritures `Succeeded` d'autres identités que Glorfindel. **Un seul écrivain par VM (L12, 07/10)** : isoler, lever, bloquer, débloquer et `reset --from-azure` tiennent le verrou de la VM (`_vm_lock` : thread + flock `~/.glorfindel/locks/`, réentrant) — la War Room et la CLI sont d'autres processus ; la réaffirmation prend ce verrou et **relit l'état** avant d'agir (une levée en cours finit d'abord, puis l'état effacé dit qu'il n'y a rien à reposer). Levée et déblocage notent leur intention avant de toucher Azure (`releasing_at` / `unblocking_at`) : coupés au milieu, ils ne sont pas pris pour un retrait hors Glorfindel. Levée/déblocage partiels (`release_failed` / `unblock_failed`) laissés à l'opérateur. Timeout des levées War Room : 600 s.

Robustesse (revue 2026-10) : une ligne JSONL corrompue ou une clé inconnue ne tue plus le démon (`_read_new_signals` / `_parse_signal_line` : ligne ignorée + signalée ; ligne encore en cours d'écriture par Annatar laissée pour le poll suivant) ; une itération en erreur est loggée et la boucle continue ; un poll de détection qui lève (backend injoignable) → `cycle_failed` au lieu d'un thread mort.

```
attack_started → thread poll-<vm>-<id>   (parallèle, N attaques × N threads)
                      ↓ détecté
               queue resource_id → decide+execute  (sérialisé, incident context partagé)
```

---

## LangGraph — 8 nodes

```
load_context → poll_detection → investigate → decide → execute_action → verify_action → store_cycle
                                                  ↓ (escalate)
                                            escalate_to_human → store_cycle
```

- `poll_detection` : no-op sauf `attack_started` → poll Azure Monitor jusqu'à alerte ou timeout ; `detection_time_s` = temps depuis `attack_time` (T0 de l'attaque), plus depuis la réception du signal
- **RulePoller (run du 2026-10-05)** — trois défauts corrigés ensemble :
  - **Fenêtre** : le timespan API vaut maintenant le plus long `ago()` de la requête + 5 min de marge (`_query_lookback_s`, défaut 10 min). Avant : `now - 2*interval_s` (60 s), qui l'emportait sur le `ago(10m)` → aveugle à toute ligne ingérée avec plus de ~84 s de retard.
  - **Attribution (B8)** : une règle `assets: [auto]` est déclinée par VM découverte, mais la requête n'est pas filtrée sur la VM → une détection sur une VM était dispatchée pour **toutes** les VMs (isolation à tort possible en `non_disruptive`, masqué par le banc mono-VM). `poll_alert(match_row=…)` ne retient que les lignes de CETTE VM (`_ResourceId` / `Computer`) ou les lignes qui ne nomment aucune ressource (agrégées par IP attaquante / compte de stockage). Ces dernières portent `context.attribution = "unattributed"` quand plusieurs VMs sont surveillées → la garde d'attribution de `decide` retient `isolate_vm` (escalade `unattributed_signal`) ; un blocage d'IP reste autonome.
  - **Nouvelles VMs (validation du 2026-10-06)** : le watch construisait son propre `AssetRegistry` (lu une fois sur disque) au lieu de celui que remplit le service de découverte, et ne déclinait les règles qu'une fois, 10 s après le démarrage → une VM allumée après le démarrage du watch (ou éteinte à ce moment) n'était **jamais** surveillée. Le RulePoller utilise maintenant `discovery.get_registry()` et `expand_for_discovered` tourne chaque minute (idempotent).
  - **Déduplication** : identité = `TimeGenerated` si présent, sinon les colonnes non numériques (qui, où) — les lignes agrégées (`summarize … by Computer`/`SourceIP`) échappaient à la dédup et auraient été redispatchées à chaque poll avec la fenêtre élargie. Suppression tant que la même identité reste dans la fenêtre ; état **persisté** dans `rule_status.json` (`dispatched`) → un redémarrage du watch ne rejoue pas une détection encore dans la fenêtre (et ne perd plus celles survenues pendant la coupure).
- `investigate` : requêtes KQL post-détection selon contenu du signal (pas le TTP label)
  - MaxWrite présent → top_write_processes + backup_agent_check (ransomware vs backup légitime)
  - FailedAttempts+SourceIP → successful_auth_from_ip (brute force a-t-il réussi ?)
  - USER=root dans syslog → root_commands + disk_write_after_escalation
  - Résultats dans `raw_signal.investigative_context` — le LLM les voit avant decide
  - No-op si pas de workspace_id ou dry_run
- `decide` : LLM via LiteLLM + few-shot anchors + RAG (3 cycles) + incident context + investigative_context
  - Gate confidence : `confidence < GLORFINDEL_CONFIDENCE_THRESHOLD` (défaut 0.7) + action autonome → escalade forcée
  - **Garde-fou déterministe (signal non caractérisé)** : indépendant du LLM — une action autonome **disruptive** (`isolate_vm`/`block_suspicious_ip`) sur un signal **sans indicateur de menace reconnu** (`normalize_row` → fallback générique/`"unknown"`, pas un label curé) → **escalade forcée**. Le gate de confiance fait confiance au modèle pour avouer une confiance basse, ce qu'un modèle faible ne fait pas (smoke : 0.85 sur un signal vague). Le garde-fou ne dépend pas de cette honnêteté. Un signal **caractérisé mais ambigu** (ex. account creation syslog) n'est PAS attrapé ici (c'est le job du gate confiance). `detection_rules.has_recognized_indicator()` + `RECOGNIZED_INDICATOR_KEYS` (= labels de `_INDICATOR_COLUMNS` **sauf `syslog_event`**). Pour « blesser » une nouvelle colonne d'indicateur → l'ajouter à `_INDICATOR_COLUMNS`. **Syslog (revue 2026-10)** : `SyslogMessage` est une *source*, pas une menace — toute règle Syslog (y compris autorée par le LLM) la produit, donc sa simple présence désactivait le garde-fou pour toute la famille. Une ligne Syslog n'est caractérisée que par un **motif curé** : `USER=root` (`privilege_escalation`, dans `normalize_row`) ou `_CURATED_SYSLOG_PATTERNS` (création de compte : `new user:` / `useradd` — vu sur les vrais runs T1136.001). Une ligne Syslog non curée + action disruptive → escalade. `normalize_row` est inchangé (le LLM voit la même chose → pas de run e2e requis).
  - **Précondition release (déterministe)** : `release_isolation` autonome **uniquement** sur `event == "recovery_complete"` (émis par Glorfindel après un restore terminé). Sur tout autre signal → escalade, quelle que soit la confiance. Pas mise sous le garde-fou signal : un `recovery_complete` ne porte aucun indicateur de menace, ça aurait bloqué la levée légitime post-restore (flux RTO).
  - **Échec de l'appel LLM** : `litellm.completion(..., num_retries=2)` dans un try → après les retries, escalade `cycle_failed` (le cycle continue jusqu'à `store_cycle`, debug écrit). Avant : l'exception remontait au worker du watch → une ligne console, menace détectée perdue, rien dans `pending` — y compris en `human_only` (le mode observe-only du premier testeur).
  - Gates extraits en helpers purs testables un par un : `_parse_decision` → `_apply_executable_guard` → `_apply_confidence_gate` → `_apply_signal_guardrail` → `_apply_attribution_guard` → `_apply_release_precondition` → `_apply_autonomy_mode`. Le mode d'autonomie est résolu **avant** l'appel LLM (la ligne debug d'un `cycle_failed` le porte). Seuil invalide (`GLORFINDEL_CONFIDENCE_THRESHOLD=abc`) → 0.7 au lieu d'un crash.
  - **Le type d'escalade vient de la garde qui a retenu l'action (seconde passe 2026-10-05)** : chaque garde note `held_by` dans l'état → `escalate_to_human` en tire le type (`_HELD_BY_TYPE`) : confiance → `low_confidence`, garde-fou signal → `uncharacterized_signal`, précondition de levée → `release_hold`, action non implémentée → `proposed_action`. Avant, les deux garde-fous tombaient dans `low_confidence`, libellé « detection timeout ».
  - **Garde « action exécutable »** : `revoke_temp_access` était annoncée au LLM (dans `AUTONOMOUS_ACTIONS`, donc dans le prompt) sans implémentation — elle finissait en `no_op` marqué exécuté, puis notifié. **Retirée d'`AUTONOMOUS_ACTIONS` le 2026-10-06** (edit du prompt → run e2e T1486 + T1110). `_EXECUTABLE_ACTIONS` reste comme garde pour la prochaine ; `execute_action` lève sur une action sans branche ; `store_cycle` ne notifie jamais un `no_op`.
  - **Parsing défensif de la décision AVANT les gates** (`_as_bool` + float safe + `.get` défauts) : un modèle non-conforme peut (a) **omettre un champ requis** → `d["reasoning"]` KeyError → crash, (b) renvoyer `escalate` en **string `"false"`** (truthy → bypasse le gate), (c) une confidence non-numérique → `float()` lève, (d) **aucun tool-call** (malgré `tool_choice`) → `tool_calls[0]` TypeError, ou un JSON malformé. Tous trouvés par le smoke multi-run (`scripts/llm_smoke.py` : llama3.2 string-bool, command-r7b champ omis, mistral-nemo no-tool-call). Extraction du tool-call protégée + tous les champs hard-défaultés/coercés ; **aucune action/décision parsée → escalade forcée**. Un modèle quirky ne peut ni crasher le cycle ni défaire un contrôle de sécurité.
- `execute_action` : **toute** exception est escaladée (`write_blocked` si PermissionError/403/AuthorizationFailed, sinon `action_failed`) — avant, seules `PermissionError`/`HttpResponseError` l'étaient ; les `RuntimeError` du connecteur (snapshot 404, « no NSG », job introuvable) et `requests` finissaient en ligne console. `PartialActionError` (isolation/block partiel) → `outcome.partial` + NIC en échec. Aucun coffre configuré (`action_backends` / `GLORFINDEL_BACKUP_VAULT`) → `action_failed`, plus de repli silencieux sur `rsv-annatar`. **Snapshot toujours fire-and-forget** (vault + vault_rg depuis la config, job suivi via `jobs.record_snapshot_job`) : un snapshot bloquant a tenu la file du VM **4h25** en run réel (`runs/watch-t1136-…-20260608T143425Z`, full backup initial).
- `verify_action` : NSG check (isolate) **+ résultat de la coupure des sessions** (`isolation_verdict` : sessions encore ouvertes → `verified=False`), `verify_release` (release : **aucune** NIC ne porte de règle — pas `not verify_isolation()`, vrai dès qu'UNE NIC est libre), Compute API (snapshot), règles **entrante ET sortante** (block)
- `respond()` / poll threads du watch : filet final `record_cycle_failure()` → escalade `cycle_failed` + ligne debug pour toute exception non prévue (graph, backend de détection injoignable pendant le poll d'un `attack_started`)
- `store_cycle` : ChromaDB + `runs/{run_id}_debug.jsonl` (toujours écrit, même si ChromaDB/webhook échoue)
- `dry_run: bool` dans `GlorfindelState` → skipe escalations.record() et actions réelles

---

## Raisonnement LLM — few-shot + signal enrichi

Le LLM ne suit pas de routing table TTP→action. Il raisonne depuis :
1. Les indicateurs bruts du signal (`first_result_row`) — normalisés via `normalize_row()` (indicateur sémantique uniforme)
2. Le contexte investigatif (`investigative_context`) collecté par le noeud `investigate`
3. Les exemples few-shot validés en prod dans `_SYSTEM_PROMPT` (prompt caching activé)
4. Les cycles passés ChromaDB + l'incident context multi-signal (investigative_context des cycles précédents propagé)

Exemples few-shot : 4 chaînes de raisonnement complètes (MaxWrite → encryption → restore ;
CallerIP RFC-1918 → exfil, disk intact → isolate ; etc.). Le LLM peut dévier sur les cas
ambigus — les exemples ancrent les cas validés.

**Règle de sécurité** : action destructive sans `escalate=True` → bloquée par le graph, pas par confiance dans le LLM.

---

## Règles d'autonomie strictes

```python
AUTONOMOUS_ACTIONS = ["isolate_vm", "release_isolation", "snapshot", "block_suspicious_ip"]
# revoke_temp_access retirée le 2026-10-06 : annoncée au LLM, jamais implémentée
HUMAN_APPROVAL_REQUIRED = ["restore_from_backup", "delete_resource", "wipe_storage", ...]
```

Actions inconnues proposées → escalade automatique, humain valide et codifie.

### Modes d'autonomie par asset (commit 9154fc6)

La gate destructive est nécessaire mais pas suffisante : le persona sans SOC craint l'action **réversible mais disruptive** (`isolate_vm`) décidée en autonome sur un faux positif. Réponse : 3 modes résolus **par asset** (escalier de confiance).

| Mode | Comportement | Statut |
|------|-------------|--------|
| `human_only` | **Aucune** action exécutée — tout recommandé/escaladé (y compris réversibles). | **Défaut** |
| `non_disruptive` | Comportement historique : `AUTONOMOUS_ACTIONS` autonomes, destructif gated. | Sélectionnable |
| `full_auto` | Différé — **valeur refusée** par la validation config. | Différé |

- Config : section `autonomy` dans `glorfindel-config.yaml` (résolution asset fnmatch > défaut global). `allow_destructive: []` = axe **séparé** du mode, `delete`/`wipe` jamais autonomes.
- Couche politique **après `decide`** (jamais un bypass) : en `human_only`, action autonome → `escalate=True` + `mode_hold=True`. Gate destructive + gate confiance restent actives.
- Nouveau type d'escalade `mode_hold` (≠ `low_confidence`/`destructive_action`) — porte l'action recommandée + confidence pour approbation en un clic.
- `store_cycle` logue `resolved_autonomy_mode` (cycle + debug.jsonl) — trail d'audit.
- `glorfindel watch --mode <m>` surcharge le défaut **global** d'une session (les règles par-asset restent prioritaires). `glorfindel list` affiche le mode résolu par VM. Warning au démarrage si `human_only` sans webhook/bot (gap de process : détection sans réponse tant qu'un humain n'agit pas).
- ⚠️ **Défaut `human_only`** : les runs gate autonomes (T1486/T1548) nécessitent `--mode non_disruptive` ou une section `autonomy` dans le config live.
- **Activation par VM (lot L6, 2026-10-07)** : passer une VM en `non_disruptive` depuis la War Room ouvre un **contrôle de préparation** (`glorfindel/readiness.py`, `GET /api/readiness/<vm>`, rien n'est écrit) : verdict `ready` / `reserve` / `not_ready` + raisons à code stable (droits via l'API de permissions, repli sur les règles si les droits du NSG de quarantaine manquent, sessions non coupées sans `runCommand` ou sous Windows, allow qui passent avant un blocage, NIC/subnet sans NSG ; AVNM et Azure Policy signalés non vérifiés). `POST /api/activate/<vm>` **recalcule** le verdict et refuse une VM pas prête ou dont une réserve n'a pas été confirmée (`acknowledged`) ; `POST /api/autonomy/<vm>` avec `non_disruptive` passe par la même vérification (retour à `human_only` : direct). Aucune VM ne quitte `human_only` sans que ses réserves aient été montrées. Banc : gondolin `ready`.
- **Verrou de préparation (L6, seconde partie, 2026-10-07)** — le trou : le défaut global, un motif (`vm-*`) ou `watch --mode` rendaient autonomes toutes les VMs, **y compris celles créées ensuite**, sans contrôle. Désormais le mode configuré n'est qu'une intention ; le mode **effectif** (`readiness.effective_mode`) vaut `human_only` tant que la VM n'est pas contrôlée `ready`, ou `reserve` avec **toutes** ses réserves confirmées (`acknowledged`). `decide` (via `ReadinessGate`, actif dès que les actions sont réelles, jamais en dry-run ; une VM jamais contrôlée l'est à la volée ; erreur du verrou → `human_only`) et la réaffirmation lisent le mode effectif. `ReadinessTracker` (lancé par la découverte après chaque passe de 60 s) contrôle les VMs en mode autonome **dès leur découverte**, puis à la cadence de posture : prête → autonome sans rien demander ; réserves → retenue + **une** carte `readiness_hold` (« ⚡ Review & turn on » → écran L6, ou `glorfindel activate <vm>`) ; pas prête → retenue + correctif ; réserve apparue après l'activation → retour en `human_only` + carte (« repasse en observation ») ; une erreur de lecture (`permissions_unknown`, `nsg_unreadable`) sur une VM active est reconfirmée à la passe suivante avant de la retenir ; AKS/VMSS et identifiants read-only → retenus sans carte. Store `~/.glorfindel/readiness.json` (verdict, réserves, acquittements ; flock, écrit par le watch ET la War Room). Activation (War Room, `glorfindel activate`) → enregistre les réserves acceptées ; retour en `human_only` → acquittements effacés (réserves remontrées à la prochaine activation). War Room : chip `⏸ CONFIRM` / `NOT READY` / `CHECKING` à côté du mode, `/api/state.autonomy_holds`. `mode_hold` d'une VM retenue : la raison dit pourquoi et comment lever.
- **Gate validée 2026-06-11** : T1486 human_only → `mode_hold` (NSG intact, approve War Room → `isolate_vm` exécuté) ✅ ; T1486 non_disruptive → `isolate_vm` autonome, `resolved_autonomy_mode=non_disruptive` dans debug.jsonl ✅. War Room : badge mode par VM, dropdown per-asset (hot-pickup `b7af4cc`), approve & execute (`/api/action/approve/{esc_id}`).

### War Room — exposition (revue 2026-10)

La War Room déclenche de vraies actions Azure (restore, release, approve & execute) et peut passer un asset en `non_disruptive`. Elle écoutait sur `0.0.0.0` sans authentification.
- `glorfindel war-room` écoute sur **127.0.0.1** par défaut ; `docker-compose.yml` publie `127.0.0.1:7007:7007` (le `--host 0.0.0.0` reste nécessaire *dans* le conteneur).
- `GLORFINDEL_WARROOM_TOKEN` (optionnel) : protège **toutes** les routes, WebSocket du feed compris (middleware ASGI). Ouvrir une fois `http://<hôte>:7007/?token=<jeton>` → cookie HttpOnly/SameSite=Strict + redirection sans le jeton ; scripts : `Authorization: Bearer <jeton>`. Sans jeton sur une adresse non-loopback → avertissement au démarrage.
- Sans jeton, un **navigateur** reçoit une page de saisie (formulaire GET → cookie → redirection) ; les clients API gardent le 401 JSON.
- Cartes : chip `shared NSG`, chips rouges **`⚠ partial`** (NICs partielles, ou release/unblock qui a laissé des règles) et **`⚠ bypassed`** (allow évaluée avant le deny) à côté de ISOLATED/BLOCKED — `/api/state` expose `partial`, `failed_nic`, `release_failed`/`unblock_failed`, `shared`, `shadowed`. Release/Revert en échec : le toast reprend les règles restantes (sortie CLI).
- Corrigé au passage : `GET /api/audit/<vm>` (panneau readiness par VM) levait `NameError: os` **à chaque appel** depuis `053156b` (18/06) — `import os` manquant ; `ruff` le signalait.

### Mode observe-only — credentials read-only (`GLORFINDEL_READ_ONLY=1`)

`human_only` n'exécute que des chemins **lecture** (détection LAW, investigate KQL, discovery Heartbeat, decide LLM, escalade locale) → peut tourner sur un SP **Reader / Log Analytics Reader** (pas Contributor). C'est l'on-ramp du premier test externe : un pair donne un accès lecture seule, observe les recos une semaine, zéro risque.

- `AzureConnector(read_only=...)` (défaut depuis `GLORFINDEL_READ_ONLY`). `_ensure_clients()` est déjà paresseux — aucun check write à l'init, `watch` démarre proprement sur Reader.
- Méthodes write (`isolate_vm`/`block`/`snapshot`/`release`/`restore`/`unblock`) → `_guard_write()` lève un `PermissionError` clair si read-only (jamais atteint en human_only).
- ⚠️ `non_disruptive` + read-only (mauvaise config) : `execute_action` catche le `PermissionError` → escalade type `write_blocked` (≠ mode_hold) → cycle complété, debug file + `pending` visibles (pas de perte silencieuse). Commit `902951a`.
- `audit.run` sous read-only → check `Credentials` (warn, pas fail) : « capacité d'écriture non vérifiable, checks ci-dessous = accès lecture uniquement ». Déploiement reste `ready` pour son usage observe-only.
- `glorfindel watch` logue le régime (`Credentials: read_only`) + warning si read-only combiné à un mode exécutant (les actions échoueront).
- ⚠️ Bouton War Room « Approuver & exécuter » sous read-only → `PermissionError` (à surfacer côté UI).

---

## Vérification post-action

| Action | Vérification | État |
|---|---|---|
| `isolate_vm` | Règles NSG deny-all sur **chaque** NIC + sessions établies coupées (`drain`) | ✅ |
| `release_isolation` | `verify_release` : **aucune** règle d'isolation sur aucune NIC (une règle illisible = non vérifié) | ✅ |
| `snapshot` | Job RSV (InProgress → `verified=None`, pas de claim) | ✅ |
| `block_suspicious_ip` | Règles **entrante et sortante** pour l'IP sur chaque placement | ✅ |

`verified=False` → escalade. `verified=None` → cycle stocké sans claim de succès.

---

## IncidentRegistry

`glorfindel/incidents.py` → groupe signaux par `resource_id` dans TTL (défaut 300s, `GLORFINDEL_INCIDENT_TTL_S`).
Persiste dans `~/.glorfindel/incidents.jsonl`. Thread-safe.
Quand `signals_count > 1` ou `actions_taken` non vide → prompt injecte contexte incident.

---

## Fichiers clés

```
glorfindel-config.yaml          → source unique pour la config infra (NE PAS confondre avec detection_rules.yaml)
                                   monitoring_backends: workspace_id LAW, endpoint Prometheus...
                                   action_backends: RSV vault_name + resource_group
                                   exceptions: fnmatch patterns opt-out par VM et/ou par règle
                                   (fichier non versionné — monté en Docker volume ou présent localement)

technique_catalog.yaml          → CONTRAT PARTAGÉ Annatar↔Glorfindel (boucle purple générative).
                                   Référentiel des techniques (resource_type → [{ttp, tactic, ...}]),
                                   seul couplage entre rouge et bleu (boucle aveugle). Bloc blue
                                   (log_source/indicator_columns/expected_latency_s) consommé par
                                   detection_authoring (autoring grounded) ; bloc red (destructive/
                                   safe_target/testdata_marker/params/reference_script) par le synthé
                                   Annatar. status: implemented | planned. Versionné (≠ config locale) ;
                                   monté en Docker (compose) + COPY Dockerfile (image autonome).

glorfindel/
  config.py             → GlorfindelConfig + load_glorfindel_config() — charge glorfindel-config.yaml
                          ExceptionConfig.is_excluded(asset_name, rule_name) — opt-out fnmatch
  discovery.py          → AssetRegistry (thread-safe, persist ~/.glorfindel/discovered_assets.json)
                          DiscoveryService — thread daemon. Cadences DÉCOUPLÉES :
                            discovery (LAW Heartbeat, cheap) toutes les 60s → VM allumée apparaît vite ;
                            posture (RSV/NSG par VM, cher) throttlée à interval_s (défaut 30min) → pas de matraquage RSV.
                          _discover_from_azure_monitor() → LAW Heartbeat query → liste VMs actives
                          _classify_asset(rid) → (kind, parent) : AKS réel (le heartbeat AMA résout l'id
                          des nœuds vers le managed cluster .../Microsoft.ContainerService/managedClusters/<n>,
                          partagé par tous les nœuds) → kind="aks_node" + parent=<id cluster> (clé de groupage) ;
                          instance VMSS directe (.../virtualMachineScaleSets/<vmss>/virtualMachines/<n>) →
                          kind="vmss_instance" + parent=<id VMSS> ; VM standalone → ("vm",""). DiscoveredAsset
                          porte kind/parent (defaults rétro-compat cache) → /api/state → War Room replie par parent.
                          replace_for_backend() : refresh + rétention — une VM absente du Heartbeat (éteinte)
                          est retenue (last_seen figé) tant que gap < GLORFINDEL_DISCOVERY_RETENTION_H (défaut 8h), puis évincée
                          None sur erreur query → cache conservé (pas d'éviction sur panne)
                          audit.run() lance NSG/backup/compute en parallèle (le RSV ne s'empile plus sur le reste)
  agent.py              → LangGraph 8 nodes + _SOURCE_LANGUAGES map (source → query lang)
                          load_context → [poll_detection | propose_detection_rule]
                          → investigate → decide → execute_action → verify_action → store_cycle
  actions.py            → CloudConnector ABC + AzureConnector + check_nsg_access/check_backup_points/check_compute_access
                          list_backup_items(vault, rg) → inventaire RSV vault-wide (protected items + last RP/state),
                          indépendant de l'état des VMs (source de vérité backup même VM éteinte). Cheap leg : 1 appel
                          paginé, pas de count RP par item (count = check_backup_points par VM, opt-in). Read-only OK.
                          list_nsgs() → inventaire NSG réel (network_security_groups.list_all) : tous les NSG +
                          associations (subnets/nics) + `vms` (resource_ids gouvernés, via nic→vm/subnet→vms d'un
                          network_interfaces.list_all) + restriction Glorfindel (rule `glorfindel-*`). Corrige le
                          sous-comptage de check_nsg_access (dérivé par-VM : rate le NSG subnet quand la NIC a le
                          sien, le NSG d'un subnet AKS, les VMs éteintes). `vms` → War Room : flag monitored
                          (VM hors-LAW = angle mort) + glow de la/les carte(s) VM au survol. Read-only OK.
  detectors.py          → DetectionConnector ABC + AzureMonitorDetector (poll 10s) + run_query()
                          run_query/poll_alert REMONTENT les échecs de query (lèvent), ne les avalent
                          plus en `[]`/no-match : un LAW injoignable (supprimé/IAM/GUID faux) était
                          indistinguable d'un LAW sain sans détection → détection aveugle en silence +
                          fausse éviction discovery. poll_alert ne lève que sur échec PERSISTANT (jamais
                          un seul SUCCESS dans la fenêtre ; 0 row sur query réussie = no-match légitime).
                          Handlers en aval déjà prêts (discovery except→None garde cache ; poller
                          except→last_error ; investigate try→[]). /api/state.monitoring_backends porte
                          `reachable`/`last_error` (dérivé du poll status) → War Room rougit le DETECT.
  detection_rules.py    → DetectionRule dataclass + RulePoller (continuous polling, status persistence)
                          load_config(path, glorfindel_cfg=None) — workspace_id résolu depuis glorfindel_cfg
                          _resolve_backend_for_rule() — la règle se LIE au backend de glorfindel-config :
                            backend nommé s'il existe ; sinon fallback sur l'unique backend du type de la règle
                            (cas mono-LAW → le nom dans detection_rules.yaml devient optionnel). Échec bruyant
                            (warning) si nom absent / ambiguïté / 0 backend — jamais de workspace_id="" silencieux.
                            Règle non résolue → enabled=False (ne poll pas). monitoring_backend_name = nom RÉSOLU
                            (l'asset matching de expand_for_discovered en dépend). start()/expand respectent enabled.
                          RulePoller.expand_for_discovered(registry, glorfindel_cfg) — démarre threads
                          par (règle auto_apply, asset découvert), thread s'arrête si asset évincé
  audit.py              → AuditCheck (+ champ `data` structuré : nsg/nsg_scope + nsgs[] multi-NIC, points/protected), AuditResult,
                          run() — NSG/backup/compute readiness checks en parallèle, IAM gap detection
  proposed_rules.py     → record/pending/approve()/reject() — detection rule proposal lifecycle
  detection_authoring.py → moteur d'autoring grounded (boucle purple GÉNÉRATIVE, côté bleu).
                          load_catalog()/catalog_entry() (lit technique_catalog.yaml),
                          fetch_table_schema() (KQL getschema — schéma RÉEL du LAW, best-effort),
                          author_rule() (appel LLM grounded partagé : catalogue + schéma → règle
                          proposée ; flag grounded_schema). techniques_needing_rules() (sélection
                          cold-start). Source UNIQUE du tool+prompt d'autoring (agent.py importe).
                          Deux appelants : propose_detection_rule (réactif) + `propose-rules` (proactif).
  memory.py             → CycleMemory ChromaDB (confidence + past_cycles_used)
  incidents.py          → IncidentRegistry (TTL, persist, thread-safe)
  cli.py                → watch, respond, restore (--wait), release, unblock, reset (revert=alias), list, pending, ack, activate,
                          audit (--all), approve-rule, reject-rule, propose-rules, check-ttl, jobs, bot, dashboard, war-room
  escalations.py        → ~/.glorfindel/escalations.jsonl + labels (proposed_rule, improve_detection ajoutés)
  bot.py                → Discord bot — un fil par VM, boutons Acquitter + Commande, /pending slash command
  tui.py                → Rich TUI full-screen (glorfindel dashboard) : resources + feed + escalations, raccourcis a/r/x/u/v
  api.py                → FastAPI War Room — /api/state (expose autonomy_modes, autonomy_default,
                          read_only, capability), /api/feed (WS), /api/config, /api/audit[/<vm>],
                          /api/pending/rules, /api/action/{release,revert,restore,ack,approve-rule,snapshot/<vm>}
                          /api/action/approve/{esc_id} — exécute l'action retenue d'un mode_hold (action_params)
                          /api/autonomy/{vm} (set_asset_mode) + /api/config/autonomy/default (set_default_mode)
                          /api/discovered — assets découverts (lecture fraîche JSON à chaque appel)
                          /api/jobs/<vm> — état du job snapshot/restore en cours (lit active_jobs/<vm>.json)
  static/index.html     → War Room web UI — cards VM expandables (compact + étendu), feed live
                          bandeau INFRASTRUCTURE (posture) : 2 axes orthogonaux — régime credentials
                          (👁 OBSERVE-ONLY ↔ ⚡ ACTIVE) + autonomy (⚡ non-disruptive / 👁 human-only).
                          Langage couleur : orange = peut agir, bleu = observe. Tue « absence de badge = actif ».
                          Mode autonomie : dropdown ⚙ Config (défaut global) + badge par carte cliquable
                          → popover capacité (ce que Glorfindel fait seul par mode, lit /api/state.capability)
                          boutons ↩️ Release (isolated) | ↩️ Unblock (blocked IP) | ⟳ Reset (les deux) | 🔄 Restore
                          grisage read-only préventif (_applyReadOnlyGuards) : write désactivés en observe-only,
                          Ack/Cmd restent actifs. Badge VM OFFLINE (heartbeat >15min, reste grisée, rétention 8h).
                          Approve & execute paramétré : block_suspicious_ip en 1-clic (action_params.ip ou invite)
                          section BACKUP par carte : nb de RPs, âge dernier backup, bouton 📸 Snapshot (fire-and-forget RSV)
                          carte MONITORING : backends + assets découverts + règles cliquables (modal query)
                          panneau ⚙ Config : Azure credentials + LLM + mode autonomie global
  rules/azure/
    detection_rules.yaml → rules UNIQUEMENT — queries KQL, TTPs, noms de backends
                           PAS de workspace_id, resource_id, ni section assets
                           assets: [auto] → s'applique aux VMs découvertes par le backend
                           monitoring_backends: [law-celebrimbor-amonsul] par rule → nom du backend
                           (OPTIONNEL : omis si un seul backend du type, cas mono-LAW → résolution fallback)

annatar/
  runner/engine.py    → garde RG + VM (`safety/guard.check_target`, tag annatar-test=true sur les DEUX — avant : RG seul,
                        `check_vm` sans site d'appel ; `annatar clean` gardé aussi) → setup → integrity check → attack
                        → emit attack_started (sans query — Glorfindel résout via detection_rules.yaml)
                        → thread daemon feedback: si detection_timeout → emit detection_missed
  runner/parser.py    → Scenario dataclass simplifié (detection: timeout/prerequisites/hints)
  signals/schema.py   → Signal + severity_for_ttp (T1486/T1041/T1110/T1548)
  signals/emitter.py  → signal normalisé JSONL

annatar/scenarios/azure/
  Structure: name, mitre, target, setup, steps, detection{timeout, prerequisites, hints}
  ransomware-vm.yaml          → T1486
  data-exfiltration.yaml      → T1041
  lateral-movement.yaml       → T1110.001
  privilege-escalation.yaml   → T1548.003
  account-creation.yaml       → T1136.001 (purple loop test — pas de règle initiale, règle proposée + approuvée)
  (cleanup/recovery/source/query/workspace_id supprimés — appartiennent à Glorfindel)

schemas/scenario.schema.json  → JSON Schema validation IDE (mis à jour: prerequisites→detection.prerequisites)
infra/terraform/              → module Celebrimbor : infra de test Azure modulaire, namespacée, jetable.
                                Celebrimbor = le bâtisseur (annatar=rouge, glorfindel=bleu, celebrimbor=infra).
                                Pilotée par config.yaml (yamldecode + for_each). instance = WORKSPACE Terraform :
                                "default" → noms canoniques (vm-celebrimbor-gondolin, law-celebrimbor-amonsul,
                                rsv-celebrimbor-erebor, rg-celebrimbor) ; instance nommée → tout suffixé "-<instance>"
                                + state isolé → stacks parallèles (pipelines short/long run).
                                Topologies de validation dans config.yaml (topologies.<n>.enabled, toutes false
                                par défaut), gated par for_each, 1 RG par topo. topo_multinic.tf = topo #1 (2 NIC).
                                Cibles : make celebrimbor-{plan,up,down,output,stop,start} [INSTANCE=] [TOPO=].
                                Schéma de noms type-celebrimbor-nom (CAF) : VM=cités, LAW=tours de guet, RSV=coffres.

~/.glorfindel/
  escalations.jsonl           → escalades persistées
  incidents.jsonl             → incidents actifs
  isolation/<vm>.json         → état NSG isolation + TTL
  blocks/<vm>.json            → IPs bloquées par VM
  proposed_rules.jsonl        → règles de détection proposées (en attente d'approbation)
  bot_posted.json             → IDs escalades déjà postées (évite doublons au redémarrage du bot)
  bot_threads.json            → resource_id → thread_id Discord (persistance entre redémarrages)
  rule_status.json            → état de polling des règles (last_poll, last_match, match_count, last_error)
  readiness.json              → verrou L6 par VM : dernier contrôle de préparation + réserves acceptées
                                (active_since, alerted) — écrit par le watch (tracker) et la War Room
  discovered_assets.json      → cache assets découverts (AssetRegistry) — survit aux redémarrages
  active_jobs/<vm>.json       → état persisté du job snapshot/restore en cours (partagé CLI/War Room)
                                réconcilié par la boucle watch (`jobs.reconcile_jobs`, cadence TTL ~1min) :
                                poll Azure (`refresh_job`, source unique CLI+API+watch) → Completed/Failed ;
                                garde-fou déterministe → `Stale` si InProgress > 24h (job mort, sinon InProgress
                                éternel — un snapshot a traîné 10j faute de `jobs --refresh` manuel)
  .bashrc                     → PS1 + HISTFILE + alias gf (chargé par make glorfindel-shell)
  .bash_history               → historique bash persistant

~/.annatar/
  .bashrc                     → PS1 + HISTFILE + alias ar (chargé par make annatar-shell)
  .bash_history               → historique bash persistant

~/.cache/chroma/              → modèle ONNX ChromaDB (79MB, téléchargé une seule fois)
```

---

## CLI — référence complète

```bash
# Workflow opérateur — Docker Compose (recommandé)
make glorfindel-start                        # lance watch + war-room → http://localhost:7007
make glorfindel-logs                         # tail logs des deux services
make glorfindel-dev                          # auto-reload sur modification de code (docker compose watch)
make glorfindel-stop                         # arrêt

# Workflow opérateur — 3 terminaux (local sans Docker Compose)
glorfindel watch runs/                       # terminal 1 — réponses automatiques
annatar run annatar/scenarios/azure/ransomware-vm.yaml  # terminal 2 — attaque
glorfindel pending --watch                   # terminal 3 — alerting (poll 2s, NEW ESCALATION)

# Setup scénario T1486 (avant chaque run)
annatar clean annatar/scenarios/azure/ransomware-vm.yaml   # nettoyage disque
# ⚠ Attendre 10 min après annatar clean — les I/O du nettoyage peuvent déclencher
#   ransomware-disk-write (ago(10m)) et fausser detection_time_s à 0.
glorfindel snapshot <resource_id> --yes --wait             # recovery point propre (~5-20min, --wait requis)
annatar run annatar/scenarios/azure/ransomware-vm.yaml     # lancer l'attaque

# État
glorfindel list                              # toutes VMs : isolations + IPs bloquées + assets découverts
glorfindel pending                           # escalades en attente
glorfindel pending --watch                   # alerting temps réel

# Actions remédiation — choisir le bon périmètre
#
# Sémantique :
#   isolated = règle NSG deny-all sur la VM  → glorfindel release (lever l'isolation)
#   blocked  = règle NSG deny sur une IP     → glorfindel unblock (dé-bloquer l'IP)
#   les deux → glorfindel reset (reset complet)
#
# War Room :  ↩️ Release (isolated) | ↩️ Unblock (blocked IP) | ⟳ Reset (les deux)
# TUI :       x:release  u:unblock  v:reset  r:restore
#
glorfindel release <resource_id> --yes       # lever isolation NSG (post-restore, VM de retour)
glorfindel unblock <ip> <resource_id> --yes  # supprimer une règle block IP
glorfindel reset <resource_id> --yes        # reset complet : release + unblock toutes IPs
glorfindel reset <resource_id> --from-azure  # source de vérité = Azure (sans état local) : retire les
                                             # glorfindel-* de CETTE VM sur ses NSG (noms déterministes,
                                             # segment IP qui ancre la correspondance) ; garde les blocages
                                             # de périmètre ; aperçu + confirmation ; --dry-run pour lister
glorfindel snapshot <resource_id> --yes      # backup on-demand RSV (setup scénario, ~5-20min)
glorfindel restore <resource_id> --yes       # Azure Backup fire-and-forget (--before auto-détecté)
glorfindel restore <resource_id> --yes --wait  # workflow complet : attend recovery_complete → release_isolation auto
glorfindel jobs <vm-name> [--refresh]        # état du job snapshot/restore en cours
glorfindel ack <escalation_id>               # acquitter escalade
glorfindel ack --all                         # acquitter toutes
glorfindel check-ttl                         # libérer isolations expirées

# Audit remédiation — vérifier que Glorfindel peut agir avant l'incident
glorfindel activate <vm|resource_id>         # réponse autonome pour une VM : contrôle de préparation,
                                             # réserves affichées puis acceptées (--yes), refus si pas prête
glorfindel audit <resource_id>               # NSG / backup / compute / IAM
glorfindel audit --all                       # toutes ressources de detection_rules.yaml
glorfindel audit --all --vault <nom>         # vault non-défaut (défaut: rsv-celebrimbor-erebor)

# Boucle purple team — apprentissage détection
glorfindel pending                           # voir les règles proposées (proposed_rule)
glorfindel propose-rules [--ttp T..] [--include-planned] [--dry-run]  # autoring PROACTIF cold-start :
                                             # génère la détection depuis technique_catalog.yaml AVANT
                                             # l'attaque (getschema sur le vrai LAW → KQL groundée).
                                             # Skip les TTPs déjà couverts. Sortie = propositions.
glorfindel approve-rule <id>                 # appliquer la règle → detection_rules.yaml
glorfindel reject-rule <id>                  # écarter la règle sans l'approuver

glorfindel memory-stats                      # ChromaDB cycle count
glorfindel bot                               # démarrer le bot Discord interactif
glorfindel dashboard                         # TUI full-screen : resources + feed + escalations
glorfindel war-room                          # War Room web sur http://localhost:7007 (pip install eregion[war-room])
glorfindel --version                         # 0.2.0

# Annatar
annatar run annatar/scenarios/azure/<scenario>.yaml  # --dry-run disponible, --skip-preflight pour bypasser le check VM

# Simulation locale sans Azure
make annatar-simulate
make annatar-simulate-gap

# Variables d'environnement
ANTHROPIC_API_KEY=...               # requis si provider Anthropic (défaut)
GLORFINDEL_LLM_MODEL=...            # ex: ollama/llama3.1, openai/gpt-4o, azure/gpt-4o (défaut: anthropic/claude-sonnet-4-6)
GLORFINDEL_LLM_BASE_URL=...         # endpoint self-hosted/Ollama (ex: http://localhost:11434)
GLORFINDEL_WEBHOOK_URL=...          # Slack/Teams/Discord webhook — escalades ET actions autonomes
                                    # Discord : https://discord.com/api/webhooks/<id>/<token>/slack
DISCORD_BOT_TOKEN=...               # Bot Discord interactif (fils par VM, boutons Acquitter/Commande)
DISCORD_CHANNEL_ID=...              # ID du channel (clic droit → Copy Channel ID)
DISCORD_PING_ROLE=...               # ID du rôle à pinger à l'ouverture d'un fil (optionnel)
GLORFINDEL_KEEP_ISOLATED=1          # mode forensique
GLORFINDEL_ISOLATION_TTL_H=4        # TTL isolation (défaut 4h)
GLORFINDEL_INCIDENT_TTL_S=300       # TTL fenêtre incident
GLORFINDEL_CONFIDENCE_THRESHOLD=0.7 # gate autonomie LLM (défaut 0.7 — en dessous → escalade forcée)
GLORFINDEL_READ_ONLY=1              # creds lecture seule (SP Reader) — mode observe-only
GLORFINDEL_DISCOVERY_RETENTION_H=8  # rétention d'une VM éteinte dans le registre avant éviction (défaut 8h)
```

---

## Tests

```bash
pytest                    # 681 tests (~15s), 0 appel Azure, 0 appel LLM, 0 écriture ~/.glorfindel/
                          # Hermétique par construction (conftest) : TOUS les chemins ~/.glorfindel redirigés
                          # vers tmp, et le glorfindel-config.yaml local ignoré (avant : avec une config locale,
                          # les tests de graphe lançaient de vraies requêtes KQL via `investigate`, suite 5× plus lente).
                          # CI : .github/workflows/ci.yml — ruff + pytest, Python 3.11 et 3.12.
                          # ruff figé (0.15.14, extra dev) + règles explicites dans pyproject
                          # ([tool.ruff.lint] select E4/E7/E9/F) : un ruff plus récent aux règles par
                          # défaut plus larges avait fait 450 constats de style au 1er run CI.
pytest tests/unit/test_agent_nodes.py        # LangGraph nodes (incl. investigate + confidence gate)
pytest tests/unit/test_glorfindel.py         # actions/routing/signals
pytest tests/unit/test_detection_rules.py    # RulePoller + load_rules + status + recently_matched
pytest tests/unit/test_proposed_rules.py     # record/pending/approve/reject + routing
pytest tests/unit/test_detection_authoring.py # catalogue + getschema + author_rule + propose-rules
pytest tests/unit/test_audit.py              # NSG/backup/compute/IAM readiness
pytest tests/unit/test_config.py             # GlorfindelConfig + ExceptionConfig
pytest tests/unit/test_discovery.py          # AssetRegistry + DiscoveryService + eviction
```

---

## Packaging

```
name = "eregion", version = "0.2.0", Apache 2.0 ✓
entrypoints : annatar + glorfindel CLIs
wheel : eregion-0.2.0-py3-none-any.whl ✓
```

---

## Coûts réels (West Europe)

- **Infra existante** : LLM API uniquement (Anthropic défaut), <$2/mois (~$0.05–0.10 par run)
- **Infra Celebrimbor (Terraform)** : ~$25–35/mois (VM ~6h/jour + disques + IP + backup + LAW). Jetable — `make celebrimbor-stop` pour pauser sans détruire. ⚠️ **`celebrimbor-down` est GARDÉ** (suite incident 2026-06-25 où un `down` non scopé a emporté tout le baseline) : il est **symétrique de `up`** et **protège le baseline**. `make celebrimbor-down TOPO=multinic` → destruction **scopée** d'une topo (via `-target` sur son RG), baseline intact. `make celebrimbor-down` **sans arg refuse** et exige `CONFIRM=<instance>` pour un teardown total (baseline inclus). Retirer une topo proprement = `enabled: false` dans `config.yaml` + `make celebrimbor-up`. Convention : chaque topo définit `azurerm_resource_group.<topo>` (count) = la cible `-target`.

---

## Détails Azure à connaître

- NSG isolation = outbound deny-all → bloque AMA (`mdsd.err` : Failed to get gig token) → detection timeout sur run suivant. Toujours `glorfindel reset` avant le prochain run.
- `annatar clean` T1486 génère des I/O disque élevées → RulePoller peut matcher la règle `ransomware-disk-write` (données dans `ago(10m)`) avant le vrai run. Résultat : `detection_time_s=0`, isolation sur données du nettoyage, pas du vrai run. Fix : attendre 10 min entre `annatar clean` et `annatar run`, ou vérifier que `detection_time_s > 0` après le run.
- **Multi-NIC — isolation/block couvrent TOUTES les NICs** : un NSG s'associe à un **subnet** OU une **NIC** (≤1 chacun ; un même NSG peut être partagé entre plusieurs subnets/NICs). Une NIC est soumise à ≤2 NSG (le sien + celui de son subnet). Une VM a 1..N NICs, chacune avec 1..N ipConfigs (IP privées multiples). **Ne couvrir que la NIC primaire laisse les autres NICs ouvertes** (faux « isolé »). `_get_vm_nic_targets(rg, vm)` énumère toutes les NICs → `isolate_vm`/`block_suspicious_ip(scope="vm")` posent **un placement par NIC** : deny any/any sur un NSG de NIC (première priorité libre ≥ 100 — **aucune règle client déplacée** depuis le lot L3), ou deny **scopé à TOUTES les IP privées de la NIC** (règle augmentée `*_address_prefixes`) sur un NSG subnet partagé (priorité libre, pas de bump). Noms de règle uniques par (VM, NIC) via `_placement_rule_base` (hash si > 80 char). `release_isolation`/`unblock_ip` défont chaque placement ; `verify_isolation`/`verify_block_ip` renvoient `verified=False` si **une seule** NIC n'est pas couverte (`uncovered_nics`). State : liste `placements[]` dans `isolation/<vm>.json` et entrée block (+ champs plats `nsg`/`nsg_scope` rétro-compat `/api/state`). **Rétro-compat** : release/verify gèrent l'ancien state single-NSG. ⚠️ `verify` confirme la **présence des règles par NIC** (pas l'API *effective security rules* — écartée : nom SDK non vérifiable hors Azure + flaky VM éteinte). ⚠️ **Phase B (backlog)** : les couches AU-DESSUS du NSG peuvent court-circuiter l'isolation et ne sont PAS encore détectées — **Azure Virtual Network Manager security admin rules** (`Always allow` globale, priorité > NSG), **UDR/route tables/Azure Firewall** (routage), **ASG**, IPs plateforme `168.63.129.16`/`169.254.169.254`. Voir mémoire `reference_azure_nsg_model`. **✅ Phase A validée sur Azure réel 2026-06-25** (topo Celebrimbor `multinic`, 2 NICs/2 NSG scope-NIC, PASS 7/7) : isolate pose la deny sur **les 2** NSG, `verify_isolation` `verified=True nics_covered=2`, retrait manuel d'une règle → `uncovered_nics` détecté, release/block/unblock multi-NIC propres. Le trou « 2e NIC joignable malgré ISOLATED » est **fermé et vérifié** (plus seulement mocké).
- **Précédence des règles NSG — une allow avant notre deny l'emporte (constat banc 2026-10-05)** : les NSG appliquent la **première** règle qui correspond, par priorité croissante. Le NSG de subnet du banc portait `allow-ssh` (Inbound, * → *, 22) en **priorité 100** : l'isolation (deny IP-scopé à la 1re priorité libre → 101) laissait **SSH ouvert** sur la VM « isolée », et `block_suspicious_ip` (deny à partir de 200) laissait passer un **brute force SSH** — pendant que la vérification, de présence seule, disait `verified=True`. Désormais : `_shadowing_rules()` (allow hors `glorfindel-*`, priorité < notre deny, source ET destination couvrant le trafic visé ; CIDR, `*`, `VirtualNetwork`/`Internet`, ASG supposé couvrant) → `shadowed_by` dans l'outcome (blocage de périmètre compris), **`verify_isolation` / `verify_block_ip` échouent** (escalade `verification_failed` qui nomme la règle — type réellement émis depuis la seconde passe du 05/10 : `escalate_to_human` n'avait pas de branche pour un échec de vérification, qui arrivait étiqueté « detection timeout », sans bouton Revert), et l'**audit** a un contrôle « NSG precedence » (fail + commande `az network nsg rule update … --priority 1000`). **Lot L3 (2026-10-06)** : plus aucune règle client n'est déplacée (avant : une règle client en priorité 100 passait à 200 pour laisser la place au deny — un `terraform apply` la remettait, ou échouait sur notre priorité) ; le deny prend la première priorité libre, sur **tout** NSG, et la préséance est donc vérifiée partout. Quand une allow passe avant notre deny sur le NSG de la carte, le deny est posé sur le **NSG du subnet** (`alt_nsg`, scopé aux IP de la VM ; le trafic doit passer les deux NSG, un deny dans l'un suffit), placement noté `moved_from` ; vérification, levée sans état et `reset --from-azure` regardent les deux NSG (`_nic_nsg_views`). **Liste des règles illisible** (throttling, erreur transitoire) → `verified=None` + `precedence_unknown` (« préséance non vérifiable »), plus `verified=True` sur une inconnue ; l'audit passe en `warn` ; `reset --from-azure` garde l'état local. Le contrôle d'ombrage utilise le nom de règle **trouvé** (une isolation au nom legacy passait sans comparaison). **Blocage gradué par port (L3)** : le port de la menace est déduit de la détection, jamais ajouté au signal (règle `ssh-*`, ligne qui mentionne ssh, requête de la règle du TTP avec `sshd`/`Failed password` → 22) et passé à `block_suspicious_ip(threat_port=)`, enregistré dans l'état. Une allow avant le deny ne contourne le blocage que si elle est **entrante et couvre ce port** (`threat_port_open`) ; sinon c'est une **exposition** (`exposure` : l'attaquant atteint d'autres ports), vérification OK. Port inconnu → toute allow compte, comme avant. Le NSG de repli s'applique aussi aux blocages. Banc : `allow-ssh` passé à **1000** (`network.tf`, appliqué le 05/10 ; topo multinic aussi) — **Glorfindel utilise la plage 100–999, les allow client doivent être au-delà**. Validé en réel le 05/10 : isolate (deny à 100) → `verify_isolation` OK → release → `verify_release` OK ; block (IP de doc 203.0.113.50) → `verify_block_ip` OK (deux sens) → unblock ; aucune règle ni état résiduel.
- ⚠️ **NSG Terraform à règles EN LIGNE** (`network.tf`, topos) : un `terraform apply` / `make celebrimbor-up` **supprime toute règle absente du fichier — y compris les `glorfindel-*` d'une isolation ou d'un blocage en cours**. `glorfindel list` doit être vide avant un apply.
- **NSG de NIC partagé — traité comme un NSG partagé (revue 2026-10)** : un même NSG peut être attaché à plusieurs NICs (pattern « un NSG par tier ») ou aussi à un subnet. L'ancien code le traitait comme « cette VM seule » et y posait un deny any/any priorité 100 → une isolation **autonome** coupait **toutes** les VMs derrière ce NSG (et deux placements sur le même NSG entraient en conflit de priorité). `_nsg_is_shared()` lit `network_interfaces`/`subnets` du NSG ; partagé (ou illisible) → `ip_scoped=True` → deny scopé aux IP de la VM, priorité libre, aucun bump (même traitement qu'un NSG subnet). Le scope affiché reste `nic` + `shared_nsg: true`. ⚠️ À valider sur Azure réel : topo `sharednsg` (`topo_sharednsg.tf`, désactivée par défaut — `make celebrimbor-up TOPO=sharednsg`, puis `make celebrimbor-down TOPO=sharednsg`). Le banc baseline n'a pas ce cas (NSG de subnet uniquement).
- **Échec partiel isolate/block** : un échec sur la NIC n laissait les règles des NICs 1..n-1 sur Azure **sans état** (invisible de `list`, hors d'atteinte de `reset`). Désormais les règles posées **restent** (confinement partiel > aucun), sont enregistrées (`partial: true`, `failed_nic`) et `PartialActionError` est levée (porte le `status_code` → `write_blocked` préservé). Les règles client décalées de la priorité 100 sont enregistrées **dès** que le décalage est confirmé ; si le deny échoue ensuite, elles sont remises à 100 immédiatement.
- **`release_isolation` / `unblock_ip` ne mentent plus** : les erreurs de suppression ne sont plus avalées (`ResourceNotFound` = déjà supprimée, OK) → statut `release_partial` / `unblock_partial` + règles en échec, **état conservé** pour un nouvel essai ; `glorfindel release`/`unblock`/`reset` le disent et sortent en code 2 (la War Room affiche donc une erreur). Sans état (perdu, corrompu, jamais écrit) : `release` recalcule les noms de règles (déterministes) sur **chaque** NIC actuelle — couvre en partie le follow-up « reset source de vérité = Azure ». État illisible → avertissement + traité comme absent (plus de crash). Écritures d'état atomiques (tmp + `os.replace`). `glorfindel release` ne dit « rien à lever » que si **aucune** NIC ne porte de règle (avant : `not verify_isolation()` → une VM à moitié isolée voyait son état effacé, règle orpheline).
- **Isolation JIT par NSG de quarantaine (lot L4, validé avec Jonathan le 2026-10-06)** : le temps de l'isolation, **chaque NIC porte le NSG de quarantaine de Glorfindel** (`nsg-glorfindel-quarantine-<région>`, tags `managed-by=glorfindel`, deux règles deny-all en 100, créé au premier besoin dans `isolation.quarantine_rg` de `glorfindel-config.yaml`, défaut : le RG de la VM ; `isolation.quarantine_nsg: false` ou `GLORFINDEL_QUARANTINE_NSG=0` pour revenir aux règles). Une NIC sans NSG le reçoit ; une NIC **avec** son NSG le reçoit **à la place** — le NSG client et ses règles restent intacts, et reviennent à la levée. Aucune règle client touchée, aucune préséance possible, isole aussi une NIC sans aucun NSG.
  - **Terraform — mesuré sur le banc (azurerm 4.81.0, pile jetable, 8 tests)** : échange ou accroche hors Terraform → `plan` sans changement, `apply` ne remet rien ; un `apply` qui modifie la NIC (tags) garde notre NSG ; le client qui **ajoute** une association en code pendant l'isolation → son `apply` échoue (`ImportAsExistsError`) ; remettre le NSG client → `plan` propre. **Reprennent la main** : le remplacement forcé de l'association (ou un changement de NSG dans son code, ForceNew) et un **redéploiement Bicep/ARM** de la NIC (même incrémental) → son NSG revient / le nôtre est retiré. Raison : la ressource NIC ne porte pas son NSG, et la lecture de l'association ne vérifie que la *présence* d'un NSG, sans comparer lequel.
  - **DNS et IMDS d'Azure (L17, mesuré le 07/10)** : un deny-all ne filtre pas 168.63.129.16 (DNS) ni 169.254.169.254 (IMDS) sans leurs service tags — une VM isolée résolvait encore les noms (tunnel DNS) et récupérait un jeton d'identité managée. Le NSG de quarantaine porte `glorfindel-quarantine-deny-dns` (110, `AzurePlatformDNS`) et `-deny-imds` (111, `AzurePlatformIMDS`), ajoutés aussi à un NSG existant. Mesuré : résolution et IMDS bloqués, **Run Command toujours fonctionnel** (WireServer non couvert par ces tags), tout revient à la levée. `isolation.forensic_sources` (CIDR) → allow entrante en 90 avant le deny (Bastion, rebond d'investigation), sessions exclues de la coupure.
  - **L'original** est enregistré dans l'état ET, avant l'échange, en tag sur notre NSG (`glorfindel-orig-<hash de la NIC>` → id du NSG client ; pas sur la NIC : Terraform réécrit ses tags) → `release` et `reset --from-azure` le remettent même sans état local. La levée ne touche la NIC que si elle porte encore **notre** NSG.
  - Échange refusé (Azure Policy, droits) → repli sur les règles (L3 : NSG de la NIC, NSG de subnet si une allow passe avant). Un **blocage d'IP** reste par règles et ne va jamais dans notre NSG (il partirait avec la levée). Un NSG de **subnet** n'est jamais échangé.
  - Droits : `networkInterfaces/write`, `networkSecurityGroups/write` (création, tags) et `/join/action`, plus `virtualMachines/runCommand/action` (coupure des sessions, neutralisation avant restore). **Vérifiés sans rien écrire** par l'audit (« Isolation permissions », `check_permissions` → API `Microsoft.Authorization/permissions`, toutes les pages, **chaque droit sur le groupe où il s'applique** (`_permission_scopes`, troisième passe T12) : `networkInterfaces/write` sur le groupe de chaque carte, `virtualNetworks/subnets/join/action` sur celui du VNet — sans lui l'échange échoue en `LinkedAuthorizationFailed` —, NSG de quarantaine, `join/action` sur le NSG du client (la levée le remet ; manquant → réserve `release_blocked`), règles sur les NSG où elles se posent, Run Command sur la VM ; les deny assignments, verrous et PIM ne sont pas évalués) — brique du bouton d'activation L6.
  - War Room : à côté du badge ISOLATED/BLOCKED, « ✓ il y a Xs » (`verified_at`), orange au-delà de 5 min (le watch ne relit plus l'état).
  - **Connaître l'état à l'instant T** : la boucle L5 relit Azure toutes les 60 s pour les VMs isolées/bloquées (`verified_at` dans l'état et `/api/state`) ; si notre NSG a été remplacé, réécheange une fois puis alerte seulement (human_only : alerte), et l'alerte cite les dernières écritures sur la NIC lues dans le journal d'activité (qui, quoi — explicatif, jamais utilisé pour détecter : il a plusieurs minutes de retard).
- **NSG subnet-level — isolation scopée à l'IP VM** (historique single-NIC, généralisé ci-dessus) : `_get_nic_nsg` prend l'NSG de la NIC si elle en a une, sinon retombe sur l'NSG du **subnet** (partagé), exposé via `nsg_scope` (`nic`|`subnet`). scope `nic` → deny any/any à priority 100 (n'affecte que la VM) ; scope `subnet` → deny **scopé aux IP privées de la VM**, priorité libre → isole UNIQUEMENT la cible. **Plus de blast radius pour isolate, même autonome.** `block_suspicious_ip(ip, resource_id, scope="vm"|"subnet")` (commit `8e085ec` + `5d32516`) :
- `scope="vm"` (défaut, **autonome**) : scopé à l'IP de la VM sur NSG subnet (inbound src=attaquant/dst=IP_VM, outbound src=IP_VM/dst=attaquant, nom suffixé par VM) ou any sur NSG NIC → ne touche que cette VM. `scoped=True`.
- `scope="subnet"` (**opt-in délibéré opérateur**) : une règle `any` (attaquant↔*) sur le **NSG du subnet** (`_get_subnet_nsg`, nom partagé sans suffixe) → bloque l'IP pour TOUT le subnet (+ VMs futures). `scoped=False` → War Room ⚠ subnet-wide. Erreur claire si le subnet n'a pas de NSG.
- `scope="subnet", replace=True` (**promote VM→subnet**, commit `522f572`) : **create-then-delete** — pose d'abord la règle subnet-wide (la VM est alors couverte) puis supprime la règle VM redondante → **jamais de gap de protection** (si la pose subnet échoue, la règle VM reste intacte, pas de rollback nécessaire). État remplacé (1 entrée), outcome porte `promoted_from`.
- Recommandation : une seule règle `any` pour le subnet-wide (pas N règles scopées) — couvre les VMs futures, cycle de vie simple. La **modal de choix** (VM vs subnet) + passage de `scope` via `/api/action approve` + affordance « Extend to subnet » (`/api/action/block-promote`) = travail War Room.
- `unblock` cible le NSG **enregistré dans l'état** (fidèle pour une règle subnet-wide), fallback résolution NIC pour l'état legacy. `verify_block` suit le scope. Principe : une action **autonome** ne modifie jamais la posture des autres VMs ; le subnet-wide est un choix explicite.
- Règles block IP persistent entre runs → conflit priority si T1110 puis T1548. Nettoyage : `glorfindel reset`.
- `isolate_vm` ne déplace plus de règle client (L3, 2026-10-06) : première priorité libre ≥ 100. Les états anciens qui portent `bumped` sont toujours restaurés à la levée.
- StorageBlobLogs : latence secondes. `AzureNetworkAnalytics_CL` inutilisable (10-60min).
- Restore via REST API `IaasVMRestoreRequest OriginalLocation` → VM deallocated puis redémarrée.
- **Une règle NSG ne coupe pas une session déjà ouverte (mesuré le 2026-10-05)** : session SSH active (17 min), session inactive (11 min) et téléchargement sortant ont survécu à l'isolation ; les nouvelles connexions étaient refusées. Run Command passe pendant l'isolation (adresse plateforme 168.63.129.16, non filtrée par les NSG) et `ss -K` lancé par ce biais coupe tout. → `isolate_vm` appelle désormais `drain_connections()` après la pose des règles : `ss -K state established` sauf loopback, 168.63.129.16 et 169.254.169.254, puis compte ce qui reste (`drain: drained | partial | failed | unsupported` — Windows non géré). Sessions encore ouvertes → vérification en échec (`verification_failed`). Demande le droit `Microsoft.Compute/virtualMachines/runCommand/action`. Le prompt (« revokes their remote foothold ») devient vrai quand la coupure réussit ; il n'a pas été modifié.
- **Le restore rejouait la dernière commande Run Command (constaté le 2026-10-05)** : au démarrage du disque restauré, l'agent VM exécute la commande Run Command dont il n'a pas vu le numéro de séquence — la dernière du modèle de VM, c'est-à-dire le script d'attaque (le chiffrement a recommencé, puis la VM a été libérée). Un attaquant passé par Run Command (T1651) obtient le même rejeu. `restore_from_backup` lance d'abord une commande inoffensive (`_neutralize_run_command`, VM allumée requise ; « neutralisée » seulement si elle a **fini** — `result(timeout)` rend la main sans lever ; extensions CustomScript et Run Commands managés v2 listés via `_replayable_scripts` — s'il y en a, ou si la liste est illisible, `run_command_neutralized: false` + `replay_vectors`, donc levée retenue ; SDK 38 : publisher/type sous `properties`) ; en cas d'échec le restore continue, le résultat porte `run_command_neutralized: false`, la CLI l'affiche et la levée autonome sur `recovery_complete` est **retenue** (`release_hold`).
- **Faux positif ransomware (B6) — ce n'est pas le démarrage (mesuré le 2026-10-06)** : 5 démarrages (4 à froid, 1 à chaud) → aucun échantillon > 1 Mo/s. Le pic de 52,2 Mo/s du 05/10 venait du **rattrapage apt/snap quotidien d'Ubuntu** (+4 à +6 min après le démarrage ; il arrive aussi sur une VM qui ne s'éteint jamais). AMA échantillonne toutes les 10 s (trous de 20–25 s sous charge), commence 61–76 s après le boot ; `total` et le volume lisent les mêmes écritures à ×0,8–1,25 près ; `System Up Time` n'est pas collecté. Correctif (PR #21, **validé par un run T1486 détecté par le RulePoller le 06/10** à T0+84 s) : moyenne de 2 échantillons consécutifs du même volume > **45 Mo/s** (choisi avec Jonathan) — max bénin 35,7 ; attaque la plus faible 53,4 (`total`) / 49,1 (volume de données) le 06/10, le HDD Standard du banc plafonnant vers 60 Mo/s ; autres attaques 65,7–120,3. Rejouée sur 3 jours d'historique : toutes les fenêtres malveillantes au-dessus de 45 sur les deux volumes, le faux positif en dessous ; à 50, le volume de données du 06/10 était raté. Sortie inchangée (`MaxWrite` par `Computer`). Limites : 2 rattrapages bénins et 4 épisodes malveillants, un seul type de disque ; une rafale de moins de 20 s serait ratée (variante possible : « ou un échantillon > 90 Mo/s »). Rapport : `collab/test_run_2026-10-06_b6_boot.md`.
- Après un restore, les anciens disques OS et data restent non attachés dans le RG (coût) — à nettoyer. ⚠️ **Pas tous** : `disk-celebrimbor-gondolin-data` et le disque OS d'origine sont suivis par Terraform (`azurerm_managed_disk.testdata`, attachement en LUN 10) — les supprimer casse l'état. Seuls les disques `vmcelebrimborgondolin-*-<date>` créés par un restore remplacé depuis sont jetables. Et après un restore, le prochain `terraform apply` détachera le disque de données restauré (`clean_lun10`) pour rattacher celui d'origine (données de juin) — à traiter côté Infra.
- VM auto-shutdown 23h UTC → `az vm start -g rg-celebrimbor -n vm-celebrimbor-gondolin` avant chaque session (ou `make celebrimbor-start`).
- Syslog latence ~60s nominal, timeout 300s dans les scénarios.
- DCR `facility_names` doit inclure `authpriv` — `useradd` sur Ubuntu génère des messages `LOG_AUTHPRIV`. Sans ce facility, T1136.001 (account creation) ne remonte pas dans LAW. Ajouté dans `monitoring.tf` (commit 9a64e83).
- Azure Backup OriginalLocation restore laisse des disques orphelins à LUN 10 → `terraform apply` échoue sur le prochain attachement. Fix : `null_resource.clean_lun10` dans `vm.tf` détache automatiquement tout disque non-testdata à LUN 10.
- `isolate_vm` écrit `~/.glorfindel/isolation/<vm>.json` **après** confirmation des règles NSG (commit `b2a41c3`) — un 403 ne laisse plus d'état orphelin « ISOLATED » sans règle. `glorfindel reset` matche le `resource_id` en case-insensitive et `release_isolation` nettoie le state file local même si Azure n'a aucune règle.
- **SDK Azure récents → enums, pas des chaînes (validation du 2026-10-06)** : `azure-mgmt-network` 33 (l'image Docker) renvoie `SecurityRuleAccess.ALLOW` là où la 30 (l'ancien venv) renvoyait `"Allow"`. `str(access).lower()` valait `'securityruleaccess.allow'` → le contrôle de préséance ne voyait **aucune** allow dans le produit déployé (contournements non détectés, repli L3 et blocage gradué inopérants), alors que les tests et la CLI de l'hôte passaient. `_enum_text()` lit la valeur ; une comparaison `==` avec la valeur fonctionne déjà (enums `str`). Le venv est aligné sur les versions de l'image ; test avec les vraies enums du SDK.
- **Imports azure.* concurrents → deadlock `_ModuleLock`** : les imports `from azure... import ...` sont paresseux (dans les méthodes). Deux threads important `azure.core` pour la 1re fois en même temps (audit parallèle, threads de poll watch) → deadlock du système d'import Python ou « cannot import name 'Pipeline' ». Fix : `actions.warm_up_azure_sdk()` importe tout une fois sur le thread principal au démarrage de `watch` ET au début de `audit.run` (avant le ThreadPool). Commit `23c2f88`. ⚠ Tout nouveau code qui importe azure dans un thread doit pouvoir compter sur le warm-up préalable, ou l'appeler.
- **Asset non-VM (AKS / VMSS) ≠ item backup IaaS — allowlist** : seule une **VM standalone** `Microsoft.Compute/virtualMachines` est un protected item Azure Backup IaaS. **Constat terrain** : le heartbeat AMA des nœuds AKS résout l'id vers le **managed cluster** (`.../Microsoft.ContainerService/managedClusters/<n>`), PAS l'instance VMSS — donc un test sur `/virtualmachinescalesets/` seul rate le vrai AKS. `recovery_points.list` y renvoie `BMSUserErrorDataSourceObjectNotFound`, **la même erreur qu'une VM standalone non protégée** (l'erreur ne discrimine pas, la **forme du resource_id** oui). `_is_backupable_vm(rid)` (allowlist : `Microsoft.Compute/virtualMachines` ET pas `/virtualMachineScaleSets/`) — plus robuste que lister les exceptions. `check_backup_points` court-circuite → `{not_backupable: True}` sans appel Azure. `posture._check_asset` **skip TOUT** (backup + NSG + compute) si `not _is_backupable_vm` → plus aucun gap parasite (`backup_linked` ni `nsg_reachable`) sur un cluster/nœud (qui n'est ni backupable ni NSG-isolatable la voie IaaS). `audit._check_backup` → `skip`. Commits `9a7bd59` (VMSS) puis élargi managed cluster + allowlist + skip-all posture. ⚠️ L'**agrégation** d'un cluster en 1 asset logique côté Glorfindel (option A) reste backlog — le repli est fait côté War Room (groupage par resource_id partagé / `parent`).
- **Snapshot/restore : RG du vault + job de LA VM (revue 2026-10)** : `snapshot`/`restore_from_backup` prennent `vault_rg` (config `action_backends[].resource_group`, comme l'audit) pour le POST REST, `recovery_points.list`, `backup_jobs.list`, `job_details.get` ; le snapshot autonome de l'agent ne retombe plus sur le défaut legacy `rsv-annatar`. Le job suivi est filtré par `entity_friendly_name == vm` + démarré après le déclenchement (avant : premier job `InProgress` du vault → deux snapshots concurrents se suivaient en croix). Restore : point le plus **récent** par `recovery_point_time` (tier vault préféré), plus l'ordre de la liste Azure.
- **Vault central multi-RG — le RG du vault ≠ le RG de la VM** : un RSV central (dans son propre resource group) peut protéger des VMs réparties sur plusieurs resource groups distincts. `check_backup_points` interrogeait le vault sous le **RG de la VM** → `ResourceNotFound` → faux « backup missing » sur TOUTES les VMs + posture_gap récurrent. Fix : `check_backup_points(resource_id, vault, vault_rg)` — le **container** d'item reste keyé par le RG de la VM (naming fabric Azure), mais le lookup `recovery_points.list`/`protected_items.get` est scopé au **RG du vault**. `vault_rg` résolu depuis `glorfindel-config.yaml` (`action_backends[].resource_group`) et propagé via `audit.run(..., vault_rg)`, `posture._vault_rg()`, `/api/audit[/<vm>]`, `glorfindel audit --vault-rg`. Fallback = RG de la VM quand vide (sandbox annatar : vault et VM co-localisés). `list_backup_items(vault, rg)` prend déjà le RG du vault.
- **Nom de container/item backup — CASSE sensible** : `recovery_points.list` est **case-SENSITIVE** sur le préfixe de type (`IaasVMContainer;` / `VM;`), alors que `protected_items.get` est **case-insensitive**. Construire en minuscules (`iaasvmcontainer;`/`vm;`) faisait réussir `protected_items.get` (→ `protected=True`) mais renvoyer `recovery_points.list` **vide** → faux « first backup pending » sur une VM **réellement** sauvegardée (RECOVER/`list_backup_items` lisait `last_recovery_point` de l'item trouvé par get → l'affichait, d'où l'incohérence posture vs RECOVER). Confirmé sur le bench Celebrimbor (`az backup recoverypoint list` montrait le RP, notre query le ratait sur la casse seule). `check_backup_points` utilise désormais le format canonique `IaasVMContainer;iaasvmcontainerv2;{rg_vm};{vm}` + `VM;...` (`_backup_item_names`). **Revue 2026-10** : `snapshot` et `restore` lisent les noms **tels que le vault les stocke** (`_resolve_backup_item_names` : `protected_items.get` insensible à la casse → id renvoyé → noms exacts) et prennent `vault_rg`. ⚠️ **Mesure réelle 2026-10-05 (lecture seule, rsv-celebrimbor-erebor)** : `recovery_points.list` renvoie les **mêmes 8 points en minuscules et en casse canonique** — la sensibilité à la casse constatée par 8bda989 n'est **pas reproduite** aujourd'hui (cause d'époque inconnue). L'hypothèse « l'ancien restore ne trouvait plus de point » est donc réfutée ; les noms canoniques + la résolution restent comme robustesse. Le restore complet n'a pas retourné en réel depuis le 09/06 (RTO 21m29s, ancienne sandbox) → à rejouer par la session Tests.

---

- **Troisième passe (07/10) — pas de succès sur une inconnue, bonne cible (L10, L11 en partie, L14 en partie)** :
  - `_original_from_tags` **lève** sur une erreur de lecture (avant : `None` → la levée laissait la carte **sans NSG** et `verify_release` disait vrai) ; la levée lit d'abord l'original dans l'état (`"original_nsg_id" in p`, `None` = la carte n'en avait pas), puis **relit la carte** (`_unquarantine`) : original absent ou inconnu → la carte reste en quarantaine, `release_partial`. Tags d'origine écrits sous verrou (`_quarantine_lock` : thread + flock `~/.glorfindel/locks/`) puis relus ; tag non posé → échange annulé, repli sur les règles. Ré-isolation d'une carte déjà en quarantaine : original repris de l'état (`_recorded_original`), pas écrasé par `None`.
  - `_rules_state` à trois états : une règle **illisible** n'est plus « disparue » → `verify_isolation` / `verify_block_ip` rendent `verified=None` (`unreadable_nics` / `unreadable_rules`), la réaffirmation ne repose rien. `_is_not_found` : 404 / `ResourceNotFoundError` seulement (la sous-chaîne « not found » couvrait aussi une ressource *référencée* manquante).
  - Coupure des sessions : `unsupported` (Windows) → **non vérifié** ; comptage `ss` en erreur → `failed` (avant : `| wc -l` donnait 0). Levée autonome seulement si `run_command_neutralized is True` (drapeau absent = inconnu → `release_hold`).
  - **Abonnement** : toute méthode d'action/vérification du connecteur refuse une VM d'un autre abonnement que `AZURE_SUBSCRIPTION_ID` (`WrongSubscriptionError` → `action_failed`) ; la préparation dit `other_subscription` (pas prête).
  - Règles : `ransomware-disk-write` lit la cadence de chaque série (`Step = min(Gap)`) — fine (≤ 25 s) : 2 échantillons > 45 Mo/s ; grossière (défaut Azure 60 s) : 1 échantillon > 25 Mo/s (moyennes 60 s reconstruites sur 10 jours : attaques 26,8–91,7, bénin max 23,2 — marge mince, à mesurer avec une vraie DCR à 60 s). `sudo-privilege-escalation` : `summarize arg_max(TimeGenerated, *) by Computer` au lieu de `| limit 1` (exécuté avant le filtre par VM → aveugle en multi-VM). Toute règle `assets: [auto]` avec `limit`/`take`/`top` → avertissement au chargement.

## Pitfalls opérateur

`backup_agent_check` retourne toujours `[]` sur les Linux VMs — `\\Process(*)\\IO Write Bytes/sec` est un counter Windows-only, Linux AMA ne le collecte pas. Idem pour `top_write_processes` (même counter). **C'est le comportement voulu** : résultats vides → le LLM ne peut pas exclure le ransomware → escalade forcée. L'alternative (`az backup job list` via RunCommand) ajouterait latence 15-30s + dépendance AZ CLI in-guest pour un résultat qui rendrait le produit trop confiant sur des données incomplètes.

`annatar run` fait un preflight check automatique (VM running + pas de règles `glorfindel-isolation-*`). Si ça échoue, le run s'arrête avec la commande exacte à lancer. `--skip-preflight` pour bypasser.

Après un `restore_from_backup`, le backup suivant est un **full backup** (~40min–4h selon Azure). Aucune API ne permet de prédire la durée. Le `glorfindel snapshot` du setup T1486 suivant peut donc être long. À anticiper avant les sessions de test.

```bash
# Si preflight échoue — commandes de fix
glorfindel list                           # voir isolations + IPs bloquées
glorfindel reset <resource_id> --yes     # reset complet

# Vérification NSG directe si besoin
az network nsg rule list -g rg-celebrimbor --nsg-name nsg-celebrimbor -o table
```

---

## Conventions

- **À chaque commit** : mettre à jour README + CLAUDE.md + générer résumé claude.ai
- `target:` = ressource attaquée, `detection:` = infra surveillance (workspace_id ici)
- `prerequisites:` = KQL vérification + instructions setup dans chaque scénario
- `setup_testdata.sh` uniquement dans T1486
- RunCommand : 5 retries (15s, 30s, 60s, 90s, 120s) — pas de SSH, pas d'IP publique requise pour Annatar (Azure VM Agent via Wire Protocol)
- `dry_run=True` dans tous les tests — jamais d'appel Azure ou LLM dans les tests
- `tests/unit/conftest.py` : fixture `autouse` redirige `escalations._STORE` → `tmp_path/escalations.jsonl` (les tests n'écrivent jamais dans `~/.glorfindel/`)
- `AZURE_SUBSCRIPTION_ID` obligatoire dans l'env (plus d'auto-détection via SubscriptionClient)
- **Edit de `few_shot_examples.yaml`, `_SYSTEM_PROMPT` ou `_build_user_message()`** : requiert un run end-to-end T1486 + au moins un autre TTP avant merge. Ces trois zones contrôlent ce que le LLM voit et comment il raisonne — les tests unitaires (LLM mocké, dry_run=True) ne peuvent pas valider le comportement résultant. Un edit mal calibré peut introduire un raccourci critique (ex: ransomware non-isolé 20min, faux positif T1041, cycle 1 sauté). Voir c6fe0d0, 740659a.
- **`past_cycles` ChromaDB = historique uniquement** : ne jamais inférer l'état courant de la VM depuis les cycles passés. `_build_user_message()` injecte `## État actuel de la VM` depuis `~/.glorfindel/isolation/<vm>.json` — c'est la source de vérité. Voir commit 740659a (bug : LLM voyait `isolate_vm` dans past_cycles → concluait "VM déjà isolée" → sautait le cycle 1).

---

## Sessions Claude spécialisées (multi-agents)

5 sessions spécialisées + 2 sessions transversales, coordonnées via `collab/`.

| Session | Fichier de rôle | Périmètre |
|---------|----------------|-----------|
| Glorfindel | `CLAUDE_GLORFINDEL.md` | `glorfindel/`, `rules/azure/`, tests unitaires Glorfindel |
| Annatar | `CLAUDE_ANNATAR.md` | `annatar/`, `annatar/scenarios/`, tests unitaires Annatar |
| Tests | `CLAUDE_TESTS.md` | Chef d'orchestre — tests fonctionnels bout en bout sur Azure réel |
| War Room | `CLAUDE_WARROOM.md` | UI/UX `glorfindel/static/index.html` + `glorfindel/api.py` |
| Infra | `CLAUDE_INFRA.md` | `infra/terraform/` — module Celebrimbor : infra Azure modulaire, namespacée, jetable + topos de validation |
| Review | `CLAUDE.md` (base) | Design review, architecture critique, BA sprint — ad hoc |
| General | `CLAUDE.md` (base) | Coordination inter-sessions, inbox routing, CLAUDE.md/README/ROADMAP |

**Démarrer une session :**
```
# Session Glorfindel
"Lis CLAUDE_GLORFINDEL.md pour tes instructions de session, puis commence par ton inbox."

# Session Annatar
"Lis CLAUDE_ANNATAR.md pour tes instructions de session, puis commence par ton inbox."

# Session Tests
"Lis CLAUDE_TESTS.md pour tes instructions de session, puis commence par ton inbox."

# Session War Room
"Lis CLAUDE_WARROOM.md pour tes instructions de session, puis commence par ton inbox."

# Session Infra
"Lis CLAUDE_INFRA.md pour tes instructions de session, puis commence par ton inbox."

# Session Review (ad hoc — challenge design et implémentations)
"Tu es la session Review d'Eregion. Lis CLAUDE.md. Ta mission : challenger les décisions architecturales, les implémentations critiques et les choix de sécurité. Commence par lire inbox_review.md."

# Session General (coordination)
"Tu es la session General d'Eregion. Lis CLAUDE.md. Ta mission : coordonner les sessions spécialisées, router les items cross-cutting, mettre à jour CLAUDE.md/README.md/ROADMAP.md. Commence par lire inbox_general.md."
```

**Protocole :** chaque session lit son inbox (`collab/inbox_<role>.md`) en début de tâche, met à jour son status (`collab/<role>_status.md`) après chaque changement significatif, et écrit dans l'inbox de l'autre si un changement a un impact cross-cutting.

---

## escalations — comportement

`gf pending` affiche les escalades avec **next steps générés par le LLM** (`suggested_steps`), contextuels à l'historique ChromaDB. Fallback statique pour les anciennes escalades sans ce champ.

**Escalade persistante — 1 carte vivante (pas N, pas figée).** La dédup `record()` (clé `action+resource_id+escalation_type` parmi les `pending`) garde **une seule** carte quand un finding re-déclenche, mais la rend vivante : `occurrences++` + `last_seen` à chaque re-fire (cheap, `first_seen` préservé → « 12× depuis 3h » d'un coup d'œil), et le contenu cher (reason/suggested_steps/confidence) **rafraîchi uniquement sur changement matériel** (delta de confiance ≥ `_MATERIAL_CONFIDENCE_DELTA`=0.1) — sinon le contenu reste stable (pas de flicker), et le **premier triage est préservé** (`first_reason`/`first_suggested_steps`/`first_confidence`). Avant : la sortie du re-`decide` était jetée → carte périmée sur un finding qui dure (constat terrain). ⚠️ Deux raffinements **différés** (touchent des hot-paths, validation run réel requise) : (a) throttle du re-`decide` LLM lui-même (risque de masquer un changement matériel si l'équivalence est trop lâche — `indicator_value` varie) ; (b) résolution du mismatch `Computer`≠`resource_id` via la map discovery (change l'input LLM via `normalize_row` → run end-to-end requis).

Types d'escalade : `unattributed_signal` (détection non attribuable à cette VM — ligne sans ressource, plusieurs VMs surveillées — action ciblant la VM retenue), `low_confidence` (gate de confiance, ou escalade demandée par le LLM sur une action autonome — libellé « confiance insuffisante », ex-« detection timeout »), `uncharacterized_signal` (garde-fou signal non caractérisé), `release_hold` (levée proposée hors `recovery_complete`), `destructive_action` (HUMAN_APPROVAL_REQUIRED), `proposed_action` (action inconnue ou non implémentée), `verification_failed` (action exécutée mais vérification en échec : règle absente, NIC non couverte, allow évaluée avant le deny — boutons Revert/reset), `proposed_rule` (règle de détection proposée après detection_missed), `mode_hold` (action autonome retenue par le mode `human_only` de l'asset — pas un manque de confiance), `write_blocked` (action tentée mais credentials read-only / IAM 403 — capability gap, pas un choix de politique), `action_failed` (échec non-auth pendant l'exécution — **toute** exception, connecteur compris — toujours escaladé, jamais d'abort silencieux du cycle), `cycle_failed` (le cycle n'a pas pu aller au bout : appel LLM en échec après retries, erreur interne, backend de détection injoignable pendant le poll — le signal est réel mais **non analysé**, triage humain), `readiness_hold` (VM configurée autonome mais retenue en `human_only` par le verrou L6 : réserves à confirmer, pas prête, ou réserve apparue depuis l'activation — bouton « Review & turn on »), `detection_blocked` (raté sur un TTP **déjà couvert** par une règle : la détection a été **empêchée** — isolation résiduelle, latence d'ingestion, backend injoignable — pas un manque de règle ; action portée `investigate_detection_gap`).

L'escalade porte `action_params` (dict, vide par défaut) pour les actions paramétrées — ex. `block_suspicious_ip` → `{"ip": ...}` extrait du signal via `_extract_suspicious_ip` (même source que `execute_action`). Permet à la War Room « Approve & execute » d'exécuter en 1 clic une action qui n'est pas à `resource_id` seul. Commit `9583ec6`.

`gf ack <id>` / `gf ack --all` → marque `resolved` dans `~/.glorfindel/escalations.jsonl`. Purement administratif — ne fait rien sur Azure. `restore_from_backup` auto-acquitte via `resolve_by_resource`. Les `posture_gap` s'**auto-résolvent** quand la condition disparaît (ex. backup nocturne comble « no recovery point yet ») — `PostureChecker.check_and_escalate` résout l'escalade au cycle suivant (commit `b208a0a`).

⚠️ **Ack d'un posture_gap encore RÉEL** : l'ack ne fait que `resolve` l'escalade ; `posture_state.json` gardait `status: "pending"` → le cycle suivant voyait « mon escalade n'est plus pending mais le gap existe toujours » → **recréait une escalade à chaque cycle** (ack inutile sur un gap persistant, ex. 14 VMs vraiment sans backup). Fix : `_maybe_escalate` interprète « pending + escalade absente de `pending()` » comme **acquitté** → `status: "acknowledged"`, ne ré-escalade plus. Le gap n'est ré-alerté que s'il **se résout puis réapparaît** (`_resolve_cleared_gaps` transitionne `pending`/`acknowledged` → `resolved` quand la condition disparaît). Un gap `acknowledged` sort de `active_gaps()` (n'apparaît plus dans `/api/state`).

⚠️ **Éviction ≠ condition résolue** : `_resolve_cleared_gaps` ne résout un gap que si son asset a été **réellement checké ce cycle** (`checked_vms`). Une VM éteinte > rétention (8h) → évincée de l'inventaire → **non checkée** → ses gaps sont **gelés** (ack préservé), PAS résolus. Sinon : VM éteinte le weekend → gap résolu à l'éviction → re-découverte lundi → **ré-escalade fraîche en masse** (le « flood du lundi », acks effacés). Avec le gel, un gap `acknowledged` reste silencieux au retour de la VM. Effet de bord assumé : une VM **supprimée** (pas juste éteinte) garde son gap gelé jusqu'à un ack (qui tient). Pour une VM intentionnellement sans backup → `exceptions:` dans `glorfindel-config.yaml` (sort du check, pas juste un ack).

## alerting webhook + bot Discord

**Webhook** (`GLORFINDEL_WEBHOOK_URL`) — one-way, Slack format :
- **Escalade** (`:rotating_light:`) — action humaine requise
- **Action autonome** (`:robot_face:`) — `isolate_vm ✓`, `block_suspicious_ip ✓`, etc. — skippé en dry-run et si `verified=False`
- Discord : utiliser l'URL webhook Discord avec `/slack` à la fin

**Bot Discord** (`glorfindel bot`, `DISCORD_BOT_TOKEN`) — bidirectionnel :
- Un fil Discord par `resource_id` (`🔴 vm-name`), créé à la première escalade pour la VM
- Chaque escalade posée dans le fil comme embed structuré (action, ressource, TTP, prochaines étapes LLM)
- Bouton **✓ Acknowledge** → `escalations.resolve()` + archivage auto si plus d'escalades pour la VM
- Bouton **📋 Command** → commande CLI à exécuter (éphémère)
- Bouton **🔄 Restore** → exécute `glorfindel restore <rid> --yes` (`restore_from_backup`, `low_confidence`)
- Bouton **↩️ Revert** → exécute `glorfindel reset <rid> --yes` (`verification_failed`) = reset complet (isolation + blocs IP)
- `/pending` slash command → liste des escalades en attente
- `DISCORD_PING_ROLE` → ping `@rôle` à l'ouverture d'un fil
- `bot_posted.json` + `bot_threads.json` : persistance entre redémarrages (pas de doublons, même fil)
- Si `DISCORD_BOT_TOKEN` set → webhook escalade supprimé (le bot gère dans les fils)
- Thread supprimé sur Discord → bot recrée automatiquement (NotFound handling)

---

## Prochaines priorités (voir ROADMAP.md pour détail complet)

0. **Isolation compatible IaC** — isolation JIT par NSG de quarantaine livrée et validée (06/10, `docs/design/module-isolation-iac.md`) ; reste L6 (écran d'activation, la brique `check_permissions` existe) et L8 (module renfort optionnel). **Dépendance couverte** : le JIT repose sur un comportement mesuré d'azurerm (4.81.0) → `make canary-jit` (`infra/canary/jit-terraform/run.sh`, pile jetable ~5 min, ressources gratuites) le revérifie sur la dernière version du provider, et `.github/workflows/canary-azurerm.yml` chaque lundi (si les secrets Azure du dépôt sont configurés). Premier passage le 07/10 : PASS. Depuis la troisième passe : contrainte de version paramétrée (`AZURERM_CONSTRAINT`), code de sortie de l'`apply` vérifié, workflow **quotidien** en matrice 3.x / 4.x / 5.x et **rouge sans secrets** ; joué le 07/10 : **PASS sur azurerm 3.117.1 et 5.8.0**.
1. **Utilisateur extérieur** — avant tout nouveau scénario ou provider
2. **glorfindel check-ttl en cron** — crontab ou systemd timer
3. **Entra ID / Service Principal** — vecteur #1 Azure 2025, `revoke_service_principal`
4. **Tests + scénarios MITRE** — T1068, T1528, T1078, T1190
5. **Schéma normalisé `first_result_row`** — prérequis tous connecteurs
6. **AWS provider** — `AwsConnector` + CloudWatch/GuardDuty
7. **Prometheus + Loki** — stack open source dominante

## Boucle purple team — implémentée

**Détection manquée (réactif) :**
```
Annatar attaque → detection_timeout
  → thread daemon (_wait_and_emit_feedback) poll runs/<run_id>_debug.jsonl
  → émet detection_missed {TTP, detection.hints, failed_query, source}
  → Glorfindel: propose_detection_rule node
  → 2 gates AVANT l'autoring (déterministes, zéro LLM) :
      (a) RulePoller a matché ce TTP récemment → faux négatif du watcher Annatar → skip
      (b) une règle couvre DÉJÀ ce TTP (detection_rules.yaml) → PAS de proposition :
          le raté n'est pas un manque de règle mais une détection EMPÊCHÉE
          (isolation résiduelle qui coupe l'AMA/l'egress, latence d'ingestion, backend KO)
          → escalade `detection_blocked` (action `investigate_detection_gap`) qui pointe
            posture/latence/backend. Constat 1er run e2e campagne (20260730T193824Z) :
            2 ratés d'origine infra → 2 règles doublon autorées (T1110, T1041) = bruit.
  → sinon (cold-start, TTP non couvert) → detection_authoring.author_rule (LLM grounded)
  → grounding : catalogue (table/colonnes) + getschema (schéma RÉEL du LAW au runtime)
  → ~/.glorfindel/proposed_rules.jsonl + escalation proposed_rule
  → glorfindel pending / War Room ⚙ → Approve
  → glorfindel approve-rule <id> → detection_rules.yaml
  → restart watch → règle active au prochain run
```

**Autoring proactif (cold-start) — `glorfindel propose-rules` :**
```
glorfindel propose-rules [--include-planned]
  → lit technique_catalog.yaml, skip les TTPs déjà couverts
  → pour chaque technique non couverte : getschema sur le vrai LAW → author_rule (LLM grounded)
  → propositions (pending / War Room) → approve-rule
  → génère la détection AVANT l'attaque (pas besoin d'un raté). Validé Azure réel (T1070.002).
```
**Deux couches anti-hallucination** : le catalogue (quelle table/colonnes) + getschema (colonnes
RÉELLES → le LLM n'invente pas de colonne). Invariant : sortie = proposition, RulePoller déterministe
inchangé, zéro LLM sur le hot-path. Le rejeu auto-activé en sandbox (étape 5) reste à venir (dépend
de l'exécuteur de campagne Annatar — voir collab/design_campaign_manifest.md).

**Remédiation non prête :**
```
glorfindel audit --all (ou watch startup)
  → AuditCheck par action: NSG (isolate_vm/block), backup (restore), compute (snapshot)
  → status: ok / warn (backup > 48h) / fail (IAM gap ou config manquante)
  → fix: commande az exacte pour corriger le trou
  → War Room ⚙ → section Remediation readiness par ressource
```

**Deux asymétries intentionnelles :**
- Réaction = LLM libre + RAG ChromaDB — apprentissage implicite, continu, aucune règle
- Détection = règles explicites (`detection_rules.yaml`) — source de vérité, query language = fonction du `source`.
  Les règles sont désormais **autorées par le LLM** (réactif sur raté + proactif `propose-rules`),
  groundées sur le catalogue + le schéma réel — mais restent des **propositions** ratifiées, exécutées
  par le `RulePoller` **déterministe**. Génératif à l'autoring, déterministe au runtime.
- Audit = vérification IAM + infra — détecte les trous *avant* l'incident

## Conventions scénarios Annatar

```yaml
# Structure minimale après refactoring :
detection:
  timeout: "300s"       # Annatar feedback watcher
  time_max: "180s"      # SLA déclaré (optionnel)
  prerequisites:        # ce qu'il faut vérifier avant de lancer
    - name: ...
      why: ...
      verify: "KQL ou commande az"
  hints:                # contexte pour propose_detection_rule
    log_source: Perf
    attack_commands_summary: >
      ...
    expected_indicators: [...]
    failure_candidates: [...]
```

Supprimés des scénarios : `cleanup`, `recovery`, `source`, `workspace_id`, `query` (tout dans Glorfindel).

---

## Ce qu'on ne fait PAS

- Pas compliance-oriented (NIS2, DORA)
- Pas d'agent en roue libre sur actions destructives
- Pas de tests sur infra prod sans consentement explicite
- Pas de dashboard monitoring — ce n'est pas le rôle de Glorfindel
- Pas de fine-tuning LLM — RAG ChromaDB suffit
- Pas de multi-cloud avant que la boucle Azure soit solide
- Pas de SaaS avant utilisateurs réels
