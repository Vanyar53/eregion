# Eregion — Roadmap & Priorités

## Objectif premier

Eregion est d'abord un projet **personnel** : un terrain pour apprendre l'IA et les LLM en profondeur — raisonnement agentique, RAG, génération grounded, évaluation — sur un usage de défense cloud dont j'ai réellement besoin. **Le plaisir de le construire et ce que j'y apprends priment sur l'adoption externe.**

Le pari assumé : la sécurité va vers la **réponse autonome** (vitesse machine des attaques → réponse machine), et Eregion explore cet espace sans le brider — mais sous contrôle (observe-only par défaut, garde-fous déterministes, tout produit LLM reste une proposition).

**Tout ce qui suit sur le positionnement produit, la concurrence et le SaaS est un scénario _optionnel_** — la voie « et si j'en faisais un produit ». Utile à garder en tête, ce n'est pas le juge de valeur du projet. Ne pas lire « pas d'utilisateur externe » comme un échec : ce n'est pas l'objectif poursuivi activement.

---

## Contexte produit (scénario optionnel)
Eregion est un CDR — Cloud Detection and Response. Détecte, répond et apprend — sans playbooks, sans équipe SOC dédiée.
Pitch : "Teste ton infra avant que les autres le fassent pour toi."
**RTO mesuré : < 25 min sur ransomware VM** — de la détection à la remise en service, sans intervention humaine sur le chemin critique (run 20260609T190824Z : 21m29s).
Cible : DevOps leads mid-market (50-500 personnes), pas de SOC dédié, <$500/mois acceptable.
Modèle : CLI open source gratuit, SaaS payant pour multi-tenant + connecteurs avancés + reporting.

---

## État actuel (v0.2.0)
- 6 TTPs validés en réel sur Azure : T1486, T1041, T1110.001, T1548.003, T1110+T1548 (parallèle), T1136.001
- Run parallèle multi-signal validé avec IncidentRegistry + propagation investigative_context entre cycles
- **✅ Isolation multi-NIC validée sur Azure réel** (2026-06-25, topo Celebrimbor `multinic`, PASS 7/7) — isolate couvre **les 2 NICs/2 NSG**, `verify_isolation` détecte `uncovered_nics` si une NIC manque. Le trou de sécurité terrain (2e NIC joignable malgré ISOLATED) est fermé et **vérifié** (plus mocké). Correctif `7603a3e`.
- **Purple loop end-to-end validé** (commit 9a64e83) — `detection_missed → propose_detection_rule → approve-rule → detection_rules.yaml → restart watch → détection réussie ~78s`. Scénario T1136.001 (account creation) créé pour ce test.
- **Boucle purple générative livrée** (PR #1) — côté rouge : Annatar `campaign plan/run` (planner compose une kill-chain depuis `technique_catalog.yaml`, LLM optionnel via `--llm`, défaut déterministe ; synthesizer matérialise des scénarios rejouables ; runner séquentiel budgété + scope guard). Côté bleu : `detection_authoring.py` (autoring grounded — catalogue + `getschema` du vrai LAW), `glorfindel propose-rules` (proactif cold-start), `campaign_replay.py` (auto-activation + rejeu). Invariant préservé : tout produit LLM reste une **proposition**, le RulePoller reste déterministe au runtime.
- 459 tests, 0 appel Azure, 0 appel LLM
- **🎯 Premier vrai incident** (2026-06-14) — Glorfindel a détecté un **vrai brute force SSH internet** (IP `95.47.246.223`, 26 FailedAttempts) sur la sandbox, hors boucle Annatar. En `human_only` → escalade `mode_hold` recommandant `block_suspicious_ip`. `investigate` a qualifié (auth échouée → block, pas isolate). Le pipeline tient sur du trafic adverse authentique — et a débusqué un bug (escalade sans IP) qu'aucun run scénarisé n'avait trouvé.
- **War Room posture + opérabilité** (~50 commits 12-14 juin) — bandeau INFRASTRUCTURE 2 axes (credentials OBSERVE-ONLY↔ACTIVE + autonomy human-only/non-disruptive), dropdown mode global + badge par carte + popover capacité, grisage read-only préventif, badge VM OFFLINE, Approve & execute paramétré (`block_suspicious_ip` 1-clic). Bugs cross-cutting débusqués via l'UI (race import Azure SDK → `warm_up_azure_sdk`, mode invisible sur VM connue par escalade, VM éteinte = disparition).
- **Hot-pickup mode** (commit b7af4cc) — `decide` recharge la config fraîche par cycle ; `watch --mode` épinglé session par-dessus config ; `resolve()` = exact > wildcard le plus long > défaut. Dropdown War Room sans restart.
- **Few-shot T1136.001** (commit b36a5a7) — ancre "T1136.001 ≠ isolate_vm", confidence 0.35 → escalade + suggested_steps forensiques. Gate T1136.001 PASSED ✅ (41s, snapshot + escalade).
- **Fix past_cycles ChromaDB** (commit 740659a) — bug critique : LLM inférait état isolation depuis ChromaDB past_cycles → sautait cycle 1 → restore direct → ransomware actif. Fix : `current_vm_state` injecté dans le prompt avant past_cycles + CRITICAL warning. Gate T1486 PASSED ✅ (run 20260609T190824Z, RTO 21m29s).
- **`expected_latency_s` par règle** (commit dd48b12) — timeout adaptatif `poll_detection` : `max(expected_latency_s, signal.detection_timeout_s)`. Couvre les spikes d'ingestion LAW > P50.
- **jobs.py** (commit 10ae917) — backend partagé CLI/War Room : `~/.glorfindel/active_jobs/<vm>.json`, `snapshot/restore --wait`, `glorfindel jobs <vm>`, `/api/jobs/<vm>`
- **Modes d'autonomie par asset** (commits 9154fc6, 364d466, ac392ac, 6122db0) — `human_only` (défaut) / `non_disruptive` / `full_auto` différé. Résolution fnmatch par asset. Couche politique post-decide, escalade `mode_hold`. Mode observe-only (`GLORFINDEL_READ_ONLY=1`) sur SP Reader — War Room UI livrée (badges, sélecteur, Approve & execute).
- **`snapshot()` fire-and-forget** sur `detection_timeout` — `wait=False`, `verify_snapshot()` tolère "InProgress"
- **Few-shot T1486 corrigé** (commit c6fe0d0) — bug sécurité : LLM sautait l'isolation, ransomware restait actif 20min. Flow corrigé : cycle 1 `isolate_vm` autonome, cycle 2 `restore_from_backup` escaladé
- **War Room BACKUP** : section visible sur chaque carte VM, bouton 📸 Snapshot (fire-and-forget RSV)
- **Stabilité War Room** : registry stale corrigé (lecture fraîche JSON), release isolation robuste, subprocess non-bloquant
- `glorfindel snapshot` (on-demand RSV) + `annatar clean` (nettoyage disque seul, remplace annatar snapshot)
- Support multi-provider LLM via LiteLLM : Anthropic (défaut), OpenAI, Azure OpenAI, Ollama, self-hosted
- **Prompt caching** activé sur system prompt (~400 lignes) — -60-80% tokens input
- **Confidence gate** : LLM confidence < 0.7 → escalade forcée même sur action autonome
- **Signal normalisé** (`normalize_row`) — indicateur sémantique uniforme entre toutes les règles KQL
- `gf pending` avec next steps contextuels générés par le LLM (ChromaDB history)
- Alerting webhook sur décisions autonomes + escalades (Slack/Teams/Discord)
- **Bot Discord interactif** : un fil par VM, boutons ✓ Acknowledge / 📋 Command / 🔄 Restore / ↩️ Revert — exécutent les commandes Glorfindel directement depuis Discord
- **War Room web** (`glorfindel war-room`, `make glorfindel-start`) — incident cards, live feed WebSocket, action buttons, infra map avec posture gaps
- **Annatar block watcher** — émet `attack_adapted` si Glorfindel bloque une IP en cours de run
- Repo public : https://github.com/Vanyar53/eregion
- Coût exploitation : <$2/mois LLM API sur infra existante

---

## La kill chain Azure — où sont les VMs

Les VMs sont rarement la cible finale. Elles sont le point d'entrée ou le pivot :

```
Entra ID compromis → VM (pivot) → Storage / Key Vault (objectif final)
```

Eregion couvre aujourd'hui le milieu de la kill chain. La roadmap ressources étend la couverture vers l'entrée (Entra ID) et la sortie (Key Vault, Storage).

---

## Phase 1 — Validation utilisateur externe (scénario optionnel)
**Objectif : prouver que quelqu'un d'autre peut l'utiliser — pertinent uniquement si la voie produit est poursuivie.**

- [ ] Premier utilisateur externe sur son infra Azure
- [ ] Collecter feedback brut — ce qui casse, ce qui manque, ce qui surprend

> Ce jalon n'est **plus le bloquant** du projet (voir _Objectif premier_). Il reste la meilleure porte d'entrée si un jour l'ambition produit prend le dessus — pas une dette.

---

## Phase 2 — Solidification (après premier utilisateur)
**Objectif : robustesse hors contexte auteur.**

- [~] **Modes d'autonomie granulaires par asset** — backend livré 2026-06-10 (`9154fc6`/`364d466` volet 1 ; `ac392ac`/`6122db0` volet 2 read-only). UI War Room + gate Tests (2 runs + run read-only) à venir. `human_only` (défaut), `non_disruptive` (actuel), `full_auto` (différé, refusé par la validation). Résolution par asset (asset > tag > défaut global), config section `autonomy`, `allow_destructive` séparé. Escalier de confiance : observe → réagit quand l'utilisateur a confiance. Débloque l'adoption externe — le persona sans SOC craint l'action réversible mais disruptive (`isolate_vm`) en autonome sur un faux positif, pas le restore (déjà gated). **`human_only` tourne sur credentials read-only** = on-ramp du premier test externe (lecture seule sur le LAW du pair, zéro risque). Défaut `human_only` = première expérience sûre.
- [~] **Gate portabilité LLM — valide la clé « maîtrise des données »** (même priorité que le test terrain). Toute la validation (few-shots, 5 TTPs, terrain) est calibrée sur **Claude**. La promesse souveraineté/self-hosted (Ollama, Mistral) est **non prouvée** : un modèle local peut choisir la mauvaise action, mal calibrer la confidence (gate inopérant), ou sortir un JSON malformé. LiteLLM fait *tourner* partout, pas *raisonner* aussi bien partout. **Sans ce gate, la 3e clé du positionnement est aspirationnelle.**
  - **Fait (2026-07)** : harnais `scripts/llm_smoke.py` + `make llm-compare` — score *integration* (tool-call valide parsé), *judgment* (agir sur menace claire, escalader sur ambigu) **et calibration** (erreurs surconfiantes = faux + confidence ≥ 0.7, que le gate ne peut pas rattraper) sur un **vrai** provider, 0 Azure. Comparatif 6 modèles Ollama × 3 runs sur 8 cas (5 TTPs + 3 pièges ambigus/sous-seuil) : `qwen2.5` 20/24, `gemma4` 19/24, `command-r7b` 18/24, `qwen3`/`gemma3` 17/24, **`qwen3.5` 0/24 (aucun tool-call — inutilisable)**. A trouvé 2 bugs sécurité réels (string-bool truthy, champ omis → crash) → parsing défensif de `decide`.
  - **Finding calibration (2026-07)** : sur un signal **caractérisé mais sous le seuil** (écriture disque 5 MB/s = 149× sous le vrai ransomware ; `sudo apt-get update`), **tous** les modèles locaux sur-agissent (isolent la VM) **avec une confiance plus haute quand ils ont tort** (`conf|wrong` ≈ 0.90–0.98 > `conf|correct` ≈ 0.79–0.87). Le mode d'échec passe **entre les deux gardes** : le garde-fou signal-non-caractérisé ne fire pas (le signal *est* caractérisé), le gate de confiance non plus (le modèle est confiant). Blast radius borné par design (action `isolate_vm` réversible + gate destructive + défaut `human_only`), **pas** par la confiance du modèle → confirme empiriquement pourquoi la sûreté ne se délègue jamais à la confidence LLM. **Axe de durcissement** : garde-fous sensibles à la magnitude (seuils par indicateur) ou contexte `investigate` systématiquement injecté avant `decide`.
  - **Reste** : le harnais score des **signaux fixes**, pas le rejeu bout-en-bout. Rejouer les 5 TTPs complets (détection → decide → verify) par modèle vs la référence Claude, produire le **tableau de capacité par modèle**.
  - **Protocole** : rejouer les TTPs validés (T1486/T1041/T1110/T1548/T1136) par modèle, comparer **action choisie + confidence + validité du tool-call JSON** vs la référence Claude. Produire un **tableau de capacité par modèle** = doc de souveraineté assumée (ce que l'acheteur obtient selon son curseur).
  - **Ordre** : (1) **Mistral Large** (cloud EU — souverain sans air-gap, capable, quick win + narratif EU) ; (2) **Mistral open-weight / Ollama** (self-hosted, souveraineté max, risque qualité le plus haut → mesurer où le raisonnement casse).
  - **Attendu** : re-tuning probable des few-shots / system prompt par modèle (travail réel, pas un flag). Notifié Tests.
- [ ] `glorfindel check-ttl` en cron — crontab ou systemd timer
- [ ] Gestion d'erreur documentée — Azure Monitor en retard, NSG apply échoué, restore timeout
- [ ] `glorfindel list --live` — détecter règles NSG orphelines
- [ ] Deuxième type de ressource testé (voir Phase 3 ressources)

---

## Phase 3 — Extension ressources Azure (priorité kill chain)

### Ordre basé sur les vecteurs d'attaque réels Azure 2025

| Priorité | Ressource | Position kill chain | Nouvelles actions | Complexité |
|---|---|---|---|---|
| 0 | **Azure Activity Logs** (`AzureActivity`) | Contrôle-plan | detection-only (escalade) | Très faible |
| 1 | **Entra ID / Service Principal** | Entrée | detection-only MVP, puis `revoke_service_principal` | Moyenne |
| 2 | **Storage Account** (misconfiguration) | Objectif | `lock_storage_public_access` | Faible |
| 3 | **Key Vault** | Objectif final | `revoke_keyvault_access` | Faible |
| 4 | **AKS** | Pivot avancé | `isolate_namespace`, `cordon_node` | Haute |
| 5 | **App Service / Function App** | Entrée exposée | `isolate_app_service` | Moyenne |

**Azure Activity Logs en premier (P0)** : déjà dans LAW par défaut, zéro permission supplémentaire, une journée de travail. Couvre les modifications NSG externes, assignations de rôles, snapshots créés par un attaquant — TTPs T1098, T1562, lateral movement contrôle-plan.

**Entra ID — detection-only pour le MVP** : pas d'action autonome sur l'identité (faux positif trop coûteux — désactiver un admin légitime). Détecter → escalader humain + suggested_steps. Action autonome après validation sur signaux réels. Prérequis : permission `Security Reader` Entra ID sur le SP Glorfindel.

**Storage et Key Vault avant AKS** : actions simples, impact élevé, faible complexité. AKS demande une nouvelle catégorie d'actions (namespace/node) — c'est un chantier à part entière.

### TTPs associés par ressource

```
Entra ID     → T1528 (steal app token), T1098 (account manipulation)
Storage      → T1530 (data from cloud storage), T1537 (transfer to cloud account)
Key Vault    → T1555 (credentials from stores), T1552 (unsecured credentials)
AKS          → T1610 (deploy container), T1613 (container discovery)
App Service  → T1190 (exploit public-facing), T1078 (valid accounts)
```

### Prérequis transversal — surveillance comportement LLM (avant scaling utilisateurs)

Pattern observé sur 3 bugs critiques de sécurité (c6fe0d0, b36a5a7, 740659a) : LLM confond contexte historique avec état courant. Chaque source de contexte injectée dans le prompt (few-shot, ChromaDB past_cycles, investigative_context) est un vecteur potentiel de dérive.

La gate "re-run end-to-end avant déploiement" protège au moment du déploiement — mais pas dans la durée. À mesure que ChromaDB accumule des cycles (usage prod sur plusieurs semaines), les past_cycles créeront des contextes que le sandbox de test ne reproduit pas.

À implémenter avant d'atteindre 5+ utilisateurs actifs :
- [ ] Monitoring des décisions LLM en prod — détecter les dérives (action inhabituelle pour un TTP donné, confidence anormalement haute sans signal fort)
- [ ] Alerting sur actions autonomes inattendues — `isolate_vm` décidé sans `MaxWrite` ni `USER=root` → flag pour revue humaine

---

## Phase 4 — Extension connecteurs (priorité marché)

### Prérequis absolu : schéma normalisé `first_result_row`

Avant tout nouveau connecteur. Sans ça chaque connecteur retourne un format différent
et le LLM se comporte de façon incohérente selon la source.

```python
# Schéma cible normalisé
{
    "source_ip": "...",      # CallerIpAddress (Azure), src_ip (Prometheus), network.client.ip (Datadog)
    "resource_id": "...",    # resource_id (Azure), instance label (Prometheus), host (Datadog)
    "alert_name": "...",     # signal type
    "severity": "...",       # critical/high/medium/low
    "raw": {}                # payload brut pour le LLM si besoin
}
```

- [x] Définir le schéma normalisé (`normalize_row()` implémenté — indicateur sémantique uniforme)
- [x] Migrer `AzureMonitorDetector` vers ce schéma (appliqué à la sortie du poll)
- [ ] Documenter le mapping dans `CONTRIBUTING.md`

### Ordre connecteurs — basé sur adoption marché

**1. AWS + CloudWatch/GuardDuty — 32% marché cloud**
```python
class AwsConnector(CloudConnector):
    def isolate_vm(self, resource_id) -> dict:
        # Security Group deny-all
    def block_suspicious_ip(self, ip, resource_id) -> dict:
        # Security Group inbound rule
    def snapshot(self, resource_id) -> str:
        # EBS snapshot

class CloudWatchDetector(DetectionConnector):
    def poll_alert(self) -> tuple[float, dict] | None:
        # CloudWatch Alarms ou GuardDuty Findings (mappe bien MITRE ATT&CK)
```

**2. Prometheus + Alertmanager + Loki — stack open source dominante**

Deux connecteurs séparés — même séparation qu'Azure Monitor (métriques) vs Syslog DCR (logs) :
- `PrometheusDetector` — Alertmanager REST API `/api/v2/alerts` — T1486, T1041
- `LokiDetector` — Loki query API LogQL — T1110.001, T1548.003

Note : Alertmanager supporte les webhooks — option push si poll insuffisant.

**3. Datadog — leader monitoring commercial mid-market**
```python
class DatadogDetector(DetectionConnector):
    def poll_alert(self) -> tuple[float, dict] | None:
        # Events API v2 ou Monitors API
        # network.client.ip → source_ip dans schéma normalisé
```

**4. GCP — 11% marché cloud, croissance forte**
- `GcpConnector` — VPC Firewall Rules + Disk snapshots
- `SecurityCommandCenterDetector` — SCC Findings

---

## Phase 5 — Nouveaux scénarios TTP

| Priorité | TTP | Scénario | Action | Note |
|---|---|---|---|---|
| 1 | T1068 | Kernel privilege escalation | `isolate_vm` | Complément T1548 |
| 2 | T1528 | Steal app access token (Entra) | `revoke_service_principal` | Nouveau type ressource |
| 3 | T1078 | Valid accounts / credential abuse | `revoke_temp_access` | Déjà dans AUTONOMOUS |
| 4 | T1190 | Exploit public-facing application | `isolate_app_service` | Nouveau type ressource |
| 5 | T1562 | Impair defenses (disable logging) | `snapshot` + escalade | Détection complexe |

---

## Phase 6 — War Room UI ✅ Livré

**Accessible sur `http://localhost:7007`** via `make glorfindel-start` ou `glorfindel war-room`.

**Ce qui est livré :**
- Infra map avec 4 zones (network, monitoring, compute, backup) + connexions SVG dynamiques
- VM cards expandables (compact + étendu), état (ok/isolated/blocked), LLM reasoning cliquable
- Boutons Release/Unblock/Reset/Restore par VM
- **Section BACKUP** par carte : recovery point count, âge dernier backup, bouton 📸 Snapshot (fire-and-forget RSV)
- Live feed WebSocket avec reconnect automatique
- Posture gaps par VM (NSG, backup, IAM) — avec commande `az` exacte pour corriger
- Règles de détection cliquables (modal avec query KQL complète + polling status)
- Config panel : Azure credentials + LLM + mode autonomie global
- `make glorfindel-dev` — auto-reload sur modification de `index.html` (volume mount)
- Registry stale corrigé : lecture fraîche `discovered_assets.json` à chaque appel API
- Release isolation robuste : `_clear_isolation_state` inconditionnel + subprocess asyncio non-bloquant
- **Posture/observe-only UI** (12-14 juin) : bandeau INFRASTRUCTURE 2 axes (credentials OBSERVE-ONLY↔ACTIVE + autonomy), dropdown mode global + badge par carte cliquable + popover capacité, grisage read-only préventif, badge VM OFFLINE (rétention 8h), Approve & execute paramétré
- **Purple loop visible en UI** : escalades `proposed_rule` affichées, approbation règle en 1-clic depuis ⚙

**Prochaine itération (après feedback premier utilisateur) :**
- [ ] Confidence score visible dans les VM cards
- [ ] Historique des actions par VM (timeline)
- [ ] Lancement de scénario Annatar depuis la War Room

---

## Phase 7 — SaaS MVP

**Prérequis : 5+ utilisateurs externes actifs.**

### Ce qui change architecturalement

```
Aujourd'hui                    SaaS
───────────────────────────────────────────────
~/.glorfindel/              →  state côté serveur (PostgreSQL)
ChromaDB local              →  vectorDB multi-tenant (Pinecone / Weaviate)
CLI autonome                →  CLI thin client + API REST backend
LangGraph local             →  LangGraph côté serveur
War Room local              →  War Room SaaS multi-tenant
```

### Modèle open-core
- **Gratuit** : CLI + scénarios de base + connecteurs Azure/AWS/Prometheus
- **Payant SaaS** : multi-tenant, RAG partagée, War Room hébergée, connecteurs avancés, reporting, support

### Pricing indicatif
- $200-500/mois par workspace
- <$2/mois LLM API par workspace (Anthropic défaut) — marge confortable
- Comparable PagerDuty (~$200/mois), Datadog (~$200/mois)

### Ce qu'on ne fait PAS en SaaS MVP
- Pas de dashboard monitoring — c'est Grafana/Datadog
- Pas de white-label
- Pas d'on-premise avant demande explicite

---

## Récapitulatif ordre de priorité global

```
1. Premier utilisateur externe              → MAINTENANT, bloque tout
2. Solidification (erreurs, cron)           → après feedback
3. Entra ID / Service Principal             → vecteur #1 Azure 2025
4. Storage misconfiguration + Key Vault     → objectifs finaux kill chain
5. Schéma normalisé first_result_row        → prérequis connecteurs
6. AWS + CloudWatch/GuardDuty               → 32% marché cloud
7. Prometheus + Loki                        → stack open source dominante
8. War Room UI                              → ✅ livré (http://localhost:7007)
9. Datadog                                  → leader commercial mid-market
10. AKS                                     → chantier complexe, après les autres
11. Nouveaux scénarios TTP                  → selon demande utilisateurs
12. GCP                                     → croissance forte, pas urgent
13. SaaS MVP                                → après 5 utilisateurs externes
```

---

## Paysage concurrentiel CDR

### Acteurs établis
| Acteur | Position | Réalité face à Eregion |
|--------|----------|------------------------|
| **Microsoft Defender for Cloud + Sentinel + Security Copilot** | CDR natif Azure + automation + LLM | **Menace existentielle** pour un outil Azure-first : natif, intégré, bundlable quasi-gratuitement. On ne gagne pas en capacité — on gagne en OSS / souveraineté / accessibilité mid-market. |
| **Darktrace** (Thoma Bravo, 2024) | Behavioral ML + réponse autonome (Antigena) | Fait la réponse autonome depuis des années. **Boîte noire, enterprise, cher.** Contre-position : transparent/auditable + self-hostable, pas « plus autonome ». |
| **Wiz** (post-Gem ~$350M, 2024) / **Palo Alto Prisma** / **CrowdStrike** | CNAPP / EDR enterprise | $50–100k+/an, nécessitent une équipe pour opérer. Overkill et inopérable pour un mid-market sans SOC. |
| **Skyhawk Security** | Startup ~2022, VC-backed | Simulation + behavioral ML. À surveiller. |

### Le moat réel d'Eregion (recalibré 2026-06)
La réponse autonome et le raisonnement LLM sont devenus **table stakes** — les incumbents les ont tous (Darktrace Antigena, MS Security Copilot, CrowdStrike Charlotte…). **On ne rivalise PAS sur la capacité.** La position défendable :
- **OSS + self-hostable** (LLM local via Ollama) — aucun gros acteur ne l'est. Souveraineté / air-gap / data EU.
- **Transparence / auditabilité** — code ouvert, chaque décision lisible (`pending`, escalades, raisonnement loggé). Anti-boîte-noire ML.
- **Opérable par une équipe sans SOC** — là où Darktrace / Wiz / MS exigent expertise + budget.
- Le pari : pas « meilleur CDR », mais **« le CDR qu'une petite équipe Azure peut faire tourner gratuitement, sans envoyer ses données à un vendeur, et dont elle voit chaque décision »**.

### Précédents d'acquisition
- **Gem Security → Wiz** (~$350M, 2024) — CDR standalone acheté plutôt que construit. Valide la catégorie.
- **Lacework → Fortinet** (2023) — CDR behavioral ML. Les CNAPP/enterprise players achètent de la CDR.
- Pattern : les CNAPP giants rachètent le CDR plutôt que de le construire.

### Scénarios Eregion
1. **Business OSS mid-market** — niche Azure/souveraine défendue, 200-500 clients × $200-500/mois. Scénario le plus réaliste vu le moat OSS/transparence.
2. **Acquisition** — 10-20 utilisateurs + différenciation claire → acteur EU souverain (Orange Cyberdefense, Thales) ou CNAPP voulant la couche transparente/mid-market.
3. **Trop tard** — terrain occupé avant traction externe. **Risque dominant aujourd'hui.**

**Ce qui détermine le scénario : un premier utilisateur externe — non encore acquis.** La fenêtre estimée (12-18 mois, mi-2025) se referme ; chaque mois de durcissement interne sans adoption tierce rapproche du scénario 3.

---

## Ce qu'on ne fait PAS
- Pas compliance-oriented (NIS2, DORA)
- Pas d'agent en roue libre sur actions destructives
- Pas de tests sur infra prod sans consentement explicite
- Pas de dashboard monitoring — ce n'est pas le rôle de Glorfindel
- Pas de fine-tuning LLM — la RAG ChromaDB suffit pour le MVP
- Pas de multi-cloud avant que la boucle Azure soit solide
- Pas de SaaS avant utilisateurs réels

---

## Vision long terme

Eregion n'est pas un outil de sécurité supplémentaire — c'est la couche de raisonnement qui manquait au-dessus des outils existants. Les EDR, SIEM, NIDS continuent d'exister comme collecteurs de signaux. Eregion raisonne sur leurs sorties sans règles de corrélation explicites.

```
Court terme  : CDR Azure — détecter, répondre, apprendre sur un cloud
Moyen terme  : CDR multi-cloud + posture (CSPM lite) — AWS, GCP, Prometheus
Long terme   : raisonnement unifié cross-sources — endpoint, réseau, cloud, identité
```

La catégorie CDR (Cloud Detection and Response) est émergente chez Gartner (intégrée dans CNAPP). C'est là qu'Eregion se positionne — sans la complexité playbook des SOAR, sans le scope limité des EDR cloud-natifs.
