# Eregion — Roadmap & Priorités

## Contexte produit
Eregion est un SOAR IA open-core. Pas de playbooks — Glorfindel raisonne depuis le contexte du signal.
Pitch : "Teste ton infra avant que les autres le fassent pour toi."
Cible : DevOps leads mid-market (50-500 personnes), pas de SOC dédié, <$500/mois acceptable.
Modèle : CLI open source gratuit, SaaS payant pour multi-tenant + connecteurs avancés + reporting.

---

## État actuel (v0.2.0)
- 5 TTPs validés en réel sur Azure : T1486, T1041, T1110.001, T1548.003 + run parallèle T1110+T1548
- Run parallèle multi-signal validé avec IncidentRegistry
- 88 tests, 0 appel Azure, 0 appel LLM
- Support multi-provider LLM via LiteLLM : Anthropic (défaut), OpenAI, Azure OpenAI, Ollama, self-hosted
- `gf pending` avec next steps contextuels générés par le LLM (ChromaDB history)
- Alerting webhook sur décisions autonomes + escalades
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

## Phase 1 — Validation utilisateur (MAINTENANT)
**Objectif : prouver que quelqu'un d'autre peut l'utiliser.**

- [ ] Premier utilisateur externe sur son infra Azure
- [ ] Collecter feedback brut — ce qui casse, ce qui manque, ce qui surprend
- [ ] Ne rien construire de nouveau avant ce retour

**Rien d'autre ne passe avant ça.**

---

## Phase 2 — Solidification (après premier utilisateur)
**Objectif : robustesse hors contexte auteur.**

- [ ] `glorfindel check-ttl` en cron — crontab ou systemd timer
- [ ] Gestion d'erreur documentée — Azure Monitor en retard, NSG apply échoué, restore timeout
- [ ] `glorfindel list --live` — détecter règles NSG orphelines
- [ ] Deuxième type de ressource testé (voir Phase 3 ressources)

---

## Phase 3 — Extension ressources Azure (priorité kill chain)

### Ordre basé sur les vecteurs d'attaque réels Azure 2025

| Priorité | Ressource | Position kill chain | Nouvelles actions | Complexité |
|---|---|---|---|---|
| 1 | **Entra ID / Service Principal** | Entrée | `revoke_service_principal` | Moyenne |
| 2 | **Storage Account** (misconfiguration) | Objectif | `lock_storage_public_access` | Faible |
| 3 | **Key Vault** | Objectif final | `revoke_keyvault_access` | Faible |
| 4 | **AKS** | Pivot avancé | `isolate_namespace`, `cordon_node` | Haute |
| 5 | **App Service / Function App** | Entrée exposée | `isolate_app_service` | Moyenne |

**Entra ID en premier** : 87% de surge des campagnes destructives Azure en 2025 via tokens volés et workload identities compromises. `revoke_temp_access` existe déjà — extension naturelle vers `revoke_service_principal`.

**Storage et Key Vault avant AKS** : actions simples, impact élevé, faible complexité. AKS demande une nouvelle catégorie d'actions (namespace/node) — c'est un chantier à part entière.

### TTPs associés par ressource

```
Entra ID     → T1528 (steal app token), T1098 (account manipulation)
Storage      → T1530 (data from cloud storage), T1537 (transfer to cloud account)
Key Vault    → T1555 (credentials from stores), T1552 (unsecured credentials)
AKS          → T1610 (deploy container), T1613 (container discovery)
App Service  → T1190 (exploit public-facing), T1078 (valid accounts)
```

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

- [ ] Définir le schéma normalisé
- [ ] Migrer `AzureMonitorDetector` vers ce schéma
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

## Phase 6 — War Room UI

**Pourquoi maintenant et pas au SaaS :**
- Réduit la friction pour le premier utilisateur externe — un clic au lieu de 3 terminaux
- Démontre la valeur en temps réel sans que l'utilisateur comprenne le CLI
- C'est une interface sur ce qui existe déjà — pas de nouveau backend

**Ce que c'est :**
```
┌──────────────────────────────────────────────┐
│ EREGION — War Room                           │
├────────────────┬─────────────────────────────┤
│ Scénarios      │ Run en cours                │
│ T1486 ▶        │ 14:32:51 Detection (50s)    │
│ T1041 ▶        │ 14:32:53 isolate_vm ✓ ✓    │
├────────────────┤ Incidents actifs            │
│ vm-victim 🔴   │ ISOLATED  52m ago           │
│                │ → revert ?                  │
├────────────────┤ Escalades                   │
│                │ restore_from_backup ▶        │
└────────────────┴─────────────────────────────┘
```

**Stack :** FastAPI + WebSocket (temps réel) + React ou HTML/JS simple. Thin layer sur `glorfindel watch` + `glorfindel list` + `glorfindel pending`.

**Ce que ce n'est pas :** dashboard de monitoring permanent, configurateur de scénarios, Grafana.

- [ ] Après le premier utilisateur externe — son feedback dicte ce qui va dans l'interface
- [ ] API REST minimale sur les commandes CLI existantes
- [ ] WebSocket pour le feed temps réel du run

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
- <$2/mois Claude API par workspace — marge confortable
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
8. War Room UI                              → après feedback premier utilisateur
9. Datadog                                  → leader commercial mid-market
10. AKS                                     → chantier complexe, après les autres
11. Nouveaux scénarios TTP                  → selon demande utilisateurs
12. GCP                                     → croissance forte, pas urgent
13. SaaS MVP                                → après 5 utilisateurs externes
```

---

## Ce qu'on ne fait PAS
- Pas compliance-oriented (NIS2, DORA)
- Pas d'agent en roue libre sur actions destructives
- Pas de tests sur infra prod sans consentement explicite
- Pas de dashboard monitoring — ce n'est pas le rôle de Glorfindel
- Pas de fine-tuning LLM — la RAG ChromaDB suffit pour le MVP
- Pas de multi-cloud avant que la boucle Azure soit solide
- Pas de SaaS avant utilisateurs réels
