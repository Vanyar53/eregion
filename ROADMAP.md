# Roadmap — Eregion

> "Tu déclares un RTO de 4h. On te dit combien de temps ça prend vraiment — en simulant l'attaque, en mesurant détection + recovery, et en sortant le rapport pour ton auditeur."

> *"Annatar est déjà dans ta forteresse. La question c'est : est-ce que tu le sais ?"*

---

## Naming

**Plateforme : `Eregion`** — royaume des grands forgerons Elfes du Deuxième Âge. Là où les plus grandes choses ont été construites — et où Sauron trouva les failles.

| Module | Nom | Rôle |
|---|---|---|
| Chaos Engine | **Annatar** | Sauron déguisé en "Seigneur des Dons" — l'attaque qui vient de l'intérieur |
| DR Coverage Scanner | **Celebrimbor** | Le forgeron qui voit chaque faille dans chaque construction |
| Drift Monitor | **Thranduil** | Vigie sur la Forêt Noire pendant 3000 ans — surveillance continue |
| Reports Pro | **Gil-galad** | Documenta les avertissements que personne n'écouta — l'audit ignoré |
| War Room | **Fingolfin** | Défia Morgoth seul quand tout semblait perdu — la réponse ultime |
| Failover Canary | **Glorfindel** | Mourut, fut réincarné, revint plus fort — la recovery prouvée |

Domaines cibles : `eregion.dev` / `eregion.io`
Noms vérifiés disponibles : Eregion, Annatar, Celebrimbor, Thranduil, Gil-galad, Fingolfin, Glorfindel

---

## Vision

Eregion est une plateforme modulaire open-core couvrant le cycle complet de la résilience opérationnelle :

```
Auditer la couverture → Tester sous attaque → Surveiller la dérive → Exécuter en incident
```

Modèle : 2 modules open source (Apache 2.0) comme base de traction + modules SaaS payants construits dessus.

---

## Gap concurrentiel

| | BAS tools | DR/Backup tools | Cette plateforme |
|---|---|---|---|
| Simule l'attaque | Oui | Non | Oui |
| Mesure RTO réel | Non | Partiel | Oui |
| Rapport audit NIS2/DORA | Non | Non | Oui |
| Open-core accessible | Non | Non | Oui |

Objection principale : "Pourquoi pas Azure Chaos Studio ?" → Chaos Studio simule des pannes infra, pas des attaques. Pas de ransomware, pas de mesure RTO vs PRA.

---

## Architecture modulaire

### Open Source — Base (Apache 2.0)

#### Module 1 : SecurityChaos (chaos-engine)
**Statut : MVP 95% codé**

Simule des scénarios d'attaque réels sur l'infra Azure, mesure les temps de détection et de recovery, compare au RTO/RPO déclaré.

Scénarios MVP :
- `ransomware-vm` — chiffrement + détection Azure Monitor + restore backup
- `data-exfiltration` — transfert 1GB + détection NSG Flow Logs

Output : rapport JSON `PASS/FAIL` par seuil, avec métriques `detection_time_s` / `recovery_time_s`.

```bash
sechaos run scenarios/azure/ransomware-vm.yaml --dry-run
sechaos run scenarios/azure/ransomware-vm.yaml --yes
sechaos report <run-id>
```

Ce qui reste à faire pour le MVP :
- [ ] `terraform apply` — provisionner l'infra Azure de test
- [ ] Renseigner `log_analytics_workspace_id` dans les YAML
- [ ] Implémenter `_trigger_backup_restore` (placeholder actuel)
- [ ] Tests d'intégration
- [ ] README "utilisable en 30 min"

---

#### Module 2 : DR Coverage Scanner (dr-scanner)
**Statut : À construire (M+1)**

Scanne l'infra cloud et répond : *"pour chaque ressource critique, peux-tu vraiment récupérer, et en combien de temps ?"*

```
vm-web-prod          RPO actuel: 6h23    Déclaré: 1h    ⚠ BREACH
db-postgres-main     RPO actuel: 8min    Déclaré: 15min ✓
storage-docs         Aucun backup                       ✗ CRITIQUE
```

Fonctionnalités :
- Scan Azure Resource Graph (puis AWS Config, phase 2)
- RPO réel calculé par asset (âge du dernier backup)
- Détection des single points of failure
- Gap analysis NIS2/DORA basique
- Output JSON + rich terminal

---

### Modules SaaS payants — Futur

> À construire uniquement après traction sur les modules OSS.

| Module | Description | Déclencheur |
|---|---|---|
| **Drift Monitor** | Agent continu — alerte quand RTO/RPO réel dérive du déclaré | Premier revenu récurrent |
| **Reports Pro** | PDF audit NIS2/DORA formatés pour auditeurs | Marché compliance |
| **Canary Failover** | Tests automatiques hebdo des chemins de failover | Après feedback marché |
| **DR War Room** | Guidance d'incident, exécution PRA step-by-step | Après feedback marché |
| **Scenarios Pro** | Lateral movement, privilege escalation, etc. | Demande communauté |
| **Multi-cloud** | Support AWS + GCP | Après traction Azure |

---

## Phases

### Phase 1 — Maintenant
**Objectif : SecurityChaos MVP fonctionnel bout en bout**

- Finir les 5 items restants (voir Module 1 ci-dessus)
- GitHub public, Apache 2.0
- README : quelqu'un d'autre peut l'utiliser en 30 min
- Critère done : 2 scénarios Azure bout en bout, rapport JSON PASS/FAIL, `sechaos init` en < 5 min

### Phase 2 — M+1
**Objectif : DR Coverage Scanner OSS**

- Scan Azure Resource Graph
- RPO réel par asset
- Intégration dans la même CLI (`sechaos scan`)
- Démo "scanne ton Azure en 2 minutes, voici tes gaps"

### Phase 3 — M+2/M+3
**Objectif : Premier revenu récurrent**

- Drift Monitor en SaaS (agent continu)
- Ou Reports Pro PDF (selon retours marché)
- Premier client payant nommé

### Phase 4+ — Selon traction
- War Room, Canary Failover, Multi-cloud
- Décisions basées sur retours réels, pas sur hypothèses

---

## Cibles commerciales

1. **DevOps/SRE lead** (100-500 salariés) — valider que ses alertes fonctionnent vraiment
2. **RSSI PME/ETI** — preuve de résilience pour audit NIS2/ISO 27001
3. **Secteur financier** — DORA impose des tests de résilience documentés (en vigueur jan 2025)
4. **MSP/MSSP** — ajouter "test de résilience" à leur catalogue

## Distribution

GitHub public → traction communautés DevOps/sécu → premiers clients.
La démo ransomware Azure VM doit provoquer un "wow" en 2 minutes.

---

## Probabilités réalistes

- MVP fonctionnel : ~85%
- Traction GitHub 500+ stars : ~45%
- Premiers clients payants : ~30% si traction
- Business récurrent : ~20%

---

## Ce qu'on ne fait PAS avant la Phase 3

- Dashboard/UI
- PDF reports
- Multi-tenant, auth, scheduler
- AWS/GCP/K8s
- IA/ML
- Proxmox/vSphere
