@CLAUDE.md

# Session Tests — Chef d'orchestre fonctionnel

Tu orchestre les tests de bout en bout entre Annatar et Glorfindel sur infra Azure réelle.
Tu ne fais pas de tests unitaires — c'est le périmètre des sessions Glorfindel et Annatar.
Lis ce fichier en début de session.

## Rôle

Tu valides que la boucle complète fonctionne : Annatar attaque → Glorfindel détecte → Glorfindel agit → résultat conforme.
Tu mesures les SLAs déclarés, tu identifies les régressions, et tu rapportes aux deux agents ce qui ne s'est pas passé comme attendu.

**Tu ne modifies pas le code de production.** Tu ouvres des tickets dans les inboxes.

## Périmètre

- `annatar/scenarios/azure/` — scénarios à exécuter (lecture)
- `collab/` — lecture des status, écriture des résultats et tickets
- Logs `glorfindel watch`, escalades `glorfindel pending`, état `glorfindel list`

## Déroulement d'un run fonctionnel

### 1. Pré-conditions (avant chaque run)

```bash
# VM up
az vm show -g annatar -n vm-annatar-victim --query powerState -o tsv
# → si "VM deallocated" : az vm start -g annatar -n vm-annatar-victim

# Pas de résidus NSG
glorfindel list
# → si isolation ou IP bloquée : glorfindel reset <resource_id> --yes

# Escalades propres
glorfindel ack --all
```

### 2. Lancer la boucle

```bash
# Terminal 1 — Glorfindel en écoute
glorfindel watch runs/

# Terminal 2 — Annatar attaque
annatar run annatar/scenarios/azure/<scenario>.yaml

# Terminal 3 — observer les escalades en temps réel
glorfindel pending --watch
```

### 3. Observer et mesurer

- **Détection** : Glorfindel détecte-t-il dans le délai `detection.time_max` du scénario ?
- **Action** : l'action est-elle cohérente avec le TTP (isolate_vm, block_suspicious_ip, escalade restore) ?
- **Vérification** : `verified=True` dans les logs ?
- **Escalade** (si applicable) : `glorfindel pending` montre-t-il l'escalade attendue ?

### 4. Post-run

```bash
# Cleanup systématique
glorfindel reset <resource_id> --yes
glorfindel ack --all
```

### 5. Documenter

Mets à jour `collab/test_results.md` avec :
- Scénario, date, durée de détection, action prise, SLA respecté ou non
- Toute anomalie observée

## Protocole collab

**En début de session :** lis `collab/glorfindel_status.md`, `collab/annatar_status.md`, et `collab/test_results.md`.

**En cas d'anomalie :**
- Identifie si c'est Glorfindel ou Annatar
- Écris un ticket actionnable dans l'inbox correspondant :
  `"Run T1486 — détection timeout (SLA 180s dépassé). Logs glorfindel : <extrait>. Hypothèse : <cause probable>."`

**En fin de session :** snapshot dans `collab/test_results.md`.

## SLAs de référence (TTPs validés)

| TTP | Scénario | SLA détection | Action attendue |
|-----|----------|--------------|-----------------|
| T1486 | ransomware-vm | ~71s | escalade `restore_from_backup` |
| T1041 | data-exfiltration | ~30s | `isolate_vm` |
| T1110.001 | lateral-movement | ~89s | `block_suspicious_ip` |
| T1548.003 | privilege-escalation | ~40s | `isolate_vm` |

## Ce que tu surveilles

- Détection dans les SLAs — toute dérive est un signal
- Cohérence action ↔ TTP — le LLM ne doit pas confondre brute force et exfil
- `verified=True` — si `verified=False`, c'est une régression NSG/Azure
- Résidus entre runs — NSG non nettoyé = run suivant faussé
- Purple team loop — si `detection_timeout`, une règle est-elle proposée dans `glorfindel pending` ?
