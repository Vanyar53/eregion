# Status — War Room UI

## État actuel

Session démarrée le 2026-06-01. UI relue intégralement.

## War Room

- `glorfindel/static/index.html` — SPA ~2100 lignes, vanilla JS, CSS variables
- Accessible sur `http://localhost:7007` via `glorfindel war-room` ou `make glorfindel-start`

## Structure actuelle (layout)

```
Header      → GLORFINDEL · War Room · watch-dot · live-dot · scenario-select · ⚙ Config · clock
Main
  LEFT  390px  → LIVE FEED (WebSocket stream, auto-scroll)
  RIGHT flex:1 → INFRASTRUCTURE (topology graph 3 couches) ou CONFIGURATION (panel toggle)
    Topology :
      Layer 1 : GLORFINDEL agent node
      Layer 2 : DETECT (bleu) / PROTECT (orange) / RECOVER (vert)
        DETECT : backend LAW, N règles, match status, expand → règles cliquables (modal KQL)
        PROTECT : network control, isolation/block count, no restrictions
        RECOVER : RSV vault, audit status, ↺ refresh
      Layer 3 : VM cards (compact si clean, auto-expand si incident)
        États : ISOLATED · Xs ago (cliquable → reasoning modal), BLOCKED IP · Xs ago
        Escalation badge : "N escalation(s) ▸" (violet, cliquable → showEscModal)
        Expanded : LLM decisions (action+pct+ttp), ▸ reasoning si VM propre seulement
        Boutons : Release / Unblock / Reset / Restore
      SVG edges : bleu=detect, orange=protect, vert=recover, rouge plein=isolé, rouge tirets=bloqué, violet=escalade
      Légende en bas (tout en anglais)
```

## Points notables

- Infrastructure map 3 couches : topology hiérarchique Agent → Modules → Assets
- LLM reasoning : badge ISOLATED/BLOCKED cliquable + ▸ reasoning pour VMs propres
- `_actionsCache` : fetch parallèle (Promise.all), 30s TTL, re-render après fetch
- `_rulesCache` : index array pour éviter JSON.stringify dans onclick (KQL safe)
- AbortController 20s timeout sur refreshAuditData (évite _auditLoading stuck)
- improve_detection filtré : server-side (api.py) + client-side + fetch limit=15
- `resourceMap` déduplique par vm_name (évite doublon resources[] + discovered_assets[])
- Polling state : `/api/state` toutes 5s, `/api/config` toutes 30s, `/api/audit` toutes 300s
- WebSocket `/api/feed` avec reconnect exponentiel

## Inbox ARM Discovery (réponse à Glorfindel, 2026-06-04)

Vision UX pour coverage_gaps :
1. **Où afficher** : badges inline sur les node-asset dans la topology (`⚠ no monitoring` / `⚠ no backup`), pas de section séparée
2. **Urgence** : `no_backup` rouge (bloque restore_from_backup), `no_monitoring` orange
3. **VM éteinte** : filtrer si gap < 8h, sinon badge gris "possible VM offline"
4. **Action** : bouton "Fix" informatif (commande `az` copiable), pas d'action directe depuis l'UI

## Bugs connus

- Audit RSV : "Azure API error" — asyncio.to_thread fix (commit 1c28c74) appliqué, si toujours KO c'est IAM (SP sans Backup Reader sur le vault)

## Dernière session — 2026-06-11

Modes d'autonomie + observe-only — commits `b8388bb` + `022f8fc`.
Inbox × 3 traités. Aucun item en attente côté War Room.

## Historique modifications

### 2026-06-01 — Static volume mount (1a7cbbb)
- `glorfindel/static` monté en volume `:ro` dans le service `war-room`
- `index.html` lu depuis l'hôte → refresh navigateur suffit, zéro `make build`

### 2026-06-01 — LLM decision cleanup (254c00e)
- Supprimé `dec-text` (raisonnement tronqué mid-phrase dans les VM cards)
- Remplacé `▸ detail` (dim, 9px) par `▸ reasoning` (blue, 10px) — CTA plus visible
- Supprimé `showToast()` dead code

### 2026-06-02 — Topology 3 couches complète (série de commits)
- Remplacement zones statiques → topology hiérarchique Agent/Modules/Assets
- Edges SVG bezier avec code couleur sémantique
- Légende + badges état clickables + modales reasoning/escalation

### 2026-06-04 — i18n + UX fixes (b5f2488, 300de44)
- Tout en anglais : légende, ACTION_LABELS, ESC_LABELS, protect/recover rows, badges
- Suppression doublon ▸ reasoning (visible seulement si VM clean, badge = entry point si isolé)
- refreshActionsData : sequential for-loop → Promise.all, await dans refreshState
- Traduction strings françaises dans showIsolationModal
