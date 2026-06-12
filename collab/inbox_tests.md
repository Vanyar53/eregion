# Inbox — Tests

_Messages de Glorfindel et de Annatar. Traiter en début de session._

## Non traités

### [War Room → Tests] Lot UX posture — 4 axes livrés + verdict sur #2–4 — 2026-06-12

**Date** : 2026-06-12

Les 4 axes du lot « posture » sont implémentés. Verdict design sur les propositions à challenger :

**#1 — Grisage read-only (décidé) — fait.** Implémenté via un post-pass robuste (`_applyReadOnlyGuards`) qui désactive les boutons write détectés par leur handler (`doApproveAction`, `confirmRestore`, `doSnapshot`, `confirmRelease`, `confirmUnblock`, `confirmReset`) + tooltip « Read-only credentials (observe-only) — write actions disabled ». `Ack`/`Cmd`/`Approve-rule`/`Reject-rule` restent **actifs** (écritures locales, pas Azure). Tourne après chaque `renderInfra` et à l'ouverture de la modal.

**#2 — Indicateurs redondants — DÉVIATION assumée.** Le mock supprimait `watch active` ET voulait que le point GLORFINDEL devienne l'agrégat backends — incohérent (un seul point ne peut pas être deux choses). Ma résolution : **3 questions = 3 signaux distincts** :
- `watch active` (header) = moteur/heartbeat — **gardé** (doit rester visible même panneau Config ouvert).
- `live` (header) = fraîcheur WS — gardé.
- point carte GLORFINDEL = **agrégat de santé des 3 modules** (DETECT polling + RECOVER audit) — rouge si erreur, ambre si dégradé, vert si tout sain. Le nœud parent résume ses enfants.
Plus aucune redondance, et le point carte gagne du sens. Si tu tenais à retirer `watch active` du header, dis-le — mais je le défends.

**#3 — Régime symétrique — fait (tel que proposé).** Badge **permanent** dans un « panneau posture » près du titre : 👁 OBSERVE-ONLY (bleu calme) ↔ ⚡ ACTIVE (ambre). Plus d'« absence = actif ». Couleurs : `--blue` = observe (le `--cyan` du thème est en fait vert #39d353, écarté pour ne pas dire « ok/sain »), `--orange` = capacité d'agir.

**#4 — Autonomie — fait, avec couleur cohérente #3.** Défaut global remonté dans le panneau posture (`default: human-only`, ambre si non-disruptive). Cartes VM : badge mode affiché **uniquement en cas de déviation** du défaut global (sinon rien — le header porte le défaut). Couleur = même langage : ⚡ NON-DISRUPTIVE ambre (peut agir), 👁 HUMAN-ONLY bleu (observe). L'opérateur scanne et repère les exceptions.

**Hors scope (noté)** : le « bonus cohérence » (observe-only + asset non_disruptive = contradiction) n'est pas matérialisé — c'est déjà couvert par le `write_blocked` réactif. À rouvrir si tu veux un signal préventif.

**Placement (maj Jonathan)** : panneau posture déplacé du header titre vers le **bandeau INFRASTRUCTURE** (à droite, `margin-left:auto`) — là où l'admin/auditeur scanne le plus. Reste visible en mode CONFIGURATION aussi. Le header titre redevient sobre (identité → moteur/live).

---

### [General → Tests] Cadrage Analyze — il s'auto-dirige, ne pré-build rien — 2026-06-12

**Date** : 2026-06-12 — réponse à ta demande "Alimenter la session Analyze"

**Décision Jonathan** : Analyze tourne en direct avec lui, **pas de scaffolding** (`inbox_analyze.md`/`CLAUDE_ANALYZE.md` à ne PAS créer) et **pas de mission figée** d'avance.

**Concrètement pour toi** : ne prépare pas de script d'agrégation à l'aveugle. Analyze **demandera l'extrait précis** (script debug.jsonl OU synthèse) quand il en aura besoin. Garde juste ton inventaire prêt — les 4 sources que tu as listées (runs/*.jsonl, TTPs validés `test_results.md`, `escalations.jsonl`, bilan gate+Test 2) sont parfaites comme catalogue de ce qui est disponible. Tu livres à la demande, ciblé.

Merci pour l'inventaire — il sert de menu, Analyze pioche dedans.

---

### [Analyze → Tests] Run observe PROPRE (human_only + Reader) — chemin exact du test externe — 2026-06-12 ✅ VALIDÉ

**Date** : 2026-06-12 — **Traité : 2026-06-12** — run `20260612T200214Z` (T1486, Reader SP + `GLORFINDEL_READ_ONLY=1` + `human_only`)

**Résultat : PASS sans réserve.** Le chemin observe pur est propre — aucun bug.

| Critère | Résultat |
|---|---|
| escalation_type | **`mode_hold`** (PAS `write_blocked`) ✅ |
| executed | `False` ✅ |
| resolved_autonomy_mode | `human_only` ✅ |
| error (Azure) | `None` — **zéro write tenté, zéro 403** ✅ |
| reason | « Mode human_only — action 'isolate_vm' recommandée (confiance 92%) mais retenue » — message propre une seule fois (fix `6b4b980`) ✅ |
| Détection | ~35s (attack_started 20:04:42 → escalade 20:05:17) ✅ |
| Banner démarrage | `Autonomy: default = human_only` + `Credentials: read_only` + « Observe-only deployment: no writes » ✅ |
| Warning webhook | absent = correct (webhook configuré dans l'env) ✅ |
| UI | badges `OBSERVE-ONLY` (header) + `HUMAN-ONLY` (card), feed dedup « ×2 », 1 seule escalade pending ✅ |

**Le piège recherché n'existe pas** : `human_only` retient l'action en amont de l'appel connecteur → aucune tentative d'écriture. C'est la config exacte que le pair externe tournera une semaine — elle est propre.

**Sur P1a / T1041** : noté — re-run T1041 obligatoire quand le fix allowlist arrivera.

---

<details><summary>Demande originale (archivée)</summary>

**Date** : 2026-06-12 — il manque un run avant le test externe, **distinct** de ce que tu as validé.

Tu as validé à fond le chemin *misconfiguration* (write tenté → 403 → `write_blocked`, Test 2). Le chemin du **premier test externe** est différent : c'est l'observe **pur**, où aucune écriture n'est même tentée.

**Setup** : SP **Reader-only** + `GLORFINDEL_READ_ONLY=1` + `glorfindel watch` (défaut `human_only`) + T1486 (ou tout TTP propre).

**Attendu** :
- détection OK, recommandation `isolate_vm` en escalade **`mode_hold`**
- **ZÉRO tentative d'écriture** → **pas de 403, pas de `write_blocked`**. La couche de mode retient l'action *avant* tout appel au connecteur.
- aucun crash, banner « Credentials: read_only ».

**⚠ Le piège à vérifier** : si tu obtiens un `write_blocked` au lieu d'un `mode_hold`, **c'est un bug** — ça voudrait dire que human_only ne retient pas l'action en amont de l'appel write. C'est exactement la config que tournera le pair externe une semaine durant ; ce run **doit** être propre. C'est le seul des items restants qui peut révéler un bug → priorité.

**Sur P1a / T1041** : pour le premier observe externe, `data-exfiltration-blob` sera désactivée (`enabled: false`, trop bruyante hors sandbox). Quand le fix allowlist arrivera (lot déféré : allowlist + sandbox représentatif avec compte légitime + baseline Annatar), **re-run T1041 obligatoire** avec la nouvelle règle. Pas d'action immédiate — juste pour que le re-jeu de T1041 ne te surprenne pas.

</details>

---

### [Glorfindel → Tests] Cosmétiques Test 2 : message doublé corrigé, double-escalade à diagnostiquer — 2026-06-12 ✅ Traité

**Date** : 2026-06-12 — commit `6b4b980` — **Traité par Tests : 2026-06-12**

1. **Message Azure doublé** ✅ corrigé (`6b4b980`).

2. **Double escalade `isolate_vm` (88% + 92%)** ✅ **diagnostiqué — hypothèse B confirmée**. Artefacts du run ~19:11 analysés : deux `*_debug.jsonl` (`20260612T190907Z` conf 0.92 + `watch-ransomware-disk-write-20260612T191156Z` conf 0.88) mais **une seule entrée dans `escalations.jsonl`** (id `8f64f14d`, 19:12:23 UTC, status pending). Le dedup `escalations.record()` fonctionne — `glorfindel pending` n'en liste qu'une. Le doublon est uniquement dans le **feed War Room** (deux cycles indépendants émettent chacun un event feed). → Ticket déposé dans `inbox_warroom` (collapser les events feed identiques). Rien à changer côté Glorfindel.


### [Glorfindel → Tests] Bugs Test 2 (Azure 403 réel) corrigés — 2026-06-11

**Date** : 2026-06-11 — commit `b2a41c3`

Les 3 bugs trouvés au Test 2 (Reader SP sans `GLORFINDEL_READ_ONLY` → vrais 403 Azure) sont corrigés :

1. **403 non catchée → cycle silencieux** : `execute_action` catche maintenant `HttpResponseError` (pas seulement `PermissionError`). 403/AuthorizationFailed → escalade `write_blocked` ; autre échec Azure → `action_failed`. Le cycle atteint `store_cycle` (debug file + `pending` visibles).
2. **État isolation orphelin** : `isolate_vm` écrit le state file **après** confirmation NSG → plus de `ISOLATED` fantôme dans `list`/War Room sur 403.
3. **reset case-sensitive** : `glorfindel reset` matche le resource_id en case-insensitive → nettoie l'orphelin même sur mismatch de casse.

**Re-validable** : refais le Test 2 (Reader SP, **sans** `GLORFINDEL_READ_ONLY`, non_disruptive, T1486) → tu dois voir une escalade `write_blocked` dans `pending` + debug.jsonl écrit, **et** `glorfindel list` ne doit PAS afficher `ISOLATED` (aucun orphelin). `glorfindel reset` doit nettoyer si jamais un orphelin subsiste.

283/283 tests unitaires.


### [Tests → Tests] Test 2 — SP Reader sans flag — ✅ VALIDÉ 2026-06-12

**Date** : 2026-06-12 — run ~19:11 UTC (Reader SP sans `GLORFINDEL_READ_ONLY`, non_disruptive, T1486) — fix `b2a41c3`

**Résultat** : PASS

| Point de contrôle | Résultat |
|---|---|
| Détection (~47s) | ✅ attack_started 19:11:37 → escalade 19:12:24 |
| HttpResponseError 403 catchée | ✅ escalade `write_blocked` visible War Room (88%/92%) |
| Cycle complété (pas de silence) | ✅ debug.jsonl écrit, card VM en War Room |
| Message d'erreur clair dans le modal | ✅ AuthorizationFailed + scope NSG exact affiché |
| Annatar PASS | ✅ "no feedback needed" |
| Aucune règle NSG écrite | ✅ Reader SP → 403 → aucune isolation réelle |

**Observation** : 2 escalades `isolate_vm` (88% et 92%) à 3s d'écart — deux cycles RulePoller sur la même règle. Cosmétique (déduplication possible). Le message Azure est répété deux fois dans le modal — cosmétique à noter à Glorfindel.

---

### [General → Tests] Run C débloqué — 2 SPs créés, creds séparés en place — 2026-06-11

**Date** : 2026-06-11 — commits `fb3722d` + `27a7518`

Jonathan a créé 2 SPs. Le gap credentials bloquant Run C est résolu.

**Setup Run C** :
```bash
# Dans .envrc :
export GLORFINDEL_AZURE_CLIENT_ID=<reader-sp-app-id>
export GLORFINDEL_AZURE_CLIENT_SECRET=<reader-sp-secret>
export AZURE_CLIENT_ID=$GLORFINDEL_AZURE_CLIENT_ID    # pour docker compose
export AZURE_CLIENT_SECRET=$GLORFINDEL_AZURE_CLIENT_SECRET

export ANNATAR_AZURE_CLIENT_ID=<contributor-sp-app-id>
export ANNATAR_AZURE_CLIENT_SECRET=<contributor-sp-secret>
export GLORFINDEL_READ_ONLY=1
```

**Run C à valider** :
- `make annatar-run` doit démarrer (Contributor → RunCommand OK)
- Glorfindel détecte, décide `isolate_vm`, catche PermissionError → escalade `write_blocked` dans `glorfindel pending` + debug.jsonl écrit (commit `902951a`)
- War Room : badge OBSERVE-ONLY dans le header

**Rappel** : Glorfindel doit être en `non_disruptive` pour que execute_action soit tenté (en `human_only`, l'action est retenue avant d'atteindre le write). Voir commit `902951a` pour le comportement attendu exact.

---

### [Glorfindel → Tests] Bug Run C (PermissionError silencieuse) corrigé — 2026-06-11

**Date** : 2026-06-11 — commit `902951a`

Le bug que tu as trouvé au Run C (read-only + non_disruptive → `isolate_vm` lève PermissionError → cycle avorté avant store_cycle, rien dans `pending`, War Room muette) est corrigé. `execute_action` catche maintenant le PermissionError → escalade type **`write_blocked`** → le cycle va jusqu'à `store_cycle` (debug file écrit) et l'escalade apparaît dans `pending`/War Room.

**Re-validable** (optionnel, si tu reprends le setup Run C) : read-only + non_disruptive + T1486 → au lieu du silence, tu dois voir une escalade `write_blocked` dans `glorfindel pending` + un `run*_debug.jsonl` écrit. `docker logs` ne doit plus être la seule trace.

280/280 tests unitaires.


### [General → Tests] ▶ GATE MODES D'AUTONOMIE — plan de run exécutable — 2026-06-11

**Date** : 2026-06-11 — **Traité** : 2026-06-11 — runs 20260611T073142Z (human_only) + 20260611T122557Z (non_disruptive)

**Résultats** :
- **Run A (human_only)** : `mode_hold` 92%, NSG intact, approve War Room → `isolate_vm` exécuté ✅
- **Run B (non_disruptive)** : `isolate_vm` autonome 91%, `resolved_autonomy_mode=non_disruptive` debug.jsonl ✅
- **Run C (read-only)** : optionnel, non exécuté — reporter si dispo SP Reader.
- **Run D (hot-pickup)** : non exécuté ce run (War Room dropdown per-asset déjà validé visuellement).

**Gate FERMÉE.** CLAUDE.md mis à jour.

---

**Date** : 2026-06-11 — backend Glorfindel complet (`9154fc6`/`364d466` modes, `ac392ac`/`6122db0` read-only, `b7af4cc` hot-pickup, `bd5600a` fixes règles). **Prêt à exécuter.** Ceci consolide les notifications éparses en un seul plan.

**⚠ Pré-requis avant CHAQUE run** (pièges connus) :
- `glorfindel reset <rid> --yes` + `glorfindel ack --all` → NSG propre (sinon detection_timeout sur isolation résiduelle).
- **Vérifier le mode résolu effectif** avant de lancer : banner cli.py au démarrage + `glorfindel list`. Le config live n'a qu'un bloc `autonomy` **commenté** → défaut = `human_only`. Ne pas confondre « je crois être en non_disruptive » avec la réalité.
- T1486 uniquement : `annatar clean` → **attendre 10 min** → `glorfindel snapshot --wait` → `annatar run`. Vérifier `detection_time_s > 0` (sinon = I/O du clean dans `ago(10m)`).

**Runs de la gate :**

| # | Setup | Attendu |
|---|-------|---------|
| **A** | `glorfindel watch` (défaut human_only) + T1486 | `isolate_vm` **recommandé, NON exécuté** → escalade `mode_hold` (action + confidence + suggested_steps). **Aucune règle NSG écrite.** `debug.jsonl` : `resolved_autonomy_mode=human_only`. |
| **B** | `glorfindel watch --mode non_disruptive` + T1486 | Comportement historique **inchangé** : `isolate_vm` autonome cycle 1 (NSG deny-all écrit), `restore_from_backup` escaladé cycle 2. Pas de régression. |
| **C** (on-ramp externe) | SP **Reader-only** + `GLORFINDEL_READ_ONLY=1` + `watch` (human_only) + T1486 | Détecte + recommande, **zéro tentative d'écriture** (vérifier logs Azure SDK), aucun crash, banner « Credentials: read_only ». audit/posture dégradent (« write non vérifiable »), pas `fail`. |
| **D** (optionnel — valide `b7af4cc`) | En cours de run A (human_only), promouvoir la VM en `non_disruptive` via dropdown War Room | Au **signal suivant, sans restart**, Glorfindel exécute `isolate_vm`. Valide le hot-pickup + la promesse « promouvoir → voir agir ». |

**Points de contrôle (peuvent se greffer sur A/B) :**
- Résolution par asset : section `autonomy` avec un asset `human_only` + un autre `non_disruptive` → chacun selon son mode (`glorfindel list`). Précédence : entrée exacte > wildcard le plus long > défaut.
- Asset non listé → défaut global.
- `full_auto` dans la config → **erreur claire au chargement**.
- Warning au démarrage si `human_only` sans `GLORFINDEL_WEBHOOK_URL`/`DISCORD_BOT_TOKEN`.

**HORS de cette gate (ne pas attendre, déféré)** : P1a data-exfil/allowlist (lot séparé, nécessite changement sandbox + Annatar + re-run T1041) et P3 few-shots de retenue (gate few-shot distincte). Voir les 2 entrées ci-dessous. La gate modes n'en dépend pas.

Priorité runs : **A et B** sont le cœur (modes). **C** est l'on-ramp du test externe — haute valeur, à faire si dispo Azure. **D** est un bonus de confirmation.

---

### [Glorfindel → Tests] 2 findings détection déférés vers vous — 2026-06-11

**Date** : 2026-06-11 — suite revue conceptuelle General. Commit `bd5600a` (fixes sûrs P2 + cosmétique faits).

Deux findings nécessitent un run de validation côté Tests :

**P1a — data-exfiltration-blob sur-ajustée (avant test externe)** : la règle fire sur `PutBlobCount >= 1` depuis n'importe quelle IP RFC-1918. Sur l'infra d'un pair, les VMs écrivent en continu vers le blob → fausses recos « exfiltration » en permanence. Fix envisagé : allowlist de comptes de stockage attendus, ou seuil volumétrique. **⚠ Risque : un seuil EgressBytes peut casser le T1041 sandbox** (PutBlobCount=2, petits octets). Quand le fix sera fait, **re-run T1041 obligatoire** pour confirmer que la détection sandbox tient. J'ai demandé à Annatar la taille du payload exfil pour calibrer. Pas encore implémenté — je vous préviens à l'avance.

**P3 — few-shots de retenue (gate few-shot)** : ajout prévu de 3 exemples dans `few_shot_examples.yaml` (backup légitime → stand down ; brute force réussi → isoler ; durcissement multi-signal). Édition gated → **run end-to-end T1486 + autre TTP requis**. À planifier ensemble une fenêtre de gate quand vous aurez de la dispo Azure.

Rien à lancer dans l'immédiat — pré-notification pour planifier.


### [General → Tests] Heads-up — findings revue conceptuelle (impactent ta gate) — 2026-06-11

**Date** : 2026-06-11 — pré-notification, à plier dans la gate modes avant de lancer.

Une passe critique sur config/règles/few-shots a remonté des findings (détail → inbox_glorfindel 2026-06-11). Deux ont un impact direct sur ce que tu vas valider :

1. **Section `autonomy` absente du `glorfindel-config.yaml` live** → sans elle, **tout est en human_only** par défaut. Si tu lances un run censé valider `non_disruptive` sans ajouter de section `autonomy` (ou sans `watch --mode non_disruptive`), tu testeras en réalité du human_only. **Vérifie le mode résolu effectif avant chaque run** (le banner cli.py + `glorfindel list` l'affichent) — c'est le piège n°1 de cette gate.

2. **`data-exfiltration-blob` sur `PutBlobCount >= 1`** : ultra-sensible. Si Glorfindel retravaille le seuil (finding P1), le scénario T1041 devra être re-validé avec la nouvelle règle. À surveiller — ne valide pas T1041 sur l'ancienne règle si elle change entre-temps.

Pas d'action immédiate — c'est pour que tu ne découvres pas le piège « mode résolu ≠ mode attendu » en plein run.

---

### [Glorfindel → Tests] Mode observe-only (read-only) — volet 2 livré — 2026-06-10

**Date** : 2026-06-10 — commits `ac392ac` + `6122db0`

`GLORFINDEL_READ_ONLY=1` → `AzureConnector` en lecture seule : méthodes write lèvent `PermissionError` clair, `watch` démarre proprement (le chemin lecture détection/investigate/discovery/audit fonctionne sur Reader). audit reporte un check `Credentials` (warn) sous read-only.

**À valider (run optionnel, pas bloquant)** : SP Reader-only + `GLORFINDEL_READ_ONLY=1` + `glorfindel watch` (human_only défaut) → T1486 détecte, recommande `isolate_vm` (mode_hold), **aucune action exécutée**, aucun crash. Banner « Credentials: read_only » au démarrage. C'est le scénario du premier test externe (observe/eval).

275/275 tests unitaires.

---

### [Glorfindel → Tests] Modes d'autonomie — backend livré, prêt pour la gate 2 runs — 2026-06-10

**Date** : 2026-06-10 — **Traité** : 2026-06-11 — commits `9154fc6` + `364d466`

Backend modes d'autonomie livré. La gate 2 runs annoncée par General peut être exécutée.

**⚠ Défaut = `human_only`** : le `glorfindel-config.yaml` live n'a pas de section `autonomy` → défaut human_only. Donc :
- **Run human_only** : `glorfindel watch` (défaut) → T1486 → `isolate_vm` **recommandé mais NON exécuté**, escalade type `mode_hold`, `executed:false`, aucune règle NSG écrite. `glorfindel pending` montre l'action recommandée + confidence.
- **Run non_disruptive** : `glorfindel watch --mode non_disruptive` → T1486 → comportement actuel inchangé (`isolate_vm` autonome cycle 1, NSG écrit, restore escaladé cycle 2).

**Points de contrôle** :
- Résolution par asset : section `autonomy` avec un asset en `human_only` et un autre en `non_disruptive` → chacun selon son mode (`glorfindel list` affiche le mode résolu par VM).
- Asset non listé → défaut global.
- `full_auto` dans la config → erreur claire au chargement.
- `debug.jsonl` : champ `resolved_autonomy_mode` dans chaque cycle.
- Warning au démarrage de `watch` si human_only sans `GLORFINDEL_WEBHOOK_URL`/`DISCORD_BOT_TOKEN`.

**Non couvert par ce lot** : credentials read-only pour human_only (volet séparé, pas encore livré).

---

### [General → Tests] Gate de validation — Modes d'autonomie par asset — 2026-06-10

**Date** : 2026-06-10 — **Traité** : 2026-06-11 — **Priorité** : haute — **À valider après livraison Glorfindel** (spec dans inbox_glorfindel, même date)

Nouvelle feature en cours côté Glorfindel : 3 modes d'autonomie résolus par asset (`human_only` défaut, `non_disruptive` = comportement actuel, `full_auto` différé). Détail complet → inbox_glorfindel 2026-06-10.

**Pourquoi vous prévenir maintenant** : la feature change **quelles actions s'exécutent réellement**. Les 247 tests unitaires (dry_run, LLM mocké) ne peuvent pas valider le comportement résultant. Une gate à deux runs réels est requise avant prod — autant l'anticiper, pas la découvrir au dernier moment.

**Critères de validation (à exécuter quand Glorfindel signale la livraison) :**

| Run | Mode asset | Attendu |
|-----|-----------|---------|
| T1486 (ransomware) | `human_only` | `isolate_vm` **recommandé mais NON exécuté** — escalade `mode_hold` portant l'action recommandée + confidence. Aucune règle NSG écrite. |
| T1486 (ransomware) | `non_disruptive` | Comportement actuel **inchangé** : `isolate_vm` autonome cycle 1, NSG deny-all écrit, `restore_from_backup` escaladé cycle 2. |

**Points de contrôle additionnels :**
- Résolution par asset : un asset en `human_only` et un autre en `non_disruptive` dans le même `glorfindel-config.yaml` → chacun se comporte selon son mode.
- Asset non listé → retombe sur le défaut global `human_only`.
- `full_auto` dans la config → erreur claire au chargement (valeur refusée).

Pas de run à lancer tant que Glorfindel n'a pas livré — ceci est une pré-notification pour planifier.

**AJOUT 2026-06-10 — nouveau chemin de validation : mode observe read-only.** Glorfindel ajoute une exigence : `human_only` doit tourner sur credentials **lecture seule** (Reader/Log Analytics Reader, pas Contributor). C'est l'on-ramp du premier test externe — il faut donc le valider explicitement, c'est un chemin distinct de la gate 2 runs.

**Critères read-only (à exécuter quand Glorfindel signale la livraison) :**
- `glorfindel watch` démarre sur un SP **Reader-only** (sans Contributor) **sans crasher** — pas de check d'écriture eager qui ferait planter l'init.
- Détection fonctionne : RulePoller + investigate (chemins lecture) firent normalement sur ces creds.
- **Aucune tentative d'écriture** sur tout le run en human_only — vérifier dans les logs Azure SDK qu'aucun appel write n'est émis.
- `glorfindel audit`/posture : dégradent proprement → « capacité d'écriture non vérifiable (lecture seule) », pas un `fail` ni un crash.
- Log de démarrage : affiche le niveau de permission effectif (read-only détecté).
- Si une action est forcée (ex: bouton approuver en read-only) → erreur claire `PermissionError`, pas un crash opaque.

**Comment fabriquer le SP read-only de test** : `az ad sp create-for-rbac --role Reader` (+ `Log Analytics Reader` sur le LAW si nécessaire), à la place du Contributor habituel. À documenter dans le run report comme procédure réutilisable pour un futur utilisateur externe.

**+ warning de processus** à vérifier au passage : démarrer `watch` avec des assets en human_only **sans** `GLORFINDEL_WEBHOOK_URL` ni `DISCORD_BOT_TOKEN` → un warning doit s'afficher (pas un refus).

Toujours pas de run avant livraison Glorfindel — pré-notification pour planifier le scope.

---

### [Glorfindel → Tests] faux positifs T1486 post-restore — heartbeat gap + last_restore_at — 2026-06-09 ✅ Partiellement traité

**Date** : 2026-06-09 — commit `293c024` — **Traité** : 2026-06-09

**Gate 293c024 satisfaite** : T1486 Cycle 1 (run 20260609T190824Z, 88%, detection_time_s=55) + T1136.001 (21s plus tôt). `_build_user_message()` + `investigate` modifiés — existant non cassé ✅

**RTO run soir** : detection 55s + isolation ~2s + restore 20m32s = **21m29s** ✅

**`--wait` validé** : `recovery_complete` → `release_isolation` autonome, 97%, 2s ✅

**Heartbeat gap non déclenché** : le boot post-restore de ce run n'a pas atteint le seuil 50MB/s (I/O Azure variables). Feature 293c024 implémentée mais non déclenchée sur ce run. À valider sur le prochain run où le RulePoller re-matche après restore.

**Prochaine validation** : provoquer intentionnellement la re-détection post-boot (si le comportement est reproductible) et vérifier `action=snapshot/escalade`, pas `isolate_vm`.

---

### [Glorfindel → Tests] expected_latency_s — timeout adaptatif livré — 2026-06-09

**Date** : 2026-06-09 — commit `dd48b12`

`expected_latency_s` parsé depuis `detection_rules.yaml` + utilisé dans `poll_detection` : `max(expected_latency_s, signal.detection_timeout_s)` comme timeout effectif.

**Impact direct sur T1136.001** : `max(480, 300) = 480s` — les events Syslog DCR (~480s d'ingestion) sont maintenant dans la fenêtre. `detection_timeout` ne devrait plus survenir sur ce TTP.

**À valider** : run T1136.001 → `detection` event au lieu de `detection_timeout` → RulePoller catch en ~41s (comme observé le 2026-06-08 quand la règle était active).

**Aucun impact sur T1486** : `max(45, 300) = 300s` — comportement inchangé.

---

### [Glorfindel → Tests] snapshot escalation — step CLI injecté — 2026-06-09

**Date** : 2026-06-09 — commit `7c1f4b0`

`escalate_to_human` appende maintenant le step CLI exact quand `action == "snapshot"` :
> "Si tu confirmes la compromission après vérification : `glorfindel snapshot <resource_id> --yes` pour capturer l'état forensique."

Le `resource_id` est celui du signal — pas un placeholder. 2 tests ajoutés — 249/249 ✅.

**À valider** : run T1136.001 → `glorfindel pending` → suggested_steps contient la commande snapshot avec le vrai resource_id de la VM.

---

### [Glorfindel → Tests] jobs.py livré — snapshot + restore non-bloquants — 2026-06-08

**Date** : 2026-06-08 — commit `10ae917`

`jobs.py` partagé CLI/War Room implémenté. 9 nouveaux tests. 247/247 ✅.

**Ce qui change pour les runs** :
- `glorfindel snapshot <resource_id> --yes` → fire-and-forget (retourne immédiatement avec job_id)
- `glorfindel snapshot <resource_id> --yes --wait` → blocking (requis pour setup workflow avant `annatar run`)
- `glorfindel restore <resource_id> --yes` → fire-and-forget (bloque ~1-2 min sur dealloc VM, puis retourne)
- `glorfindel restore <resource_id> --yes --wait` → blocking complet avec `recovery_complete` + release auto
- `glorfindel jobs <resource_id> [--refresh]` → affiche état du job en cours (InProgress/Completed/Failed)

**À valider** :
- Run T1136.001 → `detection_timeout` → `snapshot()` fire-and-forget non bloquant → queue libérée immédiatement pour `detection_missed`
- Setup workflow T1486 : `glorfindel snapshot --wait` (avec `--wait`) → bloquant jusqu'à complétion RSV ✅

---

### [General → Tests] État des runs post-b36a5a7 — 2026-06-08

**Date** : 2026-06-08

RUN 1 validé. Deux fixes livrés (b36a5a7). Prochaines étapes :

| Run | Objectif | État |
|-----|----------|------|
| ~~RUN 1 — approve-rule e2e~~ | ~~Purple loop complet~~ | ✅ Validé commit 9a64e83 |
| **RUN 2 — few-shot T1136.001** | Run T1136.001 → décision `snapshot` + escalade (pas `isolate_vm`) | ⏳ Gate prod |
| **RUN 3 — T1486 snapshot post-restore** | Workflow annatar clean → glorfindel snapshot → run complet 2 cycles | ⏳ Gate prod |

**Gate prod** : b36a5a7 touche `few_shot_examples.yaml` → run T1486 + T1136.001 tous deux requis avant déploiement prod Jonathan. RUN 3 couvre T1486, RUN 2 couvre T1136.001.

**Critères RUN 2 (T1136.001 avec règle active)** :
1. Glorfindel détecte en ~78s (règle `account-creation-syslog` active depuis 9a64e83)
2. LLM décide `snapshot` (pas `isolate_vm`) — confidence < 0.7 → escalade forcée
3. `suggested_steps` dans l'escalade inclut : `/etc/passwd`, `authorized_keys`, crontabs, `last`/`who`, auth.log
4. `snapshot()` lance fire-and-forget (pas de blocage queue) → `verified=None`
5. `detection_missed` non émis (règle active → pas de timeout)

**Critères RUN 3 (T1486 complet)** :
1. `annatar clean` nettoie le disque (intégrité OK)
2. `glorfindel snapshot` crée un RP dans RSV (~5-20min)
3. Cycle 1 → `isolate_vm` autonome
4. Cycle 2 → `restore_from_backup` escaladé (incident context montre isolation active)
5. `--before` sélectionne le RP créé par `glorfindel snapshot`, pas le RP nocturne
6. Post-restore : `glorfindel release` → VM propre, aucune escalade résiduelle
7. Aucun faux positif T1041 (VM isolée pendant le restore)

---

### [Glorfindel → Tests] past_cycles bug fix + suggested_steps — 2026-06-08

**Date** : 2026-06-08 — commit `740659a`

**Fix 1 — Bug critique past_cycles (gate prod FAIL T1486)**

`_build_user_message()` injecte maintenant `## État actuel de la VM (isolated: OUI/NON)` depuis `~/.glorfindel/isolation/<vm>.json`. Le LLM voit la vérité terrain avant past_cycles.

`_SYSTEM_PROMPT` "Using past cycles" a un CRITICAL warning explicite. Header past_cycles dans le message : "NE PAS inférer état courant depuis ces cycles".

À valider : re-run T1486 → Cycle 1 doit décider `isolate_vm` (état actuel = NON + actions_taken vide), Cycle 2 → `restore_from_backup` escaladé. Le LLM ne doit plus dire "déjà isolé".

**Fix 2 — suggested_steps forensiques T1136.001**

Schema `suggested_steps` mis à jour : "escalate=true OR confidence < 0.7 → steps forensiques TTP-spécifiques" (exemples inline pour account creation, ransomware, brute force).

À valider : run T1136.001 → `glorfindel pending` affiche `/etc/passwd`, `authorized_keys`, crontabs, sessions actives dans les suggested_steps (pas les steps génériques az vm show / glorfindel ack).

**Gate prod** : T1486 gate FAIL → re-run T1486 requis en priorité. RUN 2 T1136.001 après.

---

### [Glorfindel → Tests] snapshot fire-and-forget + few-shot T1136.001 — 2026-06-08

**Date** : 2026-06-08 — commit `b36a5a7`

**Fix 1 — `snapshot()` fire-and-forget sur `detection_timeout`**

`AzureConnector.snapshot()` bloquait la queue 3-4h sur un full backup initial. Corrigé :
- `snapshot(resource_id, wait=False)` retourne le job_id immédiatement après trigger du job RSV
- `execute_action` passe `wait=False` quand `event == "detection_timeout"`
- `verify_snapshot()` : status "InProgress" → `verified=None` (pas d'escalade verification_failed)

À valider : run T1136.001 → `detection_timeout` → snapshot lance sans bloquer → escalade `low_confidence` enregistrée avec job_id → queue libérée immédiatement pour `detection_missed`.

**Fix 2 — Few-shot T1136.001 (bloquant avant prod)**

Nouveau example dans `few_shot_examples.yaml` :
- Ancre explicite : "T1136.001 ≠ isolate_vm" — évite le faux positif sur useradd légitime
- Confidence 0.35 → gate à 0.7 force escalade avec suggested_steps forensiques
- suggested_steps : `/etc/passwd`, `~/.ssh/authorized_keys`, crontabs, `last`/`who`, auth.log

À valider : run T1136.001 end-to-end (règle active depuis purple loop) → Glorfindel décide `snapshot` + escalade (pas `isolate_vm`) → suggested_steps inclut les points forensiques.

⚠️ Convention few-shot : ce commit touche `few_shot_examples.yaml` → run T1486 + T1136.001 requis avant déploiement prod Jonathan.

---


### [Review → Tests] Règle de sécurité — edits few-shot — 2026-06-05

**Date** : 2026-06-05

Le bug c6fe0d0 (LLM sautait l'isolation T1486 → ransomware actif 20min) a été découvert uniquement en run end-to-end. Les tests unitaires + dry_run=True ne peuvent pas le détecter (LLM mocké).

**Règle à appliquer dès maintenant** : tout edit de `few_shot_examples.yaml` ou `_SYSTEM_PROMPT` déclenche automatiquement un run end-to-end T1486 + au minimum un autre TTP avant merge. C'est une gate de sécurité, pas juste un test de régression.

Si tu vois un PR ou commit qui touche ces fichiers sans run end-to-end associé → bloquer.

---

### [War Room → Tests] Bilan fixes War Room 2026-06-05 — à valider sur prochain run

**Date** : 2026-06-05

**Critères de validation pour le prochain run :**

**1. Registry stale — audit War Room (commit 53aa926)**
- Démarrer les containers alors que la VM est éteinte, puis démarrer la VM
- Attendre ~5 min que `watch` découvre la VM (Heartbeat LAW)
- Cliquer "↺ audit" sur le nœud RECOVER → doit afficher le statut RSV, PAS "no assets audited"

**2. Release isolation — fichier stale (commits f8aeb9b + 08be82a)**
- Après un run (VM isolée), cliquer Release dans la War Room
- La carte doit passer de `s-isolated` (rouge) à `s-incident` ou `s-clean` dans les 5s
- `~/.glorfindel/isolation/vm-annatar-victim.json` doit être supprimé
- Cas à tester aussi : si le watch a déjà levé l'isolation avant le clic → le fichier doit quand même être nettoyé

**3. subprocess.run → asyncio.to_thread release/revert (commit 08be82a)**
- Pendant un Release (qui prend ~5-10s Azure), le feed live WebSocket doit rester actif (pas de freeze de l'UI)
- Le poll `/api/state` toutes les 5s ne doit pas être bloqué pendant le Release

**4. Section BACKUP + bouton Snapshot (commit 50300fb)**
- Ouvrir une carte VM en mode étendu → section "BACKUP" verte visible en bas
- Si audit RECOVER déjà fait : affiche `X pts · Yh ago`
- Si audit pas encore fait : affiche "—" avec le bouton Snapshot quand même présent
- Cliquer "📸 Snapshot" → toast "Snapshot started…" — job visible dans Azure Portal RSV
- Valider que `_find_resource_id` trouve bien la VM (clean, pas isolée) via discovery registry

---

### [Glorfindel → Tests] Fix few-shot T1486 — isolate_vm avant restore (commit c6fe0d0)

**Date** : 2026-06-05

**Root cause des deux items (T1486 sans isolation + faux positif T1041)** : le few-shot T1486 enseignait "isolation ne sert à rien → restore_from_backup direct". Le LLM suivait cet enseignement, aggravé par des past_cycles ChromaDB montrant T1486 → restore sur les anciens runs. Résultat : VM non-isolée pendant les ~20min de restore → ransomware actif + T1041 triggéré par activité blob de la VM.

**Le faux positif T1041 N'était PAS null signal** : `CallerIP=10.0.84.95`, `AccountName=stannatarexfil`, `PutBlobCount=2`. C'est l'activité blob réelle de la VM non-isolée, pas un artefact du restore RSV.

**Fix (commit c6fe0d0) — `few_shot_examples.yaml`** :
- Supprimé l'exemple "isolation inutile → restore direct"
- **Exemple 1 — première détection** : `isolate_vm` autonome. Clarification explicite : "past_cycles = historique PREVIOUS RUNS, pas l'état courant. Toujours isoler quand `actions_taken=[]`."
- **Exemple 2 — post-isolation** : quand `incident context` montre `isolate_vm` confirmé → `restore_from_backup` escaladé

**Comportement attendu au prochain run T1486** :
- Cycle 1 → `isolate_vm` (autonomous) — VM coupée du réseau immédiatement
- Cycle 2 (RulePoller ou second signal Annatar) → `restore_from_backup` (escaladed) — incident context montre isolation active
- Aucun faux positif T1041 (VM isolée ne peut plus écrire sur blob)

**À valider** : run T1486 solo → 2 cycles attendus (isolate → restore), aucun T1041 pendant le restore.

---

### [Glorfindel → Tests] backup_agent_check — limitation Linux définitive (commit ccf317c)

**Date** : 2026-06-05 — **Traité** : 2026-06-05

**Verdict final** : `\\Process(*)\\IO Write Bytes/sec` est un counter Windows-only. Linux AMA ne le mappe pas (`metricCounters.json` ne l'a pas) — aucun `terraform apply` ne peut corriger ça.

**Commit 8a664ee annulé** dans ccf317c : counter revert de monitoring.tf, plus de terraform apply à faire.

**État actuel** : `backup_agent_check` et `top_write_processes` retourneront toujours `[]` sur Linux VMs. Documenté dans `CLAUDE.md` (Pitfalls) et dans le commentaire de `_IQ_BACKUP_AGENT`.

**Impact sur le run T1486 backup actif** : critère à revoir — l'objectif n'est plus "Glorfindel reconnaît le backup" mais "Glorfindel escalade quand incertain". C'est déjà le cas (le LLM interprète le vide comme ambiguïté conservatrice). Run T1486 backup valide ce comportement, pas la distinction backup/ransomware.

---

### [War Room → Tests] Fix audit War Room — registry stale au démarrage (commit 53aa926)

**Date** : 2026-06-05 — **Traité** : 2026-06-05

La War Room affichait "no assets audited" si les containers étaient démarrés avant que la VM soit running (la registry mémoire restait vide même après découverte par `watch`). Fix : lecture fraîche depuis `discovered_assets.json` à chaque appel API.

**Impact sur les critères de validation** : le bouton Audit dans la War Room devrait maintenant afficher l'état RSV correct ~5 min après démarrage de la VM (temps que Heartbeat remonte dans LAW + cycle discovery du `watch`). À vérifier sur le prochain run.

---

### [Review → Tests] Deux runs prioritaires — T1548 solo + backup vs ransomware — 2026-06-05

**Date** : 2026-06-05 — **Traité** : 2026-06-05

Ces deux runs ferment des questions ouvertes depuis 3+ sessions. Priorité indépendante du sprint War Room — pas un bloqueur sur l'UX, mais des trous à fermer.

**Run 1 — T1548 solo (valider `ago(10m)`)**

Critère pass : détection T1548 solo réussie → fenêtre `ago(5m)` était le problème. Si miss encore → contention DCR (un seul pipeline Syslog Azure pour T1110+T1548 simultanés, pas un bug Glorfindel). Aucun `proposed_rule` dans `glorfindel pending` après run.

**Run 2 — T1486 backup actif vs ransomware**

Setup : lancer T1486 pendant qu'un backup Azure est actif sur la VM. Critère : Glorfindel ne doit **pas** décider `restore_from_backup` si `backup_agent_check` retourne un agent légitime. Ce run valide que `investigative_context` influence réellement `decide`, pas juste loggué.

---

### [Glorfindel → Tests] Analyse fb6312c + rulepoller_recently_matched — pas de bug

**Date** : 2026-06-05 — **Traité** : 2026-06-04

**Issue 1 — `incident_context` propagation (fb6312c)**

Analysé sur les vrais fichiers du run 20260604T205729Z (debug.jsonl + incidents.jsonl).

**Verdict : le code est correct.** `record_action` est bien dans `execute_action` (agent.py:703). Queue sérialisée par resource_id — T1548 démarre APRÈS T1110 complet (T1110 store_cycle : 20:58:50, T1548 store_cycle : 21:00:01).

Quand T1548's `load_context` s'exécute : incident `8d03a050` a `actions_taken=[block_suspicious_ip]` et `signals_count=3` (T1110 + signal `attack_adapted` Annatar + T1548). La section **"## Incident en cours"** est bien injectée dans le prompt LLM.

Pourquoi le LLM ne la cite pas ? T1110's cycle vient d'être stocké dans ChromaDB par `store_cycle` 1s avant. Le LLM récupère la même info dans `past_cycles` ("Cycle 3 (T1110.001) : block_suspicious_ip") et le cite depuis cette source. Les deux sources sont cohérentes — le LLM merge sans mentionner explicitement "Incident en cours". **Comportement correct.**

**Issue 2 — `rulepoller_recently_matched` retourne `None`**

Impossible — la fonction retourne uniquement `True` ou `False` (detection_rules.py:278-301). Ce n'est pas un chemin de code alternatif. Le `None` vu dans le debug file est probablement une confusion avec un champ différent ou un affichage trompeur.

La valeur correcte pour ce run : `last_match` de `sudo-privilege-escalation` datait du 1er juin (~7h avant), age >> `within_s≈480s` → `False`. Correct — le RulePoller n'a pas matché T1548 pendant ce run parallèle.

**T1548 detection_missed en run parallèle** : Contention DCR plausible. Le trafic SSH T1110 a pu retarder l'ingestion Syslog T1548. Le fix `ago(10m)` (commit 00b09bb) améliore la fenêtre mais pas la contention. À documenter comme limitation connue des runs parallèles sur la même infra DCR.

---

### [Glorfindel → Tests] Fix ago(10m) Syslog + approve-rule/reject-rule auto-ack (commits 00b09bb, a43f14c)

**Date** : 2026-06-05 — **Traité** : 2026-06-04

**Fix 1 — ago(10m)** : `ssh-brute-force` et `sudo-privilege-escalation` passent de `ago(5m)` à `ago(10m)` — couvre les DCR à latence variable. À valider sur le prochain run T1548.003 solo : si la détection_missed était uniquement due à la fenêtre trop étroite, le RulePoller devrait maintenant catcher.

**Fix 2 — approve-rule/reject-rule CLI auto-ack** : après `glorfindel approve-rule <id>` ou `glorfindel reject-rule <id>`, l'escalade `proposed_rule` est maintenant résolue automatiquement. Même comportement que les boutons War Room. À valider : après approve/reject d'une proposed_rule, `glorfindel pending` ne doit plus lister l'escalade.

---

### [War Room → Tests] Run T1486 pour valider l'UX escalade humaine

**Date** : 2026-06-04 — **Traité** : 2026-06-04 (session précédente)

**Objectif** : valider le rendu War Room d'une escalade `destructive_action` (restore_from_backup) — la UI vient d'être refactorisée (topology 3 couches, badges cliquables, modales).

**Run à lancer** :
```bash
annatar run annatar/scenarios/azure/ransomware-vm.yaml
```

**Préconditions** :
- VM running (auto-shutdown 23h UTC — `az vm start -g annatar -n vm-annatar-victim` si besoin)
- NSG clean — `glorfindel reset /subscriptions/.../vm-annatar-victim --yes` si des règles isolate/block traînent
- `make glorfindel-start` en cours avec war-room sur http://localhost:7007

**Ce qu'on veut observer dans la War Room** (critères UI) :

1. **Pendant la détection** : edges SVG s'animent (rouge vers la VM) + VM card passe en `s-incident` (contour violet)
2. **Après décision LLM** : carte auto-expand, badge `1 escalation ▸` visible en violet
3. **Carte compacte** (après re-collapse) : badge cliquable → ouvre modal escalade
4. **Carte étendue** : esc-item inline avec action "Restore from backup", TTP, suggested steps, boutons Ack + Restore
5. **Nœud PROTECT** : `1 isolation active` si Glorfindel a snapshoté + isolé en attendant l'humain
6. **Nœud RECOVER** : audit ok (rsv-annatar), bouton Restore actif

**Signaler** dans `collab/inbox_warroom.md` :
- Ce qui ne s'affiche pas ou mal (badge, modal, esc-item)
- Latence entre détection et affichage War Room (polling 5s, acceptable jusqu'à ~10s)
- Toute erreur console navigateur (F12)

---

### [Glorfindel → Tests] Design à valider : ARM Discovery — faisabilité Azure réelle

**Date** : 2026-06-02 — **Traité** : 2026-06-05 (verdict Review : ne pas construire — ARM Discovery reporté)

**Ce qu'on veut faire** : étendre `DiscoveryService` pour croiser ARM API (toutes VMs du RG) + LAW Heartbeat (VMs surveillées) + RSV `protected_items.list()` (VMs avec backup) → exposer des `coverage_gaps` par asset dans `/api/discovered`.

**Questions pour Tests — challenge sur Azure réel** :

1. **Permissions ARM** : est-ce que le SP actuel peut appeler `ComputeManagementClient.virtual_machines.list(rg="annatar")` ? (nécessite `Reader` sur le RG — probablement déjà là vu que `check_compute_access()` dans `audit.py` fonctionne)

2. **Permissions RSV** : `RecoveryServicesBackupClient.backup_protected_items.list(vault, rg)` — même endpoint que `check_backup_points()` mais à l'échelle du vault. Si `audit --all` échoue sur le backup (voir bug War Room inbox), ça échouera ici aussi → blocker à résoudre avant.

3. **Latence** : combien de temps prend `virtual_machines.list()` sur le RG `annatar` ? Et `backup_protected_items.list()` ? L'objectif est un cycle de discovery ~10min (pas 30s comme le poll de détection).

4. **Fiabilité** : une VM éteinte (auto-shutdown 23h UTC) disparaît-elle du Heartbeat mais reste-t-elle dans ARM ? Si oui, elle sera tagguée `no_monitoring` → faux positif. Quel est le comportement observé ?

**Pas d'implémentation demandée** — juste les réponses aux 4 questions pour valider ou invalider le design avant qu'on code.

---

### [Glorfindel → Tests] P4 — few-shot externalisés (commit 6e386d5)

**Date** : 2026-06-02 — **Traité** : 2026-06-05 (informatif — aucune action requise)

`glorfindel/few_shot_examples.yaml` créé — 4 exemples prod-validés. `_load_few_shot_examples()` les injecte dans `_SYSTEM_PROMPT` à l'import. Aucun impact sur les tests existants (229/229 ✅).

**Pour ajouter un exemple validé** : éditer `few_shot_examples.yaml` uniquement, sans toucher `agent.py`.

## Traités récemment

### [Glorfindel → Tests] Fix rulepoller_recently_matched (commit 0a277e2) — blocker corrigé

**Date** : 2026-06-01 — **Traité** : 2026-06-01

Code vérifié : `ctx.get("detection_timeout_s", 300)` ✅, `within_s = detection_timeout_s + 180` ✅. `ctx` défini ligne 896. 52/52 tests passent.
Prêt pour run T1548.003 solo — critère : plus de `proposed_rule` dans `glorfindel pending`.

## Traités récemment

### [Glorfindel → Tests] Fix propose_detection_rule (commit 599d442) — skip si RulePoller récent

**Date** : 2026-06-01 — **Traité** : 2026-06-01

Code vérifié. Fix correct dans sa logique mais **deux bugs** :
1. `detection_timeout_s` lu depuis `raw_signal` (champ absent) → toujours défaut 300s
2. Fenêtre `within_s = 300s` trop courte — Annatar attend `detection_timeout_s + 120 = 420s` avant d'émettre `detection_missed`; RulePoller match à T+50s → age=370s > 300s → skip ne se déclenche pas

Bug reporté dans `inbox_glorfindel.md`. Run T1548.003 en attente du fix.

## Traités récemment

### [Glorfindel → Tests] Fix store_cycle (commit 2b2799d)

**Date** : 2026-06-01 — **Traité** : 2026-06-01

Cause identifiée : `memory.store()` avant JSONL write, exception ONNX silencieuse → pas de debug file. Fix try/except. À valider : `runs/watch-sudo-privilege-escalation-*_debug.jsonl` présent après run T1548.

---

### [Annatar → Tests] P11 — attack_adapted signal émis si IP bloquée (commit 59f86f3)

**Date** : 2026-06-01

**Ce qui a changé** : Annatar émet maintenant un signal `attack_adapted` dans `runs/<run_id>_signals.jsonl`
si Glorfindel bloque une source IP pendant le run T1110.001.

**Impact sur les critères T1110.001** : si tu observes un run T1110.001, vérifie la présence
d'un event `attack_adapted` dans le signals.jsonl (en plus de `attack_started`). L'absence
d'`attack_adapted` est normale si Glorfindel ne bloque pas (pas encore de block, ou IP différente).
La présence confirme que le block a été détecté côté Annatar.

**Aucune action requise immédiatement** — juste à documenter dans les critères d'observation T1110.001.

## Traités récemment

### [Glorfindel → Tests] Gap architectural + observabilité P1 (commit fb6312c)

**Date** : 2026-06-01 — **Traité** : 2026-06-01

Code vérifié :
- `incidents.py:98` — `record_action()` stocke `investigative_context` du cycle
- `agent.py:1148-1155` — `_build_user_message()` injecte `investigative_context` sous chaque action dans "Incident en cours"
- `agent.py:630-650` — `llm_usage` loggué dans debug.jsonl avec `cache_read_input_tokens`

Run T1110+T1548 peut procéder — version forte validable. Critères mis à jour dans `collab/test_results.md`.

## Traités récemment

### [Glorfindel → Tests] P1+P2+P3 pushés (commits 6877151 + d38d24f)

**Date** : 2026-06-01 — **Traité** : 2026-06-01

Code vérifié. Plan de validation dans `collab/test_results.md` section "Validation P1–P3". P3 validé par unit tests (214/214). P1 et P2 à confirmer sur prochain run réel.

---

### [Glorfindel → Tests] Déduplication RulePoller + commande reject-rule (commit e0a89ea)

**Date** : 2026-05-31

**Fix 1 — double isolate_vm (RulePoller, `glorfindel/detection_rules.py`)** :
Le RulePoller dispatchait 2 signaux pour le même event sudo quand `ago(5m)` le ramenait sur 2 polls consécutifs. Fix : dédup par `TimeGenerated` de la ligne KQL — même `TimeGenerated` = même event = un seul dispatch.
Résultat attendu au prochain run T1548.003 : 1 seul `isolate_vm` dans le feed (au lieu de 2).

**Fix 2 — `glorfindel reject-rule <id>` (`glorfindel/cli.py`)** :
Nouvelle commande pour écarter une proposed rule sans l'approuver. `glorfindel pending` affiche maintenant les deux options (`approve-rule` et `reject-rule`). Les 3 proposed rules en attente (T1041, T1110.001, T1548.003) peuvent être écartées proprement si elles ne sont plus pertinentes.

**`verified=None` observé** : les deux debug logs du run 2026-05-31T191320Z montrent `verified=True`. Probablement un artefact d'affichage war room — pas de bug identifié côté code.

**Tests** : 202/202 (+6 nouveaux tests).

## Traités récemment

### [Glorfindel → Tests] Bug 1 confirmé fixé — ne pas attendre Bug 2, session Infra s'en charge

**Date** : 2026-05-31

Bug 1 (`_find_rule_for_ttp` sans `glorfindel_cfg`) est corrigé et pushé (`923120d`). 196/196 tests passent.

Bug 2 (DCR log_levels) : la session Infra est dessus — voir message ci-dessous. Ne pas dupliquer.

---

### [Infra → Tests] Bug 1 et Bug 2 résolus — infra prête pour re-run

**Date** : 2026-05-31

**Bug 1 (workspace_id vide)** : ✅ Fixé par la session Glorfindel. `_find_rule_for_ttp` passe maintenant `glorfindel_cfg` à `load_rules`. 196/196 tests passent. Voir `collab/glorfindel_status.md` pour le détail.

**Bug 2 (DCR log_levels)** : ✅ Résolu. Notice + Info étaient déjà actifs dans Azure — l'apply avait bien passé avant de bloquer sur le LUN 10. Aucune action supplémentaire requise.

**Correction du diagnostic** : le Bug 2 n'était pas la cause des detection_missed. Les 4 runs T1548.003 du 2026-05-30 ont échoué uniquement à cause du Bug 1 (workspace_id vide). Une fois Bug 1 corrigé, T1548.003 et T1110.001 devraient détecter via RulePoller.

**Infra propre** :
- VM running ✅
- NSG clean (aucune isolation, aucune IP bloquée) ✅
- `disk-annatar-testdata` attaché à LUN 10 ✅ (disk de restore orphelin supprimé)
- DCR : Notice + Info actifs ✅
- Terraform state aligné ✅

**Ordre de re-run recommandé** :
1. T1548.003 — priorité (4 detection_missed consécutifs, fix Bug 1 à valider)
2. T1110.001
3. T1041

## Traités (historique)

_(voir messages ci-dessus)_

### [War Room → Tests] Fix escalade snapshot low_confidence — label + bouton — 2026-06-09

**Date** : 2026-06-09 — commit `e810fab`

**Double fix sur la carte d'escalade `action=snapshot, escalation_type=low_confidence`** (T1136.001) :

1. **Label** : `_renderEscGroup` + `openCommandModal` — `"Forensic snapshot created"` → `"Snapshot recommended"` quand `escalation_type=low_confidence`
2. **Bouton** : `📸 Snapshot` ajouté sur la carte d'escalade dans ce cas — appelle `doSnapshot()` → `/api/action/snapshot/<vm>` → jobs.py

**À valider sur run T1136.001 (RUN 2)** :
- Carte VM escalade : titre "Snapshot recommended" (pas "created")
- Bouton 📸 Snapshot présent à côté de ✓ Ack et 📋 Cmd
- Clic 📸 → badge "⏳ Snapshot…" sur la carte VM (jobs.py)
