# Gothmog — pannes déclarées

Gothmog est le troisième agent de la boucle : Annatar attaque, Gothmog casse, Glorfindel détecte
et répond. Ses pannes éprouvent d'abord Glorfindel : **bruit bénin** (G1, il ne doit pas
isoler), **pannes de ses dépendances** (G2, il doit échouer fermé), **reprise** (G3, temps
mesuré).

## G0 — une panne déclarée, mesurée, réversible

Une panne est **déclarée en code** à deux endroits :

- l'expérience Chaos Studio, dans Celebrimbor ([`infra/terraform/chaos.tf`](../infra/terraform/chaos.tf),
  activable par `chaos.enabled` dans `config.yaml`) : la VM inscrite auprès du moteur (cible +
  capacité `Shutdown-1.0`), l'expérience d'arrêt **propre** de 5 minutes, son identité avec un
  rôle sur mesure attribué sur cette VM seule (la lire, l'éteindre, la démarrer : pas la
  supprimer) ;
- la panne vue par Gothmog, [`experiments/vm-shutdown.yaml`](experiments/vm-shutdown.yaml), au
  schéma d'expérience d'E1 (`kind: fault`, `engine: chaos-studio`) : ses cibles, son état normal,
  ses conditions d'abandon, son retour. Elle est aussi au catalogue (`technique_catalog.yaml`,
  `azure_vm.faults`).

Gothmog n'écrit jamais l'expérience : il la lit, la démarre, la suit, l'annule au besoin.
Modèle « Experiments (classic) » : les Workspaces, vers lesquels Microsoft migre, sont en
préversion publique et hors du provider azurerm (09/2026).

### Le déroulé d'un run ([`runner/engine.py`](runner/engine.py))

| Étape | Ce qui se passe | Refusé si |
|---|---|---|
| 0. Glorfindel | le battement de la watch, lu avant tout appel au cloud (V1, [`eregion_core/watch_gate.py`](../eregion_core/watch_gate.py)) : le canal retour s'il est configuré, sinon le fichier local `~/.glorfindel/watch_heartbeat` | aucun battement de moins de 90 s : refusé, et le message dit depuis quand date le dernier (ou « never ») ; `--without-glorfindel` passe, et le rapport le dit (`metrics.without_glorfindel`) |
| 1. Contrat | `arm(run_id, "gothmog")` ([`eregion_core/orodruin.py`](../eregion_core/orodruin.py)) | contrat passif (rien lu, rien touché) ; plafond sous 3 appels (démarrer, annuler, redémarrer la VM) |
| 2. Cibles | relues **dans l'expérience Chaos Studio elle-même**, puis chacune passée par l'inscription (O0, `kind="fault"`) | cible non déclarée par la panne ou déclarée absente ; sélecteur dynamique ; cible hors banc, non inscrite, en `production` ; arrêt brutal pour une panne déclarée non destructive ; durée au-delà du plafond du run |
| 3. Avant | sondes d'état normal sur chaque cible | une sonde ne tient pas, ou ne se lit pas |
| 4. Injecter | fenêtre d'exercice ouverte (`kind: fault`, publiée vers la watch hébergée), démarrage **journalisé avant l'appel**, signal `fault_started` | — |
| 5. Pendant | l'exécution suivie toutes les 30 s ; la panne doit être constatée (VM arrêtée) | au-delà de sa durée + 5 min, ou du plafond : l'expérience est **annulée** ; Ctrl-C : annulée aussi |
| 6. Après | les sondes à nouveau, Heartbeat **postérieur à la fin** de la panne, 10 min au plus ; si le moteur n'a pas ramené la VM : le retour déclaré (`start_vm`, journalisé), puis les sondes encore | le retour n'est « vérifié » que par une sonde, jamais sur la parole du moteur |
| 7. Enregistrer | `runs/<run_id>.json` comme Annatar, avec les valeurs des sondes avant et après (`metrics.before`, `metrics.after`, par VM) ; fenêtre fermée, puis, avec le canal, le rapport publié vers H0 (#193) ; signaux dans `runs/gothmog/` | — |

**Les sondes d'état normal** ([`probes.py`](probes.py)) : la VM en marche (`PowerState/running`),
son agent `Ready` (le système répond), son Heartbeat dans Log Analytics de moins de 10 minutes.
Le Heartbeat compte à part : Chaos Studio ignore les erreurs d'extension au redémarrage, une
panne peut « réussir » avec l'agent de supervision arrêté — et Glorfindel aveugle sur cette VM.
Tout passe par l'API de contrôle d'Azure (ARM), la seule sortie qu'Orodruin laisse ouverte —
Log Analytics compris, par sa requête via ARM.

**Les signaux ne vont pas où la watch décide.** La watch de Glorfindel envoie à son graphe de
décision tout événement de `runs/*_signals.jsonl` sauf `attack_started` : un `fault_started` là
lancerait un cycle de décision sur la déclaration elle-même. Les signaux de Gothmog vont dans
`runs/gothmog/<run_id>_signals.jsonl` ; Glorfindel apprend la panne par sa fenêtre d'exercice et
par sa propre télémétrie, comme pour une vraie panne.

### Lancer

Depuis Orodruin (contrat armé), gondolin allumée :

```bash
make gothmog-preflight      # watch de Glorfindel, contrat, cibles, état normal — rien d'écrit
make gothmog-run            # la panne et son retour vérifié (~15 min)
make gothmog-run WITHOUT_GLORFINDEL=1   # run de développement sans watch vivante, dit au rapport
```

Sur la VM : `gothmog run vm-shutdown [--yes] [--dry-run] [--without-glorfindel]`,
`gothmog preflight vm-shutdown [--without-glorfindel]`,
`gothmog report <run_id>`. Ailleurs (un poste d'opérateur), le contrat est passif : rien ne
part. `--dry-run` n'appelle pas Azure.

### Mesuré sur le banc (19/10)

Run `gothmog-20261019T200123Z`, depuis Orodruin armé : **PASS**.

| Instant (UTC) | Ce qui s'est passé | Source |
|---|---|---|
| 20:01:34.32 | `chaos_start` écrit au journal d'audit | Orodruin, `runs/orodruin/audit.jsonl` |
| 20:01:34.77 | début de l'exécution (0,45 s après le journal) | Chaos Studio |
| 20:02:06 | gondolin vue arrêtée par Gothmog (`stopping` dès 20:01:57) | Gothmog ; relevé indépendant |
| 20:07:30 | gondolin redémarrée par le moteur | relevé indépendant |
| 20:07:31 | exécution `Success` | Chaos Studio |
| 20:09:08 | premier Heartbeat après la panne | Log Analytics |
| 20:09:44 | retour vérifié (les trois sondes), 133 s après la fin, sans repli | Gothmog |

Glorfindel (la watch hébergée) n'a rien fait sur gondolin : aucun cycle, aucune escalade ; la
fenêtre `fault` était sur le canal, lisible par son identité. Avant le run, la sonde Heartbeat
avait **échoué fermé** : `last` est un mot de KQL (erreur de syntaxe) — l'état normal n'étant
pas vérifié, rien n'aurait été injecté ; la colonne s'appelle `LastSeen`.

### Mutants

M71 (panne lancée sans état normal vérifié avant), M72 (cible de l'expérience non inscrite
acceptée), M73 (retour déclaré sans être vérifié), M74 (signaux de panne là où la watch
décide) — mesurés par `tests/unit/test_gothmog.py`.

## G2 — les pannes des dépendances de Glorfindel

**Côté Glorfindel, fait le 21/10 (code)** : chacune des quatre dépendances — le modèle, l'API
du cloud, la télémétrie, la configuration — échoue fermé, prouvé par un cycle complet du graphe
et un mutant par panne (M151–M158 et M170–M178, `tests/unit/test_dependency_failures.py`). Détail :
[`docs/glorfindel.md`](../docs/glorfindel.md), « Pannes des dépendances ».

**Reste, sur le banc, avec Jonathan** : injecter ces pannes pour de vrai, depuis Orodruin, sur
un Glorfindel du banc, et constater les cartes attendues. Proposition, **non mesurée** (le moteur
ne sait aujourd'hui que l'arrêt de VM, `Shutdown-1.0`) :

| Panne | Injection envisagée | Attendu de Glorfindel |
|---|---|---|
| Modèle | règle de sortie refusée vers le fournisseur du modèle, sur le NSG de la VM de Glorfindel (faute Chaos Studio « NSG security rule ») | `cycle_failed` sur chaque détection, au plus 3 × 120 s après |
| API du cloud | règle de sortie refusée vers l'étiquette de service `AzureResourceManager` | VM jamais contrôlée tenue en `human_only` ; action tentée → `action_failed` |
| Télémétrie | règle de sortie refusée vers `AzureMonitor` | RulePoller en `last_error`, nœud DETECT rouge ; aucune action disruptive sur une enquête incomplète |
| Configuration | pas une faute de Chaos Studio (un fichier local) : reste un test | — |

À décider avant : la cible (H0 n'est pas inscrite, et un Glorfindel d'exercice sur le banc
serait plus sûr qu'une coupure de celui qui observe bree) ; l'inscription des NSG auprès de
Chaos Studio et de l'inscription O0 (`kind="fault"`) ; si la faute NSG accepte bien une étiquette
de service comme destination (à mesurer, pas à supposer).

## Règles

Aucune panne en zone `production` (inscription, O0) ; exécution depuis Orodruin ; une panne est
déclarée, réversible, et son retour est vérifié ; chaque lot ajoute ses mutants au harnais.

Feuille de route : [`ROADMAP.md`](../ROADMAP.md), « Vers la 1.0 ». Session : [`CLAUDE_GOTHMOG.md`](../CLAUDE_GOTHMOG.md).
