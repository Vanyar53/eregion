# Eregion — Roadmap & Priorités

## Objectif premier

Eregion est d'abord un projet **personnel** : un terrain pour apprendre l'IA et les LLM en profondeur — raisonnement agentique, RAG, génération grounded, évaluation — sur un usage de défense cloud dont j'ai réellement besoin. **Le plaisir de le construire et ce que j'y apprends priment sur l'adoption externe.**

Le pari assumé : la sécurité va vers la **réponse autonome** (vitesse machine des attaques → réponse machine), et Eregion explore cet espace sans le brider — mais sous contrôle (observe-only par défaut, garde-fous déterministes, tout produit LLM reste une proposition).

**Tout ce qui suit sur le positionnement produit, la concurrence et le SaaS est un scénario _optionnel_** — la voie « et si j'en faisais un produit ». Utile à garder en tête, ce n'est pas le juge de valeur du projet. Ne pas lire « pas d'utilisateur externe » comme un échec : ce n'est pas l'objectif poursuivi activement.

---

## Vers la 1.0 — huitième passe (13/10)

La 1.0 vise les fonctions d'un SOC pour les charges cloud des équipes sans SOC, **prouvées par l'attaque et par la panne**. Le cœur reste Glorfindel : détecter, enquêter, répondre. Annatar (attaque) et Gothmog (panne) l'éprouvent sur une copie jetable, depuis Orodruin, avec des moteurs publics — aucune logique offensive maison. L'objectif premier ci-dessus ne change pas : la 1.0 donne une finalité qui tranche les arbitrages, pas un plan d'affaires. Eregion tourne en local ou dans une VM ; le modèle économique SaaS viendra plus tard (1.x).

Périmètre à rappeler partout : **les charges cloud**. L'astreinte humaine et les postes de travail restent à une équipe ou à un SOC managé.

### La finalité et ses cinq indicateurs

Les incidents cloud courants sont contenus seuls, en quelques minutes, de façon réversible et vérifiée ; le reste arrive à un humain, trié et expliqué ; à tout moment, on peut prouver que ça marche. Annatar et Gothmog servent la confiance dans Glorfindel ; ils ne sont pas une fin.

| Indicateur | Ce qu'il mesure | Aujourd'hui |
|---|---|---|
| Temps pour contenir | de la première action malveillante à l'action vérifiée | détection par le RulePoller en 84 s à 3 min 30 (runs du 05 au 07/10) ; ransomware : RTO 21 à 25 min |
| Part contenue seule | incidents contenus sans humain, sur tous les incidents | non mesurée |
| Actions disruptives à tort | isolations et blocages jugés faux, parmi ceux qui sont jugés | pré-observation sur le banc depuis le 16/10 (H0, bree) : cartes jugées dans la War Room (TO JUDGE) ou Discord, résumé chaque lundi, `make glorfindel-host-report` ; le critère « parc réel » reste ouvert |
| Couverture | techniques cloud pertinentes détectées, sur le catalogue | 6 TTPs validés en réel (`technique_catalog.yaml`) |
| Âge de la dernière preuve | depuis le dernier run qui a prouvé détection et réponse | objectif : moins de 30 jours ; dernier run Azure de bout en bout : 07/10 |

### La règle de production

**Jamais de panne ni d'action destructive sur une charge réelle.** En production, seulement des techniques non destructives sur des VM inscrites, et la chaîne complète sur une VM sentinelle vide. Le destructif et les pannes restent sur le banc de référence ou le jumeau. La règle est codée dès O0 : chaque inscription porte sa zone.

| Zone | Ce qui y tourne | Refusé |
|---|---|---|
| `bench` — banc de référence (Celebrimbor) | techniques, destructif, pannes, reprise | — |
| `twin` — jumeau du client | idem, avec son rapport d'écart | — |
| `production` | mode ombre ; techniques `destructive: false` sur VM inscrites ; chaîne complète sur la VM sentinelle | toute panne, toute expérience destructive |

Seule la zone `bench` sert en 0.3 ; les deux autres sont codées et testées dès O0.

### Glorfindel de base, Glorfindel adapté

Glorfindel est le produit ; Annatar, Gothmog, Orodruin et Celebrimbor sont l'atelier qui l'éprouve. **Glorfindel de base** évolue par versions : surface surveillée, règles de base, actions, contrôles de préparation, garde-fous. **Glorfindel adapté** vit chez le client : ses règles, sa mémoire, sa retenue, ses marches ; une mise à jour ne doit jamais l'écraser (P1). Le modèle et les garde-fous ne s'adaptent jamais.

| Composant | Rôle | État |
|---|---|---|
| Glorfindel | détecter, enquêter, répondre ; son IA est l'IA sous test | existe |
| Annatar | adaptateurs vers les bibliothèques d'attaque publiques (Atomic Red Team, Stratus Red Team, Caldera) | existe, évolue (R1, R2) |
| Gothmog | pannes déclarées en code ; éprouve d'abord Glorfindel (bruit bénin, dépendances, reprise) | nouveau (G0) |
| Orodruin | hôte d'exécution jetable des injecteurs, contrat de garde-fous vérifié au démarrage | nouveau (O1) |
| Celebrimbor | construit et inscrit les cibles du banc | existe |
| IA d'analyse | explique, trie, rapporte ; n'écrit pas de règle | nouveau (IA0, IA1) |

### Les jalons

| Version | Contenu | Atteinte quand |
|---|---|---|
| 0.2.0 | publiée le 15/10 | — |
| 0.3 | A0 ✅, O0 ✅, E1 ✅, O1 ✅, R1 ✅, G0 ✅, B2 ✅, IA0 ✅ ; H0 en cours (4 semaines jusqu'au 13/11 environ) | la boucle complète tourne sur le banc et le rapport de campagne s'écrit seul — **✅ 23/10, v0.3.0** ; H0 continue, puis point d'étape #70 |
| 0.4 à 0.x | A1 (avec MC0), A2, A3, B1, B3, B4 ; G1 à G3, R2, C1 à C3, D1, IA1 ; J1 à J4, P1, P2 | couverture, retenue, robustesse et reprise mesurées ; la preuve existe en production (ombre, détection non destructive, sentinelle) et sur jumeau ; les règles du client survivent aux mises à jour |
| 1.0 | critères de maturité de la septième passe ; contrats figés ; profils | voir les critères ci-dessous |
| 1.x | MC1 à MC3, G4, X1, O2 ; plus tard, le SaaS | nouveaux clouds et moteurs ajoutés sans rien casser |

En 0.x, schémas, signaux et interface peuvent encore changer ; la 1.0 les fige.

**Critères de la 1.0** :
- Critères de maturité de Glorfindel remplis (liste « Critères avant le mode autonome », septième passe) : l'autonomie est permise en production, VM par VM.
- Contrats publics figés et versionnés : signaux, schéma d'expérience, catalogue, interface de fournisseur.
- Les cinq profils (découvrir ; ma détection marche-t-elle ? ; mon infra tient-elle ? ; défense éprouvée ; plusieurs équipes) s'installent et tournent seuls, prouvé en CI.
- La preuve en production existe : mode ombre, détection non destructive, sentinelle.

### Les lots

Préfixes : **A** isolation et **B** IA (septième passe), **O** Orodruin, **H** hébergement de Glorfindel, **E** schéma d'expérience, **R** adaptateurs d'Annatar vers une bibliothèque d'attaque publique, **G** Gothmog, **X** attaque et panne combinées, **C** couverture, **D** profils d'usage, **IA** IA d'analyse, **J** preuve en production et jumeau, **P** personnalisation (la couche du client — à ne pas confondre avec les points produit P1 à P4 de la septième passe), **MC** multi-cloud. Chaque lot ajoute ses mutants au harnais avant d'être fusionné ; aucune action sur le cloud hors du banc. Estimations en jours de travail effectif, à ±50 %.

**0.3 — la boucle tourne** (22 à 36 jours avec A0, H0 et IA0)

| Lot | Contenu | Fini quand | Jours | État |
|---|---|---|---|---|
| A0 | Invariants v3 (septième passe) | jeu de contrôle attrapé au moins pour moitié au push | 5–8 | ✅ 13/10 (10 sur 16) |
| O0 | **Inscription et périmètre communs.** Un module partagé réunit `annatar/campaign/scope.py` et `annatar/safety/guard.py`. Tag générique `eregion-target=<id du banc>`, posé par Celebrimbor (`annatar-test` lu le temps de la migration). Vérifié à la synthèse et à l'exécution. Chaque inscription porte sa zone ; en `production`, seule une expérience `kind: technique` et `destructive: false` passe. Mutants : contrôle à l'exécution retiré ; identifiant de banc vide accepté ; ressource hors des groupes du banc acceptée ; casse de la valeur du tag ignorée ; destructif ou panne accepté en `production` ; zone absente traitée comme `bench` | aucune injection hors cible inscrite, ni de destructif en production ; les six mutants attrapés | 3–4 | ✅ 14/10 — `eregion_core/inscription.py` (`guard.py` supprimé, `scope.py` ne garde que `Budget`, le manifeste n'a plus sa propre copie) ; le périmètre vérifie aussi l'abonnement du scope (il le nommait sans le contrôler) ; caractère destructif lu dans le scénario puis le catalogue, inconnu = refusé en production ; M42–M47 attrapés (harnais : cible de test par mutant) ; tags du banc dans `locals.tf`, **pas appliqués** ; zone absente : la règle appliquée est validée par Jonathan (15/10) ; l'apply des tags se fera à la prochaine session banc |
| E1 | **Schéma d'expérience et catalogue communs** : `id`, `kind` (`technique` ou `fault`), `engine`, `engine_ref`, `targets` (sélecteur sur l'inscription), `steady_state` (sondes et attendus), `abort_conditions`, `revert`, `detection.hints`, `destructive`, `status`. Les scénarios actuels deviennent `kind: technique`, `engine: local-script`, sans changement de comportement ; `technique_catalog.yaml` accueille les pannes ; schéma à côté de `schemas/scenario.schema.json` pendant la migration | tous les scénarios existants valident sous le nouveau schéma ; la CI valide le catalogue ; le schéma est versionné | 2–3 | ✅ 14/10 — `experiment.schema.json` (v1) + `technique_catalog.schema.json` + `eregion_core/experiment.py` ; `kind` absent = technique, `engine` absent = local-script → les 5 scénarios valident sans changement ; catalogue validé par `test_experiment_schema.py` (CI). **Relu en Opus 5.5 le 15/10** (écrit pendant un repli sur 4.8) : pannes dans une liste `faults:` à part (une panne n'a pas de TTP et serait sinon entrée dans le planificateur d'Annatar et `propose-rules`), technique d'un autre moteur sans `steps` ni script, avec son `engine_ref` (sinon R1 impossible). Reste pour R1/G0 : `target.type` au-delà d'`azure_vm` dans le synthétiseur |
| O1 | **Orodruin, mode VM dédiée.** `infra/orodruin/`, à côté de Celebrimbor, état Terraform séparé ; identité d'exécution limitée au groupe du banc ; sortie réseau limitée au banc, aux API du cloud et à celle du modèle ; `make orodruin-up`, `-down`, `-stop`, `-check`, `-kill` ; contrat non vérifié → injecteurs passifs ; `orodruin-kill` révoque l'identité et arrête la VM ; chaque appel d'un injecteur journalisé avant exécution. Mutants : contrat non vérifié mais mode actif ; journal écrit après l'appel ; arrêt d'urgence qui oublie la révocation | le contrat est vérifié au démarrage d'un vrai run ; l'arrêt d'urgence est prouvé par un test | 3–5 | ✅ 19/10, avec Jonathan (infra réelle). Décidé le 15/10 : identité managée attachée à la VM, rôle limité au groupe du banc, `orodruin-kill` retire son attribution de rôle ; feu vert pour la VM (environ 5 à 9 € par mois). **Partie A (code) écrite le 19/10**, branche `feat/o1-orodruin` : contrat lu sans écrire (`eregion_core/orodruin.py`), porte stricte dans `run` et `clean`, audit avant appel dans l'exécuteur, plafond, kill (`infra/orodruin/kill.py`), module Terraform et cibles Make, mutants M64–M66. **Partie B faite le 19/10, avec Jonathan** : VM D2als_v6 en francecentral, sortie fermée hors périmètre (mesurée) ; faux positif trouvé et corrigé : Azure ne liste que les attributions que l'appelant peut lire, d'où `contract_reader` et M67 ; le contrat tombe quand on le casse (attribution hors du banc, sortie rouverte) ; kill réel : premier refus moins de 3 s après la révocation, avant l'extinction ; **critère atteint** : vrai run T1136.001 sur gondolin depuis Orodruin, contrat `armed` au démarrage, audit écrit 0,6 s avant le Run Command (journal d'activité : appelant = identité d'Orodruin). **Partie C, le 19/10** : le canal des fenêtres B2 vers la watch hébergée. Un conteneur de stockage à Orodruin : Orodruin écrit, Glorfindel lit, Entra ID uniquement. Le contrat n'accepte que la portée du conteneur déclaré. Mesuré : publication depuis Orodruin, lecture depuis la VM de Glorfindel, écriture de Glorfindel refusée. Mutants M68–M70. **Déployé le 19/10** sur la VM de Glorfindel (`EREGION_EXERCISE_CHANNEL` dans son `host.env`) : la watch récupère le canal. **O1 terminé** |
| H0 | **Glorfindel hébergé, pré-observation.** Glorfindel tourne en continu sur une petite VM dédiée (« Eregion dans une VM », état Terraform séparé ; ni sur Orodruin, côté rouge, ni sur une VM qu'il surveille). **bree**, une nouvelle VM du banc, tourne en continu avec une vraie charge : un petit site, des crons, les mises à jour automatiques, la sauvegarde de la nuit ; non inscrite (aucun injecteur ne la vise : les exercices restent sur gondolin, qui garde son extinction automatique) ; himring en option, pour du trafic hostile réel. Verdicts et `glorfindel report` chaque semaine, exercices écartés par leur marquage (B2) | quatre semaines de `watch` sans trou ; le bruit bénin du banc est mesuré. Ne compte pas pour le critère « parc réel », qui reste ouvert | 2–3 | à faire, avec Jonathan (infra réelle) — décidé le 15/10. Précisé le 16/10 : groupe `rg-glorfindel` ; War Room et bot Discord sur la même VM (tunnel SSH, IP publique ouverte en SSH à l'IP de Jonathan seulement), lecture seule d'abord (`Reader` + `Log Analytics Reader`, `GLORFINDEL_READ_ONLY=1`, `human_only` forcé au push) ; bree en D2as_v6 (les fausses alertes de la règle ransomware y sont mesurables), site non exposé. **Déployé et vérifié le 16/10** (Jonathan applique : le mode auto refuse `terraform apply`) : bree tourne avec sa charge, refusée par l'inscription ; Glorfindel, War Room et bot dans `rg-glorfindel` (francecentral, D2als_v6 faute de capacité B2s et de quota Basv2) ; identité managée prise après correctif (variables vides), lecture seule suffisante, accès vérifiés, chaîne complète jusqu'à Discord en ~2 min (T1136 sur bree). Mutants M54–M56. **Tourne depuis le 16/10** : premières vraies cartes (brute force SSH depuis Internet sur bree, blocage recommandé et retenu, jugées) ; outillage d'observation livré les 16–17/10 — War Room (TO JUDGE, compteur, bandeau d'observation), bot Discord (verdicts, messages synchronisés, résumé du lundi), `glorfindel-host-status`, `glorfindel-host-pull` (copie des verdicts). **Modèle passé à `claude-sonnet-5-5` le 19/10** sur la VM d'observation (harnais : 36/36, 0 erreur sûre d'elle, contre 32/36 et 4 pour `claude-sonnet-4-6`) ; run de bout en bout avant toute autonomie |
| R1 | **Premier adaptateur : Atomic Red Team** (avant Stratus, décision du 15/10). Interface d'injecteur dans `annatar/executors/` (préparer, injecter, revenir, nettoyer) ; atomics en version épinglée, un test appelé par son identifiant (`engine: atomic`, `engine_ref`), exécuté dans la VM cible par Run Command, puis sa commande de nettoyage ; seulement les techniques `implemented` au catalogue, sur cibles inscrites, depuis Orodruin ; `attack_started` et `detection_missed` inchangés | un test de la bibliothèque tourne sur le banc, sur la télémétrie que Glorfindel lit déjà ; le nettoyage et l'état initial sont vérifiés après coup ; la détection est mesurée et enregistrée dans le run | 3–5 | **Code ✅ 20/10** (#156) : `annatar/atomics/` (T1136.001 épinglé au commit `9f6a1eab`, licence MIT, sha256 dans `PIN`), `annatar/engines/atomic.py` (refus en fermé), sonde avant, commande, preuve d'effet, nettoyage, sonde après, chaque Run Command au contrat d'Orodruin ; mutants M75–M97. **Premier run le 20/10** (`20261020T121319Z`) : PASS, mais `detection: unknown` (la watch tourne sur H0, le run ne la voit pas), détection mesurée à la main (109,3 s). D'où #157 (latence dans le run, détection antérieure à l'attaque ignorée, `resource_id` comparé sans la casse ; M98–M102), #158 (code de sortie non nul sur un refus ; M103–M108) et #159 (canal retour de la watch hébergée vers le run, #160 et #163 ; M109–M115). **Run de clôture le 20/10, R1 terminé ✅** : `20261020T143259Z`, T1136.001 depuis Orodruin `armed` sur gondolin, watch sur H0. PASS, `detection: detected` et `detection_latency_s` 44,7 inscrits par le run lui-même, par le canal retour : 4,5 s jusqu'au `useradd`, 38,4 s d'ingestion, 1,9 s jusqu'au RulePoller (horloges d'Orodruin et de H0 sur PHC0, à quelques µs près). Cinq Run Command journalisés avant l'appel (journal d'activité : appelant = identité d'Orodruin) ; `userdel` du nettoyage vu dans Syslog, état initial vérifié par la sonde d'après ; carte étiquetée `EXERCISE` sur H0 (`snapshot` à 40 %, escalade `low_confidence`) |
| G0 | **Gothmog v0, sur le moteur natif du banc.** Paquet `gothmog/` calqué sur `annatar/` (exécuteur, moteurs, signaux, rapport) ; moteur Chaos Studio, cibles inscrites auprès du moteur par Celebrimbor, expérience décrite en code dans le module du banc ; signal `fault_started` ; sondes d'état normal avant, pendant et après | un arrêt de VM tourne sur le banc ; l'état normal est vérifié avant et après ; le retour à l'état initial est vérifié ; le run est enregistré comme ceux d'Annatar | 2–4 | Feu vert le 15/10 pour Chaos Studio (11 à 42 € par mois), après O1. Plan validé le 19/10 (gondolin, arrêt propre de 5 min, modèle classique, identité de l'expérience limitée à sa VM). **Code ✅ 19/10** (`gothmog/`, `infra/terraform/chaos.tf` désactivé par défaut) : cibles relues dans l'expérience et passées par l'inscription, état normal avant/pendant/après (VM, agent, Heartbeat via ARM), annulation au-delà de la durée, retour vérifié par sonde avec repli `start_vm`, run au format d'Annatar, signaux hors de ce que la watch lit, actions Chaos Studio au contrat d'Orodruin ; mutants M71–M74. **Mesuré le 19/10, G0 terminé ✅** : `Microsoft.Chaos` enregistré, Celebrimbor appliqué (cible, capacité, expérience, rôle sur gondolin seule), rôle d'Orodruin mis à jour (`armed`), preflight depuis Orodruin (les trois sondes, Log Analytics par ARM à travers la sortie fermée). Run `gothmog-20261019T200123Z` : **PASS** — `chaos_start` journalisé 0,45 s avant le début de l'exécution, VM vue arrêtée 32 s après, exécution `Success` à 20:07:31 (5 min + redémarrage par le moteur), retour vérifié 133 s plus tard (Heartbeat postérieur à la fin), sans repli ; fenêtre `fault` publiée sur le canal et lue par l'identité de la watch ; **Glorfindel : rien** — aucun cycle, aucune escalade sur gondolin (attendu). Relevé indépendant de l'état de la VM et de l'exécution concordant. Trouvé au passage : `last` est un mot de KQL, la sonde Heartbeat échouait fermé (refus, rien injecté) — colonne `LastSeen` |
| B2 | Injection par les logs (septième passe), **élargie à la mémoire** : un cycle faux ou piégé, relu comme « similaire », ne doit pas faire basculer la décision ; mémoire mélangée — aujourd'hui `memory.py` stocke un `run_id` mais `retrieve_similar` ne filtre ni n'étiquette rien, un cycle d'exercice peut remonter comme précédent d'un vrai incident : chaque cycle porte désormais sa source (`exercise` ou `real`), visible du modèle | aucun cas d'injection, par les logs ou par la mémoire, ne change l'action décidée ; une mémoire remplie d'exercices ne fait pas basculer une décision réelle (cas au harnais) | — | première moitié ✅ 13/10 (0 sur 12 détourné) ; marquage décidé le 15/10 ; **côté stockage ✅ 16/10** : `eregion_core/exercise.py` (fenêtre ouverte par Annatar avant le setup, fermée en fin de run, expiration bornée), source `exercise`/`real` dans la mémoire et sur la carte, rapport d'observation sans les exercices, dédup séparée, mutants M57–M61. **Côté modèle ✅ 19/10** : cycles passés étiquetés [EXERCICE]/[RÉEL]/[source inconnue], jamais le signal en cours ; run de bout en bout (T1486 → isoler 0,80 ; T1110.001 → bloquer 0,88). Canal des fenêtres vers le `watch` hébergé : livré avec O1, partie C, et déployé le 19/10 ; les exercices lancés depuis Orodruin arrivent étiquetés sur la VM de Glorfindel. **B2 ✅ 19/10** : le cas au harnais du critère (`--kinds memory`). Une vraie menace avec des cycles passés tous `[EXERCICE]` et clos sans action (ransomware, force brute), et un cycle passé piégé qui porte une consigne au défenseur (exfiltration). Avec `claude-sonnet-5-5` : **0 bascule sur 9**, isoler ou bloquer à chaque fois, confiance moyenne 0,87 |
| IA0 | **Premier RAG : le rapport de campagne.** Collection ChromaDB distincte de celle de Glorfindel, runs indexés par campagne ; chaque affirmation du rapport cite le run qui la fonde ; un autre modèle que celui de Glorfindel ; aucune écriture de règle ; cas au harnais : fidélité (rien d'affirmé sans run cité), contenu piégé dans un run | le rapport de la première campagne s'écrit seul, chaque affirmation est vérifiable, les cas du harnais passent | 2–4 | **fondations ✅ 19/10** (`analysis/campaign_report.py`, `docs/analysis.md`) : faits tirés des fichiers, index `campaign_runs` séparé, affirmations typées vérifiées contre les runs cités, Haiku 5.5 ; premier rapport réel (campagne du 30/07 : 9 gardées, 1 écartée), harnais (0 obéissance à une ligne plantée) ; mutant M63 ; **s'écrit seul** à la fin de `annatar campaign run` (19/10). **Côté campagne ✅ 20/10 (#165)** : une campagne peut jouer l'atomic depuis le catalogue (T1136.001 en `engine: atomic`, synthétiseur qui écrit une expérience E1, détection et latence dans le manifeste, cible Make depuis Orodruin, reset sauté et inscrit) ; mutants M116–M125. Depuis Orodruin, le rapport s'écrit sur H0 (option B, décidée le 21/10 sur #69). **Code écrit le 21/10 (#167)** : Orodruin publie la campagne (manifeste et rapports des runs) sur le conteneur des fenêtres, sans droit nouveau. La watch de H0 la tire et écrit `report.md` une fois, avec les décisions de Glorfindel (action, confiance, escalade) retrouvées dans ses `watch-*_debug.jsonl` (règle de #157, bornée par la fenêtre du run). Index sur le disque de la VM. Tests dédiés (dont un bout en bout local) et mutants M126–M149 écrits le 21/10, M159–M169 après la quatrième relecture, M180–M186 après la cinquième, M187–M188 après la sixième (appel au modèle d'analyse borné) . **IA0 terminé ✅ 23/10** (#167, #69) : H0 redéployé (montage, image), image d'Orodruin reconstruite, puis la campagne `20261023T081120Z` depuis Orodruin (T1136.001 atomic, T1548.003, T1110.001, T1041 ; 4/4 détectées, de 101,6 à 130,0 s). Son rapport s'est écrit seul sur H0, une fois, 14 s après la publication. Les 4 décisions de Glorfindel sont rattachées chacune à son run (action, confiance, escalade), dont une détection au `resource_id` d'une autre casse (le cas de M129 en réel). 15 affirmations gardées, 0 écartée, toutes justes. Orodruin n'a publié que le manifeste et les 4 rapports de run, sans aucune autre écriture |

**0.4 à 0.x — la mesure, la preuve chez le client**

| Lot | Contenu | Fini quand | Jours |
|---|---|---|---|
| A1 | Découper `actions.py` (septième passe), avec **MC0** : l'interface de fournisseur | aucun SDK de fournisseur hors de son adaptateur (CI) ; le harnais reste au-dessus de son seuil | 3–5 (MC0) — **code ✅ 26/10** (#71, branche `lot/a1-decoupage-actions`) : `glorfindel/response/` (cœur neutre) et `glorfindel/providers/azure/` (seul adaptateur, un module par préoccupation, aucun au-delà de 430 lignes), `glorfindel.actions` reste le chemin d'import ; capacités déclarées, lues par la préparation ; `tests/unit/test_provider_boundary.py` en CI ; mutants M450–M459 |
| A2, A3, B1, B3, B4 | Septième passe, tableau ci-dessous ; B1 (Mistral) passe après la 0.3 (15/10) | — | — |
| G1 | Bruit bénin : écritures disque, CPU, redémarrages | taux de recommandations disruptives fausses publié | 3–5 |
| G2 | Pannes des dépendances : modèle, API du cloud, télémétrie, configuration. **Code ✅ 21/10** (#77, branche `lot/g2-pannes-dependances`) : appel au modèle borné (`GLORFINDEL_LLM_TIMEOUT_S`, 120 s) ; VM au contrôle de préparation injoignable tenue en `human_only` ; requête d'enquête en échec gardée à part, action disruptive retenue (`telemetry_gap`) ; configuration illisible → tout en `human_only`, `--mode` compris ; seuil de confiance, interrupteur de lecture seule et âge d'approbation qui ne s'assouplissent jamais sur une valeur mal écrite ; `tests/unit/test_dependency_failures.py`, mutants M151–M158 (8/8), puis M170–M178 après la relecture (9/9). Reste : la panne réelle sur le banc, avec Jonathan (`gothmog/README.md`, « G2 ») | chaque panne : échec fermé, test et mutant | 3–5 |
| G3 | Exercice de reprise : VM détruite puis restaurée | temps de reprise dans le README | 2–3 |
| R2 | **Adaptateur Stratus Red Team, avec l'ingestion des Activity Logs.** Version épinglée, cycle `warmup`, `detonate`, `revert`, `cleanup` ; le `warmup` crée sa propre cible, que l'inscription doit savoir décrire ; une règle sur les Activity Logs, proposée par la boucle violette sur le premier raté ; la réponse à une attaque d'identité (révoquer) reste à concevoir | une technique de la bibliothèque tourne sur le banc, et Glorfindel la voit dans les Activity Logs | 4–6 |
| C1 | Run unifié, matrice de couverture, non-régression | matrice et son évolution dans la War Room | 4–6 |
| C2 | **Identité : Entra ID en détection seule** (#199, décidé le 26/10). Journaux d'Entra vers le workspace du banc (tables, latence et licence mesurées) ; règles : identifiant ajouté à une application ou un principal de service (T1098.001), consentement et vol de jeton (T1528), rôle privilégié (T1098.003) ; escalade seulement, aucune action autonome sur l'identité ; inscription d'une identité du banc à définir (O0 ne lit que des tags) ; tenant de test à trancher. Après R2 | une technique d'une bibliothèque publique sur une identité inscrite, vue dans les journaux d'Entra et escaladée ; état initial vérifié | 5–8 |
| C3 | **Charges IA d'Azure : Azure OpenAI et AI Foundry** (#200, décidé le 26/10). Une ressource d'IA inscrite au banc ; détection : `listKeys` par une identité inattendue, clé volée utilisée ailleurs (T1496), pic de jetons, accès public ouvert, filtre retiré ; détection seule d'abord ; attaque par une bibliothèque publique seulement (à trouver pour le plan de contrôle). Distinct de B2, qui protège Glorfindel lui-même. Après R2 | une technique d'une bibliothèque publique contre la ressource d'IA inscrite, détectée et escaladée ; coût du banc dans le README | 5–8 |
| D1 | Profils d'usage, CI par composant ; `CONTRIBUTING.md` : les adaptateurs comme porte d'entrée des contributeurs | cinq profils documentés ; chaque composant tourne seul | 3–5 |
| J1 | Détection seule en production : techniques non destructives sur VM inscrites, Glorfindel forcé en mode ombre | couverture mesurée sur la vraie télémétrie, sans aucune réponse | 2–3 |
| J2 | VM sentinelle : une VM vide dans le réseau de production, inscrite | isoler, bloquer, lever sur la sentinelle ; état d'origine vérifié | 3–5 |
| J3 | Rapport d'écart : mêmes contrôles de posture et de préparation sur le jumeau et la production | chaque preuve sur jumeau porte son rapport d'écart | 3–5 |
| J4 | Jumeau depuis la découverte : Celebrimbor compose un banc depuis la topologie découverte | un jumeau sans code d'infrastructure, rapport d'écart joint | 5–8 |
| P1 | Couches de règles. Aujourd'hui `proposed_rules.approve` écrit la règle approuvée dans `detection_rules.yaml`, le fichier des règles livrées. À la place : la base livrée reste intacte, les règles du client vont dans une couche chargée par-dessus ; une règle du client peut désactiver une règle de base ; une commande exporte une règle généralisée, sans identifiant | une mise à jour de la base ne perd aucune règle du client (test) ; une règle exportée ne contient ni identifiant de ressource ni d'espace de travail (test et mutant) | 2–4 |
| P2 | Remontée d'une règle vers la base, en six étapes : proposer (accord du client, 30 jours active sans fausse alerte) ; généraliser (l'IA peut proposer) ; contrôler la fuite (déterministe : identifiants, adresses, domaines, noms de l'inventaire, dans la requête comme dans l'explication) ; relecture du client ; épreuve sur le banc de référence (détecte la technique, se tait face au bruit bénin, aucune régression) ; publication anonyme avec un jeton opaque | une règle remontée de bout en bout ; mutants : un GUID, une adresse ou un nom de l'inventaire qui passe le contrôle ; le client retire sa règle sans doublon | 4–6 |
| IA1 | IA d'analyse, mémoire et modèle séparés | cas d'analyse au harnais ; rien sans validation humaine | 4–6 |

**1.x — nouveaux clouds, nouveaux moteurs**

| Lot | Contenu | Fini quand | Jours |
|---|---|---|---|
| G4 | Moteur Kubernetes (Chaos Mesh ou LitmusChaos), puis générique (Chaos Toolkit) | une expérience, deux moteurs | 3–5 |
| X1 | Attaque pendant une panne | détecte ou escalade, jamais à l'aveugle | 3–5 |
| O2 | Orodruin, mode Kubernetes (un namespace par projet) | mêmes tests de contrat sur les deux modes | 5–8 |
| MC1 | Un monde simulé par fournisseur. **Avancé en code seul après A1 (décision du 26/10)** : faux AWS en mémoire et adaptateur écrit contre lui, rien sur un vrai compte ; la règle « pas de multi-cloud avant une boucle Azure solide » tient pour MC2 et MC3. **Fait en code le 26/10** (`tests/unit/fake_aws.py`, `glorfindel/providers/aws/`, `tests/unit/test_invariants_aws.py`) : invariants verts sur AWS jusqu'à 8 000 séquences, contrôle AWS 10 sur 16 (Azure 11 sur 16), mutants M600–M617 ; quatorze hypothèses d'AWS à mesurer en MC2 ([`docs/design/monde-aws.md`](docs/design/monde-aws.md)) | invariants et mutants de contrôle verts sur AWS | 8–12 |
| MC2 | Adaptateur AWS + banc AWS | isoler-lever revient à l'état d'origine, vérifié | 10–15 |
| MC3 | Adaptateur GCP + banc GCP | mêmes critères | 8–12 |

Plan complet : 66 à 108 jours, plus 30 à 45 pour le multi-cloud. Coût du banc de développement : environ 55 à 130 € par mois (VM, disques et points de restauration, télémétrie, Orodruin, Chaos Studio, LLM). En plus pour H0 : bree en continu (D2as_v6, ~71 €/mois) et la VM de Glorfindel (D2als_v6, ~61 €/mois ; 27 € en B2als_v2 avec le quota Basv2), plus disques, IP et sauvegarde.

### L'ordre de la 0.3

Socle : **O0 → E1 → O1 → R1 → G0**, R1 étant Atomic Red Team depuis le 15/10. En parallèle : **H0** (Glorfindel hébergé, pré-observation) et la piste IA, **B2 (élargi), puis IA0** (attend les premiers runs de R1 et G0) ; B1 passe après la 0.3. A1 (découpage d'`actions.py`, qui porte MC0) passe en 0.4+. O0 et E1 sont du code pur ; O1, H0, R1 et G0 créent de l'infra réelle et se font avec Jonathan.

Documents qui suivent les lots : `docs/architecture.md` (vocabulaire et zones, avec O0 et E1), `CLAUDE_ORODRUIN.md` et `CLAUDE_GOTHMOG.md` (sessions, créées le 13/10), `schemas/` (schéma d'expérience, E1), `docs/schemas/` (Gothmog, Orodruin, inscription, en 0.3), `CHANGELOG.md` (créé le 13/10 ; tag `v0.2.0` et première release GitHub publiés le 15/10, sur 517aa1b).

#### Suivi des priorités (déplacé de `CLAUDE.md` par DX1, le 15/10)

Huitième passe (13/10) — jalon **0.3, la boucle complète tourne** : Orodruin lance une technique publique et une panne sur le banc, retour à l'état initial, on mesure ce que Glorfindel a vu.

1. **O0** ✅ (14/10) — `eregion_core/inscription.py` : périmètre, tags `eregion-target`/`eregion-zone`, zones, refus du destructif et des pannes en `production`, 6 mutants (M42–M47) ; tags du banc écrits dans `locals.tf`, **pas appliqués** (avec Jonathan)
2. **E1** ✅ (14/10) — `schemas/experiment.schema.json` (versionné v1, technique ou panne, scénarios actuels valides sans changement) + `schemas/technique_catalog.schema.json` ; `eregion_core/experiment.py` ; catalogue validé en CI
3. **O1** ✅ 19/10 — Orodruin, mode VM dédiée (état Terraform séparé) — contrat vérifié au démarrage d'un vrai run, kill mesuré, canal des fenêtres déployé (#148, #150)
4. **R1** ✅ (20/10) — adaptateur Atomic Red Team (tests dans la VM, sur la télémétrie déjà lue) : run `20261020T143259Z` depuis Orodruin, la détection de la watch hébergée inscrite dans le run avec sa latence (44,7 s) par le canal retour (#156, #157, #159) ; Stratus, avec les Activity Logs, passe en R2 (décision du 15/10)
5. **G0** ✅ (19/10) — Gothmog v0 sur Chaos Studio : arrêt propre de gondolin depuis Orodruin, état normal vérifié avant et après, retour vérifié, run enregistré (#153)
6. En parallèle : **H0** (Glorfindel sur une petite VM dédiée, bree allumée en continu avec une vraie charge : pré-observation) ; piste IA, **B2** élargi (mémoire empoisonnée, source `exercise`/`real` de chaque cycle, marquée par un fichier de fenêtre que l'injecteur écrit — avant les premiers runs R1/G0), **IA0** (rapport de campagne par RAG, après R1/G0). **B1** (Mistral) après la 0.3

Ensuite (0.4+) : A1 avec MC0, A2, A3, B1, B3, B4, G1–G3, R2 (Stratus, Activity Logs), C1, D1, IA1, J1–J4, P1, P2. Toujours valable : le chronomètre d'observation (4 semaines en `human_only` sur un parc réel, verdicts + `glorfindel report`) ; la pré-observation sur le banc (H0) ne le remplace pas.

### Décisions du 15/10 (questions soulevées le 13/10)

- **R1 : Atomic Red Team d'abord.** Les 15 techniques Azure de Stratus Red Team visent le plan de contrôle (stockage, identité, Run Command par l'API, export de disque) : on ne les voit que dans les **Activity Logs**, que Glorfindel ne lit pas (ses règles lisent Perf, Syslog et StorageBlobLogs). Son `warmup` crée aussi sa propre VM, hors des cibles inscrites, et la réponse à une attaque d'identité (révoquer) n'existe pas encore. Atomic tourne dans la VM, sur la télémétrie déjà lue : c'est le chemin le plus court vers « la boucle tourne ». Stratus, avec l'ingestion des Activity Logs, devient R2 (0.x).
- **La mémoire avant les campagnes : un fichier de fenêtre.** Les campagnes de la 0.3 vont remplir ChromaDB de cycles d'exercice, que `retrieve_similar` remonte comme précédents de vraies décisions. L'injecteur écrit donc sa fenêtre d'exercice dans un fichier que le `watch` lit, et chaque cycle porte sa source (`exercise` / `real`), avant les premiers runs de R1 et G0. L'enregistrer en mémoire est du code seul ; la montrer au modèle change ce qu'il voit : run de bout en bout exigé.
- **Zone absente : la règle d'O0 est validée.** `annatar-test=true` vaut `bench` (il n'a existé que sur Celebrimbor) ; un `eregion-target` sans zone est refusé. L'apply des nouveaux tags du banc se fera à la prochaine session banc, `glorfindel list` vide avant.
- **Le chronomètre d'observation : une pré-observation sur le banc (H0).** Une VM du banc allumée mais vide ne produit presque aucun bruit bénin : quatre semaines sans fausse alerte n'y prouveraient rien. Une nouvelle VM du banc, bree, tourne donc en continu avec une vraie charge, non inscrite (les exercices restent sur gondolin), et Glorfindel tourne en continu sur une petite VM dédiée (précisé le 16/10). L'outillage démarre et le bruit se calibre ; le critère « quatre semaines sur un parc réel » reste ouvert.
- **Le reste.** Orodruin (O1) : identité managée attachée à la VM, rôle limité au groupe du banc, feu vert pour la VM. Chaos Studio (G0) : feu vert, après O1. B1 (Mistral) : après la 0.3. #105 (règle ransomware juste après un démarrage) : mesurée sur une DCR à 60 s avant d'être corrigée, à la prochaine session banc. Budget de `CLAUDE.md` : 25 Ko, confirmé. Release v0.2.0 : publiée le 15/10.
- **Point d'étape après la 0.3** : le premier rapport de campagne apprend-il sur Glorfindel quelque chose que le banc ne savait pas ? Si oui, la 0.x continue ; sinon, retour sur Glorfindel. **Décision du 23/10 (Jonathan, #70) : la 0.x continue, et le point d'étape sera rejoué** sur une deuxième campagne, après H0 (vers le 13/11). Le premier rapport (campagne `20261023T081120Z`) est fidèle, avec ses 15 affirmations justes et citées, mais il n'apprend rien que le banc ne savait. Son index sur H0 n'avait aucun run antérieur : il ne pouvait dégager aucune tendance. La seule nouveauté a été vue par la comparaison de la session Tests, pas par le rapport. Sur la même chaîne, T1110.001 a donné une isolation à 0,78, au lieu du blocage à 0,80 du 21/10, en contexte d'incident. Elle est notée pour B3 (#74). Avant de rejouer : donner à l'index du rapport sur H0 les campagnes passées (au moins celles du 21/10 et du 23/10), pour que les tendances deviennent possibles.

### Neuvième passe (23/10, sur la v0.3.0)

Relecture de l'atelier (partie 1, écrite le 20/10) et de ce que la 0.3.0 a mesuré (partie 2). Livrés le 26/10 : **D-1** (stabilité de la décision, #186, #190), **H-1** (une fenêtre d'exercice n'est plus crue sur parole, #187, #191, mesurée sur H0), **M-1** (l'arrêt d'urgence arrête ce qui tourne, #181, #189, mesuré au banc #196) et la console de l'atelier en lecture seule (#185) ; le rapport d'un run seul arrive sur H0 (#193, #194, vu sur H0 le 26/10 pour un run d'Annatar et un run de Gothmog ; reste l'affichage des sondes). Constats encore ouverts, routés en issues : **M-2** rôle d'injection sur la VM à vraie charge (#182, à la prochaine session banc), **D-2** comparaison entre campagnes calculée par le code, avant le point d'étape rejoué (#184, avant le ~13/11), **M-3** épingle de déploiement et verrou de dépendances de l'hôte (#183, avant de passer l'hôte en écriture).

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
- **✅ Premier run e2e de la campagne générative sur Azure réel** (2026-07-30, Celebrimbor `gondolin`, planner déterministe) — validé sur **2 runs complémentaires**. Run `non_disruptive` : garde-fou destructif écarte T1486 seul ; bleu détecte + **raisonne différemment par signal en autonome** (T1136 ambigu, confidence 35% → `snapshot`+escalade ; T1548 root confirmé, 93% → `isolate_vm`). Run `human_only` (même chaîne) : **détection 4/4** + décision correcte sur les 4 (gradient de confiance juste : 35% ambigu → 88-92% confirmés ; bonne action par signal — `block` sur brute force externe, `isolate` sur root). Calibration prod (modèle par défaut Claude) = contrepartie du harnais éval (les modèles locaux sur-confiants). **⚠️ Finding d'orchestration (backlog)** : en campagne enchaînée avec bleu **autonome**, une isolation posée à un scénario **persiste et casse les scénarios suivants** (AMA outbound coupé → télémétrie Syslog bloquée ; upload exfil sortant bloqué) → faux misses + sur-proposition de règles en double. Rouge (runner) et bleu (responder) sont découplés → rouge ne peut pas défaire l'action autonome de bleu. **Contournement validé** : lancer les chaînes en `human_only` (détection complète sans effet de bord). **Fixes livrés** (2026-07-30, PR #13 Annatar + #14 Glorfindel) : plancher fenêtre synthé ≥ latence P99 par source (`Syslog: 480`, Fix D) + catalogue aligné ; advisory `human_only` sur campagne multi-scénarios (Fix A) ; hygiène erreurs CLI Annatar (`_AnnatarCli`, message état terminal corrigé) ; côté Glorfindel — un raté sur un TTP **déjà couvert** ne produit plus une règle doublon mais une escalade `detection_blocked`/`investigate_detection_gap` qui **nomme l'isolation résiduelle** comme cause probable (Fix C). **Fix B tranché** : **pas** de reset cross-conteneur — `glorfindel reset` depuis le conteneur annatar est un no-op silencieux (état découplé) et auto-désisoler entre scénarios serait sémantiquement faux (un défenseur ne désisole pas pour laisser passer l'attaque suivante) → les chaînes se lancent en `human_only`. **Follow-up ouvert (à arbitrer)** : donner à `reset` un mode « source de vérité = Azure » (retirer les règles `glorfindel-*` des NSG de la VM même **sans** état local — aujourd'hui un état local perdu/déplacé rend une isolation irrécupérable par la CLI). Dépasse le cas campagne ; chemin isolation critique → exige une validation Azure réelle avec la session Tests.
- ~870 tests (~30s), 0 appel Azure, 0 appel LLM, 0 écriture ~/.glorfindel — hermétiques par construction ; CI GitHub Actions (ruff figé + pytest, py3.11/3.12, macOS) ; invariants par propriétés (Hypothesis) sur un faux Azure dont le monde client bouge, avec deux écrivains à la fois, 500 séquences par push, 10 000 chaque nuit ; mesurés par mutation (17 sur 22 bugs réinjectés attrapés au push à chaque tour) ; 17 défauts trouvés par la machine, aucun par les revues. Schémas : `docs/architecture.md`, `docs/design/preuves.md`
- **Revue de code du 14/09 + contre-revue (2026-10-05, branche `fix/revue-code-2026-10`)** — tous les constats traités en code + tests (59 tests ajoutés). Sûreté : NSG de NIC **partagé** traité comme partagé (une isolation autonome coupait toutes les VMs derrière le NSG) ; isolation/block **partiels** enregistrés au lieu d'orphelins ; `release` vérifié par « aucune NIC isolée » (le prédicat inversé validait une VM à moitié isolée, CLI comprise) ; `release`/`unblock`/`reset` ne masquent plus les échecs ; vérif du block sur les **deux** sens ; précondition déterministe sur la levée autonome (`recovery_complete` seulement) ; garde-fou Syslog réservé aux motifs curés ; gate VM d'Annatar branchée (`run` + `clean`) ; War Room en loopback + jeton optionnel. Robustesse : toute exception d'un cycle → escalade (`action_failed` / nouveau `cycle_failed`), y compris l'échec LLM en `human_only` ; snapshot autonome **toujours** asynchrone (un snapshot bloquant a tenu la file d'une VM 4h25 en run réel) ; watch insensible aux lignes corrompues ; posture : erreur transitoire ≠ gap critique. Bugs annexes : `/api/audit/<vm>` en 500 à chaque appel depuis le 18/06 (`import os` manquant) ; tests qui interrogeaient le vrai LAW quand une config locale existait. **Suite (2026-10-05, PR #16)** : (1) **constat réel sur le banc** — `allow-ssh` en priorité 100 sur le NSG de subnet passait avant les deny de Glorfindel : une VM « isolée » restait joignable en SSH et un blocage d'IP laissait passer un brute force SSH, avec `verified=True` (vérification de présence seule). Détection ajoutée (vérification + audit « NSG precedence »), `allow-ssh` passé à 1000 sur le banc (appliqué). (2) **Validé en réel** : isolate/verify/release/verify_release, block/verify (deux sens)/unblock, snapshot asynchrone (job de la VM retrouvé dans le RG du vault). (3) Hypothèse « casse des noms casse le restore » **réfutée** par mesure (8 points dans les deux casses). (4) `reset --from-azure`, topo `sharednsg`, chips War Room `partial`/`bypassed`, page de jeton, fix `--help` des CLI, ruff figé. **⚠️ Reste à valider sur Azure réel (session Tests)** : restore complet + RTO sur Celebrimbor (dernier réel : 09/06, ancienne sandbox), topo `sharednsg`, isolation partielle multi-NIC, release sur NSG verrouillé, panne LLM → `cycle_failed`, jeton War Room dans un navigateur.
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

## Chantier en cours — Module d'isolation compatible IaC (décidé 2026-10-05)

Conception complète : [`docs/design/module-isolation-iac.md`](docs/design/module-isolation-iac.md).

**Pourquoi** : le constat du 05/10 sur le banc (`allow-ssh` en priorité 100 devant les deny de Glorfindel, isolation et blocage SSH inefficaces avec `verified=True`) montre que le mécanisme actuel — règles créées pendant l'incident, règles client décalées — entre en concurrence avec la numérotation du client **et avec son Terraform** : un `terraform apply` supprime les règles ajoutées à un NSG à règles en ligne, rétablit une règle décalée ou une association changée.

**Direction** : Terraform possède la structure, Glorfindel ne change que l'état de l'incident. Un module Terraform fourni par Eregion, ajouté une fois au code du client, déclare une ASG de quarantaine par VNet, deux règles deny en priorité 100 qui la visent, une règle « liste de blocage » en 101 dont Glorfindel gère le contenu (`ignore_changes`), et un rôle Azure minimal. Isoler = mettre les NICs dans l'ASG ; bloquer = ajouter l'IP à la liste. Le code source du provider azurerm confirme qu'une appartenance à une ASG ajoutée hors Terraform est conservée sans dérive. Plage réservée : 100–101, visible dans le code du client. AVNM : lecture seule, pour détecter un Always Allow.

**Décisions ouvertes** : portée du blocage (périmètre du NSG proposé), NSG à règles en ligne (migration ou repli), sessions déjà établies (non coupées par un NSG — à mesurer, puis action complémentaire).

**Étapes** : mesure des sessions établies → module Terraform + migration du NSG du banc → prototype plan/apply sans dérive → connecteur (ancrages, repli sur l'existant) → audit → documentation.

**Run Azure du 05/10 (deux agents, rapports dans `collab/test_run_2026-10-05_*.md`).** Validé : `cycle_failed`, jeton War Room, release sur NSG verrouillé, `reset --from-azure`, NSG de carte partagé, isolation partielle multi-NIC, restore `--wait` (RTO 24 min 42). Trouvé et corrigé : RulePoller aveugle aux lignes ingérées tard (fenêtre de 60 s), détection dispatchée pour toutes les VMs (requête non filtrée par VM), déduplication sans effet sur les lignes agrégées, restore qui rejoue la dernière commande Run Command, sessions ouvertes non coupées, `detection_time_s` mesuré depuis le signal, `glorfindel list` muet sur une isolation partielle, approbation War Room sans vérification, posture qui ignorait `exceptions:`. Ouvert : faux positif probable au démarrage (pic à 52 Mo/s pour un seuil à 50), à trancher avec plus de mesures ; T1486 détecté par le RulePoller seul à rejouer.

**Seconde passe de l'analyste (05/10) — plan en lots.** L'analyste propose de garder l'activation en un clic : les règles posées à la volée restent le mécanisme par défaut, durci pour trois situations (préséance, carte sans NSG, NSG géré en IaC), et le module devient un renfort optionnel. Choix entre « module prérequis » et « module renfort » : à trancher.

| Lot | Session | Contenu | État |
|---|---|---|---|
| L1 | Glorfindel | Échec de vérification émis en `verification_failed` (était rangé en « detection timeout ») ; type d'escalade tiré de la garde ; préséance illisible → `verified=None` ; `revoke_temp_access` retenue (pas d'implémentation) ; plus de repli `rsv-annatar` ; ombrage au nom legacy ; ombrage du blocage de périmètre ; tests du poller sans durée fixe | ✅ |
| L2 | Tests | Une session SSH ouverte survit-elle à l'isolation ? **Oui** (mesuré le 05/10 : session active 17 min, inactive 11 min, téléchargement sortant ; nouvelles connexions refusées ; Run Command passe et `ss -K` coupe tout). Reste : NSG accroché, ASG, Accelerated Networking | ✅ (règle NSG) |
| L3 | Glorfindel | Ne plus déplacer de règle client ; poser le deny dans l'autre NSG (carte ou subnet) quand l'un est contourné ; verdict « contourné » gradué selon le port de la menace | ✅ (06/10) |
| L4 | Glorfindel + Infra | Isolation JIT : NSG de quarantaine sur chaque carte le temps de l'incident (NSG client échangé puis remis ; repli sur les règles si refusé). Terraform mesuré sur le banc (8 tests) | ✅ code (06/10), validation banc en cours |
| L5 | Glorfindel | Réaffirmer les isolations et blocages actifs (reposer une fois avec alerte, escalader si la règle disparaît encore, sans boucle contre Terraform ou un humain) | ✅ (06/10) |
| L6 | War Room + Glorfindel | Bouton d'activation : contrôle de préparation et résumé par VM (07/10). Puis le **verrou de préparation** : un mode autonome venu du défaut global, d'un motif ou de `--mode` n'agit seul que sur une VM contrôlée prête (ou dont les réserves ont été confirmées) ; nouvelle VM contrôlée dès sa découverte ; réserve apparue après l'activation → retour en `human_only` + alerte | ✅ (07/10), validation banc en cours |
| L7 | Glorfindel | Couper les sessions ouvertes après isolation : **fait** (`drain_connections`, `ss -K` par Run Command, vérification en échec si des sessions restent). `revoke_temp_access` retirée du prompt le 06/10 (run e2e) ; le prompt T1548 devient vrai quand la coupure réussit | ✅ |
| L8 | Infra + War Room | Module « renfort » Terraform et Bicep (ASG par ipConfiguration, liste de blocage avec sentinelle et garde contre les préfixes larges) | après L6 |
| L9 | plus tard | PR dans le dépôt du client ; provenance de `recovery_complete` ; signaux écrits pendant un redémarrage du watch | — |

**Troisième passe de l'analyste (07/10) — huit lots de plus.** Tous les constats hauts recoupés dans le code ; deux sont des régressions des correctifs B6 et B8 (règle ransomware muette à l'échantillonnage Azure par défaut, règle sudo aveugle en multi-VM). T11 (le bouton L6 contourné par le mode global) était déjà fermé par le verrou de préparation (#28).

| Lot | Session | Contenu | État |
|---|---|---|---|
| L10 | Glorfindel | Pas de succès sur une inconnue : levée autonome seulement si la neutralisation est confirmée (`is True`) ; Windows (`unsupported`) ou comptage des sessions en erreur ⇒ non vérifié ; NSG d'origine inconnu ⇒ la carte reste en quarantaine, et la levée relit la carte pour confirmer que l'original est revenu ; tags d'origine sous verrou + relecture (échange annulé sinon) ; « not found » seulement sur 404 ; règle illisible ≠ règle disparue (la réaffirmation ne repose plus sur une erreur de lecture) | ✅ (07/10) |
| L11 | Glorfindel | Bonne cible : action refusée hors de l'abonnement du connecteur (`WrongSubscriptionError`, préparation `other_subscription`) ✅ ; plus d'attribution par défaut à une VM unique ✅ (L13) ; routage par ID de ressource et par nom d'hôte ✅ (L13)  ; registre de découverte indexé par ID de ressource (deux VMs de même nom d'hôte = deux actifs) ✅ ; nom d'hôte ambigu → aucune attribution ✅ ; règles livrées qui sortent `_ResourceId` ✅  ; état local indexé par nom **et** ID (`<vm>--<hash>.json` : deux VMs homonymes partageaient `isolation/<vm>.json`, lever l'une effaçait l'état de l'autre ; ancien fichier lu seulement s'il est le sien, migré à l'écriture ; le message au LLM lit l'état par ID) ✅ ; War Room : un nom de VM ambigu (homonymes) est refusé en 409 au lieu de viser la première trouvée ✅ ; reste : clients par abonnement (aujourd'hui : refus) | en partie |
| L12 | Glorfindel + War Room | Un seul écrivain par VM : verrou par VM (thread + flock, réentrant) autour d'isoler / lever / bloquer / débloquer / `reset --from-azure` ; la réaffirmation relit l'état sous ce verrou ; levée et déblocage notent leur intention avant de toucher Azure (`releasing_at`, `unblocking_at`), levée ou déblocage partiel laissés à l'opérateur ; timeout War Room 60 s → 600 s. Plus léger que la file unique proposée, même effet | ✅ (07/10) |
| L13 | Glorfindel | Détection : **une requête par règle et par cycle** (un thread par règle, `run_query`), lignes **routées** vers la VM qu'elles nomment (`_ResourceId`, `Computer`) ou dont l'IP privée a fait l'appel (`CallerIpAddress` → table IP → VM lue sur Azure, cache 5 min — T1041) ; ligne nommant une VM non surveillée ignorée ; ligne non attribuée envoyée **une fois**, ancrée sur une VM, `unattributed` + `candidates` (isolation **et** blocage retenus) ; dédup par **ensemble d'identités** avec expiration, enregistré après l'envoi ; une ligne d'événement par cycle et par VM ; règle SSH par `SourceIP, Computer` ; client Log Analytics mis en cache. Rejoué sur 10 jours de données réelles : ransomware et 12 brute force routés vers gondolin. **Validé en réel le 07/10** : T1110 (détection T0+~125 s, routée par `Computer`) et T1041 (ligne `CallerIpAddress = 10.10.1.4:50374` attribuée à gondolin par la table IP → VM, `isolate_vm` 92 % retenu par `human_only`) | ✅ (07/10) |
| L14 | Glorfindel + Infra | Règle ransomware valable à 60 s (cadence lue dans les données : 2 échantillons > 45 Mo/s à ≤ 25 s, sinon 1 échantillon > 25 Mo/s — rejouée sur 10 jours : 4 attaques sur 4, aucun bénin) et règle sudo sans `limit 1` ✅ ; avertissement au chargement pour `limit`/`take`/`top` ✅ ; audit « Disk write sampling » : cadence réelle lue dans les données Perf de la VM (fin / grossier / **compteur absent = règle aveugle**) ✅ — gondolin ~11 s ; **seuil grossier mesuré le 07/10** (DCR du banc passée à 60 s le temps d'un T1486 : échantillons 8,7 puis 42,2 Mo/s, détecté à T0+~3,5 min ; 45 l'aurait raté ; DCR remise à 10 s) ✅ ; reste : bénin mesuré à 60 s réels, second abonnement, Windows, homonymes au banc | en partie |
| L15 | War Room + Glorfindel | Mode global via la préparation ✅ (#28) ; escalades retenues (`low_confidence`, `uncharacterized_signal`, `unattributed_signal`, `release_hold`) titrées « held » avec « Approve & execute », plus « VM isolated » pour une isolation non faite ✅ ; Restore en un clic (bot, TUI, Cmd) seulement après un snapshot ✅ ; un `verification_failed` garde `verified`/`shadowed_by` dans le debug et ChromaDB ✅  ; droits vérifiés là où ils s'appliquent (cartes, VNet `subnets/join`, NSG de quarantaine, NSG du client pour la levée, NSG des règles, VM), pagination suivie, préparation `release_blocked` ✅ ; libellés ✅ | ✅ (07/10) |
| L16 | Glorfindel + Infra | Restore : « neutralisée » seulement si la commande inoffensive a fini (`poller.done()`) ; extensions CustomScript et Run Commands managés (v2) listés — s'il y en a, levée retenue (champ lu dans `properties`, forme du SDK 38 mesurée) ✅. Canary : code de sortie de l'`apply` vérifié, contrainte de version paramétrée, quotidien sur 3.x / 4.x / 5.x, rouge sans secrets ✅ — **joué le 07/10 : PASS sur azurerm 3.117.1 et 5.8.0** (5.x n'avait jamais été testé). Reste : cas « déjà existant », remplacement forcé, Bicep | ✅ (07/10) |
| L17 | Glorfindel + Tests | Quarantaine renforcée : deny `AzurePlatformDNS` / `AzurePlatformIMDS` — **mesuré le 07/10** : avant, une VM isolée résolvait encore les noms et atteignait IMDS (jeton d'identité managée) ; après, résolution système et DNS direct bloqués, IMDS bloqué, Run Command toujours fonctionnel, tout revient à la levée ✅ ; accès forensique configurable (`isolation.forensic_sources`, allow avant le deny, sessions épargnées par la coupure) ✅ ; « non tenable » (Bicep, réconciliateurs continus) annoncé par la préparation ✅ ; NSG par abonnement : implicite (actions refusées hors de l'abonnement du connecteur) | ✅ (07/10) |

**Quatrième passe de l'analyste (07/10, soir) — sept lots.** Constats confirmés ; la plupart portent sur le code livré le jour même (#28 à #39). Le plus grave est ancien : la levée au TTL (Q1).

| Lot | Session | Contenu | État |
|---|---|---|---|
| L19 | Glorfindel + War Room | Le TTL **escalade** (`ttl_exceeded`, une carte par isolation, action `review_isolation`), ne lève plus jamais — watch et `check-ttl`. Approbation : carte non attribuée refusée, carte plus vieille que `GLORFINDEL_APPROVAL_MAX_AGE_H` (2 h) ou antérieure à un restore refusée, IP = une seule adresse (`single_host_ip`, aussi dans `block_suspicious_ip`). Marqueur de levée/déblocage de plus de 30 min → alerte unique « interrompue », jamais de ré-isolation. Verrou avec délai pour les tâches de fond. Boucle du watch : chaque tâche protégée séparément. Restore en un clic seulement sur une carte de restore (un snapshot retenu n'a jamais eu lieu) | ✅ (07/10) |
| L18 | Glorfindel | Une identité de VM : préparation indexée par `nom--hash(ID)` (un homonyme n'hérite plus du verdict « prête » ni des réserves acquittées ; nom ambigu ⇒ VM retenue) ✅ ; fichiers d'état en minuscules (une VM, un fichier, quelle que soit la casse de l'ID) et nom de VM tiré de l'ID (`web--01`) ✅ ; séries ransomware et agrégat sudo par `_ResourceId` (résultats identiques sur 10 jours réels) ✅ ; reste : verrous, autonomie (motifs par nom), alertes, jobs, garde d'abonnement à la construction des requêtes (Q13) | en partie |
| L20 | Glorfindel | Périmètre vérifié par son contenu. Q5 : sources forensiques validées (adresse ou ≤ 256 adresses, ni tag ni `*`), TCP 22/3389 seulement, filtre shell échappé, réserves `forensic_access` / `forensic_rejected` ✅. Q6 : NSG de quarantaine lu et remis par le contenu de ses règles, règles étrangères retirées, NSG sans notre tag jamais adopté ✅ (mesuré : le NSG du banc est lu intact). Q7 : tag `none` explicite, tag absent = inconnu (la carte reste en quarantaine), création sous verrou ✅. Q11 : `verified=None` après isoler / lever / bloquer → escalade, agent et War Room ✅. Q15 : **impossible tel que proposé — mesuré** : Azure refuse une règle DNS/IMDS dont la source n'est pas `*` (`InvalidDNSExfilSourceTag`), donc le repli par règles ne peut pas les refuser à une seule VM ; il le déclare (`platform_open`, réserve de préparation), et la quarantaine les bloque (remesuré sans cache : DNS direct, résolution système, IMDS bloqués) | ✅ (08/10) |
| L21 | Glorfindel | Attribution IP par VNet, IP ambiguë ⇒ non attribuée ; règle T1041 (PutBlock, identité, port hors identité) | ✅ 13/10 — IP ambiguë = non attribuée ; règle T1041 : PutBlock, port hors identité |
| L22 | Glorfindel + Tests | Cadence grossière : signal sans isolation autonome ; ligne de base par VM | à faire |
| L23 | Glorfindel + War Room + Infra | Restore : liste blanche d'extensions ; secrets `-e NOM` ; canary : remise vérifiée, version comparée | à faire |
| L24 | Tests | Invariants : machine à états Hypothesis sur un Azure en mémoire (évaluation NSG, politiques, 429, crash avant/après écriture, disque plein, `terraform apply`, redéploiement de carte, état perdu), 7 propriétés (jamais plus ouvert que conçu, configuration client intacte, pas de succès sur un mensonge, pas d'effet sur une autre VM, réaffirmation qui n'ouvre rien, un fichier d'état par VM, tout se lève). **Sept défauts trouvés et corrigés** : nom de règle commun aux homonymes (isolation de l'un qui rouvre l'autre, vérification vraie sans isolation), présence par nom prise pour une preuve, levée `released` avec une carte encore isolée (état réécrit par une ré-isolation interrompue, NSG d'origine masqué par la quarantaine), any/any sur un NSG partagé qui semblait dédié, subnet illisible pris pour « sans NSG », reste contourné qui masquait un deny sain, seconde carte oubliée par `reset --from-azure`. Mesuré sur le banc (quarantaine, repli, levée sans état). Passage profond nocturne Linux + macOS. **Blocages ajoutés à la machine (08/10)** : deux défauts de plus — `unblock_ip` sans état disait `unblocked` en laissant les règles (balaie maintenant chaque carte, ne compte que ce qui existait) ; `verify_block_ip` lisait « contourné » un blocage sain à côté d'un ancien placement contourné (vérifié par carte). Reste : banc « chaos » sur Azure réel | ✅ (08/10) |

**Cinquième passe (07/10, nuit).** #40 tient entièrement ; #41 avait une régression critique (C1) sur les disques insensibles à la casse.

| Lot | Contenu | État |
|---|---|---|
| L18-bis | C1 : jamais supprimer un fichier qui EST la cible (`samefile`) — sur macOS/Windows/Docker Desktop, enregistrer l'état d'une VM à majuscule le supprimait. C2 : état retrouvé par son hash quelle que soit la casse, variantes nettoyées à l'écriture, migration au démarrage du watch (`migrate_state_files`). C3 : `rsplit("--", 1)` dans la préparation. C4 : `/api/state` lit la préparation par ID (homonymes : mode le plus permissif + « ambiguous ») ; `revoke` par nom touche tous les homonymes. CI : job macOS (APFS, insensible à la casse) ; protection de branche sur `main` avec checks requis | ✅ (07/10) |

**Sixième passe (08/10).** L'auditeur a soumis les invariants à un test par mutation : ils attrapent tout ce qu'ils modélisent, mais 6 classes de bugs historiques sur 9 passent, parce que le monde du client ne bouge jamais. Un constat haut côté code (S1).

| Lot | Contenu | État |
|---|---|---|
| L25 | S1 : config illisible ⇒ isolation refusée (`ConfigError`, préparation `config_unreadable`) ; toute quarantaine de Glorfindel sur la carte = ré-application ; retour de `_set_nic_nsg` vérifié ; `forensic_ports` validé. S2 : blocages vérifiés par contenu, allow `glorfindel-*` comptée. S3 : migration avec contrôle de l'ID. S4 : `reset --from-azure` lit ses échecs. S5 : pollers arrêtés à la fin de chaque test, garde « rien hors du bac à sable ». S6 : seules les allow avant nos deny altèrent la quarantaine | ✅ (12/10) |
| L26 | Invariants v2 : monde client qui bouge (règles ajoutées / restreintes / retirées, NSG et VM supprimés, IP changée, politiques, tags perdus, 403 persistant, API throttlée, config changée ou illisible), I2 par auteur, I7 compatible Q7, I8 (ce qui est sur Azure est dans l'état), I9 (pas de ré-isolation d'une levée commencée), I10 (config respectée), I4 direct sur NSG partagé, toutes les vérifications à chaque étape ; génération orientée (composites), base Hypothesis rejouée au push, régressions figées ; périmètre, promotion, `reset --from-azure`, forensique, 2 régions, Windows. Harnais de mutation `scripts/mutation_check.py` (22 mutants) : **1 sur 17 → 15 sur 17** attrapés au push à chaque tour ; hebdo `mutants.yml`. **Cinq défauts trouvés et corrigés** : règle de l'ancienne IP laissée par la levée sans état et `reset --from-azure` ; `verify_block_ip` sur les IP enregistrées ; blocage caché derrière la quarantaine compté comme blocage ; levée d'une carte redéployée bloquée par un original inutile ; levée partielle puis nouvelle levée qui vidait le NSG de quarantaine partagé (toutes les VMs en quarantaine du groupe rouvertes) | ✅ (12/10) |
| L27 | Concurrence : deux opérations entrelacées appel par appel dans la machine, avec les vrais verrous (propriété I11 : l'état local dit ce qu'Azure a) ; verrous testés entre vrais processus (`test_locks.py`). M17 (verrou retiré) attrapé à chaque tour. **Trois défauts trouvés et corrigés** : déblocage aveugle derrière la quarantaine ; `reset --from-azure` qui lisait l'original dans le seul tag ; reset partiel qui laissait l'état intact (la réaffirmation aurait reposé ce qu'on retirait). Schémas : `docs/architecture.md`, `docs/design/preuves.md` | ✅ (13/10) |
| — | S7 à S9 (basse) : `platform_open` montré à l'isolation, coupure des sessions limitée aux ports forensiques, divers | ✅ 15/10 — S8 (#110 : la coupure n'épargne que TCP vers les ports forensiques ; la validation était déjà faite, L25/L26), S9 (#111 : une vérification qui lève garde l'action → `verification_failed` ; le reste déjà couvert, L24/L27), S7 (puce « ⚠ DNS/IMDS », `list` et notification ; un refus de quarantaine à l'exécution devient une réserve de préparation). Reste de S7 : le deny DNS/IMDS à source `*` sur un NSG de carte dédié — à mesurer sur une topologie à NSG de carte |

**Septième passe (12/10, sur `adf4e15`).** La suite d'invariants reconnaît les bugs qu'elle a appris mais généralise peu : sur 16 mutants nouveaux, 2 attrapés à coup sûr au push. Le code non muté échoue à 5 000 séquences (règle orpheline d'une VM supprimée appliquée à une VM vivante, V-1). Deux constats hauts hors du modèle du monde (U1, U2). Vérifié par mesure avant d'y répondre : U3 (la config ne s'écrit plus sous Docker : `EBUSY`) et la séquence figée de M18 qui n'attrape rien. Deux pistes en parallèle après L28 : stabiliser l'isolation, revenir à l'IA.

| Lot | Contenu | Fini quand | État |
|---|---|---|---|
| L28 | **Immédiat.** U3 (config sous Docker : le changement de mode depuis la War Room échoue depuis #49), U2 (une carte détachée de la quarantaine perd son NSG d'origine — introduit par le correctif M20 de #50), U4 (deny de quarantaine vérifiés sans la config), première alerte sur les règles orphelines (U1) avec V-1, séquence figée de M18 réparée | le mode se change depuis la War Room en Docker ; une carte détachée retrouve son original ou fait escalader ; une règle orpheline est signalée ; la nuit est verte | ✅ (13/10) — U3 mesuré dans le conteneur (écriture en place sous `flock`, un lecteur d'un autre conteneur attend le verrou) ; escalade `orphan_rule` |
| A0 | **Isolation — avant A1.** Invariants v3 : faire varier ce qui ne varie jamais (horloge, abonnements, protocole, altérations qui inversent une règle, noms d'avant l'empreinte, création de VM et réutilisation d'IP, sources forensiques) ; un écrivain étranger au milieu d'une opération (rend M14 observable) ; oracles indépendants du code (I9 sur le journal du test, exemption forensique conditionnelle, I2 par auteur) ; vivacité (un blocage manquant est reposé ou escaladé) ; taux par mutant, attrapés « seulement par séquence figée » comptés à part ; **jeu de mutants de contrôle** (les 16 de la septième passe), jamais utilisé pour orienter la génération | le jeu de contrôle est attrapé au moins pour moitié au push et aux trois quarts la nuit | ✅ 13/10 — contrôle 10/16 au push (3 au départ), M14 et M02 attrapés, 13 défauts du produit corrigés |
| A1 | **Isolation.** Découper `actions.py` (~4 000 lignes) en un module : cœur (placements, noms, vérification par contenu), quarantaine, repli par règles, blocages, état ; un seul adaptateur Azure (garde d'abonnement, contrôle de version des écritures de carte) | le harnais reste au-dessus de son seuil à chaque étape ; aucun fichier au-delà de quelques centaines de lignes | ✅ 26/10 avec MC0 (ligne A1 du tableau « 0.4 à 0.x ») ; la garde d'abonnement et le contrôle de la carte avant écriture (`_set_nic_nsg`, `expect`) sont dans l'adaptateur. Pas fait : un vrai contrôle de version (ETag, If-Match) des écritures de carte — il changerait le comportement, hors d'un découpage |
| A2 | **Isolation.** Un type d'identité de VM unique (fin de L18) ; un type à trois états pour les prédicats de sûreté | confondre « inconnu » et « faux » devient une erreur de type | à faire |
| A3 | **Isolation.** Balayage des règles orphelines (U1 : retrait après alerte) ; liste blanche d'extensions au restore et secrets passés par nom (L23) ; validation stricte de la config (types, clés inconnues, `"false"`) | une VM qui reçoit l'IP d'une VM supprimée n'est jamais coupée ; une config mal écrite est refusée avec un message clair | à faire |
| B1 | **IA.** Mistral Large 4 dans le harnais (`make llm-compare`), le modèle par défaut actuel en référence — première comparaison de deux modèles cloud ; hébergé en Europe. Demande `MISTRAL_API_KEY` | tableau intégration / jugement / sur-confiance, 8 cas × 3 runs, pour les deux modèles | après la 0.3 (15/10) |
| B2 | **IA.** Injection par les logs : scénario Annatar qui attaque le défenseur (lignes Syslog porteuses d'instructions), dimension « résistance à l'injection » dans le harnais, défense (contenu des logs balisé comme donnée, escalade si injection suspectée) | aucun cas d'injection ne change l'action décidée | première moitié ✅ 13/10 : 4 cas d'injection dans le harnais (`--kinds injection`) ; modèle par défaut (Sonnet 4.6) **0/12 détourné**, décisions identiques aux menaces propres, l'injection nommée comme telle dans l'explication (confiance 0,82 contre 0,94). Reste, avec Jonathan : les modèles locaux, un scénario Annatar qui écrit ces lignes sur le banc, et la défense — dont une garde déterministe « jamais de silence » (un `no_action` sans escalade sur une détection caractérisée = rien de fait ni dit, aucune garde ne l'attrape) |
| B3 | **IA.** Les deux faiblesses de raisonnement connues : cycles passés pris pour preuve du signal courant ; absence d'un compteur propre à Windows prise pour une preuve. Run e2e T1486 + T1110 exigé (modification du prompt) | les deux cas ajoutés au harnais passent, T1486 et T1110 restent corrects | **D-1 (1ʳᵉ tranche) ✅ 26/10** (#186, #190) : force brute seule → bloquer 15/15 ; après root sur la même VM → bloquer 8 / isoler 7 (`sonnet-5-5`), décision instable en contexte d'incident ; le modèle par défaut refuse la température ; accord des tirages (`GLORFINDEL_DECISION_DRAWS`) ajouté. Restent les deux faiblesses nommées |
| B4 | **IA.** Précision sur données réelles : étiqueter les détections d'une observation réelle, en tirer la précision des règles et des décisions, verser des cas anonymisés au harnais (avec P1, P4) | on sait combien de fois Glorfindel a eu raison sur du vrai trafic | à faire ; les cas appariés de D-1 (même attaque seule / après root, #186) entrent au harnais |
| — | Ensuite : L21 (Q2), L22 (Q8), S7 à S9 (✅ 15/10 ; le deny DNS/IMDS sur NSG de carte dédié est **écarté par décision le 19/10** — une règle à source `*` toucherait d'autres cartes, maintenant ou plus tard (L24) ; la quarantaine les refuse sans ce risque, le repli le dit — `docs/azure.md`), U5 (blocage retiré du NSG détaché pendant la quarantaine), détails de la septième passe (regex `01-web`, S3 sans ID, version des écritures de carte, garde du bac à sable), produit P1 (règle T1136.001 sans exclusions, ✅ 15/10), P2 (✗ NSG contre la préparation, ✅ 15/10), P3 (point rouge = posture, pas panne, ✅ 15/10), P4 (groupe « Détection » sur la carte, ✅ 15/10) | — | à faire |

**Critères avant le mode autonome** (tous constatés, aucun à l'impression) :
- [x] Concurrence couverte : M17 attrapé (✅ L27) ; M14 attrapé par un écrivain étranger simulé (✅ A0)
- [ ] Décision stable sous tirage : une action disruptive autonome n'est prise que si plusieurs tirages du modèle s'accordent (`GLORFINDEL_DECISION_DRAWS`), sinon escalade ; la température de la décision est fixée ou tracée (D-1, #186, 26/10 ; reste les cas appariés et B3)
- [ ] Suite mesurée : harnais au-dessus de son seuil, jeu de contrôle attrapé au moins pour moitié au push (✅ 10/16, A0) et aux trois quarts la nuit (à mesurer)
- [ ] Aucun constat haut ouvert sur le chemin d'isolation (U1, U2 et leurs successeurs)
- [ ] Détection fiable sur les VMs visées : attribution sans ambiguïté (✅ L21), pas de détection aveugle (point produit P4 de la septième passe — ✅ 15/10, la couverture se voit : groupe « Detection » sur la carte, état de chaque règle ; reste à la constater sur le parc visé)
- [ ] Seuil ransomware réglé sur du bénin réel, plusieurs types de disques (L22)
- [ ] Garde d'abonnement mesurée sur un second abonnement réel
- [ ] Exercice réel sur des VMs de test dédiées, environnement proche de la production (NSG en IaC, homonymes, Windows) : isoler, bloquer, lever, retour à l'état d'origine vérifié
- [ ] Au moins quatre semaines d'observation en `human_only` sur un parc réel, taux de recommandations disruptives fausses mesuré et jugé acceptable — de quoi la mesurer : verdicts et `glorfindel report` (13/10, `docs/observation.md`) ; la pré-observation sur le banc (H0, 15/10) ne compte pas

Puis activation VM par VM, par la préparation, en commençant par des VMs non critiques.

**Environnements de test (second abonnement, environnements proches de la production) — trois règles** : lecture seule d'abord (principal Reader, `human_only`) ; écritures (isolation, blocage) seulement sur des VMs de test dédiées et taguées, avec l'accord de leurs responsables ; rien de ces environnements dans le dépôt public (ni identifiant, ni nom de ressource, ni code d'infrastructure, ni dans les documents).

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
  - **Finding calibration (2026-07)** : sur un signal **caractérisé mais sous le seuil** (écriture disque 5 MB/s = 149× sous le vrai ransomware ; `sudo apt-get update`), **tous** les modèles locaux sur-agissent (isolent la VM) **avec une confiance plus haute quand ils ont tort** (`conf|wrong` ≈ 0.90–0.98 > `conf|correct` ≈ 0.79–0.87). Le mode d'échec passe **entre les deux gardes** : le garde-fou signal-non-caractérisé ne fire pas (le signal *est* caractérisé), le gate de confiance non plus (le modèle est confiant). Blast radius borné par design (action `isolate_vm` réversible + gate destructive + défaut `human_only`), **pas** par la confiance du modèle → confirme empiriquement pourquoi la sûreté ne se délègue jamais à la confidence LLM. **Nuance prod (vérifié 2026-07-29)** : les règles curées enforcent DÉJÀ ce seuil (`ransomware-disk-write` : `MaxWrite > 50000000` ; `ssh-brute-force` : `FailedAttempts >= 10`) — le RulePoller filtre le sous-seuil **avant** `decide()`, donc ce mode d'échec **ne peut pas se produire en prod pour ces indicateurs** ; le harnais le mesure sur le LLM **en isolation** (rows injectées). L'axe de durcissement réel n'est donc PAS un garde-fou magnitude dans `decide` (redondant, jamais atteint) mais l'**enforcement d'un seuil de magnitude dans les règles autorées par le LLM** (`detection_authoring`) — une règle générée pourrait fixer un seuil faible/absent et re-surfacer le sous-seuil.
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

Dans le plan 0.x (26/10) : les Activity Logs arrivent avec **R2** ; Entra ID devient **C2** (#199) et les charges IA d'Azure, absentes de ce tableau, **C3** (#200), tous deux après R2. Storage, Key Vault, AKS et App Service n'ont pas encore de lot.

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

## Phase 7 — SaaS MVP (horizon 1.x)

**Plus tard.** Eregion tourne en local ou dans une VM (sur Azure ou ailleurs) ; le modèle économique SaaS se construira sur la 1.x, à son rythme (huitième passe). Ce qui suit reste une esquisse.

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

Depuis la huitième passe (13/10), l'ordre est celui des jalons (section « Vers la 1.0 ») : **0.3** (O0, E1, O1, H0, R1, G0 ; B2, IA0), puis la **0.x**, puis la **1.0**. L'ancien ordre se range ainsi :

```
Module d'isolation compatible IaC   → livré (L1–L7 + JIT, 06–07/10) ; L8 (module renfort) reste optionnel
Canary azurerm                      → ✅ quotidien, 3.x / 4.x / 5.x
Premier utilisateur externe         → la preuve chez le client devient J1–J4 (ombre, sentinelle, jumeau), 0.x
Solidification (erreurs, cron)      → septième passe (A1–A3), 0.4+
Entra ID / Service Principal        → hors des lots chiffrés ; R2 le rend pressant (Stratus attaque l'identité)
Nouveaux scénarios TTP              → par les adaptateurs (R1 Atomic, R2 Stratus), plus de script maison
Schéma normalisé first_result_row   → avec MC0 (interface de fournisseur), 0.4+
AWS, GCP                            → MC2, MC3 (1.x)
Prometheus + Loki, Datadog          → après MC0 : une source de télémétrie de plus derrière l'interface
AKS                                 → O2 et G4 (Kubernetes), 1.x
War Room UI                         → ✅ livré ; matrice de couverture en C1
SaaS                                → plus tard, sur la 1.x
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

### Analyse d'innovation (2026-10-06)
Les briques sont standard (deny NSG, snapshot, KQL à seuil, tri LLM) ; l'assemblage et la discipline ne le sont pas.
- **Nouveau** : (1) la **défense vérifiée** — chaque action est prouvée contre Azure (préséance, sessions coupées, relecture chaque minute, auteur d'un changement, droits vérifiés sans écriture) ; le marché pose et suppose, et personne ne vérifie les prérequis réseau avant d'automatiser. (2) La **boucle purple fermée** sur une vraie infra (le raté de détection produit une règle ancrée sur le schéma réel) — les outils BAS mesurent les trous, les CDR détectent, aucun n'écrit la règle. (3) L'**isolation qui cohabite avec Terraform** (JIT NSG, original dans Azure, mesuré). (4) La **sûreté indépendante de la confiance du LLM** (gardes déterministes, mode par actif).
- **Faible ou fragile** : détection à seuils calés sur peu de données (marge B6 : 53 contre 45 Mo/s) — loin des baselines comportementales commerciales ; apport du LLM surtout en écriture de règles et cas ambigus, pas dans la décision ; périmètre Azure/VM/réseau quand les attaques passent par l'identité ; le JIT repose sur un angle mort du provider azurerm (la lecture de l'association ne compare pas le NSG réel) → canary CI.
- **Paris** : faire de la « défense vérifiée » l'identité du projet ; publier les deux découvertes (rejeu Run Command au restore, comportement Terraform) — décision Jonathan ; Entra ID avant tout nouveau scénario VM.

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
- Jamais de panne ni d'action destructive sur une charge réelle ; pas de tests sur infra prod sans consentement explicite (règle de production, codée dès O0)
- Pas de logique offensive maison : des bibliothèques publiques, version épinglée
- Pas de dashboard monitoring — ce n'est pas le rôle de Glorfindel
- Pas de fine-tuning LLM — la RAG ChromaDB suffit ; aucune donnée d'un client n'entraîne un modèle
- Pas de multi-cloud avant que la boucle Azure soit solide (sauf MC0, l'interface de fournisseur)
- Pas de modèle économique SaaS avant la 1.x — Eregion tourne en local ou dans une VM

---

## Vision long terme

Eregion n'est pas un outil de sécurité supplémentaire — c'est la couche de raisonnement qui manquait au-dessus des outils existants. Les EDR, SIEM, NIDS continuent d'exister comme collecteurs de signaux. Eregion raisonne sur leurs sorties sans règles de corrélation explicites.

```
Court terme  : CDR Azure — détecter, répondre, apprendre sur un cloud
Moyen terme  : CDR multi-cloud + posture (CSPM lite) — AWS, GCP, Prometheus
Long terme   : raisonnement unifié cross-sources — endpoint, réseau, cloud, identité
```

La catégorie CDR (Cloud Detection and Response) est émergente chez Gartner (intégrée dans CNAPP). C'est là qu'Eregion se positionne — sans la complexité playbook des SOAR, sans le scope limité des EDR cloud-natifs.
