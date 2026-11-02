# BL1 — la boucle avec la réponse exécutée : la session de banc

Deux des cinq indicateurs de la finalité étaient vides depuis le début : **le temps pour contenir**
et **la part contenue seule**. Jusqu'au 30/10, H0 observait en `human_only`, avec une identité
lectrice : la 0.3 a mesuré la détection et la décision, jamais le confinement. BL1 (#280) les
remplit, sur le banc.

Le lot a été préparé sans infra réelle (le 30/10) : le calcul, la campagne déclarée, les tests. La
session de banc, avec Jonathan, consiste à lancer, regarder, juger. Cette page la déroule, commande
par commande.

**Le résultat du 31/10** (#280) : la panne `vm-shutdown` n'a pas été prise pour une attaque (1
panne, 0) ; T1136.001 détectée en 144 s, mais contenue seule 0 fois sur 1 (un instantané recommandé
à 35 %, escaladé sous le seuil de 0,7) — le critère 1 tenu, le 2 à mesurer avec une technique que le
modèle juge grave (BL1b, #396).

**Depuis le 31/10, H0 garde la posture de la session** (décision de Jonathan ; bree aussi en
`non_disruptive` depuis le 01/11) : le rôle « Eregion Glorfindel Response » sur le seul groupe du
banc, `GLORFINDEL_READ_ONLY=0`, gondolin et bree en `non_disruptive`, le CD actif. Les étapes 3 et 7
ne servent plus que si H0 a été remis en lecture seule. Ce que la posture ouvre et ce qui la borne :
le modèle de menace ([`design/modele-de-menace.md`](design/modele-de-menace.md), §5).

## Ce qui est prêt

- **Le calcul** : [`analysis/containment.py`](../analysis/containment.py). Les définitions sont dans
  [`analysis.md`](analysis.md), « Temps pour contenir et part contenue seule ».
- **Où les lire** :
  - le rapport de la campagne (`report.md`, section « Réponse », calculée, jamais écrite par le
    modèle) ;
  - la page Annatar de la console (la campagne, encadré **RESPONSE**) ;
  - l'accueil de la console (tuiles **TIME TO CONTAIN** et **CONTAINED ALONE**, sur 30 jours) ;
  - `make glorfindel-host-containment CAMPAIGN=<id>`, sur H0, en lecture seule, sans geste de plus
    (depuis BL1c : la commande lit elle-même l'inscription des VM d'une campagne venue du canal, et
    retire les variables d'identité vides que compose passe, comme la watch).
- **La campagne déclarée** : [`annatar/campaign/declared/bl1-reponse.yaml`](../annatar/campaign/declared/bl1-reponse.yaml).
  Elle tient en trois étapes :
  1. la panne `vm-shutdown` (Chaos Studio, 5 min) ;
  2. la technique T1136.001, par l'atomic épinglé d'Atomic Red Team ;
  3. la reprise.

  Les deux injecteurs visent gondolin, inscrite `bench`, que la watch tient en `non_disruptive`.
  La déclaration est vérifiée contre le catalogue avant tout plan
  ([`declared.py`](../annatar/campaign/declared.py)). Une technique doit être implémentée, venir
  d'une bibliothèque publique (jamais un script maison) et ne pas être destructive. La panne doit
  être déclarée sur les mêmes cibles, en zone `bench`.

  **La technique grave attend R2 (BL1b, #396).** La session du 31/10 a mesuré la part contenue
  seule à 0 sur 1 : T1136.001 (création d'un compte) est jugée ambiguë par le modèle. La mesurer
  en exercice demande une technique que le modèle juge grave — le signal
  `sudo-privilege-escalation` (T1548.003). Atomic Red Team n'offre pas, à la version épinglée, de
  test sudo→root réversible, non interactif et sans prérequis, jouable par l'injecteur R1 (détail :
  [`design/bl1-technique-grave.md`](design/bl1-technique-grave.md)).

  **Décision de Jonathan (02/11) : « le réel + R2 ».** La règle « bibliothèques publiques
  seulement » reste entière, sans exception. La part contenue seule se mesure sur le **trafic
  réel** (bree en `non_disruptive` depuis le 01/11, 5 blocages autonomes ; le tableau ci-dessous,
  du 31/10, la dit encore en `human_only`), compté par l'Overview avec OV1 (#399).
  **À rejouer** : BL1, quand R2 (#79, Stratus Red Team) apportera une technique grave jouable, en
  seconde technique après T1136.001. D'ici là, rien de nouveau au-delà de la session du 31/10 ; la
  campagne garde sa seule technique publique, T1136.001.
- **Le test de bout en bout** : [`tests/unit/test_containment.py`](../tests/unit/test_containment.py).
  Il rejoue la campagne avec les injecteurs simulés. Le vrai graphe de Glorfindel décide, avec le
  modèle simulé, et agit sur le faux Azure de la machine à invariants. Sa réaffirmation voit une
  isolation retirée. Le rapport et la console relisent les deux indicateurs.

**Pourquoi la panne d'abord.** Une VM isolée n'envoie plus sa télémétrie : l'agent de supervision
est coupé, comme mesuré le 30/07. Le retour de la panne se vérifie pourtant par le Heartbeat. La
panne passe donc avant la technique. La campagne d'Annatar n'a qu'une technique : son lanceur ne
lève pas l'isolation entre deux scénarios depuis Orodruin, où `glorfindel reset` n'existe pas.

**Comment la panne est rattachée à la campagne.** Le format de run est commun depuis C1, mais une
campagne d'Annatar ne joue pas encore elle-même une panne. Deux cas :
- un run de Gothmog sur une des VM de la campagne, qui la chevauche ou tombe dans l'heure qui
  l'entoure, est rattaché seul, et le rapport dit comment ;
- sinon, on le nomme : `FAULT_RUNS=<run>`.

## Où tourne la watch qui répond

**Depuis le 31/10, (a) est la posture de H0 sur le banc** : rien à poser avant une session. Le choix
du 30/10 reste ci-dessous, pour ses raisons.

Le 30/10, H0 était lecteur : identité managée `Reader` et `Log Analytics Reader`,
`GLORFINDEL_READ_ONLY=1`, et la config forcée en `human_only` au push (SEC7). Pour que Glorfindel
isole seul, une watch devait pouvoir écrire sur le groupe du banc, le temps de la campagne.
**Jonathan a retenu (a) le 30/10**, puis l'a gardée le 31/10 ; (c) est le repli, (b) est écartée.
La posture est écrite au modèle de menace ([`design/modele-de-menace.md`](design/modele-de-menace.md),
§5).

| | (a) **retenue** : H0, rôle « Response » sur le banc | (b) **écartée** : une watch sur le poste de Jonathan | (c) **repli** : H0, avec un principal propre à la watch |
|---|---|---|---|
| Ce qui écrit | l'identité managée de H0 : watch, console et bot | le principal de réponse de Jonathan (`.envrc`) | la watch seule (`GLORFINDEL_AZURE_CLIENT_*`) ; la console et le bot restent lecteurs |
| Règle de production | tenue : rôle sur `rg-celebrimbor` seul ; gondolin `bench` ; bree reste en `human_only` | tenue, même portée | tenue, même portée |
| Le canal retour (V1) | inchangé : H0 publie son battement, Orodruin le lit | **cassé** : seule l'identité de H0 écrit le battement et les détections. Il faut soit ouvrir l'écriture du conteneur `watch` à l'opérateur et arrêter la watch de H0, soit lancer `--without-glorfindel`, qui annule la mesure | inchangé |
| La console | celle de H0 : bandeau « lecture seule » levé, boutons actifs (toutes les VM) | une console locale : les fichiers de la campagne arrivent sur H0, pas sur le poste | celle de H0 : les approbations échouent (`write_blocked`), la console reste de fait lectrice |
| Le CD | en pause pendant la session (`make glorfindel-host-cd-disable`, étape 3) : il redéploierait H0 au milieu | intact | idem (a) |
| L'observation de bree | continue (`human_only`) | **trou** : la watch de H0 arrêtée | continue |
| Secret | aucun | celui du poste | un secret client sur H0, le temps de la session |
| À défaire | le rôle, `READ_ONLY=1`, gondolin en `human_only`, push, redémarrage, le CD réactivé | le rôle du canal, redémarrer la watch de H0 | les variables vidées, le secret révoqué, `READ_ONLY=1`, gondolin en `human_only` |

**Retenue : (a)** (décision de Jonathan, 30/10).
- Une seule watch et un seul battement.
- Les cartes, le rapport de la campagne et les deux indicateurs sont au même endroit (H0, sa
  console), comme le sera une vraie exploitation.
- Aucun secret, et le retour se fait en quatre gestes.

Ce que (a) ouvre de plus que (c) : un clic dans la console, ou un bouton du bot, peut écrire sur le
banc, bree comprise. C'est un humain qui agit, derrière le jeton de la console ou la liste de
Discord. Pensé le 30/10 pour une session courte, c'est depuis le 31/10 la posture de tous les jours.
Si Jonathan veut une console qui reste lectrice, (c) est le repli, au prix d'un secret sur H0. (b)
casse le canal retour : écartée.

## Le déroulé (environ 1 h 30 à 2 h)

Toutes les commandes sont lancées depuis le poste, avec `source .envrc` dans le shell (zsh). Avant
chaque `YES=1`, le plan est montré et relu.

### 0. Avant (5 min, lecture seule)

Le CD de H0 reste actif : ne pas publier de release pendant la session, elle redéploierait H0 au
milieu de la campagne (ou mettre le CD en pause, comme à l'étape 3).

```bash
source .envrc
git fetch --tags && git log --oneline -1 origin/main     # la branche de BL1 fusionnée
make glorfindel-host-status                              # H0 : conteneurs Up, aucune erreur
make glorfindel-host-report                              # l'observation de la semaine, pour la note
```

### 1. Le banc (5 à 15 min)

```bash
make celebrimbor-plan                  # relire : aucun changement attendu (chaos.enabled: true, gondolin inscrite)
make celebrimbor-up YES=1              # seulement si le plan montre un écart voulu (ID1 a pu changer le banc)
make celebrimbor-start VM=gondolin     # gondolin s'éteint à 23 h UTC
az vm show -g rg-celebrimbor -n vm-celebrimbor-gondolin --query tags     # eregion-target, eregion-zone=bench
az group show -n rg-celebrimbor --query tags                             # idem sur le groupe
```

Ces deux lectures sont la vraie vérification de la zone. La déclaration de la campagne ne dit
`bench` que sur le papier : `declared.py` ne lit aucun tag. Les injecteurs relisent l'inscription
avant d'agir (O0), mais c'est ici qu'on le voit.

### 2. Orodruin (5 min ; 30 min s'il faut le recréer)

```bash
make orodruin-start
make orodruin-push REF=<le commit de main qui porte BL1>   # l'image publiée, vérifiée (CI3)
make orodruin-check                                        # attendu : armed
```

S'il a été détruit, suivre `infra/orodruin/README.md`, « Déroulé » : `orodruin-plan`, puis
`orodruin-up YES=1` et `orodruin-lock YES=1`, chacun après la relecture de son plan.

### 3. La watch qui répond — option (a) (facultative, 10 min)

**Seulement si H0 a été remis en lecture seule** (étape 7). Sinon, la posture du 31/10 est déjà là :
vérifier dans la console (page Glorfindel) que gondolin est en `non_disruptive`, et passer à
l'étape 4. Un `make glorfindel-host-push` garde les modes en place sur H0 (depuis le 02/11) ; après
un `make glorfindel-host-push HUMAN_ONLY=1`, les redonner dans la console.

```bash
make glorfindel-host-cd-disable        # le CD en pause : aucune release ne redéploie H0 pendant la session
make glorfindel-host-cd-status         # attendu : en pause
P=$(terraform -chdir=infra/glorfindel-host output -raw principal_id)
SCOPE=/subscriptions/${AZURE_SUBSCRIPTION_ID}/resourceGroups/rg-celebrimbor
az role assignment create --assignee-object-id ${P} --assignee-principal-type ServicePrincipal \
  --role "Eregion Glorfindel Response" --scope ${SCOPE}
# infra/glorfindel-host/host.env : GLORFINDEL_READ_ONLY=0
make glorfindel-host-push              # .env et config (le défaut human_only ; les modes en place sur H0 gardés, et dits)
make glorfindel-host-start REF=<le même commit>
make glorfindel-host-tunnel            # la console : page Glorfindel, gondolin → non_disruptive
```

`glorfindel-host-start REF=…` **construit** l'image sur la VM (`deploy.sh`) : c'est le chemin de
secours, hors de la vérification de CI3 (`infra/glorfindel-host/README.md`, « Au quotidien »).

Le passage en `non_disruptive` ouvre le contrôle de préparation. Attendu : `ready`, puisque les
droits viennent d'arriver. Une réserve se lit et se confirme, ou la session s'arrête là. Le 31/10,
bree était restée en `human_only` ; la posture du 01/11 la met aussi en `non_disruptive`, par le
même contrôle. `make glorfindel-host-ssh` puis `docker exec eregion-watch glorfindel list` montre le
mode résolu par VM.

### 4. La campagne (30 à 45 min)

```bash
make gothmog-preflight                 # watch vivante, contrat, cibles, état normal : rien d'écrit
make gothmog-run                       # la panne et son retour vérifié (~15 min) ; noter son run_id
# attendre la fin de la grâce de la panne : 15 min après sa fin (fault_end du rapport)
make orodruin-campaign-plan CAMPAIGN_TARGET=<resource_id de gondolin> \
  CAMPAIGN_DECLARED=annatar/campaign/declared/bl1-reponse.yaml   # rend l'id de la campagne
make orodruin-campaign-run CAMPAIGN=<id>   # T1136.001 ; Glorfindel doit isoler seul, puis vérifier
```

**Pourquoi attendre la grâce de la panne.** Une détection de T1136.001 vue pendant la fenêtre de
la panne serait comptée « prise pour une attaque » : le calcul écarte celles qui tombent dans la
fenêtre d'un run de la technique, mais une décision tardive ou non rattachée resterait ambiguë.
Lancer la campagne après la grâce sépare les deux fenêtres.

Pendant la campagne, dans la console : la carte de l'action autonome, et gondolin `ISOLATED`.

### 5. La reprise (5 min)

Une fois le run fini (le nettoyage de l'atomic est passé), la console fait **↩️ Release** sur
gondolin. En ligne de commande, sur H0 :
`docker exec eregion-watch glorfindel release <resource_id> --yes`. La levée est vérifiée sur
Azure, et elle est notée au fil des actions.

### 6. Lire les indicateurs (5 min, puis le rapport ~25 min après)

```bash
make glorfindel-host-containment CAMPAIGN=<id>                          # la panne rattachée seule (dans l'heure)
make glorfindel-host-containment CAMPAIGN=<id> FAULT_RUNS=<run Gothmog> # sinon, nommée
make glorfindel-host-campaign-report CAMPAIGN=<id>                      # report.md, section « Réponse »
```

La mesure se lance seule, sans geste de plus. Le 31/10, elle écartait chaque run (« sa VM n'est pas
inscrite »), puis butait sur les variables d'identité vides de compose ; BL1c l'a corrigée.

Dans la console, à trois endroits :
- la page **Annatar**, la campagne, encadré **RESPONSE** ;
- l'**accueil**, les tuiles TIME TO CONTAIN et CONTAINED ALONE ;
- la page **Gothmog**, le run de la panne et ses cycles.

### 7. Le retour en lecture seule (facultatif, 10 min)

**Seulement pour remettre H0 en lecture seule** : depuis le 31/10, la posture de H0 garde le rôle,
`GLORFINDEL_READ_ONLY=0` et les modes. Hors de ce cas, ne garder que les deux dernières lignes
(`orodruin-stop`, `celebrimbor-stop`), vérifier que plus aucune isolation ni blocage ne reste
sur gondolin (`glorfindel list`), et `make glorfindel-host-cd-enable` si le CD a été mis en pause.

```bash
# console : gondolin et bree → human_only ; plus aucune isolation ni blocage (glorfindel list)
# P et SCOPE viennent de l'étape 3 ; shell rouvert, les recalculer :
P=$(terraform -chdir=infra/glorfindel-host output -raw principal_id)
SCOPE=/subscriptions/${AZURE_SUBSCRIPTION_ID}/resourceGroups/rg-celebrimbor
az role assignment delete --assignee ${P} --role "Eregion Glorfindel Response" --scope ${SCOPE}
# infra/glorfindel-host/host.env : GLORFINDEL_READ_ONLY=1
make glorfindel-host-push HUMAN_ONLY=1 # toutes les VM de nouveau en human_only
make glorfindel-host-start REF=<le tag publié en service>   # la release d'avant, celle du CD
make glorfindel-host-status            # bandeau lecture seule, aucune erreur
az role assignment list --assignee ${P} --all -o table      # Reader et Log Analytics Reader seulement
make glorfindel-host-cd-enable         # le CD reprend
make glorfindel-host-cd-status         # actif ; la release en service est celle d'avant
make orodruin-stop
make celebrimbor-stop                  # bree (always-on) épargnée
```

## Ce que Jonathan juge à la fin

1. **La panne n'a pas été prise pour une attaque.**
   - Attendu : « Pannes : 1 · prise(s) pour une attaque : 0 ».
   - Une isolation exécutée sur gondolin pendant la panne serait une action disruptive à tort.
2. **La technique est contenue seule.**
   - Attendu : issue « contenu seul », action `isolate_vm` ou `block_suspicious_ip`, part 1 sur 1.
   - Le temps pour contenir se compare à la détection : 84 s à 3 min 30 entre le 05 et le 07/10,
     44,7 s pour T1136.001 le 20/10.
   - Autre issue possible, et dite : le modèle peut répondre à T1136.001 par un instantané et une
     escalade. Le 30/07, il l'avait jugée ambiguë, à 35 %. Ce serait une mesure, pas un échec du
     banc.
3. **L'isolation a tenu.** Aucune carte « vérification échouée » ou « contournée » sur gondolin
   avant la reprise.
4. **La reprise l'a levée.** gondolin n'est plus `ISOLATED`, et la levée est vérifiée.
5. **Rien hors du périmètre.**
   - Aucune action sur bree, aucune autre VM touchée.
   - À vérifier : `glorfindel list` et le fil des actions de la console.
6. **Les identifiants des runs.** Ceux de la campagne et de la panne vont dans l'issue #280,
   avec la décision : BL1 tenu, ou à rejouer.
