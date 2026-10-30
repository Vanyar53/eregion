# Observer avant d'autoriser

Le mode autonome d'une VM ne se décide pas sur une impression. Le dernier critère de
maturité du ROADMAP le dit : **au moins quatre semaines en `human_only` sur un parc réel,
avec un taux de recommandations disruptives fausses mesuré et jugé acceptable.** Cette page
décrit comment mener cette observation et lire ce qu'elle mesure.

Pendant l'observation, Glorfindel détecte, enquête et décide comme en production, mais
n'exécute rien : chaque décision devient une carte (« isoler la VM, 92 % — retenu par le
mode `human_only` »). L'opérateur dit, pour chaque carte, si la recommandation était juste.
Le rapport compte.

## Mise en place

1. **Des identifiants en lecture seule.** Un principal de service avec les rôles *Reader*
   et *Log Analytics Reader* sur le périmètre observé, rien de plus. Ses identifiants dans
   `.envrc` (jamais dans le dépôt), et `GLORFINDEL_READ_ONLY=1` : toute tentative d'écriture
   lèverait une erreur claire au lieu d'atteindre Azure.
2. **Le mode `human_only` partout.** C'est le défaut ; vérifier qu'aucune section
   `autonomy` de `glorfindel-config.yaml` ne passe un actif en `non_disruptive`.
   `glorfindel list` affiche le mode résolu par VM.
3. **Le workspace Log Analytics** dans `glorfindel-config.yaml` (`monitoring_backends`), et
   les règles de détection livrées (`assets: [auto]`).
4. **Une alerte qui arrive** : webhook (`GLORFINDEL_WEBHOOK_URL`) ou bot Discord. Sans elle,
   les cartes s'accumulent sans que personne les voie.
5. `make glorfindel-start` (il refuse de démarrer sans `AZURE_SUBSCRIPTION_ID`), puis
   vérifier dans `make glorfindel-logs` que la découverte trouve les VMs
   (`heartbeat → N VM(s)`).

Les règles des environnements de test s'appliquent : lecture seule d'abord, et rien de ces
environnements dans le dépôt public — ni nom, ni identifiant, ni rapport.

## Pré-observation sur le banc (H0)

Avant le parc réel, l'observation tourne sur le banc (décision du 15/10) : bree, une VM du banc
allumée en continu et non inscrite (`always_on`, `enrolled: false` dans
`infra/terraform/config.yaml`), et Glorfindel sur une petite VM dédiée,
pour que le `watch` n'ait pas de trou (`infra/glorfindel-host/README.md`). Une VM allumée mais vide ne produit presque aucun bruit
bénin : quatre semaines sans fausse alerte n'y prouveraient rien. Bree porte donc une vraie
charge — un petit site, des crons, les mises à jour automatiques, la sauvegarde de la nuit.
Les exercices d'Annatar et de Gothmog sont marqués (B2) et sortent du rapport. Cette
pré-observation démarre l'outillage et calibre le bruit ; elle ne compte pas pour le critère
« quatre semaines sur un parc réel ».

**Un scanner qui revient.** En observation rien n'est bloqué : le même attaquant revient et ouvre une carte à chaque visite (une fois la précédente acquittée). La carte le dit (« ↻ same IP seen 2× in 7 days — judged right ») — elle n'est jamais jugée à ta place —, et le rapport compte les attaquants derrière les blocages (« blocks 4 for 2 IPs »).

**Le résumé du lundi.** Avec le bot Discord, chaque lundi matin le salon reçoit le compte de la semaine — le même que `glorfindel report --since 7d`.

**Le modèle.** Depuis le 19/10, le Glorfindel de l'observation (VM hébergée) décide avec `claude-sonnet-5-5` (harnais : 36/36 bonnes décisions, 0 erreur sûre d'elle ; `claude-sonnet-4-6` : 32/36 et 4). Les cartes d'avant le 19/10 viennent de `claude-sonnet-4-6`. Run de bout en bout fait le 19/10 (T1486 → isoler 0,80 ; T1110.001 → bloquer 0,88) : c'est le défaut du code depuis (#139).

**Garder les verdicts.** Ils ne vivent que sur l'hôte de Glorfindel : une copie par semaine
(`make glorfindel-host-pull` sur la VM hébergée, H0) évite de perdre l'observation avec un disque.

## Juger chaque carte

Pour chaque carte de décision, juger la recommandation **comme si elle avait été
exécutée** :

| Verdict | Quand |
|---|---|
| `right` | la menace était réelle et l'action proportionnée |
| `wrong` | faux positif, ou action disproportionnée ou erronée (isoler une VM pour une sauvegarde nocturne) |
| `unsure` | impossible de trancher avec ce qu'on sait |

Dans la console, page Glorfindel (`/glorfindel`), la liste **TO JUDGE** (colonne de gauche, 16/10 ; le seul endroit où l'on juge une carte depuis le 26/10) : les cartes de décision des 7 derniers jours sans verdict — en attente ou déjà acquittées, les cartes d'exercice comprises et marquées (H-1, 26/10) —, chacune avec une note facultative et **✓ Right** / **✗ Wrong** / **? Unsure** — un verdict donné là ou dans Discord acquitte aussi la carte (un seul clic) ; l'en-tête affiche le compte de la semaine (cartes, jugées, part des isolations et blocages jugés faux). Les mêmes boutons restent sur les cartes de décision. En ligne de
commande, avec l'identifiant (ou ses 6 premiers caractères) affiché par `glorfindel pending` :

```bash
glorfindel verdict 3f2a91c0 wrong --note "rattrapage apt du matin"
glorfindel verdict 3f2a91c0 right
```

Le verdict est indépendant de l'acquittement : on peut juger une carte avant ou après
l'avoir acquittée. Une carte qui se répète (« 12× depuis 3 h ») compte une seule fois. La
note est gardée avec le verdict : c'est elle qui dira, plus tard, quelle règle affiner.

Les cartes de posture, de règle proposée, de préparation, de TTL et les alertes de la
réaffirmation ne sont pas des décisions sur une détection : elles n'entrent pas dans le
rapport.

## Le rapport

```bash
glorfindel report --since 7d       # la semaine
glorfindel report --since 4w       # la période d'observation
glorfindel report --since all --json
```

Il donne, par action recommandée et par règle de détection, le nombre de verdicts justes,
faux, incertains et de cartes non jugées, et surtout le **taux de recommandations
disruptives fausses** : parmi les recommandations d'isoler ou de bloquer qui ont été
jugées, la part fausse. (`GET /api/report?since=7d` renvoie la même chose.)

Les cartes d'exercice n'y entrent pas (B2, 16/10) : une carte dont la VM était couverte par la
fenêtre d'un injecteur (Annatar, puis Gothmog) porte `source: exercise` et le rapport la compte
à part (« N exercise card(s) left out »). Elles restent pourtant dans la liste TO JUDGE, marquées
(H-1) : une fenêtre d'exercice est l'affirmation de l'hôte des injecteurs, et une carte cachée
sur cette seule foi laisserait passer une vraie attaque qu'une fenêtre forgée couvrirait. Un compte créé à la main pour un test, comme celui du
16/10 sur bree, n'est pas un exercice déclaré : il compte, d'où la note du verdict.

Une carte non jugée n'entre pas dans le taux. Un taux calculé sur trois cartes ne dit rien :
le rapport donne aussi les effectifs.

## Ce que les chiffres décident

À fixer avant de commencer, pour ne pas les ajuster aux résultats :

- **Le seuil** : à partir de quel taux de recommandations disruptives fausses une VM peut
  passer en `non_disruptive` ? Avec combien de recommandations jugées au minimum ?
- **Par règle** : une règle qui produit des verdicts `wrong` est-elle affinée (seuil,
  exclusion) avant d'activer l'autonomie sur les actifs qu'elle couvre ?
- **Les VMs** : l'autonomie s'active VM par VM (contrôle de préparation, réserves
  confirmées) — lesquelles en premier ?

Ces seuils sont une décision de l'opérateur, pas du code.

## Et le confinement ?

L'observation mesure la décision, jamais le confinement : en `human_only`, rien ne s'exécute. Le
temps pour contenir et la part contenue seule restent donc vides sur H0. Ils se mesurent sur le
banc, sur une VM `bench` en `non_disruptive`, le temps d'une campagne déclarée (BL1, #280) :
[`banc-bl1.md`](banc-bl1.md). Les définitions sont dans [`analysis.md`](analysis.md), « Temps
pour contenir et part contenue seule ». Les cartes de cette campagne sont des cartes d'exercice
(B2) : elles n'entrent pas dans le taux de recommandations disruptives fausses de l'observation.
