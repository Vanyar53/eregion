# BL1b — une technique publique jugée grave, pour mesurer le contenu seul

> **Décision de Jonathan (02/11) : « le réel + R2 ».** La règle « bibliothèques publiques
> seulement » reste entière, sans aucune exception.
> - **La part contenue seule se mesure sur le trafic réel** : bree est en `non_disruptive` et
>   compte déjà 5 blocages autonomes. L'Overview les comptera avec OV1 (#399).
> - **Pour les exercices**, BL1 sera rejoué quand **R2** (#79, Stratus Red Team, techniques cloud
>   publiques) apportera une technique grave jouable.
>
> L'option 2 ci-dessous (attendre une couverture publique) est retenue, avec le réel en plus ;
> les options 1 (assouplir `declared.py` pour un script maison) et 3 (atomic sans nettoyage dans
> R1) sont écartées.

BL1 (#280, session du 31/10) a mesuré la part contenue seule pour la première fois : **0 sur 1**.
La seule technique d'une bibliothèque publique au catalogue, **T1136.001** (création d'un compte
local, atomic épinglé), le modèle la juge **ambiguë** : un instantané recommandé à 35 %, sous le
seuil de confiance, escaladé — jamais exécuté seul. Pour mesurer le contenu seul il faut une
technique que le modèle juge **grave** au point d'isoler seul : le 30/07, une élévation sudo vers
root à 93 %, isolation autonome.

Ce document tranche le choix de cette technique, à partir des fichiers d'Atomic Red Team épinglés
(`annatar/atomics/PIN`, commit `9f6a1eab…`, vérifié identique à `master` le 02/11). **Conclusion :
aucun des deux candidats de l'issue #396 n'est jouable aujourd'hui par l'injecteur R1 à la version
épinglée.** La raison est détaillée ci-dessous, avec la preuve ; les pistes de déblocage, qui
touchent une règle de sûreté ou une politique, ont été tranchées par Jonathan le 02/11 (encadré
ci-dessus).

## Le critère

La technique visée doit, pour ce lot :

1. venir d'une **bibliothèque publique** (Atomic Red Team, R1) — jamais un script maison (règle de
   la huitième passe, et garde de `declared.py` : « a public library's engine only ») ;
2. être **non destructive** et à **nettoyage connu** (l'adaptateur R1 exige un `cleanup_command` :
   on ne laisse jamais la cible modifiée, `annatar/engines/atomic.py`) ;
3. être **détectée par une règle livrée** de Glorfindel
   (`glorfindel/rules/azure/detection_rules.yaml`) ;
4. produire un signal qu'un **analyste** — et, au banc, le **modèle** — jugerait grave ;
5. être **jouable fidèlement** par l'adaptateur R1 : linux, exécuteur `sh`/`bash`,
   `elevation_required` non `false`, **sans `dependencies`** (Orodruin n'a pas d'accès Internet :
   tout atomic est vendorisé dans l'image, aucun prérequis ni téléchargement au runtime).

Parmi les règles livrées, **une seule** décrit une élévation de privilège sur une VM Linux :
`sudo-privilege-escalation` (T1548.003), qui se déclenche sur une ligne `sudo … USER=root …
COMMAND=…` dans Syslog. `ssh-brute-force` (T1110.001) se déclenche sur des `Failed password … from
<IP externe>` écrites par `sshd`. Toutes les autres règles couvrent le plan de contrôle (NSG,
rôles, instantané, Entra) ou l'impact (rançongiciel, exfiltration), pas une élévation sur la VM.
**Le signal grave recherché est donc celui de `sudo-privilege-escalation` : il faut T1548.003.**

## Les candidats, test par test (version épinglée)

### T1548.003 — Abuse Elevation Control Mechanism: Sudo and Sudo Caching

Six tests ; trois visent FreeBSD (`dependencies` → refusés par R1). Les trois linux restants :

| Test (guid) | Nettoyage | Destructif | Jouable R1 ? |
|---|---|---|---|
| **Sudo usage** (`150c3a08…`) | **aucun** | non (énumération) | **non** — pas de `cleanup_command`, et la commande fait `sudo vim /etc/sudoers`, qui ouvre un éditeur interactif : sous Run Command (sans terminal) il bloque. |
| **Unlimited sudo cache timeout** (`a7b17659…`) | aucun | **oui** — `sed -i` sur `/etc/sudoers` | non |
| **Disable tty_tickets** (`91a60b03…`) | aucun | **oui** — ajoute une ligne à `/etc/sudoers` | non |

Le seul test non destructif (« Sudo usage ») produirait bien le signal attendu (`sudo cat
/etc/sudoers` → une ligne `USER=root COMMAND=…` que `sudo-privilege-escalation` détecte), mais il
n'a **pas de nettoyage déclaré** et contient `sudo vim`. L'adaptateur R1, fidèle et fail-closed, le
**refuse**. Les deux autres modifient `/etc/sudoers` **sans** le restaurer : destructifs, non
réversibles par l'atomic lui-même.

### T1110.001 — Brute Force: Password Guessing

Les tests linux (« SUDO Brute Force » Debian / Redhat / FreeBSD) :

- déclarent tous des `dependencies` (vérifier/installer `openssl`, `sudo`, `curl`…) → **refusés**
  par R1 ;
- **téléchargent et exécutent un script distant** (`curl -s <url> | bash`) → impossible depuis
  Orodruin (pas d'accès Internet), et c'est de la logique offensive non vendorisée, tirée au
  runtime ;
- **ne sont pas du SSH** : ils forcent le mot de passe `sudo` d'un compte créé pour l'occasion, pas
  des connexions SSH. Ils n'écrivent donc **aucune** ligne `sshd` « Failed password … from … » : la
  règle livrée `ssh-brute-force` **ne se déclencherait pas**.

L'hypothèse de l'issue (« essais de mots de passe SSH ») ne correspond pas au contenu d'Atomic Red
Team : T1110.001 y est un brute-force **sudo**, pas SSH.

### La preuve

L'adaptateur R1 (`resolve_ref`) refuse, à la version épinglée, les quatre tests pertinents :

```
REFUSED  Sudo usage                 T1548.003/150c3a08… :: no cleanup_command — R1 requires a declared return to the initial state
REFUSED  Unlimited sudo cache …     T1548.003/a7b17659… :: no cleanup_command — R1 requires a declared return to the initial state
REFUSED  SUDO Brute Force - Debian  T1110.001/ba1bf0b6… :: declares dependencies (prereqs) — out of scope for R1
REFUSED  SUDO Brute Force - Redhat  T1110.001/4097bc00… :: declares dependencies (prereqs) — out of scope for R1
```

(mesuré sur les fichiers vendorisés au commit épinglé, adaptateur inchangé).

## Ce qui est écarté, et pourquoi

- **T1110.001 (SSH)** — écarté : pas de test SSH dans Atomic Red Team ; les tests linux sont du
  brute-force sudo avec prérequis et charge distante, injouables depuis Orodruin, et non détectés
  par `ssh-brute-force`.
- **T1548.003 « Sudo usage »** — écarté : pas de nettoyage déclaré (refusé par R1) et `sudo vim`
  interactif (bloque sous Run Command). On ne peut pas l'éditer (« l'atomic tel quel »).
- **T1548.003 destructifs** — écartés : modifient `/etc/sudoers` sans réversion ; destructifs.
- **La variante « compte root » de T1136.001** (`a1040a30…`, test « Butter » : `useradd -g 0 -d
  /root`, déjà vendorisée, réversible par `userdel`) — un analyste la jugerait grave (compte dans
  le groupe root). Écartée pour deux raisons : (1) le catalogue est indexé par TTP et T1136.001 y
  est déjà (test `evil_user`) — on ne peut pas ajouter une seconde entrée T1136.001 ni déclarer
  deux tests distincts du même TTP ; (2) le signal reste une **création de compte**, que le modèle
  a jugée ambiguë — il ne verrait pas « groupe root » dans la sortie de la règle t1136. Elle ne
  remplit donc pas le besoin (un signal **grave**).

## Les options examinées, et la décision (02/11)

La mesure du contenu seul exige le signal `sudo-privilege-escalation`, et Atomic Red Team n'offre
pas, à ce jour, de test sudo→root **réversible, non interactif, sans prérequis**. Les trois
options examinées, et ce que Jonathan en a retenu le 02/11 :

1. **Écartée.** **Assouplir, de façon étroite et tracée, la règle « bibliothèque publique seule » de
   `declared.py` pour une technique grave sans atomic fidèle.** Le script maison
   `scripts/vm/privilege_escalation_sim.sh` (T1548.003) produit déjà, par `logger` seul (aucune
   escalade ni modification réelle — **non destructif**), exactement les lignes `sudo … USER=root …
   COMMAND=…` que la règle livrée détecte. Un opt-in explicite par déclaration (un indicateur
   revu par un humain), documenté au modèle de menace, débloquerait la mesure immédiatement. C'est
   un **retour en arrière de politique** sur « plus de logique offensive maison » : il revient à
   Jonathan, pas à un lot. Jonathan garde la règle entière, sans aucune exception.
2. **Retenue, avec le réel en plus.** **Attendre une couverture publique d'une élévation grave sur VM** (une mise à jour d'Atomic Red
   Team avec un test sudo→root réversible, ou R2/Stratus sur le plan de contrôle avec une règle
   livrée correspondante), puis câbler la technique. Ce sera R2 (#79, Stratus Red Team) ; d'ici
   là, la part contenue seule se mesure sur le trafic réel (bree en `non_disruptive`, 5 blocages
   autonomes), compté par l'Overview avec OV1 (#399).
3. **Écartée.** **Autoriser dans R1 un atomic en lecture seule sans nettoyage** (nouvelle garde + mutant) :
   insuffisant seul, car le seul candidat non destructif (« Sudo usage ») reste injouable à cause
   de `sudo vim`, et on ne peut pas éditer l'atomic.

D'ici R2, la campagne déclarée de BL1 (`annatar/campaign/declared/bl1-reponse.yaml`) garde sa
seule technique publique, T1136.001. En exercice, la part contenue seule reste à 0 sur 1, par
décision correcte du modèle sur une technique ambiguë — une mesure, pas un échec du banc. Sur le
trafic réel, elle se lit dans l'Overview (OV1, #399).

## À rejouer au banc

Rien de nouveau à rejouer avant R2 : la session BL1 du 31/10 reste la référence
(`docs/banc-bl1.md`). Quand R2 (#79) apportera une technique grave jouable (Stratus Red Team, avec
une règle livrée qui la détecte), rejouer BL1 avec elle en seconde technique, après T1136.001, et
lire la part contenue seule (`analysis/containment.py`). D'ici là, la part contenue seule se lit
sur le trafic réel, dans l'Overview (OV1, #399).
