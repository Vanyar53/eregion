# La corrélation, brique du produit (COR1, COR2), et ce qu'auditd y ajoute (AUD1)

Décision de Jonathan (02/11), après la relecture d'ADM1 : « faire le meilleur ». Une détection qui
relie deux événements vaut plus que deux détections isolées. La corrélation fait donc partie du produit :
c'est une brique réutilisable de Glorfindel, pas l'astuce d'une règle.

Code : `glorfindel/correlation.py`. Tests : `tests/unit/test_correlation.py`. Issues : #407 (COR1),
#427 (COR2, l'origine confirmée hors de la VM). AUD1 (#408), qui ferme une partie de leurs limites par
les lignes d'auditd : `glorfindel/auditd.py`, `tests/unit/test_auditd.py` — [ci-dessous](#ce-que-ferme-aud1-auditd).

## Où elle tourne

Elle tourne dans le **RulePoller**, juste après le routage des lignes d'une règle vers leurs VMs
(`poll_once`, puis `correlation.settle`). C'est le même endroit que les sudo attendus d'ADM1, et
elle tourne avant tout signal :

- **Avant la décision.** Aucun cycle du graphe n'est ouvert, et aucun appel au modèle n'est fait.
  Comme le seuil d'une règle, la sûreté ne se délègue pas à la confiance du modèle (leçon du 28/07).
- **Jamais dans le prompt.** Le modèle ne voit pas la liste des origines. Il ne tranche pas non plus
  l'écart. Une carte porte seulement le fait établi par le code : `SessionOrigin` (pourquoi le shell
  root reste une carte), ou `Correlation` et `SuccessfulLogins` (le brute force qui a réussi).
- **Hors du verrou du poller**, que toutes les règles partagent. Ses requêtes ne retiennent pas
  les autres règles.

## Ce qu'elle lit

Elle lit les lignes Syslog `auth` et `authpriv` de la VM, que celle-ci soit désignée par
`_ResourceId` ou par `Computer`. Les valeurs sont vérifiées puis écrites en littéraux KQL (SEC4c).

| Ligne | Ce qu'elle en tire |
|---|---|
| `Accepted <méthode> for <compte> from <adresse> port <n> …`, sous l'étiquette `sshd` ou `sshd-session` seulement (la même phrase sous une autre étiquette n'est pas lue) | Une session, et son origine. Une IPv4 écrite en IPv6 (`::ffff:a.b.c.d`) est lue comme elle-même. |
| `pam_unix(sshd:session): session opened for user <compte>` sans `Accepted` du même processus (même `ProcessID`, 60 s avant au plus) | Une session dont l'origine n'est pas écrite : **inconnue**. |
| `pam_unix(<su, su-l, sudo, runuser, login, cron…>:session): session opened for user <compte> … by <autre>` | Le compte a été pris par un autre compte, ou par le système : son origine n'est **pas suivie**. |
| `pam_unix(systemd-user:session)` | Rien. systemd en ouvre une à chaque connexion SSH. |
| `session closed`, `Disconnected` | Rien (voir les limites). |

La lecture se fait en une requête par VM et par passe, sur 7 jours (`SESSION_LOOKBACK_S`, décision de Jonathan, 02/11), filtrée sur les
comptes en cause et coupée à 1 000 lignes (`ROWS_MAX`). Elle ne ramène que les lignes que la brique
lit : les `Accepted` de sshd « for <compte> from », les sessions ouvertes « for user <compte> » —
jamais celles de sudo vers root (`session opened for user root … by <compte>`, une par sudo) ni
celles de `systemd-user`. Une semaine de sudo d'un administrateur actif remplissait sinon la lecture,
et chacun de ses shells root devenait une carte.

La requête ne tourne que pour les lignes qui en ont besoin. C'est le cas d'un shell root en attente,
quand le compte déclare des origines, et d'une ligne de brute force. Une ligne déjà vue à une passe
précédente n'est pas relue.

Il y a au plus 4 requêtes par règle et par passe (`QUERIES_PER_POLL`). Au-delà, le résultat est inconnu.

Chaque requête est comptée dans `rule_status.json` (`correlation` : `queries`, `origin`, `card`,
`unknown`, `compromised`, `unchecked`). La console affiche ce compte dans le détail de la règle.

## Inconnu, donc carte (A0)

Elle ne conclut jamais sans lignes. Dans chacun des cas suivants, le résultat est inconnu, et un shell
root reste une carte qui dit pourquoi :

- une requête qui échoue ;
- une lecture coupée à sa limite (une session plus récente pourrait manquer) ;
- une ligne qui ne nomme pas sa VM ;
- un instant illisible ;
- aucune session trouvée ;
- le plafond de requêtes atteint.

## Premier usage : l'origine des shells root d'ADM1

ADM1 laisse les shells root d'un administrateur attendu (`sudo -i`, `sudo su -`, `bash`, `python -c`…)
en carte : sous sudo, ce qui s'y fait n'est jamais écrit. Pour un shell root d'admin, le meilleur
rapport entre bruit et sûreté est de le **qualifier par l'origine de sa session SSH**.

Chaque entrée `expected_sudo.admins` peut déclarer `origins`, des plages CIDR. Un bastion est une
plage, et une adresse seule vaut `/32` ou `/128`. Les origines sont lues strictement :

- des bits d'hôte non nuls sont refusés ;
- `/0` est refusé ;
- une liste vide est refusée.

Plusieurs entrées qui nomment la VM et le compte additionnent leurs origines.

Un shell root ou du code en ligne d'un compte attendu n'est écarté que si **toutes** les sessions de
ce compte, ouvertes dans la fenêtre avant la ligne, viennent d'une origine attendue. Il faut aussi
qu'aucune autre session n'ait pris le compte. L'écart est alors journalisé (`via: origin`, `origin`)
et compté (`origin_count`). Sinon, la ligne reste une carte, et `SessionOrigin` en dit la raison :

- « session depuis 203.0.113.9, origine inconnue » ;
- « session depuis 10.1.2.3, adresse du réseau hors des origines déclarées — mouvement latéral
  possible » (une adresse privée qui n'est pas déclarée) ;
- « compte pris par su-l depuis mallory — origine non suivie » ;
- « session SSH sans ligne « Accepted » — origine inconnue » ;
- « aucune session SSH trouvée pour ce compte sur 7 jours » ;
- « sessions non lues : … ».

Sans `origins`, le comportement est celui d'ADM1 : une carte, et aucune requête. **L'origine
n'efface jamais une commande sensible.** `sudo bash -c 'cat /etc/shadow'`, ou un texte de
`sensitive_commands` dans un shell, reste une carte quelle que soit l'origine
(`expected_sudo.shell_only`).

## Second usage : le brute force qui réussit

Sur une règle de la technique T1110.001 (`ssh-brute-force`), chaque ligne qui porte une adresse
(`SourceIP`) et un nombre d'échecs (`FailedAttempts`) est rapprochée des connexions réussies de la VM.
Ce sont les lignes `Accepted …` de sshd, prises dans la fenêtre de la règle (sa période de recherche
plus la marge d'ingestion).

Si une connexion réussie vient de la même adresse, la ligne est marquée
`Correlation: ssh-login-after-brute-force`, avec ses connexions (`SuccessfulLogins` : compte, méthode,
instant). Le signal est alors **critique** : un compte est peut-être compromis. Il passe en tête des
cartes de la passe.

**Une compromission est toujours dite à un humain** (décision de l'Orchestre, 02/11, dans le
sens de Jonathan : « précautionneux »). La décision reste celle du graphe (modes d'autonomie, gardes de
`decide`) : une action autonome non disruptive, comme le blocage de l'adresse, peut partir. Mais la
carte ne disparaît jamais derrière elle. Après une action exécutée et vérifiée, `compromise_card`
(`glorfindel/agent.py`, accroché à `verify_action`) écrit une carte `account_compromised` : l'adresse,
les comptes, l'action déjà faite, les gestes à faire (mot de passe, clés, sessions). Elle n'est jamais
approuvable en un clic. Une carte que le cycle fait de toute façon (mode `human_only`, garde, action
en échec, vérification en défaut) commence par « Compte peut-être compromis ».

La marque est un texte, donc elle fait partie de l'identité de dédoublonnage de la ligne agrégée. Un
brute force déjà envoyé, puis réussi, donne **un** signal critique de plus, puis plus rien pour cette
adresse et cette VM tant que la fenêtre court. Côté cartes :

- après une action autonome, la carte `account_compromised` porte l'adresse (`action_params.ip`) :
  une adresse, une carte ; une seconde compromission sur la VM, depuis une autre adresse, a la sienne ;
- quand le cycle escalade, la carte en attente du brute force pour cette adresse (`mode_hold`, bloquer
  l'adresse) reçoit le signal. Une compromission ne s'y fond jamais en silence : `escalations.record`
  tient pour un changement matériel une raison qui dit la compromission alors que la carte ne la disait
  pas, ou une sévérité qui monte. La carte prend alors la nouvelle raison (« Compte peut-être
  compromis… ») et la sévérité critique, la première raison étant gardée (`first_reason`). Une carte
qui dit la compromission la garde : un signal ordinaire de la même adresse (un scanner qui continue
après la connexion) met à jour le reste, jamais sa raison.

**Une vérification impossible** (requête en échec, lecture coupée, plafond, VM introuvable) est comptée
(`unchecked`) et dite sur la ligne : `LoginCheck: {status: unchecked, why}`. Ce champ n'est pas un
texte, l'identité de la ligne ne bouge pas. Le cycle le dit à un humain comme une compromission : après
une action autonome, une carte `compromise_unchecked` (une par adresse) ; sinon, la carte du cycle
commence par « Connexion après brute force non vérifiée ». Les comptes portés par la carte sont bornés
à 64 caractères.

## Ses limites, assumées

- **Une fermeture de session n'est pas lue.** N'importe quel utilisateur local écrit
  `session closed` avec `logger`. Une session d'origine inconnue, dite fermée, effacerait ce qui
  rend la carte. Toute session ouverte dans les 7 jours compte donc. Conséquence : un administrateur
  qui s'est connecté une fois depuis une origine non déclarée (ou qui a une crontab) voit ses shells
  root en carte pendant 7 jours. La solution est de déclarer cette origine.
- **Une session ouverte avant la fenêtre de 7 jours n'est pas vue.** Si c'est la seule session, le
  résultat est inconnu, donc une carte. Mais si une autre session du même compte, d'une origine
  attendue, tombe dans la fenêtre, le shell root est écarté. Un intrus qui garde une session plus
  de 7 jours, pendant qu'un administrateur se connecte depuis le bastion, passe donc.
- **Un accès qui n'écrit aucune ligne de session n'est pas vu.** C'est le cas d'un service qui tourne
  sous le compte, ou d'une ligne perdue à l'ingestion. Lier une commande à sa session exacte (son
  terminal, son processus) demande `auditd` : là où il est posé, AUD1 lit chaque commande du shell
  root sous l'identité de connexion, quelle que soit l'origine de la session (ci-dessous).
- **Sans source déclarée, un réducteur de bruit, pas une preuve** (décision de Jonathan, 02/11).
  Tout utilisateur local peut écrire une ligne de connexion sshd venant d'une origine déclarée
  (`logger -p auth.info -t sshd`). L'écart par origine ne tient donc que contre un administrateur
  honnête et contre un intrus qui ne connaît pas Eregion. Un intrus dont la vraie session est plus
  ancienne que la fenêtre, ou un accès qui n'écrit aucune ligne de session, peut faire écarter un
  shell root seul. Les commandes sensibles restent toujours une carte. Une ligne forgée n'efface
  jamais une session réelle vue dans la fenêtre. **Avec une source déclarée, la limite de la ligne
  forgée est levée** (COR2, ci-dessous) : une ligne écrite par `logger` n'a pas de trace hors de la
  VM, et fait une carte. Le reste demeure ouvert, avec ou sans source : une session plus ancienne
  que la fenêtre, un accès qui n'écrit aucune ligne de session ne sont toujours pas vus par la
  corrélation — mais, là où auditd est posé, ce qu'ils font de sensible en root fait une carte (AUD1,
  ci-dessous).

## L'origine confirmée hors de la VM (COR2)

Décision de Jonathan (02/11) : COR1 est livré comme réducteur de bruit, sa limite écrite ; COR2 la
ferme par une preuve prise hors de la VM. Issue : #427.

**La clé** : `expected_sudo.origin_proof`, une source parmi `none` (le défaut : COR1 tel quel),
`bastion`, `flows`. Elle vaut pour toutes les entrées qui déclarent `origins`. Lue strictement : une
autre valeur, un texte attendu et autre chose écrit, ou une source sans aucune entrée qui déclare
`origins` (rien à confirmer) refusent le fichier.

**La règle de l'écart.** Avec une source, un shell root ne s'écarte que si, en plus de COR1 (toutes
les sessions des 7 jours viennent d'une origine déclarée, aucun compte pris par un autre), **chaque**
session vue dans le Syslog a sa trace dans la source :

| Source | Table lue | Une session est confirmée par |
|---|---|---|
| `bastion` | `MicrosoftAzureBastionAuditLogs` (les journaux d'audit d'Azure Bastion, dans le workspace) | une session Bastion vers cette VM (`TargetResourceId`, casse ignorée), par ce compte (`UserName`), ouverte (`SessionStartTime`) à 120 s au plus de la ligne `Accepted`. **Une session Bastion ne confirme qu'une session SSH** : une ligne forgée à l'instant d'une vraie session n'en trouve plus. Une session écrite deux fois (son `TunnelId`) compte une fois. |
| `flows` | `NTANetAnalytics` (les journaux de flux du VNet, enrichis par traffic analytics) | un flux autorisé (`FlowStatus == "A"`, TCP) de l'adresse de la session (`SrcIp`) vers le port 22 de cette VM (`DestVm`, `<groupe>/<vm>`, casse ignorée), dont l'intervalle (`FlowStartTime`–`FlowEndTime`) couvre la ligne à 120 s près. |

La VM est celle du registre (la ressource où la ligne a été routée), jamais celle qu'écrit la ligne.
Les valeurs passent par `kql.literal`. La requête ne remonte que jusqu'à la plus ancienne session à
confirmer (plus 120 s et 10 min de marge, 7 jours au plus), sur les comptes (Bastion) ou les
adresses (flux) en cause, coupée à 1 000 lignes. Elle ne tourne que pour les shells root que COR1
aurait écartés : une ligne déjà en carte par son origine n'en fait pas. C'est une requête de plus par
VM, dans le même plafond de 4 par règle et par passe.

**Inconnu, donc carte (A0).** Une trace absente fait une carte qui le dit (« session depuis
198.51.100.7 (2026-11-02 10:00:00 UTC) sans trace dans Azure Bastion — origine non confirmée hors de
la VM »), comptée `unconfirmed`. Une source illisible, coupée à sa limite, le plafond atteint, une
VM que la source ne sait pas nommer, l'instant d'une session illisible : inconnu, une carte, compté
`unknown`.

**Dit.** Un shell root écarté avec sa preuve est journalisé avec la source (`proof`) et compté
(`confirmed`, `origin_confirmed`). `glorfindel report` et la console disent, pour les shells root
écartés par l'origine, « every one confirmed outside the VM (COR2) », ou « origin read in the VM
only » quand aucune source ne les a confirmés.

**Ce qu'elle ne fait pas encore.**

- **Attendre la preuve.** Une trace écrite après le shell root (Bastion à la fin de la session,
  traffic analytics par lots de 10 ou 60 minutes) est absente au moment de la décision : la ligne est
  une carte. Selon la latence mesurée (B2, F4 dans `docs/operations.md`), un shell root ouvert juste
  après la connexion fera une carte. Retenir la ligne jusqu'à l'arrivée de la preuve demande un état
  « en attente » borné dans le RulePoller : un lot à part, si la mesure le justifie.
- **Les flux prouvent une adresse, pas une session.** Les flux d'un même quadruplet sont agrégés : un
  flux réel de l'origine couvre une ligne forgée à la même minute. C'est moins fort que Bastion.
- **Une source par déploiement**, pas par entrée : une VM sans Bastion, la source étant `bastion`,
  voit ses shells root en carte.
- **Les tables et leurs colonnes sont des hypothèses** (la documentation publique de Microsoft Learn,
  pas une mesure) : B1–B5 et F1–F4 dans `docs/operations.md`, à trancher au banc avec Jonathan.
- **Bastion ne nomme pas l'adresse de l'instance** d'où vient la session sur la VM : « même
  origine » se réduit, pour Bastion, à l'origine déclarée (la plage d'`AzureBastionSubnet`) plus la
  VM, le compte et l'instant.
- **Pour le brute force, l'ordre n'est pas vérifié.** La ligne agrégée ne dit pas l'instant du premier
  échec : une connexion réussie depuis l'adresse, n'importe où dans la fenêtre, suffit. Une
  connexion réussie juste avant les échecs est aussi suspecte. La dédup tient pour une ligne
  agrégée (la règle livrée). Pour une règle du client qui rend des lignes datées, la marque ne
  change pas l'identité.

## Ce que ferme AUD1 (auditd)

Décision de la feuille de route (#408), après COR2 : la bonne pratique des benchmarks CIS pour Linux
est une règle `auditd` qui journalise toute commande exécutée sous un autre utilisateur, en gardant
l'identité de connexion d'origine (`auid`). Le noyau pose l'`auid` à la connexion (`pam_loginuid`) et le
garde à travers `sudo` et `su` : une commande lancée dans un shell root porte encore le compte qui
s'est connecté.

**Sur le banc, derrière un drapeau désactivé** (`auditd_enabled`, `infra/terraform/auditd.tf` ;
`docs/operations.md`, « auditd au banc (AUD1) »), deux règles d'audit et le greffon syslog d'auditd
(`audisp-syslog`, facilité `local6`, la DCR du banc) :

- la règle du CIS, `-C euid!=uid -F auid!=unset -S execve -k user_emulation` : un programme exécuté
  sous un autre utilisateur (`sudo` lui-même, `su`, un binaire setuid) ;
- **ce qu'elle ne voit pas** : sudo passe à uid = euid = 0 avant de lancer la commande, et un shell root
  a uid = euid = 0 — aucune de ses commandes n'a `euid != uid`. La seconde règle,
  `-F euid=0 -F auid>=1000 -F auid!=unset -S execve -k root_command`, écrit chaque exécution en root
  d'une connexion humaine, sous le même `auid`.

**La règle livrée `auditd-sensitive-root-command`** (T1059.004) lit `Syslog`, `local6`, l'étiquette
`audisp-syslog` : une ligne par exécution d'un humain (auid ≥ 1000, jamais unset) en root (euid 0), ses
enregistrements SYSCALL et EXECVE réunis par événement (`msg=audit(<instant>:<numéro>)`), **tous** ceux
de l'événement, jamais un choisi. Puis, dans le RulePoller, avant tout signal et hors du verrou, comme
ADM1 (`auditd.settle`) :

| La ligne | Ce qu'elle devient |
|---|---|
| lue en entier, sa commande dans la liste sensible d'ADM1 — `SENSITIVE_SHIPPED` et `sensitive_commands`, la même liste, jamais recopiée (`expected_sudo.listed`) | une carte : le compte de connexion (`LoginAccount`, « admin1 (auid 1001) » ; « auid 1001 (nom absent de la ligne) » sans le format ENRICHED), la commande (`AuditCommand`), la catégorie (`Sensitive`), le programme (`Exe`), le terminal et la session (`Tty`, `Session`) |
| lue en entier, hors de la liste | rien : c'est la règle, pas un écart. Un `ls` du shell root n'est pas une détection ; le shell lui-même a été jugé sur la ligne de sudo (`sudo-privilege-escalation`) |
| illisible ou ambiguë : pas d'EXECVE, deux SYSCALL ou deux EXECVE pour un événement, un argument coupé ou réparti sur plusieurs enregistrements, `argc` qui ne tombe pas juste, un champ illisible, un nombre hors borne (des chiffres autres qu'ASCII comme `²`, plus de 10 chiffres, `argc` au-delà de 256), une commande plus longue que ce qui est lu (1 024 caractères), une lecture qui lève | une carte qui dit pourquoi (`AuditRead`, A0) |

- **Un compte attendu (ADM1) reste soumis à la liste**, comme pour sudo : `expected_sudo.admins`
  n'écarte rien ici.
- **Une ligne écrite pour faire échouer la lecture ne fait taire rien** (relecture d'AUD1) : chaque
  ligne est lue bornée et à part, une lecture qui lève est une carte ; une étape de lecture du poller
  en défaut (AUD1, ADM1, COR1) est dite (`last_error`) et la passe continue avec les lignes telles que
  lues, rien d'écarté qui n'ait été lu ; une passe qui lève ne tue jamais le fil de la règle. Les
  enregistrements ne sont sur la carte qu'une fois (`SyslogMessage`, 2 000 caractères chacun).
- **Un shell n'est pas une catégorie** ici (`root_shell` d'ADM1 n'est pas lu) : à l'intérieur du shell
  root, chaque commande est lue pour elle-même.
- **Le programme est lu par son chemin** (`exe`, celui du noyau), puis ses arguments : `argv[0]` est à
  l'appelant (`exec -a vim /usr/sbin/useradd` reste `accounts`). Un argument écrit en hexadécimal par
  le noyau (il contient une espace, un guillemet, un caractère de contrôle) est décodé.
- **Une carte par VM et par passe** : la commande la plus récente, qui nomme les autres
  (`AuditCommands`, 20 au plus ; `AuditCount`, toutes) — aucune envoyée sans être dite. La carte est
  caractérisée (`root_command`) : un instantané seul en `non_disruptive` laisse sa carte (le plancher de
  `decide`).
- **Dit** : `rule_status.json` garde, à chaque passe, ce que la fenêtre de la règle contient (`auditd` :
  `events`, `sensitive`, `unreadable`) — zéro événement dit qu'aucune ligne n'arrive ;
  `glorfindel report` l'affiche.

**Ce qu'AUD1 ferme**, là où auditd est posé :

- **le shell root d'ADM1** : ce qui s'y fait de sensible fait une carte, et pas seulement ce que sudo
  écrit ; un script non listé (`sudo /tmp/x.py`) est lu par les programmes qu'il lance ;
- **les limites de COR1 et COR2** : un shell root écarté par l'origine de ses sessions — une ligne de
  session forgée, une session plus ancienne que la fenêtre de 7 jours, un accès qui n'écrit aucune
  ligne de session — ne cache plus ses commandes sensibles : l'`auid` porte la connexion, quelle que
  soit l'origine que la corrélation a lue. L'écart de COR1 reste un réducteur de bruit sur le shell ;
  AUD1 en lit le contenu.

**Ce qui reste ouvert**, écrit ici :

- **Ce qui n'est pas une exécution n'est pas vu** : une commande interne du shell et ses redirections
  (`echo … >> /root/.ssh/authorized_keys`), un fichier lu ou écrit par un programme déjà lancé, du
  code en ligne d'un interpréteur qui n'exécute rien. Les règles de surveillance de fichiers du CIS
  (`-w /etc/shadow`, `-w /etc/sudoers`, `-w /etc/passwd`…) les verraient : un lot à part.
- **La liste lit des noms** : une copie renommée d'un programme (`cp /usr/sbin/useradd /tmp/u`) ne
  porte plus le sien.
- **Sans `auid` d'un humain, rien n'est lu** : un démon compromis (un service, une page web), l'agent
  de la VM (Run Command), les tâches cron de root (auid 0), une connexion directe de root (auid 0).
  Le sujet d'AUD1 est l'identité de connexion d'un humain.
- **Le silence n'est pas vu** : un greffon arrêté, auditd tué par son numéro de processus (`kill <pid>`
  ne nomme rien), une ligne perdue par journald ou rsyslog (A10). Arrêter ou retirer auditd, son greffon
  ou ses règles par leur nom est une commande sensible (`supervision`, `audit`, `log_config`), écrite
  avant d'agir ; mais l'absence de lignes n'est pas une détection (pas de battement des lignes d'audit),
  et les règles ne sont pas immuables sur le banc (`-e 2` demanderait un redémarrage pour les changer).
- **Une ligne forgée ajoute une carte** : tout utilisateur de la VM peut écrire une ligne `local6`
  étiquetée `audisp-syslog`. Elle n'en efface aucune (deux enregistrements pour un événement : une
  carte), mais elle peut nommer un autre compte ; le journal d'audit de la VM (root seul, `ausearch`)
  dit le vrai.
- **Deux cartes pour un geste** : `sudo cat /etc/shadow` fait la carte d'ADM1 (la ligne de sudo) et
  celle d'AUD1 (l'exécution) — deux sources, deux règles.
- **Le bruit** : les scripts de maintenance d'une mise à jour de paquets, un outil de configuration
  qui se connecte en SSH puis passe root (Ansible et `become`, sous l'auid de son compte) exécutent des
  commandes de la liste — des cartes, et du volume (A12, A13). Un écart par le nom du programme parent
  ne sera pas fait : un intrus le choisirait (`dpkg -i` d'un paquet à lui).
- **La forme des lignes est une hypothèse** (la documentation d'auditd, du noyau et d'Azure Monitor,
  pas une mesure) : A1–A13 dans `docs/operations.md`, « Les hypothèses d'AUD1 », à trancher au banc avec
  Jonathan.
