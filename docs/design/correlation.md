# La corrélation, brique du produit (COR1)

Décision de Jonathan (02/11), après la relecture d'ADM1 : « faire le meilleur ». Une détection qui
relie deux événements vaut plus que deux détections isolées. La corrélation fait donc partie du produit :
c'est une brique réutilisable de Glorfindel, pas l'astuce d'une règle.

Code : `glorfindel/correlation.py`. Tests : `tests/unit/test_correlation.py`. Issue : #407.

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
  terminal, son processus) demande `auditd` : c'est AUD1.
- **Un réducteur de bruit, pas une preuve** (décision de Jonathan, 02/11). Tout utilisateur local
  peut écrire une ligne de connexion sshd venant d'une origine déclarée (`logger -p auth.info -t
  sshd`). L'écart par origine ne tient donc que contre un administrateur honnête et contre un intrus
  qui ne connaît pas Eregion. Un intrus dont la vraie session est plus ancienne que la fenêtre, ou un
  accès qui n'écrit aucune ligne de session, peut faire écarter un shell root seul. Les commandes
  sensibles restent toujours une carte. Une ligne forgée n'efface jamais une session réelle vue dans
  la fenêtre. La réponse est planifiée : l'origine confirmée hors de la VM (Bastion, flux réseau),
  **COR2, #427**.
- **Pour le brute force, l'ordre n'est pas vérifié.** La ligne agrégée ne dit pas l'instant du premier
  échec : une connexion réussie depuis l'adresse, n'importe où dans la fenêtre, suffit. Une
  connexion réussie juste avant les échecs est aussi suspecte. La dédup tient pour une ligne
  agrégée (la règle livrée). Pour une règle du client qui rend des lignes datées, la marque ne
  change pas l'identité.
