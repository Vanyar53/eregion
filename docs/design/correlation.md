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
| `Accepted <méthode> for <compte> from <adresse> port <n> …` (sshd, sshd-session) | Une session, et son origine. Une IPv4 écrite en IPv6 (`::ffff:a.b.c.d`) est lue comme elle-même. |
| `pam_unix(sshd:session): session opened for user <compte>` sans `Accepted` du même processus (même `ProcessID`, 60 s avant au plus) | Une session dont l'origine n'est pas écrite : **inconnue**. |
| `pam_unix(<su, su-l, sudo, runuser, login, cron…>:session): session opened for user <compte> … by <autre>` | Le compte a été pris par un autre compte, ou par le système : son origine n'est **pas suivie**. |
| `pam_unix(systemd-user:session)` | Rien. systemd en ouvre une à chaque connexion SSH. |
| `session closed`, `Disconnected` | Rien (voir les limites). |

La lecture se fait en une requête par VM et par passe, sur 24 h (`SESSION_LOOKBACK_S`), filtrée sur les
comptes en cause et coupée à 1 000 lignes (`ROWS_MAX`).

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
- « aucune session SSH trouvée pour ce compte sur 24 h » ;
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
cartes de la passe. La décision reste celle du graphe (modes d'autonomie, gardes de `decide`).

La marque est un texte, donc elle fait partie de l'identité de dédoublonnage de la ligne agrégée. Un
brute force déjà en carte, puis réussi, donne **une** carte critique de plus, puis plus rien pour
cette adresse et cette VM tant que la fenêtre court. Une vérification impossible laisse la carte du
brute force telle quelle, et elle est comptée (`unchecked`).

## Ses limites, assumées

- **Une fermeture de session n'est pas lue.** N'importe quel utilisateur local écrit
  `session closed` avec `logger`. Une session d'origine inconnue, dite fermée, effacerait ce qui
  rend la carte. Toute session ouverte dans les 24 h compte donc. Conséquence : un administrateur
  qui s'est connecté une fois depuis une origine non déclarée voit ses shells root en carte pendant
  24 h. La solution est de déclarer cette origine.
- **Une session ouverte avant la fenêtre de 24 h n'est pas vue.** Si c'est la seule session, le
  résultat est inconnu, donc une carte. Mais si une autre session du même compte, d'une origine
  attendue, tombe dans la fenêtre, le shell root est écarté. Un intrus qui garde une session plus
  de 24 h, pendant qu'un administrateur se connecte depuis le bastion, passe donc.
- **Un accès qui n'écrit aucune ligne de session n'est pas vu.** C'est le cas d'un service qui tourne
  sous le compte, ou d'une ligne perdue à l'ingestion. Lier une commande à sa session exacte (son
  terminal, son processus) demande `auditd` : c'est AUD1.
- **Une ligne forgée ne peut qu'ajouter une session.** Un utilisateur local qui écrit un faux
  `Accepted` (avec `logger -p auth.info -t sshd`) ne fait que rendre plus de cartes. Il n'efface
  jamais une session réelle.
- **Pour le brute force, l'ordre n'est pas vérifié.** La ligne agrégée ne dit pas l'instant du premier
  échec : une connexion réussie depuis l'adresse, n'importe où dans la fenêtre, suffit. Une
  connexion réussie juste avant les échecs est aussi suspecte. La dédup tient pour une ligne
  agrégée (la règle livrée). Pour une règle du client qui rend des lignes datées, la marque ne
  change pas l'identité.
