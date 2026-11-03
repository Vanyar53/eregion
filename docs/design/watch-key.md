# La clé de la watch (SEC19, N-03) — et ce que FS1 en reprendra

La garde « jamais sans Glorfindel » (V1) lit un battement. Avant SEC19, ce battement était
**lié** (SEC5 : le condensé de l'abonnement que la watch lit) mais pas **authentifié** : qui
pouvait écrire le fichier des injecteurs ou le blob du canal retour pouvait écrire un battement
que la garde croyait. Depuis SEC19, la garde ne croit qu'un battement signé par la clé de la watch,
vérifié avec une clé publique épinglée du côté de l'injecteur.

Code : `eregion_core/watch_key.py` (la clé, la signature, la vérification), `eregion_core/watch_gate.py`
(la garde), `eregion_core/watch_channel.py` (le battement du canal), `glorfindel/cli.py` (la copie
pour les injecteurs, la commande `glorfindel watch-key`). Tests : `tests/unit/test_watch_key.py`,
`tests/unit/test_watch_gate.py`.

## La clé

- **Une paire Ed25519**, tirée par la watch à son premier démarrage sans clé. La moitié privée :
  `~/.eregion/watch-key/watch_ed25519`, 32 octets bruts, mode 0600, son répertoire 0700, écrite en
  `O_EXCL` (deux watches qui démarrent ensemble n'en écrivent jamais deux).
- **Un répertoire que seule la watch monte** (`docker-compose.yml`, le service `watch` ; `make
  glorfindel-watch`). Jamais dans `~/.glorfindel` : la console et le bot le montent, les injecteurs
  en montent une partie. Jamais sous `runs/`. La watch refuse une clé placée là, une clé lisible par
  d'autres, un lien, un autre propriétaire, un fichier d'une autre taille : elle ne signe pas, et le
  dit dans son journal. Ses battements partent alors sans signature, et les injecteurs les refusent.
- **Le répertoire est créé avant les services**, au nom de l'opérateur (`make glorfindel-start`,
  `-restart`, `-dev`, `team-start`, `deploy.sh` sur H0). Laissé à docker, il serait à root, et la
  watch ne pourrait pas tirer sa clé.
- **La moitié publique s'épingle** : `make watch-key` (la watch de ce poste) ou
  `make glorfindel-host-watch-key` (celle de H0, lue dans son conteneur par SSH, clé d'hôte épinglée)
  donnent `export EREGION_WATCH_KEY=ed25519:<base64 de 32 octets>` et l'empreinte
  (`SHA256:…`, la forme d'une empreinte SSH). Jamais la clé privée.

## Le battement signé

La watch signe ce qu'elle écrit pour les injecteurs (`~/.glorfindel/injectors/watch_heartbeat`) et
dans le canal retour (`heartbeat.json`). Elle y ajoute trois champs :

- `seq`, un compteur qui ne fait que monter : les millisecondes de sa date, un de plus que le
  dernier quand deux tombent dans la même ;
- `key`, l'empreinte de sa clé — dite, jamais crue : la vérification se fait avec la clé épinglée ;
- `sig`, la signature Ed25519 de **`eregion.watch-beat/1`, un saut de ligne, puis le JSON canonique
  de tous les autres champs** (clés triées, sans espace) : la date, le périmètre, et sur le canal
  `since` et `windows` aussi.

Le canal local des verdicts (SEC18, `runs/verdicts/heartbeat.json`) n'est pas signé : il porte
exactement ses champs, et la garde ne le lit jamais.

## Ce que l'injecteur refuse, avant tout appel au cloud

La clé publique vient de **`EREGION_WATCH_KEY`, l'environnement de l'injecteur**, et de rien
d'autre : `orodruin.env` sur Orodruin, l'environnement de l'opérateur sur un poste (`.envrc`, passé
aux conteneurs par le compose et le Makefile). Jamais du canal, jamais du battement. L'ordre de la
garde : le battement frais (sinon son âge est dit), puis signé, puis lié au même abonnement (SEC5).
Sont refusés, la raison dite :

| Cas | Ce que dit le refus |
|---|---|
| aucune clé épinglée, ou pas une clé | `no watch key pinned (EREGION_WATCH_KEY)` et le geste (`make watch-key`, `make glorfindel-host-watch-key`, `orodruin.env`) |
| un battement sans signature (une watch d'avant SEC19, une main qui écrit là, une watch sans clé) | `unsigned` |
| signé d'une autre clé | `signed by another key`, les deux empreintes |
| une signature qui ne tient pas (un champ changé après la signature, l'empreinte d'une autre clé recopiée, une signature faite pour un autre usage) | `its signature does not hold` |
| un compteur sous celui déjà vu (un battement plus ancien rejoué après un plus récent) | `not above one already seen` |

**Le compteur vu** est gardé par clé dans `runs/orodruin/.watch_seen.json`, le répertoire des
injecteurs (SEC18). Le même battement relu (avant chaque action d'un run) n'est pas un rejeu. Un
fichier qu'on ne peut pas écrire n'est pas un refus : ce qui est lu est vérifié quand même. La
console montre la garde comme un injecteur la lit (Dagorlad) sans tenir ce compteur.

`--without-glorfindel` reste la dérogation de développement, inscrite au rapport (V1) : elle ne lit
aucun battement.

## Ce que cela prouve, et ce que non

**Prouvé** : la watch qui détient cette clé a écrit ce battement, pour cet abonnement, il y a moins
de 90 s, et l'injecteur n'en a pas vu de plus récent. **Pas prouvé** : que les workspaces de la watch
voient la cible, ni sa santé au-delà de sa boucle de battement. **Ce qui reste** : qui lit la clé
privée (root sur l'hôte de la watch, l'utilisateur de la watch) signe comme elle ; un battement
capturé reste rejouable dans sa fenêtre de 90 s tant qu'aucun plus récent n'a été lu par cet
injecteur.

## FS1 reprend cette clé (#413)

La file d'actions signée de FS1 signera avec **la même clé**, pour un autre usage. Ce qui sépare
les deux usages, c'est **le domaine**, le préfixe de ce qui est signé :

- un battement : `eregion.watch-beat/1\n` + le JSON canonique ;
- une action de la file (FS1) : `eregion.action-queue/1\n` + le JSON canonique de l'action.

Une signature faite pour la file ne se lit jamais comme un battement, ni l'inverse
(`tests/unit/test_watch_key.py::test_a_signature_under_another_domain_never_reads_as_a_heartbeat`).
FS1 ajoute son domaine à `watch_key.py`, signe par `Signer.sign(domain, body)` et vérifie par la même
clé épinglée ; il ne tire pas de seconde clé. Changer de clé (une clé lisible par d'autres, une VM
reconstruite) se fait une fois pour les deux usages : la retirer, laisser la watch en tirer une
autre, épingler la nouvelle chez les injecteurs.
