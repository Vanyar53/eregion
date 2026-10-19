# Orodruin — le contrat de garde-fous vérifié au démarrage

_Conception — 2026-10-14, relue en Opus 5.5 le 2026-10-15 — statut : **code écrit le 19/10**
(O1, partie A : `eregion_core/orodruin.py`, `infra/orodruin/`, mutants M64–M66), **rien de
mesuré** : la VM n'existe pas encore. Les comportements Azure (lecture des attributions,
sortie réelle, délai de révocation) se mesurent sur le banc avec Jonathan (partie B)._

## Ce qu'Orodruin est, et ce qu'il n'est pas

Orodruin est l'hôte d'où les injecteurs (Annatar, puis Gothmog) agissent : une VM jetable,
séparée des cibles, dont les droits et la sortie réseau sont bornés, et qui **ne s'arme que si
son contrat tient**. Contrat non vérifié ⇒ mode passif : les injecteurs ne touchent rien.

Orodruin n'est pas un garde-fou de cible — c'est `eregion_core/inscription.py` (O0) qui décide
si une ressource est inscrite et si sa zone autorise l'expérience. Orodruin est la couche en
dessous : même si un injecteur essayait d'agir hors cible inscrite, l'identité et le réseau
d'Orodruin ne le lui permettraient pas. Les deux sont indépendants et se cumulent.

```
inscription (O0)   « cette cible est-elle à moi, sa zone permet-elle ceci ? »  — logique
contrat Orodruin   « cet hôte a-t-il le droit, et seulement le droit, d'agir ? » — infra
```

## Le contrat

Six garanties. Chacune a un mécanisme, et une vérification qui ne demande **aucune écriture**
(elle lit l'état effectif, ou tente une action qui doit échouer).

| Garantie | Mécanisme | Vérifiée par |
|---|---|---|
| Périmètre réseau | sortie limitée au banc, aux API de contrôle du cloud et à l'API du modèle | une connexion hors périmètre échoue |
| Identité limitée | identité d'exécution restreinte au groupe de ressources du banc | lecture de ses attributions de rôle, à toutes les portées, et de ses droits effectifs sur le banc |
| Cibles inscrites | l'inscription est revérifiée à chaque injection | refus sans inscription (O0, déjà en place) |
| Plafond | limite de l'orchestrateur, ou quota | configuration effective lue |
| Arrêt d'urgence | révoquer l'identité, tout arrêter | essai à blanc en CI |
| Audit | chaque appel d'un injecteur journalisé **avant** exécution | l'écriture précède l'appel |

### `orodruin-check` — la porte

`orodruin-check` vérifie le contrat et rend un verdict à code stable, comme la préparation de
Glorfindel (`readiness.py`) : `armed` (tout tient) ou `passive` (au moins une garantie manque),
avec la liste des manques. Rien n'est écrit. Tant que le verdict n'est pas `armed`, tout
injecteur lancé depuis Orodruin reste passif — il ne touche aucune cible.

Lectures du contrat, sans écriture :

- **identité**, deux lectures, parce qu'il faut prouver une absence autant qu'une présence :
  - ses **attributions de rôle, à toutes les portées** (`Microsoft.Authorization/roleAssignments`,
    filtrées sur le principal de l'identité) : chacune doit être contenue dans le groupe du banc.
    Une attribution plus large (l'abonnement, un autre groupe) = manque. C'est ce qui prouve
    qu'elle n'a **aucun** droit ailleurs ;
  - ses **droits effectifs sur le groupe du banc** (`Microsoft.Authorization/permissions`, toutes
    les pages) : elle peut faire ce que les injecteurs demandent. La brique existe dans l'audit de
    Glorfindel (`check_permissions`), mais elle prouve la **présence** d'un droit sur une portée
    donnée, jamais son absence ailleurs — d'où la première lecture.

  Non couverts par ces lectures, à mesurer sur le banc à l'implémentation : les droits venus d'un
  groupe Entra ID dont l'identité serait membre, les deny assignments, PIM.
- **réseau** : une tentative de connexion vers une adresse hors périmètre doit échouer (timeout
  ou refus). Le périmètre autorisé : le banc, l'API de contrôle du cloud, l'API du modèle.
- **plafond** : la configuration effective de l'orchestrateur (ou le quota) est lue et comparée
  à la limite déclarée.

Un contrat qui ne peut pas être lu (API injoignable, droits insuffisants pour lire les droits)
→ `passive`, jamais `armed` par défaut : on échoue fermé.

### L'ordre d'un run

```
orodruin-check → armed ?
  non  → passif : l'injecteur ne touche rien, dit pourquoi
  oui  → pour chaque injection :
           journaliser l'appel (qui, quoi, quand, cible)   ← AVANT
           inscription O0 (check_target)                   ← refus si hors cible/zone
           exécuter
```

Le journal précède l'exécution, toujours. Un run interrompu entre le journal et l'appel laisse
une trace « on allait faire ceci » — jamais un appel sans trace.

### `orodruin-kill` — l'arrêt d'urgence

`orodruin-kill` **révoque l'identité d'exécution** puis arrête la VM, dans cet ordre : révoquer
d'abord, pour qu'un injecteur en cours perde ses droits même si l'arrêt de la VM traîne. Un kill
qui arrêterait la VM sans révoquer l'identité serait un faux arrêt (l'identité survit à un
redémarrage). L'essai à blanc en CI vérifie que l'ordre tient et que la révocation est bien
tentée avant l'arrêt.

## Les cibles Make

| Cible | Fait |
|---|---|
| `orodruin-up` | crée la VM et l'identité, état Terraform **séparé** de Celebrimbor |
| `orodruin-check` | vérifie le contrat, affiche le verdict, n'écrit rien |
| `orodruin-stop` | éteint la VM sans la détruire (pause) |
| `orodruin-down` | détruit la VM et l'identité |
| `orodruin-kill` | révoque l'identité, puis arrête la VM (urgence) |

État Terraform séparé : Orodruin ne partage pas le `terraform.tfstate` de Celebrimbor, pour
qu'un `apply` ou un `down` de l'un ne touche jamais l'autre (même règle que les topologies).

## Mutants d'O1 (à ajouter au harnais avant la fusion)

La spécification d'O1 nomme trois bugs. Chacun aura son mutant dans `scripts/mutation_check.py`,
mesuré par les tests d'Orodruin (table `TESTS`, comme O0) :

1. **contrat non vérifié mais mode actif** : `orodruin-check` échoue (ou n'est pas lancé) et les
   injecteurs agissent quand même → un run doit rester passif.
2. **journal écrit après l'appel** : l'ordre est inversé → un appel sans trace préalable.
3. **arrêt d'urgence qui oublie la révocation** : `orodruin-kill` arrête la VM sans révoquer
   l'identité → l'identité survit.

## L'implémentation (19/10)

- **La porte, c'est le contrat lui-même.** Le moteur d'Annatar (`run`) et `clean` appellent
  `arm()` avant de lire la cible. Il n'y a pas de drapeau « je suis sur Orodruin » : sur un poste
  d'opérateur (droits sur tout l'abonnement, sortie ouverte), les mêmes lectures échouent, donc
  l'injecteur y reste passif.
- **Un seul point de passage pour l'audit** : `AzureVMExecutor._before_call`, appelé avant tout
  appel qui écrit sur la cible (le démarrage d'une VM arrêtée compris). Sans session armée, il
  refuse (`Passive`). La ligne est écrite sur disque (fsync) avant l'appel ; au-delà du plafond,
  une ligne `refused_cap` et l'appel n'a pas lieu.
- **Qui je suis** : l'`oid` du jeton de l'API de contrôle, pas un réglage qui pourrait dériver.
- **Plafond** : `EREGION_MAX_INJECTIONS` (≤ 20) et `EREGION_MAX_RUN_S` (≤ 2 h, la durée maximale
  d'une fenêtre d'exercice), déclarés dans `orodruin.env`. Absent ou au-dessus du plafond →
  `passive`.
- **Réseau** : deux sondes TCP vers des adresses hors périmètre (`1.1.1.1:443`, `9.9.9.9:443`),
  par adresse (le DNS reste autorisé).
- **Kill** : `infra/orodruin/kill.py`, depuis le `az login` de l'opérateur. Il supprime toutes
  les attributions de l'identité (filtrées sur `principalId`, à toutes les portées), puis
  désalloue la VM sans attendre.
- **Sortie** : règles NSG séparées, avec le refus d'Internet posé par `egress_locked` (vrai par
  défaut). Le premier apply le lève, le temps d'installer Docker. L'image d'Annatar arrive
  ensuite par SSH.

Décisions du 19/10 (go de Jonathan sur le plan) :
- la porte est stricte partout ;
- pas de peering avec le banc ;
- le canal des fenêtres B2 vers la watch hébergée (un conteneur de stockage dans
  `rg-orodruin`, lu par Glorfindel) vient après la mesure ;
- le rôle de lecture au niveau de l'abonnement (`contract_reader`) seulement si la mesure
  l'exige.

## Questions ouvertes (pour Jonathan, à l'implémentation)

- **Identité d'exécution** : ~~une identité managée ou un principal de service dédié ?~~
  **Tranché le 15/10 : une identité managée attachée à la VM Orodruin**, avec un rôle limité au
  groupe du banc. Pas de secret à gérer ; `orodruin-kill` retire son attribution de rôle (voir
  « Révocation »).
- **Périmètre réseau** : un NSG sur la VM Orodruin qui n'autorise en sortie que le banc + les
  préfixes des API du cloud (service tags `AzureResourceManager`, `AzureActiveDirectory`) + l'API
  du modèle ? Les service tags couvrent les API de contrôle ; l'API du modèle est une adresse
  externe à autoriser nommément.
- **Coût** : la VM Orodruin s'ajoute au banc (~5–9 €/mois d'après la ROADMAP). `orodruin-stop`
  entre les sessions, comme Celebrimbor.
- **Révocation** : révoquer une identité managée = retirer son attribution de rôle ; révoquer un
  principal de service = désactiver le principal ou retirer son attribution. L'essai à blanc en CI
  doit pouvoir simuler la révocation sans toucher à une vraie identité (mock de l'appel).

## Ce que ce document ne décide pas

- Le mode Kubernetes (O2) et le mode relais (SaaS) — plus tard. Ce document couvre le mode VM
  dédiée (O1).
- Rien n'est mesuré ici : c'est une conception. Les comportements Azure (révocation effective,
  périmètre réseau réel) seront **mesurés sur le banc** à l'implémentation, comme l'exige la règle
  « certitude par la mesure ».
