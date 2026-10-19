# Orodruin — l'hôte d'où les injecteurs agissent (O1)

Celebrimbor forge les cibles, Orodruin ce qui les éprouve : une petite VM, groupe
`rg-orodruin`, d'où Annatar (puis Gothmog) injecte sur le banc. Elle ne s'arme que si son
contrat tient ; sinon les injecteurs restent passifs et ne touchent rien.

Contrat (garanties, vérifications, kill, mutants) :
[`docs/design/orodruin-contract.md`](../../docs/design/orodruin-contract.md). Code :
[`eregion_core/orodruin.py`](../../eregion_core/orodruin.py).

## Ce que ce module pose

- **État Terraform séparé** (ici, local) : un apply ou un down de Celebrimbor ou de Glorfindel
  ne touche jamais Orodruin, et inversement.
- **Identité managée** de la VM, sans secret. Un rôle personnalisé sur `rg-celebrimbor` avec
  les seules actions que demandent les injecteurs (lire les groupes et les VMs, démarrer une
  VM, Run Command, lire les NSG) — la liste est celle d'`eregion_core/orodruin.py`, un test les
  garde identiques — plus `Log Analytics Reader` sur l'espace de logs du banc.
- **Sortie fermée** hors périmètre : API de contrôle d'Azure, Entra ID, API du modèle
  (`160.79.104.0/23`), DNS et IMDS ; le reste d'Internet refusé. Pas de peering avec le banc :
  Run Command passe par l'API de contrôle.
- **Entrée** : SSH depuis ton IP seulement.
- Pas de tag `eregion-target` : Orodruin n'est pas une cible.

## Déroulé (avec Jonathan — c'est lui qui lance les apply)

```bash
# 0. Lecture seule : quota de la famille, SKU, prix → vm_size (repli : D2als_v6)
make orodruin-plan                 # relire le plan
make orodruin-up                   # 1er apply, sortie ouverte : la VM installe Docker
make orodruin-ssh                  # attendre ~/.orodruin-ready, puis exit
make orodruin-lock                 # 2e apply : la sortie se referme
cp infra/orodruin/orodruin.env.example infra/orodruin/orodruin.env   # abonnement, plafond
make orodruin-push                 # image d'Annatar (docker save | ssh) + orodruin.env
make orodruin-check                # le contrat lu depuis la VM : armed ou passive
```

Un run se lance ensuite depuis la VM (`make orodruin-ssh`, puis `docker run … annatar run …`) :
le moteur relit le contrat au démarrage, journalise chaque appel dans `~/runs/orodruin/audit.jsonl`
avant de l'exécuter, et s'arrête au plafond déclaré.

Entre les sessions : `make orodruin-stop` (désalloue), `make orodruin-start`.

**Urgence** : `make orodruin-kill` — depuis ton `az login`, révoque toutes les attributions de
rôle de l'identité, puis désalloue la VM (`DRY_RUN=1` pour voir les commandes ; `PRINCIPAL=`
et `VM_ID=` si l'état Terraform est illisible). Le kill retire les droits hors de Terraform :
`make orodruin-lock` les repose. Retirer un rôle ne prend pas effet à l'instant (cache du plan
de contrôle) — c'est pour ça que la VM s'arrête aussi.

## À mesurer sur le banc (O1, partie B)

1. L'identité peut-elle lire ses attributions au niveau de l'abonnement avec ses seuls droits
   sur le banc ? Sinon : `contract_reader = true` (une lecture d'attributions, rien d'autre — la
   seule attribution hors du banc que le contrat accepte).
2. La sortie : une connexion hors périmètre échoue ; l'API de contrôle, Entra ID, l'API du
   modèle, DNS et IMDS passent ; depuis un conteneur aussi.
3. Le délai entre `orodruin-kill` et le premier refus de l'API.
4. Un vrai run : contrat tenu → `armed`, un scénario non destructif sur gondolin ; sortie
   rouverte exprès → `passive`, rien de touché.

Modes suivants : Kubernetes (O2, un namespace par projet), relais.
