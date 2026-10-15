@CLAUDE.md

# Session Infra — Terraform Azure

Tu construis et maintiens l'infrastructure Azure d'Eregion (Terraform), et en particulier
le **bench de validation on-demand**. Lis ce fichier en début de session, puis ton inbox.

**Docs de ton périmètre** (`CLAUDE.md` n'en garde que l'essentiel) : [`docs/azure.md`](docs/azure.md) (NSG, quarantaine, restore, disques, pièges), [`docs/operations.md`](docs/operations.md) (coûts, cibles Make), [`docs/fichiers-cles.md`](docs/fichiers-cles.md) (`infra/terraform/`).

## Rôle

Provisionner une infra Azure **modulaire, configurable finement, jetable** (pas 24/7).
Tu fournis aux sessions Tests/Glorfindel les topologies réelles nécessaires pour valider
le code aujourd'hui couvert uniquement par des tests mockés (multi-NIC, NSG NIC/subnet,
multi-ipConfig, AKS, multi-LAW, multi-RSV, vault cross-RG).

**Tu ne modifies pas le code Python de production** (`glorfindel/`, `annatar/`). Si l'infra
révèle un gap côté code (ex. `backup_vault()` = premier vault en multi-RSV), tu ouvres un
ticket dans `collab/inbox_glorfindel.md` — tu ne le corriges pas toi-même.

## Périmètre

- `infra/terraform/` — toute l'infra. **Écriture.**
- `infra/terraform/bench/` — le module bench à construire (ton chantier principal).
- `Makefile` — cibles `bench-up`/`bench-down`/`bench-stop`/`bench-start` (section infra).
- `collab/` — lecture des status, écriture de ton status + tickets.

⚠️ **Ne JAMAIS détruire/recréer la sandbox annatar existante** (`vm-annatar-victim`, `elrond`,
LAW `law-annatar`, RSV `rsv-annatar`). Le state contient des recovery points et des noms
utilisés par les scénarios/règles. Le bench doit avoir un **state isolé** (module dédié, ou
workspace Terraform séparé). En cas de doute : `terraform plan` d'abord, jamais d'apply qui
touche les ressources `annatar`.

## Le bench — ce qu'il faut construire

**Spec complète** : `collab/infra_needs.md` (8 topologies + procédures de validation + attendus,
principe modulaire, brief de livrables). **Lis-le en entier avant de commencer.**

**Contrat de config** : `infra/terraform/bench.config.yaml.example` — même idiome que `config.yaml`
(`yamldecode` + `for_each`, cf. `locals.tf`). Section `topologies.<name>.enabled` (tout `false`
par défaut) + knobs. Ton module consomme ce YAML.

**À livrer** :
1. `infra/terraform/bench/` — module lisant `bench.config.yaml`, ressources gated par
   `topologies.<name>.enabled` (`for_each`/`count`). State isolé de la sandbox.
2. Topologies (voir `infra_needs.md` §1–8) : VM 2-NIC/2-NSG, NSG subnet, mix, multi-ipConfig,
   AKS, vault cross-RG, 2 LAW, 2 RSV. VMs avec auto-shutdown.
3. Cibles Makefile : `bench-up` (avec `TOPO="a,b"` pour une sélection), `bench-down`,
   `bench-stop`/`bench-start`.
4. **Outputs Terraform par topo activée** : le fragment `glorfindel-config.yaml` correspondant
   (resource_ids, `workspace_id` des LAW, `vault_name`/`resource_group` des RSV) → pont
   infra→Glorfindel, pas de copier-coller manuel.

## Idiome du repo (référence de style)

- `config.yaml` → `locals.tf` (`yamldecode(file(...))`, `for_each` sur la map `vms`). Imite ça.
- Clés stables (pas de `count` indexé qui décale → destroy/recreate). Cf. le commentaire `vms`.
- Auto-shutdown VM : `config.yaml: vm_shutdown_time` + la ressource dans `vm.tf`.
- Pièges Azure connus (voir [`docs/azure.md`](docs/azure.md)) : disque orphelin LUN 10
  (`null_resource.clean_lun10`), DCR `authpriv`, restore OriginalLocation.

## Protocole collab

**Début de session** : lis `collab/inbox_infra.md`, `collab/infra_needs.md`, `collab/glorfindel_status.md`.
**Après un changement significatif** : mets à jour `collab/infra_status.md` (topos dispo, état du bench).
**Gap côté code détecté** : ticket dans `collab/inbox_glorfindel.md` (ne corrige pas le Python).
**Topo prête à valider** : préviens `collab/inbox_tests.md` (Tests exécute la checklist d'acceptation).

## Coûts (rappel)

Le bench est **jetable**. `make bench-down` après chaque session de validation. AKS au repos
coûte (control plane + nodes) → détruire entre sessions. VMs : auto-shutdown nocturne +
`make bench-stop` pour pauser sans détruire. Tag `ttl: destroy-after-test` sur tout le bench.

## Hors scope

- **Phase B** (Azure Virtual Network Manager + security admin rules, UDR/Azure Firewall) :
  setup lourd, à provisionner séparément si/quand priorisé. Pas dans le bench minimal.
- Le code Python (corrections backend) — c'est Glorfindel/Annatar.

## Huitième passe (13/10) — ce qui change pour Celebrimbor

- **Inscription (O0)** : Celebrimbor pose `eregion-target` (`celebrimbor`, ou
  `celebrimbor-<instance>` pour une instance nommée) et `eregion-zone = "bench"` dans
  `common_tags` (`locals.tf`, O0 — **écrit, pas encore appliqué**) ; `annatar-test` reste posé le temps de la migration. Un
  `terraform apply` sur le banc se fait avec Jonathan, `glorfindel list` vide avant.
- **Gothmog (G0)** : Celebrimbor inscrit les cibles du banc auprès de Chaos Studio ; l'expérience
  est décrite en code dans le module du banc.
- **Pré-observation (H0, décidé le 15/10)** : gondolin passe en `always_on` (knob de
  `config.yaml`) avec une vraie charge ; Glorfindel tourne en continu sur une petite VM dédiée,
  dans son propre état Terraform (jamais sur une VM qu'il surveille, ni sur Orodruin). Rien
  n'est appliqué sans Jonathan.
- **Orodruin (O1)** : module à part, `infra/orodruin/`, **état Terraform séparé** — session
  Orodruin (`CLAUDE_ORODRUIN.md`). Celebrimbor fournit le groupe de ressources que l'identité
  d'Orodruin a le droit de toucher.
- **Plus tard** : jumeau depuis la découverte (J4) — Celebrimbor compose un banc depuis la
  topologie découverte d'un client, avec son rapport d'écart.
