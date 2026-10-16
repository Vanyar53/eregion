locals {
  cfg = yamldecode(file("${path.module}/config.yaml"))

  # ── Namespacing d'instance ─────────────────────────────────────────────────
  # L'instance est le workspace Terraform. "default" = la stack canonique ;
  # tout autre workspace = stack éphémère, suffixée "-<instance>" → des pipelines
  # parallèles (short-run / long-run / CI) coexistent sans collision de noms ni
  # de state (state isolé par workspace).
  instance = terraform.workspace
  ns       = local.instance == "default" ? "" : "-${local.instance}"
  project  = local.cfg.project # "celebrimbor"

  # Préfixe de nom <type>-celebrimbor[-<instance>] (convention Azure CAF : type en tête).
  base_rg = "rg-${local.project}${local.ns}"

  # Storage account : 3-24 car., minuscules alphanum, pas de tiret, globalement unique.
  # default → nom lisible ; instance → token hashé court pour rester sous 24 car.
  exfil_storage_name = local.instance == "default" ? "stcelebrimborexfil" : "stcbrexfil${substr(md5(local.instance), 0, 8)}"

  # Staging SA du restore Azure Backup IaaS (disques restaurés stagés ici, même
  # région/souscription). SA dédié — séparé de l'exfil (attaque) : pas de diag
  # setting → aucune I/O de restore ne pollue le flux StorageWrite du LAW (T1041).
  staging_storage_name = local.instance == "default" ? "stcelebrimborstaging" : "stcbrstg${substr(md5(local.instance), 0, 8)}"

  common_tags = {
    project    = local.project
    managed-by = "terraform"
    eregion    = "test-infra"
    instance   = local.instance
    # Inscription (eregion_core/inscription.py, O0) : aucun injecteur n'agit sur un
    # groupe ni une VM sans `eregion-target=<id du banc>` ; la zone dit ce qui peut y
    # tourner. Tout Celebrimbor EST le banc de référence → inscrit par construction
    # (survit aux rebuilds). Une instance nommée est un autre banc.
    "eregion-target" = local.instance == "default" ? "celebrimbor" : "celebrimbor-${local.instance}"
    "eregion-zone"   = "bench"
    # Ancien tag de chaos, encore lu pendant la migration — à retirer quand le banc
    # porte les tags ci-dessus (après un `make celebrimbor-up`).
    "annatar-test" = "true"
  }

  # Une VM `enrolled: false` (config.yaml) porte les mêmes tags SAUF ceux de l'inscription :
  # sans eregion-target ni annatar-test, eregion_core/inscription.py refuse toute injection
  # contre elle (bree, la VM de la pré-observation). Seule la VM compte pour l'inscription.
  inscription_tags = ["eregion-target", "eregion-zone", "annatar-test"]
  unenrolled_tags  = { for k, v in local.common_tags : k => v if !contains(local.inscription_tags, k) }

  # ── Hôtes baseline ─────────────────────────────────────────────────────────
  vm_defaults = {
    vm_size      = local.cfg.vm_size
    disk_size_gb = local.cfg.disk_size_gb
    image        = local.cfg.vm_image
    os_disk      = local.cfg.os_disk
  }

  # Per-host : merge des défauts + surcharges + noms dérivés de la clé (nom propre Tolkien).
  # Knobs par hôte (dans config.yaml vms.<clé>) :
  #   enabled   (défaut true)  → false = hôte NON déployé (gate opt-in, ex. honeypot à la demande).
  #   always_on (défaut false) → true  = pas d'auto-shutdown (VM 24/7, ex. honeypot long-run).
  #   enrolled  (défaut true)  → false = pas de tag d'inscription (aucun injecteur ne la vise).
  # Un hôte enabled:false disparaît de la map → aucune de ses ressources (for_each) n'est créée.
  vms = {
    for key, override in try(local.cfg.vms, {}) :
    key => merge(
      local.vm_defaults,
      override == null ? {} : override,
      {
        vm_name   = "vm-${local.project}-${key}${local.ns}"
        nic_name  = "nic-${local.project}-${key}${local.ns}"
        pip_name  = "pip-${local.project}-${key}${local.ns}"
        disk_name = "disk-${local.project}-${key}-data${local.ns}"
        dcra_name = "dcra-${local.project}-${key}${local.ns}"
      }
    )
    if try(override.enabled, true)
  }

  # ── Clusters managés (assets d'un autre type — cf. section clusters: du config) ──
  # Contrat exposé ici pour que la section ne flotte pas orpheline. Consommé par un
  # futur clusters.tf (azurerm_kubernetes_cluster) — pas de ressource pilotée encore.
  clusters = try(local.cfg.clusters, {})

  # ── Gating des topologies de test ──────────────────────────────────────────
  # topo_filter (var, depuis `make celebrimbor-up TOPO=...`) surcharge les flags YAML :
  #   - filtre non vide  → une topo est active SSI son nom y figure
  #   - filtre vide      → on respecte topologies.<name>.enabled du config.yaml
  topologies = try(local.cfg.topologies, {})
  topo_enabled = {
    for name, t in local.topologies :
    name => length(var.topo_filter) > 0 ? contains(var.topo_filter, name) : try(t.enabled, false)
  }
}
