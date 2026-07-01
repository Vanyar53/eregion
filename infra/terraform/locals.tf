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
  }

  # ── Hôtes baseline ─────────────────────────────────────────────────────────
  vm_defaults = {
    vm_size      = local.cfg.vm_size
    disk_size_gb = local.cfg.disk_size_gb
  }

  # Per-host : merge des défauts + surcharges + noms dérivés de la clé (nom propre Tolkien).
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
  }

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
