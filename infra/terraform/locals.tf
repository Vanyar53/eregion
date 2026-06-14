locals {
  cfg = yamldecode(file("${path.module}/config.yaml"))

  # Global VM defaults — overridden per-VM in the `vms` map.
  vm_defaults = {
    vm_size      = local.cfg.vm_size
    disk_size_gb = local.cfg.disk_size_gb
  }

  # Per-VM config: merge global defaults with the per-VM overrides, then bake in
  # the resource names. Key "victim" keeps the historical names so the existing
  # deployment migrates in place (see moved.tf) — no destroy/recreate, recovery
  # points preserved. Extra VMs get names derived from their key.
  vms = {
    for key, override in try(local.cfg.vms, { victim = {} }) :
    key => merge(
      local.vm_defaults,
      override == null ? {} : override,
      {
        vm_name   = key == "victim" ? "vm-annatar-victim" : "vm-annatar-${key}"
        nic_name  = key == "victim" ? "nic-annatar-vm" : "nic-annatar-vm-${key}"
        pip_name  = key == "victim" ? "pip-annatar-vm" : "pip-annatar-vm-${key}"
        disk_name = key == "victim" ? "disk-annatar-testdata" : "disk-annatar-testdata-${key}"
        dcra_name = key == "victim" ? "dcra-annatar-vm" : "dcra-annatar-${key}"
      }
    )
  }
}
