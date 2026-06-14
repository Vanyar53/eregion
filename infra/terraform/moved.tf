# Migration en place : passage de ressources VM singulières → for_each (clé "victim").
# Ces blocs `moved` indiquent à Terraform que l'adresse a changé (`.victim` →
# `.victim["victim"]`) au lieu de détruire/recréer la VM existante. Les noms Azure
# de la clé "victim" sont préservés à l'identique (voir locals.tf), donc le plan
# doit afficher 0 destroy / 0 replace pour le déploiement mono-VM actuel.
#
# Une fois la migration appliquée sur tous les environnements, ces blocs peuvent
# être supprimés (ils ne servent qu'à la transition).

moved {
  from = azurerm_linux_virtual_machine.victim
  to   = azurerm_linux_virtual_machine.victim["victim"]
}

moved {
  from = azurerm_managed_disk.testdata
  to   = azurerm_managed_disk.testdata["victim"]
}

moved {
  from = null_resource.clean_lun10
  to   = null_resource.clean_lun10["victim"]
}

moved {
  from = azurerm_virtual_machine_data_disk_attachment.testdata
  to   = azurerm_virtual_machine_data_disk_attachment.testdata["victim"]
}

moved {
  from = azurerm_dev_test_global_vm_shutdown_schedule.victim
  to   = azurerm_dev_test_global_vm_shutdown_schedule.victim["victim"]
}

moved {
  from = azurerm_virtual_machine_extension.ama
  to   = azurerm_virtual_machine_extension.ama["victim"]
}

moved {
  from = azurerm_public_ip.annatar_vm
  to   = azurerm_public_ip.annatar_vm["victim"]
}

moved {
  from = azurerm_network_interface.annatar_vm
  to   = azurerm_network_interface.annatar_vm["victim"]
}

moved {
  from = azurerm_backup_protected_vm.victim
  to   = azurerm_backup_protected_vm.victim["victim"]
}

moved {
  from = azurerm_monitor_data_collection_rule_association.vm
  to   = azurerm_monitor_data_collection_rule_association.vm["victim"]
}

moved {
  from = azurerm_role_assignment.ama_dcr
  to   = azurerm_role_assignment.ama_dcr["victim"]
}

moved {
  from = azurerm_role_assignment.vm_storage_exfil
  to   = azurerm_role_assignment.vm_storage_exfil["victim"]
}
