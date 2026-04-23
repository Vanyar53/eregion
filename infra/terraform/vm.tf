resource "azurerm_linux_virtual_machine" "victim" {
  name                = "vm-sechaos-victim"
  resource_group_name = azurerm_resource_group.sechaos.name
  location            = azurerm_resource_group.sechaos.location
  size                = var.vm_size
  admin_username      = var.admin_username
  tags = merge(azurerm_resource_group.sechaos.tags, {
    "sechaos-test" = "true"
  })

  network_interface_ids = [azurerm_network_interface.sechaos_vm.id]

  admin_ssh_key {
    username   = var.admin_username
    public_key = var.admin_ssh_public_key
  }

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }

  source_image_reference {
    publisher = "Canonical"
    offer     = "0001-com-ubuntu-server-jammy"
    sku       = "22_04-lts-gen2"
    version   = "latest"
  }

  # Prepare test data volume mount and safety marker
  custom_data = base64encode(<<-EOF
    #!/bin/bash
    mkfs.ext4 /dev/sdc
    mkdir -p /mnt/testdata
    mount /dev/sdc /mnt/testdata
    echo "/dev/sdc /mnt/testdata ext4 defaults 0 0" >> /etc/fstab
    touch /mnt/testdata/.sechaos_test_marker
    chmod 600 /mnt/testdata/.sechaos_test_marker
  EOF
  )
}

resource "azurerm_managed_disk" "testdata" {
  name                 = "disk-sechaos-testdata"
  location             = azurerm_resource_group.sechaos.location
  resource_group_name  = azurerm_resource_group.sechaos.name
  storage_account_type = "Standard_LRS"
  create_option        = "Empty"
  disk_size_gb         = 32
  tags                 = azurerm_resource_group.sechaos.tags
}

resource "azurerm_virtual_machine_data_disk_attachment" "testdata" {
  managed_disk_id    = azurerm_managed_disk.testdata.id
  virtual_machine_id = azurerm_linux_virtual_machine.victim.id
  lun                = 10
  caching            = "None"
}

# Azure Monitor Agent extension
resource "azurerm_virtual_machine_extension" "ama" {
  name                       = "AzureMonitorLinuxAgent"
  virtual_machine_id         = azurerm_linux_virtual_machine.victim.id
  publisher                  = "Microsoft.Azure.Monitor"
  type                       = "AzureMonitorLinuxAgent"
  type_handler_version       = "1.0"
  auto_upgrade_minor_version = true
}
