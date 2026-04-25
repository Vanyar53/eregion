resource "azurerm_linux_virtual_machine" "victim" {
  name                = "vm-annatar-victim"
  resource_group_name = azurerm_resource_group.annatar.name
  location            = azurerm_resource_group.annatar.location
  size                = local.cfg.vm_size
  admin_username      = local.cfg.admin_username
  tags = merge(azurerm_resource_group.annatar.tags, {
    "annatar-test" = "true"
  })

  network_interface_ids = [azurerm_network_interface.annatar_vm.id]

  identity {
    type = "SystemAssigned"
  }

  admin_ssh_key {
    username   = local.cfg.admin_username
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

  custom_data = base64encode(<<-EOF
    #!/bin/bash
    # Wait for the data disk to appear (udev may not have settled yet)
    for i in $(seq 1 30); do
      DATA_DISK=$(lsblk -dpno NAME,SIZE | awk '$2=="32G"{print $1}' | head -1)
      [ -n "$DATA_DISK" ] && break
      sleep 2
    done
    if [ -z "$DATA_DISK" ]; then
      echo "ERROR: data disk not found after 60s" >&2
      exit 1
    fi
    mkfs.ext4 "$DATA_DISK"
    mkdir -p /mnt/testdata
    mount "$DATA_DISK" /mnt/testdata
    DATA_UUID=$(blkid -o value -s UUID "$DATA_DISK")
    echo "UUID=$DATA_UUID /mnt/testdata ext4 defaults,nofail 0 0" >> /etc/fstab
    touch /mnt/testdata/.annatar_test_marker
    chmod 600 /mnt/testdata/.annatar_test_marker
  EOF
  )
}

resource "azurerm_managed_disk" "testdata" {
  name                 = "disk-annatar-testdata"
  location             = azurerm_resource_group.annatar.location
  resource_group_name  = azurerm_resource_group.annatar.name
  storage_account_type = "Standard_LRS"
  create_option        = "Empty"
  disk_size_gb         = local.cfg.disk_size_gb
  tags                 = azurerm_resource_group.annatar.tags
}

resource "azurerm_virtual_machine_data_disk_attachment" "testdata" {
  managed_disk_id    = azurerm_managed_disk.testdata.id
  virtual_machine_id = azurerm_linux_virtual_machine.victim.id
  lun                = 10
  caching            = "None"
}

resource "azurerm_dev_test_global_vm_shutdown_schedule" "victim" {
  virtual_machine_id = azurerm_linux_virtual_machine.victim.id
  location           = azurerm_resource_group.annatar.location
  enabled            = true
  daily_recurrence_time = local.cfg.vm_shutdown_time
  timezone           = "UTC"

  notification_settings {
    enabled         = true
    time_in_minutes = 15
    email           = local.cfg.vm_shutdown_email
  }
}

resource "azurerm_virtual_machine_extension" "ama" {
  name                       = "AzureMonitorLinuxAgent"
  virtual_machine_id         = azurerm_linux_virtual_machine.victim.id
  publisher                  = "Microsoft.Azure.Monitor"
  type                       = "AzureMonitorLinuxAgent"
  type_handler_version       = "1.0"
  auto_upgrade_minor_version = true
}
