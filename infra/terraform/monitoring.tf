resource "azurerm_log_analytics_workspace" "sechaos" {
  name                = "law-sechaos"
  location            = azurerm_resource_group.sechaos.location
  resource_group_name = azurerm_resource_group.sechaos.name
  sku                 = "PerGB2018"
  retention_in_days   = 30
  tags                = azurerm_resource_group.sechaos.tags
}

# Data Collection Rule — collect VM perf metrics and syslogs
resource "azurerm_monitor_data_collection_rule" "sechaos" {
  name                = "dcr-sechaos"
  resource_group_name = azurerm_resource_group.sechaos.name
  location            = azurerm_resource_group.sechaos.location
  tags                = azurerm_resource_group.sechaos.tags

  destinations {
    log_analytics {
      workspace_resource_id = azurerm_log_analytics_workspace.sechaos.id
      name                  = "law-sechaos-dest"
    }
  }

  data_flow {
    streams      = ["Microsoft-Perf", "Microsoft-Syslog"]
    destinations = ["law-sechaos-dest"]
  }

  data_sources {
    performance_counter {
      streams                       = ["Microsoft-Perf"]
      sampling_frequency_in_seconds = 10
      counter_specifiers = [
        "\\LogicalDisk(*)\\Disk Write Bytes/sec",
        "\\LogicalDisk(*)\\Disk Read Bytes/sec",
        "\\Network Interface(*)\\Bytes Sent/sec",
        "\\Processor(_Total)\\% Processor Time",
      ]
      name = "perf-counters"
    }

    syslog {
      streams        = ["Microsoft-Syslog"]
      facility_names = ["auth", "syslog", "daemon"]
      log_levels     = ["Warning", "Error", "Critical", "Alert", "Emergency"]
      name           = "syslog-collection"
    }
  }
}

resource "azurerm_monitor_data_collection_rule_association" "vm" {
  name                    = "dcra-sechaos-vm"
  target_resource_id      = azurerm_linux_virtual_machine.victim.id
  data_collection_rule_id = azurerm_monitor_data_collection_rule.sechaos.id
}

# Alert — Disk write anomaly (ransomware signal)
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "disk_write_anomaly" {
  name                = "alert-sechaos-disk-write-anomaly"
  resource_group_name = azurerm_resource_group.sechaos.name
  location            = azurerm_resource_group.sechaos.location
  tags                = azurerm_resource_group.sechaos.tags

  scopes                  = [azurerm_log_analytics_workspace.sechaos.id]
  description             = "High disk write rate — potential ransomware"
  severity                = 1
  enabled                 = true
  evaluation_frequency    = "PT1M"
  window_duration         = "PT5M"
  auto_mitigation_enabled = false

  criteria {
    query = <<-EOQ
      Perf
      | where ObjectName == "Logical Disk" and CounterName == "Disk Write Bytes/sec"
      | where CounterValue > 52428800
      | summarize MaxWrite = max(CounterValue) by bin(TimeGenerated, 1m), Computer
    EOQ
    time_aggregation_method = "Count"
    threshold               = 1
    operator                = "GreaterThan"
    failing_periods {
      minimum_failing_periods_to_trigger_alert = 1
      number_of_evaluation_periods             = 1
    }
  }
}
