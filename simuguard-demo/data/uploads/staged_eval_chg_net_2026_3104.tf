# Synthesized Terraform HCL from ServiceNow Change Request
resource "panos_security_policy" "Allow_Dev_To_Prod_DB_Lateral_Access" {
  rule {
    name                  = "Allow-Dev-To-Prod-DB-Lateral-Access"
    source_zones          = ["Dev-App-Workloads"]
    source_addresses      = ["obj-dev-app-subnet (10.200.10.0/23)"]
    destination_zones     = ["Database-Backend"]
    destination_addresses = ["obj-db-postgres-cluster-vip (10.100.20.10/32)"]
    applications          = ["postgresql"]
    services              = ["service-postgresql (TCP/5432)"]
    action                = "allow"
    security_profile_group = "none"
  }
}
