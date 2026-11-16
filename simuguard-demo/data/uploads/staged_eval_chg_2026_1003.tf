# Synthesized Terraform HCL from ServiceNow Change Request
resource "panos_security_policy" "Allow_Banking_App_To_DB" {
  rule {
    name                  = "Allow-Banking-App-To-DB"
    source_zones          = ["Trust-Application"]
    source_addresses      = ["10.200.10.0/24"]
    destination_zones     = ["Trust-Database"]
    destination_addresses = ["10.200.20.15/32"]
    applications          = ["postgresql"]
    services              = ["tcp-5432"]
    action                = "allow"
    security_profile_group = "Strict-Enterprise-Security"
  }
}
