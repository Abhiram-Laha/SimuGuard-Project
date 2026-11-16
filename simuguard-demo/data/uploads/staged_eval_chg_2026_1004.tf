# Synthesized Terraform HCL from ServiceNow Change Request
resource "panos_security_policy" "Allow_Inbound_Support_Portal" {
  rule {
    name                  = "Allow-Inbound-Support-Portal"
    source_zones          = ["Untrust-Internet"]
    source_addresses      = ["any"]
    destination_zones     = ["Untrust-Internet"]
    destination_addresses = ["10.100.30.25"]
    applications          = ["ssl"]
    services              = ["tcp-443"]
    action                = "allow"
    security_profile_group = "Strict-Enterprise-Security"
  }
}
