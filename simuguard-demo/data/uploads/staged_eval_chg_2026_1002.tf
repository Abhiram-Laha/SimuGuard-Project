# Synthesized Terraform HCL from ServiceNow Change Request
resource "panos_security_policy" "Allow_Analytics_Internet_Access" {
  rule {
    name                  = "Allow-Analytics-Internet-Access"
    source_zones          = ["Trust-Analytics"]
    source_addresses      = ["10.100.20.0/24"]
    destination_zones     = ["Untrust-Internet"]
    destination_addresses = ["any"]
    applications          = ["any"]
    services              = ["any"]
    action                = "allow"
    security_profile_group = "none"
  }
}
