# Synthesized Terraform HCL from ServiceNow Change Request
resource "panos_security_policy" "TEMP_VENDOR_TROUBLESHOOT" {
  rule {
    name                  = "TEMP-VENDOR-TROUBLESHOOT"
    source_zones          = ["VPN-VENDOR"]
    source_addresses      = ["10.90.8.0/24"]
    destination_zones     = ["DC-SERVER"]
    destination_addresses = ["10.24.0.0/16"]
    applications          = ["any"]
    services              = ["any"]
    action                = "allow"
    security_profile_group = "none"
  }
}
