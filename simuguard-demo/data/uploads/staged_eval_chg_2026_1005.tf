# Synthesized Terraform HCL from ServiceNow Change Request
resource "panos_security_policy" "Allow_Vendor_Integration_Any" {
  rule {
    name                  = "Allow-Vendor-Integration-Any"
    source_zones          = ["Trust-Vendor"]
    source_addresses      = ["10.100.40.0/24"]
    destination_zones     = ["Untrust-Internet"]
    destination_addresses = ["any"]
    applications          = ["any"]
    services              = ["any"]
    action                = "allow"
    security_profile_group = "none"
  }
}
