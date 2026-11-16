# Synthesized Terraform HCL from ServiceNow Change Request
resource "panos_security_policy" "Allow_Customer_Portal_API_HTTPS" {
  rule {
    name                  = "Allow-Customer-Portal-API-HTTPS"
    source_zones          = ["Trust-Application"]
    source_addresses      = ["10.100.10.0/24"]
    destination_zones     = ["Untrust-Internet"]
    destination_addresses = ["198.51.100.25/32"]
    applications          = ["ssl"]
    services              = ["tcp-443"]
    action                = "allow"
    security_profile_group = "Strict-Enterprise-Security"
  }
}
