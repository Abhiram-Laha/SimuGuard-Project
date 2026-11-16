# Synthesized Terraform HCL from ServiceNow Change Request
resource "panos_security_policy" "extracted_firewall_rule" {
  rule {
    name                  = "Allow-Service-Traffic"
    source_zones          = ["Untrust-Internet"]
    source_addresses      = ["0.0.0.0/0"]
    destination_zones     = ["Untrust-Internet"]
    destination_addresses = ["10.100.2.15/32"]
    applications          = ["any"]
    services              = ["service-https"]
    action                = "allow"
    security_profile_group = "Strict-Enterprise-Security"
  }
}
