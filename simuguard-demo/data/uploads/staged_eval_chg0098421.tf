# Synthesized Terraform HCL from ServiceNow Change Request
resource "panos_security_policy" "FIN_APP_TO_ACMEPAY" {
  rule {
    name                  = "FIN-APP-TO-ACMEPAY"
    source_zones          = ["DC-APP"]
    source_addresses      = ["10.24.16.0/27"]
    destination_zones     = ["INTERNET"]
    destination_addresses = ["198.51.100.40/32"]
    applications          = ["ssl"]
    services              = ["tcp/443"]
    action                = "allow"
    security_profile_group = "AGT-Internet-Strict"
  }
}
