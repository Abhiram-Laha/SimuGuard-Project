# Synthesized Terraform HCL from ServiceNow Change Request
resource "panos_security_policy" "Allow_Analytics_Outbound_Wildcard_Destination" {
  rule {
    name                  = "Allow-Analytics-Outbound-Wildcard-Destination"
    source_zones          = ["Trust-DMZ"]
    source_addresses      = ["obj-dmz-analytics-subnet (10.100.4.0/24)"]
    destination_zones     = ["Untrust-Internet"]
    destination_addresses = ["any (0.0.0.0/0)"]
    applications          = ["ssl"]
    services              = ["service-https (TCP/443)"]
    action                = "allow"
    security_profile_group = "Strict-Enterprise-Security"
  }
}
