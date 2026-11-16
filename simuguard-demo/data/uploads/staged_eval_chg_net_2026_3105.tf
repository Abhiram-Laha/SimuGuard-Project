# Synthesized Terraform HCL from ServiceNow Change Request
resource "panos_security_policy" "Allow_Untrust_Inbound_SSH_Public" {
  rule {
    name                  = "Allow-Untrust-Inbound-SSH-Public"
    source_zones          = ["Untrust-Internet"]
    source_addresses      = ["any (0.0.0.0/0)"]
    destination_zones     = ["Trust-DMZ"]
    destination_addresses = ["obj-dmz-analytics-subnet (10.100.4.0/24)"]
    applications          = ["ssh"]
    services              = ["service-ssh (TCP/22)"]
    action                = "allow"
    security_profile_group = "none"
  }
}
