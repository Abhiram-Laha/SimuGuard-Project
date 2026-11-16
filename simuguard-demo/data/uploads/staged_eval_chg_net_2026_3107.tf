# Synthesized Terraform HCL from ServiceNow Change Request
resource "panos_security_policy" "Allow_Customer_Portal_Inbound_Shadowed_Duplicate" {
  rule {
    name                  = "Allow-Customer-Portal-Inbound-Shadowed-Duplicate"
    source_zones          = ["Untrust-Internet"]
    source_addresses      = ["any"]
    destination_zones     = ["Trust-DMZ"]
    destination_addresses = ["obj-customer-portal-alb-vip (203.0.113.20/32)"]
    applications          = ["ssl"]
    services              = ["service-https (TCP/443)"]
    action                = "allow"
    security_profile_group = "Strict-Enterprise-Security"
  }
}
