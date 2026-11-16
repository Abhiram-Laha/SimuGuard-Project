# SimuGuard AI Demonstration Scenario: Safe Perimeter Firewall Change
# Scenario Identifier: SIM-DEMO-004
# Domain: Network Security / Palo Alto NGFW
# Policy Objective: Allow egress telemetry to approved enterprise SIEM ingestion collector.

resource "panos_security_policy" "safe_logging_egress" {
  rule {
    name                  = "Allow-Corp-SIEM-Outbound-Safe"
    source_zones          = ["Trust-DMZ"]
    source_addresses      = ["10.100.4.0/24"]
    source_users          = ["any"]
    destination_zones     = ["Untrust-Internet"]
    destination_addresses = ["52.84.120.0/22"] # Scoped to verified partner logging endpoint
    applications          = ["ssl", "web-browsing"] # Layer-7 App-ID deep inspection active
    services              = ["service-https"]
    action                = "allow"
    security_profile_group = "corporate-threat-prevention-standard" # Enterprise threat prevention active
  }
}
