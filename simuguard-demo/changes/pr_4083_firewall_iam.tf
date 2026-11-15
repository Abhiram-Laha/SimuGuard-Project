# ===================================================================================
# Change Request: PR #4082
# Submitted by: Analytics Pipeline Automation Bot
# Title: Enable External Webhook Stream & S3 Lake Ingestion
# Target Firewall: pan-vm-core-firewall-01 (Mgt/Prod Perimeter)
# ===================================================================================

# ⚠️ RISK 1: Palo Alto Layer-7 App-ID Bypass & Destination Zone Over-Exposure
# This rule is intended to let DMZ pods send SSL metrics to our third-party logging vendor.
# Instead of restricting destination_addresses to the partner CIDR, it opens egress to 'any'.
# Worse, setting applications to 'any' allows malware or non-SSL web-browsing to tunnel over port 443.
resource "panos_security_policy" "analytics_egress_rule" {
  rule {
    name                  = "Allow-Analytics-Outbound-Webhook"
    source_zones          = ["Trust-DMZ"]
    source_addresses      = ["10.100.4.0/24"] # Analytics Pod Subnet
    source_users          = ["any"]
    
    destination_zones     = ["Untrust-Internet"]
    destination_addresses = ["any"] # ⚠️ Critical Flaw: Should be scoped strictly to partner CIDR (52.84.120.0/22)
    
    applications          = ["any"] # ⚠️ Critical Flaw: Bypasses Palo Alto App-ID. Should be ["ssl", "web-browsing"]
    services              = ["service-https"]
    action                = "allow"
    
    # ⚠️ RISK 2: Disables NGFW Deep Packet Threat Inspection Profiles
    # This turns off Palo Alto Antivirus, Anti-Spyware, and Vulnerability Protection profiles,
    # allowing arbitrary data exfiltration and uninspected Command & Control (C2) channels.
    security_profile_group = "none" 
  }
}

# ⚠️ RISK 3: Cloud Privilege Escalation & CUI Vault Exposure
# The analytics pod needs to write telemetry logs to an unclassified staging bucket.
# The DevOps team attached the AWS managed 'AmazonS3FullAccess' policy for a quick fix.
# This grants the pod full read, write, and delete permissions over the restricted CUI financial vault.
resource "aws_iam_role_policy_attachment" "analytics_s3_access" {
  role       = "role-analytics-ingestion-svc"
  policy_arn = "arn:aws:iam::aws:policy/AmazonS3FullAccess" # ⚠️ Critical Flaw: Violates least-privilege (NIST SP 800-171 CUI flow)
}
