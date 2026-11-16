# Synthesized Terraform HCL from ServiceNow Change Request
resource "panos_security_policy" "REPORTING_TO_FINANCE_DB" {
  rule {
    name                  = "REPORTING-TO-FINANCE-DB"
    source_zones          = ["DC-APP"]
    source_addresses      = ["TBD - application team to confirm"]
    destination_zones     = ["DC-DATABASE"]
    destination_addresses = ["TBD - DBA team to confirm"]
    applications          = ["postgresql"]
    services              = ["tcp/5432"]
    action                = "allow"
    security_profile_group = "Standard-Internal"
  }
}
