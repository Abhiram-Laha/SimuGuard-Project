# SimuGuard AI — Terraform HCL Parser Verification (Phase 4)

This document presents the independent audit of the Terraform ingestion and parsing engine (`simuguard/parsers/hcl_parser.py` and `resource_models.py`).

---

## 1. Parser Architecture and Domain Models

The parser utilizes `python-hcl2` for AST tokenization and normalizes extracted blocks into typed Pydantic models:
- `PanosSecurityPolicyResource` (`panos_security_policy` with nested `PanosSecurityPolicyRule` blocks).
- `AwsSecurityGroupRuleResource` (`aws_security_group_rule`).
- `AwsIamRolePolicyAttachmentResource` (`aws_iam_role_policy_attachment`).
- `AwsIamPolicyDocumentResource` (`aws_iam_policy_document` / `data.aws_iam_policy_document`).
- `GenericTerraformResource` (fallback for unrecognized resource blocks).

---

## 2. Sample PR Parsing Evaluation

### PR-4082 (`changes/pr_4082_firewall_iam.tf`)
- **Extracted Resources:**
  1. `aws_security_group_rule.allow_outbound_webhook`:
     - Direction: `egress`
     - Ports: `443` to `443` (TCP)
     - CIDRs: `["0.0.0.0/0"]`
     - Target SG: `sg-analytics-web-01`
  2. `aws_iam_role_policy_attachment.analytics_s3_access`:
     - Role: `role-analytics-ingestion-svc`
     - Policy ARN: `arn:aws:iam::aws:policy/AmazonS3FullAccess`
- **Schema Errors:** 0. Valid HCL: **True**.

### PR-4083 (`changes/pr_4083_firewall_iam.tf`)
- **Extracted Resources:**
  1. `panos_security_policy.analytics_egress_rule`:
     - Rule Name: `Allow-Analytics-Outbound-Webhook`
     - Source: `["Trust-DMZ"]` (`10.100.4.0/24`)
     - Destination: `["Untrust-Internet"]` (`["any"]`)
     - Applications: `["any"]`
     - Services: `["service-https"]`
     - Security Profile Group: `"none"`
  2. `aws_iam_role_policy_attachment.analytics_s3_access`:
     - Role: `role-analytics-ingestion-svc`
     - Policy ARN: `arn:aws:iam::aws:policy/AmazonS3FullAccess`
- **Schema Errors:** 0. Valid HCL: **True**.

### `allow_netflix.tf` (`changes/allow_netflix.tf`)
- **Extracted Resource:** `aws_security_group_rule.allow_outbound_netflix`.
- **Target SG:** `sg-guest-network-01`.
- **Provider Schema Error Identified:**
  - `unsupported_attributes`: `["destination"]`
  - Error: *"Attribute 'destination' is not supported by Terraform AWS provider for resource 'aws_security_group_rule.allow_outbound_netflix'. AWS Security Groups operate at Layer 4 and do not accept domain names or FQDN destinations."*
- **Outcome:** The parser separates provider-schema errors from security findings.

---

## 3. Known Parser Limitations

1. **Static HCL vs. Dynamic Evaluation:** `python-hcl2` parses literal HCL structures. Dynamic Terraform interpolations (e.g., `for_each`, `count`, ternary conditionals `var.env == "prod" ? a : b`, or external data source lookups) are represented as literal strings rather than evaluated expressions.
2. **Local Variables and Modules:** Variable references (`var.partner_cidr`, `local.subnet_ids`) are captured as raw token strings (`"var.partner_cidr"`). Terraform module instantiation (`module "network" { ... }`) is parsed into generic blocks rather than recursively expanded.
3. **Syntax Error Pipeline Handling:** When HCL syntax errors occur (e.g. unclosed braces), the parser records an `HclSyntaxError`. As identified during this audit, the downstream analyzer must explicitly translate these into a `SYNTAX-01` blocking security gap.
