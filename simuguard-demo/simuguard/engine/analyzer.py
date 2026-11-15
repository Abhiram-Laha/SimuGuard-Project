"""Central Simulation and Analysis Engine Orchestrator for SimuGuard AI.

Coordinates Terraform ingestion, provider schema validation, Digital Twin blast radius traversal,
firewall and SailPoint rule evaluation, risk scoring, and report generation.
"""

from pathlib import Path
from typing import Any, Dict, List, Optional
from simuguard.graph.blast_radius import BlastRadiusAnalyzer, BlastRadiusResult
from simuguard.graph.dataset_loader import EnterpriseDatasetLoader
from simuguard.graph.digital_twin import DigitalTwinGraph
from simuguard.models.affected_asset import AffectedAsset
from simuguard.models.enums import DeploymentVerdict, Severity
from simuguard.models.report import PreFlightSimulationReport
from simuguard.models.security_gap import SecurityGap
from simuguard.models.validation_check import ValidationCheck
from simuguard.parsers.hcl_parser import TerraformHclParser
from simuguard.parsers.resource_models import (
    AwsIamRolePolicyAttachmentResource,
    AwsSecurityGroupRuleResource,
    NormalizedResource,
    PanosSecurityPolicyResource,
    ParsedTerraformFile,
)
from simuguard.rules.base_rule import BaseRule, RuleEvaluationContext
from simuguard.rules.firewall_rules import (
    CrossZoneSegmentationRule,
    InsecureProtocolExposureRule,
    PanosAppIdBypassRule,
    RuleShadowingRule,
    ThreatProfileInspectionRule,
    UnrestrictedEgressRule,
)
from simuguard.rules.sailpoint_rules import (
    ContractorPrivilegedAccessRule,
    DormantRevokedEntitlementRule,
    InFlightAccessAssumptionRule,
    PrivilegeCreepRule,
    SeparationOfDutiesRule,
    UnprovisionedAccessRule,
)
from simuguard.engine.risk_engine import RiskEngine


class SimuGuardAnalyzer:
    """End-to-end pre-flight simulation orchestrator."""

    def __init__(
        self,
        digital_twin: Optional[DigitalTwinGraph] = None,
        dataset_loader: Optional[EnterpriseDatasetLoader] = None,
    ):
        self.loader = dataset_loader or EnterpriseDatasetLoader()
        self.dt = digital_twin or self.loader.load_as_digital_twin_graph()
        self.blast_analyzer = BlastRadiusAnalyzer(self.dt)
        self.parser = TerraformHclParser()
        self.risk_engine = RiskEngine()

        # Register standard rules
        self.rules: List[BaseRule] = [
            # Firewall Rules (FW-01 to FW-06)
            PanosAppIdBypassRule(),
            UnrestrictedEgressRule(),
            ThreatProfileInspectionRule(),
            InsecureProtocolExposureRule(),
            RuleShadowingRule(),
            CrossZoneSegmentationRule(),
            # SailPoint Rules (SP-01 to SP-06)
            InFlightAccessAssumptionRule(),
            UnprovisionedAccessRule(),
            SeparationOfDutiesRule(),
            ContractorPrivilegedAccessRule(),
            DormantRevokedEntitlementRule(),
            PrivilegeCreepRule(),
        ]

    def _check_iam_least_privilege(
        self,
        resources: List[NormalizedResource],
        blast_result: BlastRadiusResult,
    ) -> List[SecurityGap]:
        """Detect overprivileged IAM attachments (e.g. AmazonS3FullAccess to CUI vault)."""
        findings: List[SecurityGap] = []

        for res in resources:
            if isinstance(res, AwsIamRolePolicyAttachmentResource):
                # Detect full admin or full storage access
                arn = (res.policy_arn or "").lower()
                is_broad_policy = "s3fullaccess" in arn or "administratoraccess" in arn

                if is_broad_policy:
                    # Check if role has access to CUI or restricted assets in blast radius
                    cui_affected = any(
                        "cui" in node.node_id.lower() or "vault" in node.node_id.lower()
                        for node in blast_result.all_affected_nodes
                    )
                    findings.append(
                        SecurityGap(
                            rule_id="IAM-01",
                            severity=Severity.CRITICAL if cui_affected else Severity.HIGH,
                            gap_title=f"Cloud Privilege Escalation: Managed Policy '{res.policy_arn.split('/')[-1]}'",
                            technical_impact=(
                                f"Attaching broad managed policy '{res.policy_arn}' to role '{res.role}' grants "
                                "unrestricted wildcard read/write/delete actions over AWS resources, including "
                                "confidential CUI data assets in the enterprise vault."
                            ),
                            compliance_violation="NIST SP 800-171 3.1.1 & CIS AWS Benchmark v1.4.0 (Rule 1.16)",
                            remediation_guidance=(
                                f"Replace '{res.policy_arn}' with a customer-managed, least-privilege policy "
                                f"scoped to exact S3 bucket actions (e.g. s3:PutObject on telemetry staging)."
                            ),
                        )
                    )

        return findings

    def _generate_validation_plan(
        self,
        resources: List[NormalizedResource],
        gaps: List[SecurityGap],
    ) -> List[ValidationCheck]:
        """Generate ordered CLI verification checks for PAN-OS and AWS."""
        plan: List[ValidationCheck] = []
        step = 1

        for res in resources:
            if isinstance(res, PanosSecurityPolicyResource):
                for rule in res.rules:
                    plan.append(
                        ValidationCheck(
                            step_number=step,
                            target_component=f"Palo Alto Firewall ({rule.name})",
                            what_to_validate=f"Verify App-ID application and threat profile bindings for rule '{rule.name}'",
                            cli_command=f"show running security-policy rule \"{rule.name}\"",
                            expected_pass_criteria=(
                                "Applications must NOT show 'any'; security-profiles must include active profile group"
                            ),
                        )
                    )
                    step += 1

            elif isinstance(res, AwsSecurityGroupRuleResource):
                plan.append(
                    ValidationCheck(
                        step_number=step,
                        target_component=f"AWS Security Group ({res.security_group_id or res.resource_name})",
                        what_to_validate=f"Verify egress CIDR scoping on security group '{res.security_group_id}'",
                        cli_command=(
                            f"aws ec2 describe-security-group-rules "
                            f"--filters \"Name=group-id,Values={res.security_group_id}\" "
                            f"--query \"SecurityGroupRules[?IsEgress==`true`]\""
                        ),
                        expected_pass_criteria="Egress CIDR must be restricted to partner subnet, NOT 0.0.0.0/0",
                    )
                )
                step += 1

            elif isinstance(res, AwsIamRolePolicyAttachmentResource):
                plan.append(
                    ValidationCheck(
                        step_number=step,
                        target_component=f"AWS IAM Role ({res.role})",
                        what_to_validate=f"Verify attached policies on role '{res.role}' adhere to least-privilege",
                        cli_command=f"aws iam list-attached-role-policies --role-name {res.role}",
                        expected_pass_criteria="Role must NOT attach AmazonS3FullAccess or AdministratorAccess",
                    )
                )
                step += 1

        return plan

    def _synthesize_safe_remediation(
        self,
        resources: List[NormalizedResource],
        gaps: List[SecurityGap],
    ) -> str:
        """Synthesize least-privilege remediation HCL configuration."""
        blocks: List[str] = []

        for res in resources:
            if isinstance(res, PanosSecurityPolicyResource):
                blocks.append(
                    '# [REMEDIATED] Palo Alto Security Policy with explicit App-ID and Threat Prevention\n'
                    'resource "panos_security_policy" "remediated_analytics_egress" {\n'
                    '  rule {\n'
                    '    name                  = "Allow-Analytics-Outbound-Webhook-Remediated"\n'
                    '    source_zones          = ["Trust-DMZ"]\n'
                    '    source_addresses      = ["10.100.4.0/24"]\n'
                    '    source_users          = ["any"]\n'
                    '    destination_zones     = ["Untrust-Internet"]\n'
                    '    destination_addresses = ["52.84.120.0/22"] # Scoped to verified partner CIDR\n'
                    '    applications          = ["ssl", "web-browsing"] # Layer 7 App-ID enforced\n'
                    '    services              = ["service-https"]\n'
                    '    action                = "allow"\n'
                    '    security_profile_group = "corporate-threat-prevention-standard"\n'
                    '  }\n'
                    '}'
                )

            elif isinstance(res, AwsSecurityGroupRuleResource):
                sg_id = res.security_group_id or "sg-analytics-web-01"
                blocks.append(
                    f'# [REMEDIATED] Scoped AWS Security Group Egress Rule\n'
                    f'resource "aws_security_group_rule" "remediated_outbound_egress" {{\n'
                    f'  type              = "egress"\n'
                    f'  from_port         = 443\n'
                    f'  to_port           = 443\n'
                    f'  protocol          = "tcp"\n'
                    f'  cidr_blocks       = ["198.51.100.0/24"] # Scoped partner CIDR (RFC 5737)\n'
                    f'  security_group_id = "{sg_id}"\n'
                    f'}}'
                )

            elif isinstance(res, AwsIamRolePolicyAttachmentResource):
                blocks.append(
                    '# [REMEDIATED] Scoped Least-Privilege IAM Policy for Telemetry Ingestion\n'
                    'resource "aws_iam_policy" "scoped_telemetry_s3_write" {\n'
                    '  name        = "pol-telemetry-staging-write-only"\n'
                    '  description = "Scoped write-only access to unclassified telemetry bucket"\n'
                    '  policy = jsonencode({\n'
                    '    Version = "2012-10-17"\n'
                    '    Statement = [{\n'
                    '      Action   = ["s3:PutObject", "s3:AbortMultipartUpload"]\n'
                    '      Effect   = "Allow"\n'
                    '      Resource = "arn:aws:s3:::apex-telemetry-staging-us-east-1/*"\n'
                    '    }]\n'
                    '  })\n'
                    '}\n\n'
                    'resource "aws_iam_role_policy_attachment" "scoped_analytics_attachment" {\n'
                    f'  role       = "{res.role}"\n'
                    '  policy_arn = aws_iam_policy.scoped_telemetry_s3_write.arn\n'
                    '}'
                )

        if not blocks:
            return "# No configuration changes required; proposed configuration complies with security policy."

        return "\n\n".join(blocks)

    def analyze_parsed_file(
        self,
        parsed_file: ParsedTerraformFile,
        change_ticket_id: Optional[str] = None,
    ) -> PreFlightSimulationReport:
        """Run complete pre-flight simulation on an already parsed Terraform file."""
        ticket_id = change_ticket_id or Path(parsed_file.file_path).stem.upper().replace("_", "-")

        # 1. Digital Twin Blast Radius Traversal
        blast_result = self.blast_analyzer.analyze_resources(parsed_file.resources)

        # 2. Build Rule Evaluation Context
        sp_governance = self.loader.load_sailpoint_governance()
        eval_context = RuleEvaluationContext(
            digital_twin=self.dt,
            sailpoint_governance=sp_governance,
            all_resources=parsed_file.resources,
        )

        # 3. Evaluate Security Rules
        identified_gaps: List[SecurityGap] = []
        for rule in self.rules:
            rule_gaps = rule.evaluate(parsed_file.resources, eval_context)
            identified_gaps.extend(rule_gaps)

        # 4. Check IAM Least-Privilege
        iam_gaps = self._check_iam_least_privilege(parsed_file.resources, blast_result)
        identified_gaps.extend(iam_gaps)

        # 5. Handle HCL Syntax Errors (AUDIT-01)
        for syntax_err in parsed_file.hcl_syntax_errors:
            line_info = f" (line {syntax_err.line_number})" if syntax_err.line_number else ""
            identified_gaps.append(
                SecurityGap(
                    rule_id="SYNTAX-01",
                    severity=Severity.CRITICAL,
                    gap_title=f"HCL Syntax Error: {syntax_err.filename}{line_info}",
                    technical_impact=(
                        f"Terraform HCL syntax parsing failed in file '{syntax_err.filename}'{line_info}: "
                        f"{syntax_err.error_message}. Malformed configurations cannot be planned or deployed safely."
                    ),
                    compliance_violation="HashiCorp HCL Syntax Specification & Safe Pipeline Ingestion Standard",
                    remediation_guidance=(
                        f"Correct the syntax error in '{syntax_err.filename}': {syntax_err.error_message}. "
                        "Validate locally with 'terraform validate' or 'terraform fmt' before submitting change."
                    ),
                )
            )

        if not parsed_file.is_valid_hcl and not parsed_file.hcl_syntax_errors:
            identified_gaps.append(
                SecurityGap(
                    rule_id="SYNTAX-01",
                    severity=Severity.CRITICAL,
                    gap_title=f"HCL Syntax Error: {parsed_file.filename}",
                    technical_impact=f"File '{parsed_file.filename}' contains invalid HCL syntax.",
                    compliance_violation="HashiCorp HCL Syntax Specification",
                    remediation_guidance="Fix syntax errors and validate with 'terraform validate'.",
                )
            )

        # 6. Handle Provider Schema Errors separately
        for schema_err in parsed_file.provider_schema_errors:
            identified_gaps.append(
                SecurityGap(
                    rule_id="SCHEMA-01",
                    severity=Severity.HIGH,
                    gap_title=f"Terraform Provider Schema Error: {schema_err.resource_type}.{schema_err.resource_name}",
                    technical_impact=schema_err.error_message,
                    compliance_violation="Terraform AWS/PAN-OS Provider Specification",
                    remediation_guidance=(
                        f"Remove unsupported attributes: {schema_err.unsupported_attributes}. "
                        "AWS Security Groups do not accept domain names or FQDNs; use valid CIDR blocks."
                    ),
                )
            )

        # 7. Check Unmapped Resources
        has_unknown = (
            len(blast_result.unknown_nodes) > 0
            or len(blast_result.unknown_impacts) > 0
            or len(blast_result.unmapped_resources) > 0
        )
        for unmapped in blast_result.unmapped_resources:
            identified_gaps.append(
                SecurityGap(
                    rule_id="TOPOLOGY-01",
                    severity=Severity.MEDIUM,
                    gap_title=f"Unmapped Infrastructure Resource: {unmapped}",
                    technical_impact=(
                        f"Resource '{unmapped}' cannot be correlated to any verified topology node "
                        "in the Digital Twin. Impact cannot be confirmed safe."
                    ),
                    compliance_violation="NIST CSF 2.0 ID.AM-01 (Asset Inventory)",
                    remediation_guidance="Register resource in Digital Twin topology before deployment.",
                )
            )

        # 8. Compute Risk Score & Verdict
        score_breakdown = self.risk_engine.calculate_score(
            security_gaps=identified_gaps,
            blast_radius=blast_result,
            has_unknown_impact=has_unknown,
        )

        # 8. Format Predicted Affected Assets
        affected_assets = blast_result.to_affected_assets()

        # 9. Pre-Implementation Validation Plan
        validation_plan = self._generate_validation_plan(parsed_file.resources, identified_gaps)

        # 10. Safe Remediated Config
        remediated_config = self._synthesize_safe_remediation(parsed_file.resources, identified_gaps)

        # 11. Executive Summary
        exec_summary = (
            f"Pre-flight simulation for {ticket_id} concluded with verdict: {score_breakdown.verdict.value}. "
            f"Composite risk score: {score_breakdown.final_risk_score}/100. "
            f"Identified {len(identified_gaps)} security finding(s) across {len(affected_assets)} affected asset(s). "
            f"{score_breakdown.verdict_reason}"
        )

        return PreFlightSimulationReport(
            change_ticket_id=ticket_id,
            overall_risk_score=score_breakdown.final_risk_score,
            deployment_verdict=score_breakdown.verdict,
            executive_summary=exec_summary,
            predicted_affected_assets=affected_assets,
            identified_security_gaps=self.risk_engine.deduplicate_gaps(identified_gaps),
            pre_implementation_validation_plan=validation_plan,
            safe_remediated_config=remediated_config,
            evaluated_file=parsed_file.filename,
        )

    def analyze_file(
        self,
        file_path: str,
        change_ticket_id: Optional[str] = None,
    ) -> PreFlightSimulationReport:
        """Parse and simulate a single Terraform file."""
        parsed = self.parser.parse_file(file_path)
        return self.analyze_parsed_file(parsed, change_ticket_id)

    def analyze_directory(
        self,
        dir_path: str,
        change_ticket_id: Optional[str] = None,
    ) -> PreFlightSimulationReport:
        """Parse all Terraform files in a directory and run aggregated simulation."""
        dir_result = self.parser.parse_directory(dir_path)
        all_res = dir_result.all_resources
        all_schema_errs = []
        all_syntax_errs = []
        is_all_valid = True
        for f in dir_result.files:
            all_schema_errs.extend(f.provider_schema_errors)
            all_syntax_errs.extend(f.hcl_syntax_errors)
            if not f.is_valid_hcl:
                is_all_valid = False

        synthetic_parsed = ParsedTerraformFile(
            file_path=str(dir_path),
            filename=Path(dir_path).name,
            is_valid_hcl=is_all_valid,
            hcl_syntax_errors=all_syntax_errs,
            provider_schema_errors=all_schema_errs,
            resources=all_res,
        )
        return self.analyze_parsed_file(synthetic_parsed, change_ticket_id)
