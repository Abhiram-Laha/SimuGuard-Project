"""Unit tests for FirewallRemediator (Stage 2)."""

import pytest
from simuguard.models.enums import Severity
from simuguard.models.security_gap import SecurityGap
from simuguard.parsers.resource_models import (
    AwsSecurityGroupRuleResource,
    PanosSecurityPolicyResource,
    PanosSecurityPolicyRule,
)
from simuguard.remediation.firewall_remediator import FirewallRemediator
from simuguard.rules.base_rule import RuleEvaluationContext


@pytest.fixture
def firewall_remediator():
    network_data = {
        "address_objects": [
            {"name": "obj-partner-webhook-cidr", "value": "198.51.100.0/24"},
            {"name": "obj-dmz-analytics-subnet", "value": "10.100.4.0/24"},
        ],
        "policies": [
            {"name": "Allow-Core-DNS", "security_profile_group": "Strict-Enterprise-Security"}
        ],
    }
    return FirewallRemediator(modeled_network_data=network_data)


class TestFirewallRemediator:
    """Test firewall remediation logic across FW-01 through FW-06."""

    def test_fw01_panos_app_id_remediation(self, firewall_remediator):
        rule = PanosSecurityPolicyRule(
            name="Allow-Analytics-Outbound-Webhook",
            source_zones=["Trust-DMZ"],
            source_addresses=["10.100.4.0/24"],
            source_users=["any"],
            destination_zones=["Untrust-Internet"],
            destination_addresses=["any"],
            applications=["any"],
            services=["service-https"],
            action="allow",
        )
        res = PanosSecurityPolicyResource(
            resource_type="panos_security_policy",
            resource_name="analytics_egress_rule",
            source_file="test.tf",
            rules=[rule],
        )
        gap = SecurityGap(
            rule_id="FW-01",
            severity=Severity.CRITICAL,
            gap_title="PAN-OS App-ID Deep Inspection Bypass: Rule 'Allow-Analytics-Outbound-Webhook'",
            technical_impact="applications set to any disables Layer 7 inspection",
            compliance_violation="CIS PAN-OS Benchmark 4.1",
        )
        ctx = RuleEvaluationContext(all_resources=[res])

        rec = firewall_remediator.remediate_gap(gap, res, ctx)
        assert rec is not None
        assert rec.rule_id == "FW-01"
        assert 'applications = ["ssl", "web-browsing"]' in rec.recommended_config_snippet
        assert rec.confidence_score >= 0.90
        assert not rec.requires_manual_review

    def test_fw02_aws_security_group_egress_remediation(self, firewall_remediator):
        sg_res = AwsSecurityGroupRuleResource(
            resource_type="aws_security_group_rule",
            resource_name="allow_outbound_webhook",
            source_file="test.tf",
            rule_type="egress",
            from_port=443,
            to_port=443,
            protocol="tcp",
            cidr_blocks=["0.0.0.0/0"],
            security_group_id="sg-analytics-web-01",
        )
        gap = SecurityGap(
            rule_id="FW-02",
            severity=Severity.HIGH,
            gap_title="Unrestricted AWS Security Group Egress: 'allow_outbound_webhook'",
            technical_impact="Egress allows 0.0.0.0/0",
            compliance_violation="CIS AWS Benchmark 5.3",
        )
        ctx = RuleEvaluationContext(all_resources=[sg_res])

        rec = firewall_remediator.remediate_gap(gap, sg_res, ctx)
        assert rec is not None
        assert rec.rule_id == "FW-02"
        assert "198.51.100.0/24" in rec.recommended_config_snippet
        assert not rec.requires_manual_review

    def test_fw03_threat_profile_attachment_remediation(self, firewall_remediator):
        rule = PanosSecurityPolicyRule(
            name="Allow-Analytics-Outbound-Webhook",
            source_zones=["Trust-DMZ"],
            source_addresses=["10.100.4.0/24"],
            source_users=["any"],
            destination_zones=["Untrust-Internet"],
            destination_addresses=["any"],
            applications=["ssl"],
            services=["service-https"],
            action="allow",
            security_profile_group="none",
        )
        res = PanosSecurityPolicyResource(
            resource_type="panos_security_policy",
            resource_name="analytics_egress_rule",
            source_file="test.tf",
            rules=[rule],
        )
        gap = SecurityGap(
            rule_id="FW-03",
            severity=Severity.HIGH,
            gap_title="Missing Threat Prevention Profile: Rule 'Allow-Analytics-Outbound-Webhook'",
            technical_impact="security_profile_group is none",
            compliance_violation="CIS PAN-OS Benchmark 4.2",
        )
        ctx = RuleEvaluationContext(all_resources=[res])

        rec = firewall_remediator.remediate_gap(gap, res, ctx)
        assert rec is not None
        assert rec.rule_id == "FW-03"
        assert "Strict-Enterprise-Security" in rec.recommended_config_snippet or "corporate-threat-prevention-standard" in rec.recommended_config_snippet

    def test_fw04_insecure_protocol_remediation(self, firewall_remediator):
        gap = SecurityGap(
            rule_id="FW-04",
            severity=Severity.MEDIUM,
            gap_title="Insecure Cleartext Protocol: Rule 'Cleartext-HTTP'",
            technical_impact="Cleartext HTTP allows eavesdropping",
            compliance_violation="NIST SP 800-52",
        )
        ctx = RuleEvaluationContext()
        rec = firewall_remediator.remediate_gap(gap, None, ctx)
        assert rec is not None
        assert rec.rule_id == "FW-04"
        assert "service-https" in rec.recommended_config_snippet or "443" in rec.recommended_config_snippet

    def test_fw05_rule_shadowing_remediation(self, firewall_remediator):
        gap = SecurityGap(
            rule_id="FW-05",
            severity=Severity.MEDIUM,
            gap_title="Rule Shadowing: 'Specific-Rule' is shadowed by 'Broad-Rule'",
            technical_impact="Rule will never be evaluated",
            compliance_violation="NIST SP 800-41",
        )
        ctx = RuleEvaluationContext()
        rec = firewall_remediator.remediate_gap(gap, None, ctx)
        assert rec is not None
        assert rec.rule_id == "FW-05"
        assert "move rule" in rec.recommended_config_snippet

    def test_fw06_cross_zone_remediation(self, firewall_remediator):
        gap = SecurityGap(
            rule_id="FW-06",
            severity=Severity.CRITICAL,
            gap_title="Prohibited Cross-Zone Segmentation: Rule 'Untrust-To-Vault'",
            technical_impact="Direct internet flow into CUI vault",
            compliance_violation="PCI-DSS Req 1.3",
        )
        ctx = RuleEvaluationContext()
        rec = firewall_remediator.remediate_gap(gap, None, ctx)
        assert rec is not None
        assert rec.rule_id == "FW-06"
        assert "deny" in rec.recommended_config_snippet.lower()
