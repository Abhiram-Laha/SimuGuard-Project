"""Unit tests for SimuGuard AI firewall analysis rules (FW-01 through FW-06)."""

import pytest
from simuguard.models.enums import Severity
from simuguard.parsers.resource_models import (
    AwsSecurityGroupRuleResource,
    PanosSecurityPolicyResource,
    PanosSecurityPolicyRule,
)
from simuguard.rules.base_rule import RuleEvaluationContext
from simuguard.rules.firewall_rules import (
    CrossZoneSegmentationRule,
    InsecureProtocolExposureRule,
    PanosAppIdBypassRule,
    RuleShadowingRule,
    ThreatProfileInspectionRule,
    UnrestrictedEgressRule,
)


@pytest.fixture
def empty_context():
    return RuleEvaluationContext()


class TestFW01PanosAppIdBypassRule:
    """Test FW-01: Detection of App-ID bypass via application = ['any']."""

    def test_app_id_bypass_detected(self, empty_context):
        rule = PanosAppIdBypassRule()
        panos_res = PanosSecurityPolicyResource(
            resource_type="panos_security_policy",
            resource_name="egress_policy",
            source_file="test.tf",
            rules=[
                PanosSecurityPolicyRule(
                    name="Test-Bypass-Rule",
                    source_zones=["Trust-DMZ"],
                    source_addresses=["10.100.4.0/24"],
                    destination_zones=["Untrust-Internet"],
                    destination_addresses=["any"],
                    applications=["any"],
                    services=["service-https"],
                    action="allow",
                )
            ],
        )

        findings = rule.evaluate([panos_res], empty_context)
        assert len(findings) == 1
        assert findings[0].rule_id == "FW-01"
        assert findings[0].severity == Severity.CRITICAL
        assert "App-ID Deep Inspection Bypass" in findings[0].gap_title

    def test_explicit_app_id_compliant(self, empty_context):
        rule = PanosAppIdBypassRule()
        panos_res = PanosSecurityPolicyResource(
            resource_type="panos_security_policy",
            resource_name="egress_policy",
            source_file="test.tf",
            rules=[
                PanosSecurityPolicyRule(
                    name="Test-Compliant-Rule",
                    source_zones=["Trust-DMZ"],
                    destination_zones=["Untrust-Internet"],
                    applications=["ssl", "web-browsing"],
                    action="allow",
                )
            ],
        )

        findings = rule.evaluate([panos_res], empty_context)
        assert len(findings) == 0

    def test_deny_rule_with_any_not_flagged(self, empty_context):
        rule = PanosAppIdBypassRule()
        panos_res = PanosSecurityPolicyResource(
            resource_type="panos_security_policy",
            resource_name="egress_policy",
            source_file="test.tf",
            rules=[
                PanosSecurityPolicyRule(
                    name="Test-Deny-Rule",
                    source_zones=["Trust-DMZ"],
                    destination_zones=["Untrust-Internet"],
                    applications=["any"],
                    action="deny",
                )
            ],
        )

        findings = rule.evaluate([panos_res], empty_context)
        assert len(findings) == 0


class TestFW02UnrestrictedEgressRule:
    """Test FW-02: Platform-aware unrestricted egress across PAN-OS and AWS SGs."""

    def test_panos_unrestricted_egress_flagged(self, empty_context):
        rule = UnrestrictedEgressRule()
        panos_res = PanosSecurityPolicyResource(
            resource_type="panos_security_policy",
            resource_name="egress_policy",
            source_file="test.tf",
            rules=[
                PanosSecurityPolicyRule(
                    name="Allow-Internet",
                    source_zones=["Trust-DMZ"],
                    destination_zones=["Untrust-Internet"],
                    destination_addresses=["any"],
                    action="allow",
                )
            ],
        )

        findings = rule.evaluate([panos_res], empty_context)
        assert len(findings) == 1
        assert findings[0].rule_id == "FW-02"
        assert findings[0].severity == Severity.HIGH

    def test_panos_scoped_egress_compliant(self, empty_context):
        rule = UnrestrictedEgressRule()
        panos_res = PanosSecurityPolicyResource(
            resource_type="panos_security_policy",
            resource_name="egress_policy",
            source_file="test.tf",
            rules=[
                PanosSecurityPolicyRule(
                    name="Allow-Partner-Only",
                    source_zones=["Trust-DMZ"],
                    destination_zones=["Untrust-Internet"],
                    destination_addresses=["52.84.120.0/22"],
                    action="allow",
                )
            ],
        )

        findings = rule.evaluate([panos_res], empty_context)
        assert len(findings) == 0

    def test_aws_sg_unrestricted_egress_all_ports_critical(self, empty_context):
        rule = UnrestrictedEgressRule()
        sg_res = AwsSecurityGroupRuleResource(
            resource_type="aws_security_group_rule",
            resource_name="allow_all_egress",
            source_file="test.tf",
            rule_type="egress",
            protocol="-1",
            from_port=0,
            to_port=0,
            cidr_blocks=["0.0.0.0/0"],
            security_group_id="sg-dev-nodes",
        )

        findings = rule.evaluate([sg_res], empty_context)
        assert len(findings) == 1
        assert findings[0].rule_id == "FW-02"
        assert findings[0].severity == Severity.CRITICAL

    def test_aws_sg_unrestricted_egress_scoped_port_high(self, empty_context):
        rule = UnrestrictedEgressRule()
        sg_res = AwsSecurityGroupRuleResource(
            resource_type="aws_security_group_rule",
            resource_name="allow_https_egress",
            source_file="test.tf",
            rule_type="egress",
            protocol="tcp",
            from_port=443,
            to_port=443,
            cidr_blocks=["0.0.0.0/0"],
            security_group_id="sg-analytics-web-01",
        )

        findings = rule.evaluate([sg_res], empty_context)
        assert len(findings) == 1
        assert findings[0].rule_id == "FW-02"
        assert findings[0].severity == Severity.HIGH


class TestFW03ThreatProfileInspectionRule:
    """Test FW-03: Threat prevention profile group validation against baseline."""

    def test_missing_profile_on_protected_zone_flagged(self, empty_context):
        rule = ThreatProfileInspectionRule()
        panos_res = PanosSecurityPolicyResource(
            resource_type="panos_security_policy",
            resource_name="policy",
            source_file="test.tf",
            rules=[
                PanosSecurityPolicyRule(
                    name="No-Profile-DMZ",
                    source_zones=["Trust-DMZ"],
                    destination_zones=["Untrust-Internet"],
                    security_profile_group="none",
                    action="allow",
                )
            ],
        )

        findings = rule.evaluate([panos_res], empty_context)
        assert len(findings) == 1
        assert findings[0].rule_id == "FW-03"
        assert findings[0].severity == Severity.HIGH

    def test_attached_profile_group_compliant(self, empty_context):
        rule = ThreatProfileInspectionRule()
        panos_res = PanosSecurityPolicyResource(
            resource_type="panos_security_policy",
            resource_name="policy",
            source_file="test.tf",
            rules=[
                PanosSecurityPolicyRule(
                    name="Standard-DMZ",
                    source_zones=["Trust-DMZ"],
                    destination_zones=["Untrust-Internet"],
                    security_profile_group="corporate-threat-prevention-standard",
                    action="allow",
                )
            ],
        )

        findings = rule.evaluate([panos_res], empty_context)
        assert len(findings) == 0

    def test_omitted_profile_on_exempt_zone_not_flagged(self, empty_context):
        rule = ThreatProfileInspectionRule()
        panos_res = PanosSecurityPolicyResource(
            resource_type="panos_security_policy",
            resource_name="policy",
            source_file="test.tf",
            rules=[
                PanosSecurityPolicyRule(
                    name="Local-Loopback",
                    source_zones=["Management-Zone"],
                    destination_zones=["Management-Zone"],
                    security_profile_group=None,
                    action="allow",
                )
            ],
        )

        findings = rule.evaluate([panos_res], empty_context)
        assert len(findings) == 0


class TestFW04InsecureProtocolExposureRule:
    """Test FW-04: Cleartext protocol and port exposure with encryption context."""

    def test_cleartext_http_flagged(self, empty_context):
        rule = InsecureProtocolExposureRule()
        panos_res = PanosSecurityPolicyResource(
            resource_type="panos_security_policy",
            resource_name="policy",
            source_file="test.tf",
            rules=[
                PanosSecurityPolicyRule(
                    name="Allow-Cleartext-Web",
                    source_zones=["Corporate-User-Zone"],
                    destination_zones=["Untrust-Internet"],
                    applications=["web-browsing"],
                    services=["service-http"],
                    action="allow",
                )
            ],
        )

        findings = rule.evaluate([panos_res], empty_context)
        assert len(findings) == 1
        assert findings[0].rule_id == "FW-04"

    def test_encrypted_ssl_context_not_flagged(self, empty_context):
        rule = InsecureProtocolExposureRule()
        panos_res = PanosSecurityPolicyResource(
            resource_type="panos_security_policy",
            resource_name="policy",
            source_file="test.tf",
            rules=[
                PanosSecurityPolicyRule(
                    name="Allow-SSL-Web",
                    source_zones=["Trust-DMZ"],
                    destination_zones=["Untrust-Internet"],
                    applications=["ssl"],
                    services=["service-https"],
                    action="allow",
                )
            ],
        )

        findings = rule.evaluate([panos_res], empty_context)
        assert len(findings) == 0

    def test_database_port_exposed_publicly_critical(self, empty_context):
        rule = InsecureProtocolExposureRule()
        sg_res = AwsSecurityGroupRuleResource(
            resource_type="aws_security_group_rule",
            resource_name="public_postgres",
            source_file="test.tf",
            rule_type="ingress",
            protocol="tcp",
            from_port=5432,
            to_port=5432,
            cidr_blocks=["0.0.0.0/0"],
            security_group_id="sg-rds-postgres-prod",
        )

        findings = rule.evaluate([sg_res], empty_context)
        assert len(findings) == 1
        assert findings[0].rule_id == "FW-04"
        assert findings[0].severity == Severity.CRITICAL


class TestFW05RuleShadowingRule:
    """Test FW-05: Detection of rule shadowing based on rule evaluation order."""

    def test_shadowed_rule_detected(self, empty_context):
        rule = RuleShadowingRule()
        panos_res = PanosSecurityPolicyResource(
            resource_type="panos_security_policy",
            resource_name="policy",
            source_file="test.tf",
            rules=[
                PanosSecurityPolicyRule(
                    name="Rule-A-Broad",
                    source_zones=["Trust-DMZ"],
                    source_addresses=["any"],
                    destination_zones=["Untrust-Internet"],
                    destination_addresses=["any"],
                    applications=["any"],
                    services=["any"],
                    action="allow",
                ),
                PanosSecurityPolicyRule(
                    name="Rule-B-Specific-Shadowed",
                    source_zones=["Trust-DMZ"],
                    source_addresses=["10.100.4.0/24"],
                    destination_zones=["Untrust-Internet"],
                    destination_addresses=["52.84.120.0/22"],
                    applications=["ssl"],
                    services=["service-https"],
                    action="allow",
                ),
            ],
        )

        findings = rule.evaluate([panos_res], empty_context)
        assert len(findings) == 1
        assert findings[0].rule_id == "FW-05"
        assert "Rule-B-Specific-Shadowed" in findings[0].gap_title

    def test_non_overlapping_rules_not_shadowed(self, empty_context):
        rule = RuleShadowingRule()
        panos_res = PanosSecurityPolicyResource(
            resource_type="panos_security_policy",
            resource_name="policy",
            source_file="test.tf",
            rules=[
                PanosSecurityPolicyRule(
                    name="Rule-1-DMZ",
                    source_zones=["Trust-DMZ"],
                    destination_zones=["Untrust-Internet"],
                    applications=["ssl"],
                    action="allow",
                ),
                PanosSecurityPolicyRule(
                    name="Rule-2-Corp",
                    source_zones=["Corporate-User-Zone"],
                    destination_zones=["Internal-Core"],
                    applications=["ssh"],
                    action="allow",
                ),
            ],
        )

        findings = rule.evaluate([panos_res], empty_context)
        assert len(findings) == 0


class TestFW06CrossZoneSegmentationRule:
    """Test FW-06: Cross-zone micro-segmentation violations using topology evidence."""

    def test_untrust_to_restricted_vault_prohibited(self, empty_context):
        rule = CrossZoneSegmentationRule()
        panos_res = PanosSecurityPolicyResource(
            resource_type="panos_security_policy",
            resource_name="policy",
            source_file="test.tf",
            rules=[
                PanosSecurityPolicyRule(
                    name="Illegal-Direct-Vault-Access",
                    source_zones=["Untrust-Internet"],
                    destination_zones=["Restricted-Data-Vault"],
                    action="allow",
                )
            ],
        )

        findings = rule.evaluate([panos_res], empty_context)
        assert len(findings) == 1
        assert findings[0].rule_id == "FW-06"
        assert findings[0].severity == Severity.CRITICAL

    def test_dmz_to_pci_direct_access_prohibited(self, empty_context):
        rule = CrossZoneSegmentationRule()
        panos_res = PanosSecurityPolicyResource(
            resource_type="panos_security_policy",
            resource_name="policy",
            source_file="test.tf",
            rules=[
                PanosSecurityPolicyRule(
                    name="Illegal-DMZ-To-PCI",
                    source_zones=["Trust-DMZ"],
                    destination_zones=["PCI-Cardholder-Zone"],
                    action="allow",
                )
            ],
        )

        findings = rule.evaluate([panos_res], empty_context)
        assert len(findings) == 1
        assert findings[0].rule_id == "FW-06"
        assert findings[0].severity == Severity.CRITICAL
