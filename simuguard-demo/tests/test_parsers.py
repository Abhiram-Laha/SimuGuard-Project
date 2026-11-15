"""Unit tests for Terraform / HCL parser and resource normalizer."""

from pathlib import Path
import pytest
from simuguard.parsers.hcl_parser import TerraformHclParser
from simuguard.parsers.resource_models import (
    AwsIamRolePolicyAttachmentResource,
    AwsSecurityGroupRuleResource,
    PanosSecurityPolicyResource,
)

BASE_DIR = Path(__file__).parent.parent.resolve()
CHANGES_DIR = BASE_DIR / "changes"


@pytest.fixture
def parser() -> TerraformHclParser:
    return TerraformHclParser()


class TestPanosSecurityPolicyParser:
    """Tests for PAN-OS security policy parsing and normalization."""

    def test_parse_panos_security_policy_valid(self, parser: TerraformHclParser):
        hcl = """
        resource "panos_security_policy" "test_policy" {
          rule {
            name                  = "Allow-HTTPS-Web"
            source_zones          = ["Trust-DMZ"]
            source_addresses      = ["10.100.4.0/24"]
            destination_zones     = ["Untrust-Internet"]
            destination_addresses = ["52.84.120.0/22"]
            applications          = ["ssl", "web-browsing"]
            services              = ["service-https"]
            action                = "allow"
            security_profile_group = "Strict-Enterprise-Security"
          }
        }
        """
        parsed = parser.parse_string(hcl, filename="test_panos.tf")
        assert parsed.is_valid_hcl is True
        assert len(parsed.resources) == 1

        res = parsed.resources[0]
        assert isinstance(res, PanosSecurityPolicyResource)
        assert res.resource_type == "panos_security_policy"
        assert res.resource_name == "test_policy"
        assert len(res.rules) == 1

        rule = res.rules[0]
        assert rule.name == "Allow-HTTPS-Web"
        assert rule.source_zones == ["Trust-DMZ"]
        assert rule.source_addresses == ["10.100.4.0/24"]
        assert rule.destination_zones == ["Untrust-Internet"]
        assert rule.destination_addresses == ["52.84.120.0/22"]
        assert rule.applications == ["ssl", "web-browsing"]
        assert rule.security_profile_group == "Strict-Enterprise-Security"
        assert rule.action == "allow"

    def test_parse_panos_security_policy_wildcards(self, parser: TerraformHclParser):
        """Verify extraction of 'any' applications and 'none' security profile."""
        hcl = """
        resource "panos_security_policy" "wildcard_policy" {
          rule {
            name                  = "Allow-All"
            source_zones          = ["Trust-DMZ"]
            source_addresses      = ["10.100.4.0/24"]
            destination_zones     = ["Untrust-Internet"]
            destination_addresses = ["any"]
            applications          = ["any"]
            services              = ["service-https"]
            action                = "allow"
            security_profile_group = "none"
          }
        }
        """
        parsed = parser.parse_string(hcl, filename="wildcard.tf")
        assert parsed.is_valid_hcl is True
        res = parsed.resources[0]
        assert isinstance(res, PanosSecurityPolicyResource)
        rule = res.rules[0]
        assert rule.applications == ["any"]
        assert rule.destination_addresses == ["any"]
        assert rule.security_profile_group == "none"


class TestAwsSecurityGroupRuleParser:
    """Tests for AWS Security Group Rule parsing and schema validation."""

    def test_parse_valid_aws_security_group_rule(self, parser: TerraformHclParser):
        hcl = """
        resource "aws_security_group_rule" "allow_outbound" {
          type              = "egress"
          from_port         = 443
          to_port           = 443
          protocol          = "tcp"
          cidr_blocks       = ["0.0.0.0/0"]
          security_group_id = "sg-analytics-web-01"
        }
        """
        parsed = parser.parse_string(hcl, filename="sg_valid.tf")
        assert parsed.is_valid_hcl is True
        assert len(parsed.provider_schema_errors) == 0
        assert len(parsed.resources) == 1

        res = parsed.resources[0]
        assert isinstance(res, AwsSecurityGroupRuleResource)
        assert res.rule_type == "egress"
        assert res.from_port == 443
        assert res.to_port == 443
        assert res.protocol == "tcp"
        assert res.cidr_blocks == ["0.0.0.0/0"]
        assert res.security_group_id == "sg-analytics-web-01"
        assert len(res.unsupported_attributes) == 0

    def test_parse_aws_sg_with_unsupported_destination(self, parser: TerraformHclParser):
        """Verify destination = ['netflix.com'] is parsed as valid HCL but flagged with ProviderSchemaError."""
        hcl = """
        resource "aws_security_group_rule" "allow_netflix" {
          type              = "egress"
          from_port         = 443
          to_port           = 443
          protocol          = "tcp"
          destination       = ["netflix.com"]
          security_group_id = "sg-guest-01"
        }
        """
        parsed = parser.parse_string(hcl, filename="netflix.tf")
        # HCL syntax itself is valid!
        assert parsed.is_valid_hcl is True
        assert len(parsed.hcl_syntax_errors) == 0

        # Provider schema validation error must be flagged
        assert len(parsed.provider_schema_errors) == 1
        err = parsed.provider_schema_errors[0]
        assert err.resource_type == "aws_security_group_rule"
        assert "destination" in err.unsupported_attributes

        res = parsed.resources[0]
        assert isinstance(res, AwsSecurityGroupRuleResource)
        assert "destination" in res.unsupported_attributes
        assert res.unsupported_attributes["destination"] == ["netflix.com"]


class TestAwsIamRolePolicyAttachmentParser:
    """Tests for AWS IAM Role Policy Attachment parsing."""

    def test_parse_valid_iam_attachment(self, parser: TerraformHclParser):
        hcl = """
        resource "aws_iam_role_policy_attachment" "s3_access" {
          role       = "role-analytics-ingestion-svc"
          policy_arn = "arn:aws:iam::aws:policy/AmazonS3FullAccess"
        }
        """
        parsed = parser.parse_string(hcl, filename="iam.tf")
        assert parsed.is_valid_hcl is True
        assert len(parsed.resources) == 1

        res = parsed.resources[0]
        assert isinstance(res, AwsIamRolePolicyAttachmentResource)
        assert res.role == "role-analytics-ingestion-svc"
        assert res.policy_arn == "arn:aws:iam::aws:policy/AmazonS3FullAccess"

    def test_missing_required_attribute_flagged(self, parser: TerraformHclParser):
        hcl = """
        resource "aws_iam_role_policy_attachment" "incomplete" {
          role = "some-role"
        }
        """
        parsed = parser.parse_string(hcl, filename="incomplete_iam.tf")
        assert parsed.is_valid_hcl is True
        assert len(parsed.provider_schema_errors) == 1
        assert "policy_arn" in parsed.provider_schema_errors[0].error_message


class TestMalformedHclAndEdgeCases:
    """Tests for syntax error handling and resilience."""

    def test_syntax_error_unclosed_brace(self, parser: TerraformHclParser):
        bad_hcl = """
        resource "panos_security_policy" "broken" {
          rule {
            name = "Incomplete"
        """
        parsed = parser.parse_string(bad_hcl, filename="broken.tf")
        assert parsed.is_valid_hcl is False
        assert len(parsed.hcl_syntax_errors) == 1
        assert parsed.hcl_syntax_errors[0].filename == "broken.tf"
        assert len(parsed.resources) == 0

    def test_nonexistent_file_handling(self, parser: TerraformHclParser):
        parsed = parser.parse_file("non_existent_file_path.tf")
        assert parsed.is_valid_hcl is False
        assert len(parsed.hcl_syntax_errors) == 1
        assert "not found" in parsed.hcl_syntax_errors[0].error_message.lower()

    def test_multiple_resources_in_single_file(self, parser: TerraformHclParser):
        hcl = """
        resource "aws_security_group_rule" "rule1" {
          type              = "egress"
          from_port         = 80
          to_port           = 80
          protocol          = "tcp"
          cidr_blocks       = ["10.0.0.0/8"]
          security_group_id = "sg-01"
        }
        resource "aws_iam_role_policy_attachment" "attach1" {
          role       = "my-role"
          policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
        }
        """
        parsed = parser.parse_string(hcl, filename="multi.tf")
        assert parsed.is_valid_hcl is True
        assert len(parsed.resources) == 2
        types = [r.resource_type for r in parsed.resources]
        assert "aws_security_group_rule" in types
        assert "aws_iam_role_policy_attachment" in types


class TestRealSampleFilesAnalysis:
    """Tests executing real parsing against all 3 sample files in the repository."""

    def test_parse_allow_netflix_tf(self, parser: TerraformHclParser):
        path = CHANGES_DIR / "allow_netflix.tf"
        parsed = parser.parse_file(path)

        assert parsed.is_valid_hcl is True
        assert len(parsed.hcl_syntax_errors) == 0
        assert len(parsed.resources) == 1

        res = parsed.resources[0]
        assert isinstance(res, AwsSecurityGroupRuleResource)
        assert res.resource_name == "allow_outbound_netflix"
        assert res.from_port == 443
        assert res.to_port == 443
        assert res.protocol == "tcp"

        # Explicit verification: destination = ["netflix.com"] is extracted and flagged
        assert len(parsed.provider_schema_errors) == 1
        assert "destination" in parsed.provider_schema_errors[0].unsupported_attributes
        assert res.unsupported_attributes.get("destination") == ["netflix.com"]

    def test_parse_pr_4082_firewall_iam_tf(self, parser: TerraformHclParser):
        path = CHANGES_DIR / "pr_4082_firewall_iam.tf"
        parsed = parser.parse_file(path)

        assert parsed.is_valid_hcl is True
        assert len(parsed.hcl_syntax_errors) == 0
        assert len(parsed.provider_schema_errors) == 0
        assert len(parsed.resources) == 2

        # 1. AWS SG Rule with 0.0.0.0/0
        sg_res = [r for r in parsed.resources if isinstance(r, AwsSecurityGroupRuleResource)][0]
        assert sg_res.resource_name == "allow_outbound_webhook"
        assert sg_res.cidr_blocks == ["0.0.0.0/0"]

        # 2. IAM Role Policy Attachment with AmazonS3FullAccess
        iam_res = [r for r in parsed.resources if isinstance(r, AwsIamRolePolicyAttachmentResource)][0]
        assert iam_res.resource_name == "analytics_s3_access"
        assert iam_res.role == "role-analytics-ingestion-svc"
        assert iam_res.policy_arn == "arn:aws:iam::aws:policy/AmazonS3FullAccess"

    def test_parse_pr_4083_firewall_iam_tf(self, parser: TerraformHclParser):
        path = CHANGES_DIR / "pr_4083_firewall_iam.tf"
        parsed = parser.parse_file(path)

        assert parsed.is_valid_hcl is True
        assert len(parsed.hcl_syntax_errors) == 0
        assert len(parsed.provider_schema_errors) == 0
        assert len(parsed.resources) == 2

        # 1. PAN-OS Security Policy
        panos_res = [r for r in parsed.resources if isinstance(r, PanosSecurityPolicyResource)][0]
        assert panos_res.resource_name == "analytics_egress_rule"
        assert len(panos_res.rules) == 1

        rule = panos_res.rules[0]
        assert rule.name == "Allow-Analytics-Outbound-Webhook"
        assert rule.source_zones == ["Trust-DMZ"]
        assert rule.source_addresses == ["10.100.4.0/24"]
        assert rule.destination_zones == ["Untrust-Internet"]
        assert rule.destination_addresses == ["any"]
        assert rule.applications == ["any"]
        assert rule.services == ["service-https"]
        assert rule.security_profile_group == "none"
        assert rule.action == "allow"

        # 2. IAM Role Policy Attachment with AmazonS3FullAccess
        iam_res = [r for r in parsed.resources if isinstance(r, AwsIamRolePolicyAttachmentResource)][0]
        assert iam_res.resource_name == "analytics_s3_access"
        assert iam_res.role == "role-analytics-ingestion-svc"
        assert iam_res.policy_arn == "arn:aws:iam::aws:policy/AmazonS3FullAccess"

    def test_parse_entire_changes_directory(self, parser: TerraformHclParser):
        dir_res = parser.parse_directory(CHANGES_DIR)
        assert len(dir_res.files) == 3
        assert dir_res.total_resources == 5
        assert dir_res.total_hcl_syntax_errors == 0
        assert dir_res.total_provider_schema_errors == 1
