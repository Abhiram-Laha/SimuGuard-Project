"""Unit tests for AwsRemediator (Stage 2)."""

import pytest
from simuguard.models.enums import Severity
from simuguard.models.security_gap import SecurityGap
from simuguard.parsers.resource_models import AwsIamRolePolicyAttachmentResource
from simuguard.remediation.aws_remediator import AwsRemediator
from simuguard.rules.base_rule import RuleEvaluationContext


@pytest.fixture
def aws_remediator():
    iam_data = {
        "roles": [{"name": "role-analytics-ingestion-svc", "id": "role-1"}],
    }
    apps_data = {
        "applications": [
            {
                "id": "APP-003-CUSTOMER-ANALYTICS",
                "name": "Customer Telemetry & Analytics",
                "iam_roles": ["role-analytics-ingestion-svc"],
            }
        ]
    }
    assets_data = {
        "data_assets": [
            {"name": "Development Staging & Telemetry Storage", "resource_id": "apex-dev-staging-telemetry"}
        ]
    }
    return AwsRemediator(
        iam_data=iam_data,
        applications_data=apps_data,
        data_assets_data=assets_data,
    )


class TestAwsRemediator:
    """Test AWS IAM least-privilege remediation and dependency evaluation."""

    def test_remediate_amazons3fullaccess_explicit_detachment(self, aws_remediator):
        res = AwsIamRolePolicyAttachmentResource(
            resource_type="aws_iam_role_policy_attachment",
            resource_name="analytics_s3_access",
            source_file="pr_4082.tf",
            role="role-analytics-ingestion-svc",
            policy_arn="arn:aws:iam::aws:policy/AmazonS3FullAccess",
        )
        gap = SecurityGap(
            rule_id="IAM-01",
            severity=Severity.CRITICAL,
            gap_title="Cloud Privilege Escalation: Managed Policy 'AmazonS3FullAccess'",
            technical_impact="Wildcard read/write/delete across all S3 buckets including CUI vault",
            compliance_violation="NIST SP 800-171 3.1.1",
        )
        ctx = RuleEvaluationContext(all_resources=[res])

        rec = aws_remediator.remediate_gap(gap, res, ctx)
        assert rec is not None
        assert rec.rule_id == "IAM-LEAST-PRIVILEGE"
        # Must explicitly replace AmazonS3FullAccess with customer policy
        assert "AmazonS3FullAccess" in rec.current_config_snippet
        assert "pol-analytics-telemetry-staging-write" in rec.recommended_config_snippet
        assert "s3:PutObject" in rec.recommended_config_snippet
        assert "apex-dev-staging-telemetry" in rec.recommended_config_snippet
        # Verify dependency checking was performed
        assert "Customer Telemetry & Analytics" in rec.dependencies[0]
        assert not rec.requires_manual_review

    def test_shared_role_triggers_operational_warning_and_manual_review(self):
        # Setup role shared across 2 applications
        apps_data = {
            "applications": [
                {"name": "App One", "iam_roles": ["shared-role"]},
                {"name": "App Two", "iam_roles": ["shared-role"]},
            ]
        }
        remediator = AwsRemediator(applications_data=apps_data)
        res = AwsIamRolePolicyAttachmentResource(
            resource_type="aws_iam_role_policy_attachment",
            resource_name="shared_attach",
            source_file="test.tf",
            role="shared-role",
            policy_arn="arn:aws:iam::aws:policy/AmazonS3FullAccess",
        )
        gap = SecurityGap(
            rule_id="IAM-01",
            severity=Severity.HIGH,
            gap_title="Cloud Privilege Escalation: AmazonS3FullAccess",
            technical_impact="Broad permissions",
            compliance_violation="CIS AWS 1.16",
        )
        ctx = RuleEvaluationContext(all_resources=[res])
        rec = remediator.remediate_gap(gap, res, ctx)
        assert rec is not None
        assert rec.requires_manual_review is True
        assert "shared by multiple applications" in rec.operational_impact
