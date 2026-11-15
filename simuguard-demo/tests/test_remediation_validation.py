"""Unit and integration tests for ValidationEngine and candidate overlay (Stage 4)."""

import pytest
from simuguard.engine.analyzer import SimuGuardAnalyzer
from simuguard.models.enums import DeploymentVerdict
from simuguard.parsers.hcl_parser import TerraformHclParser
from simuguard.remediation.config_generator import ConfigGenerator
from simuguard.remediation.models import RemediationPlan
from simuguard.remediation.recommendation_engine import RecommendationEngine
from simuguard.remediation.validation_engine import ValidationEngine


@pytest.fixture
def analyzer():
    return SimuGuardAnalyzer()


@pytest.fixture
def validation_engine(analyzer):
    return ValidationEngine(base_analyzer=analyzer)


class TestValidationEngine:
    """Test closed-loop candidate validation across safe and unsafe configurations."""

    def test_candidate_validation_safe_hcl(self, validation_engine, tmp_path):
        # Create an original sample file
        orig_file = tmp_path / "pr_test.tf"
        orig_file.write_text(
            'resource "aws_security_group_rule" "test_egress" {\n'
            '  type              = "egress"\n'
            '  from_port         = 443\n'
            '  to_port           = 443\n'
            '  protocol          = "tcp"\n'
            '  cidr_blocks       = ["0.0.0.0/0"]\n'
            '  security_group_id = "sg-analytics-web-01"\n'
            '}\n',
            encoding="utf-8",
        )

        # Build candidate safe plan
        safe_hcl = (
            'resource "aws_security_group_rule" "test_egress" {\n'
            '  type              = "egress"\n'
            '  from_port         = 443\n'
            '  to_port           = 443\n'
            '  protocol          = "tcp"\n'
            '  cidr_blocks       = ["198.51.100.0/24"] # Scoped partner CIDR\n'
            '  security_group_id = "sg-analytics-web-01"\n'
            '}\n'
        )
        plan = RemediationPlan(
            plan_id="PLAN-TEST-01",
            change_ticket_id="PR-TEST-01",
            synthesized_candidate_hcl=safe_hcl,
        )

        post_report, overlay_result = validation_engine.validate_candidate_plan(
            plan=plan,
            original_file_path=str(orig_file),
        )

        assert post_report is not None
        # Must evaluate to ALLOW since scoped CIDR resolves FW-02
        assert post_report.deployment_verdict == DeploymentVerdict.ALLOW
        assert post_report.overall_risk_score == 0
        assert overlay_result.overlay_applied is True

    def test_candidate_validation_malformed_hcl_forces_block(self, validation_engine, tmp_path):
        orig_file = tmp_path / "pr_valid.tf"
        orig_file.write_text(
            'resource "aws_security_group_rule" "rule1" {\n'
            '  type = "egress"\n  from_port = 443\n  to_port = 443\n  protocol = "tcp"\n'
            '  cidr_blocks = ["10.0.0.0/8"]\n  security_group_id = "sg-analytics-web-01"\n'
            '}\n',
            encoding="utf-8",
        )

        # Malformed candidate HCL
        broken_plan = RemediationPlan(
            plan_id="PLAN-BROKEN",
            change_ticket_id="PR-BROKEN",
            synthesized_candidate_hcl='resource "aws_security_group_rule" "broken" {\n  unclosed quote = "val\n',
        )

        post_report, _ = validation_engine.validate_candidate_plan(
            plan=broken_plan,
            original_file_path=str(orig_file),
        )

        # Must force BLOCK_DEPLOYMENT due to SYNTAX-01
        assert post_report.deployment_verdict == DeploymentVerdict.BLOCK_DEPLOYMENT
        assert any(g.rule_id == "SYNTAX-01" for g in post_report.identified_security_gaps)
