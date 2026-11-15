"""Unit tests for SimuGuard AI remediation models (Stage 1)."""

import pytest
from pydantic import ValidationError
from simuguard.models.enums import DeploymentVerdict, Severity
from simuguard.models.report import PreFlightSimulationReport
from simuguard.remediation.models import (
    BeforeAfterComparisonReport,
    CandidateOverlayResult,
    FindingIdentity,
    FindingResolutionDetail,
    FindingResolutionStatus,
    RemediationPlan,
    RemediationRecommendation,
    RemediationStatus,
)


class TestFindingIdentity:
    """Test composite finding identity construction and normalization."""

    def test_canonical_key_generation(self):
        ident = FindingIdentity(
            rule_id="FW-01",
            affected_resource="panos_security_policy.analytics_egress_rule",
            relevant_attribute="applications:any",
            original_finding_ref="App-ID Deep Inspection Bypass",
        )
        assert ident.canonical_key == "FW-01::panos_security_policy.analytics_egress_rule::applications:any"

    def test_canonical_key_wildcard_attribute_handling(self):
        ident = FindingIdentity(
            rule_id="IAM-LEAST-PRIVILEGE",
            affected_resource="aws_iam_role_policy_attachment.analytics_s3_access",
        )
        assert ident.canonical_key == "IAM-LEAST-PRIVILEGE::aws_iam_role_policy_attachment.analytics_s3_access::*"

    def test_case_insensitivity_and_stripping(self):
        ident = FindingIdentity(
            rule_id="  sp-03  ",
            affected_resource="  Identity-John-Doe  ",
            relevant_attribute="  Role-Prod-Admin  ",
        )
        assert ident.canonical_key == "SP-03::identity-john-doe::role-prod-admin"


class TestRemediationRecommendation:
    """Test RemediationRecommendation validation, status, and constraints."""

    def test_valid_recommendation_creation(self):
        ident = FindingIdentity(
            rule_id="FW-02",
            affected_resource="aws_security_group_rule.allow_outbound_webhook",
            relevant_attribute="cidr_blocks",
        )
        rec = RemediationRecommendation(
            remediation_id="REM-FW02-001",
            original_finding_id="FW-02",
            finding_identity=ident,
            rule_id="FW-02",
            affected_resource="aws_security_group_rule.allow_outbound_webhook",
            current_config_snippet='cidr_blocks = ["0.0.0.0/0"]',
            recommended_config_snippet='cidr_blocks = ["198.51.100.0/24"]',
            explanation="Scope egress to verified partner webhook CIDR.",
            security_benefit="Restricts outbound lateral exfiltration to arbitrary public hosts.",
            operational_impact="Egress restricted strictly to partner webhook service.",
            dependencies=["Partner IP verification"],
            validation_steps=["aws ec2 describe-security-group-rules"],
            confidence_score=0.95,
            limitations=None,
            requires_manual_review=False,
            status=RemediationStatus.PROPOSED,
        )
        assert rec.confidence_score == 0.95
        assert rec.status == RemediationStatus.PROPOSED
        assert not rec.requires_manual_review

    def test_confidence_score_validation(self):
        ident = FindingIdentity(rule_id="FW-01", affected_resource="r1")
        with pytest.raises(ValidationError):
            RemediationRecommendation(
                remediation_id="REM-1",
                original_finding_id="FW-01",
                finding_identity=ident,
                rule_id="FW-01",
                affected_resource="r1",
                current_config_snippet="any",
                recommended_config_snippet="ssl",
                explanation="exp",
                security_benefit="ben",
                operational_impact="imp",
                confidence_score=1.5,  # Exceeds 1.0 -> must raise ValidationError
            )

        with pytest.raises(ValidationError):
            RemediationRecommendation(
                remediation_id="REM-1",
                original_finding_id="FW-01",
                finding_identity=ident,
                rule_id="FW-01",
                affected_resource="r1",
                current_config_snippet="any",
                recommended_config_snippet="ssl",
                explanation="exp",
                security_benefit="ben",
                operational_impact="imp",
                confidence_score=-0.1,  # Below 0.0 -> must raise ValidationError
            )

        valid_rec = RemediationRecommendation(
            remediation_id="REM-1",
            original_finding_id="FW-01",
            finding_identity=ident,
            rule_id="FW-01",
            affected_resource="r1",
            current_config_snippet="any",
            recommended_config_snippet="ssl",
            explanation="exp",
            security_benefit="ben",
            operational_impact="imp",
            confidence_score=0.87654,
        )
        assert valid_rec.confidence_score == 0.8765
        # Pydantic ge=0.0, le=1.0 will raise ValidationError
        # Wait, let's verify if le=1.0 raises ValidationError or validator clamps
        # If field has le=1.0, Pydantic raises ValidationError before validator unless mode='before'
        # Let's test that invalid confidence raises ValidationError or validates properly


class TestCandidateOverlayResult:
    """Test candidate overlay data structure."""

    def test_overlay_result_construction(self):
        overlay = CandidateOverlayResult(
            overlay_applied=True,
            removed_relationships=["role-analytics-ingestion-svc -> s3-bucket-restricted-cui"],
            added_relationships=["role-analytics-ingestion-svc -> s3-dev-staging-telemetry"],
            effective_iam_permissions={"s3:PutObject": ["arn:aws:s3:::apex-dev-staging-telemetry/incoming/*"]},
            residual_sensitive_exposures=[],
            affected_applications=["APP-003-CUSTOMER-ANALYTICS"],
            operational_warnings=[],
            requires_manual_review=False,
        )
        assert overlay.overlay_applied is True
        assert len(overlay.removed_relationships) == 1
        assert len(overlay.residual_sensitive_exposures) == 0


class TestBeforeAfterComparisonReport:
    """Test differential comparison report structure and score delta."""

    def test_report_delta_calculation(self):
        pre_report = PreFlightSimulationReport(
            change_ticket_id="PR-4082",
            overall_risk_score=100,
            deployment_verdict=DeploymentVerdict.BLOCK_DEPLOYMENT,
            executive_summary="Critical security risks identified in proposed deployment.",
            safe_remediated_config="# safe",
        )
        post_report = PreFlightSimulationReport(
            change_ticket_id="PR-4082",
            overall_risk_score=0,
            deployment_verdict=DeploymentVerdict.ALLOW,
            executive_summary="All security checks passed.",
            safe_remediated_config="# safe",
        )
        comp = BeforeAfterComparisonReport(
            change_ticket_id="PR-4082",
            pre_remediation_report=pre_report,
            post_remediation_report=post_report,
            risk_score_before=100,
            risk_score_after=0,
            risk_score_delta=100,
            verdict_before=DeploymentVerdict.BLOCK_DEPLOYMENT,
            verdict_after=DeploymentVerdict.ALLOW,
            resolved_count=2,
            unresolved_count=0,
            summary_narrative="Risk reduced from 100 to 0. All 2 findings resolved.",
        )
        assert comp.risk_score_delta == 100
        assert comp.verdict_after == DeploymentVerdict.ALLOW
        assert comp.resolved_count == 2
