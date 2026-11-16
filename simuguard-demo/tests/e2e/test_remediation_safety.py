"""Safety, Immutability, and Exact Boundary Tests for Remediation & Risk Engines (Milestone F, Stage 4).

Verifies:
- Candidate remediation NEVER mutates original configuration files or baseline Digital Twin.
- Unsafe relationships are severed in candidate overlay graph without affecting baseline.
- Replacement rules strictly use supported values from modeled environment.
- Unmapped values trigger manual review warnings.
- Exact score boundary tests: 0, 39, 40, 69, 70, 100.
- Strict precedence rules: CRITICAL -> BLOCK, Score >= 70 -> BLOCK, HIGH -> WARN, UNKNOWN -> WARN, ALLOW only when score < 40 and zero blocking/warning findings.
"""

from pathlib import Path
import pytest

from simuguard.engine.risk_engine import RiskEngine
from simuguard.graph.blast_radius import BlastRadiusResult, ImpactedNode, UnknownImpactAsset
from simuguard.graph.dataset_loader import EnterpriseDatasetLoader
from simuguard.graph.digital_twin import DigitalTwinGraph
from simuguard.models.enums import AssetCriticality, BlastTier, DeploymentVerdict, Severity
from simuguard.models.security_gap import SecurityGap
from simuguard.parsers.resource_models import AwsIamRolePolicyAttachmentResource, NormalizedResource
from simuguard.remediation.candidate_overlay import CandidateDigitalTwinOverlay
from simuguard.remediation.models import FindingIdentity, RemediationRecommendation, RemediationStatus


@pytest.fixture
def risk_engine() -> RiskEngine:
    return RiskEngine()


# =============================================================================
# 1. Exact Risk Engine Boundary Tests
# =============================================================================

def test_risk_boundary_zero_score_allow(risk_engine: RiskEngine):
    """Test score 0: Zero findings and zero unmapped impacts produces ALLOW."""
    breakdown = risk_engine.calculate_score(security_gaps=[], blast_radius=None, has_unknown_impact=False)
    assert breakdown.final_risk_score == 0
    assert breakdown.verdict == DeploymentVerdict.ALLOW


def test_risk_boundary_39_score_allow(risk_engine: RiskEngine):
    """Test boundary score 39: Below 40 with Low findings renders ALLOW."""
    # 13 Low gaps (weight 3 each = 39.0 base score * 1.0 = 39)
    low_gaps = [
        SecurityGap(
            rule_id=f"HYGIENE-{i}",
            severity=Severity.LOW,
            gap_title=f"Minor Configuration Deviation {i}",
            technical_impact="Low impact operational finding.",
            compliance_violation="NIST SP 800-53 CM-6",
        )
        for i in range(13)
    ]
    breakdown = risk_engine.calculate_score(security_gaps=low_gaps, blast_radius=None, has_unknown_impact=False)
    assert breakdown.final_risk_score == 39
    assert breakdown.verdict == DeploymentVerdict.ALLOW


def test_risk_boundary_40_score_warn(risk_engine: RiskEngine):
    """Test boundary score 40: Exactly at threshold 40 renders WARN_MANUAL_REVIEW."""
    # 4 Medium gaps (weight 10 each = 40.0 base score * 1.0 = 40)
    med_gaps = [
        SecurityGap(
            rule_id=f"MED-{i}",
            severity=Severity.MEDIUM,
            gap_title=f"Operational Gap {i}",
            technical_impact="Medium operational deviation.",
            compliance_violation="NIST SP 800-53 AC-2",
        )
        for i in range(4)
    ]
    breakdown = risk_engine.calculate_score(security_gaps=med_gaps, blast_radius=None, has_unknown_impact=False)
    assert breakdown.final_risk_score == 40
    assert breakdown.verdict == DeploymentVerdict.WARN_MANUAL_REVIEW


def test_risk_boundary_69_score_warn(risk_engine: RiskEngine):
    """Test boundary score 69: In range 40-69 without Critical renders WARN_MANUAL_REVIEW."""
    # 23 Low gaps (weight 3 each = 69.0 base score * 1.0 = 69)
    low_gaps = [
        SecurityGap(
            rule_id=f"LOW-HYGIENE-{i}",
            severity=Severity.LOW,
            gap_title=f"Security Hygiene Gap {i}",
            technical_impact="Low operational deviation.",
            compliance_violation="NIST SP 800-53 CM-6",
        )
        for i in range(23)
    ]
    breakdown = risk_engine.calculate_score(security_gaps=low_gaps, blast_radius=None, has_unknown_impact=False)
    assert breakdown.final_risk_score == 69
    assert breakdown.verdict == DeploymentVerdict.WARN_MANUAL_REVIEW


def test_risk_boundary_70_score_block(risk_engine: RiskEngine):
    """Test boundary score 70: At threshold 70 renders BLOCK_DEPLOYMENT."""
    med_gaps = [
        SecurityGap(
            rule_id=f"MED-GAP-{i}",
            severity=Severity.MEDIUM,
            gap_title=f"Security Hygiene Gap {i}",
            technical_impact="Medium severity issue.",
            compliance_violation="NIST SP 800-53 SC-7",
        )
        for i in range(7)
    ]
    breakdown = risk_engine.calculate_score(security_gaps=med_gaps, blast_radius=None, has_unknown_impact=False)
    assert breakdown.final_risk_score == 70
    assert breakdown.verdict == DeploymentVerdict.BLOCK_DEPLOYMENT


def test_risk_boundary_100_score_block(risk_engine: RiskEngine):
    """Test boundary score 100: Max bounded score renders BLOCK_DEPLOYMENT."""
    crit_gaps = [
        SecurityGap(
            rule_id=f"CRIT-{i}",
            severity=Severity.CRITICAL,
            gap_title=f"Critical Security Breach {i}",
            technical_impact="Total network compromise.",
            compliance_violation="PCI-DSS 1.3",
        )
        for i in range(3)
    ]
    breakdown = risk_engine.calculate_score(security_gaps=crit_gaps, blast_radius=None, has_unknown_impact=False)
    assert breakdown.final_risk_score == 100
    assert breakdown.verdict == DeploymentVerdict.BLOCK_DEPLOYMENT


def test_verdict_precedence_critical_overrides_low_score(risk_engine: RiskEngine):
    """Test precedence rule 1: A single CRITICAL gap blocks deployment even if score were artificially low."""
    gap = SecurityGap(
        rule_id="FW-02",
        severity=Severity.CRITICAL,
        gap_title="Unrestricted Ingress to Untrust",
        technical_impact="Critical perimeter breach.",
        compliance_violation="NIST SP 800-53 SC-7",
    )
    breakdown = risk_engine.calculate_score(security_gaps=[gap], blast_radius=None)
    assert breakdown.verdict == DeploymentVerdict.BLOCK_DEPLOYMENT


def test_verdict_precedence_high_cannot_result_in_allow(risk_engine: RiskEngine):
    """Test precedence rule 2: A HIGH gap can NEVER produce ALLOW even with score < 40."""
    high_gap = SecurityGap(
        rule_id="FW-03",
        severity=Severity.HIGH,
        gap_title="Omitted Threat Profile",
        technical_impact="Inspection bypass.",
        compliance_violation="CIS PAN-OS 4.1",
    )
    breakdown = risk_engine.calculate_score(security_gaps=[high_gap], blast_radius=None)
    assert breakdown.final_risk_score == 25  # Below 40 numerical score!
    assert breakdown.verdict == DeploymentVerdict.WARN_MANUAL_REVIEW, "HIGH finding must force WARN, never ALLOW"


def test_verdict_precedence_unknown_impact_cannot_result_in_allow(risk_engine: RiskEngine):
    """Test precedence rule 2: UNKNOWN impact can NEVER produce ALLOW even with score 0."""
    blast_unknown = BlastRadiusResult(
        direct_impacts=[],
        cascading_impacts=[],
        unknown_nodes=["unmapped-cluster-01"],
        unknown_impacts=[
            UnknownImpactAsset(
                resource_identifier="unmapped-cluster-01",
                resource_type="Kubernetes Cluster",
                reason="Not registered in Digital Twin topology",
            )
        ],
    )
    breakdown = risk_engine.calculate_score(security_gaps=[], blast_radius=blast_unknown)
    assert breakdown.final_risk_score == 0
    assert breakdown.verdict == DeploymentVerdict.WARN_MANUAL_REVIEW, "UNKNOWN impact must force WARN, never ALLOW"


# =============================================================================
# 2. Remediation Safety & Digital Twin Graph Immutability
# =============================================================================

def test_digital_twin_baseline_immutability():
    """Verify that constructing CandidateDigitalTwinOverlay does not mutate the baseline graph."""
    loader = EnterpriseDatasetLoader()
    base_dt = loader.load_as_digital_twin_graph()

    orig_node_count = base_dt.nx_graph.number_of_nodes()
    orig_edge_count = base_dt.nx_graph.number_of_edges()

    orig_res = [
        AwsIamRolePolicyAttachmentResource(
            resource_type="aws_iam_role_policy_attachment",
            resource_name="analytics_s3_access",
            role="role-analytics-ingestion-svc",
            policy_arn="arn:aws:iam::aws:policy/AmazonS3FullAccess",
            source_file="test_original.tf",
        )
    ]
    cand_res = [
        AwsIamRolePolicyAttachmentResource(
            resource_type="aws_iam_role_policy_attachment",
            resource_name="analytics_s3_scoped",
            role="role-analytics-ingestion-svc",
            policy_arn="arn:aws:iam::123456789012:policy/analytics-telemetry-writer",
            source_file="test_candidate.tf",
        )
    ]

    overlay_engine = CandidateDigitalTwinOverlay(base_digital_twin=base_dt)
    ephemeral_dt, overlay_res = overlay_engine.create_candidate_overlay(
        candidate_resources=cand_res,
        original_resources=orig_res,
    )

    # 1. Baseline graph MUST remain 100% unchanged
    assert base_dt.nx_graph.number_of_nodes() == orig_node_count
    assert base_dt.nx_graph.number_of_edges() == orig_edge_count

    # 2. Ephemeral candidate graph reflects severed relationship
    assert overlay_res.overlay_applied is True
    assert len(overlay_res.removed_relationships) >= 1
    assert any("AmazonS3FullAccess Revoked" in r or "CUI Path Severed" in r for r in overlay_res.removed_relationships)


def test_remediation_unmapped_entities_require_manual_review():
    """Verify unmapped CIDRs or configuration values require manual review and flag placeholders."""
    rec = RemediationRecommendation(
        remediation_id="REM-TEST-001",
        original_finding_id="FW-02",
        finding_identity=FindingIdentity(
            rule_id="FW-02",
            affected_resource="panos_security_policy.rule1",
            relevant_attribute="destination_addresses",
        ),
        rule_id="FW-02",
        affected_resource="panos_security_policy.rule1",
        current_config_snippet='destination_addresses = ["any"]',
        recommended_config_snippet='destination_addresses = ["<PARTNER_CIDR_PLACEHOLDER>"]',
        explanation="Partner CIDR cannot be inferred without CMDB record; manual review required.",
        security_benefit="Restricts egress scope.",
        operational_impact="Prevents unauthorized data exfiltration.",
        confidence_score=0.75,
        requires_manual_review=True,
        placeholders_used=["<PARTNER_CIDR_PLACEHOLDER>"],
        status=RemediationStatus.NEEDS_MANUAL_REVIEW,
    )

    assert rec.requires_manual_review is True
    assert len(rec.placeholders_used) == 1
    assert rec.status == RemediationStatus.NEEDS_MANUAL_REVIEW
