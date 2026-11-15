"""Unit tests for SimuGuard AI deterministic risk scoring and verdict precedence engine."""

import pytest
from simuguard.graph.blast_radius import BlastRadiusResult, ImpactedNode
from simuguard.models.affected_asset import AffectedAsset
from simuguard.models.enums import (
    AssetCriticality,
    BlastTier,
    DeploymentVerdict,
    ImpactStatus,
    Severity,
)
from simuguard.models.security_gap import SecurityGap
from simuguard.engine.risk_engine import RiskEngine


@pytest.fixture
def risk_engine():
    return RiskEngine()


class TestFindingDeduplication:
    """Test finding deduplication logic."""

    def test_identical_findings_deduplicated(self, risk_engine):
        gap1 = SecurityGap(
            rule_id="FW-01",
            severity=Severity.CRITICAL,
            gap_title="PAN-OS App-ID Deep Inspection Bypass",
            technical_impact="Layer 7 inspection disabled on rule 1",
            compliance_violation="CIS Benchmark 4.1",
        )
        gap2 = SecurityGap(
            rule_id="FW-01",
            severity=Severity.CRITICAL,
            gap_title="PAN-OS App-ID Deep Inspection Bypass",
            technical_impact="Layer 7 inspection disabled on rule 1 (duplicate instance)",
            compliance_violation="CIS Benchmark 4.1",
        )
        gap3 = SecurityGap(
            rule_id="FW-02",
            severity=Severity.HIGH,
            gap_title="Unrestricted Internet Egress",
            technical_impact="Outbound 0.0.0.0/0 allowed",
            compliance_violation="CIS Benchmark 4.3",
        )

        deduped = risk_engine.deduplicate_gaps([gap1, gap2, gap3])
        assert len(deduped) == 2
        assert {g.rule_id for g in deduped} == {"FW-01", "FW-02"}


class TestAssetCriticalitySelection:
    """Test asset criticality selection from blast radius."""

    def test_highest_criticality_selected(self, risk_engine):
        assets = [
            AffectedAsset(
                asset_id="dev-bucket",
                criticality=AssetCriticality.LOW,
                impact_description="Dev asset affected",
            ),
            AffectedAsset(
                asset_id="internal-db",
                criticality=AssetCriticality.HIGH,
                impact_description="Prod db affected",
            ),
            AffectedAsset(
                asset_id="cui-vault",
                criticality=AssetCriticality.CRITICAL,
                impact_description="CUI vault affected",
            ),
        ]
        highest = risk_engine._determine_highest_criticality(assets)
        assert highest == AssetCriticality.CRITICAL

    def test_empty_affected_assets_defaults_to_medium(self, risk_engine):
        highest = risk_engine._determine_highest_criticality([])
        assert highest == AssetCriticality.MEDIUM


class TestRiskScoreBoundariesAndCalculations:
    """Test exact mathematical boundary calculations."""

    def test_zero_findings_produces_zero_risk_score(self, risk_engine):
        breakdown = risk_engine.calculate_score(security_gaps=[], blast_radius=None)
        assert breakdown.final_risk_score == 0
        assert breakdown.verdict == DeploymentVerdict.ALLOW

    def test_blast_multiplier_calculation_and_cap(self, risk_engine):
        # 10 direct, 10 cascading -> 1.0 + 0.05*10 + 0.02*10 = 1.0 + 0.5 + 0.2 = 1.7
        blast = BlastRadiusResult(
            direct_impacts=[
                ImpactedNode(
                    node_id=f"dir-{i}",
                    node_name=f"dir-{i}",
                    node_type="Type",
                    criticality=AssetCriticality.MEDIUM,
                    tier=BlastTier.DIRECT,
                    impact_reason="reason",
                    trigger_resource="res",
                )
                for i in range(10)
            ],
            cascading_impacts=[
                ImpactedNode(
                    node_id=f"casc-{i}",
                    node_name=f"casc-{i}",
                    node_type="Type",
                    criticality=AssetCriticality.MEDIUM,
                    tier=BlastTier.CASCADING,
                    impact_reason="reason",
                    trigger_resource="res",
                )
                for i in range(10)
            ],
        )
        gap = SecurityGap(
            rule_id="RULE-1",
            severity=Severity.LOW,
            gap_title="Low gap",
            technical_impact="impact",
            compliance_violation="compliance",
        )
        breakdown = risk_engine.calculate_score([gap], blast_radius=blast)
        # Low weight = 3.0 * Medium (1.0) = 3.0. Multiplier = 1.7. Unrounded = 5.1 -> 5
        assert breakdown.blast_radius_multiplier == 1.7
        assert breakdown.final_risk_score == 5

    def test_blast_multiplier_capped_at_two(self, risk_engine):
        blast = BlastRadiusResult(
            direct_impacts=[
                ImpactedNode(
                    node_id=f"dir-{i}",
                    node_name=f"dir-{i}",
                    node_type="Type",
                    criticality=AssetCriticality.MEDIUM,
                    tier=BlastTier.DIRECT,
                    impact_reason="reason",
                    trigger_resource="res",
                )
                for i in range(30)  # 30 * 0.05 = 1.5 -> 1.0 + 1.5 = 2.5 > 2.0
            ]
        )
        breakdown = risk_engine.calculate_score([], blast_radius=blast)
        assert breakdown.blast_radius_multiplier == 2.0

    def test_blast_multiplier_consistent_rounding_precision(self, risk_engine):
        """Test AUDIT-03: Multiplier precision avoids floating point artifacts."""
        # N_direct = 2, N_cascading = 5 -> in IEEE 754, 1.0 + 0.05*2 + 0.02*5 is 1.2000000000000002
        blast = BlastRadiusResult(
            direct_impacts=[
                ImpactedNode(node_id=f"d-{i}", node_name=f"d-{i}", node_type="T", criticality=AssetCriticality.MEDIUM, tier=BlastTier.DIRECT, impact_reason="reason", trigger_resource="t")
                for i in range(2)
            ],
            cascading_impacts=[
                ImpactedNode(node_id=f"c-{i}", node_name=f"c-{i}", node_type="T", criticality=AssetCriticality.MEDIUM, tier=BlastTier.CASCADING, impact_reason="reason", trigger_resource="t")
                for i in range(5)
            ],
        )
        breakdown = risk_engine.calculate_score([], blast_radius=blast)
        assert breakdown.blast_radius_multiplier == 1.2
        # Verify str representation is clean
        assert str(breakdown.blast_radius_multiplier) == "1.2"

    def test_risk_score_deterministic_repeatability(self, risk_engine):
        """Test that risk score calculations are 100% deterministic and repeatable."""
        blast = BlastRadiusResult(
            direct_impacts=[
                ImpactedNode(node_id="d1", node_name="d1", node_type="T", criticality=AssetCriticality.CRITICAL, tier=BlastTier.DIRECT, impact_reason="reason", trigger_resource="t")
            ],
            cascading_impacts=[
                ImpactedNode(node_id="c1", node_name="c1", node_type="T", criticality=AssetCriticality.HIGH, tier=BlastTier.CASCADING, impact_reason="reason", trigger_resource="t")
            ],
        )
        gaps = [
            SecurityGap(rule_id="R1", severity=Severity.HIGH, gap_title="High Gap", technical_impact="impact description", compliance_violation="compliance control"),
            SecurityGap(rule_id="R2", severity=Severity.MEDIUM, gap_title="Med Gap", technical_impact="impact description", compliance_violation="compliance control"),
        ]

        scores = [risk_engine.calculate_score(gaps, blast_radius=blast).final_risk_score for _ in range(100)]
        assert len(set(scores)) == 1
        # Formula check: (25 + 10) * 1.5 (CRITICAL) = 52.5; multiplier = 1.07; 52.5 * 1.07 = 56.175 -> 56
        assert scores[0] == 56


class TestVerdictDecisionPrecedence:
    """Test that verdict precedence rules strictly govern decisions."""

    def test_critical_finding_overrides_numerical_score_forces_block(self, risk_engine):
        # Even if a single finding had low weight, CRITICAL forces BLOCK_DEPLOYMENT
        crit_gap = SecurityGap(
            rule_id="FW-01",
            severity=Severity.CRITICAL,
            gap_title="Palo Alto App-ID Bypass",
            technical_impact="Layer 7 inspection disabled",
            compliance_violation="CIS Benchmark",
        )
        breakdown = risk_engine.calculate_score([crit_gap])
        assert breakdown.verdict == DeploymentVerdict.BLOCK_DEPLOYMENT

    def test_high_finding_forces_warn_manual_review(self, risk_engine):
        high_gap = SecurityGap(
            rule_id="FW-03",
            severity=Severity.HIGH,
            gap_title="Threat Profile Disabled",
            technical_impact="No antivirus",
            compliance_violation="CIS Benchmark",
        )
        breakdown = risk_engine.calculate_score([high_gap])
        assert breakdown.verdict == DeploymentVerdict.WARN_MANUAL_REVIEW

    def test_unknown_impact_forces_warn_manual_review_even_with_low_score(self, risk_engine):
        low_gap = SecurityGap(
            rule_id="RULE-LOW",
            severity=Severity.LOW,
            gap_title="Minor naming issue",
            technical_impact="Low impact",
            compliance_violation="Standard",
        )
        # Score is low (e.g. 3), but has_unknown_impact is True
        breakdown = risk_engine.calculate_score([low_gap], has_unknown_impact=True)
        assert breakdown.final_risk_score < 40
        assert breakdown.verdict == DeploymentVerdict.WARN_MANUAL_REVIEW
        assert "unmapped resources or UNKNOWN impact" in breakdown.verdict_reason

    def test_allow_only_when_score_below_40_and_no_high_critical_unknowns(self, risk_engine):
        low_gap = SecurityGap(
            rule_id="RULE-LOW",
            severity=Severity.LOW,
            gap_title="Minor configuration notice",
            technical_impact="Minimal risk",
            compliance_violation="Guideline",
        )
        breakdown = risk_engine.calculate_score([low_gap], has_unknown_impact=False)
        assert breakdown.final_risk_score < 40
        assert breakdown.verdict == DeploymentVerdict.ALLOW
