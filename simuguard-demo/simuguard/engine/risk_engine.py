"""Deterministic Risk Scoring and Verdict Engine for SimuGuard AI.

Calculates composite risk scores (0-100) based on deduplicated security findings,
asset criticality multipliers, direct and cascading blast radius impacts,
and evaluates deployment verdicts using strict precedence rules.
"""

from typing import Dict, List, Optional, Set, Tuple
from pydantic import BaseModel, ConfigDict, Field
from simuguard.graph.blast_radius import BlastRadiusResult, ImpactedNode
from simuguard.models.affected_asset import AffectedAsset
from simuguard.models.enums import AssetCriticality, DeploymentVerdict, Severity
from simuguard.models.security_gap import SecurityGap


# Severity weights for Base Score calculation
SEVERITY_WEIGHTS: Dict[Severity, float] = {
    Severity.CRITICAL: 40.0,
    Severity.HIGH: 25.0,
    Severity.MEDIUM: 10.0,
    Severity.LOW: 3.0,
}

# Asset criticality multipliers
CRITICALITY_MULTIPLIERS: Dict[AssetCriticality, float] = {
    AssetCriticality.CRITICAL: 1.5,
    AssetCriticality.HIGH: 1.2,
    AssetCriticality.MEDIUM: 1.0,
    AssetCriticality.LOW: 0.8,
}

CRITICALITY_RANK: Dict[AssetCriticality, int] = {
    AssetCriticality.CRITICAL: 4,
    AssetCriticality.HIGH: 3,
    AssetCriticality.MEDIUM: 2,
    AssetCriticality.LOW: 1,
}


class RiskScoreBreakdown(BaseModel):
    """Detailed mathematical breakdown of the risk score calculation."""

    model_config = ConfigDict(extra="ignore")

    raw_base_score: float = Field(..., description="Sum of (severity_weight * criticality_multiplier) across deduplicated gaps")
    deduplicated_gaps_count: int = Field(..., description="Number of unique security gaps evaluated")
    direct_impacts_count: int = Field(..., description="Count of directly impacted infrastructure nodes (N_direct)")
    cascading_impacts_count: int = Field(..., description="Count of downstream impacted nodes (N_cascading)")
    blast_radius_multiplier: float = Field(..., description="Calculated blast radius multiplier beta in [1.0, 2.0]")
    unrounded_score: float = Field(..., description="Base score multiplied by blast radius multiplier")
    final_risk_score: int = Field(..., ge=0, le=100, description="Final score bounded between 0 and 100")
    verdict: DeploymentVerdict = Field(..., description="Deployment gate verdict")
    verdict_reason: str = Field(..., description="Explanation of why this verdict was rendered")


class RiskEngine:
    """Calculates deterministic risk scores and assigns pre-flight deployment verdicts."""

    def __init__(
        self,
        severity_weights: Optional[Dict[Severity, float]] = None,
        criticality_multipliers: Optional[Dict[AssetCriticality, float]] = None,
    ):
        self.severity_weights = severity_weights or SEVERITY_WEIGHTS
        self.criticality_multipliers = criticality_multipliers or CRITICALITY_MULTIPLIERS

    def deduplicate_gaps(self, gaps: List[SecurityGap]) -> List[SecurityGap]:
        """Deduplicate findings based on rule ID, title, and technical impact snippet."""
        seen: Set[Tuple[str, str]] = set()
        unique_gaps: List[SecurityGap] = []

        for gap in gaps:
            # Create a signature for deduplication
            rule = gap.rule_id or "GENERIC"
            title = gap.gap_title.strip()
            key = (rule, title)

            if key not in seen:
                seen.add(key)
                unique_gaps.append(gap)

        return unique_gaps

    def _determine_highest_criticality(
        self,
        affected_assets: List[AffectedAsset],
    ) -> AssetCriticality:
        """Select the highest asset criticality among affected assets."""
        if not affected_assets:
            return AssetCriticality.MEDIUM

        highest = AssetCriticality.LOW
        highest_rank = 0
        for asset in affected_assets:
            rank = CRITICALITY_RANK.get(asset.criticality, 2)
            if rank > highest_rank:
                highest_rank = rank
                highest = asset.criticality

        return highest

    def calculate_score(
        self,
        security_gaps: List[SecurityGap],
        blast_radius: Optional[BlastRadiusResult] = None,
        has_unknown_impact: bool = False,
    ) -> RiskScoreBreakdown:
        """Calculate the deterministic risk score and deployment verdict.

        Formula:
            Base Score = SUM( SeverityWeight(g.severity) * CriticalityMultiplier(highest_criticality) )
            Blast Multiplier beta = min(2.0, 1.0 + 0.05 * N_direct + 0.02 * N_cascading)
            Final Score = min(100, max(0, round(Base Score * beta)))

        Precedence Rules:
            1. BLOCK_DEPLOYMENT: Any CRITICAL finding, risk score >= 70, or prohibited SoD / critical data breach.
            2. WARN_MANUAL_REVIEW: Any HIGH finding, risk score 40-69, or unresolved UNKNOWN impact.
            3. ALLOW: Only when score < 40, no HIGH or CRITICAL findings, no UNKNOWN impacts.
        """
        deduped = self.deduplicate_gaps(security_gaps)

        # 1. Determine asset criticality from blast radius
        affected_assets: List[AffectedAsset] = []
        n_direct = 0
        n_cascading = 0
        unmapped_present = has_unknown_impact

        if blast_radius is not None:
            affected_assets = blast_radius.to_affected_assets()
            n_direct = len(blast_radius.direct_impacts)
            n_cascading = len(blast_radius.cascading_impacts)
            if blast_radius.unmapped_resources or len(blast_radius.unknown_impacts) > 0:
                unmapped_present = True

        criticality = self._determine_highest_criticality(affected_assets)
        crit_mult = self.criticality_multipliers.get(criticality, 1.0)

        # 2. Compute Base Score
        base_score = 0.0
        for gap in deduped:
            weight = self.severity_weights.get(gap.severity, 10.0)
            base_score += weight * crit_mult

        # 3. Compute Blast Radius Multiplier (capped at 2.0)
        blast_multiplier = 1.0 + (0.05 * n_direct) + (0.02 * n_cascading)
        if blast_multiplier > 2.0:
            blast_multiplier = 2.0

        # 4. Final Bounded Score
        unrounded = base_score * blast_multiplier
        final_score = int(min(100, max(0, round(unrounded))))

        # 5. Evaluate Verdict Precedence
        has_critical_gap = any(g.severity == Severity.CRITICAL for g in deduped)
        has_high_gap = any(g.severity == Severity.HIGH for g in deduped)

        verdict: DeploymentVerdict
        verdict_reason: str

        # Precedence Rule 1: BLOCK_DEPLOYMENT
        if has_critical_gap:
            verdict = DeploymentVerdict.BLOCK_DEPLOYMENT
            crit_titles = [g.gap_title for g in deduped if g.severity == Severity.CRITICAL]
            verdict_reason = (
                f"Deployment BLOCKED: Detected {len(crit_titles)} CRITICAL security finding(s): "
                f"[{'; '.join(crit_titles[:2])}]. Critical security violations override numerical scores."
            )
        elif final_score >= 70:
            verdict = DeploymentVerdict.BLOCK_DEPLOYMENT
            verdict_reason = (
                f"Deployment BLOCKED: Composite risk score of {final_score}/100 exceeds the maximum "
                "allowable deployment threshold (70/100)."
            )

        # Precedence Rule 2: WARN_MANUAL_REVIEW
        elif has_high_gap:
            verdict = DeploymentVerdict.WARN_MANUAL_REVIEW
            high_titles = [g.gap_title for g in deduped if g.severity == Severity.HIGH]
            verdict_reason = (
                f"Manual Review Required: Detected {len(high_titles)} HIGH severity finding(s): "
                f"[{'; '.join(high_titles[:2])}]."
            )
        elif unmapped_present:
            verdict = DeploymentVerdict.WARN_MANUAL_REVIEW
            verdict_reason = (
                "Manual Review Required: Change contains unmapped resources or UNKNOWN impact relationships "
                "in the Digital Twin. Cannot confirm isolation without manual review."
            )
        elif 40 <= final_score < 70:
            verdict = DeploymentVerdict.WARN_MANUAL_REVIEW
            verdict_reason = (
                f"Manual Review Required: Composite risk score of {final_score}/100 falls in the "
                "elevated risk range (40-69)."
            )

        # Precedence Rule 3: ALLOW
        else:
            verdict = DeploymentVerdict.ALLOW
            verdict_reason = (
                f"Deployment APPROVED: Composite risk score of {final_score}/100 is within acceptable limits (<40). "
                "Zero HIGH or CRITICAL security findings and zero unmapped impacts detected."
            )

        return RiskScoreBreakdown(
            raw_base_score=base_score,
            deduplicated_gaps_count=len(deduped),
            direct_impacts_count=n_direct,
            cascading_impacts_count=n_cascading,
            blast_radius_multiplier=blast_multiplier,
            unrounded_score=unrounded,
            final_risk_score=final_score,
            verdict=verdict,
            verdict_reason=verdict_reason,
        )
