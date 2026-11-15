"""Recommendation engine orchestrating multi-domain remediation generation.

Dispatches security findings across:
- FirewallRemediator (PAN-OS, AWS SG)
- AwsRemediator (IAM Least-Privilege, S3 Scoping, VPC)
- SailPointRemediator (ISC Identity Governance)

Compiles individual recommendations into a cohesive RemediationPlan.
"""

from typing import Any, Dict, List, Optional
from simuguard.graph.dataset_loader import EnterpriseDatasetLoader
from simuguard.models.report import PreFlightSimulationReport
from simuguard.models.security_gap import SecurityGap
from simuguard.parsers.resource_models import NormalizedResource
from simuguard.remediation.aws_remediator import AwsRemediator
from simuguard.remediation.firewall_remediator import FirewallRemediator
from simuguard.remediation.models import (
    FindingIdentity,
    RemediationPlan,
    RemediationRecommendation,
    RemediationStatus,
)
from simuguard.remediation.sailpoint_remediator import SailPointRemediator
from simuguard.rules.base_rule import RuleEvaluationContext


class RecommendationEngine:
    """Central orchestrator for synthesizing technically accurate, multi-domain remediations."""

    def __init__(
        self,
        loader: Optional[EnterpriseDatasetLoader] = None,
        firewall_remediator: Optional[FirewallRemediator] = None,
        aws_remediator: Optional[AwsRemediator] = None,
        sailpoint_remediator: Optional[SailPointRemediator] = None,
    ):
        self.loader = loader or EnterpriseDatasetLoader()

        # Load enterprise context if not explicitly provided
        network_data = self.loader.load_network_topology()
        iam_data = self.loader.load_iam_governance()
        app_data = self.loader.load_applications_and_dependencies()
        data_assets = self.loader.load_data_assets()
        sailpoint_data = self.loader.load_sailpoint_governance()

        self.firewall_remediator = firewall_remediator or FirewallRemediator(
            modeled_network_data=network_data
        )
        self.aws_remediator = aws_remediator or AwsRemediator(
            iam_data=iam_data,
            applications_data=app_data,
            data_assets_data=data_assets,
        )
        self.sailpoint_remediator = sailpoint_remediator or SailPointRemediator(
            sailpoint_data=sailpoint_data
        )

    def generate_recommendations(
        self,
        security_gaps: List[SecurityGap],
        resources: List[NormalizedResource],
        context: Optional[RuleEvaluationContext] = None,
    ) -> List[RemediationRecommendation]:
        """Generate structured remediation recommendations for all identified security gaps."""
        ctx = context or RuleEvaluationContext(all_resources=resources)
        recommendations: List[RemediationRecommendation] = []
        seen_canonical_keys: set = set()

        for gap in security_gaps:
            rule_id = (gap.rule_id or "").upper().strip()

            # Find matching resource if available
            matched_res = self._find_matching_resource(gap, resources)

            rec: Optional[RemediationRecommendation] = None

            # Route to domain remediators
            if rule_id.startswith("FW-") or "firewall" in (gap.gap_title or "").lower() or "egress" in (gap.gap_title or "").lower():
                rec = self.firewall_remediator.remediate_gap(gap, matched_res, ctx)

            elif (
                rule_id.startswith("SP-")
                or "sailpoint" in (gap.gap_title or "").lower()
                or "unmapped governance entity" in (gap.gap_title or "").lower()
                or "pending_is_not_access" in (gap.gap_title or "").lower()
            ):
                rec = self.sailpoint_remediator.remediate_gap(gap, matched_res, ctx)

            elif (
                rule_id.startswith("IAM")
                or "cloud privilege escalation" in (gap.gap_title or "").lower()
                or "amazons3fullaccess" in (gap.gap_title or "").lower()
            ):
                rec = self.aws_remediator.remediate_gap(gap, matched_res, ctx)

            # Fallback for generic gaps
            if rec is None:
                rec = self._generic_fallback_remediation(gap, matched_res)

            if rec:
                key = rec.finding_identity.canonical_key
                if key not in seen_canonical_keys:
                    seen_canonical_keys.add(key)
                    recommendations.append(rec)

        return recommendations

    def _find_matching_resource(
        self,
        gap: SecurityGap,
        resources: List[NormalizedResource],
    ) -> Optional[NormalizedResource]:
        """Correlate a security gap with its corresponding normalized resource."""
        title = (gap.gap_title or "").lower()
        impact = (gap.technical_impact or "").lower()

        for res in resources:
            rname = res.resource_name.lower()
            rtype = res.resource_type.lower()
            if rname in title or rname in impact or f"{rtype}.{rname}" in title:
                return res

        # If only one resource exists in the file, associate it
        if len(resources) == 1:
            return resources[0]

        return None

    def _generic_fallback_remediation(
        self,
        gap: SecurityGap,
        resource: Optional[NormalizedResource],
    ) -> RemediationRecommendation:
        """Fallback recommendation when rule has no dedicated remediator."""
        rule = gap.rule_id or "GENERIC"
        res_name = resource.resource_name if resource else "unknown_resource"
        finding_ident = FindingIdentity(
            rule_id=rule,
            affected_resource=res_name,
            original_finding_ref=gap.gap_title,
        )

        return RemediationRecommendation(
            remediation_id=f"REM-GEN-{res_name[:12]}",
            original_finding_id=rule,
            finding_identity=finding_ident,
            rule_id=rule,
            affected_resource=res_name,
            current_config_snippet="# Unsafe or non-compliant configuration flagged by policy",
            recommended_config_snippet=gap.remediation_guidance or "# Apply least-privilege remediation patch",
            explanation=gap.technical_impact,
            security_benefit=f"Resolves compliance violation: {gap.compliance_violation}",
            operational_impact="Review operational requirements before applying.",
            dependencies=[],
            validation_steps=["Re-run SimuGuard pre-flight analysis to verify resolution"],
            confidence_score=0.70,
            requires_manual_review=True,
            status=RemediationStatus.NEEDS_MANUAL_REVIEW,
        )
