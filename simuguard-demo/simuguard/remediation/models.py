"""Data models for SimuGuard AI Remediation and Validation Engine (Phase 5).

Provides structured schemas for:
- Traceable remediation recommendations
- Stable finding identities
- Candidate overlay and effective permission tracking
- Before-and-after comparison and differential verification
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field, field_validator
from simuguard.models.enums import CaseInsensitiveEnum, DeploymentVerdict, Severity
from simuguard.models.report import PreFlightSimulationReport


class RemediationStatus(CaseInsensitiveEnum):
    """Lifecycle status of a remediation recommendation."""

    PROPOSED = "PROPOSED"
    VALIDATED = "VALIDATED"
    PARTIALLY_RESOLVED = "PARTIALLY_RESOLVED"
    UNRESOLVED = "UNRESOLVED"
    NEEDS_MANUAL_REVIEW = "NEEDS_MANUAL_REVIEW"
    REJECTED = "REJECTED"


class FindingResolutionStatus(CaseInsensitiveEnum):
    """Resolution verification status of an individual security gap."""

    RESOLVED = "RESOLVED"
    PARTIALLY_RESOLVED = "PARTIALLY_RESOLVED"
    UNRESOLVED = "UNRESOLVED"
    REGRESSION_INTRODUCED = "REGRESSION_INTRODUCED"
    NEEDS_MANUAL_REVIEW = "NEEDS_MANUAL_REVIEW"


class FindingIdentity(BaseModel):
    """Stable composite identity for a security finding across evaluations.

    Prevents comparing findings solely by rule ID. Enforces matching on:
    - rule_id (e.g. FW-01, FW-02, SP-03, IAM-LEAST-PRIVILEGE)
    - affected_resource (e.g. aws_iam_role_policy_attachment.analytics_s3_access)
    - relevant_attribute (e.g. policy_arn:AmazonS3FullAccess, applications:any)
    - original_finding_ref (e.g. gap_title or rule unique token)
    """

    model_config = ConfigDict(extra="ignore", validate_assignment=True)

    rule_id: str = Field(..., description="Rule ID that flagged the violation")
    affected_resource: str = Field(..., description="Target infrastructure resource or identity entity")
    relevant_attribute: Optional[str] = Field(
        default=None,
        description="Specific property or argument involved (e.g. policy_arn, cidr_blocks, applications)",
    )
    original_finding_ref: Optional[str] = Field(
        default=None,
        description="Summary snippet or token from the original gap title",
    )

    @property
    def canonical_key(self) -> str:
        """Return a normalized canonical key for deterministic matching."""
        rule = (self.rule_id or "GENERIC").strip().upper()
        res = (self.affected_resource or "GLOBAL").strip().lower()
        attr = (self.relevant_attribute or "*").strip().lower()
        return f"{rule}::{res}::{attr}"


class RemediationRecommendation(BaseModel):
    """Structured, traceable remediation recommendation for a security gap."""

    model_config = ConfigDict(extra="ignore", validate_assignment=True)

    remediation_id: str = Field(..., description="Unique remediation ID (e.g. REM-FW01-001)")
    original_finding_id: str = Field(..., description="Correlated rule or gap ID (e.g. FW-01, SP-03)")
    finding_identity: FindingIdentity = Field(..., description="Stable composite finding identity")
    rule_id: str = Field(..., description="Rule identifier")
    affected_resource: str = Field(..., description="Terraform resource or governance identity affected")
    current_config_snippet: str = Field(..., description="Current unsafe configuration block")
    recommended_config_snippet: str = Field(..., description="Proposed safe configuration patch")
    explanation: str = Field(..., description="Detailed explanation of why the change is necessary")
    security_benefit: str = Field(..., description="Specific security and compliance risk reduction")
    operational_impact: str = Field(..., description="Expected operational side-effects or network requirements")
    dependencies: List[str] = Field(default_factory=list, description="Prerequisite configurations or approvals")
    validation_steps: List[str] = Field(default_factory=list, description="Verification checks to confirm fix")
    confidence_score: float = Field(..., ge=0.0, le=1.0, description="Confidence rating of recommendation (0.0 - 1.0)")
    limitations: Optional[str] = Field(default=None, description="Known architectural boundaries or manual prerequisites")
    requires_manual_review: bool = Field(
        default=False,
        description="True if recommendation requires manual engineer confirmation or placeholder completion",
    )
    placeholders_used: List[str] = Field(
        default_factory=list,
        description="List of explicit placeholders requiring manual engineer substitution",
    )
    status: RemediationStatus = Field(default=RemediationStatus.PROPOSED)

    @field_validator("confidence_score")
    @classmethod
    def validate_confidence(cls, v: float) -> float:
        return round(max(0.0, min(1.0, float(v))), 4)


class CandidateOverlayResult(BaseModel):
    """Result of evaluating a proposed configuration against an isolated Digital Twin overlay.

    Evaluates effective permissions, topological rewiring, and sensitive exposures
    without mutating the original Digital Twin graph or live datasets.
    """

    model_config = ConfigDict(extra="ignore", validate_assignment=True)

    overlay_applied: bool = Field(..., description="Whether the candidate overlay was successfully constructed")
    removed_relationships: List[str] = Field(
        default_factory=list,
        description="Graph edges severed by the proposed remediation (e.g. role -> CUI vault)",
    )
    added_relationships: List[str] = Field(
        default_factory=list,
        description="Graph edges established by the proposed remediation (e.g. role -> staging telemetry bucket)",
    )
    effective_iam_permissions: Dict[str, Any] = Field(
        default_factory=dict,
        description="Calculated effective IAM permissions for affected roles",
    )
    residual_sensitive_exposures: List[str] = Field(
        default_factory=list,
        description="Sensitive data assets (e.g. CUI, PCI) that remain reachable under overlay",
    )
    affected_applications: List[str] = Field(
        default_factory=list,
        description="Applications utilizing the affected resources (derived from dependency graph)",
    )
    operational_warnings: List[str] = Field(
        default_factory=list,
        description="Operational side-effects, potential service disruption, or missing dependency warnings",
    )
    requires_manual_review: bool = Field(
        default=False,
        description="Set to True if dependencies or effective permissions cannot be definitively validated",
    )


class FindingResolutionDetail(BaseModel):
    """Differential verification status for a single finding."""

    model_config = ConfigDict(extra="ignore", validate_assignment=True)

    finding_identity: FindingIdentity
    original_gap_title: str
    original_severity: Severity
    resolution_status: FindingResolutionStatus
    validation_evidence: str
    residual_risk: Optional[str] = None


class RemediationPlan(BaseModel):
    """Composite remediation plan for a change ticket."""

    model_config = ConfigDict(extra="ignore", validate_assignment=True)

    plan_id: str = Field(..., description="Unique remediation plan identifier")
    change_ticket_id: str = Field(..., description="Correlated change request ID")
    recommendations: List[RemediationRecommendation] = Field(default_factory=list)
    synthesized_candidate_hcl: str = Field(..., description="Full executable remediated HCL configuration")
    target_environment: str = Field(default="Enterprise Hybrid (PAN-OS / AWS / SailPoint)")
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class BeforeAfterComparisonReport(BaseModel):
    """Complete differential analysis between baseline and remediated configurations."""

    model_config = ConfigDict(extra="ignore", validate_assignment=True)

    change_ticket_id: str
    pre_remediation_report: PreFlightSimulationReport
    post_remediation_report: Optional[PreFlightSimulationReport] = None
    candidate_overlay_result: Optional[CandidateOverlayResult] = None
    risk_score_before: int
    risk_score_after: int
    risk_score_delta: int  # risk_score_before - risk_score_after (positive value indicates risk reduction)
    verdict_before: DeploymentVerdict
    verdict_after: DeploymentVerdict
    finding_resolutions: List[FindingResolutionDetail] = Field(default_factory=list)
    resolved_count: int = 0
    partially_resolved_count: int = 0
    unresolved_count: int = 0
    regression_count: int = 0
    manual_review_count: int = 0
    direct_assets_before: int = 0
    direct_assets_after: int = 0
    cascading_assets_before: int = 0
    cascading_assets_after: int = 0
    summary_narrative: str
