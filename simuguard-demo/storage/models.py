"""Domain and persistence models for SimuGuard AI local storage."""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional
from pydantic import BaseModel, Field


class CaseInsensitiveEnum(str, Enum):
    """Base enum that allows case-insensitive string lookups."""

    @classmethod
    def _missing_(cls, value: Any) -> Any:
        if isinstance(value, str):
            upper_val = value.strip().upper()
            for member in cls:
                if member.value == upper_val:
                    return member
        return None


class WorkflowState(CaseInsensitiveEnum):
    """Workflow state for an ITSM-style change request."""

    DRAFT = "DRAFT"
    SUBMITTED = "SUBMITTED"
    ANALYZING = "ANALYZING"
    ANALYSIS_COMPLETE = "ANALYSIS_COMPLETE"
    REMEDIATING = "REMEDIATING"
    REMEDIATED = "REMEDIATED"
    VALIDATED = "VALIDATED"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    CLOSED = "CLOSED"


class ChangeType(CaseInsensitiveEnum):
    """Classification of the security change."""

    FIREWALL_POLICY = "FIREWALL_POLICY"
    AWS_IAM = "AWS_IAM"
    SAILPOINT_GOVERNANCE = "SAILPOINT_GOVERNANCE"
    HYBRID_CHANGE = "HYBRID_CHANGE"


class ChangePriority(CaseInsensitiveEnum):
    """ITSM priority level."""

    STANDARD = "STANDARD"
    NORMAL = "NORMAL"
    EXPEDITED = "EXPEDITED"
    EMERGENCY = "EMERGENCY"


class ChangeDomain(CaseInsensitiveEnum):
    """Enterprise domain affected by the change."""

    NETWORK_SECURITY = "NETWORK_SECURITY"
    CLOUD_INFRASTRUCTURE = "CLOUD_INFRASTRUCTURE"
    IDENTITY_GOVERNANCE = "IDENTITY_GOVERNANCE"
    MULTI_DOMAIN = "MULTI_DOMAIN"


class ChangeRequestRecord(BaseModel):
    """Persistent representation of a Change Request."""

    request_number: str
    title: str
    description: str = ""
    submitted_by: str = "SecOps Engineer"
    submitter_role: str = "Network Security Operations"
    change_type: str = ChangeType.FIREWALL_POLICY.value
    domain: str = ChangeDomain.NETWORK_SECURITY.value
    priority: str = ChangePriority.NORMAL.value
    status: str = WorkflowState.SUBMITTED.value
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    assigned_engineer: Optional[str] = "SecOps Operations"
    target_environment: str = "Apex Global Production (Digital Twin)"
    source_file_path: Optional[str] = None
    raw_content: Optional[str] = None


class AssessmentRecord(BaseModel):
    """Persistent representation of a SimuGuard AI simulation assessment."""

    assessment_id: str
    request_number: str
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    verdict: str  # ALLOW, WARN_MANUAL_REVIEW, BLOCK_DEPLOYMENT
    composite_risk_score: float = 0.0
    max_risk_score: float = 0.0
    security_gaps_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    blast_radius_nodes_count: int = 0
    assessment_type: str = "ORIGINAL"  # ORIGINAL or POST_REMEDIATION
    raw_json: Optional[str] = None


class RemediationRecord(BaseModel):
    """Persistent record of an automated remediation and validation outcome."""

    remediation_id: str
    request_number: str
    assessment_id: str
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    synthesized_hcl: Optional[str] = None
    plan_json: Optional[str] = None
    comparison_json: Optional[str] = None
    status: str = "GENERATED"


class ActivityLogRecord(BaseModel):
    """Audit log entry for ITSM change lifecycle tracking."""

    id: Optional[int] = None
    request_number: str
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    actor: str = "System"
    action: str
    details: Optional[str] = None


class KPISummary(BaseModel):
    """Aggregated KPI metrics for the executive overview."""

    total_requests: int = 0
    allowed_count: int = 0
    warn_count: int = 0
    blocked_count: int = 0
    remediated_count: int = 0
    avg_risk_score: float = 0.0
