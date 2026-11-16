"""Domain and persistence models for SimuGuard AI local storage."""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
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

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    EMERGENCY = "EMERGENCY"
    EXPEDITED = "EXPEDITED"
    NORMAL = "NORMAL"
    STANDARD = "STANDARD"


class ChangeDomain(CaseInsensitiveEnum):
    """Enterprise domain affected by the change."""

    NETWORK_SECURITY = "NETWORK_SECURITY"
    CLOUD_INFRASTRUCTURE = "CLOUD_INFRASTRUCTURE"
    IDENTITY_GOVERNANCE = "IDENTITY_GOVERNANCE"
    MULTI_DOMAIN = "MULTI_DOMAIN"


class FirewallChangeDetails(BaseModel):
    """Domain-specific attributes for Network Security / Firewall change requests."""

    firewall_platform: str = "Palo Alto Networks PA-5450"
    firewall_device: str = "fw-edge-01-primary"
    panorama_reference: Optional[str] = "pan-mgmt-01.mgmt.apex-global.example"
    rule_name: str = ""
    source_zone: str = "Trust-DMZ"
    destination_zone: str = "Untrust-Internet"
    source_addresses: str = "10.100.4.0/24"
    destination_addresses: str = "any"
    applications: str = "ssl"
    services: str = "service-https"
    protocol: str = "TCP"
    source_port: str = "any"
    destination_port: str = "443"
    action: str = "allow"
    security_profile: str = "Strict-Enterprise-Security"
    change_operation: str = "Create"  # Create, Modify, Delete


class SailPointChangeDetails(BaseModel):
    """Domain-specific attributes for Identity Governance / SailPoint change requests."""

    # Identity Information
    identity_id: str = ""
    identity_name: str = ""
    employee_id: str = ""
    worker_id: str = ""
    worker_type: str = ""
    corporate_email: str = ""
    identity_profile: str = ""
    identity_source: str = ""
    account_id: str = ""
    account_status: str = "ACTIVE"
    manager: str = ""
    manager_id: str = ""
    department: str = ""
    current_department: str = ""
    new_department: str = ""
    current_role: str = ""
    new_role: str = ""
    location: str = ""

    # Access Information
    requested_role: str = ""
    access_profile: str = ""
    entitlement: str = ""
    access_to_add: List[str] = Field(default_factory=list)
    access_to_remove: List[str] = Field(default_factory=list)
    privileged_access_requested: bool = False
    privileged_entitlements: List[str] = Field(default_factory=list)
    application_name: str = ""
    business_justification: str = ""
    access_duration: str = ""
    access_expiry: Optional[str] = None
    start_date: str = ""
    effective_date: str = ""
    termination_date: str = ""
    lifecycle_type: str = ""

    # Governance Lifecycle
    request_status: str = "SUBMITTED"
    approval_status: str = "PENDING"
    provisioning_status: str = "UNPROVISIONED"
    certification_status: str = "UNCERTIFIED"
    revocation_status: str = "NONE"

    # AWS IAM & Cloud Governance Details
    role_name: str = ""
    role_arn: str = ""
    target_role_name: str = ""
    target_role_arn: str = ""
    source_role_name: str = ""
    source_role_arn: str = ""
    source_identity_record_id: str = ""
    requested_policy_name: str = ""
    identity_record_id: str = ""
    aws_account: str = ""
    source_aws_account: str = ""
    target_aws_account: str = ""
    assigned_workload: str = ""
    current_attached_policies: List[str] = Field(default_factory=list)
    permission_boundary: str = ""
    permission_boundary_arn: str = ""
    boundary_action: str = ""
    trust_relationship_id: str = ""
    trusted_principal: str = ""
    mfa_condition: str = ""
    external_id_condition: str = ""


class ChangeRequestRecord(BaseModel):
    """Persistent representation of a Change Request."""

    request_number: str
    title: str
    description: str = ""
    justification: str = ""
    submitted_by: str = "SecOps Engineer"
    submitter_role: str = "Network Security Operations"
    change_type: str = ChangeType.FIREWALL_POLICY.value
    domain: str = ChangeDomain.NETWORK_SECURITY.value
    priority: str = ChangePriority.NORMAL.value
    status: str = WorkflowState.SUBMITTED.value
    category: str = "Network Security"
    subcategory: str = "Security Policy Rule"
    assignment_group: str = "SecOps-Network-Team"
    assigned_engineer: Optional[str] = "SecOps Operations"
    business_service: str = "Enterprise Network Perimeter"
    configuration_item: str = "PAN-NGFW-EDGE-01"
    affected_application: str = "Customer Web Portal"
    infrastructure_platform: str = "Palo Alto Networks NGFW"
    target_environment: str = "Apex Global Production (Digital Twin)"
    scenario_name: Optional[str] = None
    source_file_path: Optional[str] = None
    raw_content: Optional[str] = None

    # Section C — Planning
    implementation_plan: str = ""
    technical_approach: str = ""
    backout_plan: str = ""
    validation_plan: str = ""
    business_impact: str = ""
    operational_impact: str = ""
    dependencies: str = ""
    additional_notes: str = ""

    # Section D — Schedule
    planned_start: Optional[str] = None
    planned_end: Optional[str] = None
    maintenance_window: str = "Weekend Maintenance Window"
    scheduling_notes: str = ""

    # Section E — Initial Risk Context
    expected_business_impact: str = "Low"
    expected_technical_impact: str = "Low"
    expected_service_disruption: str = "None"
    risk_context: str = ""

    # Domain specific payload in JSON format
    firewall_details_json: Optional[str] = None
    sailpoint_details_json: Optional[str] = None

    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


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
