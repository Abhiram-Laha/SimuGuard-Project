"""Explicit Separation of Duties (SoD) definitions and conflict detector for SimuGuard AI."""

from typing import Dict, List, Optional, Set
from pydantic import BaseModel, ConfigDict, Field
from simuguard.models.enums import Severity


class SoDConflictDefinition(BaseModel):
    """Explicit definition of an unallowable toxic role or entitlement combination."""

    model_config = ConfigDict(extra="ignore")

    conflict_id: str = Field(..., description="Unique conflict ID (e.g. SOD-01)")
    name: str = Field(..., description="Human-readable title of the conflict")
    description: str = Field(..., description="Detailed description of the conflicting responsibilities")
    severity: Severity = Field(default=Severity.CRITICAL, description="Severity rating of this SoD conflict")
    conflicting_role_pairs: List[Set[str]] = Field(
        default_factory=list,
        description="Pairs of role IDs that cannot be held concurrently",
    )
    conflicting_entitlement_pairs: List[Set[str]] = Field(
        default_factory=list,
        description="Pairs of entitlement IDs that cannot be held concurrently",
    )
    compliance_framework: str = Field(
        default="SOX 404 & NIST SP 800-53 AC-5",
        description="Regulatory standard mandating this separation",
    )
    risk_summary: str = Field(
        ...,
        description="Operational and fraud/tampering risk if this combination is permitted",
    )


class SoDConflictResult(BaseModel):
    """Result of an identified Separation of Duties conflict for an identity."""

    model_config = ConfigDict(extra="ignore")

    identity_id: str
    identity_name: Optional[str] = None
    conflict_def: SoDConflictDefinition
    matched_roles: List[str] = Field(default_factory=list)
    matched_entitlements: List[str] = Field(default_factory=list)
    explanation: str


# Canonical enterprise SoD conflict catalog for Apex Global Technologies
ENTERPRISE_SOD_CATALOG: List[SoDConflictDefinition] = [
    SoDConflictDefinition(
        conflict_id="SOD-01",
        name="Developer vs. Production Cloud Administrator",
        description=(
            "Software developers with application codebase commit rights must not hold production "
            "cloud infrastructure or root administrative credentials."
        ),
        severity=Severity.CRITICAL,
        conflicting_role_pairs=[
            {"sp-role-developer", "sp-role-cloud-administrator"},
            {"sp-role-developer", "sp-role-production-support-engineer"},
        ],
        conflicting_entitlement_pairs=[
            {"sp-ent-aws-dev-poweruser", "sp-ent-aws-prod-root-admin"},
            {"sp-ent-aws-dev-poweruser", "sp-ent-aws-iam-admin"},
            {"sp-ent-aws-dev-poweruser", "sp-ent-aws-ec2-prod-admin"},
        ],
        compliance_framework="SOX 404 (ITGC Segregation of Duties) & NIST SP 800-53 AC-5",
        risk_summary="Permits unreviewed code or backdoor deployment directly to production workloads.",
    ),
    SoDConflictDefinition(
        conflict_id="SOD-02",
        name="Financial Analyst vs. Payment Disbursement Admin",
        description=(
            "Individuals with financial reporting, ledger analysis, or payment approval roles must not hold "
            "payment execution, disbursement, or database tokenization custodian rights."
        ),
        severity=Severity.CRITICAL,
        conflicting_role_pairs=[
            {"sp-role-finance-analyst", "sp-role-payment-security-custodian"},
        ],
        conflicting_entitlement_pairs=[
            {"sp-ent-aws-s3-cui-read", "sp-ent-db-token-admin"},
            {"sp-ent-ad-finance-reporting", "sp-ent-db-token-admin"},
        ],
        compliance_framework="SOX 404 Section 404(b) & PCI-DSS Req 7.1",
        risk_summary="Allows unauthorized creation and unilateral settlement of fraudulent payment transactions.",
    ),
    SoDConflictDefinition(
        conflict_id="SOD-03",
        name="SecOps Incident Responder vs. Network Firewall Administrator",
        description=(
            "Security operations auditors and incident responders must remain independent from network firewall "
            "administrators who author and deploy perimeter security rules."
        ),
        severity=Severity.HIGH,
        conflicting_role_pairs=[
            {"sp-role-security-operations-analyst", "sp-role-network-security-engineer"},
        ],
        conflicting_entitlement_pairs=[
            {"sp-ap-aws-secops-audit", "sp-ap-paloalto-firewall-admin"},
            {"sp-ent-secops-siem-read", "sp-ent-paloalto-admin"},
        ],
        compliance_framework="NIST SP 800-53 AC-6 (Least Privilege) & ISO 27001 A.9.1.2",
        risk_summary="Compromises independent monitoring; firewall changes could conceal malicious traffic from SIEM.",
    ),
]


class SoDMatrixEvaluator:
    """Evaluates identity role and entitlement assignments against explicit SoD definitions."""

    def __init__(self, catalog: Optional[List[SoDConflictDefinition]] = None):
        self.catalog = catalog or ENTERPRISE_SOD_CATALOG

    def check_identity_sod(
        self,
        identity_id: str,
        assigned_role_ids: Set[str],
        assigned_entitlement_ids: Set[str],
        identity_name: Optional[str] = None,
    ) -> List[SoDConflictResult]:
        """Check whether an identity's assigned roles or entitlements violate SoD."""
        conflicts: List[SoDConflictResult] = []

        for definition in self.catalog:
            # Check role-based conflicts
            for role_pair in definition.conflicting_role_pairs:
                if role_pair.issubset(assigned_role_ids):
                    matched = sorted(list(role_pair))
                    conflicts.append(
                        SoDConflictResult(
                            identity_id=identity_id,
                            identity_name=identity_name,
                            conflict_def=definition,
                            matched_roles=matched,
                            explanation=(
                                f"Identity '{identity_id}' holds conflicting roles: {matched}. "
                                f"Risk: {definition.risk_summary}"
                            ),
                        )
                    )

            # Check entitlement-based conflicts
            for ent_pair in definition.conflicting_entitlement_pairs:
                if ent_pair.issubset(assigned_entitlement_ids):
                    matched = sorted(list(ent_pair))
                    conflicts.append(
                        SoDConflictResult(
                            identity_id=identity_id,
                            identity_name=identity_name,
                            conflict_def=definition,
                            matched_entitlements=matched,
                            explanation=(
                                f"Identity '{identity_id}' holds conflicting entitlements: {matched}. "
                                f"Risk: {definition.risk_summary}"
                            ),
                        )
                    )

        return conflicts
