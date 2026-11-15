"""Rules package for SimuGuard AI.

Contains deterministic security, compliance, and posture evaluation rules:
- PAN-OS App-ID and Threat Profile enforcement (FW-01 to FW-06)
- SailPoint Identity Security Cloud governance enforcement (SP-01 to SP-06)
- Explicit Separation of Duties (SoD) conflict detection
"""

from simuguard.rules.base_rule import BaseRule, RuleEvaluationContext
from simuguard.rules.firewall_rules import (
    CrossZoneSegmentationRule,
    InsecureProtocolExposureRule,
    PanosAppIdBypassRule,
    RuleShadowingRule,
    ThreatProfileInspectionRule,
    UnrestrictedEgressRule,
)
from simuguard.rules.sailpoint_rules import (
    ContractorPrivilegedAccessRule,
    DormantRevokedEntitlementRule,
    InFlightAccessAssumptionRule,
    PrivilegeCreepRule,
    SeparationOfDutiesRule,
    UnprovisionedAccessRule,
)
from simuguard.rules.sod_matrix import (
    ENTERPRISE_SOD_CATALOG,
    SoDConflictDefinition,
    SoDConflictResult,
    SoDMatrixEvaluator,
)

__all__ = [
    "BaseRule",
    "RuleEvaluationContext",
    # Firewall Rules
    "PanosAppIdBypassRule",
    "UnrestrictedEgressRule",
    "ThreatProfileInspectionRule",
    "InsecureProtocolExposureRule",
    "RuleShadowingRule",
    "CrossZoneSegmentationRule",
    # SailPoint Rules
    "InFlightAccessAssumptionRule",
    "UnprovisionedAccessRule",
    "SeparationOfDutiesRule",
    "ContractorPrivilegedAccessRule",
    "DormantRevokedEntitlementRule",
    "PrivilegeCreepRule",
    # SoD Matrix
    "SoDConflictDefinition",
    "SoDConflictResult",
    "SoDMatrixEvaluator",
    "ENTERPRISE_SOD_CATALOG",
]
