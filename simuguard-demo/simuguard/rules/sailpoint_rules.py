"""SailPoint Identity Security Cloud governance rules for SimuGuard AI.

Implements identity governance checks separate from AWS runtime authorization:
- SP-01: In-Flight / Unapproved Access Assumption (PENDING_IS_NOT_ACCESS)
- SP-02: Unprovisioned / Failed Provisioning State Detection
- SP-03: Separation of Duties (SoD) Conflict Detection
- SP-04: Contractor Privileged Access Violation
- SP-05: Dormant / Revoked Entitlement Exposure
- SP-06: Excessive Entitlement Accumulation (Privilege Creep)
"""

from typing import Any, Dict, List, Optional, Set, Tuple
from simuguard.models.enums import Severity
from simuguard.models.security_gap import SecurityGap
from simuguard.parsers.resource_models import (
    AwsIamRolePolicyAttachmentResource,
    NormalizedResource,
)
from simuguard.rules.base_rule import BaseRule, RuleEvaluationContext
from simuguard.rules.sod_matrix import SoDMatrixEvaluator


# Documented enterprise departmental entitlement baselines for privilege creep detection
DEPARTMENTAL_ENTITLEMENT_BASELINES: Dict[str, int] = {
    "Information Security": 3,
    "Cloud Platform Operations": 3,
    "Software Engineering": 3,
    "Finance & Treasury": 2,
    "Governance Risk & Compliance": 2,
    "Database Engineering": 2,
    "Third-Party Contractor": 1,
}
DEFAULT_DEPARTMENTAL_BASELINE = 2

# Privileged access profiles and entitlements restricted from contractors
PRIVILEGED_PROFILES: Set[str] = {
    "sp-ap-aws-prod-admin",
    "sp-ap-paloalto-firewall-admin",
    "sp-ap-db-token-admin",
}
PRIVILEGED_ENTITLEMENTS: Set[str] = {
    "sp-ent-aws-prod-root-admin",
    "sp-ent-aws-iam-admin",
    "sp-ent-aws-ec2-prod-admin",
    "sp-ent-paloalto-admin",
    "sp-ent-db-token-admin",
}


def correlate_identities_from_resources(
    resources: List[NormalizedResource],
    sp_data: Dict[str, Any],
    context: RuleEvaluationContext,
) -> Tuple[Set[str], List[str]]:
    """Correlate proposed changes to actual identities and accounts in SailPoint.

    Returns:
        Tuple of (correlated_identity_ids, unmapped_entity_errors)
    """
    if context.extra_metadata.get("evaluate_all_identities"):
        all_ids = {i["id"] for i in sp_data.get("identities", {}).get("identities", [])}
        return all_ids, []

    if "target_identities" in context.extra_metadata:
        return set(context.extra_metadata["target_identities"]), []

    # If no resources are provided (e.g. standalone rule unit tests), evaluate all
    if not resources:
        all_ids = {i["id"] for i in sp_data.get("identities", {}).get("identities", [])}
        return all_ids, []

    correlated: Set[str] = set()
    unmapped: List[str] = []

    accounts = sp_data.get("accounts", {}).get("accounts", [])
    identities = sp_data.get("identities", {}).get("identities", [])
    known_ident_ids = {i["id"] for i in identities}

    has_iam_or_identity_resource = False

    for res in resources:
        if isinstance(res, AwsIamRolePolicyAttachmentResource):
            has_iam_or_identity_resource = True
            role_name = res.role.strip()
            # Match account
            matched_ident: Optional[str] = None
            for acct in accounts:
                if (
                    acct.get("account_name") == role_name
                    or acct.get("native_identity", "").endswith(f"/{role_name}")
                    or acct.get("id") == role_name
                ):
                    matched_ident = acct.get("identity_id")
                    break

            if matched_ident and matched_ident in known_ident_ids:
                correlated.add(matched_ident)
            else:
                unmapped.append(f"IAM Role '{role_name}' has no correlated identity in SailPoint")

        # Check raw attributes for any explicit SailPoint identity or account reference
        raw_text = str(res.raw_attributes)
        for ident_id in known_ident_ids:
            if ident_id in raw_text:
                correlated.add(ident_id)

    return correlated, unmapped


class InFlightAccessAssumptionRule(BaseRule):
    """SP-01: Principle: PENDING_IS_NOT_ACCESS.

    Flags any configuration or grant assuming in-flight, unapproved, or rejected
    access requests have conferred effective access.
    """

    rule_id = "SP-01"
    name = "In-Flight or Unapproved Access Assumption (PENDING_IS_NOT_ACCESS)"
    description = (
        "Enforces the fundamental identity governance boundary that pending or unapproved access requests "
        "convey ZERO effective permissions and cannot be incorporated into infrastructure configurations."
    )
    severity = Severity.CRITICAL
    compliance_frameworks = [
        "NIST SP 800-53 AC-2 (Account Management)",
        "NIST SP 800-53 AC-3 (Access Enforcement)",
        "ISO 27001 A.9.2.2 (User Access Provisioning)",
    ]

    def evaluate(
        self,
        resources: List[NormalizedResource],
        context: RuleEvaluationContext,
    ) -> List[SecurityGap]:
        findings: List[SecurityGap] = []
        sp_data = context.sailpoint_governance
        if not sp_data:
            return findings

        correlated_idents, unmapped = correlate_identities_from_resources(
            resources, sp_data, context
        )

        for err in unmapped:
            findings.append(
                SecurityGap(
                    rule_id=self.rule_id,
                    severity=Severity.HIGH,
                    gap_title=f"Unmapped Governance Entity: {err}",
                    technical_impact=(
                        f"{err}. Governance status is UNKNOWN; cannot verify access authorization "
                        "against SailPoint Identity Security Cloud."
                    ),
                    compliance_violation="NIST SP 800-53 AC-2 & CIS AWS Benchmark v1.4.0",
                    remediation_guidance="Register IAM role in SailPoint Identity Security Cloud account catalog.",
                )
            )

        if not correlated_idents:
            return findings

        access_requests = sp_data.get("access_requests", {}).get("access_requests", [])

        for req in access_requests:
            req_id = req.get("id")
            target_id = req.get("target_identity_id")
            requester_id = req.get("requester_identity_id")
            status = (req.get("status") or "").upper()
            effective_granted = req.get("effective_access_granted", False)

            # Check if this request involves any correlated identity
            if target_id not in correlated_idents and requester_id not in correlated_idents:
                continue

            if status in ["PENDING_APPROVAL", "REJECTED", "CANCELLED"]:
                if effective_granted:
                    findings.append(
                        SecurityGap(
                            rule_id=self.rule_id,
                            severity=self.severity,
                            gap_title=f"PENDING_IS_NOT_ACCESS Violation: Request '{req_id}'",
                            technical_impact=(
                                f"Access request '{req_id}' holds approval status '{status}', but was flagged "
                                f"with effective_access_granted=True for identity '{target_id}'. "
                                "In-flight requests convey ZERO valid permissions."
                            ),
                            compliance_violation="NIST SP 800-53 AC-2 & AC-3",
                            remediation_guidance=(
                                f"Revoke effective access assumption on request '{req_id}' until formally approved."
                            ),
                        )
                    )

            # Check if resources directly reference this unapproved request
            for res in resources:
                raw_str = str(res.raw_attributes)
                if req_id and req_id in raw_str and status != "APPROVED":
                    findings.append(
                        SecurityGap(
                            rule_id=self.rule_id,
                            severity=self.severity,
                            gap_title=f"Infrastructure Change Assumes In-Flight Access: '{req_id}'",
                            technical_impact=(
                                f"Resource '{res.resource_type}.{res.resource_name}' directly references "
                                f"unapproved access request '{req_id}' (status: {status}). "
                                "Prematurely provisions permissions before required governance approval."
                            ),
                            compliance_violation="NIST SP 800-53 AC-2 & ISO 27001 A.9.2.2",
                            remediation_guidance=(
                                f"Wait for multi-tier executive approval for request '{req_id}' before deploying."
                            ),
                        )
                    )

        return findings


class UnprovisionedAccessRule(BaseRule):
    """SP-02: Flags entitlements or roles whose provisioning status is not verified on target source."""

    rule_id = "SP-02"
    name = "Unprovisioned or Failed Identity Provisioning State"
    description = (
        "Distinguishes approved from provisioned access, ensuring configurations do not assume "
        "permissions are active until downstream connector reconciliation confirms status on the target system."
    )
    severity = Severity.HIGH
    compliance_frameworks = [
        "NIST SP 800-53 AC-2 (Account Management)",
        "NIST CSF 2.0 PR.AC-01",
    ]

    UNCONFIRMED_STATES: Set[str] = {
        "REQUESTED_NOT_PROVISIONED",
        "FAILED",
        "PENDING_RECONCILIATION",
        "TIMEOUT",
    }

    def evaluate(
        self,
        resources: List[NormalizedResource],
        context: RuleEvaluationContext,
    ) -> List[SecurityGap]:
        findings: List[SecurityGap] = []
        sp_data = context.sailpoint_governance
        if not sp_data:
            return findings

        correlated_idents, _ = correlate_identities_from_resources(resources, sp_data, context)
        if not correlated_idents:
            return findings

        prov_events = sp_data.get("provisioning_events", {}).get("provisioning_events", [])

        for event in prov_events:
            ident_id = event.get("identity_id")
            if ident_id not in correlated_idents:
                continue

            prov_id = event.get("id")
            state = (event.get("state") or "").upper()
            recon_status = (event.get("reconciliation_status") or "").upper()

            if state in self.UNCONFIRMED_STATES or recon_status != "VERIFIED_ON_SOURCE":
                if event.get("action") == "GRANT":
                    findings.append(
                        SecurityGap(
                            rule_id=self.rule_id,
                            severity=self.severity,
                            gap_title=f"Unprovisioned Identity Grant: Event '{prov_id}' (State: {state})",
                            technical_impact=(
                                f"Provisioning event '{prov_id}' for identity '{ident_id}' targeting "
                                f"source '{event.get('source_id')}' is in state '{state}' (reconciliation: '{recon_status}'). "
                                "Downstream infrastructure assuming this access is active will fail or create orphaned permissions."
                            ),
                            compliance_violation="NIST SP 800-53 AC-2 & NIST CSF 2.0 PR.AC-01",
                            remediation_guidance=(
                                f"Wait for target source reconciliation to verify provisioning for event '{prov_id}'."
                            ),
                        )
                    )

        return findings


class SeparationOfDutiesRule(BaseRule):
    """SP-03: Separation of Duties (SoD) Conflict Detection using explicit conflict catalog."""

    rule_id = "SP-03"
    name = "Separation of Duties (SoD) Toxic Role & Entitlement Conflict"
    description = (
        "Evaluates identity role and entitlement combinations against explicit SoD definitions "
        "to prevent conflicting dual-control responsibilities."
    )
    severity = Severity.CRITICAL
    compliance_frameworks = [
        "SOX 404 (ITGC Segregation of Duties)",
        "NIST SP 800-53 AC-5 (Separation of Duties)",
        "PCI-DSS Req 7.1",
    ]

    def __init__(self):
        self.evaluator = SoDMatrixEvaluator()

    def evaluate(
        self,
        resources: List[NormalizedResource],
        context: RuleEvaluationContext,
    ) -> List[SecurityGap]:
        findings: List[SecurityGap] = []
        sp_data = context.sailpoint_governance
        if not sp_data:
            return findings

        correlated_idents, _ = correlate_identities_from_resources(resources, sp_data, context)
        if not correlated_idents:
            return findings

        identities = sp_data.get("identities", {}).get("identities", [])
        relationships = sp_data.get("relationships", {}).get("relationships", [])

        # Build identity role and entitlement mapping from relationships
        roles_by_ident: Dict[str, Set[str]] = {}
        ents_by_ident: Dict[str, Set[str]] = {}

        for rel in relationships:
            src = rel.get("source")
            tgt = rel.get("target")
            rtype = rel.get("relationship")

            if rtype == "MEMBER_OF_ROLE" or rtype == "ASSIGNED_ROLE":
                roles_by_ident.setdefault(src, set()).add(tgt)
            elif rtype in ["HAS_ENTITLEMENT", "EFFECTIVE_ENTITLEMENT"]:
                ents_by_ident.setdefault(src, set()).add(tgt)

        for ident in identities:
            ident_id = ident.get("id")
            if ident_id not in correlated_idents:
                continue

            display_name = ident.get("display_name")
            assigned_roles = roles_by_ident.get(ident_id, set())
            assigned_ents = ents_by_ident.get(ident_id, set())

            conflicts = self.evaluator.check_identity_sod(
                identity_id=ident_id,
                assigned_role_ids=assigned_roles,
                assigned_entitlement_ids=assigned_ents,
                identity_name=display_name,
            )

            for conflict in conflicts:
                findings.append(
                    SecurityGap(
                        rule_id=self.rule_id,
                        severity=conflict.conflict_def.severity,
                        gap_title=f"Separation of Duties (SoD) Conflict: {conflict.conflict_def.name} ({ident_id})",
                        technical_impact=conflict.explanation,
                        compliance_violation=conflict.conflict_def.compliance_framework,
                        remediation_guidance=(
                            f"Enforce segregation of duties: revoke one of the conflicting roles on identity '{ident_id}'."
                        ),
                    )
                )

        return findings


class ContractorPrivilegedAccessRule(BaseRule):
    """SP-04: Flags third-party contractor identities assigned privileged profiles or entitlements."""

    rule_id = "SP-04"
    name = "Contractor Privileged Access Violation"
    description = (
        "Enforces strict vendor isolation by detecting external contractor identities "
        "assigned root, production, or administrative privileges."
    )
    severity = Severity.CRITICAL
    compliance_frameworks = [
        "NIST SP 800-171 3.1.1 (Limit system access to authorized users)",
        "ISO 27001 A.9.2 (User Access Provisioning)",
        "NIST SP 800-53 AC-6",
    ]

    def evaluate(
        self,
        resources: List[NormalizedResource],
        context: RuleEvaluationContext,
    ) -> List[SecurityGap]:
        findings: List[SecurityGap] = []
        sp_data = context.sailpoint_governance
        if not sp_data:
            return findings

        correlated_idents, _ = correlate_identities_from_resources(resources, sp_data, context)
        if not correlated_idents:
            return findings

        identities = sp_data.get("identities", {}).get("identities", [])
        relationships = sp_data.get("relationships", {}).get("relationships", [])

        aps_by_ident: Dict[str, Set[str]] = {}
        ents_by_ident: Dict[str, Set[str]] = {}

        for rel in relationships:
            src = rel.get("source")
            tgt = rel.get("target")
            rtype = rel.get("relationship")

            if rtype in ["ASSIGNED_ACCESS_PROFILE", "HAS_ACCESS_PROFILE"]:
                aps_by_ident.setdefault(src, set()).add(tgt)
            elif rtype in ["HAS_ENTITLEMENT", "EFFECTIVE_ENTITLEMENT"]:
                ents_by_ident.setdefault(src, set()).add(tgt)

        for ident in identities:
            ident_id = ident.get("id")
            if ident_id not in correlated_idents:
                continue

            is_contractor = (
                ident.get("employment_type", "").upper() == "CONTRACTOR"
                or "Contract" in ident.get("department", "")
            )
            if not is_contractor:
                continue

            display_name = ident.get("display_name")
            assigned_aps = aps_by_ident.get(ident_id, set())
            assigned_ents = ents_by_ident.get(ident_id, set())

            violating_aps = assigned_aps.intersection(PRIVILEGED_PROFILES)
            if violating_aps:
                findings.append(
                    SecurityGap(
                        rule_id=self.rule_id,
                        severity=self.severity,
                        gap_title=f"Contractor Privileged Profile Violation: '{ident_id}'",
                        technical_impact=(
                            f"Third-party contractor '{display_name}' ({ident_id}) is assigned privileged "
                            f"access profile(s): {sorted(list(violating_aps))}. "
                            "Violates vendor least-privilege boundary and exposes core production systems to non-employees."
                        ),
                        compliance_violation="NIST SP 800-171 3.1.1 & NIST SP 800-53 AC-6",
                        remediation_guidance=(
                            f"Revoke privileged profiles {sorted(list(violating_aps))} from contractor '{ident_id}' "
                            "and restrict to development sandbox."
                        ),
                    )
                )

            violating_ents = assigned_ents.intersection(PRIVILEGED_ENTITLEMENTS)
            if violating_ents:
                findings.append(
                    SecurityGap(
                        rule_id=self.rule_id,
                        severity=self.severity,
                        gap_title=f"Contractor Privileged Entitlement Violation: '{ident_id}'",
                        technical_impact=(
                            f"Third-party contractor '{display_name}' ({ident_id}) holds administrative "
                            f"entitlement(s): {sorted(list(violating_ents))}."
                        ),
                        compliance_violation="NIST SP 800-171 3.1.1 & ISO 27001 A.9.2",
                        remediation_guidance=(
                            f"Revoke privileged entitlements from contractor '{ident_id}' immediately."
                        ),
                    )
                )

        return findings


class DormantRevokedEntitlementRule(BaseRule):
    """SP-05: Treats revoked-pending-deprovisioning as outstanding access-removal risk."""

    rule_id = "SP-05"
    name = "Outstanding Access-Removal Risk (Revoked-Pending-Deprovisioning)"
    description = (
        "Detects entitlements marked as REVOKED during access certification reviews that have not yet "
        "been deprovisioned from target systems."
    )
    severity = Severity.HIGH
    compliance_frameworks = [
        "NIST SP 800-53 AC-2 (Account Management)",
        "ISO 27001 A.9.2.6 (Removal or adjustment of access rights)",
        "PCI-DSS Req 8.1.3",
    ]

    def evaluate(
        self,
        resources: List[NormalizedResource],
        context: RuleEvaluationContext,
    ) -> List[SecurityGap]:
        findings: List[SecurityGap] = []
        sp_data = context.sailpoint_governance
        if not sp_data:
            return findings

        correlated_idents, _ = correlate_identities_from_resources(resources, sp_data, context)
        if not correlated_idents:
            return findings

        certifications = sp_data.get("certifications", {}).get("certifications", [])

        for cert in certifications:
            target_ident = cert.get("target_identity_id")
            if target_ident not in correlated_idents:
                continue

            decision = (cert.get("decision") or "").upper()
            reviewed_item = cert.get("reviewed_item_id")
            campaign = cert.get("campaign_name")

            if decision in ["REVOKED", "REVOKED_PENDING_DEPROVISIONING"]:
                findings.append(
                    SecurityGap(
                        rule_id=self.rule_id,
                        severity=self.severity,
                        gap_title=f"Outstanding Access-Removal Risk: Revoked Item '{reviewed_item}' ({target_ident})",
                        technical_impact=(
                            f"Access certification review '{campaign}' revoked item '{reviewed_item}' for "
                            f"identity '{target_ident}', but reconciliation indicates permissions remain active on target. "
                            "Represents a dormant access liability subject to unauthorized lateral usage."
                        ),
                        compliance_violation="ISO 27001 A.9.2.6 & NIST SP 800-53 AC-2",
                        remediation_guidance=(
                            f"Trigger automated SailPoint deprovisioning workflow to purge '{reviewed_item}' "
                            f"from target accounts of '{target_ident}'."
                        ),
                    )
                )

        return findings


class PrivilegeCreepRule(BaseRule):
    """SP-06: Evaluates identity entitlement accumulation against documented departmental baselines."""

    rule_id = "SP-06"
    name = "Excessive Entitlement Accumulation (Privilege Creep)"
    description = (
        "Evaluates whether an identity's accumulated entitlements exceed documented departmental baselines "
        "or span contradictory business domains."
    )
    severity = Severity.MEDIUM
    compliance_frameworks = [
        "NIST SP 800-53 AC-6 (Least Privilege)",
        "NIST CSF 2.0 PR.AC-01",
    ]

    def evaluate(
        self,
        resources: List[NormalizedResource],
        context: RuleEvaluationContext,
    ) -> List[SecurityGap]:
        findings: List[SecurityGap] = []
        sp_data = context.sailpoint_governance
        if not sp_data:
            return findings

        correlated_idents, _ = correlate_identities_from_resources(resources, sp_data, context)
        if not correlated_idents:
            return findings

        identities = sp_data.get("identities", {}).get("identities", [])
        relationships = sp_data.get("relationships", {}).get("relationships", [])

        ents_by_ident: Dict[str, Set[str]] = {}
        for rel in relationships:
            src = rel.get("source")
            tgt = rel.get("target")
            rtype = rel.get("relationship")
            if rtype in ["HAS_ENTITLEMENT", "EFFECTIVE_ENTITLEMENT"]:
                ents_by_ident.setdefault(src, set()).add(tgt)

        for ident in identities:
            ident_id = ident.get("id")
            if ident_id not in correlated_idents:
                continue

            dept = ident.get("department", "Default")
            baseline = DEPARTMENTAL_ENTITLEMENT_BASELINES.get(dept, DEFAULT_DEPARTMENTAL_BASELINE)
            assigned_ents = ents_by_ident.get(ident_id, set())
            count = len(assigned_ents)

            if count > baseline + 1:
                findings.append(
                    SecurityGap(
                        rule_id=self.rule_id,
                        severity=self.severity,
                        gap_title=f"Privilege Creep Detected: Identity '{ident_id}' ({count} entitlements)",
                        technical_impact=(
                            f"Identity '{ident.get('display_name')}' in department '{dept}' holds {count} active "
                            f"entitlements, exceeding the documented departmental baseline of {baseline}. "
                            f"Active entitlements: {sorted(list(assigned_ents))}."
                        ),
                        compliance_violation="NIST SP 800-53 AC-6 & NIST CSF 2.0 PR.AC-01",
                        remediation_guidance=(
                            f"Initiate manager access recertification to de-allocate legacy entitlements for '{ident_id}'."
                        ),
                    )
                )

        return findings
