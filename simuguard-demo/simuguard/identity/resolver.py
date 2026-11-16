"""Centralized Dynamic Identity Resolution Service for SimuGuard AI (SailPoint ISC).

Provides dynamic, centralized, deterministic correlation of identity references across
SailPoint Identity Security Cloud without hardcoding any employee names, IDs, or using
arbitrary default fallback identities.
"""

from enum import Enum
import re
from typing import Any, Dict, List, Optional, Set, Tuple
from pydantic import BaseModel, ConfigDict, Field


class IdentityResolutionStatus(str, Enum):
    """Outcome status of identity resolution."""
    RESOLVED = "RESOLVED"
    UNMAPPED = "UNMAPPED"
    AMBIGUOUS = "AMBIGUOUS"
    CONFLICT = "CONFLICT"


class IdentityLifecycleCategory(str, Enum):
    """Categorized governance lifecycle state of resolved identity."""
    ACTIVE_EMPLOYEE = "ACTIVE_EMPLOYEE"
    CONTRACTOR = "CONTRACTOR"
    SERVICE_ACCOUNT = "SERVICE_ACCOUNT"
    JOINER = "JOINER"
    MOVER = "MOVER"
    LEAVER = "LEAVER"
    UNKNOWN = "UNKNOWN"


class IdentityAccessState(BaseModel):
    """Distinguishes between requested, approved, provisioned, and effective access."""
    is_requested: bool = False
    is_approved: bool = False
    is_provisioned: bool = False
    is_effective: bool = False
    governance_state_summary: str = ""


class IdentityResolutionResult(BaseModel):
    """Structured result returned by CentralizedIdentityResolver."""
    model_config = ConfigDict(arbitrary_types_allowed=True)

    status: IdentityResolutionStatus
    identity: Optional[Dict[str, Any]] = None
    identity_id: Optional[str] = None
    display_name: Optional[str] = None
    employment_type: Optional[str] = None
    lifecycle_state: Optional[str] = None
    department: Optional[str] = None
    job_title: Optional[str] = None
    identity_profile_id: Optional[str] = None
    lifecycle_category: IdentityLifecycleCategory = IdentityLifecycleCategory.UNKNOWN
    account_ids: List[str] = Field(default_factory=list)
    candidate_matches: List[str] = Field(default_factory=list)
    message: str = ""


class CentralizedIdentityResolver:
    """Dynamic, centralized resolver for SailPoint identity governance entities."""

    def __init__(self, sailpoint_data: Optional[Dict[str, Any]] = None):
        self.sp_data = sailpoint_data or {}
        self._identities: List[Dict[str, Any]] = self.sp_data.get("identities", {}).get("identities", [])
        self._accounts: List[Dict[str, Any]] = self.sp_data.get("accounts", {}).get("accounts", [])
        self._roles: List[Dict[str, Any]] = self.sp_data.get("roles", {}).get("roles", [])

    def resolve_identity(
        self,
        query: Optional[str] = None,
        employee_id: Optional[str] = None,
        account_id: Optional[str] = None,
        target_department: Optional[str] = None,
    ) -> IdentityResolutionResult:
        """Resolve identity dynamically from query, employee_id, or account_id.

        Never defaults to any hardcoded identity when matching fails.
        Detects conflicts between employee_id and query name.
        Detects duplicate/ambiguous matches when multiple identities match.
        """
        raw_query = (query or "").strip()
        raw_eid = (employee_id or "").strip()
        raw_acct = (account_id or "").strip()

        if not raw_query and not raw_eid and not raw_acct:
            return IdentityResolutionResult(
                status=IdentityResolutionStatus.UNMAPPED,
                message="No target identity specified. Identity resolution cannot proceed without an identity reference.",
            )

        # 1. Match by employee_id if provided
        ident_by_eid: Optional[Dict[str, Any]] = None
        if raw_eid:
            for ident in self._identities:
                eid_val = ident.get("employee_id") or ident.get("attributes", {}).get("employeeId")
                if eid_val and str(eid_val).strip().lower() == raw_eid.lower():
                    ident_by_eid = ident
                    break

        # 2. Match by account_id if provided
        ident_by_acct: Optional[Dict[str, Any]] = None
        if raw_acct:
            matched_ident_id = None
            for acct in self._accounts:
                if (
                    acct.get("id") == raw_acct
                    or acct.get("native_identity") == raw_acct
                    or acct.get("account_name") == raw_acct
                ):
                    matched_ident_id = acct.get("identity_id")
                    break
            if matched_ident_id:
                for ident in self._identities:
                    if ident.get("id") == matched_ident_id:
                        ident_by_acct = ident
                        break

        # 3. Match by query text (ID, display_name, email)
        candidates_by_query: List[Dict[str, Any]] = []
        if raw_query:
            # Check for embedded ID in parentheses, e.g. "Sarah Chen (sp-ident-sarah-chen)"
            embedded_id_match = re.search(r"\((sp-ident-[a-zA-Z0-9_-]+)\)", raw_query)
            extracted_id = embedded_id_match.group(1) if embedded_id_match else None

            # Check direct exact ID match
            for ident in self._identities:
                ident_id = ident.get("id", "")
                if extracted_id and ident_id.lower() == extracted_id.lower():
                    candidates_by_query = [ident]
                    break
                if raw_query.lower() == ident_id.lower():
                    candidates_by_query = [ident]
                    break

            # If no exact ID match, check email or exact display name
            if not candidates_by_query:
                clean_name = re.sub(r"\s*\([^)]*\)", "", raw_query).strip()
                for ident in self._identities:
                    disp = (ident.get("display_name") or "").strip()
                    email = (ident.get("email") or "").strip()
                    if email and raw_query.lower() == email.lower():
                        candidates_by_query.append(ident)
                    elif disp and clean_name.lower() == disp.lower():
                        candidates_by_query.append(ident)

            # If still no exact match, check case-insensitive substring
            if not candidates_by_query and len(raw_query) >= 3:
                clean_name = re.sub(r"\s*\([^)]*\)", "", raw_query).strip().lower()
                for ident in self._identities:
                    disp = (ident.get("display_name") or "").strip().lower()
                    if clean_name and (clean_name in disp or disp in clean_name):
                        candidates_by_query.append(ident)

        # 4. Check for Conflict between employee_id and query name
        if ident_by_eid and candidates_by_query:
            matching_ids = {c.get("id") for c in candidates_by_query}
            if ident_by_eid.get("id") not in matching_ids:
                return IdentityResolutionResult(
                    status=IdentityResolutionStatus.CONFLICT,
                    message=(
                        f"Identity Conflict Detected: Employee ID '{raw_eid}' resolves to '{ident_by_eid.get('display_name')}' "
                        f"({ident_by_eid.get('id')}), but identity query '{raw_query}' maps to '{candidates_by_query[0].get('display_name')}' "
                        f"({candidates_by_query[0].get('id')}). Identity verification failed."
                    ),
                    candidate_matches=[
                        f"{ident_by_eid.get('display_name')} ({ident_by_eid.get('id')})",
                        f"{candidates_by_query[0].get('display_name')} ({candidates_by_query[0].get('id')})",
                    ],
                )

        # 5. Check for Ambiguity / Duplicates
        if len(candidates_by_query) > 1:
            match_descriptions = [f"{c.get('display_name')} ({c.get('id')})" for c in candidates_by_query]
            return IdentityResolutionResult(
                status=IdentityResolutionStatus.AMBIGUOUS,
                candidate_matches=match_descriptions,
                message=(
                    f"Ambiguous Identity Reference: Query '{raw_query}' matched multiple candidate identities: "
                    f"{', '.join(match_descriptions)}. Please provide exact unique Identity ID."
                ),
            )

        # Determine resolved target identity
        resolved_ident: Optional[Dict[str, Any]] = None
        if ident_by_eid:
            resolved_ident = ident_by_eid
        elif candidates_by_query:
            resolved_ident = candidates_by_query[0]
        elif ident_by_acct:
            resolved_ident = ident_by_acct

        # 6. Unmapped check: Never fallback to default identity!
        if not resolved_ident:
            ref_str = raw_query or raw_eid or raw_acct
            return IdentityResolutionResult(
                status=IdentityResolutionStatus.UNMAPPED,
                message=(
                    f"Identity '{ref_str}' cannot be correlated to any registered identity profile "
                    "or active authoritative directory in SailPoint ISC."
                ),
            )

        # 7. Collect accounts
        ident_id = resolved_ident.get("id", "")
        linked_accounts = [
            a.get("id") for a in self._accounts
            if a.get("identity_id") == ident_id
        ]
        if not linked_accounts:
            linked_accounts = resolved_ident.get("source_accounts", [])

        # 8. Classify Governance Lifecycle State
        l_state = (resolved_ident.get("lifecycle_state") or "ACTIVE").upper()
        emp_type = (resolved_ident.get("employment_type") or "EMPLOYEE").upper()
        idp_id = (resolved_ident.get("identity_profile_id") or "").lower()

        if l_state in ["LEAVER", "TERMINATED", "INACTIVE", "DEPROVISIONED"]:
            lifecycle_category = IdentityLifecycleCategory.LEAVER
        elif l_state in ["JOINER", "PREHIRE", "ONBOARDING"]:
            lifecycle_category = IdentityLifecycleCategory.JOINER
        elif emp_type == "CONTRACTOR" or "contractor" in idp_id:
            lifecycle_category = IdentityLifecycleCategory.CONTRACTOR
        elif emp_type == "SERVICE" or "svc-" in ident_id:
            lifecycle_category = IdentityLifecycleCategory.SERVICE_ACCOUNT
        elif target_department and resolved_ident.get("department") and target_department.lower() != resolved_ident.get("department", "").lower():
            lifecycle_category = IdentityLifecycleCategory.MOVER
        else:
            lifecycle_category = IdentityLifecycleCategory.ACTIVE_EMPLOYEE

        return IdentityResolutionResult(
            status=IdentityResolutionStatus.RESOLVED,
            identity=resolved_ident,
            identity_id=ident_id,
            display_name=resolved_ident.get("display_name"),
            employment_type=emp_type,
            lifecycle_state=l_state,
            department=resolved_ident.get("department"),
            job_title=resolved_ident.get("job_title"),
            identity_profile_id=resolved_ident.get("identity_profile_id"),
            lifecycle_category=lifecycle_category,
            account_ids=linked_accounts,
            message=f"Successfully correlated to SailPoint identity '{resolved_ident.get('display_name')}' ({ident_id}).",
        )

    @classmethod
    def evaluate_access_state(
        cls,
        request_status: Optional[str] = None,
        approval_status: Optional[str] = None,
        provisioning_status: Optional[str] = None,
    ) -> IdentityAccessState:
        """Evaluate distinct governance access states.

        Enforces:
        - Requested access is not approved access (SP-01)
        - Approved access is not provisioned access (SP-02)
        - Effective access requires BOTH approved AND provisioned.
        """
        req_norm = (request_status or "").upper().strip()
        appr_norm = (approval_status or "").upper().strip()
        prov_norm = (provisioning_status or "").upper().strip()

        is_requested = req_norm in ["SUBMITTED", "PENDING", "REQUESTED", "IN_REVIEW", "APPROVED"]
        is_approved = appr_norm in ["APPROVED", "AUTO_APPROVED", "SIGNED_OFF"]
        is_provisioned = prov_norm in ["PROVISIONED", "SUCCESSFULLY_PROVISIONED", "ACTIVE"]

        # Effective access strictly requires both approval AND provisioning
        is_effective = is_approved and is_provisioned

        summary_parts = []
        if is_effective:
            summary_parts.append("EFFECTIVE (Approved & Provisioned)")
        elif is_provisioned and not is_approved:
            summary_parts.append("PROVISIONED_WITHOUT_APPROVAL (Unauthorized / Orphan Grant)")
        elif is_approved and not is_provisioned:
            summary_parts.append("APPROVED_PENDING_PROVISIONING (SP-02 Unprovisioned Gap)")
        elif is_requested and not is_approved:
            summary_parts.append("PENDING_APPROVAL (SP-01 In-Flight Request)")
        else:
            summary_parts.append("NO_EFFECTIVE_ACCESS")

        return IdentityAccessState(
            is_requested=is_requested,
            is_approved=is_approved,
            is_provisioned=is_provisioned,
            is_effective=is_effective,
            governance_state_summary=" • ".join(summary_parts),
        )
