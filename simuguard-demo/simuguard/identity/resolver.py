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
    IDENTITY_MISMATCH = "CONFLICT"


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
    """Dynamic, centralized resolver for SailPoint and AWS IAM identity governance entities."""

    def __init__(
        self,
        sailpoint_data: Optional[Dict[str, Any]] = None,
        iam_data: Optional[Dict[str, Any]] = None,
    ):
        self.sp_data = sailpoint_data or {}
        self._identities: List[Dict[str, Any]] = self.sp_data.get("identities", {}).get("identities", [])
        self._accounts: List[Dict[str, Any]] = self.sp_data.get("accounts", {}).get("accounts", [])
        self._roles: List[Dict[str, Any]] = self.sp_data.get("roles", {}).get("roles", [])

        # AWS IAM Digital Twin data
        self.iam_data = iam_data
        if self.iam_data is None:
            try:
                from simuguard.graph.dataset_loader import EnterpriseDatasetLoader
                self.iam_data = EnterpriseDatasetLoader().load_aws_iam_governance()
            except Exception:
                self.iam_data = {}
        self._iam_identities: List[Dict[str, Any]] = (self.iam_data or {}).get("identities", {}).get("identities", [])
        self._iam_roles: List[Dict[str, Any]] = (self.iam_data or {}).get("roles", {}).get("roles", [])
        self._iam_trusts: List[Dict[str, Any]] = (self.iam_data or {}).get("trust_relationships", {}).get("trust_relationships", [])
        self._iam_policies: List[Dict[str, Any]] = (self.iam_data or {}).get("policies", {}).get("policies", [])
        self._iam_resource_policies: List[Dict[str, Any]] = (self.iam_data or {}).get("resource_policies", {}).get("resource_policies", [])

    def _resolve_aws_iam_identity(
        self,
        query: str,
        identifier: str,
        account_id: str,
    ) -> Optional[IdentityResolutionResult]:
        """Resolve AWS IAM role, user, or service identity from Digital Twin data."""
        raw_q = query.strip()
        raw_id = identifier.strip()
        raw_acct = account_id.strip()

        # Check if query or identifier points to an AWS IAM resource
        is_iam_ref = any([
            "arn:aws:iam:" in raw_q.lower(),
            "arn:aws:iam:" in raw_id.lower(),
            raw_id.startswith("ident-role-"),
            raw_id.startswith("ident-user-"),
            raw_id.startswith("ident-group-"),
            raw_id.startswith("ident-svc-"),
            raw_q.startswith("ident-role-"),
            raw_q.startswith("role-"),
            raw_id.startswith("role-"),
        ])

        if not is_iam_ref:
            # Also check if query or id matches any known IAM identity/role ID or trust relationship
            known_ids = {i.get("id", "").lower() for i in self._iam_identities}
            known_names = {i.get("name", "").lower() for i in self._iam_identities}
            known_roles = {r.get("id", "").lower() for r in self._iam_roles}
            known_trusts = set()
            for tr in self._iam_trusts:
                if tr.get("assumes_role"):
                    known_trusts.add(tr["assumes_role"].lower())
                    known_trusts.add(tr["assumes_role"].lower().split("/")[-1])
                if tr.get("id"):
                    known_trusts.add(tr["id"].lower())
                if tr.get("role_id"):
                    known_trusts.add(tr["role_id"].lower())
            if (raw_q.lower() in known_ids or raw_q.lower() in known_names or 
                raw_q.lower() in known_roles or raw_q.lower() in known_trusts):
                is_iam_ref = True
            elif (raw_id.lower() in known_ids or raw_id.lower() in known_names or 
                  raw_id.lower() in known_roles or raw_id.lower() in known_trusts):
                is_iam_ref = True

        if not is_iam_ref:
            return None

        # Clean query if it has embedded ID: e.g. "role-analytics-ingestion-svc (ident-role-analytics-ingestion-svc)"
        clean_q = raw_q
        emb_m = re.search(r"\((ident-[a-zA-Z0-9_-]+)\)", raw_q, re.IGNORECASE)
        if emb_m:
            if not raw_id:
                raw_id = emb_m.group(1).strip()
            clean_q = re.sub(r"\s*\([^)]*\)", "", raw_q).strip()

        # Helper to find identity in _iam_identities, _iam_roles, and _iam_trusts
        def find_iam_match(term: str) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
            if not term:
                return None, None
            t_low = term.lower()
            # 1. Exact ARN match
            for ident in self._iam_identities:
                if ident.get("arn", "").lower() == t_low:
                    role_rec = next((r for r in self._iam_roles if r.get("arn", "").lower() == t_low or r.get("id", "").lower() == ident.get("name", "").lower()), None)
                    return ident, role_rec
            for r in self._iam_roles:
                if r.get("arn", "").lower() == t_low:
                    ident = next((i for i in self._iam_identities if i.get("arn", "").lower() == t_low or i.get("name", "").lower() == r.get("id", "").lower()), None)
                    return ident, r

            # 2. Exact ID match (ident-role-...)
            for ident in self._iam_identities:
                if ident.get("id", "").lower() == t_low:
                    role_rec = next((r for r in self._iam_roles if r.get("id", "").lower() == ident.get("name", "").lower() or r.get("arn", "").lower() == ident.get("arn", "").lower()), None)
                    return ident, role_rec

            # 3. Exact Name / Role ID match
            for ident in self._iam_identities:
                if ident.get("name", "").lower() == t_low:
                    role_rec = next((r for r in self._iam_roles if r.get("id", "").lower() == t_low or r.get("arn", "").lower() == ident.get("arn", "").lower()), None)
                    return ident, role_rec
            for r in self._iam_roles:
                if r.get("id", "").lower() == t_low:
                    ident = next((i for i in self._iam_identities if i.get("name", "").lower() == t_low), None)
                    return ident, r

            # 4. Match in trust_relationships.json (cross-account assumed role or trust target)
            for tr in self._iam_trusts:
                assumes = tr.get("assumes_role", "")
                assumes_short = assumes.split("/")[-1] if "/" in assumes else assumes
                tr_id = tr.get("id", "")
                if t_low in [assumes.lower(), assumes_short.lower(), tr_id.lower()]:
                    target_acct = tr.get("target_account", "111122223333")
                    ident = {
                        "id": f"ident-{assumes_short}",
                        "name": assumes_short,
                        "type": "AWS_IAM_Role",
                        "arn": assumes,
                        "account_id": target_acct,
                        "criticality": "HIGH",
                        "trust_relationship_id": tr.get("id"),
                    }
                    role_rec = {
                        "id": assumes_short,
                        "arn": assumes,
                        "account_id": target_acct,
                        "attached_policies": ["SecurityAudit"],
                    }
                    return ident, role_rec

            return None, None

        ident_by_id, role_by_id = find_iam_match(raw_id)
        ident_by_q, role_by_q = find_iam_match(clean_q)

        # Detect conflict if both provided and resolve to different entities
        if ident_by_id and ident_by_q:
            id1 = ident_by_id.get("id") or ident_by_id.get("arn")
            id2 = ident_by_q.get("id") or ident_by_q.get("arn")
            if id1 != id2:
                # Check if this is an expected cross-account trust pairing (source -> target)
                is_trust_pair = False
                for tr in self._iam_trusts:
                    tr_role = tr.get("role_id", "").lower()
                    tr_assumes = tr.get("assumes_role", "").lower()
                    n1 = ident_by_id.get("name", "").lower()
                    n2 = ident_by_q.get("name", "").lower()
                    a1 = ident_by_id.get("arn", "").lower()
                    a2 = ident_by_q.get("arn", "").lower()
                    if ((tr_role in [n1, a1] and tr_assumes in [n2, a2]) or 
                        (tr_role in [n2, a2] and tr_assumes in [n1, a1])):
                        is_trust_pair = True
                        break
                if not is_trust_pair:
                    return IdentityResolutionResult(
                        status=IdentityResolutionStatus.CONFLICT,
                        message=(
                            f"Identity Conflict Detected: Identity Record '{raw_id}' resolves to '{ident_by_id.get('name')}', "
                            f"but Role Query '{raw_q}' maps to '{ident_by_q.get('name')}'. Identity verification failed."
                        ),
                        candidate_matches=[
                            f"{ident_by_id.get('name')} ({ident_by_id.get('id')})",
                            f"{ident_by_q.get('name')} ({ident_by_q.get('id')})",
                        ],
                    )

        matched_ident = ident_by_id or ident_by_q
        matched_role = role_by_id or role_by_q

        # If reference was an explicit AWS IAM reference but not found
        if not matched_ident and not matched_role:
            target_str = raw_id or clean_q or raw_q
            return IdentityResolutionResult(
                status=IdentityResolutionStatus.UNMAPPED,
                message=(
                    f"Specified AWS IAM identity reference '{target_str}' not found in authoritative IAM Digital Twin directory. "
                    "Substitution with another identity is strictly prohibited."
                ),
            )

        # Synthesize combined identity record
        ident_id = (matched_ident.get("id") if matched_ident else f"ident-{matched_role.get('id')}")
        ident_name = (matched_ident.get("name") if matched_ident else matched_role.get("id"))
        ident_arn = (matched_ident.get("arn") if matched_ident else matched_role.get("arn"))
        acct = (matched_ident.get("account_id") if matched_ident else matched_role.get("account_id", raw_acct))
        crit = (matched_ident.get("criticality") if matched_ident else matched_role.get("criticality", "High"))
        itype = (matched_ident.get("type") if matched_ident else "IAM_Role")

        full_ident = {
            **(matched_ident or {}),
            "role_details": matched_role or {},
            "id": ident_id,
            "name": ident_name,
            "arn": ident_arn,
            "account_id": acct,
            "criticality": crit,
            "type": itype,
            "attached_policies": matched_role.get("attached_policies", []) if matched_role else [],
            "permission_boundary": matched_role.get("permission_boundary") if matched_role else None,
            "assigned_to": matched_ident.get("assigned_to", []) if matched_ident else [],
        }

        return IdentityResolutionResult(
            status=IdentityResolutionStatus.RESOLVED,
            identity=full_ident,
            identity_id=ident_id,
            display_name=ident_name,
            employment_type=itype,
            lifecycle_state="ACTIVE",
            department=f"AWS Account {acct}" if acct else "AWS IAM",
            job_title=itype,
            identity_profile_id=f"aws-iam-{acct}" if acct else "aws-iam",
            lifecycle_category=IdentityLifecycleCategory.SERVICE_ACCOUNT if "role" in itype.lower() or "svc" in itype.lower() else IdentityLifecycleCategory.ACTIVE_EMPLOYEE,
            account_ids=[acct] if acct else [],
            message=f"Successfully correlated to AWS IAM identity '{ident_name}' ({ident_arn}).",
        )

    def resolve_identity(
        self,
        query: Optional[str] = None,
        employee_id: Optional[str] = None,
        worker_id: Optional[str] = None,
        account_id: Optional[str] = None,
        email: Optional[str] = None,
        department: Optional[str] = None,
        target_department: Optional[str] = None,
        identifier: Optional[str] = None,
    ) -> IdentityResolutionResult:
        """Resolve identity dynamically from query, employee_id, worker_id, account_id, or email.

        Never defaults to any hardcoded identity when matching fails.
        Detects conflicts between employee_id, email, and query name.
        Detects duplicate/ambiguous matches when multiple identities match.
        Strictly requires exact employee/worker ID resolution when provided; never substitutes another identity.
        """
        raw_query = (query or "").strip()
        raw_eid = (identifier or employee_id or worker_id or "").strip()
        raw_acct = (account_id or "").strip()
        raw_email = (email or "").strip().lower()

        # If query contains an embedded ID, extract it
        if raw_query:
            embedded_eid = re.search(r"\((EMP-[a-zA-Z0-9_-]+|CTR-[a-zA-Z0-9_-]+)\)", raw_query, re.IGNORECASE)
            if embedded_eid and not raw_eid:
                raw_eid = embedded_eid.group(1).strip()

        if not raw_query and not raw_eid and not raw_acct and not raw_email:
            return IdentityResolutionResult(
                status=IdentityResolutionStatus.UNMAPPED,
                message="No target identity specified. Identity resolution cannot proceed without an identity reference.",
            )

        # Check AWS IAM identities & roles first
        iam_res = self._resolve_aws_iam_identity(
            query=raw_query,
            identifier=raw_eid,
            account_id=raw_acct,
        )
        if iam_res is not None:
            return iam_res

        # 1. Match by employee_id / worker_id if provided
        ident_by_eid: Optional[Dict[str, Any]] = None
        if raw_eid:
            raw_eid_lower = raw_eid.lower()
            for ident in self._identities:
                attrs = ident.get("attributes") or {}
                candidates_to_check = [
                    str(ident.get("id") or ""),
                    str(ident.get("employee_id") or ""),
                    str(ident.get("worker_id") or ""),
                    str(attrs.get("employeeId") or ""),
                    str(attrs.get("workerId") or ""),
                ]
                if any(c.strip().lower() == raw_eid_lower for c in candidates_to_check if c.strip()):
                    ident_by_eid = ident
                    break

        # 2. Match by email if provided
        ident_by_email: Optional[Dict[str, Any]] = None
        if raw_email:
            for ident in self._identities:
                em = (ident.get("email") or ident.get("attributes", {}).get("email") or "").strip().lower()
                if em and em == raw_email:
                    ident_by_email = ident
                    break

        # Check for Conflict between employee_id and email
        if ident_by_eid and ident_by_email and ident_by_eid.get("id") != ident_by_email.get("id"):
            return IdentityResolutionResult(
                status=IdentityResolutionStatus.CONFLICT,
                message=(
                    f"Identity Conflict Detected: Employee ID '{raw_eid}' resolves to '{ident_by_eid.get('display_name')}' "
                    f"({ident_by_eid.get('id')}), but Email '{raw_email}' resolves to '{ident_by_email.get('display_name')}' "
                    f"({ident_by_email.get('id')}). Identity verification failed."
                ),
                candidate_matches=[
                    f"{ident_by_eid.get('display_name')} ({ident_by_eid.get('id')})",
                    f"{ident_by_email.get('display_name')} ({ident_by_email.get('id')})",
                ],
            )

        # 3. Match by account_id if provided
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

        # 4. Match by query text (ID, display_name, email)
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
        elif raw_eid:
            # An explicit Employee/Worker ID was provided, but could not be resolved in the directory.
            # Substitution with another identity based on name/substring is strictly prohibited.
            return IdentityResolutionResult(
                status=IdentityResolutionStatus.UNMAPPED,
                message=(
                    f"Specified Employee/Worker ID '{raw_eid}' not found in authoritative identity directory. "
                    f"Substitution with another identity based on name query '{raw_query}' is strictly prohibited."
                ),
            )
        elif ident_by_email:
            resolved_ident = ident_by_email
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
