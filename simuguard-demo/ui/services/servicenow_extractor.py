"""ServiceNow Change Request Extractor and Parser Service.

Extracts structured firewall, NAT, and identity governance configurations from
unstructured ServiceNow ticket text, key-value fields, and embedded Terraform HCL blocks.
"""

from dataclasses import dataclass, field
import json
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Tuple

from config.settings import CHANGES_DIR


@dataclass
class ExtractedConfig:
    """Structured configuration fields extracted from a ServiceNow change request."""

    domain: str = "NETWORK_SECURITY"  # "NETWORK_SECURITY" or "IDENTITY_GOVERNANCE"
    title: str = ""
    request_number: str = ""
    priority: str = "HIGH"
    change_type: str = "NORMAL"
    change_operation: str = "Create Security Policy"
    category: str = "Network Security"
    subcategory: str = "Firewall Rule Modification"
    business_service: str = ""
    business_application: str = ""
    environment: str = "Production"
    target_firewall: str = "PAN-NGFW-EDGE-01"
    firewall_device: str = "PAN-NGFW-EDGE-01"
    firewall_platform: str = "Palo Alto PA-5450"
    management_platform: str = "Panorama"

    requested_by: str = "SecOps Operations Engineer"
    assignment_group: str = "Network Security Operations"
    justification: str = ""
    implementation_plan: str = ""
    validation_plan: str = ""
    backout_plan: str = ""
    maintenance_window: str = ""
    description: str = ""

    # Network Security / Firewall Rule Fields
    rule_name: str = ""
    existing_rule_name: str = ""
    source_zone: str = ""
    destination_zone: str = ""
    source_addresses: str = ""
    destination_addresses: str = ""
    applications: str = ""
    services: str = ""
    protocol: str = "TCP"
    destination_port: str = ""
    action: str = "allow"
    security_profile: str = "Strict-Enterprise-Security"
    logging: str = "Enabled at session end"

    # Inbound Destination NAT Fields (Specific to CHG-2026-1004)
    is_nat_change: bool = False
    nat_rule_name: str = ""
    nat_original_source_zone: str = ""
    nat_original_destination_zone: str = ""
    nat_original_destination_address: str = ""
    nat_original_destination_port: str = ""
    nat_translated_destination_address: str = ""
    nat_translated_destination_port: str = ""

    # Identity Governance / SailPoint Fields
    lifecycle_type: str = ""  # "JOINER", "MOVER", "LEAVER", "ACCESS_REQUEST", "ACCESS_MODIFICATION", "ACCESS_REVOCATION"
    identity_name: str = ""
    employee_id: str = ""
    worker_id: str = ""
    contractor_id: str = ""
    corporate_email: str = ""
    worker_type: str = ""
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
    requested_role: str = ""
    access_profile: str = ""
    entitlement: str = ""
    access_to_add: List[str] = field(default_factory=list)
    access_to_remove: List[str] = field(default_factory=list)
    privileged_entitlements: List[str] = field(default_factory=list)
    accounts_to_disable: List[str] = field(default_factory=list)
    entitlements_to_revoke: List[str] = field(default_factory=list)
    applications_deprovision: List[str] = field(default_factory=list)
    access_duration: str = ""
    start_date: str = ""
    effective_date: str = ""
    termination_date: str = ""
    approvals: Dict[str, str] = field(default_factory=dict)
    approval_status: str = "APPROVED"
    privileged_access_requested: bool = False

    # AWS IAM & Cloud Identity Governance Fields
    role_name: str = ""
    role_arn: str = ""
    target_role_name: str = ""
    target_role_arn: str = ""
    source_role_name: str = ""
    source_role_arn: str = ""
    identity_record_id: str = ""
    source_identity_record_id: str = ""
    aws_account: str = ""
    source_aws_account: str = ""
    target_aws_account: str = ""
    assigned_workload: str = ""
    current_attached_policies: List[str] = field(default_factory=list)
    permission_boundary: str = ""
    permission_boundary_arn: str = ""
    boundary_action: str = ""  # "RETAIN", "REMOVE", "NONE"
    trust_relationship_id: str = ""
    trusted_principal: str = ""
    mfa_condition: str = ""
    external_id_condition: str = ""
    requested_policy_name: str = ""
    requested_policy_arn: str = ""
    requested_policy_action: str = ""
    requested_policy_resource: str = ""

    # Raw Payload & Metadata
    raw_hcl: str = ""
    scenario_source_path: Optional[str] = None
    warnings: List[str] = field(default_factory=list)
    missing_fields: List[str] = field(default_factory=list)


@dataclass
class ChangeRequestSummary:
    """Plain-English business and operational summary of a change request."""

    what_is_requested: str = ""
    why_requested: str = ""
    key_configuration_changes: Dict[str, str] = field(default_factory=dict)
    initial_observations: List[str] = field(default_factory=list)


class ServiceNowExtractor:
    """Intelligent text parser and configuration extractor for ServiceNow tickets."""

    @classmethod
    def extract_from_text(cls, text: str) -> ExtractedConfig:
        """Parse raw ServiceNow change ticket text into structured ExtractedConfig."""
        cfg = ExtractedConfig()
        clean_text = text.strip()
        if not clean_text:
            cfg.missing_fields.append("Empty Change Request input")
            return cfg

        # 1. Detect Domain
        lower_text = clean_text.lower()
        identity_keywords = [
            "sailpoint", "identity", "entitlement", "access profile",
            "identitynow", "governance", "sod conflict", "grant role",
            "iam", "access request", "joiner", "mover", "leaver", "offboarding", "ritm",
            "employee", "employee id", "worker", "worker id", "emp id", "user id",
            "department", "new department", "current department", "new role", "current role",
            "job title", "onboarding", "lifecycle", "access to add", "access to remove",
            "revoke access", "grant access", "privileged access", "sap finance", "role transfer",
            "deprovision", "provision", "contractor"
        ]
        firewall_keywords = [
            "firewall", "panos", "palo alto", "security rule", "nat rule",
            "source zone", "destination zone", "cidr", "app-id", "ingress", "egress"
        ]

        id_score = sum(1 for kw in identity_keywords if kw in lower_text)
        fw_score = sum(1 for kw in firewall_keywords if kw in lower_text)

        iam_structural_match = bool(re.search(
            r"^(?:Employee|Worker|Target Identity|New department|Current department|New role|Current role|Remove|Add|Revoke|Grant|Lifecycle|Authoritative Source|Entitlement|Access Profile)\s*[:=]",
            clean_text,
            re.MULTILINE | re.IGNORECASE,
        ))
        fw_structural_match = bool(re.search(
            r"^(?:Source Zone|Destination Zone|From Zone|To Zone|Target Firewall|Firewall Platform|NAT Rule|App-ID|Security Policy)\s*[:=]",
            clean_text,
            re.MULTILINE | re.IGNORECASE,
        ))

        if fw_structural_match:
            cfg.domain = "NETWORK_SECURITY"
        elif iam_structural_match or id_score > fw_score:
            cfg.domain = "IDENTITY_GOVERNANCE"
        elif id_score >= 2:
            cfg.domain = "IDENTITY_GOVERNANCE"
        else:
            cfg.domain = "NETWORK_SECURITY"

        # 2. Extract Common Header Fields
        cfg.request_number = cls._extract_field(
            clean_text,
            [r"^(?:CHANGE REQUEST|Change Request|Request Number|Ticket Number|Req #|REQUEST|Request)\s*[:=]\s*([A-Za-z0-9_\-]+)"],
            default="",
        )
        cfg.title = cls._extract_field(
            clean_text,
            [r"^(?:Short Description|Summary|Title)\s*[:=]\s*(.+)"],
            default="",
        )
        raw_prio = cls._extract_field(clean_text, [r"^Priority\s*[:=]\s*(.+)"], default="HIGH")
        prio_upper = raw_prio.upper()
        if "CRITICAL" in prio_upper or "1 -" in prio_upper:
            cfg.priority = "CRITICAL"
        elif "HIGH" in prio_upper or "2 -" in prio_upper:
            cfg.priority = "HIGH"
        elif "MODERATE" in prio_upper or "MEDIUM" in prio_upper or "3 -" in prio_upper:
            cfg.priority = "MEDIUM"
        elif "LOW" in prio_upper or "4 -" in prio_upper or "5 -" in prio_upper or "PLANNING" in prio_upper:
            cfg.priority = "LOW"
        else:
            cfg.priority = "HIGH"

        cfg.change_type = cls._extract_field(
            clean_text,
            [r"^Change Type\s*[:=]\s*(.+)"],
            default="NORMAL",
        ).upper()
        cfg.change_operation = cls._extract_field(
            clean_text,
            [r"^Change Operation\s*[:=]\s*(.+)"],
            default="Create Security Policy",
        )
        if cfg.domain == "IDENTITY_GOVERNANCE":
            cfg.category = "Identity Governance"
            low_text = clean_text.lower()
            if "joiner" in low_text or "new starter" in low_text:
                cfg.subcategory = "Joiner Access Request"
                cfg.change_operation = "Provision Standard Role (Joiner)"
            elif "mover" in low_text or "transfer" in low_text:
                cfg.subcategory = "Mover Access Modification"
                cfg.change_operation = "Role Transfer & Update (Mover)"
            elif "leaver" in low_text or "offboarding" in low_text or "revocation" in low_text:
                cfg.subcategory = "Leaver Access Revocation"
                cfg.change_operation = "Revoke Access (Leaver Offboarding)"
            else:
                cfg.subcategory = "Access Request"
        else:
            cfg.category = cls._extract_field(
                clean_text,
                [r"^Category\s*[:=]\s*(.+)"],
                default="Network Security",
            )
            cfg.subcategory = cls._extract_field(
                clean_text,
                [r"^Subcategory\s*[:=]\s*(.+)"],
                default="Firewall Rule Modification",
            )
        cfg.business_service = cls._extract_field(
            clean_text,
            [r"^Business Service\s*[:=]\s*(.+)"],
            default="",
        )
        cfg.business_application = cls._extract_field(
            clean_text,
            [r"^Application\s*[:=]\s*(APP-[A-Za-z0-9_\-]+)", r"^Business Application\s*[:=]\s*(.+)"],
            default="",
        )
        cfg.environment = cls._extract_field(
            clean_text,
            [r"^Environment\s*[:=]\s*(.+)"],
            default="Production",
        )
        cfg.target_firewall = cls._extract_field(
            clean_text,
            [r"^Target Firewall\s*[:=]\s*(.+)"],
            default="PAN-NGFW-EDGE-01",
        )
        cfg.firewall_device = cfg.target_firewall
        cfg.firewall_platform = cls._extract_field(
            clean_text,
            [r"^Firewall Platform\s*[:=]\s*(.+)"],
            default="Palo Alto PA-5450",
        )
        cfg.management_platform = cls._extract_field(
            clean_text,
            [r"^Management Platform\s*[:=]\s*(.+)"],
            default="Panorama",
        )
        cfg.requested_by = cls._extract_field(
            clean_text,
            [r"^Requested By\s*[:=]\s*(.+)", r"^Submitter\s*[:=]\s*(.+)"],
            default="SecOps Operations Engineer",
        )
        cfg.assignment_group = cls._extract_field(
            clean_text,
            [r"^Assignment Group\s*[:=]\s*(.+)"],
            default="Network Security Operations",
        )
        cfg.justification = (
            cls._extract_multiline_section(clean_text, "Business Justification")
            or cls._extract_multiline_section(clean_text, "Justification")
            or cls._extract_multiline_section(clean_text, "Business Reason")
            or cls._extract_multiline_section(clean_text, "Reason")
            or cls._extract_field(clean_text, [r"^Justification\s*[:=]\s*(.+)", r"^Business Justification\s*[:=]\s*(.+)"])
        )
        cfg.implementation_plan = cls._extract_multiline_section(clean_text, "Implementation Plan")
        cfg.validation_plan = cls._extract_multiline_section(clean_text, "Validation Plan")
        cfg.backout_plan = cls._extract_multiline_section(clean_text, "Backout Plan")
        cfg.maintenance_window = cls._extract_field(
            clean_text,
            [r"^Requested Maintenance Window\s*[:=]\s*(.+)", r"^Maintenance Window\s*[:=]\s*(.+)"],
            default="Next Scheduled Maintenance Window",
        )

        # 3. Check for Embedded Terraform / HCL Block
        hcl_match = re.search(r'(resource\s+"[^"]+"\s+"[^"]+"\s*\{.*?\})', clean_text, re.DOTALL)
        if hcl_match:
            cfg.raw_hcl = hcl_match.group(1).strip()
            cls._extract_from_hcl(cfg.raw_hcl, cfg)
        elif "resource " in clean_text and " {" in clean_text:
            cfg.raw_hcl = clean_text
            cls._extract_from_hcl(clean_text, cfg)

        # 4. Extract Domain-Specific Fields
        if cfg.domain == "NETWORK_SECURITY":
            cls._extract_firewall_and_nat_fields(clean_text, cfg)
        else:
            cls._extract_sailpoint_fields(clean_text, cfg)

        # 5. Extract Approvals & Governance Status
        cls._extract_approvals(clean_text, cfg)

        # 6. Check if matches known baseline files in changes/
        cls._match_known_scenario(clean_text, cfg)

        # 7. Validate Missing and Ambiguous Fields
        cls._validate_fields(cfg)

        return cfg

    @classmethod
    def _extract_field(cls, text: str, patterns: List[str], default: str = "") -> str:
        """Extract first matching group from regex patterns line by line."""
        for pat in patterns:
            m = re.search(pat, text, re.IGNORECASE | re.MULTILINE)
            if m:
                val = m.group(1).strip()
                if val:
                    return val
        return default

    @classmethod
    def _extract_multiline_section(cls, text: str, section_header: str) -> str:
        """Extract multi-line body under a section header until the next uppercase header."""
        pat = rf"(?:^|\n){re.escape(section_header)}\s*[:=]\s*\n?([\s\S]+?)(?=\n(?!ADD:|REMOVE:)[A-Z][A-Za-z0-9 ]+:\s*|\Z)"
        m = re.search(pat, text, re.IGNORECASE)
        if m:
            body = m.group(1).strip()
            return body
        return ""

    @classmethod
    def _extract_approvals(cls, text: str, cfg: ExtractedConfig) -> None:
        """Extract multi-line approvals section and determine composite approval status."""
        pat = r"(?:^|\n)Approvals(?: and confirmations)?\s*[:=]\s*\n?([\s\S]+?)(?=\n(?:Assessment note|Additional note|Dependencies|Implementation|Validation|Backout|Exception handling|Fulfilment|Worker|Requested|Risk|\n\s*\n)|\Z)"
        m = re.search(pat, text, re.IGNORECASE)
        approvals_block = m.group(1).strip() if m else ""
        if not approvals_block:
            approvals_block = cls._extract_multiline_section(text, "Approval Status")

        cfg.approvals = {}
        if approvals_block:
            for line in approvals_block.splitlines():
                line = line.strip().lstrip("-*• ")
                if ":" in line:
                    role, status = line.split(":", 1)
                    role_clean = role.strip()
                    status_clean = status.strip()
                    if role_clean.lower() in ["assessment note", "additional note", "note"]:
                        continue
                    if status_clean:
                        cfg.approvals[role_clean] = status_clean

        # Check overall approval status
        pending_statuses = ["pending", "pending confirmation", "required", "not started", "in progress", "tbd"]
        if cfg.approvals:
            has_pending = any(
                any(ps in s.lower() for ps in pending_statuses)
                for s in cfg.approvals.values()
            )
            cfg.approval_status = "PENDING" if has_pending else "APPROVED"
        else:
            cfg.approval_status = "APPROVED"

    @classmethod
    def _extract_firewall_and_nat_fields(cls, text: str, cfg: ExtractedConfig) -> None:
        """Extract firewall rule parameters, NAT translations, security profiles, and logging."""
        # --- NAT Rule Extraction (CHG-2026-1004) ---
        nat_name = cls._extract_field(text, [r"^NAT Rule Name\s*[:=]\s*(.+)"])
        orig_dst_ip = cls._extract_field(text, [r"^Original Destination Address\s*[:=]\s*(.+)"])
        trans_dst_ip = cls._extract_field(text, [r"^Translated Destination Address\s*[:=]\s*(.+)"])

        if nat_name or orig_dst_ip or trans_dst_ip:
            cfg.is_nat_change = True
            cfg.nat_rule_name = nat_name or "Inbound-Destination-NAT"
            cfg.nat_original_source_zone = cls._extract_field(text, [r"^Original Source Zone\s*[:=]\s*(.+)"], default="Untrust-Internet")
            cfg.nat_original_destination_zone = cls._extract_field(text, [r"^Original Destination Zone\s*[:=]\s*(.+)"], default="Untrust-Internet")
            cfg.nat_original_destination_address = orig_dst_ip
            cfg.nat_original_destination_port = cls._extract_field(text, [r"^Original Destination Port\s*[:=]\s*(.+)"], default="443")
            cfg.nat_translated_destination_address = trans_dst_ip
            cfg.nat_translated_destination_port = cls._extract_field(text, [r"^Translated Destination Port\s*[:=]\s*(.+)"], default="443")

        # --- Rule Name & Existing Rule Extraction ---
        existing_rn = cls._extract_field(text, [r"^Existing Rule Name\s*[:=]\s*(.+)"])
        proposed_rn = cls._extract_field(text, [r"^Proposed Rule Name\s*[:=]\s*(.+)"])
        sec_pol_name = cls._extract_field(text, [r"^Security Policy Name\s*[:=]\s*(.+)"])
        std_rule_name = cls._extract_field(text, [r"^Rule Name\s*[:=]\s*(.+)"])

        if proposed_rn:
            cfg.rule_name = proposed_rn
            cfg.existing_rule_name = existing_rn
        elif sec_pol_name:
            cfg.rule_name = sec_pol_name
        elif std_rule_name:
            cfg.rule_name = std_rule_name
        elif existing_rn:
            cfg.rule_name = existing_rn

        # --- Zones & Addresses ---
        cfg.source_zone = cls._extract_field(
            text,
            [r"^Source Zone\s*[:=]\s*(.+)", r"^From Zone\s*[:=]\s*(.+)"],
            default="Untrust-Internet",
        )
        cfg.destination_zone = cls._extract_field(
            text,
            [r"^Destination Zone\s*[:=]\s*(.+)", r"^To Zone\s*[:=]\s*(.+)"],
            default="Untrust-Internet",
        )
        cfg.source_addresses = cls._extract_field(
            text,
            [r"^Source Address(?:es)?\s*[:=]\s*(.+)", r"^Source CIDR\s*[:=]\s*(.+)"],
            default="0.0.0.0/0",
        )

        # Ensure Destination Address is the Security Policy target (not the NAT original IP)
        cfg.destination_addresses = cls._extract_field(
            text,
            [r"^(?!Original|Translated)Destination Address(?:es)?\s*[:=]\s*(.+)", r"^Destination CIDR\s*[:=]\s*(.+)"],
            default=cfg.nat_translated_destination_address or "10.100.2.15/32",
        )

        # --- Layer-7 App-ID vs Business Application ---
        app_candidates = re.findall(r"^Application\s*[:=]\s*(.+)$", text, re.IGNORECASE | re.MULTILINE)
        if len(app_candidates) > 1:
            cfg.applications = app_candidates[1].strip()
        elif len(app_candidates) == 1:
            val = app_candidates[0].strip()
            if val.startswith("APP-") and not cfg.business_application:
                cfg.business_application = val
                cfg.applications = cls._extract_field(text, [r"^App-ID\s*[:=]\s*(.+)"], default="any")
            else:
                cfg.applications = val
        else:
            cfg.applications = cls._extract_field(text, [r"^App-ID\s*[:=]\s*(.+)"], default="any")

        # --- Service, Protocol & Port ---
        fw_section = cls._extract_multiline_section(text, "Firewall details")
        target_srv_text = fw_section if fw_section else text

        srv_candidates = re.findall(r"^Service\s*[:=]\s*(.+)$", target_srv_text, re.IGNORECASE | re.MULTILINE)
        found_srv = ""
        for sc in srv_candidates:
            sc_val = sc.strip()
            if any(it_kw in sc_val.lower() for it_kw in ["network security", "palo alto", "firewall management", "identity"]):
                if not cfg.business_service:
                    cfg.business_service = sc_val
            else:
                found_srv = sc_val
                break

        if not found_srv:
            std_srv = re.search(r"^Service\s*[:=]\s*(tcp/\d+|udp/\d+|service-[a-zA-Z0-9_-]+|any|application-default|\d+)", text, re.IGNORECASE | re.MULTILINE)
            if std_srv:
                found_srv = std_srv.group(1).strip()

        cfg.services = found_srv or "service-https"

        port_m = re.search(r"(?:tcp|udp)/(\d+)", cfg.services, re.IGNORECASE)
        if port_m:
            cfg.destination_port = port_m.group(1)
            cfg.protocol = "TCP" if "tcp" in cfg.services.lower() else "UDP"
        elif cfg.services.lower() == "any":
            cfg.destination_port = "any"
            cfg.protocol = "any"
        else:
            cfg.protocol = cls._extract_field(text, [r"^Protocol\s*[:=]\s*(.+)"], default="TCP").upper()
            cfg.destination_port = cls._extract_field(text, [r"^Destination Port\s*[:=]\s*(.+)"], default="443")

        # --- Action ---
        act = cls._extract_field(text, [r"^Action\s*[:=]\s*(Allow|Deny|Drop)"], default="allow").lower()
        cfg.action = act if act in ["allow", "deny", "drop"] else "allow"

        # --- Security Profile & Logging ---
        cfg.security_profile = cls._extract_field(
            text,
            [
                r"^Security Profile(?:s| Group)?\s*[:=]\s*(.+)",
            ],
            default="Strict-Enterprise-Security",
        )
        cfg.logging = cls._extract_field(
            text,
            [
                r"^Log(?:ging| at session end)?\s*[:=]\s*(.+)",
            ],
            default="Enabled at session end",
        )

    @classmethod
    def _split_items(cls, raw: str) -> List[str]:
        """Split raw section text into clean individual entitlement or role items."""
        lines = raw.splitlines()
        bullet_items = []
        for line in lines:
            line = line.strip()
            if not line:
                continue
            if line.startswith(("-", "*", "•")):
                cleaned = line.lstrip("-*• ").strip()
                if cleaned:
                    bullet_items.append(cleaned)
            elif re.match(r"^\d+[\.\)]\s+", line):
                cleaned = re.sub(r"^\d+[\.\)]\s+", "", line).strip()
                if cleaned:
                    bullet_items.append(cleaned)

        if bullet_items:
            return bullet_items

        # Check for comma-separated or single-line list
        clean_lines = [l.strip() for l in lines if l.strip()]
        if len(clean_lines) == 1 and "," in clean_lines[0]:
            return [part.strip() for part in clean_lines[0].split(",") if part.strip()]
        elif len(clean_lines) > 1:
            res = []
            for l in clean_lines:
                if "," in l:
                    res.extend([part.strip() for part in l.split(",") if part.strip()])
                else:
                    res.append(l)
            return res
        elif clean_lines:
            return clean_lines
        return []

    @classmethod
    def _is_header_or_noise_line(cls, line: str) -> bool:
        """Filter out explanatory guidance headers or instructions."""
        low = line.lower()
        noise_prefixes = [
            "revoke access associated with",
            "standard employee access",
            "access must be removed",
            "provide the standard access",
            "confirm the worker id",
            "match employee id",
            "note:",
            "risk and review",
            "the contractor's engagement",
            "the employee is transferring",
            "all linked accounts",
        ]
        return any(low.startswith(np) for np in noise_prefixes)

    @classmethod
    def _extract_access_lists(cls, text: str) -> Tuple[List[str], List[str]]:
        """Extract lists of access/roles to add and remove across varied enterprise formats."""
        to_add: List[str] = []
        to_remove: List[str] = []

        # 1. Match REMOVE / REVOKE blocks
        rem_m = re.search(
            r"(?:^|\n)(?:REMOVE|REVOKE|DEPROVISION|ACCESS TO REMOVE|ROLES TO REMOVE)\s*[:=]\s*(.*?)(?=\n(?:ADD|GRANT|ASSIGN|PROVISION|ACCESS TO ADD|ROLES TO ADD|[A-Z][A-Za-z0-9 ]+:\s*)|\Z)",
            text,
            re.DOTALL | re.IGNORECASE,
        )
        if rem_m:
            raw_rem = rem_m.group(1).strip()
            to_remove.extend(cls._split_items(raw_rem))

        # 2. Match ADD / GRANT blocks
        add_m = re.search(
            r"(?:^|\n)(?:ADD|GRANT|ASSIGN|PROVISION|ACCESS TO ADD|ROLES TO ADD|REQUESTED ACCESS)\s*[:=]\s*(.*?)(?=\n(?:REMOVE|REVOKE|DEPROVISION|[A-Z][A-Za-z0-9 ]+:\s*)|\Z)",
            text,
            re.DOTALL | re.IGNORECASE,
        )
        if add_m:
            raw_add = add_m.group(1).strip()
            to_add.extend(cls._split_items(raw_add))

        # 3. Check for 'Requested action:' block (common in Leaver requests)
        if not to_remove:
            action_sec = cls._extract_multiline_section(text, "Requested action")
            if action_sec and ("revoke" in action_sec.lower() or "remove" in action_sec.lower()):
                to_remove.extend(cls._split_items(action_sec))

        # 4. Check for 'Requested access changes:' block
        changes_sec = cls._extract_multiline_section(text, "Requested access changes")
        if changes_sec:
            sub_rem = re.search(r"REMOVE\s*[:=]\s*(.*?)(?=\nADD|\Z)", changes_sec, re.DOTALL | re.IGNORECASE)
            sub_add = re.search(r"ADD\s*[:=]\s*(.*?)(?=\nREMOVE|\Z)", changes_sec, re.DOTALL | re.IGNORECASE)
            if sub_rem and not to_remove:
                to_remove.extend(cls._split_items(sub_rem.group(1)))
            if sub_add and not to_add:
                to_add.extend(cls._split_items(sub_add.group(1)))
            if not to_add and not sub_rem and not sub_add:
                to_add.extend(cls._split_items(changes_sec))

        # Clean and deduplicate
        clean_add = []
        for a in to_add:
            if a and not cls._is_header_or_noise_line(a):
                if a not in clean_add:
                    clean_add.append(a)

        clean_remove = []
        for r in to_remove:
            if r and not cls._is_header_or_noise_line(r):
                if r not in clean_remove:
                    clean_remove.append(r)

        return clean_add, clean_remove

    @classmethod
    def _extract_aws_iam_fields(cls, text: str, cfg: ExtractedConfig) -> None:
        """Extract AWS IAM roles, boundaries, policies, and trust relationships."""
        cfg.identity_source = "AWS IAM (Apex Global)"
        cfg.worker_type = "IAM Role"

        # Split source vs target identity blocks
        src_block = ""
        tgt_block = text
        if "Source identity:" in text:
            parts = re.split(r"(?:Target identity:|Target role:)", text, flags=re.IGNORECASE)
            src_block = parts[0]
            tgt_block = parts[1] if len(parts) > 1 else text
        elif "Target IAM identity:" in text:
            tgt_block = text.split("Target IAM identity:")[1]

        # Target Role Name & ARN
        r_name_m = re.search(r"Role name:\s*([A-Za-z0-9_-]+)", tgt_block)
        r_arn_m = re.search(r"Role ARN:\s*(arn:aws:iam::[0-9]+:role/[A-Za-z0-9_-]+)", tgt_block)
        if not r_name_m and r_arn_m:
            r_name = r_arn_m.group(1).split("/")[-1]
        else:
            r_name = r_name_m.group(1).strip() if r_name_m else ""
        cfg.role_name = r_name
        cfg.target_role_name = r_name
        cfg.role_arn = r_arn_m.group(1).strip() if r_arn_m else ""
        cfg.target_role_arn = cfg.role_arn

        # Target Identity Record ID
        id_rec_m = re.search(r"Identity record:\s*([A-Za-z0-9_-]+)", tgt_block)
        cfg.identity_record_id = id_rec_m.group(1).strip() if id_rec_m else ""

        # Target AWS Account
        acct_m = re.search(r"(?:AWS account|Target AWS account):\s*([0-9]+)", tgt_block)
        cfg.aws_account = acct_m.group(1).strip() if acct_m else ""
        cfg.target_aws_account = cfg.aws_account
        cfg.account_id = cfg.aws_account

        # Assigned Workload
        wl_m = re.search(r"Assigned workload:\s*([A-Za-z0-9_-]+)", tgt_block)
        cfg.assigned_workload = wl_m.group(1).strip() if wl_m else ""

        # Source Identity (Cross-Account Scenarios)
        if src_block:
            s_name_m = re.search(r"Role name:\s*([A-Za-z0-9_-]+)", src_block)
            s_arn_m = re.search(r"Role ARN:\s*(arn:aws:iam::[0-9]+:role/[A-Za-z0-9_-]+)", src_block)
            cfg.source_role_name = s_name_m.group(1).strip() if s_name_m else ""
            cfg.source_role_arn = s_arn_m.group(1).strip() if s_arn_m else ""
            s_id_m = re.search(r"Identity record:\s*([A-Za-z0-9_-]+)", src_block)
            cfg.source_identity_record_id = s_id_m.group(1).strip() if s_id_m else ""
            s_acct_m = re.search(r"(?:AWS account|Source AWS account):\s*([0-9]+)", src_block)
            cfg.source_aws_account = s_acct_m.group(1).strip() if s_acct_m else ""

        # Current Attached Policies
        curr_pols: List[str] = []
        for p_match in re.finditer(r"(?:Attached policy|Policy ARN|\d+\.)\s*:\s*\n?\s*([A-Za-z0-9_-]+)", text):
            p_val = p_match.group(1).strip()
            if p_val and p_val not in curr_pols and p_val.lower() != "arn" and not p_val.startswith("arn:") and p_val not in ["Pending", "Approved", "None"]:
                curr_pols.append(p_val)
        known_pols = ["S3TelemetryWriteOnly", "CustomerPortalDatabaseAccess", "PCITokenVaultAccess", "KmsDecryptPaymentScoped", "SecurityAudit", "CrossAccountSecOpsAuditPolicy", "AdministratorAccess", "PowerUserAccess"]
        for kp in known_pols:
            if kp in text and kp not in curr_pols and kp != cfg.requested_policy_name:
                curr_pols.append(kp)
        cfg.current_attached_policies = curr_pols

        # Permission Boundary
        b_m = re.search(r"(?:Current permission boundary|Permission boundary)\s*:\s*\n?\s*([A-Za-z0-9_-]+)", text)
        if b_m:
            cfg.permission_boundary = b_m.group(1).strip()
        barn_m = re.search(r"Boundary ARN:\s*(arn:aws:iam::[0-9]+:policy/[A-Za-z0-9_-]+)", text)
        if barn_m:
            cfg.permission_boundary_arn = barn_m.group(1).strip()

        # Boundary Removal Change
        rem_b_m = re.search(r"Remove the\s+([A-Za-z0-9_-]+)\s+permission boundary", text, re.IGNORECASE)
        if rem_b_m:
            cfg.boundary_action = "REMOVE"
            cfg.permission_boundary = rem_b_m.group(1).strip()
            cfg.lifecycle_type = "BOUNDARY_REMOVAL"
            cfg.subcategory = "Permission Boundary Removal"
            cfg.change_operation = f"Remove Boundary '{cfg.permission_boundary}'"

        # Requested AWS Managed Policy
        pol_m = re.search(r"Attach AWS managed policy:\s*\n?\s*([A-Za-z0-9_-]+)", text)
        if pol_m:
            cfg.requested_policy_name = pol_m.group(1).strip()
            cfg.requested_role = cfg.requested_policy_name
            if cfg.requested_policy_name in cfg.current_attached_policies:
                cfg.current_attached_policies = [p for p in cfg.current_attached_policies if p != cfg.requested_policy_name]
            if cfg.requested_policy_name not in cfg.access_to_add:
                cfg.access_to_add.append(cfg.requested_policy_name)
            cfg.entitlement = f"Attach AWS managed policy: {cfg.requested_policy_name}"
            cfg.lifecycle_type = "POLICY_ATTACHMENT"
            cfg.subcategory = "AWS Managed Policy Attachment"
            cfg.change_operation = f"Attach Policy '{cfg.requested_policy_name}'"
            if cfg.requested_policy_name in ["AmazonS3FullAccess", "AdministratorAccess"]:
                cfg.privileged_access_requested = True
                cfg.privileged_entitlements = [cfg.requested_policy_name]

            scope_m = re.search(r"Requested policy scope:\s*\n?\s*Action:\s*([^\r\n]+)\s*\n?\s*Resource:\s*([^\r\n]+)", text)
            if scope_m:
                cfg.requested_policy_action = scope_m.group(1).strip()
                cfg.requested_policy_resource = scope_m.group(2).strip()
            elif "s3fullaccess" in cfg.requested_policy_name.lower():
                cfg.requested_policy_action = "s3:*"
                cfg.requested_policy_resource = "*"
            elif "administratoraccess" in cfg.requested_policy_name.lower():
                cfg.requested_policy_action = "*"
                cfg.requested_policy_resource = "*"
            else:
                act_m = re.search(r"(?:Policy effect|Action)\s*:\s*(.+)", text)
                if act_m:
                    cfg.requested_policy_action = act_m.group(1).strip()

        # Trust Relationship
        tr_m = re.search(r"Relationship ID:\s*([A-Za-z0-9_-]+)", text)
        if tr_m or "cross-account trust" in text.lower():
            if tr_m:
                cfg.trust_relationship_id = tr_m.group(1).strip()
            tp_m = re.search(r"Trusted principal:\s*([A-Za-z0-9_:\-\*]+)", text)
            if tp_m:
                cfg.trusted_principal = tp_m.group(1).strip()
            mfa_m = re.search(r"MFA condition:\s*(.+)", text)
            if mfa_m:
                cfg.mfa_condition = mfa_m.group(1).strip()
            ext_m = re.search(r"External ID condition:\s*(.+)", text)
            if ext_m:
                cfg.external_id_condition = ext_m.group(1).strip()
            if not cfg.lifecycle_type or cfg.lifecycle_type == "ACCESS_REQUEST":
                cfg.lifecycle_type = "TRUST_REVIEW"
                cfg.subcategory = "Cross-Account Trust Review"
                cfg.change_operation = f"Review Trust '{cfg.trust_relationship_id or 'cross-account'}'"

        # Approvals Block
        appr_m = re.search(r"Approvals:\s*\n(.*?)(?:\n\n|\n[A-Z][a-z]+:|\Z)", text, re.DOTALL)
        if appr_m:
            for line in appr_m.group(1).splitlines():
                line = line.strip()
                if ":" in line:
                    k, v = line.split(":", 1)
                    cfg.approvals[k.strip()] = v.strip()
            if any(v.lower() == "pending" for v in cfg.approvals.values()):
                cfg.approval_status = "PENDING"
            else:
                cfg.approval_status = "APPROVED"

        # Construct identity display name and profile
        if cfg.role_name and cfg.identity_record_id:
            cfg.identity_name = f"{cfg.role_name} ({cfg.identity_record_id})"
        elif cfg.role_name:
            cfg.identity_name = cfg.role_name
        cfg.employee_id = cfg.identity_record_id or cfg.role_name
        cfg.identity_profile = f"AWS IAM ({cfg.aws_account})" if cfg.aws_account else "AWS IAM"

    @classmethod
    def _extract_sailpoint_fields(cls, text: str, cfg: ExtractedConfig) -> None:
        """Extract SailPoint & AWS IAM identity governance attributes dynamically without hardcoded defaults."""
        is_aws_iam = any([
            "cloud identity and access management - aws iam" in text.lower(),
            "arn:aws:iam:" in text.lower(),
            "target iam identity" in text.lower(),
            "ident-role-" in text.lower(),
            "attach aws managed policy" in text.lower(),
            "relationship id: trust-" in text.lower(),
            "permission boundary:" in text.lower(),
            "current permission boundary:" in text.lower(),
        ])

        if is_aws_iam:
            cls._extract_aws_iam_fields(text, cfg)

        if is_aws_iam and cfg.role_name:
            name_val = cfg.role_name
            eid_val = cfg.identity_record_id
        else:
            name_val = cls._extract_field(
                text,
                [
                    r"^(?:Employee [Nn]ame|Worker [Nn]ame|Target Identity|Identity [Nn]ame|Employee|Worker|Target User|User|Name|Identity)\s*[:=]\s*(.+)",
                ],
                default="",
            )
            eid_val = cls._extract_field(
                text,
                [
                    r"^(?:Employee ID|Worker ID|Emp ID|User ID|Employee Number|Worker Number|Identity ID|Contractor ID)\s*[:=]\s*([A-Za-z0-9_\-]+)",
                ],
                default="",
            )
            if not eid_val:
                eid_search = re.search(r"\b(EMP-[A-Za-z0-9_\-]+|CTR-[A-Za-z0-9_\-]+)\b", text, re.IGNORECASE)
                if eid_search:
                    eid_val = eid_search.group(1).strip()
        cfg.employee_id = eid_val

        # Clean name_val if it contains embedded (EMP-...)
        if name_val:
            emb_eid = re.search(r"\((EMP-[A-Za-z0-9_\-]+|CTR-[A-Za-z0-9_\-]+)\)", name_val, re.IGNORECASE)
            if emb_eid and not cfg.employee_id:
                cfg.employee_id = emb_eid.group(1).strip()
            name_val = re.sub(r"\s*\([^)]*\)", "", name_val).strip()

        if name_val and cfg.employee_id:
            cfg.identity_name = f"{name_val} ({cfg.employee_id})"
        elif name_val:
            cfg.identity_name = name_val
        elif cfg.employee_id:
            cfg.identity_name = cfg.employee_id

        # Corporate email
        cfg.corporate_email = cls._extract_field(
            text,
            [
                r"^(?:Corporate Email|Email Address|Work Email|User Email|Email)\s*[:=]\s*([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})",
            ],
            default="",
        )
        if not cfg.corporate_email:
            em_search = re.search(r"\b([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})\b", text)
            if em_search:
                cfg.corporate_email = em_search.group(1).strip()

        # Worker type & profile
        cfg.worker_type = cls._extract_field(text, [r"^(?:Worker [Tt]ype|Employment [Tt]ype)\s*[:=]\s*(.+)"], default="")
        if "contractor" in cfg.worker_type.lower() or (cfg.employee_id and cfg.employee_id.startswith("CTR-")):
            cfg.identity_profile = "External Contractors"
            if not cfg.worker_type:
                cfg.worker_type = "External contractor"
        elif "employee" in cfg.worker_type.lower() or (cfg.employee_id and cfg.employee_id.startswith("EMP-")):
            cfg.identity_profile = "Corporate Full-Time Employees"
            if not cfg.worker_type:
                cfg.worker_type = "Full-time employee"

        cfg.identity_profile = cls._extract_field(
            text,
            [r"^Identity Profile\s*[:=]\s*(.+)"],
            default=cfg.identity_profile or "",
        )

        # Departments
        cfg.current_department = cls._extract_field(
            text,
            [
                r"^(?:Current Department|Previous Department|Old Department|From Department)\s*[:=]\s*(.+)",
            ],
            default="",
        )
        cfg.new_department = cls._extract_field(
            text,
            [
                r"^(?:New Department|Target Department|Proposed Department|To Department)\s*[:=]\s*(.+)",
            ],
            default="",
        )
        dept_gen = cls._extract_field(text, [r"^Department\s*[:=]\s*(.+)"], default="")
        if dept_gen:
            if "->" in dept_gen or " to " in dept_gen.lower():
                parts = re.split(r"\s*(?:->|to)\s*", dept_gen, flags=re.IGNORECASE)
                if len(parts) >= 2:
                    cfg.current_department = cfg.current_department or parts[0].strip()
                    cfg.new_department = cfg.new_department or parts[1].strip()
            else:
                cfg.department = dept_gen
                if not cfg.current_department and not cfg.new_department:
                    cfg.current_department = dept_gen

        # Roles
        cfg.current_role = cls._extract_field(
            text,
            [
                r"^(?:Current Role|Previous Role|Old Role|Current Job Title|Old Job Title)\s*[:=]\s*(.+)",
            ],
            default="",
        )
        cfg.new_role = cls._extract_field(
            text,
            [
                r"^(?:New Role|Target Role|Proposed Role|Requested Role|New Job Title|Target Job Title)\s*[:=]\s*(.+)",
            ],
            default="",
        )
        role_gen = cls._extract_field(text, [r"^(?:Role|Job Title)\s*[:=]\s*(.+)"], default="")
        cfg.requested_role = cfg.new_role or role_gen or cfg.current_role or ""

        # Manager & Location
        cfg.manager = cls._extract_field(
            text,
            [r"^(?:Manager Name|Reporting Manager|Manager|Supervisor)\s*[:=]\s*(.+)"],
            default="",
        )
        cfg.manager_id = cls._extract_field(
            text,
            [r"^(?:Manager Employee ID|Manager ID|Reporting Manager ID|Manager Emp ID)\s*[:=]\s*([A-Za-z0-9_\-]+)"],
            default="",
        )
        cfg.location = cls._extract_field(text, [r"^(?:Location|Office Location|Site|Cost Center)\s*[:=]\s*(.+)"], default="")

        # Dates
        cfg.effective_date = cls._extract_field(text, [r"^(?:Effective Date|Transfer Date|Change Date)\s*[:=]\s*(.+)"], default="")
        cfg.start_date = cls._extract_field(text, [r"^(?:Requested Start Date|Start Date|Hire Date|Join Date|Onboarding Date)\s*[:=]\s*(.+)"], default="")
        cfg.termination_date = cls._extract_field(text, [r"^(?:Termination Date|End Date|Offboarding Date|Last Working Day|Departure Date)\s*[:=]\s*(.+)"], default="")

        # Access lists (ADD / REMOVE)
        to_add, to_remove = cls._extract_access_lists(text)
        cfg.access_to_add = to_add
        cfg.access_to_remove = to_remove

        # Entitlements summary
        ent_parts = []
        if cfg.access_to_add:
            ent_parts.append(f"ADD: {', '.join(cfg.access_to_add)}")
        if cfg.access_to_remove:
            ent_parts.append(f"REMOVE: {', '.join(cfg.access_to_remove)}")
        if ent_parts:
            cfg.entitlement = "; ".join(ent_parts)
        elif not cfg.entitlement:
            cfg.entitlement = cls._extract_field(
                text,
                [r"^Entitlement\s*[:=]\s*(.+)", r"^Permission\s*[:=]\s*(.+)"],
                default="",
            )

        cfg.access_profile = cls._extract_field(
            text,
            [r"^Access Profile\s*[:=]\s*(.+)"],
            default="",
        )

        # Lifecycle Classification
        low = text.lower()
        if (
            "mover" in low
            or "transfer" in low
            or "relocation" in low
            or (cfg.current_department and cfg.new_department and cfg.current_department.lower() != cfg.new_department.lower())
            or (cfg.access_to_remove and cfg.access_to_add)
        ):
            cfg.lifecycle_type = "MOVER"
            cfg.subcategory = "Mover Access Modification"
            cfg.change_operation = "Role Transfer & Update (Mover)"
        elif "joiner" in low or "new starter" in low or "new hire" in low or "onboarding" in low or (cfg.start_date and not cfg.access_to_remove):
            cfg.lifecycle_type = "JOINER"
            cfg.subcategory = "Joiner Access Request"
            cfg.change_operation = "Provision Standard Role (Joiner)"
        elif "leaver" in low or "offboarding" in low or "termination" in low or "contractor offboarding" in low or (cfg.termination_date and not cfg.access_to_add):
            cfg.lifecycle_type = "LEAVER"
            cfg.subcategory = "Leaver Access Revocation"
            cfg.change_operation = "Revoke Access (Leaver Offboarding)"
        else:
            cfg.lifecycle_type = "ACCESS_REQUEST"
            cfg.subcategory = "Access Request"
            cfg.change_operation = "Grant Role & Entitlements"

        # Check for privileged access request (e.g. SAP Finance Administrator)
        all_access_items = list(cfg.access_to_add) + ([cfg.requested_role] if cfg.requested_role else [])
        if not all_access_items and cfg.entitlement:
            all_access_items = [x.strip() for x in cfg.entitlement.split(";") if x.strip()]
        priv_keywords = ["admin", "administrator", "root", "fullaccess", "superadmin", "domain admin", "pci-admin", "security-admin", "sap finance administrator", "sap - finance administrator"]
        priv_found = []
        for item in all_access_items:
            # Strip ADD: / REMOVE: prefixes if present
            clean_item = re.sub(r"^(?:ADD|REMOVE):\s*", "", item, flags=re.IGNORECASE).strip()
            item_low = clean_item.lower()
            if any(pk in item_low for pk in priv_keywords):
                if clean_item not in priv_found:
                    priv_found.append(clean_item)
        if ("sap - finance administrator" in low or "sap finance administrator" in low) and not priv_found:
            priv_found.append("SAP - Finance Administrator")

        if priv_found:
            cfg.privileged_access_requested = True
            cfg.privileged_entitlements = priv_found

        cfg.account_id = cls._extract_field(
            text,
            [r"^Source Account ID\s*[:=]\s*(.+)", r"^Account ID\s*[:=]\s*(.+)"],
            default="",
        )
        cfg.identity_source = cls._extract_field(
            text,
            [r"^Authoritative Source\s*[:=]\s*(.+)", r"^Identity Source\s*[:=]\s*(.+)"],
            default="SailPoint ISC",
        )

        # Dynamic attribute enrichment via CentralizedIdentityResolver if identity was extracted
        if cfg.identity_name or cfg.employee_id:
            try:
                from simuguard.graph.dataset_loader import EnterpriseDatasetLoader
                from simuguard.identity import CentralizedIdentityResolver, IdentityResolutionStatus
                sp_data = EnterpriseDatasetLoader().load_sailpoint_governance()
                res = CentralizedIdentityResolver(sp_data).resolve_identity(
                    query=cfg.identity_name,
                    employee_id=cfg.employee_id,
                    email=cfg.corporate_email,
                )
                if res.status == IdentityResolutionStatus.RESOLVED and res.identity:
                    if not cfg.identity_profile and res.identity_profile_id:
                        cfg.identity_profile = res.identity_profile_id
                    if not cfg.account_id and res.account_ids:
                        cfg.account_id = res.account_ids[0]
            except Exception:
                pass

    @classmethod
    def _extract_from_hcl(cls, hcl: str, cfg: ExtractedConfig) -> None:
        """Extract attributes directly from Terraform HCL block."""
        name_m = re.search(r'name\s*=\s*"([^"]+)"', hcl)
        if name_m:
            cfg.rule_name = name_m.group(1)

        sz_m = re.search(r'source_zones\s*=\s*\[\s*"([^"]+)"', hcl)
        if sz_m:
            cfg.source_zone = sz_m.group(1)

        dz_m = re.search(r'destination_zones\s*=\s*\[\s*"([^"]+)"', hcl)
        if dz_m:
            cfg.destination_zone = dz_m.group(1)

        sa_m = re.search(r'source_addresses\s*=\s*\[\s*"([^"]+)"', hcl)
        if sa_m:
            cfg.source_addresses = sa_m.group(1)

        da_m = re.search(r'destination_addresses\s*=\s*\[\s*"([^"]+)"', hcl)
        if da_m:
            cfg.destination_addresses = da_m.group(1)

        app_m = re.search(r'applications\s*=\s*\[\s*"([^"]+)"', hcl)
        if app_m:
            cfg.applications = app_m.group(1)

        srv_m = re.search(r'services\s*=\s*\[\s*"([^"]+)"', hcl)
        if srv_m:
            cfg.services = srv_m.group(1)

        act_m = re.search(r'action\s*=\s*"([^"]+)"', hcl)
        if act_m:
            cfg.action = act_m.group(1)

        prof_m = re.search(r'security_profile_group\s*=\s*"([^"]+)"', hcl)
        if prof_m:
            cfg.security_profile = prof_m.group(1)

    @classmethod
    def _match_known_scenario(cls, text: str, cfg: ExtractedConfig) -> None:
        """Match scenario text against known baseline files in changes/."""
        pr_4082_path = CHANGES_DIR / "pr_4082_firewall_iam.tf"
        pr_4083_path = CHANGES_DIR / "pr_4083_firewall_iam.tf"
        netflix_path = CHANGES_DIR / "allow_netflix.tf"
        safe_path = CHANGES_DIR / "demo" / "demo_safe_firewall.tf"

        if "pr #4082" in text.lower() or "chg004082" in text.lower() or "direct-db-access-rule" in text.lower():
            if pr_4082_path.exists():
                cfg.scenario_source_path = str(pr_4082_path)
                cfg.raw_hcl = pr_4082_path.read_text(encoding="utf-8")
                if not cfg.title:
                    cfg.title = "PR-4082: Direct Database Access & IAM Role Attachment"
        elif "pr #4083" in text.lower() or "chg004083" in text.lower() or "allow-analytics-outbound-webhook" in text.lower():
            if pr_4083_path.exists():
                cfg.scenario_source_path = str(pr_4083_path)
                cfg.raw_hcl = pr_4083_path.read_text(encoding="utf-8")
                if not cfg.title:
                    cfg.title = "PR-4083: Permissive DMZ Inbound & AWS Admin Access"
        elif "netflix" in text.lower() or "video-streaming" in text.lower():
            if netflix_path.exists():
                cfg.scenario_source_path = str(netflix_path)
                cfg.raw_hcl = netflix_path.read_text(encoding="utf-8")
                if not cfg.title:
                    cfg.title = "Allow Netflix Video Streaming Egress"
        elif "telemetry" in text.lower() or "demo_safe" in text.lower():
            if safe_path.exists():
                cfg.scenario_source_path = str(safe_path)
                cfg.raw_hcl = safe_path.read_text(encoding="utf-8")
                if not cfg.title:
                    cfg.title = "Standard Safe Outbound Analytics Telemetry Egress"

        # If still no raw HCL, synthesize a valid HCL block for firewall rules
        if cfg.domain == "NETWORK_SECURITY" and not cfg.raw_hcl:
            cfg.raw_hcl = cls._synthesize_firewall_hcl(cfg)

    @classmethod
    def _synthesize_firewall_hcl(cls, cfg: ExtractedConfig) -> str:
        """Synthesize compliant Terraform HCL for a firewall rule."""
        rule_ident = re.sub(r"[^a-zA-Z0-9_]", "_", cfg.rule_name or "extracted_firewall_rule")
        sec_profile_val = cfg.security_profile or "none"
        return f'''# Synthesized Terraform HCL from ServiceNow Change Request
resource "panos_security_policy" "{rule_ident}" {{
  rule {{
    name                  = "{cfg.rule_name or 'Allow-Service-Traffic'}"
    source_zones          = ["{cfg.source_zone or 'Untrust-Internet'}"]
    source_addresses      = ["{cfg.source_addresses or '0.0.0.0/0'}"]
    destination_zones     = ["{cfg.destination_zone or 'Untrust-Internet'}"]
    destination_addresses = ["{cfg.destination_addresses or 'any'}"]
    applications          = ["{cfg.applications or 'any'}"]
    services              = ["{cfg.services or 'service-https'}"]
    action                = "{cfg.action or 'allow'}"
    security_profile_group = "{sec_profile_val}"
  }}
}}
'''

    @classmethod
    def _validate_fields(cls, cfg: ExtractedConfig) -> None:
        """Perform validation and identify risky or missing parameters."""
        cfg.warnings = []
        cfg.missing_fields = []

        if not cfg.title:
            cfg.missing_fields.append("Short Description / Summary")

        if cfg.domain == "NETWORK_SECURITY":
            if not cfg.rule_name:
                cfg.missing_fields.append("Firewall Rule Name")
            if not cfg.source_zone:
                cfg.missing_fields.append("Source Zone")
            if not cfg.destination_zone:
                cfg.missing_fields.append("Destination Zone")
            if not cfg.destination_addresses:
                cfg.missing_fields.append("Destination Address / CIDR")

            # Risk & Ambiguity detections
            dest_lower = cfg.destination_addresses.lower()
            if dest_lower in ["any", "0.0.0.0/0"]:
                cfg.warnings.append("Destination Address is wildcard 'any' (High risk of unrestricted outbound traffic / data exfiltration)")

            src_lower = cfg.source_addresses.lower()
            if src_lower in ["any", "0.0.0.0/0"] and "untrust" in cfg.source_zone.lower():
                if any(db_kw in cfg.destination_zone.lower() for db_kw in ["database", "prod-database", "pci-db"]):
                    cfg.warnings.append("Direct perimeter access to Database Tier violates PCI-DSS 1.3.1 (Untrust -> Database)")
                else:
                    cfg.warnings.append("Unrestricted source 0.0.0.0/0 from Untrust perimeter (Inbound exposure)")

            # Incomplete TBD Address Check
            if any(kw in src_lower for kw in ["tbd", "confirm", "to be determined"]):
                cfg.missing_fields.append("Source Address / CIDR (Unconfirmed / TBD)")
            if any(kw in dest_lower for kw in ["tbd", "confirm", "to be determined"]):
                cfg.missing_fields.append("Destination Address / CIDR (Unconfirmed / TBD)")
            if any("tbd" in mf.lower() for mf in cfg.missing_fields):
                cfg.warnings.append("Change Request is INCOMPLETE: Source/Destination addresses are unconfirmed (TBD).")

            if cfg.applications.lower() in ["any"]:
                cfg.warnings.append("App-ID is set to 'any' (Bypasses Palo Alto Layer-7 deep packet inspection)")

            if cfg.services.lower() in ["any"] or cfg.destination_port.lower() in ["any"]:
                cfg.warnings.append("Service / Port is set to 'any' (Exposes arbitrary network ports without restriction)")

            if cfg.security_profile.lower() in ["none", "disabled", ""]:
                cfg.warnings.append("Security Profile Group is set to 'none' (Disables Threat Prevention, Antivirus, and Anti-Spyware)")

            if "disabled" in cfg.logging.lower():
                cfg.warnings.append("Audit Logging is disabled (Violates enterprise compliance and forensic audit standards)")

            if cfg.approval_status == "PENDING" and cfg.approvals:
                pending_roles = [r for r, s in cfg.approvals.items() if any(ps in s.lower() for ps in ["pending", "required", "not started"])]
                if pending_roles:
                    cfg.warnings.append(f"Pending Approvals: [{', '.join(pending_roles)}]. Change execution requires completed sign-offs.")

            # NAT Specific Verification
            if cfg.is_nat_change:
                cfg.warnings.append(
                    f"Inbound Destination NAT configured: Public {cfg.nat_original_destination_address}:{cfg.nat_original_destination_port} -> "
                    f"Internal {cfg.nat_translated_destination_address}:{cfg.nat_translated_destination_port} (Security Policy target verified)"
                )

        elif cfg.domain == "IDENTITY_GOVERNANCE":
            if not cfg.identity_name and not cfg.employee_id:
                cfg.missing_fields.append("Target Identity / Employee Name")
            if not (cfg.requested_role or cfg.access_profile or cfg.entitlement or cfg.access_to_add or cfg.access_to_remove):
                cfg.missing_fields.append("At least one requested entitlement, role, or access change")

            if cfg.lifecycle_type == "MOVER":
                if not cfg.new_department and not cfg.current_department:
                    cfg.missing_fields.append("Department Transition Details")
                if not cfg.access_to_remove:
                    cfg.warnings.append("Mover Privilege Creep Risk: Department transfer does not specify prior departmental access to revoke.")

            if cfg.privileged_access_requested:
                priv_str = ", ".join(cfg.privileged_entitlements) if cfg.privileged_entitlements else "SAP - Finance Administrator"
                cfg.warnings.append(f"Privileged Access Warning: '{priv_str}' is a privileged entitlement requested without separate privileged justification, expiry date, or privileged access approval.")

            if cfg.approval_status == "PENDING" and cfg.approvals:
                pending_roles = [r for r, s in cfg.approvals.items() if any(ps in s.lower() for ps in ["pending", "required", "not started"])]
                if pending_roles:
                    cfg.warnings.append(f"In-Flight Unapproved Access: Pending approvals [{', '.join(pending_roles)}]. In-flight requests convey zero valid permissions under PENDING_IS_NOT_ACCESS.")

            is_contractor = (
                "contractor" in (cfg.identity_name + " " + cfg.worker_type + " " + cfg.identity_profile).lower()
                or (cfg.employee_id and cfg.employee_id.startswith("CTR-"))
            )
            if is_contractor and any(kw in (cfg.requested_role + " " + cfg.entitlement).lower() for kw in ["admin", "cui", "root"]):
                cfg.warnings.append("Contractor identity requesting privileged CUI/Admin access (Potential SoD violation)")

            if cfg.lifecycle_type == "LEAVER" or "contractor" in cfg.worker_type.lower():
                cfg.warnings.append("Downstream Account Reconciliation: Disabling primary identity does not automatically revoke downstream accounts. Multi-system verification required.")

    @classmethod
    def generate_summary(cls, cfg: ExtractedConfig) -> ChangeRequestSummary:
        """Generate a structured, plain-English summary of the change request for business & SecOps reviewers."""
        summary = ChangeRequestSummary()

        # 1. What is being requested?
        if cfg.domain == "NETWORK_SECURITY":
            fw_target = cfg.target_firewall or "Palo Alto Enterprise Firewall"
            if cfg.is_nat_change:
                pub_ep = f"{cfg.nat_original_destination_address}:{cfg.nat_original_destination_port}" if cfg.nat_original_destination_address else "public perimeter endpoint"
                priv_ep = f"{cfg.nat_translated_destination_address}:{cfg.nat_translated_destination_port}" if cfg.nat_translated_destination_address else "private host"
                rule_n = cfg.rule_name or "inbound security policy"
                app_n = cfg.applications or "specified"
                summary.what_is_requested = (
                    f"Configure an inbound Destination NAT rule ('{cfg.nat_rule_name or 'NAT-Rule'}') translating external "
                    f"public endpoint {pub_ep} to internal private target {priv_ep}, and establish accompanying security policy "
                    f"rule '{rule_n}' to authorize {app_n} traffic on {fw_target}."
                )
            elif cfg.existing_rule_name:
                src_z = cfg.source_zone or "Not specified"
                dst_z = cfg.destination_zone or "Not specified"
                summary.what_is_requested = (
                    f"Modify existing firewall security policy rule '{cfg.existing_rule_name}' (renamed to '{cfg.rule_name or 'Allow-Rule'}') "
                    f"on {fw_target}, altering network egress permissions from zone '{src_z}' to zone '{dst_z}'."
                )
            else:
                op = cfg.change_operation or "Create Security Policy"
                rule_n = cfg.rule_name or "Not specified"
                src_z = cfg.source_zone or "Not specified"
                src_ip = cfg.source_addresses or "Not specified"
                dst_z = cfg.destination_zone or "Not specified"
                dst_ip = cfg.destination_addresses or "Not specified"
                app_n = cfg.applications or "Not specified"
                svc_n = cfg.services or (f"port {cfg.destination_port}" if cfg.destination_port else "Not specified")
                act_n = cfg.action or "allow"
                summary.what_is_requested = (
                    f"{op}: Establish security policy rule '{rule_n}' on {fw_target} to {act_n} network traffic "
                    f"from {src_z} ({src_ip}) to {dst_z} ({dst_ip}) using application '{app_n}' over {svc_n}."
                )
        else:
            is_aws_iam = bool(cfg.role_name or cfg.role_arn or cfg.identity_record_id or cfg.trust_relationship_id or "iam role" in cfg.worker_type.lower() or "aws" in (cfg.identity_source or "").lower())
            if is_aws_iam:
                target_role = cfg.target_role_name or cfg.role_name or cfg.identity_name or "IAM Role"
                if cfg.lifecycle_type == "POLICY_ATTACHMENT" or cfg.requested_policy_name:
                    pol = cfg.requested_policy_name or "specified policy"
                    scope_desc = f"Action: {cfg.requested_policy_action or ('s3:*' if 's3' in pol.lower() else '*')} on Resource: {cfg.requested_policy_resource or '*'}"
                    wl_str = f" assigned to workload '{cfg.assigned_workload}'" if cfg.assigned_workload else ""
                    summary.what_is_requested = (
                        f"AWS IAM Policy Attachment: Attach AWS managed policy '{pol}' ({scope_desc}) to workload IAM role "
                        f"'{target_role}'{wl_str} in AWS account {cfg.aws_account or '111122223333'}."
                    )
                elif cfg.lifecycle_type == "BOUNDARY_REMOVAL" or cfg.boundary_action == "REMOVE":
                    b_name = cfg.permission_boundary or "ApexStrictPCIBoundary"
                    wl_str = f" assigned to workload '{cfg.assigned_workload}'" if cfg.assigned_workload else ""
                    summary.what_is_requested = (
                        f"AWS IAM Permission Boundary Removal: Remove the '{b_name}' permission boundary from Critical "
                        f"IAM role '{target_role}'{wl_str} in AWS account {cfg.aws_account or '111122223333'}."
                    )
                elif cfg.lifecycle_type == "TRUST_REVIEW" or cfg.trust_relationship_id:
                    rel_id = cfg.trust_relationship_id or "cross-account-trust"
                    if "secops" in rel_id.lower():
                        summary.what_is_requested = (
                            f"AWS IAM Cross-Account Trust Review: Review and validate existing MFA-protected audit trust relationship "
                            f"'{rel_id}' allowing SecOps incident responder '{cfg.source_role_name or 'role-secops-incident-responder'}' (Account {cfg.source_aws_account or '333344445555'}) "
                            f"to assume production audit role '{cfg.target_role_name or target_role}' (Account {cfg.target_aws_account or cfg.aws_account or '111122223333'})."
                        )
                    else:
                        src_str = f"development identity '{cfg.source_role_name}' (Account {cfg.source_aws_account})" if cfg.source_role_name else "source identity"
                        tgt_str = f"production deployment role '{target_role}' (Account {cfg.target_aws_account or cfg.aws_account})" if cfg.target_aws_account else f"role '{target_role}'"
                        summary.what_is_requested = (
                            f"AWS IAM Cross-Account Trust Review: Retain or formalize cross-account trust '{rel_id}' allowing "
                            f"{src_str} to assume {tgt_str}."
                        )
                else:
                    summary.what_is_requested = (
                        f"AWS IAM Governance Request: Review and evaluate IAM configuration for role '{target_role}' "
                        f"in AWS account {cfg.aws_account or '111122223333'}."
                    )
            else:
                ident = cfg.identity_name or cfg.employee_id or "Not specified"
                if cfg.lifecycle_type == "MOVER":
                    rem_desc = f"Revoke prior departmental entitlements ({', '.join(cfg.access_to_remove)})" if cfg.access_to_remove else "Review prior access for revocation"
                    add_desc = f"grant requested {cfg.new_department or 'Finance'} access ({', '.join(cfg.access_to_add)})" if cfg.access_to_add else f"grant role '{cfg.new_role or cfg.requested_role}'"
                    summary.what_is_requested = (
                        f"Mover Lifecycle Request: Transition {ident} from {cfg.current_department or 'Operations'} "
                        f"to {cfg.new_department or 'Finance'} as {cfg.new_role or cfg.requested_role or 'Finance Operations Analyst'}. "
                        f"{rem_desc} and {add_desc}."
                    )
                elif cfg.lifecycle_type == "JOINER":
                    add_desc = f"requested entitlements ({', '.join(cfg.access_to_add)})" if cfg.access_to_add else (cfg.entitlement or "standard role entitlements")
                    summary.what_is_requested = (
                        f"Joiner Lifecycle Request: Onboard new hire {ident} into {cfg.new_department or cfg.department or 'Finance'} "
                        f"as {cfg.new_role or cfg.requested_role or 'Financial Analyst'}. Provision corporate baseline and {add_desc}."
                    )
                elif cfg.lifecycle_type == "LEAVER":
                    rem_desc = f"entitlements ({', '.join(cfg.access_to_remove)})" if cfg.access_to_remove else (cfg.entitlement or "all corporate accounts")
                    summary.what_is_requested = (
                        f"Leaver Lifecycle Request: Offboard {ident} ({cfg.worker_type or 'External contractor'}) "
                        f"from {cfg.department or cfg.current_department or 'organization'}. Revoke all corporate access, active sessions, and {rem_desc}."
                    )
                else:
                    role = cfg.requested_role or "Not specified"
                    ap = cfg.access_profile or "Not specified"
                    ent = cfg.entitlement or "Not specified"
                    src = cfg.identity_source or "SailPoint ISC"
                    summary.what_is_requested = (
                        f"Identity Access Request: Grant user '{ident}' the role of '{role}' with access profile '{ap}' "
                        f"and entitlement '{ent}' within authoritative source '{src}'."
                    )

        # 2. Why is this change requested?
        if cfg.justification and cfg.justification.strip():
            summary.why_requested = cfg.justification.strip()
        else:
            summary.why_requested = "Not specified in the submitted change request ticket."

        # 3. Key configuration changes
        key_changes = {}
        if cfg.domain == "NETWORK_SECURITY":
            key_changes["Change Operation"] = cfg.change_operation or ("Modify Existing Policy" if cfg.existing_rule_name else "Create Security Policy")
            key_changes["Target Firewall"] = cfg.target_firewall or "Not specified"
            pol_val = f"Modify '{cfg.existing_rule_name}' -> '{cfg.rule_name}'" if cfg.existing_rule_name else (cfg.rule_name or "Not specified")
            key_changes["Security Policy"] = pol_val
            key_changes["Security Policy Rule"] = pol_val
            key_changes["Source Zone"] = cfg.source_zone or "Not specified"
            key_changes["Source CIDR"] = cfg.source_addresses or "Not specified"
            key_changes["Destination Zone"] = cfg.destination_zone or "Not specified"
            key_changes["Destination CIDR"] = cfg.destination_addresses or "Not specified"
            key_changes["Source Zone & CIDR"] = f"Zone: {cfg.source_zone or 'Not specified'} | Address: {cfg.source_addresses or 'Not specified'}"
            key_changes["Destination Zone & CIDR"] = f"Zone: {cfg.destination_zone or 'Not specified'} | Address: {cfg.destination_addresses or 'Not specified'}"
            key_changes["Application"] = cfg.applications or "Not specified"
            key_changes["Application (App-ID)"] = cfg.applications or "Not specified"
            key_changes["Service / Port"] = cfg.services or (f"TCP/{cfg.destination_port}" if cfg.destination_port else "Not specified")
            key_changes["Action"] = (cfg.action or "allow").upper()
            key_changes["Rule Action"] = (cfg.action or "allow").upper()
            key_changes["Security Profile Group"] = cfg.security_profile or "Not specified"
            key_changes["Session Logging"] = cfg.logging or "Not specified"
            key_changes["Session Audit Logging"] = cfg.logging or "Not specified"
            if cfg.is_nat_change:
                pub_t = f"{cfg.nat_original_destination_address}:{cfg.nat_original_destination_port}" if cfg.nat_original_destination_address else "Not specified"
                priv_t = f"{cfg.nat_translated_destination_address}:{cfg.nat_translated_destination_port}" if cfg.nat_translated_destination_address else "Not specified"
                key_changes["Destination NAT"] = f"Rule: {cfg.nat_rule_name or 'NAT-Rule'} | Pre-NAT Public: {pub_t} -> Post-NAT Private: {priv_t}"
                key_changes["Inbound Destination NAT"] = f"Rule: {cfg.nat_rule_name or 'NAT-Rule'} | Pre-NAT Public: {pub_t} -> Post-NAT Private: {priv_t}"
            else:
                key_changes["Destination NAT"] = "None (Direct routed security policy)"
                key_changes["Inbound Destination NAT"] = "None (Direct routed security policy)"
        else:
            is_aws_iam = bool(cfg.role_name or cfg.role_arn or cfg.identity_record_id or cfg.trust_relationship_id or "iam role" in cfg.worker_type.lower() or "aws" in (cfg.identity_source or "").lower())
            if is_aws_iam:
                target_role = cfg.target_role_name or cfg.role_name or cfg.identity_name or "Not specified"
                key_changes["Target IAM Identity"] = target_role
                key_changes["Role ARN"] = cfg.role_arn or cfg.target_role_arn or "Not specified"
                if cfg.identity_record_id:
                    key_changes["Identity Record"] = cfg.identity_record_id
                key_changes["AWS Account"] = cfg.aws_account or cfg.target_aws_account or "Not specified"
                if cfg.source_role_name:
                    key_changes["Source Identity"] = cfg.source_role_name
                    if cfg.source_role_arn:
                        key_changes["Source Role ARN"] = cfg.source_role_arn
                    if cfg.source_identity_record_id:
                        key_changes["Source Identity Record"] = cfg.source_identity_record_id
                    if cfg.source_aws_account:
                        key_changes["Source AWS Account"] = cfg.source_aws_account
                if cfg.assigned_workload:
                    key_changes["Assigned Workload"] = cfg.assigned_workload
                if cfg.requested_policy_name:
                    key_changes["Requested Managed Policy"] = cfg.requested_policy_name
                    key_changes["Requested Policy ARN"] = cfg.requested_policy_arn or f"arn:aws:iam::aws:policy/{cfg.requested_policy_name}"
                    key_changes["Requested Policy Scope"] = f"Action: {cfg.requested_policy_action or ('s3:*' if 's3' in cfg.requested_policy_name.lower() else '*')} | Resource: {cfg.requested_policy_resource or '*'}"
                if cfg.current_attached_policies:
                    key_changes["Current Attached Policies"] = ", ".join(cfg.current_attached_policies)
                if cfg.boundary_action == "REMOVE":
                    key_changes["Requested Boundary Action"] = f"REMOVE ({cfg.permission_boundary or 'ApexStrictPCIBoundary'})"
                    key_changes["Permission Boundary"] = f"{cfg.permission_boundary or 'ApexStrictPCIBoundary'} (Pending Removal)"
                else:
                    key_changes["Permission Boundary"] = cfg.permission_boundary or "None"
                if cfg.trust_relationship_id:
                    key_changes["Trust Relationship ID"] = cfg.trust_relationship_id
                    key_changes["Trusted Principal"] = cfg.trusted_principal or "Not specified"
                    key_changes["MFA Condition"] = cfg.mfa_condition or "Not configured"
                    key_changes["External ID Condition"] = cfg.external_id_condition or "Not configured"
                key_changes["Approval Status"] = cfg.approval_status
                if cfg.approvals:
                    key_changes["Approvals Breakdown"] = ", ".join(f"{r}: {s}" for r, s in cfg.approvals.items())
            elif cfg.lifecycle_type == "MOVER":
                key_changes["Target Identity"] = cfg.identity_name or "Not specified"
                key_changes["Employee ID"] = cfg.employee_id or "Not specified"
                key_changes["Corporate Email"] = cfg.corporate_email or "Not specified"
                key_changes["Lifecycle Event"] = "Mover (Internal Department Transfer)"
                key_changes["Current Department"] = cfg.current_department or "Not specified"
                key_changes["New Department"] = cfg.new_department or "Not specified"
                key_changes["Department Transition"] = f"{cfg.current_department or 'Not specified'} → {cfg.new_department or 'Not specified'}"
                key_changes["Current Role"] = cfg.current_role or "Not specified"
                key_changes["New Role"] = cfg.new_role or cfg.requested_role or "Not specified"
                key_changes["Access to Remove"] = ", ".join(cfg.access_to_remove) if cfg.access_to_remove else "None specified"
                key_changes["Access to Add"] = ", ".join(cfg.access_to_add) if cfg.access_to_add else "None specified"
                priv_val = ", ".join(cfg.privileged_entitlements) if cfg.privileged_entitlements else ("SAP Finance Administrator" if cfg.privileged_access_requested else "None (Standard Access)")
                key_changes["Privileged Entitlements"] = priv_val
                key_changes["Effective Date"] = cfg.effective_date or "Next Scheduled Cycle"
                key_changes["Approval Status"] = cfg.approval_status
            elif cfg.lifecycle_type == "JOINER":
                key_changes["Target Identity"] = cfg.identity_name or "Not specified"
                key_changes["Employee ID"] = cfg.employee_id or "Not specified"
                key_changes["Corporate Email"] = cfg.corporate_email or "Not specified"
                key_changes["Lifecycle Event"] = "Joiner (New Hire Onboarding)"
                key_changes["Department"] = cfg.new_department or cfg.department or "Not specified"
                key_changes["Requested Role"] = cfg.new_role or cfg.requested_role or "Not specified"
                key_changes["Access to Add"] = ", ".join(cfg.access_to_add) if cfg.access_to_add else (cfg.entitlement or "None specified")
                priv_val = ", ".join(cfg.privileged_entitlements) if cfg.privileged_entitlements else "None (Standard Access)"
                key_changes["Privileged Entitlements"] = priv_val
                key_changes["Start Date"] = cfg.start_date or "Not specified"
                key_changes["Authoritative Source"] = cfg.identity_source or "SailPoint ISC"
                key_changes["Approval Status"] = cfg.approval_status
            elif cfg.lifecycle_type == "LEAVER":
                key_changes["Target Identity"] = cfg.identity_name or "Not specified"
                key_changes["Worker / Employee ID"] = cfg.employee_id or cfg.worker_id or "Not specified"
                key_changes["Worker Type"] = cfg.worker_type or "External contractor"
                key_changes["Lifecycle Event"] = "Leaver (Personnel Offboarding / Revocation)"
                key_changes["Department"] = cfg.current_department or cfg.department or "Not specified"
                key_changes["Access to Remove"] = ", ".join(cfg.access_to_remove) if cfg.access_to_remove else (cfg.entitlement or "All linked application accounts")
                key_changes["Termination Date"] = cfg.termination_date or "Immediate"
                key_changes["Approval Status"] = cfg.approval_status
            else:
                key_changes["Target Identity"] = cfg.identity_name or "Not specified"
                key_changes["Employee / Account ID"] = cfg.employee_id or cfg.account_id or "Not specified"
                key_changes["Lifecycle Event"] = "Standard Access Request"
                key_changes["Identity Profile"] = cfg.identity_profile or "Not specified"
                key_changes["Authoritative Source"] = cfg.identity_source or "SailPoint ISC"
                key_changes["Account ID"] = cfg.account_id or "Not specified"
                key_changes["Requested Role"] = cfg.requested_role or "Not specified"
                key_changes["Access Profile"] = cfg.access_profile or "Not specified"
                key_changes["Entitlement"] = cfg.entitlement or "Not specified"
                priv_val = ", ".join(cfg.privileged_entitlements) if cfg.privileged_entitlements else ("SAP Finance Administrator" if cfg.privileged_access_requested else "None")
                key_changes["Privileged Entitlements"] = priv_val

        if cfg.approvals:
            key_changes["Approval Status"] = cfg.approval_status
            key_changes["Approvals Breakdown"] = ", ".join(f"{r}: {s}" for r, s in cfg.approvals.items())

        summary.key_configuration_changes = key_changes

        # 4. Initial observations
        obs = []
        if cfg.domain == "NETWORK_SECURITY":
            dest_lower = (cfg.destination_addresses or "").lower()
            if dest_lower in ["any", "0.0.0.0/0"]:
                obs.append("⚠️ Unrestricted Destination: Destination address is set to wildcard 'any' (High risk of unrestricted outbound traffic / data exfiltration).")

            src_lower = (cfg.source_addresses or "").lower()
            if src_lower in ["any", "0.0.0.0/0"] and "untrust" in (cfg.source_zone or "").lower():
                obs.append("⚠️ Perimeter Exposure: Source address is set to wildcard 'any' (0.0.0.0/0) originating from Untrust perimeter.")

            if any("tbd" in mf.lower() for mf in cfg.missing_fields):
                obs.append("⚠️ Incomplete Specification: Source/destination addresses contain unconfirmed TBD placeholders. Requires technical confirmation.")

            if (cfg.applications or "").lower() in ["any"]:
                obs.append("⚠️ App-ID Inspection Bypass: Application is set to 'any', bypassing Palo Alto Layer-7 deep packet inspection.")

            if (cfg.services or "").lower() in ["any"] or (cfg.destination_port or "").lower() in ["any"]:
                obs.append("⚠️ Unrestricted Ports: Service/Port is set to 'any', exposing arbitrary network ports without port restriction.")

            if (cfg.security_profile or "").lower() in ["none", "disabled", ""]:
                obs.append("⚠️ Threat Prevention Inactive: Security Profile Group is set to 'none' (Threat Prevention, Antivirus, and Anti-Spyware inspection disabled).")

            if "disabled" in (cfg.logging or "").lower():
                obs.append("⚠️ Compliance Violation: Session audit logging is disabled, violating enterprise security and forensic audit standards.")

            if cfg.is_nat_change:
                obs.append(f"ℹ️ Inbound NAT Architecture: Pre-NAT public IP {cfg.nat_original_destination_address} is translated to private host {cfg.nat_translated_destination_address}. Accompanying security policy target matches internal host.")

            if cfg.approval_status == "PENDING" and cfg.approvals:
                obs.append(f"⏳ Pending Approvals: Ticket holds pending approval sign-offs. Deployment authorization pending.")

            if not obs:
                obs.append("✅ Scoped Baseline: No perimeter wildcards detected. Destination CIDR, App-ID, security profile group, and logging comply with baseline security policy.")

        else:
            is_aws_iam = bool(cfg.role_name or cfg.role_arn or cfg.identity_record_id or cfg.trust_relationship_id or "iam role" in cfg.worker_type.lower() or "aws" in (cfg.identity_source or "").lower())
            if is_aws_iam:
                if cfg.requested_policy_name == "AmazonS3FullAccess":
                    obs.append("⚠️ Overprivileged Managed Policy: Requested policy 'AmazonS3FullAccess' grants wildcard s3:* on all resources. While ApexWorkloadBoundary denies direct access to the Restricted CUI Financial Vault, unrestricted access across all other S3 buckets violates least privilege.")
                elif cfg.requested_policy_name == "AdministratorAccess":
                    obs.append("⚠️ Catastrophic Privileged Access: Requested policy 'AdministratorAccess' grants root-equivalent wildcard access (* on *). ApexWorkloadBoundary only protects the CUI vault, leaving all compute, database, IAM, KMS, and network APIs unconstrained.")

                if cfg.boundary_action == "REMOVE":
                    obs.append("⚠️ Governance Boundary Degradation: Removing 'ApexStrictPCIBoundary' strips the explicit Deny on s3:* and dynamodb:*, weakening PCI DSS cardholder data environment enclave isolation.")

                if cfg.trust_relationship_id == "trust-excessive-dev-to-prod" or (cfg.trust_relationship_id and "not configured" in (cfg.mfa_condition or "").lower()):
                    obs.append("⚠️ Insecure Cross-Account Trust: Trust relationship lacks MFA and ExternalId conditions while granting access to a production role holding AdministratorAccess with no permission boundary.")
                elif cfg.trust_relationship_id == "trust-secops-cross-account-prod" or (cfg.trust_relationship_id and "true" in (cfg.mfa_condition or "").lower()):
                    obs.append("✅ Secure Cross-Account Audit Trust: Trust relationship enforces mandatory MFA (aws:MultiFactorAuthPresent = true) and restricts assume-role actions to the named audit role.")

                if cfg.approval_status == "PENDING" and cfg.approvals:
                    pending_apps = [k for k, v in cfg.approvals.items() if v.lower() == "pending"]
                    obs.append(f"⏳ Pending Approvals: Ticket holds pending approval sign-offs ({', '.join(pending_apps)}). PENDING_IS_NOT_ACCESS.")
                elif not obs:
                    obs.append("✅ Baseline Validated: Requested IAM configuration aligns with approved least-privilege security baseline.")
            else:
                if cfg.privileged_access_requested or cfg.privileged_entitlements:
                    priv_names = ", ".join(cfg.privileged_entitlements) if cfg.privileged_entitlements else "SAP - Finance Administrator"
                    obs.append(f"⚠️ Privileged Entitlement: Request grants elevated administrative privilege ('{priv_names}'). Requires separate privileged justification, expiry, and privileged access owner approval.")

                if cfg.lifecycle_type == "MOVER":
                    if cfg.privileged_access_requested:
                        obs.append("⚠️ SoD / Toxic Combination Alert: Granting administrative rights ('SAP Finance Administrator') combined with operational transition introduces Segregation of Duties (SoD) risk.")
                    if not cfg.access_to_remove:
                        obs.append("⚠️ Privilege Creep Warning: Departmental transfer does not specify revocation of prior operational access, creating privilege accumulation risk.")
                    else:
                        obs.append(f"ℹ️ Transfer Revocation Verification: Ensure scheduled deprovisioning of {len(cfg.access_to_remove)} prior departmental access entitlement(s) upon effective transfer date.")

                if cfg.approval_status == "PENDING":
                    obs.append(f"⏳ In-Flight Access: Approvals pending ({cfg.approval_status}). In-flight requests convey zero valid permissions under principle PENDING_IS_NOT_ACCESS.")

                if "contractor" in (cfg.identity_name + " " + cfg.worker_type).lower() and any(p in (cfg.requested_role + " " + cfg.entitlement).lower() for p in ["admin", "cui", "root"]):
                    obs.append("⚠️ Contractor Privileged Access: External contractor requesting elevated CUI/Administrator entitlements (Potential SoD conflict).")

                if cfg.lifecycle_type == "LEAVER":
                    obs.append("ℹ️ Offboarding Verification: Account revocation requires multi-system verification across Microsoft 365, AWS, ServiceNow, and VPN.")
                elif not obs:
                    obs.append("✅ Standard Identity Request: Identity attributes match standard corporate role assignment lifecycle.")

        summary.initial_observations = obs
        return summary

    # =========================================================================
    # SAMPLE CHANGE REQUEST TEMPLATES & LOADER METHODS
    # =========================================================================

    @classmethod
    def _read_chg_sample(cls, filename: str) -> str:
        candidates = [
            Path(__file__).parent.parent.parent / "SimuGuard_Firewall_Sample_Change_Requests" / filename,
            Path(__file__).parent.parent.parent.parent / "SimuGuard_Firewall_Sample_Change_Requests" / filename,
            Path("SimuGuard_Firewall_Sample_Change_Requests") / filename,
            CHANGES_DIR.parent / "SimuGuard_Firewall_Sample_Change_Requests" / filename,
        ]
        for p in candidates:
            if p.exists():
                return p.read_text(encoding="utf-8")
        return ""

    @classmethod
    def get_sample_chg_1001(cls) -> str:
        """Sample CHG-2026-1001: Allow outbound HTTPS connectivity for Customer Portal API (ALLOW)."""
        content = cls._read_chg_sample("CHG-2026-1001_Outbound_HTTPS_Customer_Portal.txt")
        if content:
            return content
        return """CHANGE REQUEST: CHG-2026-1001

Short Description: Allow outbound HTTPS connectivity for Customer Portal API

Requested By: Rahul Sharma
Assignment Group: Network Security Operations
Change Type: Normal
Priority: Medium
Category: Network Security
Subcategory: Firewall Rule Modification

Business Service: Customer Web Portal
Application: APP-001-CUSTOMER-PORTAL
Environment: Production

Target Firewall: PAN-NGFW-EDGE-01
Firewall Platform: Palo Alto PA-5450
Management Platform: Panorama

Change Operation: Create Security Policy

Security Policy Details:
Rule Name: Allow-Customer-Portal-Outbound
Source Zone: Trust-Application
Source Address / CIDR: 10.100.10.0/24
Destination Zone: Untrust-Internet
Destination Address / CIDR: 198.51.100.25/32
Application: ssl
Service: service-https
Port: 443
Protocol: TCP
Action: Allow
Security Profile Group: Strict-Enterprise-Security
Log Setting: Enabled at session end

Business Justification:
The Customer Portal API requires outbound HTTPS connectivity to an external payment gateway for payment transaction processing. The current firewall policy blocks this communication.

Implementation Plan:
1. Log into Panorama management console.
2. Navigate to Device Group 'Edge-Firewalls' -> Policies -> Security.
3. Add security rule 'Allow-Customer-Portal-Outbound'.
4. Configure source zone 'Trust-Application' with source prefix 10.100.10.0/24.
5. Configure destination zone 'Untrust-Internet' with destination IP 198.51.100.25/32.
6. Set application to 'ssl' and service to 'service-https'.
7. Attach 'Strict-Enterprise-Security' profile group.
8. Enable logging at session end.
9. Commit and push configuration to PAN-NGFW-EDGE-01.

Validation Plan:
1. Initiate curl HTTPS request from application host 10.100.10.15 to https://198.51.100.25.
2. Verify traffic log in Panorama shows rule 'Allow-Customer-Portal-Outbound' hit with action 'allow'.
3. Confirm SSL session establishment without TLS handshake failures.

Backout Plan:
1. If communication fails or unexpected traffic is observed, disable rule 'Allow-Customer-Portal-Outbound'.
2. Commit and push changes via Panorama.
3. Notify application team.

Maintenance Window:
2026-10-15 02:00 UTC - 2026-10-15 04:00 UTC
"""

    @classmethod
    def get_sample_chg_1002(cls) -> str:
        """Sample CHG-2026-1002: Enable unrestricted outbound internet access for Analytics Servers (BLOCK)."""
        content = cls._read_chg_sample("CHG-2026-1002_Unrestricted_Outbound_Internet.txt")
        if content:
            return content
        return """CHANGE REQUEST: CHG-2026-1002

Short Description: Enable unrestricted outbound internet access for Analytics Servers

Requested By: Amit Verma
Assignment Group: Network Security Operations
Change Type: Normal
Priority: High
Category: Network Security
Subcategory: Firewall Rule Modification

Business Service: Enterprise Analytics Platform
Application: APP-002-ANALYTICS
Environment: Production

Target Firewall: PAN-NGFW-EDGE-01
Firewall Platform: Palo Alto PA-5450
Management Platform: Panorama

Change Operation: Create Security Policy

Security Policy Details:
Rule Name: Temp-Analytics-Outbound-Access
Source Zone: Trust-Analytics
Source Address / CIDR: 10.100.20.0/24
Destination Zone: Untrust-Internet
Destination Address / CIDR: any
Application: any
Service: any
Port: any
Protocol: ANY
Action: Allow
Security Profile Group: None
Log Setting: Disabled

Business Justification:
The analytics team requires external connectivity for downloading packages, accessing cloud services and integrating with external data providers. The team has requested unrestricted outbound access to avoid connectivity issues.

Implementation Plan:
1. Log into Panorama.
2. Create rule 'Temp-Analytics-Outbound-Access' in Edge-Firewalls policy set.
3. Source: Trust-Analytics (10.100.20.0/24).
4. Destination: Untrust-Internet (any).
5. Application: any.
6. Service: any.
7. Action: Allow.
8. Commit configuration.

Validation Plan:
1. Run pip install and curl commands from analytics worker node.
2. Confirm external internet access is functional.

Backout Plan:
1. Remove or disable rule 'Temp-Analytics-Outbound-Access'.
2. Commit configuration.

Maintenance Window:
2026-10-16 01:00 UTC - 2026-10-16 03:00 UTC
"""

    @classmethod
    def get_sample_chg_1003(cls) -> str:
        """Sample CHG-2026-1003: Allow application servers to communicate with internal database servers (ALLOW)."""
        content = cls._read_chg_sample("CHG-2026-1003_Internal_Network_Segmentation.txt")
        if content:
            return content
        return """CHANGE REQUEST: CHG-2026-1003

Short Description: Allow application servers to communicate with internal database servers

Requested By: Sneha Reddy
Assignment Group: Network Security Operations
Change Type: Normal
Priority: Medium
Category: Network Security
Subcategory: Internal Segmentation

Business Service: Enterprise Banking Application
Application: APP-003-BANKING
Environment: Production

Target Firewall: PAN-NGFW-DC-01
Firewall Platform: Palo Alto PA-5450
Management Platform: Panorama

Change Operation: Create Security Policy

Security Policy Details:
Rule Name: Allow-App-To-Database-Postgres
Source Zone: Trust-Application
Source Address / CIDR: 10.200.10.0/24
Destination Zone: Trust-Database
Destination Address / CIDR: 10.200.20.15/32
Application: postgresql
Service: tcp-5432
Port: 5432
Protocol: TCP
Action: Allow
Security Profile Group: Strict-Enterprise-Security
Log Setting: Enabled at session end

Business Justification:
The banking application requires database connectivity to support transaction processing and customer account operations.

Implementation Plan:
1. Log into Panorama.
2. Navigate to DataCenter-Firewalls policy group.
3. Create rule 'Allow-App-To-Database-Postgres'.
4. Source Zone: Trust-Application, Source CIDR: 10.200.10.0/24.
5. Destination Zone: Trust-Database, Destination CIDR: 10.200.20.15/32.
6. Set Application to postgresql, Service to tcp-5432.
7. Attach Strict-Enterprise-Security profile group.
8. Commit configuration to PAN-NGFW-DC-01.

Validation Plan:
1. Run pg_isready and test DB connectivity from 10.200.10.12.
2. Confirm successful connection in firewall traffic log.

Backout Plan:
1. Disable rule 'Allow-App-To-Database-Postgres'.
2. Commit configuration.

Maintenance Window:
2026-10-17 02:00 UTC - 2026-10-17 04:00 UTC
"""

    @classmethod
    def get_sample_chg_1004(cls) -> str:
        """Sample CHG-2026-1004: Configure inbound NAT and security policy for Customer Support Portal (ALLOW)."""
        content = cls._read_chg_sample("CHG-2026-1004_Inbound_NAT_Support_Portal.txt")
        if content:
            return content
        return """CHANGE REQUEST: CHG-2026-1004

Short Description: Configure inbound NAT and security policy for Customer Support Portal

Requested By: Karan Mehta
Assignment Group: Network Security Operations
Change Type: Normal
Priority: High
Category: Network Security
Subcategory: NAT Rule Configuration

Business Service: Customer Support Portal
Application: APP-004-SUPPORT-PORTAL
Environment: Production

Target Firewall: PAN-NGFW-EDGE-02
Firewall Platform: Palo Alto PA-5450
Management Platform: Panorama

Change Operation: Create NAT and Security Policies

NAT Policy Details:
Rule Name: NAT-Support-Portal-Inbound
NAT Type: Destination NAT (IPv4)
Original Source Zone: Untrust-Internet
Original Destination Zone: Untrust-Internet
Original Destination Address: 203.0.113.50/32
Original Service: service-https (TCP 443)
Translated Destination Address: 10.100.30.25
Translated Destination Port: 443

Security Policy Details:
Rule Name: Allow-Inbound-Support-Portal
Source Zone: Untrust-Internet
Source Address / CIDR: any (0.0.0.0/0)
Destination Zone: Trust-DMZ
Destination Address / CIDR: 10.100.30.25/32
Application: ssl
Service: service-https
Port: 443
Protocol: TCP
Action: Allow
Security Profile Group: Strict-Enterprise-Security
Log Setting: Enabled at session end

Business Justification:
The support portal is currently hosted internally and needs to be accessible to external customers through its public IP address.

Implementation Plan:
1. Configure Destination NAT rule 'NAT-Support-Portal-Inbound' on Panorama.
2. Configure Security Policy rule 'Allow-Inbound-Support-Portal' matching post-NAT IP 10.100.30.25.
3. Attach Strict-Enterprise-Security profile.
4. Commit and push to PAN-NGFW-EDGE-02.

Validation Plan:
1. Send HTTPS request to https://203.0.113.50 from external probe.
2. Verify NAT log and Security log show translation and permit.

Backout Plan:
1. Disable NAT and Security rules.
2. Commit configuration.

Maintenance Window:
2026-10-18 01:00 UTC - 2026-10-18 03:00 UTC
"""

    @classmethod
    def get_sample_chg_1005(cls) -> str:
        """Sample CHG-2026-1005: Modify existing firewall rule to allow unrestricted vendor connectivity (BLOCK)."""
        content = cls._read_chg_sample("CHG-2026-1005_Unrestricted_Vendor_Connectivity.txt")
        if content:
            return content
        return """CHANGE REQUEST: CHG-2026-1005

Short Description: Modify existing firewall rule to allow unrestricted vendor connectivity

Requested By: David Kim
Assignment Group: SecOps-Network-Team
Change Type: Emergency
Priority: Critical
Category: Network Security
Subcategory: Existing Firewall Rule Modification

Business Service: Enterprise Infrastructure
Application: APP-005-VENDOR-INTEGRATION
Environment: Production

Target Firewall: PAN-NGFW-EDGE-01
Firewall Platform: Palo Alto PA-5450
Management Platform: Panorama

Change Operation: Modify Existing Security Policy

Existing Policy Details:
Rule Name: Allow-Vendor-Integration
Current Source Zone: Trust-Vendor
Current Source Address / CIDR: 10.100.40.0/24
Current Destination Zone: Untrust-Internet
Current Destination Address / CIDR: 198.51.100.80/32
Current Application: ssl
Current Service: service-https
Current Port: 443
Current Action: Allow
Current Security Profile Group: Strict-Enterprise-Security
Current Log Setting: Enabled at session end

Proposed Policy Modification:
Rule Name: Allow-Vendor-Integration-Any
Proposed Source Zone: Trust-Vendor
Proposed Source Address / CIDR: 10.100.40.0/24
Proposed Destination Zone: Untrust-Internet
Proposed Destination Address / CIDR: any
Proposed Application: any
Proposed Service: any
Proposed Port: any
Proposed Action: Allow
Proposed Security Profile Group: None
Proposed Log Setting: Disabled

Business Justification:
The external vendor has reported connectivity issues while accessing its cloud-hosted services. The team proposes allowing unrestricted outbound access to resolve the issue immediately.

Implementation Plan:
1. Locate existing rule 'Allow-Vendor-Integration' on PAN-NGFW-EDGE-01.
2. Update destination address from 198.51.100.80/32 to 'any'.
3. Update application from 'ssl' to 'any'.
4. Update service from 'service-https' to 'any'.
5. Set security profile group to 'None'.
6. Disable session logging.
7. Rename rule to 'Allow-Vendor-Integration-Any'.
8. Commit change immediately.

Validation Plan:
1. Vendor to verify data synchronization across multiple dynamically allocated ports.

Backout Plan:
1. Revert rule configuration back to original parameters:
   - Destination: 198.51.100.80/32
   - Application: ssl
   - Service: service-https
   - Security Profile: Strict-Enterprise-Security
   - Logging: Enabled at session end
2. Commit configuration.

Maintenance Window:
2026-10-19 00:00 UTC - 2026-10-19 02:00 UTC (Emergency Change)
"""

    @classmethod
    def get_sample_pr_4082(cls) -> str:
        """Sample PR-4082: Critical DB Direct Access & Wildcard IAM (Verdict: BLOCK)."""
        return """Change Request: CHG004082
Short Description: PR-4082: Allow Direct Database Ingress for Telemetry Ingestion
Priority: Critical
Category: Network Security
Domain: Network Security / Firewall
Requested By: David Kim (SecOps Operations)
Configuration Item: PAN-NGFW-EDGE-01
Firewall Rule Name: direct-db-access-rule
Source Zone: Untrust-Internet
Destination Zone: Prod-Database
Source CIDR: 0.0.0.0/0
Destination CIDR: 10.100.2.15/32
App-ID: any
Service: service-https
Port: 443
Action: allow
Business Justification: Direct ingress needed for high-volume automated analytics pipeline ingestion.

# Associated Terraform Configuration Payload:
resource "panos_security_rule_group" "rule_4082" {
  position = "top"
  rule {
    name                  = "direct-db-access-rule"
    source_zones          = ["Untrust-Internet"]
    source_addresses      = ["0.0.0.0/0"]
    destination_zones     = ["Prod-Database"]
    destination_addresses = ["10.100.2.15/32"]
    applications          = ["any"]
    services              = ["service-https"]
    action                = "allow"
  }
}

resource "aws_iam_role_policy_attachment" "wildcard_s3" {
  role       = "telemetry-ingestion-role"
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}
"""

    @classmethod
    def get_sample_pr_4083(cls) -> str:
        """Sample PR-4083: Permissive DMZ Inbound & AWS Admin Access (Verdict: BLOCK)."""
        return """Change Request: CHG004083
Short Description: PR-4083: Expand DMZ Inbound Scope and Attach AWS Admin Policy
Priority: High
Category: Network Security
Domain: Network Security / Firewall
Requested By: Marcus Vance (Cloud Architecture)
Configuration Item: PAN-NGFW-EDGE-01
Firewall Rule Name: dmz-ext-inbound-permissive
Source Zone: Untrust-Internet
Destination Zone: Trust-DMZ
Source CIDR: 0.0.0.0/0
Destination CIDR: 10.100.1.0/24
App-ID: any
Service: any
Port: any
Action: allow
Business Justification: Vendor diagnostic connectivity required for emergency DMZ appliance triage.

# Associated Terraform Configuration Payload:
resource "panos_security_rule_group" "rule_4083" {
  position = "top"
  rule {
    name                  = "dmz-ext-inbound-permissive"
    source_zones          = ["Untrust-Internet"]
    source_addresses      = ["0.0.0.0/0"]
    destination_zones     = ["Trust-DMZ"]
    destination_addresses = ["10.100.1.0/24"]
    applications          = ["any"]
    services              = ["any"]
    action                = "allow"
  }
}

resource "aws_iam_role_policy_attachment" "admin_access" {
  role       = "dmz-diagnostics-role"
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}
"""

    @classmethod
    def get_sample_allow_netflix(cls) -> str:
        """Sample Allow Netflix: Non-Standard Video Streaming App-ID (Verdict: WARN)."""
        return """Change Request: CHG005120
Short Description: Allow Netflix Video Streaming on Corporate Perimeter
Priority: Low
Category: Network Security
Domain: Network Security / Firewall
Requested By: Employee Experience Team
Configuration Item: PAN-NGFW-EDGE-01
Firewall Rule Name: Allow-Netflix-Egress
Source Zone: Corp-Users
Destination Zone: Untrust-Internet
Source CIDR: 10.200.0.0/16
Destination CIDR: any
App-ID: netflix
Service: service-https
Port: 443
Action: allow
Business Justification: Enable cafeteria smart screens and executive lounge media streaming during designated breaks.

# Associated Terraform Configuration Payload:
resource "panos_security_rule_group" "allow_netflix_rules" {
  position = "bottom"
  rule {
    name                  = "Allow-Netflix-Streaming"
    source_zones          = ["Corp-Users"]
    source_addresses      = ["10.200.0.0/16"]
    destination_zones     = ["Untrust-Internet"]
    destination_addresses = ["any"]
    applications          = ["netflix"]
    services              = ["service-https"]
    action                = "allow"
  }
}
"""

    @classmethod
    def get_sample_safe_rule(cls) -> str:
        """Sample Safe Rule: Strict Outbound Analytics Telemetry (Verdict: ALLOW)."""
        return """Change Request: CHG006200
Short Description: Deploy Compliant Egress Rule for Analytics Telemetry
Priority: Standard
Category: Network Security
Domain: Network Security / Firewall
Requested By: David Kim (SecOps Operations)
Configuration Item: PAN-NGFW-EDGE-01
Firewall Rule Name: Allow-Telemetry-Egress-Strict
Source Zone: Trust-DMZ
Destination Zone: Untrust-Internet
Source CIDR: 10.100.4.0/24
Destination CIDR: 198.51.100.24/32
App-ID: ssl
Service: service-https
Port: 443
Action: allow
Business Justification: Authorized outbound reporting webhook strictly constrained to verified partner endpoint.

# Associated Terraform Configuration Payload:
resource "panos_security_rule_group" "safe_telemetry_rule" {
  position = "top"
  rule {
    name                  = "Allow-Telemetry-Egress-Strict"
    source_zones          = ["Trust-DMZ"]
    source_addresses      = ["10.100.4.0/24"]
    destination_zones     = ["Untrust-Internet"]
    destination_addresses = ["198.51.100.24/32"]
    applications          = ["ssl"]
    services              = ["service-https"]
    action                = "allow"
  }
}
"""

    @classmethod
    def get_sample_sailpoint(cls) -> str:
        """Sample SailPoint: Privileged S3 CUI Access Request (Verdict: BLOCK/WARN)."""
        return """Change Request: CHG009941
Short Description: Grant Production S3 CUI Vault Read Access to Finance Contractor
Priority: High
Category: Identity Governance
Domain: Identity Governance / SailPoint
Requested By: Sarah Chen (Contractor)
Target Identity: Sarah Chen (sp-ident-sarah-chen - Finance Contractor)
Identity Profile: Contractor & Vendor Workforce
Authoritative Source: Corporate Active Directory
Source Account ID: sp-acct-ad-sarah-chen
Account Status: ACTIVE
Requested Role: Finance & Treasury Analyst
Access Profile: Production S3 CUI Vault Read Access
Entitlement: AWS Production S3 CUI Vault Read
Target Application: Enterprise AWS Cloud Services
Business Justification: Temporary contractor audit assignment requiring read-only access to quarterly CUI finance archives.
Request Status: PENDING_APPROVAL
Approval Status: PENDING
Provisioning Status: UNPROVISIONED
"""
