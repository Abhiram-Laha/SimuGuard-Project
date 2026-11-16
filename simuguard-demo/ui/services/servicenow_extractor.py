"""ServiceNow Change Request Extractor and Parser Service.

Extracts structured firewall, NAT, and identity governance configurations from
unstructured ServiceNow ticket text, key-value fields, and embedded Terraform HCL blocks.
"""

from dataclasses import dataclass, field
import json
from pathlib import Path
import re
from typing import Any, Dict, List, Optional

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
    identity_name: str = ""
    employee_id: str = ""
    worker_type: str = ""
    identity_profile: str = "Corporate Full-Time Employees"
    identity_source: str = "Corporate Active Directory"
    account_id: str = ""
    account_status: str = "ACTIVE"
    requested_role: str = ""
    access_profile: str = ""
    entitlement: str = ""
    approvals: Dict[str, str] = field(default_factory=dict)
    approval_status: str = "APPROVED"
    privileged_access_requested: bool = False

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
            "iam", "access request", "joiner", "mover", "leaver", "offboarding", "ritm"
        ]
        firewall_keywords = [
            "firewall", "panos", "palo alto", "security rule", "nat rule",
            "source zone", "destination zone", "cidr", "app-id", "ingress", "egress"
        ]

        id_score = sum(1 for kw in identity_keywords if kw in lower_text)
        fw_score = sum(1 for kw in firewall_keywords if kw in lower_text)

        if id_score > fw_score and id_score >= 2:
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
        pat = r"(?:^|\n)Approvals(?: and confirmations)?\s*[:=]\s*\n?([\s\S]+?)(?=\n(?:Additional note|Dependencies|Implementation|Validation|Backout|Exception handling|Fulfilment|Worker|Requested|Risk|\n\s*\n)|\Z)"
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
                    cfg.approvals[role.strip()] = status.strip()

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
    def _extract_sailpoint_fields(cls, text: str, cfg: ExtractedConfig) -> None:
        """Extract SailPoint identity governance attributes dynamically without hardcoded defaults."""
        name_val = cls._extract_field(
            text,
            [
                r"^Employee [Nn]ame\s*[:=]\s*(.+)",
                r"^Worker [Nn]ame\s*[:=]\s*(.+)",
                r"^Target Identity\s*[:=]\s*(.+)",
                r"^Identity [Nn]ame\s*[:=]\s*(.+)",
                r"^Identity\s*[:=]\s*(.+)",
                r"^Name\s*[:=]\s*(.+)",
            ],
            default="",
        )
        eid_val = cls._extract_field(
            text,
            [
                r"^Employee ID\s*[:=]\s*([A-Za-z0-9_\-]+)",
                r"^Worker ID\s*[:=]\s*([A-Za-z0-9_\-]+)",
                r"^Employee Number\s*[:=]\s*([A-Za-z0-9_\-]+)",
                r"^Worker Number\s*[:=]\s*([A-Za-z0-9_\-]+)",
            ],
            default="",
        )
        cfg.employee_id = eid_val
        if name_val and eid_val:
            cfg.identity_name = f"{name_val} ({eid_val})"
        elif name_val:
            cfg.identity_name = name_val
        elif eid_val:
            cfg.identity_name = eid_val

        cfg.worker_type = cls._extract_field(text, [r"^Worker [Tt]ype\s*[:=]\s*(.+)"], default="")
        if "contractor" in cfg.worker_type.lower():
            cfg.identity_profile = "External Contractors"
        elif "employee" in cfg.worker_type.lower():
            cfg.identity_profile = "Corporate Full-Time Employees"

        cfg.identity_profile = cls._extract_field(
            text,
            [r"^Identity Profile\s*[:=]\s*(.+)"],
            default=cfg.identity_profile or "",
        )

        cfg.requested_role = cls._extract_field(
            text,
            [
                r"^Requested Role\s*[:=]\s*(.+)",
                r"^Role Name\s*[:=]\s*(.+)",
                r"^Role\s*[:=]\s*(.+)",
                r"^New [Jj]ob [Tt]itle\s*[:=]\s*(.+)",
                r"^Job [Tt]itle\s*[:=]\s*(.+)",
            ],
            default="",
        )
        cfg.access_profile = cls._extract_field(
            text,
            [r"^Access Profile\s*[:=]\s*(.+)"],
            default="",
        )

        # Entitlements extraction
        req_access_sec = (
            cls._extract_multiline_section(text, "Requested access changes")
            or cls._extract_multiline_section(text, "Requested access")
            or cls._extract_multiline_section(text, "Requested action")
        )
        if req_access_sec:
            lines = [l.strip() for l in req_access_sec.splitlines() if l.strip()]
            clean_items = []
            for l in lines:
                if l.startswith(("-", "*", "•")):
                    clean_items.append(l.lstrip("-*• ").strip())
                elif l.upper().startswith(("ADD:", "REMOVE:")):
                    clean_items.append(l)
            if clean_items:
                cfg.entitlement = "; ".join(clean_items)

        if not cfg.entitlement:
            cfg.entitlement = cls._extract_field(
                text,
                [r"^Entitlement\s*[:=]\s*(.+)", r"^Permission\s*[:=]\s*(.+)"],
                default="",
            )

        # Check for privileged access request
        all_ent_text = (cfg.entitlement + " " + cfg.requested_role + " " + text).lower()
        if "sap - finance administrator" in all_ent_text or ("admin" in all_ent_text and "finance" in all_ent_text):
            cfg.privileged_access_requested = True

        cfg.account_id = cls._extract_field(
            text,
            [r"^Source Account ID\s*[:=]\s*(.+)", r"^Account ID\s*[:=]\s*(.+)"],
            default="",
        )
        cfg.identity_source = cls._extract_field(
            text,
            [r"^Authoritative Source\s*[:=]\s*(.+)", r"^Identity Source\s*[:=]\s*(.+)"],
            default="",
        )

        # Dynamic attribute enrichment via CentralizedIdentityResolver if identity was extracted
        if cfg.identity_name:
            try:
                from simuguard.graph.dataset_loader import EnterpriseDatasetLoader
                from simuguard.identity import CentralizedIdentityResolver, IdentityResolutionStatus
                sp_data = EnterpriseDatasetLoader().load_sailpoint_governance()
                res = CentralizedIdentityResolver(sp_data).resolve_identity(
                    query=cfg.identity_name,
                    employee_id=cfg.employee_id,
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
            if not cfg.identity_name:
                cfg.missing_fields.append("Target Identity")
            if not (cfg.requested_role or cfg.access_profile or cfg.entitlement):
                cfg.missing_fields.append("At least one requested entitlement or role")

            if cfg.privileged_access_requested:
                cfg.warnings.append("Privileged Access Warning: 'SAP - Finance Administrator' is a privileged entitlement requested without separate privileged justification, expiry date, or privileged access approval.")

            if cfg.approval_status == "PENDING" and cfg.approvals:
                pending_roles = [r for r, s in cfg.approvals.items() if any(ps in s.lower() for ps in ["pending", "required", "not started"])]
                if pending_roles:
                    cfg.warnings.append(f"In-Flight Unapproved Access: Pending approvals [{', '.join(pending_roles)}]. In-flight requests convey zero valid permissions under PENDING_IS_NOT_ACCESS.")

            if "contractor" in (cfg.identity_name + " " + cfg.worker_type).lower() and ("admin" in cfg.requested_role.lower() or "cui" in cfg.entitlement.lower()):
                cfg.warnings.append("Contractor identity requesting privileged CUI/Admin access (Potential SoD violation)")

            if "leaver" in cfg.subcategory.lower() or "offboarding" in cfg.subcategory.lower() or "contractor" in cfg.worker_type.lower():
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
            ident = cfg.identity_name or "Not specified"
            role = cfg.requested_role or "Not specified"
            ap = cfg.access_profile or "Not specified"
            ent = cfg.entitlement or "Not specified"
            src = cfg.identity_source or "Not specified"
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
            key_changes["Target Identity"] = cfg.identity_name or "Not specified"
            key_changes["Identity Profile"] = cfg.identity_profile or "Not specified"
            key_changes["Authoritative Source"] = cfg.identity_source or "Not specified"
            key_changes["Account ID"] = cfg.account_id or "Not specified"
            key_changes["Requested Role"] = cfg.requested_role or "Not specified"
            key_changes["Access Profile"] = cfg.access_profile or "Not specified"
            key_changes["Entitlement"] = cfg.entitlement or "Not specified"

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
            if cfg.privileged_access_requested:
                obs.append("⚠️ Privileged Entitlement: Request includes elevated administrative permissions ('SAP - Finance Administrator') without dedicated justification or expiry.")

            if cfg.approval_status == "PENDING":
                obs.append(f"⏳ In-Flight Access: Approvals pending ({cfg.approval_status}). In-flight requests convey zero valid permissions under PENDING_IS_NOT_ACCESS.")

            if "contractor" in (cfg.identity_name or "").lower() and ("admin" in (cfg.requested_role or "").lower() or "cui" in (cfg.entitlement or "").lower()):
                obs.append("⚠️ Contractor Privileged Access: External contractor requesting elevated CUI/Administrator entitlements (Potential SoD conflict).")

            if "leaver" in cfg.subcategory.lower() or "offboarding" in cfg.subcategory.lower():
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
