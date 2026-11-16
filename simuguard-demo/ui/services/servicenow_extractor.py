"""ServiceNow Change Request Extractor and Parser Service.

Extracts structured firewall and identity governance configurations from
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
    justification: str = ""
    description: str = ""
    requested_by: str = "SecOps Operations Engineer"

    # Network Security / Firewall Fields
    firewall_platform: str = "Palo Alto Networks PA-5450"
    firewall_device: str = "fw-edge-01-primary"
    rule_name: str = ""
    source_zone: str = "Untrust-Internet"
    destination_zone: str = ""
    source_addresses: str = ""
    destination_addresses: str = ""
    applications: str = ""
    services: str = "service-https"
    destination_port: str = "443"
    action: str = "allow"
    security_profile: str = "Strict-Enterprise-Security"

    # Identity Governance / SailPoint Fields
    identity_name: str = ""
    identity_profile: str = "Corporate Full-Time Employees"
    identity_source: str = "Corporate Active Directory"
    account_id: str = ""
    account_status: str = "ACTIVE"
    requested_role: str = ""
    access_profile: str = ""
    entitlement: str = ""

    # Raw Payload & Metadata
    raw_hcl: str = ""
    scenario_source_path: Optional[str] = None
    warnings: List[str] = field(default_factory=list)
    missing_fields: List[str] = field(default_factory=list)


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
            "identitynow", "governance", "sod conflict", "grant role"
        ]
        firewall_keywords = [
            "firewall", "panos", "palo alto", "security rule",
            "source zone", "destination zone", "cidr", "app-id", "ingress", "egress"
        ]

        id_score = sum(1 for kw in identity_keywords if kw in lower_text)
        fw_score = sum(1 for kw in firewall_keywords if kw in lower_text)

        if id_score > fw_score and id_score >= 2:
            cfg.domain = "IDENTITY_GOVERNANCE"
        else:
            cfg.domain = "NETWORK_SECURITY"

        # 2. Extract Common Fields using Regex Patterns
        cfg.title = cls._extract_field(
            clean_text,
            [r"(?:short description|summary|title)\s*[:=]\s*(.+)", r"^([A-Z0-9_\- ]{10,80})$"],
            default="ServiceNow Change Request",
        )
        cfg.request_number = cls._extract_field(
            clean_text,
            [r"(?:change request|change number|cr number|ticket number|req(?:uest)?\s*#?)\s*[:=]\s*([A-Za-z0-9_\-]+)"],
            default="",
        )
        cfg.priority = cls._extract_field(
            clean_text,
            [r"priority\s*[:=]\s*(critical|high|medium|low|emergency|expedited)"],
            default="HIGH",
        ).upper()
        if cfg.priority not in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            cfg.priority = "HIGH"

        cfg.justification = cls._extract_field(
            clean_text,
            [r"(?:business justification|justification|reason)\s*[:=]\s*(.+?)(?=\n[A-Z]|\Z)"],
            default="Operational infrastructure change requested via ServiceNow ITSM.",
        )
        cfg.requested_by = cls._extract_field(
            clean_text,
            [r"(?:requested by|submitter|requester)\s*[:=]\s*(.+)"],
            default="David Kim (Senior SecOps Operations Engineer)",
        )

        # 3. Check for Embedded Terraform / HCL Block
        hcl_match = re.search(r'(resource\s+"[^"]+"\s+"[^"]+"\s*\{.*?\})', clean_text, re.DOTALL)
        if hcl_match:
            cfg.raw_hcl = hcl_match.group(1).strip()
            cls._extract_from_hcl(cfg.raw_hcl, cfg)
        elif "resource " in clean_text and " {" in clean_text:
            # Entire text may be Terraform
            cfg.raw_hcl = clean_text
            cls._extract_from_hcl(clean_text, cfg)

        # 4. Extract Domain-Specific Fields from Text Lines
        if cfg.domain == "NETWORK_SECURITY":
            cls._extract_firewall_fields(clean_text, cfg)
        else:
            cls._extract_sailpoint_fields(clean_text, cfg)

        # 5. Check if matches known certified files
        cls._match_known_scenario(clean_text, cfg)

        # 6. Validate Missing and Ambiguous Fields
        cls._validate_fields(cfg)

        return cfg

    @classmethod
    def _extract_field(cls, text: str, patterns: List[str], default: str = "") -> str:
        """Extract first matching group from regex patterns."""
        for pat in patterns:
            m = re.search(pat, text, re.IGNORECASE | re.MULTILINE)
            if m:
                val = m.group(1).strip()
                if val:
                    return val
        return default

    @classmethod
    def _extract_firewall_fields(cls, text: str, cfg: ExtractedConfig) -> None:
        """Extract network security and firewall attributes."""
        if not cfg.rule_name:
            cfg.rule_name = cls._extract_field(
                text,
                [r"(?:rule name|policy name|security policy)\s*[:=]\s*(.+)"],
                default="Allow-Egress-Rule",
            )
        if not cfg.source_zone:
            cfg.source_zone = cls._extract_field(
                text,
                [r"(?:source zone|src zone|from zone)\s*[:=]\s*(.+)"],
                default="Untrust-Internet",
            )
        if not cfg.destination_zone:
            cfg.destination_zone = cls._extract_field(
                text,
                [r"(?:destination zone|dst zone|to zone)\s*[:=]\s*(.+)"],
                default="Prod-Database",
            )
        if not cfg.source_addresses:
            cfg.source_addresses = cls._extract_field(
                text,
                [r"(?:source address(?:es)?|source cidr|src ip|source ip)\s*[:=]\s*(.+)"],
                default="0.0.0.0/0",
            )
        if not cfg.destination_addresses:
            cfg.destination_addresses = cls._extract_field(
                text,
                [r"(?:destination address(?:es)?|destination cidr|dst ip|dest ip|destination)\s*[:=]\s*(.+)"],
                default="10.100.2.15/32",
            )
        if not cfg.applications:
            cfg.applications = cls._extract_field(
                text,
                [r"(?:applications?|app-id|application)\s*[:=]\s*(.+)"],
                default="any",
            )
        if not cfg.services:
            cfg.services = cls._extract_field(
                text,
                [r"(?:services?|service object)\s*[:=]\s*(.+)"],
                default="service-https",
            )
        if not cfg.destination_port:
            cfg.destination_port = cls._extract_field(
                text,
                [r"(?:destination port|dst port|port)\s*[:=]\s*(.+)"],
                default="443",
            )
        if not cfg.action:
            act = cls._extract_field(text, [r"action\s*[:=]\s*(allow|deny|drop)"], default="allow").lower()
            cfg.action = act if act in ["allow", "deny", "drop"] else "allow"

    @classmethod
    def _extract_sailpoint_fields(cls, text: str, cfg: ExtractedConfig) -> None:
        """Extract SailPoint identity governance attributes."""
        cfg.identity_name = cls._extract_field(
            text,
            [r"(?:target identity|identity name|identity|user)\s*[:=]\s*(.+)"],
            default="Sarah Chen (sp-ident-sarah-chen)",
        )
        cfg.requested_role = cls._extract_field(
            text,
            [r"(?:requested role|role name|role)\s*[:=]\s*(.+)"],
            default="Finance & Treasury Analyst",
        )
        cfg.access_profile = cls._extract_field(
            text,
            [r"(?:access profile|profile)\s*[:=]\s*(.+)"],
            default="Production S3 CUI Vault Read Access",
        )
        cfg.entitlement = cls._extract_field(
            text,
            [r"(?:entitlement|permission)\s*[:=]\s*(.+)"],
            default="AWS Production S3 CUI Vault Read",
        )
        cfg.account_id = cls._extract_field(
            text,
            [r"(?:account id|source account)\s*[:=]\s*(.+)"],
            default="sp-acct-ad-sarah-chen",
        )
        cfg.identity_source = cls._extract_field(
            text,
            [r"(?:authoritative source|identity source|source)\s*[:=]\s*(.+)"],
            default="Corporate Active Directory",
        )

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

    @classmethod
    def _match_known_scenario(cls, text: str, cfg: ExtractedConfig) -> None:
        """Match scenario text against known baseline files in changes/."""
        pr_4082_path = CHANGES_DIR / "pr_4082_firewall_iam.tf"
        pr_4083_path = CHANGES_DIR / "pr_4083_firewall_iam.tf"
        netflix_path = CHANGES_DIR / "allow_netflix.tf"
        safe_path = CHANGES_DIR / "demo" / "demo_safe_firewall.tf"

        if "4082" in text or "direct-db-access-rule" in text or "pci-db-sg" in text:
            if pr_4082_path.exists():
                cfg.scenario_source_path = str(pr_4082_path)
                cfg.raw_hcl = pr_4082_path.read_text(encoding="utf-8")
                if not cfg.title:
                    cfg.title = "PR-4082: Direct Database Access & IAM Role Attachment"
        elif "4083" in text or "dmz-ext-inbound-permissive" in text or "arn:aws:iam::aws:policy/AdministratorAccess" in text:
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
        return f'''# Synthesized Terraform HCL from ServiceNow Change Request
resource "panos_security_rule_group" "{rule_ident}" {{
  position = "top"

  rule {{
    name                  = "{cfg.rule_name or 'Allow-Service-Traffic'}"
    source_zones          = ["{cfg.source_zone or 'Untrust-Internet'}"]
    source_addresses      = ["{cfg.source_addresses or '0.0.0.0/0'}"]
    destination_zones     = ["{cfg.destination_zone or 'Prod-Database'}"]
    destination_addresses = ["{cfg.destination_addresses or '10.100.2.15/32'}"]
    applications          = ["{cfg.applications or 'any'}"]
    services              = ["{cfg.services or 'service-https'}"]
    action                = "{cfg.action or 'allow'}"
  }}
}}
'''

    @classmethod
    def _validate_fields(cls, cfg: ExtractedConfig) -> None:
        """Perform validation and identify risky or missing parameters."""
        cfg.warnings = []
        cfg.missing_fields = []

        if not cfg.title or cfg.title == "ServiceNow Change Request":
            cfg.missing_fields.append("Short Description / Summary")

        if cfg.domain == "NETWORK_SECURITY":
            if not cfg.rule_name:
                cfg.missing_fields.append("Firewall Rule Name")
            if not cfg.destination_zone:
                cfg.missing_fields.append("Destination Zone")
            if not cfg.destination_addresses:
                cfg.missing_fields.append("Destination Address / CIDR")

            # Risk & Ambiguity detections
            if cfg.destination_addresses.lower() in ["any", "0.0.0.0/0"]:
                cfg.warnings.append("Destination Address is wildcard 'any' (High risk of unrestricted ingress/egress)")
            if cfg.source_addresses.lower() in ["any", "0.0.0.0/0"] and cfg.destination_zone.lower() in ["prod-database", "database", "pci-db", "cui-vault"]:
                cfg.warnings.append("Source 0.0.0.0/0 into Protected Database Zone (Critical exposure)")
            if cfg.applications.lower() in ["any"]:
                cfg.warnings.append("App-ID is set to 'any' (High risk of protocol evasion; specific App-ID required)")
            if cfg.action.lower() == "allow" and "database" in cfg.destination_zone.lower() and "untrust" in cfg.source_zone.lower():
                cfg.warnings.append("Direct perimeter access to Database Tier violates PCI-DSS 1.3.1")

        elif cfg.domain == "IDENTITY_GOVERNANCE":
            if not cfg.identity_name:
                cfg.missing_fields.append("Target Identity")
            if not (cfg.requested_role or cfg.access_profile or cfg.entitlement):
                cfg.missing_fields.append("At least one requested entitlement or role")

            # Ambiguity detections
            if "contractor" in cfg.identity_name.lower() and ("admin" in cfg.requested_role.lower() or "cui" in cfg.entitlement.lower()):
                cfg.warnings.append("Contractor identity requesting privileged CUI/Admin access (Potential SoD violation)")

    # =========================================================================
    # SAMPLE PRE-LOADED TEMPLATES
    # =========================================================================

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

resource "aws_iam_role_policy_attachment" "role_attachment" {
  role       = "analytics-pipeline-role"
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
