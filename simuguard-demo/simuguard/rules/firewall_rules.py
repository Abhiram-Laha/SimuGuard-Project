"""Firewall security analysis rules for PAN-OS policies and AWS Security Groups.

Platform-aware implementation covering:
- FW-01: App-ID Deep Inspection Bypass
- FW-02: Unrestricted Wildcard Egress
- FW-03: Threat Prevention Profile Baseline Inspection
- FW-04: Insecure Cleartext Protocol & Port Exposure
- FW-05: Rule Shadowing & Redundancy Detection
- FW-06: Cross-Zone Micro-Segmentation Violations
"""

from typing import Any, Dict, List, Optional, Set
from simuguard.models.enums import Severity
from simuguard.models.security_gap import SecurityGap
from simuguard.parsers.resource_models import (
    AwsSecurityGroupRuleResource,
    NormalizedResource,
    PanosSecurityPolicyResource,
    PanosSecurityPolicyRule,
)
from simuguard.rules.base_rule import BaseRule, RuleEvaluationContext


# Protected zones requiring mandatory Threat Prevention Profiles per corporate baseline
PROTECTED_ZONES_BASELINE: Set[str] = {
    "Trust-DMZ",
    "zone-trust-dmz",
    "Internal-Core",
    "zone-internal-core",
    "Restricted-Data-Vault",
    "zone-restricted-data-vault",
    "PCI-Cardholder-Zone",
    "zone-pci-cardholder",
}

# Forbidden cross-zone micro-segmentation pairs (direct flow prohibited)
FORBIDDEN_ZONE_FLOWS: List[Dict[str, Any]] = [
    {
        "source": {"Untrust-Internet", "zone-untrust-internet"},
        "destination": {"Restricted-Data-Vault", "zone-restricted-data-vault"},
        "reason": "Direct Internet ingress to the Restricted Data Vault is strictly prohibited.",
        "severity": Severity.CRITICAL,
    },
    {
        "source": {"Untrust-Internet", "zone-untrust-internet"},
        "destination": {"PCI-Cardholder-Zone", "zone-pci-cardholder"},
        "reason": "Direct Internet ingress to PCI Cardholder Data Environment violates PCI-DSS Req 1.3.",
        "severity": Severity.CRITICAL,
    },
    {
        "source": {"Trust-DMZ", "zone-trust-dmz"},
        "destination": {"Restricted-Data-Vault", "zone-restricted-data-vault"},
        "reason": "Direct DMZ-to-Vault communication bypasses internal segmentation firewall inspection proxies.",
        "severity": Severity.CRITICAL,
    },
    {
        "source": {"Trust-DMZ", "zone-trust-dmz"},
        "destination": {"PCI-Cardholder-Zone", "zone-pci-cardholder"},
        "reason": "Direct DMZ-to-PCI flow violates cardholder data isolation boundary.",
        "severity": Severity.CRITICAL,
    },
    {
        "source": {"Dev-VPC-Zone", "zone-dev-vpc"},
        "destination": {"Restricted-Data-Vault", "zone-restricted-data-vault"},
        "reason": "Development environments must never route directly to production CUI vaults.",
        "severity": Severity.CRITICAL,
    },
]


class PanosAppIdBypassRule(BaseRule):
    """FW-01: Detects PAN-OS security policies bypassing Layer 7 App-ID inspection."""

    rule_id = "FW-01"
    name = "PAN-OS App-ID Deep Inspection Bypass"
    description = (
        "Flags PAN-OS security policies where application is set to 'any', "
        "bypassing Layer 7 signature inspection and allowing arbitrary protocol tunneling."
    )
    severity = Severity.CRITICAL
    compliance_frameworks = [
        "CIS Palo Alto Firewall Benchmark v1.1.0 (Rule 4.1)",
        "NIST CSF 2.0 PR.PT-04",
        "NIST SP 800-171 3.13.1",
    ]

    def evaluate(
        self,
        resources: List[NormalizedResource],
        context: RuleEvaluationContext,
    ) -> List[SecurityGap]:
        findings: List[SecurityGap] = []

        for res in resources:
            if not isinstance(res, PanosSecurityPolicyResource):
                continue

            for rule in res.rules:
                if rule.action.strip().lower() != "allow":
                    continue

                # Check if applications list contains "any"
                apps_lower = [a.strip().lower() for a in rule.applications]
                if "any" in apps_lower:
                    findings.append(
                        SecurityGap(
                            rule_id=self.rule_id,
                            severity=self.severity,
                            gap_title=f"PAN-OS App-ID Deep Inspection Bypass: Rule '{rule.name}'",
                            technical_impact=(
                                f"Setting 'applications = [\"any\"]' in rule '{rule.name}' disables Palo Alto "
                                "Layer 7 App-ID deep packet classification. Malicious payloads and non-standard "
                                "protocols (including C2 tunnels) can bypass firewall inspection across "
                                f"zones {rule.source_zones} -> {rule.destination_zones}."
                            ),
                            compliance_violation="CIS Palo Alto Firewall Benchmark v1.1.0 (Rule 4.1) & NIST CSF 2.0 PR.PT-04",
                            remediation_guidance=(
                                f"Explicitly specify required App-IDs (e.g. applications = [\"ssl\", \"web-browsing\"]) "
                                f"in rule '{rule.name}' instead of wildcard 'any'."
                            ),
                        )
                    )

        return findings


class UnrestrictedEgressRule(BaseRule):
    """FW-02: Detects unrestricted wildcard egress across PAN-OS policies and AWS Security Groups."""

    rule_id = "FW-02"
    name = "Unrestricted Wildcard Egress Scope"
    description = (
        "Flags egress rules that expose internal or DMZ workloads to wildcard destinations (0.0.0.0/0 or 'any') "
        "without destination scoping or egress proxying."
    )
    severity = Severity.HIGH
    compliance_frameworks = [
        "CIS AWS Benchmark v1.4.0 (Rule 5.3)",
        "CIS Palo Alto Firewall Benchmark v1.1.0 (Rule 4.3)",
        "NIST SP 800-171 3.13.6",
    ]

    def evaluate(
        self,
        resources: List[NormalizedResource],
        context: RuleEvaluationContext,
    ) -> List[SecurityGap]:
        findings: List[SecurityGap] = []

        for res in resources:
            # 1. Platform-aware check for PAN-OS policies
            if isinstance(res, PanosSecurityPolicyResource):
                for rule in res.rules:
                    if rule.action.strip().lower() != "allow":
                        continue

                    # Evaluate source zone, destination zone, direction, service, and destination scope
                    dest_zones_lower = [z.strip().lower() for z in rule.destination_zones]
                    is_targeting_untrust = any(
                        "untrust" in z or "internet" in z for z in dest_zones_lower
                    )
                    dest_addrs_lower = [a.strip().lower() for a in rule.destination_addresses]
                    has_wildcard_dest = any(
                        a in ["any", "0.0.0.0/0", "::/0"] for a in dest_addrs_lower
                    )

                    if is_targeting_untrust and has_wildcard_dest:
                        findings.append(
                            SecurityGap(
                                rule_id=self.rule_id,
                                severity=self.severity,
                                gap_title=f"Unrestricted Internet Egress: PAN-OS Rule '{rule.name}'",
                                technical_impact=(
                                    f"Rule '{rule.name}' permits outbound traffic from source zones {rule.source_zones} "
                                    f"to Untrusted Internet with unrestricted wildcard destination addresses {rule.destination_addresses}. "
                                    "Workloads can communicate with arbitrary external IP addresses, facilitating data exfiltration."
                                ),
                                compliance_violation="CIS Palo Alto Firewall Benchmark v1.1.0 (Rule 4.3) & NIST SP 800-171 3.13.6",
                                remediation_guidance=(
                                    f"Scope destination_addresses in rule '{rule.name}' to verified partner CIDRs, "
                                    "or route egress traffic through an outbound filtering proxy."
                                ),
                            )
                        )

            # 2. Platform-aware check for AWS Security Group rules
            elif isinstance(res, AwsSecurityGroupRuleResource):
                is_egress = (res.rule_type or "").strip().lower() == "egress"
                if not is_egress:
                    continue

                has_wildcard_cidr = (
                    "0.0.0.0/0" in res.cidr_blocks or "::/0" in res.ipv6_cidr_blocks
                )
                if has_wildcard_cidr:
                    # Check service/port scope
                    is_all_ports = res.protocol in ["-1", "all"] or (
                        res.from_port in [0, None] and res.to_port in [0, 65535, None]
                    )
                    rule_sev = Severity.CRITICAL if is_all_ports else Severity.HIGH

                    findings.append(
                        SecurityGap(
                            rule_id=self.rule_id,
                            severity=rule_sev,
                            gap_title=f"Unrestricted AWS Security Group Egress: '{res.resource_name}'",
                            technical_impact=(
                                f"AWS Security Group rule '{res.resource_name}' on SG '{res.security_group_id}' allows "
                                f"egress to '0.0.0.0/0' on protocol '{res.protocol}' ports {res.from_port}-{res.to_port}. "
                                "Enables unrestricted outbound network communication to any host on the public internet."
                            ),
                            compliance_violation="CIS AWS Foundations Benchmark v1.4.0 (Rule 5.3) & NIST CSF 2.0 PR.AC-05",
                            remediation_guidance=(
                                f"Restrict cidr_blocks on '{res.resource_name}' to specific target service CIDRs, "
                                "VPC endpoints, or AWS Prefix Lists."
                            ),
                        )
                    )

        return findings


class ThreatProfileInspectionRule(BaseRule):
    """FW-03: Validates PAN-OS Threat Prevention profile groups against security baseline."""

    rule_id = "FW-03"
    name = "PAN-OS Threat Prevention Profile Group Baseline Inspection"
    description = (
        "Validates that PAN-OS allow rules traversing protected security zones attach an active "
        "Security Profile Group (Antivirus, Anti-Spyware, Vulnerability Protection, URL, WildFire)."
    )
    severity = Severity.HIGH
    compliance_frameworks = [
        "CIS Palo Alto Firewall Benchmark v1.1.0 (Rule 4.2)",
        "NIST SP 800-171 3.13.1",
        "NIST SP 800-53 SC-7",
    ]

    def evaluate(
        self,
        resources: List[NormalizedResource],
        context: RuleEvaluationContext,
    ) -> List[SecurityGap]:
        findings: List[SecurityGap] = []

        for res in resources:
            if not isinstance(res, PanosSecurityPolicyResource):
                continue

            for rule in res.rules:
                if rule.action.strip().lower() != "allow":
                    continue

                # Compare against applicable security baseline: check if source or dest is in protected baseline
                src_protected = any(z in PROTECTED_ZONES_BASELINE for z in rule.source_zones)
                dst_protected = any(z in PROTECTED_ZONES_BASELINE for z in rule.destination_zones)

                # Only enforce baseline when rule traverses a protected enterprise zone
                if not (src_protected or dst_protected):
                    continue

                # Evaluate profile group
                prof_group = (rule.security_profile_group or "").strip()
                is_disabled_or_missing = prof_group == "" or prof_group.lower() in [
                    "none",
                    "disabled",
                    "null",
                ]

                if is_disabled_or_missing:
                    findings.append(
                        SecurityGap(
                            rule_id=self.rule_id,
                            severity=self.severity,
                            gap_title=f"Missing Threat Prevention Profile: Rule '{rule.name}'",
                            technical_impact=(
                                f"Palo Alto rule '{rule.name}' between {rule.source_zones} and {rule.destination_zones} "
                                f"omits or disables security_profile_group ('{prof_group or 'none'}'). "
                                "Traffic flows without deep packet inspection, antivirus, anti-spyware, "
                                "or WildFire zero-day sandbox analysis."
                            ),
                            compliance_violation="CIS Palo Alto Firewall Benchmark v1.1.0 (Rule 4.2) & NIST SP 800-171 3.13.1",
                            remediation_guidance=(
                                f"Attach an approved security profile group (e.g. security_profile_group = "
                                f"'corporate-threat-prevention-standard') to rule '{rule.name}'."
                            ),
                        )
                    )

        return findings


class InsecureProtocolExposureRule(BaseRule):
    """FW-04: Evaluates protocol, application, and encryption context to detect cleartext exposure."""

    rule_id = "FW-04"
    name = "Insecure Cleartext Protocol & Port Exposure"
    description = (
        "Evaluates protocol, application, and encryption context to flag unencrypted cleartext "
        "protocols (HTTP, Telnet, FTP) and direct database exposure across zone boundaries."
    )
    severity = Severity.MEDIUM
    compliance_frameworks = [
        "NIST SP 800-52 Rev 2 (Guidelines for TLS)",
        "NIST SP 800-171 3.13.8",
        "PCI-DSS Req 4.1",
    ]

    CLEARTEXT_APPS: Set[str] = {"http", "telnet", "ftp", "tftp", "rsh"}
    CLEARTEXT_PORTS: Set[int] = {21, 23, 80}
    DATABASE_PORTS: Set[int] = {3306, 5432, 1433, 1521, 27017}

    def evaluate(
        self,
        resources: List[NormalizedResource],
        context: RuleEvaluationContext,
    ) -> List[SecurityGap]:
        findings: List[SecurityGap] = []

        for res in resources:
            if isinstance(res, PanosSecurityPolicyResource):
                for rule in res.rules:
                    if rule.action.strip().lower() != "allow":
                        continue

                    apps_lower = [a.strip().lower() for a in rule.applications]
                    services_lower = [s.strip().lower() for s in rule.services]

                    # Contextual encryption check: do not flag if application is explicitly SSL/TLS or SSH
                    has_encryption_app = any(
                        app in ["ssl", "ssh", "ipsec", "https", "paloalto-admin-ssl"]
                        for app in apps_lower
                    )

                    # Flag cleartext administrative protocols
                    has_cleartext_app = any(app in self.CLEARTEXT_APPS for app in apps_lower)
                    has_cleartext_service = any("service-http" in s for s in services_lower)

                    if (has_cleartext_app or has_cleartext_service) and not has_encryption_app:
                        findings.append(
                            SecurityGap(
                                rule_id=self.rule_id,
                                severity=self.severity,
                                gap_title=f"Insecure Cleartext Protocol: Rule '{rule.name}'",
                                technical_impact=(
                                    f"Rule '{rule.name}' allows unencrypted cleartext application traffic "
                                    f"{rule.applications} with services {rule.services}. Credentials and payload "
                                    "data can be intercepted via network eavesdropping."
                                ),
                                compliance_violation="NIST SP 800-52 Rev 2 & PCI-DSS Req 4.1",
                                remediation_guidance=(
                                    f"Require encrypted protocols (e.g. applications = [\"ssl\"]) and replace "
                                    f"cleartext services with secure equivalents in rule '{rule.name}'."
                                ),
                            )
                        )

            elif isinstance(res, AwsSecurityGroupRuleResource):
                # Evaluate port, protocol, and direction
                from_p = res.from_port
                to_p = res.to_port
                if from_p is not None and to_p is not None:
                    # Check cleartext ports (e.g. port 80 HTTP, port 23 Telnet)
                    for port in self.CLEARTEXT_PORTS:
                        if from_p <= port <= to_p:
                            findings.append(
                                SecurityGap(
                                    rule_id=self.rule_id,
                                    severity=Severity.LOW,
                                    gap_title=f"Cleartext Port Exposure: SG Rule '{res.resource_name}' (Port {port})",
                                    technical_impact=(
                                        f"Rule '{res.resource_name}' on SG '{res.security_group_id}' opens cleartext "
                                        f"port {port}. Cleartext protocols lack transport layer security."
                                    ),
                                    compliance_violation="NIST SP 800-52 Rev 2 & NIST CSF 2.0 PR.DS-02",
                                    remediation_guidance=(
                                        f"Upgrade service on '{res.resource_name}' to HTTPS/TLS on port 443."
                                    ),
                                )
                            )

                    # Check database port direct exposure to 0.0.0.0/0
                    if "0.0.0.0/0" in res.cidr_blocks:
                        for db_port in self.DATABASE_PORTS:
                            if from_p <= db_port <= to_p:
                                findings.append(
                                    SecurityGap(
                                        rule_id=self.rule_id,
                                        severity=Severity.CRITICAL,
                                        gap_title=f"Database Port Public Exposure: SG Rule '{res.resource_name}' (Port {db_port})",
                                        technical_impact=(
                                            f"Database port {db_port} is exposed to the public internet ('0.0.0.0/0') "
                                            f"by SG rule '{res.resource_name}'. Exposes internal relational database "
                                            "to direct external brute-force and remote exploitation."
                                        ),
                                        compliance_violation="CIS AWS Foundations Benchmark v1.4.0 (Rule 5.1)",
                                        remediation_guidance=(
                                            f"Remove '0.0.0.0/0' from '{res.resource_name}' and restrict database "
                                            "ingress exclusively to verified application security groups."
                                        ),
                                    )
                                )

        return findings


class RuleShadowingRule(BaseRule):
    """FW-05: Implements rule-shadowing checks using rule order and relevant matching conditions."""

    rule_id = "FW-05"
    name = "Firewall Rule Shadowing and Redundancy Detection"
    description = (
        "Evaluates PAN-OS rule evaluation order to identify rules that are shadowed or rendered "
        "redundant by preceding broader rules."
    )
    severity = Severity.MEDIUM
    compliance_frameworks = [
        "CIS Palo Alto Firewall Benchmark v1.1.0 (Rule 4.4)",
        "NIST SP 800-41 Rev 1 (Guidelines on Firewalls)",
    ]

    def _matches_superset(self, set_a: List[str], set_b: List[str]) -> bool:
        """Return True if set_a is a wildcard 'any' or contains all elements of set_b."""
        sa = {x.strip().lower() for x in set_a}
        sb = {x.strip().lower() for x in set_b}
        if "any" in sa:
            return True
        return sb.issubset(sa)

    def evaluate(
        self,
        resources: List[NormalizedResource],
        context: RuleEvaluationContext,
    ) -> List[SecurityGap]:
        findings: List[SecurityGap] = []

        for res in resources:
            if not isinstance(res, PanosSecurityPolicyResource):
                continue

            rules = res.rules
            num_rules = len(rules)

            for i in range(num_rules):
                preceding_rule = rules[i]
                for j in range(i + 1, num_rules):
                    subsequent_rule = rules[j]

                    # Check if preceding rule matches superset on all matching criteria
                    src_zones_match = self._matches_superset(
                        preceding_rule.source_zones, subsequent_rule.source_zones
                    )
                    src_addrs_match = self._matches_superset(
                        preceding_rule.source_addresses, subsequent_rule.source_addresses
                    )
                    dst_zones_match = self._matches_superset(
                        preceding_rule.destination_zones, subsequent_rule.destination_zones
                    )
                    dst_addrs_match = self._matches_superset(
                        preceding_rule.destination_addresses, subsequent_rule.destination_addresses
                    )
                    apps_match = self._matches_superset(
                        preceding_rule.applications, subsequent_rule.applications
                    )
                    services_match = self._matches_superset(
                        preceding_rule.services, subsequent_rule.services
                    )

                    is_shadowed = (
                        src_zones_match
                        and src_addrs_match
                        and dst_zones_match
                        and dst_addrs_match
                        and apps_match
                        and services_match
                    )

                    if is_shadowed:
                        act_a = preceding_rule.action.strip().lower()
                        act_b = subsequent_rule.action.strip().lower()
                        relationship = "redundant" if act_a == act_b else "shadowed"

                        findings.append(
                            SecurityGap(
                                rule_id=self.rule_id,
                                severity=self.severity,
                                gap_title=f"Rule Shadowing: '{subsequent_rule.name}' is {relationship} by '{preceding_rule.name}'",
                                technical_impact=(
                                    f"Subsequent rule '{subsequent_rule.name}' will never be evaluated for matching "
                                    f"traffic because preceding rule '{preceding_rule.name}' has broader or identical "
                                    f"matching conditions. Rule '{subsequent_rule.name}' constitutes dead policy."
                                ),
                                compliance_violation="NIST SP 800-41 Rev 1 & CIS Palo Alto Benchmark Rule 4.4",
                                remediation_guidance=(
                                    f"Reorder rules in Panorama so that specific rule '{subsequent_rule.name}' "
                                    f"is evaluated before broader rule '{preceding_rule.name}', or delete redundant rule."
                                ),
                            )
                        )

        return findings


class CrossZoneSegmentationRule(BaseRule):
    """FW-06: Establishes cross-zone micro-segmentation violations using policy and topology evidence."""

    rule_id = "FW-06"
    name = "Cross-Zone Micro-Segmentation Policy Violation"
    description = (
        "Validates proposed firewall rules against the enterprise zone segmentation topology, "
        "flagging uninspected direct connectivity between untrusted zones and sensitive PCI/CUI vault zones."
    )
    severity = Severity.CRITICAL
    compliance_frameworks = [
        "PCI-DSS Req 1.3 (Prohibit direct public access to cardholder data)",
        "NIST SP 800-171 3.13.2 (Employ architectural designs for boundary protection)",
        "NIST CSF 2.0 PR.AC-05",
    ]

    def evaluate(
        self,
        resources: List[NormalizedResource],
        context: RuleEvaluationContext,
    ) -> List[SecurityGap]:
        findings: List[SecurityGap] = []

        for res in resources:
            if not isinstance(res, PanosSecurityPolicyResource):
                continue

            for rule in res.rules:
                if rule.action.strip().lower() != "allow":
                    continue

                for flow in FORBIDDEN_ZONE_FLOWS:
                    src_match = any(z in flow["source"] for z in rule.source_zones)
                    dst_match = any(z in flow["destination"] for z in rule.destination_zones)

                    if src_match and dst_match:
                        findings.append(
                            SecurityGap(
                                rule_id=self.rule_id,
                                severity=flow["severity"],
                                gap_title=f"Prohibited Cross-Zone Segmentation: Rule '{rule.name}'",
                                technical_impact=(
                                    f"Rule '{rule.name}' directly connects source zones {rule.source_zones} to "
                                    f"sensitive destination zones {rule.destination_zones}. {flow['reason']} "
                                    "Bypasses internal multi-tier inspection and perimeter isolation boundaries."
                                ),
                                compliance_violation="PCI-DSS Req 1.3 & NIST SP 800-171 3.13.2",
                                remediation_guidance=(
                                    f"Remove direct cross-zone policy '{rule.name}'. Inter-zone traffic must route "
                                    "exclusively through internal segmentation firewall inspection proxies."
                                ),
                            )
                        )

        return findings
