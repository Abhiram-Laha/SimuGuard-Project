# SimuGuard AI — Security Rule Audit Matrix (Phase 4)

This document provides the independent technical audit of all security rules implemented in Phase 4 of SimuGuard AI, covering Palo Alto PAN-OS policies, AWS Security Groups, and SailPoint Identity Security Cloud governance.

---

## 1. Firewall Security Rules (FW-01 to FW-06)

| Rule ID | Rule Name | Target Component | Detection Condition | Severity | Test Case Status | Platform Awareness & Edge Case Evaluation |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **FW-01** | App-ID Deep Inspection Bypass | PAN-OS `panos_security_policy` | `action == "allow"` AND `"any" in rule.applications` | **CRITICAL** | **PASS** | Evaluates PAN-OS Layer 7 classification. Explicitly ignores `deny` rules where wildcarding is standard. Does not flag multi-app lists (e.g. `["ssl", "web-browsing"]`). |
| **FW-02** | Unrestricted Wildcard Egress Scope | PAN-OS & AWS Security Groups | • PAN-OS: Outbound to `Untrust-Internet` with destination `"any"` or `"0.0.0.0/0"`.<br>• AWS SG: `type == "egress"` with `cidr_blocks` containing `"0.0.0.0/0"`. | **HIGH / CRITICAL** | **PASS** | **Platform-Aware:**<br>• PAN-OS evaluates source zone, destination zone, direction, service, and destination CIDR scope. Scoped partner CIDRs (e.g. `52.84.120.0/22`) pass without violation.<br>• AWS SG differentiates all-ports egress (`protocol == "-1"` $\rightarrow$ **CRITICAL**) from scoped HTTPS port 443 egress (**HIGH**). |
| **FW-03** | Threat Profile Group Baseline Inspection | PAN-OS `panos_security_policy` | Allow rule traversing corporate protected zones baseline (`Trust-DMZ`, `Internal-Core`, `Restricted-Data-Vault`, `PCI-Cardholder-Zone`) with missing or `"none"` `security_profile_group`. | **HIGH** | **PASS** | **Baseline-Aware:** Compares zone against `PROTECTED_ZONES_BASELINE`. Exempt local loopback or intra-zone management rules do not trigger false violations. |
| **FW-04** | Insecure Cleartext Protocol & Port Exposure | PAN-OS & AWS Security Groups | • PAN-OS: Cleartext apps (`http`, `telnet`, `ftp`) or `service-http` without SSL context.<br>• AWS SG: Cleartext ports (21, 23, 80) or database ports (3306, 5432) exposed to `0.0.0.0/0`. | **MEDIUM / CRITICAL** | **PASS** | **Encryption-Aware:** Does **not** infer cleartext from port number alone. If application is explicitly SSL/TLS (`ssl`, `paloalto-admin-ssl`), no cleartext finding is generated. Exposing database ports directly to `0.0.0.0/0` is escalated to **CRITICAL**. |
| **FW-05** | Rule Shadowing and Redundancy Detection | PAN-OS `panos_security_policy` | Rule sequence evaluation: Preceding Rule $A$ matches a superset or identical combination of zones, CIDRs, apps, and services relative to subsequent Rule $B$. | **MEDIUM** | **PASS** | Evaluates rule order in the policy. Identifies dead code or shadowed rules where preceding broad rules eclipse subsequent specific rules. |
| **FW-06** | Cross-Zone Micro-Segmentation Violations | PAN-OS `panos_security_policy` | Correlates proposed rule with topology segmentation matrix: direct connectivity between Untrusted/DMZ/Dev zones and `Restricted-Data-Vault` or `PCI-Cardholder-Zone`. | **CRITICAL** | **PASS** | Enforces perimeter and PCI/CUI boundaries. Bypassing intermediate internal firewalls or inspection proxies is strictly prohibited and flagged **CRITICAL**. |

---

## 2. SailPoint Identity Governance Rules (SP-01 to SP-06 & SP-CORR)

| Rule ID | Rule Name | Target Component | Detection Condition | Severity | Test Case Status | Governance Semantics & Lifecycle Evaluation |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **SP-01** | In-Flight / Unapproved Access Assumption | SailPoint `access_requests` | Configuration relies on or assigns access for a request with status `PENDING_APPROVAL`, `REJECTED`, or prematurely flagged `effective_access_granted: True`. | **CRITICAL** | **PASS** | Enforces `PENDING_IS_NOT_ACCESS`. In-flight requests convey zero effective permissions and cannot be incorporated into infrastructure. |
| **SP-02** | Unprovisioned / Failed Identity Provisioning State | SailPoint `provisioning_events` | Grant provisioning event in state `REQUESTED_NOT_PROVISIONED`, `FAILED`, `PENDING_RECONCILIATION`, or `TIMEOUT`. | **HIGH** | **PASS** | Distinguishes approved from provisioned access. Downstream configurations cannot assume permissions are active until connector reconciliation confirms status `VERIFIED_ON_SOURCE`. |
| **SP-03** | Separation of Duties (SoD) Conflict Detection | SailPoint `identities`, `roles`, `entitlements` | Identity assigned toxic combinations defined in `ENTERPRISE_SOD_CATALOG`: `SOD-01` (Dev + Cloud Admin), `SOD-02` (Finance + Payment Admin), `SOD-03` (SecOps + Firewall Admin). | **CRITICAL** | **PASS** | Uses explicit conflict catalog in `sod_matrix.py`. Detects dual-control violations across correlated accounts and cross-source entitlements. |
| **SP-04** | Contractor Privileged Access Violation | SailPoint `identities` | Third-party contractor identity (`employment_type == "CONTRACTOR"`) assigned privileged profile (`sp-ap-aws-prod-admin`, `sp-ap-paloalto-firewall-admin`) or root entitlements. | **CRITICAL** | **PASS** | Prevents non-employee access to production infrastructure or root cloud permissions. Enforces contractor development sandbox isolation. |
| **SP-05** | Outstanding Access-Removal Risk | SailPoint `certifications` | Access certification review revoked an item (`REVOKED` or `REVOKED_PENDING_DEPROVISIONING`), but account or entitlement remains active on target system. | **HIGH** | **PASS** | Identifies dormant access and incomplete de-provisioning liabilities before granting new access. |
| **SP-06** | Excessive Entitlement Accumulation (Privilege Creep) | SailPoint `identities`, `entitlements` | Identity accumulated active entitlements exceeding documented departmental baseline (Engineering: 3, Finance: 2, Contractor: 1, Default: 2). | **MEDIUM** | **PASS** | Evaluates privilege accumulation over time. Flags cross-domain entitlement sprawl for manager access recertification. |
| **SP-CORR** | Missing Governance Entity Correlation | Proposed Terraform IAM Entities | Proposed IAM role or identity cannot be correlated to any authoritative identity or account in the SailPoint catalog. | **HIGH** | **PASS** | Returns `ImpactStatus.UNKNOWN`. Prevents unmapped cloud IAM roles from being silently treated as compliant or safe. |

---

## 3. Separation of Duties (SoD) Catalog (`sod_matrix.py`)

```
┌──────────┬─────────────────────────────────────┬─────────────────────────────────┬──────────┐
│ Conflict │ Conflicting Role A                  │ Conflicting Role B              │ Severity │
├──────────┼─────────────────────────────────────┼─────────────────────────────────┼──────────┤
│ SOD-01   │ Software Developer                  │ Production Cloud Administrator  │ CRITICAL │
│          │ (sp-role-developer)                 │ (sp-role-cloud-administrator)   │          │
├──────────┼─────────────────────────────────────┼─────────────────────────────────┼──────────┤
│ SOD-02   │ Financial Analyst                   │ Payment Disbursement Admin      │ CRITICAL │
│          │ (sp-role-finance-analyst)           │ (sp-role-payment-security-cust.)│          │
├──────────┼─────────────────────────────────────┼─────────────────────────────────┼──────────┤
│ SOD-03   │ SecOps Analyst / Incident Responder │ Network Firewall Administrator  │ HIGH     │
│          │ (sp-role-security-operations-anal.) │ (sp-role-network-security-eng.) │          │
└──────────┴─────────────────────────────────────┴─────────────────────────────────┴──────────┘
```

All 3 conflict definitions strictly enforce compliance with **SOX 404**, **NIST SP 800-53 AC-5**, and **PCI-DSS Req 7.1**.
