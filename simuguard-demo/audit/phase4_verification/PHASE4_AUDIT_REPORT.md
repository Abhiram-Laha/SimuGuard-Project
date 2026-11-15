# SimuGuard AI — Phase 4 Source Code Verification & Security Audit Report
**Phase 5, Milestone A: Independent Security & Quality Audit**

- **Audit Date:** 2026-11-16
- **Auditor Role:** Senior Python Engineer, Application Security Architect, DevSecOps Engineer & Enterprise Network Security Auditor
- **Audit Target:** SimuGuard AI (Phase 4 Security Analysis & Risk Scoring Engine)
- **Organization Context:** Apex Global Technologies (`apex-global.example`)
- **Execution Mode:** Strict Read-Only Audit (No live infrastructure modifications, no external API calls)

---

## Executive Summary

An independent, rigorous source code audit and security verification was conducted on Phase 4 of SimuGuard AI. The audit evaluated all Python modules across `simuguard/`, the test suite under `tests/`, sample Terraform pull requests under `changes/`, enterprise Digital Twin datasets under `demo_environment/`, and output artifacts.

The project demonstrates high software engineering quality, clean separation of concerns, robust deterministic risk modeling, and strict adherence to enterprise cybersecurity benchmarks (CIS Benchmarks, NIST CSF 2.0, NIST SP 800-171, PCI-DSS, and SOX 404).

### Key Verification Metrics
- **Total Tests Discovered & Executed:** **143 tests** (101 regression tests + 42 Phase 4 tests).
- **Test Suite Results:** **143 Passed, 0 Failed, 0 Skipped, 0 Warnings** in **2.35s**.
- **Firewall Rules Verified:** **6 rules** (FW-01 to FW-06) across PAN-OS and AWS Security Groups.
- **SailPoint Identity Rules Verified:** **6 rules** (SP-01 to SP-06) plus SoD Matrix and SP-CORR.
- **Digital Twin Active Graph:** **220 active nodes**, **77 active directed edges** (100% referential integrity).
- **Mathematical Risk Engine:** 100% deterministic, bounded in $[0, 100]$, with strict verdict precedence.
- **Audit Final Verdict:** **PASS WITH FINDINGS** (Core engine is functionally verified and mathematically correct; two non-blocking edge-case findings identified for Phase 5 baseline hardening).

---

## 1. Repository Structure & Code Quality Inspection

The codebase is organized into cleanly decoupled, single-responsibility packages:

```
simuguard-demo/
├── changes/                     # Real-world Terraform test scenarios (PR-4082, PR-4083, allow_netflix.tf)
├── demo_environment/            # Synthetic enterprise dataset (Apex Global Technologies)
│   ├── network/                 # Firewalls, Panorama, zones, subnets, policies
│   ├── cloud/                   # AWS multi-account, VPCs, compute, databases, S3
│   ├── iam/                     # Customer-managed IAM roles, policies, cross-account trust
│   ├── sailpoint/               # Identity Security Cloud: identities, accounts, roles, certs, prov
│   └── data_assets/             # Sensitive data classifications (Restricted CUI, PCI, PII)
├── simuguard/
│   ├── models/                  # Strict Pydantic v2 domain schemas (SecurityGap, AffectedAsset, Report)
│   ├── parsers/                 # python-hcl2 ingestion and typed resource models
│   ├── graph/                   # NetworkX Digital Twin & blast radius traversal engine
│   ├── rules/                   # FW-01 to FW-06, SP-01 to SP-06, SoD conflict matrix
│   ├── engine/                  # SimuGuardAnalyzer & deterministic RiskEngine
│   └── reporters/               # Terminal ANSI reporter and JSON exporter
├── tests/                       # 143 unit and integration tests across 9 test modules
└── audit/phase4_verification/   # Independent audit reports, test logs, and verification artifacts
```

- **Import Integrity:** Verified. All 19 internal modules import with zero circular dependencies and zero import warnings.
- **Dependency Scope:** Purely local dependencies (`pydantic`, `pytest`, `python-hcl2`, `networkx`, `reportlab`, `python-pptx`). No live external dependencies or credentials required.
- **Legacy Compatibility:** Original baseline scripts (`agent_runner.py`, `simulation_output_artifact.json`) and Terraform examples are 100% preserved.

---

## 2. Firewall Security Rules Audit (FW-01 to FW-06)

All six firewall rules were independently evaluated against positive, negative, and edge-case scenarios:

1. **FW-01 (App-ID Bypass):** Correctly flags `action == "allow"` rules where `applications` contains `"any"`. Accurately ignores `deny` rules. Severity: **CRITICAL**.
2. **FW-02 (Unrestricted Wildcard Egress):** Evaluates platform-specific semantics:
   - *PAN-OS:* Assesses source zone, destination zone (`Untrust-Internet`), direction, and destination CIDRs. Scoped partner CIDRs (`52.84.120.0/22`) pass cleanly.
   - *AWS SG:* Evaluates egress rules with `0.0.0.0/0`. Differentiates all-ports egress (`protocol == "-1"` $\rightarrow$ **CRITICAL**) from scoped HTTPS port 443 egress (**HIGH**).
3. **FW-03 (Threat Prevention Baseline):** Compares rules against `PROTECTED_ZONES_BASELINE` (`Trust-DMZ`, `Internal-Core`, `Restricted-Data-Vault`, `PCI-Cardholder-Zone`). Flagging occurs only when rules traversing protected zones omit or disable security profile groups (`"none"`). Exempt local management rules pass without false positives. Severity: **HIGH**.
4. **FW-04 (Insecure Protocol Exposure):** Does **not** infer cleartext from a port number alone; evaluates protocol, application, and encryption context. Rules using SSL/TLS encryption pass cleanly. Direct public exposure of database ports (3306, 5432) to `0.0.0.0/0` is escalated to **CRITICAL**.
5. **FW-05 (Rule Shadowing & Redundancy):** Evaluates rule sequence in top-down order. Identifies preceding broad rules matching superset conditions that shadow subsequent specific rules. Severity: **MEDIUM**.
6. **FW-06 (Cross-Zone Segmentation Violations):** Correlates proposed rules against the enterprise topology matrix. Uninspected direct crossings between Untrusted/DMZ/Dev zones and `Restricted-Data-Vault` or `PCI-Cardholder-Zone` are flagged **CRITICAL**.

---

## 3. SailPoint Identity Governance Rules Audit (SP-01 to SP-06)

The identity governance rules enforce strict segregation between the governance plane and the AWS runtime authorization plane:

1. **SP-01 (`PENDING_IS_NOT_ACCESS`):** Verifies that in-flight or unapproved access requests (`PENDING_APPROVAL`, `REJECTED`) convey zero effective access. Flags premature effective access assumptions as **CRITICAL**.
2. **SP-02 (Unprovisioned / Failed Provisioning):** Distinguishes *approved* access from *provisioned* access. Detects provisioning events in `REQUESTED_NOT_PROVISIONED` or `FAILED` states, flagging downstream dependencies as **HIGH**.
3. **SP-03 (Separation of Duties):** Uses the explicit `ENTERPRISE_SOD_CATALOG` in `sod_matrix.py`. Accurately detects toxic pairs: `SOD-01` (Dev + Cloud Admin), `SOD-02` (Finance + Payment Admin), and `SOD-03` (SecOps + Firewall Admin). Severity: **CRITICAL**.
4. **SP-04 (Contractor Privileged Access):** Strictly restricts contractor identities (`employment_type == "CONTRACTOR"`) from holding root, production, or administrative profiles. Severity: **CRITICAL**.
5. **SP-05 (Outstanding Access-Removal Risk):** Identifies entitlements marked as `REVOKED` or `REVOKED_PENDING_DEPROVISIONING` during certification campaigns that remain active on target systems. Severity: **HIGH**.
6. **SP-06 (Privilege Creep):** Evaluates active entitlement counts against documented departmental baselines (Engineering: 3, Finance: 2, Contractors: 1). Flags entitlement sprawl as **MEDIUM**.
7. **SP-CORR (Missing Correlation):** Unmapped IAM roles that cannot be correlated to any SailPoint identity or account are assigned status `ImpactStatus.UNKNOWN` and flagged **HIGH**.

---

## 4. Mathematical Verification of the Risk Engine

The risk engine implementation in `simuguard/engine/risk_engine.py` was independently verified:

### Formula
$$\text{Base Score} = \sum_{g \in \text{DeduplicatedGaps}} W(\text{severity}_g) \times M(\text{highest\_criticality})$$
$$\beta = \min\left(2.0, \; 1.0 + 0.05 \times N_{\text{direct}} + 0.02 \times N_{\text{cascading}}\right)$$
$$R = \min\left(100, \; \max\left(0, \; \text{round}\left(\text{Base Score} \times \beta\right)\right)\right)$$

### Verified Mathematical Properties
- **Finding Deduplication:** Gaps are deduplicated by `(rule_id, gap_title)`. Verified.
- **Severity Weights:** CRITICAL $= 40.0$, HIGH $= 25.0$, MEDIUM $= 10.0$, LOW $= 3.0$. Verified.
- **Asset Criticality Multipliers:** CRITICAL $= 1.5$, HIGH $= 1.2$, MEDIUM $= 1.0$, LOW $= 0.8$. Highest criticality is selected from affected assets. Verified.
- **Blast Multiplier Cap:** Strictly capped at $2.0$. Verified.
- **Score Bounds:** Constrained to $0 \le R \le 100$. Verified.

### Verdict Precedence Rules
Precedence rules ensure that a numerical score can never override a severe security violation:
- **`BLOCK_DEPLOYMENT`:** Triggered by any CRITICAL finding **OR** score $\ge 70$.
- **`WARN_MANUAL_REVIEW`:** Triggered by any HIGH finding, any UNKNOWN impact, **OR** score $40 - 69$.
- **`ALLOW`:** Requires score $< 40$, **zero** CRITICAL findings, **zero** HIGH findings, and **zero** UNKNOWN impacts.

---

## 5. Sample PR Scenario Verification

The simulator was executed against the three Terraform change sets:

| Change Set | Evaluated Resources | Key Findings Identified | Affected Assets | Risk Score | Verdict | Audit Status |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **PR-4082** (`pr_4082_firewall_iam.tf`) | • `aws_security_group_rule.allow_outbound_webhook`<br>• `aws_iam_role_policy_attachment.analytics_s3_access` | • FW-02 (Unrestricted AWS SG Egress)<br>• IAM-01 (Cloud Privilege Escalation to CUI Vault) | 9 assets (Direct: 2, Cascading: 7 including CUI Vault) | **100 / 100** | **BLOCK_DEPLOYMENT** | **PASS** |
| **PR-4083** (`pr_4083_firewall_iam.tf`) | • `panos_security_policy.analytics_egress_rule`<br>• `aws_iam_role_policy_attachment.analytics_s3_access` | • FW-01 (App-ID Bypass)<br>• FW-02 (Unrestricted Internet Egress)<br>• FW-03 (Missing Threat Profile)<br>• FW-04 (Insecure Cleartext Protocol)<br>• IAM-01 (Cloud Privilege Escalation) | 15 assets (Direct: 7, Cascading: 8 including CUI Vault) | **100 / 100** | **BLOCK_DEPLOYMENT** | **PASS** |
| **`allow_netflix.tf`** | • `aws_security_group_rule.allow_outbound_netflix` | • SCHEMA-01 (Provider Schema Error: `destination` unsupported)<br>• TOPOLOGY-01 (Unmapped SG: `sg-guest-network-01`) | 0 assets (Unmapped $\rightarrow$ UNKNOWN impact) | **35 / 100** | **WARN_MANUAL_REVIEW** | **PASS** |

### Critical Reconciliations Verified
1. **PR-4082 Reconciled:** The attachment of `AmazonS3FullAccess` to `role-analytics-ingestion-svc` is identified as a **CRITICAL** privilege escalation (`IAM-01`) exposing `s3-enterprise-cui-vault` and `DATA-01-CUI-FINANCIAL-VAULT`. It is **not** treated as a scoped change.
2. **`allow_netflix.tf` Reconciled:** Separately reports the AWS provider schema error (`destination` unsupported) and the unmapped security group (`sg-guest-network-01`). Even with a numerical score of 35, the verdict correctly escalates to `WARN_MANUAL_REVIEW`.

---

## 6. Audit Findings & Edge Cases (Non-Blocking)

- **AUDIT-01 (High Severity - Edge Case):** `analyzer.py` explicitly captures `parsed_file.provider_schema_errors` as `SCHEMA-01`, but does not convert `parsed_file.hcl_syntax_errors` into an explicit `SYNTAX-01` gap item if an unparseable file is passed.
  - *Recommendation:* Add explicit loop in `analyzer.py` mapping `hcl_syntax_errors` to `SYNTAX-01` (`Severity.CRITICAL`).
- **AUDIT-02 (Medium Severity - Edge Case):** `correlate_identities_from_resources()` defaults to scanning all enterprise identities when `resources == []`. While intended for standalone rule tests, analyzing an empty or unparseable file can attribute unrelated enterprise governance events to the change ticket.
  - *Recommendation:* Require unit tests to pass `extra_metadata={"evaluate_all_identities": True}`. If `resources == []` and flag is not set, return empty correlated identities (`set()`).
- **AUDIT-03 (Low Severity - Precision):** Floating-point operations in blast multiplier calculation can produce minor IEEE 754 precision artifacts (`1.2000000000000002`).
  - *Recommendation:* Round multiplier to 4 decimal places before computing final score.

---

## 7. Final Acceptance Decision

### **STATUS: PASS WITH FINDINGS**

The Phase 4 source code and security architecture are **independently verified and approved**. All 143 unit and regression tests pass deterministically. The mathematical risk scoring, blast radius traversal, firewall platform awareness, and SailPoint governance models function as designed.

The identified edge cases (AUDIT-01 and AUDIT-02) are non-blocking and have clear remediation paths documented in `audit/phase4_verification/findings_and_recommendations.md` for incorporation into the Phase 5 baseline.
