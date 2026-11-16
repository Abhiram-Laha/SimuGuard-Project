# SimuGuard AI — Security Model & Mathematical Risk Methodology
**Apex Global Technologies Enterprise Cybersecurity Architecture**

---

## 1. Security Philosophy & Invariants

SimuGuard AI enforces the following non-negotiable security principles:

1. **Air-Gapped Local Simulation**: Never require cloud credentials, production API keys, or live outbound connections. All evaluations are performed against verified local synthetic Digital Twin models.
2. **Determinism**: Identical configurations evaluated against identical Digital Twin topologies produce 100% identical risk scores and deployment verdicts. No stochastic or probabilistic scoring models are used.
3. **Verdict Precedence Over Numerical Scores**: Severe security violations (CRITICAL findings, toxic Separation of Duties, or unmapped impact relationships) unconditionally override numerical thresholds. A low numerical score can never force an `ALLOW` verdict if a critical vulnerability is present.
4. **Unknown Is Never Safe**: Unmapped resources, missing CIDR classifications, or unverified identities are categorized as `ImpactStatus.UNKNOWN`, triggering mandatory manual review (`WARN_MANUAL_REVIEW`). Missing topology data is never treated as proof of isolation.
5. **Non-Destructive Remediation**: Automated candidate synthesis operates strictly on deep copies of configurations and ephemeral graph overlays. Original scenario files and enterprise datasets are strictly immutable.

---

## 2. Security Rule Catalog

### A. Network Security Rules (`FW-01` to `FW-06`)

| Rule ID | Severity | Policy Title | Compliance Benchmark | Technical Impact Evaluated |
| :--- | :---: | :--- | :--- | :--- |
| **`FW-01`** | **CRITICAL** | PAN-OS App-ID Deep Inspection Bypass | CIS Palo Alto Firewall v1.1.0 (4.1)<br>NIST CSF 2.0 PR.PT-04 | Setting `applications = ["any"]` on `allow` rules disables Palo Alto Layer 7 App-ID deep packet classification, allowing arbitrary non-standard protocols and C2 tunnels. |
| **`FW-02`** | **HIGH / CRITICAL** | Unrestricted Internet Egress | CIS Palo Alto Benchmark (4.3)<br>NIST SP 800-171 3.13.6 | Permitting egress to `0.0.0.0/0` or `destination_addresses = ["any"]` without partner CIDR scoping. (AWS SG egress with `protocol = "-1"` escalates to CRITICAL). |
| **`FW-03`** | **HIGH** | Missing Threat Prevention Profile Group | CIS Palo Alto Benchmark (4.2)<br>NIST SP 800-171 3.13.1 | Rules traversing protected zones (`Trust-DMZ`, `Internal-Core`, `Restricted-Data-Vault`, `PCI-Cardholder-Zone`) that omit or set `security_profile_group = "none"`. |
| **`FW-04`** | **MEDIUM / CRITICAL** | Insecure Cleartext Protocol Exposure | NIST SP 800-52 Rev 2<br>PCI-DSS Req 4.1 | Permitting cleartext protocols (HTTP, Telnet) across network boundaries. Exposure of direct database ports (3306, 5432) to `0.0.0.0/0` escalates to CRITICAL. |
| **`FW-05`** | **MEDIUM** | Security Rule Shadowing & Redundancy | CIS Palo Alto Benchmark (4.4) | Preceding broad rules matching superset conditions that shadow and render subsequent specific rules unreachable. |
| **`FW-06`** | **CRITICAL** | Cross-Zone Segmentation Violation | NIST SP 800-53 SC-7<br>PCI-DSS Req 1.3 | Uninspected direct crossings between Untrusted/DMZ zones and `Restricted-Data-Vault` or `PCI-Cardholder-Zone`. |

### B. Cloud IAM Security Rules (`IAM-01`)

| Rule ID | Severity | Policy Title | Compliance Benchmark | Technical Impact Evaluated |
| :--- | :---: | :--- | :--- | :--- |
| **`IAM-01`** | **CRITICAL** | Cloud Privilege Escalation: Broad Policy | CIS AWS Benchmark v1.4.0 (1.16)<br>NIST SP 800-171 3.1.1 | Attaching broad managed policies (`AmazonS3FullAccess` or `AdministratorAccess`) to workload service roles, granting cross-zone exfiltration paths to CUI/PCI data stores. |

### C. SailPoint Identity Governance Rules (`SP-01` to `SP-06`)

| Rule ID | Severity | Policy Title | Compliance Benchmark | Technical Impact Evaluated |
| :--- | :---: | :--- | :--- | :--- |
| **`SP-01`** | **CRITICAL** | In-Flight Access Assumption | NIST SP 800-53 AC-2<br>SOX 404 ITGC | In-flight or unapproved access requests (`PENDING_APPROVAL`, `REJECTED`) treated as effective access. Enforces `PENDING_IS_NOT_ACCESS`. |
| **`SP-02`** | **HIGH** | Unprovisioned / Failed Access Grant | NIST SP 800-53 AC-2 | Access approved at the governance plane but not yet provisioned (`REQUESTED_NOT_PROVISIONED` or `FAILED`) on target infrastructure. |
| **`SP-03`** | **CRITICAL** | Toxic Separation of Duties (SoD) Conflict | SOX 404 ITGC<br>NIST SP 800-53 AC-5 | Assignment of conflicting roles from `ENTERPRISE_SOD_CATALOG` (`SOD-01`: Dev + Cloud Admin; `SOD-02`: Finance + Payment Admin; `SOD-03`: SecOps + Firewall Admin). |
| **`SP-04`** | **CRITICAL** | External Contractor Privileged Access | CIS Controls v8 (5.4)<br>NIST SP 800-171 3.1.5 | External contractors (`employment_type == "CONTRACTOR"`) assigned root, production administrator, or security administrator profiles. |
| **`SP-05`** | **HIGH** | Outstanding Access-Removal / Dormant Risk | NIST SP 800-53 AC-2(3) | Entitlements marked `REVOKED` during certification campaigns that remain active or un-deprovisioned on target systems. |
| **`SP-06`** | **MEDIUM** | Entitlement Privilege Creep | NIST SP 800-53 AC-6 | Active entitlement counts exceeding documented departmental baselines (Engineering: 3, Finance: 2, Contractors: 1). |
| **`SP-CORR-01`** | **HIGH** | Unmapped Identity / Account Mapping | NIST SP 800-53 IA-2 | Workload roles or identities that cannot be correlated to any SailPoint identity or account mapping (`ImpactStatus.UNKNOWN`). |

---

## 3. Mathematical Risk Scoring Formula

SimuGuard AI calculates risk through a three-stage formula:

### Stage 1: Base Severity Score
$$\text{Base Score} = \sum_{g \in \text{DeduplicatedGaps}} W(\text{severity}_g) \times M(\text{highest\_criticality})$$

- **Severity Weights $W(\text{severity})$**:
  - $\text{CRITICAL} = 40.0$
  - $\text{HIGH} = 25.0$
  - $\text{MEDIUM} = 10.0$
  - $\text{LOW} = 3.0$
- **Asset Criticality Multipliers $M(\text{criticality})$**:
  - $\text{CRITICAL} = 1.5$ (e.g. `s3-enterprise-cui-vault`, `DATA-01-CUI-FINANCIAL-VAULT`)
  - $\text{HIGH} = 1.2$ (e.g. `fw-edge-01-primary`, `zone-trust-dmz`)
  - $\text{MEDIUM} = 1.0$ (Default enterprise assets)
  - $\text{LOW} = 0.8$ (e.g. `s3-dev-staging-telemetry`)
- *Asset Selection Rule*: The highest asset criticality among all traversed blast-radius assets is selected for $M$. If no assets are impacted, $M = 1.0$ (MEDIUM).

### Stage 2: Blast Radius Multiplier ($\beta$)
$$\beta = \min\left(2.0, \; \max\left(1.0, \; 1.0 + 0.05 \times N_{\text{direct}} + 0.02 \times N_{\text{cascading}}\right)\right)$$

- $N_{\text{direct}}$: Number of directly affected infrastructure nodes.
- $N_{\text{cascading}}$: Number of cascading transitive dependencies reached through satisfied traversal conditions.
- *Ceiling*: $\beta$ is strictly capped at $2.0$.

### Stage 3: Bounded Composite Risk Score
$$\text{Score} = \min\left(100, \; \max\left(0, \; \text{round}\left(\text{Base Score} \times \beta\right)\right)\right)$$

---

## 4. Verdict Precedence Architecture

The final deployment verdict is assigned through a deterministic hierarchical decision tree:

```
                  ┌─────────────────────────────────────┐
                  │ Evaluate Deduplicated Security Gaps │
                  └──────────────────┬──────────────────┘
                                     │
                     Is any finding CRITICAL?
                     Or is Risk Score >= 70?
                                     │
                    ├─── YES ────────┴──────── NO ───┐
                    ▼                                ▼
        ┌───────────────────────┐       Is any finding HIGH?
        │   BLOCK_DEPLOYMENT    │       Or any UNKNOWN impacts?
        │ (Rule 1: Unconditional)│       Or is Risk Score in 40-69?
        └───────────────────────┘                    │
                                     ├─── YES ───────┴─────── NO ───┐
                                     ▼                              ▼
                         ┌───────────────────────┐      ┌───────────────────────┐
                         │  WARN_MANUAL_REVIEW   │      │         ALLOW         │
                         │ (Rule 2: CAB Review)  │      │ (Rule 3: Approved)    │
                         └───────────────────────┘      └───────────────────────┘
```

- **Rule 1 (`BLOCK_DEPLOYMENT`)**:
  - Any CRITICAL finding (e.g., `FW-01`, `IAM-01`, `SP-03`, `SP-04`).
  - Composite risk score $\ge 70$.
- **Rule 2 (`WARN_MANUAL_REVIEW`)**:
  - Any HIGH finding (e.g., `FW-02`, `FW-03`, `SP-02`, `SP-05`, `SP-CORR-01`).
  - Composite risk score between $40$ and $69$.
  - Presence of unmapped resources or `ImpactStatus.UNKNOWN` relationships (e.g. `allow_netflix.tf`).
- **Rule 3 (`ALLOW`)**:
  - Composite risk score $< 40$.
  - **Zero** CRITICAL findings.
  - **Zero** HIGH findings.
  - **Zero** UNKNOWN impacts.
