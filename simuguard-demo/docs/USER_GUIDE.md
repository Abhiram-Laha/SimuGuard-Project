# SimuGuard AI — Operations & User Guide
**Pre-Deployment Security Change-Risk Assessment Platform**
*Apex Global Technologies Enterprise Security Operations*

---

## 1. Overview & System Purpose

SimuGuard AI is a local, pre-flight change-risk simulation and automated remediation engine. Designed specifically for **Network Security Operations Engineers** and **Identity Operations Engineers**, it allows security teams to model, analyze, and validate proposed infrastructure and access changes *before* deployment to production.

By evaluating proposed changes against an internal **Digital Twin** (220 active enterprise nodes and 77 directional relationships), SimuGuard AI calculates quantitative risk scores, determines blast radius, flags security policy violations, and synthesizes candidate least-privilege configurations.

---

## 2. Navigating the Enterprise Dashboard

The application interface is inspired by enterprise ITSM platforms (ServiceNow) and organized into nine primary navigation views accessible via the dark navy sidebar:

| Navigation Item | Purpose | Key Actions |
| :--- | :--- | :--- |
| **📊 Overview** | Executive summary of recent change requests, gate verdicts, and risk trends. | View KPI metrics; inspect recent changes; review guided demo script. |
| **➕ New Change Request** | Pre-flight intake form for Firewall and SailPoint access changes. | Select demo scenarios; upload Terraform `.tf` files; save drafts or submit. |
| **📋 Assessment History** | Complete historical ledger of change requests and audit activity logs. | Filter by domain, priority, status; search tickets; paginate records. |
| **🔍 Assessment Results** | In-depth breakdown of simulation results for the active change request. | Inspect composite risk score, severity counts, and identified security gaps. |
| **🛠️ Remediation Center** | Automated least-privilege remediation recommendations and HCL patch. | Review policy recommendations; inspect candidate synthesized HCL. |
| **⚖️ Before & After Comparison** | Differential risk validation comparing original vs candidate state. | Inspect risk score reduction delta, severed blast paths, and resolved gaps. |
| **🌐 Digital Twin Explorer** | Interactive topological graph inspection and blast radius explorer. | Search assets, inspect dependency degrees, view candidate graph overlay. |
| **📄 Reports & Exports** | Publication-grade PDF and structured JSON export artifacts. | Download executive audit PDFs and machine-readable JSON exports. |
| **⚙️ Settings / About** | System diagnostics, platform health, and schema validation. | Run diagnostic checks on Python runtime, SQLite schema, and engines. |

---

## 3. Creating & Submitting Change Requests

### A. Creating a Firewall Policy Change
1. Click **➕ New Change Request** in the sidebar.
2. Select **Change Domain**: `Network Security (Firewall & Perimeter)`.
3. Choose a configuration source:
   - **Load Certified Scenario**: Select one of the pre-loaded enterprise scenarios from the dropdown:
     - `PR #4083 — Palo Alto NGFW Webhook Egress & S3 CUI Exposure` (Dangerous)
     - `PR #4082 — Analytics Egress Webhook & S3 FullAccess` (Excessive IAM)
     - `PR #4085 — Scoped SIEM Log Egress` (Safe Scoped Rule)
     - `PR #4101 — Allow Guest Network Netflix Streaming` (Unmapped SG)
   - **Upload Custom Terraform**: Upload a valid `.tf` configuration file (maximum 5MB).
4. Review the auto-populated ServiceNow fields (Short Description, Priority, Configuration Item, Assignment Group, Maintenance Window).
5. Choose your action:
   - **Save as Draft**: Stores the request in `DRAFT` status in the local database without triggering simulation.
   - **Submit & Run Pre-Flight Simulation**: Promotes request to `SUBMITTED` and triggers immediate deterministic risk evaluation.

### B. Creating a SailPoint Identity Governance Change
1. Navigate to **➕ New Change Request**.
2. Select **Change Domain**: `Identity Governance (SailPoint ISC)`.
3. Fill in the Identity and Governance fields:
   - **Target Identity**: Enter or select an identity (e.g., `sp-ident-sophia-alvarez`).
   - **Requested Role / Profile**: Specify the requested role or entitlement (e.g., `sp-prof-prod-admin`).
   - **Business Justification**: Detail the reason for the access grant.
4. *Note*: Attaching a Terraform file is **optional** for SailPoint requests; the engine evaluates the governance model directly against the synthetic identity store.
5. Click **🚀 Submit Change Request & Run Simulation**.

---

## 4. Reviewing Assessment Results & Findings

Upon submission, the engine transitions the ticket to `ANALYSIS_COMPLETE` and opens the **Assessment Results** view:

- **Deployment Verdict**:
  - `ALLOW` (Green): Low-risk change ($\text{Score} < 40$). Zero CRITICAL, zero HIGH, zero UNKNOWN impacts.
  - `WARN_MANUAL_REVIEW` (Amber): Elevated risk ($\text{Score } 40 - 69$), HIGH severity finding, or unmapped entity requiring CAB review.
  - `BLOCK_DEPLOYMENT` (Red): Prohibitive risk ($\text{Score } \ge 70$) or at least one CRITICAL security violation.
- **Composite Risk Score**: Calculated deterministically on a $0 - 100$ scale factoring finding severity weights and blast radius multipliers.
- **Identified Security Gaps**: Every violation is presented with its Rule ID (e.g., `FW-01`, `IAM-01`, `SP-04`), severity, technical impact, compliance benchmark (CIS, NIST, PCI-DSS), and remediation guidance.
- **Affected Infrastructure Assets**: A list of all enterprise workloads, zones, and data stores within the blast path, categorizing direct vs cascading impacts.

---

## 5. Automated Remediation & Candidate Validation

1. From Assessment Results, click **🛠️ Proceed to Remediation Plan** or navigate to **Remediation Center**.
2. **Remediation Recommendations**: Review the itemized action plan generated by `RecommendationEngine`.
3. **Synthesized Candidate Configuration**: Inspect the automatically generated candidate HCL patch. The engine removes wildcards, scopes CIDRs to verified partners, attaches threat profiles, and detaches overprivileged IAM policies.
4. **Candidate Overlay Validation**: The engine automatically applies the candidate change onto an ephemeral copy of the Digital Twin (`CandidateDigitalTwinOverlay`), re-evaluating risk without modifying the original baseline.
5. Click **⚖️ View Before & After Comparison**:
   - Review the **Risk Score Delta** (e.g., $-100$ point reduction).
   - Inspect the **Finding Resolution Breakdown** (Resolved, Partially Resolved, Manual Review Required).
   - Verify that all excessive relationships to sensitive vaults are marked as severed.

---

## 6. Exporting Audit Reports

1. Navigate to **📄 Reports & Exports**.
2. Select the desired Change Request from the selector.
3. Choose an export format:
   - **Download Executive Audit Report (PDF)**: A publication-grade PDF generated via ReportLab containing the executive summary, gate verdict, finding breakdown, blast radius table, candidate validation results, and local simulation disclaimer.
   - **Download Structured Assessment Payload (JSON)**: A full machine-readable JSON artifact containing raw metrics, schema metadata, and audit evidence.

---

## 7. Managing Assessment History & Settings

- **Assessment History**: Filter past tickets by domain (`Network Security` vs `Identity Governance`), priority, workflow status, or keyword search. Click **Open Record** to view complete ticket detail and activity audit timelines.
- **Settings / About**: Review application version, runtime environment, loaded Digital Twin metrics (220 nodes, 77 edges), and click **Run Self-Diagnostics** to perform an on-demand integrity audit.
