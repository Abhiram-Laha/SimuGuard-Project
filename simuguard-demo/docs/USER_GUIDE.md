# SimuGuard AI — Operations & User Guide
**Pre-Deployment Security Change-Risk Assessment Platform**
*Apex Global Technologies Enterprise Security Operations*

---

## 1. Overview & System Purpose

SimuGuard AI is a local, pre-flight change-risk simulation and automated remediation engine. Designed specifically for **Network Security Operations Engineers** and **Identity Operations Engineers**, it allows security teams to model, analyze, and validate proposed infrastructure and access changes *before* deployment to production.

By evaluating proposed changes against an internal **Digital Twin** (220 active enterprise nodes and 77 directional relationships), SimuGuard AI calculates quantitative risk scores, determines blast radius, flags security policy violations, and synthesizes candidate least-privilege configurations.

---

## 2. Navigating the Streamlined Enterprise Workspace

The application features a simplified single-workspace architecture designed so Network Security Operations and Identity Governance engineers can complete their entire assessment lifecycle from one central screen without navigating through complex sub-menus.

The sidebar contains four primary entries:

| Navigation Item | Purpose | Key Actions |
| :--- | :--- | :--- |
| **⚡ New Assessment** *(Default Landing Page)* | The primary unified assessment workspace. Centers the entire change-risk workflow on one screen. | Paste change requests; extract configurations; review fields; execute simulation; inspect inline results, blast radius, remediation patches, and download reports. |
| **📋 Assessment History** | Complete historical ledger of change requests and audit activity logs. | Filter by domain, priority, status; search tickets; open historical changes directly into the primary workspace. |
| **📄 Reports** | Publication-grade compliance reports and compliance export hub. | View KPI metrics across all assessments; download executive audit PDFs and machine-readable JSON exports. |
| **⚙️ Settings & Diagnostics** | Administrative environment controls and platform health diagnostics. | Toggle between Demo Sandbox and Production; reset demo scenarios safely; inspect system health and runtime integrity. |

---

## 3. The Single Assessment Workspace Workflow

The primary assessment workflow follows four seamless inline steps:

### Step 1: Paste Change Request
1. Enter or paste your complete ServiceNow change ticket into the large text input area.
2. Alternatively, click any of the **Quick Demo Scenarios** buttons (`PR-4082`, `PR-4083`, `Netflix`, `Safe Rule`, `SailPoint`) to populate an authentic enterprise request in one click.
3. Click **🔍 Extract Configuration**. SimuGuard's intelligent text extractor automatically parses the domain, change parameters, rule specifications, or SailPoint identity attributes.

### Step 2: Review Configuration
1. Inspect the extracted fields (Short Description, Priority, Rule Name, Zones, CIDRs, App-ID, Port, Action, or SailPoint Identity details).
2. All values are editable directly in-place.
3. SimuGuard automatically flags missing mandatory parameters in red and highlights high-risk configuration ambiguities (e.g., wildcard CIDRs, `applications = any`, unapproved contractor access) in amber alert boxes.

### Step 3: Run Pre-Flight Assessment
1. Click the prominent **🚀 Run Pre-Flight Assessment** button.
2. SimuGuard AI models the change against the enterprise Digital Twin topology, evaluates deterministic security rules, computes quantitative risk scores, and generates candidate least-privilege remediation patches.

### Step 4: Inline Results & Verification
All assessment results render immediately on the same page below the intake form:
- **Executive Decision Banner**: Unambiguous verdict badge (`BLOCK_DEPLOYMENT`, `WARN_MANUAL_REVIEW`, or `ALLOW`) with summary rationale.
- **Risk Score KPI Cards**: Baseline risk score, security gaps count, affected assets count, candidate risk score, and risk reduction delta.
- **Structured Workspace Tabs**:
  - `🔍 Security Findings & Assets`: Detailed table of identified security gaps, rule IDs, compliance violations (PCI-DSS, NIST SP 800-53), and impacted infrastructure assets.
  - `🌐 Digital Twin Blast Radius`: Topological traversal reach, direct entrypoints, and transitive database/workload dependencies.
  - `🛠️ Remediation & Candidate Patch`: Actionable recommendations, synthesized candidate HCL patch, and closed-loop validation checks.
  - `⚖️ Before & After Comparison`: Differential score reduction (e.g. `100 → 0 pts`), verdict progression, and gap resolution tracking.
  - `📄 Export Compliance Report`: One-click download buttons for publication-grade Executive PDF reports and audit-ready JSON exports.
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
