# SimuGuard AI — Executive 5–10 Minute Demonstration Script
**Pre-Deployment Security Change-Risk Assessment Platform**

This guide provides an end-to-end, scripted demonstration flow designed for enterprise stakeholders, CISOs, Network Security Directors, and Identity Governance leads.

---

## ⏱️ Demonstration Timeline & Overview

| Segment | Duration | Focus Area | Key Takeaway |
| :--- | :---: | :--- | :--- |
| **1. Introduction & Single Workspace** | 1.0 min | Unified Assessment Workspace | Shift-left security with zero multi-page navigation. |
| **2. ServiceNow Intake & Extraction** | 2.0 min | Paste & Extract (PR-4082) | Intelligent ticket extraction and ambiguity alerts. |
| **3. Pre-Flight Assessment Execution** | 1.5 min | Simulation & Risk Scoring | Deterministic scoring and `BLOCK_DEPLOYMENT` verdict. |
| **4. Digital Twin & Blast Radius** | 1.5 min | Topology & Asset Traversal | Visualizing PCI Database & CUI Vault reachability. |
| **5. Automated Remediation & Patch** | 2.0 min | Candidate Patch & Verification | Closed-loop least-privilege overlay and 100-point drop. |
| **6. Compliance Exports & Multi-Domain** | 2.0 min | PDF Report & SailPoint Intake | Publication-grade CAB PDFs and Identity Governance. |

---

## 🎬 Step-by-Step Scripted Demonstration

### Segment 1: Introduction & Single Workspace (1.0 min)
1. **Action**: Launch the application (`streamlit run app.py`).
2. **Spoken Narration**:
   > *"Good morning. Today, network and cloud security teams face a critical challenge: Terraform changes and access requests often introduce severe security exposures that are only discovered post-deployment or during a failed audit.*
   >
   > *SimuGuard AI introduces a streamlined, single-workspace pre-flight change risk platform. A Network Security Operations Engineer can paste an entire ServiceNow change ticket, review extracted parameters, run deep pre-flight simulation against an enterprise Digital Twin, inspect blast radius, review automated remediation patches, and export CAB reports—all on one screen without navigating across disparate menus."*
3. **Action**: Highlight the clean 4-item sidebar (**⚡ New Assessment**, **📋 Assessment History**, **📄 Reports**, **⚙️ Settings & Diagnostics**).

---

### Segment 2: ServiceNow Intake & Extraction (2.0 min)
1. **Action**: Click the **📌 PR-4082 (DB Ingress)** quick scenario button.
2. **Spoken Narration**:
   > *"Let's examine a live scenario where an engineer requests direct perimeter access to a database for analytics ingestion. Notice how clicking the template populates the raw ServiceNow change ticket."*
3. **Action**: Click **🔍 Extract Configuration**.
4. **Spoken Narration**:
   > *"In one click, SimuGuard's extractor parses the rule attributes (Source Zone, Destination Zone, CIDRs, App-ID, Port) and immediately raises an inline alert: Destination is set to a protected PCI Database and App-ID is wildcarded to 'any'."*

---

### Segment 3: Pre-Flight Assessment Execution (1.5 min)
1. **Action**: Click **🚀 Run Pre-Flight Assessment**.
2. **Spoken Narration**:
   > *"Instantly, SimuGuard executes deterministic pre-flight simulation against the Apex Global Digital Twin (220 active enterprise nodes). Notice the verdict banner: **BLOCK_DEPLOYMENT** with a risk score of **100/100**.*
   >
   > *SimuGuard identifies 3 critical security gaps: direct Internet ingress violating PCI-DSS 1.3.1, Palo Alto Layer-7 App-ID bypass, and an attached AWS AdministratorAccess policy."*

---

### Segment 4: Digital Twin Blast Radius & Remediation (2.0 min)
1. **Action**: Click the **🌐 Digital Twin Blast Radius** tab. Show the 14 exposed infrastructure nodes.
2. **Action**: Click the **🛠️ Remediation & Candidate Patch** tab.
3. **Spoken Narration**:
   > *"Rather than simply rejecting the change, SimuGuard synthesizes a safe candidate configuration: scoping the destination CIDR, enforcing Layer-7 App-ID inspection, and generating a least-privilege IAM policy. Closed-loop validation confirms the post-remediation score drops to 0/100, achieving an approved ALLOW status."*
4. **Action**: Switch to the **⚖️ Before & After Comparison** tab to highlight the 100-point risk drop.

---

### Segment 5: Compliance Reporting & Multi-Domain Governance (2.0 min)
1. **Action**: Click the **📄 Export Compliance Report** tab.
2. **Action**: Click **📥 Download Executive PDF Report** to show the generated CAB audit artifact.
3. **Action**: Load the **📌 SailPoint (S3 Access)** scenario in the workspace to demonstrate multi-domain governance simulation (evaluating contractor identity, authoritative directory correlation, and in-flight access rules).

---

### Segment 4: Closed-Loop Automated Remediation (2.0 min)
1. **Action**: Click **🛠️ Remediation Center** in the sidebar.
2. **Spoken Narration**:
   > *"Instead of simply blocking the engineer and rejecting the ticket, SimuGuard's `RecommendationEngine` generates an actionable, least-privilege fix:*
   > - *It scopes the destination CIDR to the verified partner IP (`198.51.100.0/24`).*
   > - *It enforces explicit Layer 7 App-IDs (`ssl`, `web-browsing`).*
   > - *It attaches our corporate threat-prevention profile group.*
   > - *It strips `AmazonS3FullAccess` and replaces it with a scoped, write-only telemetry policy.*
   >
   > *Crucially, SimuGuard generates the actual synthesized Terraform candidate configuration ready for the engineer to review."*
3. **Action**: Click **⚖️ Before & After Comparison** in the sidebar.
4. **Spoken Narration**:
   > *"Here is the closed-loop validation proof: SimuGuard overlaid the candidate configuration onto an isolated clone of the Digital Twin. The result:*
   > - *Verdict transitions from **`BLOCK_DEPLOYMENT`** to **`ALLOW`**.*
   > - *Composite risk score drops from **100/100 to 0/100** (a 100-point risk reduction delta).*
   > - *All 5 findings are certified **RESOLVED**.*
   > - *The exfiltration path to the CUI Vault is severed.*
   > - *And all original files remained 100% untouched and unmutated."*

---

### Segment 5: Executive Audit Reporting (1.0 min)
1. **Action**: Click **📄 Reports & Exports** in the sidebar.
2. **Action**: Show the **Download Executive Audit Report (PDF)** button and the **Structured JSON Artifact** preview.
3. **Spoken Narration**:
   > *"Security Operations can immediately download an audit-ready executive PDF report. It includes full change metadata, finding breakdowns, CIS/NIST compliance mappings, blast radius tables, and before-and-after validation evidence for Change Advisory Board (CAB) review."*

---

### Segment 6: Identity Governance & System Diagnostics (1.5 min)
1. **Action**: Click **📋 Assessment History** and select ticket `SIM-DEMO-003` (`[DEMO-03] Contractor Privileged Access Request`).
2. **Spoken Narration**:
   > *"SimuGuard also protects identity governance. In `SIM-DEMO-003`, an access request was submitted to grant external contractor Sophia Alvarez a Production Administrator role. SimuGuard cross-referenced our synthetic SailPoint identity repository and SoD matrix, immediately flagging policy `SP-04` and enforcing `BLOCK_DEPLOYMENT`."*
3. **Action**: Click **⚙️ Settings / About** in the sidebar.
4. **Action**: Review the **System Health & Integrity** checkmark table.
5. **Closing Narration**:
   > *"In summary, SimuGuard AI operates entirely air-gapped without requiring cloud credentials or production access. It provides deterministic, mathematically bounded risk scoring and automated remediation across both network security and identity governance.*
   >
   > *Thank you. I'd be happy to take any questions or demonstrate additional scenarios."*
