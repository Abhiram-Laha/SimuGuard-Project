# SimuGuard AI — Executive 5–10 Minute Demonstration Script
**Pre-Deployment Security Change-Risk Assessment Platform**

This guide provides an end-to-end, scripted demonstration flow designed for enterprise stakeholders, CISOs, Network Security Directors, and Identity Governance leads.

---

## ⏱️ Demonstration Timeline & Overview

| Segment | Duration | Focus Area | Key Takeaway |
| :--- | :---: | :--- | :--- |
| **1. Introduction & Problem Statement** | 1.0 min | Dashboard Overview & Context | Shift-left security for network & IAM changes. |
| **2. Scenario Walkthrough (PR-4083)** | 3.0 min | New Change Intake & Simulation | Deterministic risk scoring and `BLOCK_DEPLOYMENT`. |
| **3. Digital Twin & Blast Radius** | 1.5 min | Topology Explorer | Visualizing CUI Vault exposure through graph traversal. |
| **4. Automated Remediation** | 2.0 min | Remediation & Comparison | Closed-loop candidate overlay and 100-point risk drop. |
| **5. Executive Reporting & Audit** | 1.0 min | PDF & JSON Exports | Audit-ready artifacts for CAB and compliance teams. |
| **6. Identity Governance & Diagnostics** | 1.5 min | SailPoint & Self-Diagnostics | Multi-domain governance and air-gapped system health. |

---

## 🎬 Step-by-Step Scripted Demonstration

### Segment 1: Introduction & Executive Dashboard (1.0 min)
1. **Action**: Open the SimuGuard AI application (`streamlit run app.py`).
2. **Spoken Narration**:
   > *"Good morning. Today, network and cloud security teams face a critical challenge: Terraform pipelines and access change requests frequently introduce severe security flaws—such as uninspected egress tunnels or overprivileged IAM roles—that are only caught after deployment or during an audit.*
   >
   > *SimuGuard AI solves this by introducing a local, pre-flight simulation engine. Before any configuration is committed or pushed to production, SimuGuard models the change against an enterprise Digital Twin, calculates a deterministic risk score, identifies blast radius, and generates automated remediation patches."*
3. **Action**: Point out the **Executive KPI Row** (Total Changes, Blocked, Manual Review, Approved, Auto-Remediated, Avg Score) and the **Gate Verdict Distribution** chart on the Overview page.

---

### Segment 2: Scenario Walkthrough — Dangerous Firewall Policy (3.0 min)
1. **Action**: Click **➕ New Change Request** in the sidebar.
2. **Action**: In the **Scenario Selector**, choose:
   `PR #4083 — Palo Alto NGFW Webhook Egress & S3 CUI Exposure`
3. **Spoken Narration**:
   > *"Here an engineer has submitted a pull request intended to allow outbound webhook traffic from our DMZ to an external analytics provider. Let's inspect what happens when we submit this ticket for pre-flight simulation."*
4. **Action**: Click **🚀 Submit Change Request & Run Simulation**.
5. **Action**: The dashboard automatically navigates to **Assessment Results**.
6. **Spoken Narration**:
   > *"Notice the immediate result: **Deployment Verdict: BLOCK_DEPLOYMENT** with a maximum composite risk score of **100/100**.*
   >
   > *SimuGuard didn't just check port numbers—it performed deep semantic analysis and identified 5 distinct security violations:*
   > 1. *`FW-01 (CRITICAL)`: App-ID bypass setting `applications = any`, turning off Layer 7 packet inspection.*
   > 2. *`FW-02 (HIGH)`: Unrestricted Internet egress to `0.0.0.0/0`.*
   > 3. *`FW-03 (HIGH)`: Missing Threat Prevention profile group.*
   > 4. *`FW-04 (MEDIUM)`: Cleartext service protocol exposure.*
   > 5. *`IAM-01 (CRITICAL)`: Cloud privilege escalation attaching `AmazonS3FullAccess` to the ingestion role.*
   >
   > *Under SimuGuard's deterministic precedence rules, any CRITICAL finding triggers an unconditional BLOCK, overriding any manual exceptions."*

---

### Segment 3: Digital Twin & Blast Radius Analysis (1.5 min)
1. **Action**: Click **🌐 Digital Twin Explorer** in the sidebar.
2. **Action**: Switch to the **💥 Blast-Radius & Candidate Overlay Explorer** tab.
3. **Action**: Select `SIM-DEMO-001` from the dropdown.
4. **Spoken Narration**:
   > *"SimuGuard models the full enterprise topology—220 active nodes across network perimeters, VPCs, compute clusters, IAM roles, and sensitive data stores.*
   >
   > *Notice how the blast radius traversed 15 assets. The perimeter firewall policy widened DMZ egress, while the attached IAM policy opened a cross-zone traversal path directly into `s3-enterprise-cui-vault` and our restricted financial data asset. SimuGuard caught this cascading data exfiltration risk before a single byte of infrastructure was provisioned."*

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
