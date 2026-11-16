# SimuGuard AI — Demonstration & Evaluation Guide
**Step-by-Step Operator & Evaluator Walkthrough**

---

## 1. Local Installation & Application Startup

### Prerequisites
- **Python**: Python 3.10+ (Python 3.13 recommended)
- **Git**
- **Operating System**: Windows, macOS, or Linux

### Step 1: Navigate to Workspace & Install Dependencies
Open a terminal in the project directory:

```bash
# Navigate to the application directory
cd simuguard-demo

# Optional: Create and activate a Python virtual environment
python -m venv .venv

# Windows PowerShell:
.venv\Scripts\Activate.ps1
# macOS / Linux:
source .venv/bin/activate

# Install required dependencies
pip install -r requirements.txt
```

### Step 2: Launch the Streamlit Application
Start the SimuGuard AI dashboard:

```bash
# From within the simuguard-demo directory:
streamlit run app.py
```

Or from the repository root:
```bash
streamlit run simuguard-demo/app.py
```

### Step 3: Access the Dashboard
Open your web browser and navigate to:
```
http://localhost:8501
```

The application automatically opens to **⚡ New Assessment** (the Single Assessment Workspace) running in **Demo Sandbox Mode** with the Apex Global Technologies Digital Twin active.

---

## 2. The Single Assessment Workspace Walkthrough

The redesigned SimuGuard AI experience consolidates the entire risk assessment workflow onto a single unified screen.

### Step 1: Submit a Change Request
1. On the **Change Risk Assessment Workspace**, locate the **1. Paste Change Request** intake card.
2. In the large 300px dark-navy text area, either:
   - Paste a raw ServiceNow change ticket text, OR
   - Click one of the **Sample Firewall Change Requests** one-click buttons:
     - `📄 CHG-1001 (Outbound HTTPS)`: Scoped outbound HTTPS API integration (`ALLOW`).
     - `📄 CHG-1002 (Unrestricted Egress)`: Outbound any/any egress violation (`BLOCK_DEPLOYMENT`).
     - `📄 CHG-1003 (Internal DB Seg)`: Inter-zone banking PostgreSQL rule (`ALLOW`).
     - `📄 CHG-1004 (Inbound NAT)`: Inbound NAT rule exposing customer portal (`BLOCK_DEPLOYMENT`).
     - `📄 CHG-1005 (Vendor Modify)`: Vendor overbroad access modification (`BLOCK_DEPLOYMENT`).
   - Or expand **⚡ Additional Scenarios** to load `PR-4082`, `PR-4083`, `Netflix`, `Safe Rule`, or `SailPoint`.

### Step 2: Extract Configuration & Review Plain-English Summary
1. Click the **🔍 Extract Configuration** button directly beneath the text area.
2. The platform instantly parses the ticket and renders the **Change Request Summary**:
   - **1. What is being requested?**: Plain-English explanation of the technical action.
   - **2. Why is this change requested?**: Exact business justification extracted from the original request.
   - **3. Key configuration changes**: Native Streamlit table summarizing firewall operation, target, source/destination zones, addresses, applications, services, and profile parameters.
   - **4. Initial observations & potential risks**: Highlights of high-risk configurations (e.g. wildcard addresses, disabled profiles, pending approvals).
3. Directly below the summary, review the **2. Review Extracted Configuration** form:
   - Inspect rule name, firewall target, zones, CIDRs, application, service port, action, and logging.
   - Fields can be modified or corrected in-place if needed.
   - Missing fields are highlighted with clear validation alerts.

### Step 3: Run Pre-Flight Assessment
1. Click the prominent **🚀 Run Pre-Flight Assessment** button.
2. SimuGuard AI evaluates the change against the 220-node Digital Twin, runs deterministic security benchmark rules, computes blast radius, and generates automated remediation patches.
3. The assessment results appear immediately on the same page.

### Step 4: Inspect Findings and Affected Assets
1. **Executive Decision Banner**: Review the overall verdict badge (`ALLOW`, `WARN_MANUAL_REVIEW`, or `BLOCK_DEPLOYMENT`) and rationale.
2. **KPI Score Cards**: Review Baseline Risk Score ($0 - 100$), Security Gaps count, Affected Assets count, Candidate Risk Score, and Risk Reduction Delta.
3. Select the **🔍 Security Findings & Assets** tab:
   - **Identified Security Gaps**: Review each finding's Rule ID (`FW-01`, `FW-02`, `IAM-01`, `SP-01`), severity, compliance violations (PCI-DSS, CIS Benchmarks, NIST SP 800-53), and technical impact.
   - **Directly Affected Infrastructure Assets**: Review the asset table detailing asset name, type, criticality (`CRITICAL`, `HIGH`, `MEDIUM`), blast tier (`DIRECT` vs `CASCADING`), data classification, and impact nature.

### Step 5: Inspect Digital Twin Blast Radius
1. Switch to the **🌐 Digital Twin Blast Radius** tab.
2. Review the topological traversal path:
   - **Direct Entrypoints**: Workloads and zones directly targeted by the proposed rule.
   - **Cascading Dependencies**: Downstream database clusters, payment environments, and cloud storage vaults reached through satisfied traversal conditions.
   - **Unmapped Resources**: Incomplete or unknown topology references (e.g. unmapped zones) flagged with explicit audit warnings.

### Step 6: Simulate Remediation & Validate Candidate Changes
1. Switch to the **🛠️ Remediation & Candidate Patch** tab.
2. **Remediation Plan**: Review itemized actionable recommendations generated by `RecommendationEngine`.
3. **Synthesized Candidate Configuration**: Inspect the synthesized, least-privilege Terraform HCL code that fixes wildcards, enforces App-ID, attaches security profile groups, and scopes cloud permissions.
4. **Pre-Implementation Validation Plan**: Review automated CLI verification commands (e.g. PAN-OS policy match tests, IAM policy checks) generated for validation prior to deployment.

### Step 7: Compare Before and After Results
1. Switch to the **⚖️ Before & After Comparison** tab.
2. Review the differential validation metrics:
   - **Score Delta**: Visual before/after score drop (e.g., $100 \rightarrow 0$ points).
   - **Verdict Progression**: E.g., `BLOCK_DEPLOYMENT` $\rightarrow$ `ALLOW`.
   - **Finding Resolution Matrix**: Status of each finding (`RESOLVED`, `PARTIALLY_RESOLVED`, `MANUAL_REVIEW_REQUIRED`).
   - **Severed Attack Paths**: Confirmation that excessive reachability to sensitive databases or CUI vaults has been eliminated.

### Step 8: Export Audit Reports
1. Switch to the **📄 Export Compliance Report** tab.
2. Download compliance artifacts with a single click:
   - **📥 Download Executive PDF Report**: Publication-grade, two-pass numbered audit report complete with executive decision, KPI summary, findings, blast radius inventory, and validation evidence.
   - **📥 Download Structured JSON Artifact**: Machine-readable JSON export (schema version 1.0.0) for CI/CD pipeline integration.

---

## 3. How to Run the Six Realistic Enterprise Scenarios

The folder `SimuGuard_Realistic_Org_Change_Requests` contains 6 synthetic enterprise change tickets designed to validate real-world edge cases.

### Scenario Overview

| File Name | Ticket Number | Domain & Type | Expected Verdict | Key Evaluation Focus |
| :--- | :--- | :--- | :---: | :--- |
| `01_FW_Approved_SaaS_Integration.txt` | `CHG0098421` | Firewall (Palo Alto) | `WARN_MANUAL_REVIEW` | Scoped SaaS rule to AcmePay. Flags unmapped source zone `DC-APP` as a topology gap and detects pending Change Manager approval. |
| `02_FW_Overbroad_ThirdParty_Access.txt` | `CHG0098476` | Firewall (Palo Alto) | `BLOCK_DEPLOYMENT` | Vendor access with `any`/`any`, disabled profiles, and disabled logging. Triggers `FW-01`, `FW-02`, `FW-03`, `FW-04` with a risk score $\ge 85$. |
| `03_FW_Production_Database_Rule_Incomplete.txt` | `CHG0098510` | Firewall (Palo Alto) | `BLOCK_DEPLOYMENT` | PostgreSQL migration rule containing `TBD` placeholder addresses. Triggers `INCOMPLETE-01` blocking gap. |
| `04_IAM_Joiner_Standard_Finance_Analyst.txt` | `RITM0047312` | Identity Governance (SailPoint) | `BLOCK_DEPLOYMENT` | New employee Priya Nair (`EMP-4102`). Target ID is unmapped in directory; strictly verifies zero fallback to `Priya Patel`. Flags `SP-CORR-01`, `SP-01`, `SP-02`. |
| `05_IAM_Mover_Conflicting_And_Privileged_Access.txt` | `RITM0047398` | Identity Governance (SailPoint) | `BLOCK_DEPLOYMENT` | Internal mover Arjun Mehta (`EMP-2871`) requesting `SAP - Finance Administrator`. Triggers `SP-04` (Privileged Access), `SP-06` (Privilege Creep), risk score 100. |
| `06_IAM_Leaver_Contractor_Offboarding.txt` | `RITM0047455` | Identity Governance (SailPoint) | `BLOCK_DEPLOYMENT` | Contractor Vikram Rao (`CTR-0924`) offboarding. Rejects fallback to internal employee `Vikram Sharma`. Flags `SP-CORR-01`, `SP-01`, generates orphan account check. |

### Testing Via Dashboard (Interactive)
1. Open the file from `SimuGuard_Realistic_Org_Change_Requests/` in any text editor.
2. Copy the complete text and paste it into the **Paste Change Request** text area.
3. Click **🔍 Extract Configuration**.
4. Review the generated business summary and extracted parameters.
5. Click **🚀 Run Pre-Flight Assessment**.
6. Observe the verdict, risk score, security gaps, and blast radius.

### Testing Via Automated Test Suite (CLI)
Execute the dedicated regression test suite:

```bash
# Run all 8 realistic change request tests:
pytest simuguard-demo/tests/e2e/test_realistic_org_change_requests.py -v

# Run the complete test suite (338 tests):
pytest simuguard-demo/tests/ -q
```

All 338 automated test cases execute deterministically in ~30–35 seconds.
