# 🛡️ SimuGuard AI
**Pre-Deployment Security Change-Risk Assessment Platform**
*Autonomous Simulation, Digital Twin Blast-Radius Modeling, and Closed-Loop Remediation Engine*

[![Python](https://img.shields.io/badge/Python-3.11%20%7C%203.12%20%7C%203.13-blue.svg)](https://www.python.org/)
[![Tests](https://img.shields.io/badge/Tests-357%20Passing-brightgreen.svg)](simuguard-demo/tests/)
[![Security](https://img.shields.io/badge/Air--Gapped-Verified-success.svg)](simuguard-demo/docs/SECURITY_MODEL.md)
[![ITSM](https://img.shields.io/badge/UI-ServiceNow%20Single%20Workspace-0f62fe.svg)](simuguard-demo/docs/USER_GUIDE.md)
[![Deployment](https://img.shields.io/badge/Streamlit%20Cloud-Ready-red.svg)](https://streamlit.io/cloud)

---

## 📌 Overview

**SimuGuard AI** is a local, pre-flight change-risk simulation and automated remediation platform designed for **Network Security Operations Engineers** and **Identity Operations Engineers**.

Modern DevOps, GitOps, and ITSM pipelines frequently process firewall modifications and access grants that inadvertently bypass Layer 7 App-ID inspection, create unrestricted egress tunnels, grant excessive cloud IAM permissions, or introduce toxic Separation of Duties (SoD) conflicts.

SimuGuard AI provides a shift-left pre-deployment gate:
1. **Intakes raw ServiceNow change tickets** through an intelligent extractor and plain-English summary generator.
2. **Models changes** against a 220-node enterprise Digital Twin (Palo Alto NGFWs, network zones, subnets, compute, data vaults, SailPoint identities).
3. **Calculates deterministic risk scores** ($0 - 100$) and enforces unambiguous `ALLOW` / `WARN` / `BLOCK` deployment gates.
4. **Synthesizes least-privilege candidate configurations** and validates them on an ephemeral candidate Digital Twin overlay.
5. **Generates publication-grade compliance audit reports** (Executive PDF and structured JSON).

---

## ☁️ Streamlit Community Cloud Deployment

SimuGuard AI is fully audited, containerized, and optimized for 1-click deployment on **Streamlit Community Cloud** (Debian Linux runtime).

### Deployment Settings Form Values

When deploying the repository on Streamlit Community Cloud, enter the following exact settings:

| Setting | Value | Description |
| :--- | :--- | :--- |
| **Repository** | `Abhiram-Laha/SimuGuard-Project-Deloitte` | Your GitHub repository |
| **Branch** | `main` | Production deployment branch |
| **Main file path** | `app.py` | Unified root entry point (also supports `simuguard-demo/app.py`) |
| **Python Version** | `3.11` *(Recommended)* or `3.12` | Fully verified with binary wheels on Linux |
| **Dependency File** | `requirements.txt` | Discovered automatically at repository root |

### Platform Architecture & Compatibility Highlights
- **Unambiguous Dependency Discovery**: Single root `requirements.txt` declaring pinned, tested versions (`streamlit>=1.35.0,<=1.42.0`, `pydantic>=2.7.0,<3.0.0`, `networkx>=3.0.0,<4.0.0`, `pandas>=2.0.0,<3.0.0`, `reportlab>=4.0.0,<6.0.0`, `python-hcl2>=8.2.0,<9.0.0`).
- **Universal Entry Point**: Root `app.py` dynamically resolves repository structure and executes the application natively without isolated `runpy` dictionaries.
- **Pre-Flight Data & SQLite Bootstrapping**: Automatically initializes local SQLite schema (`simuguard_demo.db`) and seeds 5 enterprise change scenarios with zero manual setup.
- **Ephemeral Storage Boundary**: Streamlit Community Cloud containers have ephemeral disk storage. All demonstration data and assessment capabilities are completely self-contained and re-initialized idempotently on any container reboot.

---

## 🚀 Local Quick Start

### 1. Prerequisites
- Python 3.10, 3.11, 3.12, or 3.13
- Git

### 2. Installation & Startup
```bash
# Clone the repository
git clone https://github.com/Abhiram-Laha/SimuGuard-Project-Deloitte.git
cd SimuGuard-Project-Deloitte

# Create and activate virtual environment
python -m venv .venv

# On Windows:
.venv\Scripts\Activate.ps1
# On macOS / Linux:
source .venv/bin/activate

# Install dependencies from repository root
pip install -r requirements.txt

# Launch the Streamlit application
streamlit run app.py
```

Open `http://localhost:8501` in your browser. The application automatically opens to **⚡ New Assessment** (the Single Assessment Workspace) in **Demo Sandbox Mode**.

### 3. Running the Test Suite
```bash
pytest
```
All **357 tests pass deterministically** with 0 failures in under 35 seconds (including full deployment smoke tests).

---

## 🖥️ Single Assessment Workspace (Primary Workflow)

The entire engineer experience is consolidated into **one primary workspace** on a single screen:
1. **1. Paste Change Request**: Large 300px dark-navy text area with monospace font, complete with 1-click template scenario buttons (`CHG-1001` through `CHG-1005`, `PR-4082`, `PR-4083`, `Netflix`, `Safe Rule`, `SailPoint`).
2. **Change Request Summary**: Plain-English business summary (what is requested, original business justification, structured key changes table, and initial observations).
3. **2. Review Extracted Configuration**: In-place editable form with validation warnings for missing fields or policy ambiguities.
4. **Pre-Flight Simulation Results**: Inline decision gate banner, KPI metrics, security gap breakdown with CIS/NIST compliance mappings, directly affected infrastructure assets table, condition-aware blast radius view, synthesized candidate patch, before/after comparison delta, and one-click PDF/JSON downloads.

---

## 🎯 Test Scenarios Included

### Official Firewall Project Scenarios
Accessible directly via 1-click buttons in the workspace:
- `CHG-2026-1001`: Outbound HTTPS Customer Portal API (`ALLOW`, Score: 0)
- `CHG-2026-1002`: Analytics Unrestricted Outbound Egress (`BLOCK_DEPLOYMENT`, Score: 100 $\rightarrow$ Remediated to 0)
- `CHG-2026-1003`: Banking App-to-Database Segmentation (`ALLOW`, Score: 0)
- `CHG-2026-1004`: Inbound NAT Customer Support Portal (`ALLOW`, Score: 0)
- `CHG-2026-1005`: Unrestricted Vendor Connectivity (`BLOCK_DEPLOYMENT`, Score: 100 $\rightarrow$ Remediated to 0)

### Realistic Enterprise Change Requests (`SimuGuard_Realistic_Org_Change_Requests/`)
- `01_FW_Approved_SaaS_Integration.txt` (`CHG0098421`): Scoped SaaS rule (`WARN_MANUAL_REVIEW`, unmapped `DC-APP` zone).
- `02_FW_Overbroad_ThirdParty_Access.txt` (`CHG0098476`): Overbroad vendor access (`BLOCK_DEPLOYMENT`, score $\ge 85$).
- `03_FW_Production_Database_Rule_Incomplete.txt` (`CHG0098510`): Incomplete database rule with placeholder `TBD` IPs (`BLOCK_DEPLOYMENT`, `INCOMPLETE-01`).
- `04_IAM_Joiner_Standard_Finance_Analyst.txt` (`RITM0047312`): Joiner Priya Nair (`EMP-4102`). Target unmapped in directory; strictly verifies zero substitution (`BLOCK_DEPLOYMENT`).
- `05_IAM_Mover_Conflicting_And_Privileged_Access.txt` (`RITM0047398`): Mover Arjun Mehta (`EMP-2871`) requesting `SAP - Finance Administrator` (`BLOCK_DEPLOYMENT`, score: 100).
- `06_IAM_Leaver_Contractor_Offboarding.txt` (`RITM0047455`): Contractor Vikram Rao (`CTR-0924`) offboarding. Rejects fallback to internal employees (`BLOCK_DEPLOYMENT`).

---

## 🔒 Security & Air-Gapped Guarantees

- **100% Local Simulation**: No outbound API calls, phone-home telemetry, or external web lookups.
- **Zero Live Modifiers**: Cannot push, commit, or execute configuration changes onto live firewalls, routers, or cloud infrastructure.
- **Database Isolation**: Demo sandbox runs against `simuguard_demo.db`. The production database `simuguard_history.db` remains isolated with **0 records**.
- **Deterministic Risk Engine**: Mathematical scoring formula governed by strict hierarchical verdict precedence.
- **Data Integrity**: Missing topology or identity data is treated as `UNKNOWN` and never assumed safe.

---

## 📚 Complete Documentation Links

All detailed technical documentation is available in the [`simuguard-demo/docs/`](simuguard-demo/docs/) directory:

- 🏗️ [System Architecture & Component Design](simuguard-demo/docs/ARCHITECTURE.md)
- 🎬 [Demonstration & Evaluation Guide](simuguard-demo/docs/DEMO_GUIDE.md)
- ⚠️ [Project Limitations & Boundary Specifications](simuguard-demo/docs/PROJECT_LIMITATIONS.md)
- 🛡️ [Security Model & Risk Methodology](simuguard-demo/docs/SECURITY_MODEL.md)
- 📖 [Operations & User Guide](simuguard-demo/docs/USER_GUIDE.md)

---
*SimuGuard AI — Apex Global Technologies Enterprise Security Platform*
