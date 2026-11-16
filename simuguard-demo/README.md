# 🛡️ SimuGuard AI
**Pre-Deployment Security Change-Risk Assessment Platform**
*Autonomous Simulation, Digital Twin Blast-Radius Modeling, and Closed-Loop Remediation Engine*

[![Python](https://img.shields.io/badge/Python-3.13%2B-blue.svg)](https://www.python.org/)
[![Tests](https://img.shields.io/badge/Tests-306%20Passing-brightgreen.svg)](tests/)
[![Security](https://img.shields.io/badge/Air--Gapped-Verified-success.svg)](#security--architecture)
[![ITSM](https://img.shields.io/badge/UI-ServiceNow%20Single%20Workspace-0f62fe.svg)](#dashboard-interface)

---

## 📌 Executive Overview

**SimuGuard AI** is a local, pre-flight change-risk simulation and automated remediation platform designed for **Network Security Operations Engineers** and **Identity Operations Engineers**.

Modern DevOps and GitOps pipelines frequently deploy Terraform configurations or access grants that inadvertently bypass perimeter firewall App-ID inspection, grant excessive cloud IAM permissions, or introduce toxic Separation of Duties (SoD) conflicts. 

SimuGuard AI shifts security assessment to the pre-deployment phase:
1. **Models changes** against a 220-node enterprise Digital Twin before deployment.
2. **Evaluates security benchmarks** (CIS Benchmarks, NIST CSF 2.0, NIST SP 800-171, PCI-DSS, SOX 404).
3. **Calculates deterministic risk scores** ($0 - 100$) and enforces unambiguous `ALLOW` / `WARN` / `BLOCK` deployment gates.
4. **Synthesizes least-privilege candidate configurations** and validates them on an ephemeral candidate Digital Twin overlay.
5. **Provides an enterprise ITSM interface** (ServiceNow-inspired) with persistent SQLite history, audit activity logs, and publication-grade PDF/JSON export artifacts.

---

## 🚀 Key Features

- **Palo Alto PAN-OS Security Analysis**: Deep Layer 7 App-ID bypass detection (`applications = ["any"]`), wildcard egress detection, missing Threat Prevention profile groups, cleartext protocol enforcement, and cross-zone matrix inspection.
- **AWS Cloud IAM Privilege Analysis**: Detects broad managed policies (`AmazonS3FullAccess`, `AdministratorAccess`), cross-account trust escalation, and evaluates access reachability to sensitive CUI/PCI data vaults.
- **SailPoint ISC Governance Modeling**: Detects premature in-flight access assumptions (`PENDING_IS_NOT_ACCESS`), unprovisioned access grants, contractor privileged access violations, dormant revoked entitlements, and toxic Separation of Duties conflicts.
- **Condition-Aware Blast Radius Analysis**: NetworkX graph engine evaluates conditional edge traversal, categorizing assets into `DIRECT` triggers vs `CASCADING` transitive impacts across 220 enterprise nodes.
- **Deterministic Risk Engine**: Bounded mathematical scoring formula factoring gap severities, asset criticality multipliers, and blast multipliers, strictly governed by hierarchical verdict precedence.
- **Closed-Loop Automated Remediation**: Generates candidate least-privilege HCL patches, applies them to an isolated candidate Digital Twin overlay, and computes before-and-after risk reduction deltas.
- **ITSM Change Management Interface**: ServiceNow-inspired Streamlit dashboard with intake forms, draft saving, automatic request numbering (`SIM-CHG-XXXX`), audit timelines, and PDF/JSON export pipelines.
- **Dedicated Demonstration Sandbox**: Pre-loaded with 5 certified demonstration scenarios in an isolated demo database (`simuguard_demo.db`), keeping production history completely clean.

---

## 🛠️ Technology Stack

| Layer | Technologies Used |
| :--- | :--- |
| **Language & Runtime** | Python 3.13+ (Type-hinted, strict Pydantic v2 schemas) |
| **Parsing & Ingestion** | `python-hcl2` with custom typed AST normalizer |
| **Graph & Topology** | `networkx` Directed Multi-Relational Graph (`nx.DiGraph`) |
| **Storage & Persistence** | SQLite 3 (WAL mode, foreign keys enabled, atomic transactions) |
| **User Interface** | Streamlit (Custom enterprise ServiceNow CSS theme, Altair charts) |
| **Reporting Pipeline** | ReportLab Platypus (Two-pass numbered PDF canvas) & JSON |
| **Testing & Quality** | Pytest 9.2+ (Unit, integration, hardening, diagnostics, E2E) |

---

## 📁 Repository Structure

```
simuguard-demo/
├── app.py                             # Main Streamlit dashboard application entry point
├── config/
│   └── settings.py                    # Application branding, navigation constants & DB paths
├── storage/
│   ├── database.py                    # SQLite schema, migrations, connection management
│   ├── models.py                      # Pydantic persistence models (ChangeRequest, Assessment, etc.)
│   ├── repository.py                  # Concurrency-safe ChangeRepository interface
│   └── upload_handler.py              # File upload validation, sanitization & staging cleanup
├── simuguard/                         # Core Security & Simulation Engine
│   ├── models/                        # Strict Pydantic domain schemas (SecurityGap, Report, etc.)
│   ├── parsers/                       # Terraform/HCL ingestion engine
│   ├── graph/                         # Digital Twin loader & condition-aware blast radius engine
│   ├── rules/                         # FW-01..06, SP-01..06 & SoD conflict matrix
│   ├── engine/                        # SimuGuardAnalyzer & deterministic RiskEngine
│   ├── remediation/                   # RecommendationEngine, ConfigGenerator, Overlay, Validation
│   └── reporters/                     # Terminal reporter & JSON exporter
├── ui/                                # Presentation Layer
│   ├── theme.py & layout.py           # Enterprise CSS typography & page layout
│   ├── navigation.py                  # Router & page dispatcher
│   ├── components/                    # Sidebar, metric cards, status badges
│   ├── pages/                         # 9 core navigation views + Record Detail view
│   └── services/                      # DemoEnvironmentService, AssessmentRunner, ReportExportService
├── demo_environment/                  # Apex Global Technologies Synthetic Enterprise Dataset
├── changes/                           # Real-world Terraform change sets (PR-4082, PR-4083, etc.)
├── docs/                              # Comprehensive documentation suite
│   ├── USER_GUIDE.md                  # Complete operator & analyst workflow guide
│   ├── DEMO_GUIDE.md                  # 5-10 minute executive demonstration script
│   ├── ARCHITECTURE.md                # System component design with Mermaid diagrams
│   ├── SECURITY_MODEL.md              # Rule catalog & mathematical risk scoring methodology
│   └── PROJECT_LIMITATIONS.md         # Air-gapped boundaries & local simulation guarantees
└── tests/                             # 288 automated tests (Unit, Integration, E2E)
```

---

## ⚡ Installation & Application Startup

### 1. Prerequisites
- Python 3.10+ (Python 3.13 recommended)
- Git

### 2. Application Directory & Virtual Environment
```bash
# Navigate to project workspace
cd simuguard-demo

# Optional: activate virtual environment
# Windows:
venv\Scripts\activate
# Linux/macOS:
source venv/bin/activate

# Install dependencies (if not already installed)
pip install -r requirements.txt
```

### 3. Launching the Dashboard
Start the local Streamlit application:
```bash
streamlit run app.py
```
Open your browser to `http://localhost:8501`. 

**Default Landing Page**: The application automatically lands on **"New Assessment"** (the Single Assessment Workspace) in **Demo Sandbox Mode**, ready for interactive evaluation.

---

## 🖥️ Single Assessment Workspace (Primary Workflow)

The entire engineer experience is consolidated into **one primary workspace** (`New Assessment`), eliminating context switching:

1. **Step 1: Paste Change Request**: Ingest raw ServiceNow tickets, HCL blocks, or load 1-click scenarios.
2. **Step 2: Review Configuration**: Inspect extracted fields, review parameter warnings (App-ID wildcard, unrestricted egress), and verify Inbound Destination NAT mapping.
3. **Step 3: Run Pre-Flight Assessment**: Execute deterministic pre-flight simulation against the 220-node Digital Twin.
4. **Step 4: Inline Results & Verification**: Review decision gate verdict, security gaps, blast-radius asset graph, synthesized candidate configuration, before-and-after comparison, and download executive PDF/JSON compliance reports.

---

## 🎯 Official Firewall Change Request Scenarios

SimuGuard AI includes the 5 official firewall change request specifications (located in `SimuGuard_Firewall_Sample_Change_Requests/`), accessible via 1-click loaders directly in Section 1 of the workspace:

| Change Request | Title / Scope | Gate Verdict | Risk Score | Gaps | Technical Highlights |
| :--- | :--- | :---: | :---: | :---: | :--- |
| **`CHG-2026-1001`** | Outbound HTTPS Customer Portal API | **`ALLOW`** | **0 / 100** | 0 | Scoped destination (`198.51.100.25/32`), App-ID `ssl`, Strict profile, logging enabled. |
| **`CHG-2026-1002`** | Analytics Unrestricted Outbound Egress | **`BLOCK_DEPLOYMENT`** | **100 / 100** | 2 | Wildcard destination `any`, App-ID `any`, profile `None`, logging `Disabled`. Remediated to `0/100` (`ALLOW`). |
| **`CHG-2026-1003`** | Banking App-to-Database Segmentation | **`ALLOW`** | **0 / 100** | 0 | Strict internal segmentation (`10.200.20.15/32:5432`), App-ID `postgresql`, compliant posture. |
| **`CHG-2026-1004`** | Inbound NAT Customer Support Portal | **`ALLOW`** | **0 / 100** | 0 | Separates public external IP (`203.0.113.50`) from private translated target (`10.100.30.25`). Policy matches private host. |
| **`CHG-2026-1005`** | Unrestricted Vendor Connectivity | **`BLOCK_DEPLOYMENT`** | **100 / 100** | 2 | Emergency modification to permissive `any`. Blocked; remediated to `0/100` (`ALLOW`). |

---

## 📦 Pre-Loaded Demonstration Sandbox Scenarios

In addition to the text change requests above, the demo database (`data/simuguard_demo.db`) comes pre-loaded with 5 historical baseline records:

| Identifier | Title | Scenario Scope | Gate Verdict | Risk Delta |
| :--- | :--- | :--- | :---: | :---: |
| **`SIM-DEMO-001`** | Dangerous Perimeter Firewall Policy | PAN-OS App-ID bypass (`applications = ["any"]`) & S3 FullAccess attachment. | **`BLOCK_DEPLOYMENT`** (Score: 100) | $-100 \rightarrow$ `ALLOW` (Score: 0) |
| **`SIM-DEMO-002`** | Excessive Cloud IAM Privilege Escalation | Broad `AmazonS3FullAccess` attachment creating cross-zone path to CUI Vault. | **`BLOCK_DEPLOYMENT`** (Score: 100) | $-100 \rightarrow$ `ALLOW` (Score: 0) |
| **`SIM-DEMO-003`** | Contractor Privileged Access Request | External contractor Sophia Alvarez assigned Production Administrator role. | **`BLOCK_DEPLOYMENT`** (Score: 100) | Remediated via policy |
| **`SIM-DEMO-004`** | Safe Scoped Firewall Policy | Egress strictly scoped to partner CIDR (`52.84.120.0/22`) with App-ID & Threat Group. | **`ALLOW`** (Score: 0) | Safe baseline (Zero gaps) |
| **`SIM-DEMO-005`** | Unmapped Entity Exception | Egress rule referencing unmapped SG `sg-guest-network-01` outside Digital Twin. | **`WARN_MANUAL_REVIEW`** (Score: 35) | Unmapped entity review |

### Resetting Demonstration Scenarios
To reset the demonstration sandbox to its pristine baseline:
- Navigate to **"Settings & Diagnostics"** and click **"Reset Demo Sandbox Data"**, or
- Run the CLI reset utility:
  ```bash
  python -c "from ui.services.demo_service import DemoEnvironmentService; DemoEnvironmentService.reset_demo_database()"
  ```

---

## 🧪 Automated Testing

SimuGuard AI maintains an exhaustive regression test suite covering unit schemas, parsers, graph traversals, security rules, candidate overlays, persistence, concurrency safety, and end-to-end single workspace workflows:

```bash
# Execute the complete 306-test regression suite:
python -m pytest -v
```

All **306 tests run deterministically** with 0 failures and 0 warnings, completing in **under 30 seconds** in pure air-gapped mode.

---

## 🔒 Security & Project Limitations

SimuGuard AI was architected as a **safe, local pre-deployment simulation platform**. To guarantee absolute environment safety, the following operational constraints are strictly enforced:

1. **Air-Gapped & Local-Only Operation**:
   - Zero outbound network calls, telemetry phone-home, or external web lookups.
   - Zero live API connectors to Palo Alto Panorama, AWS STS/IAM/EC2, SailPoint ISC, or ServiceNow.
2. **Zero Production Mutation**:
   - SimuGuard AI cannot push, commit, or execute configuration changes onto actual firewalls, routers, or cloud infrastructure.
   - All remediation patches are candidate configurations generated for review and validated exclusively on an in-memory ephemeral candidate Digital Twin overlay.
3. **Database Isolation**:
   - Demo sandbox workflows operate strictly in `data/simuguard_demo.db`.
   - The production database `data/simuguard_history.db` remains 100% clean and isolated.
4. **Deterministic Simulation vs Live Threat Intelligence**:
   - Security evaluations are based on static benchmark rules (CIS Benchmarks, NIST SP 800-171, PCI-DSS, SOX 404).
   - Real-time threat feeds (e.g. WildFire live cloud lookups) are not queried.
5. **No Blind Hallucinations**:
   - The extraction and remediation engines never invent credentials, private subnets, or external partner IP ranges.
   - Ambiguous or unknown parameters are explicitly tagged for human review (`NEEDS_MANUAL_REVIEW`).

For full details, see [docs/PROJECT_LIMITATIONS.md](docs/PROJECT_LIMITATIONS.md).

---

## 📚 Complete Documentation Links

- 📖 [Operations & User Guide](docs/USER_GUIDE.md)
- 🎬 [Executive 5–10 Minute Demo Script](docs/DEMO_GUIDE.md)
- 🏗️ [System Architecture & Component Design](docs/ARCHITECTURE.md)
- 🛡️ [Security Model & Risk Methodology](docs/SECURITY_MODEL.md)
- ⚠️ [Project Limitations & Boundaries](docs/PROJECT_LIMITATIONS.md)

---
*SimuGuard AI — Apex Global Technologies Enterprise Security Platform*
