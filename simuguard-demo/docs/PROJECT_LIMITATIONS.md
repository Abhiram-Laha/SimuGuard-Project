# SimuGuard AI — Project Limitations & Boundary Specifications
**Apex Global Technologies Pre-Deployment Simulation Platform**

---

## 1. Architectural Scope & Boundary Definition

SimuGuard AI was designed and implemented strictly as a **local pre-deployment simulation platform**. To ensure absolute safety, zero infrastructure risk, and 100% demo predictability, the following architectural constraints are intentionally maintained:

### A. Synthetic Enterprise Modeling (Digital Twin)
- **Dataset Nature**: The network topology, AWS cloud multi-account structure, IAM roles, data vaults, and SailPoint governance entities represent the **Apex Global Technologies Synthetic Dataset** (220 active nodes, 77 directional relationships).
- **Scope**: While modeled on real-world Fortune 500 topologies, the graph is stored locally in static JSON files (`demo_environment/`).
- **Boundaries**: Entities outside this dataset (e.g. unmapped security groups such as `sg-guest-network-01` or unknown IAM principals) are flagged as `ImpactStatus.UNKNOWN` and require manual review.

### B. Air-Gapped & Local-Only Operation
- **Zero Live Connectors**: The platform deliberately contains **zero** outbound network connections, credentials, API keys, or live connectors to:
  - Palo Alto Panorama or PAN-OS XML APIs
  - SailPoint Identity Security Cloud (ISC) REST APIs
  - Amazon Web Services (AWS STS, IAM, S3, EC2 APIs)
  - ServiceNow Change Management REST APIs
- **Safety Guarantee**: SimuGuard AI cannot modify, mutate, push, or execute changes on live firewalls, production IAM roles, or cloud accounts.

### C. Offline Policy Simulation vs Real-Time Threat Feeds
- **Static Benchmarks**: Policy evaluations reflect established cybersecurity standards (CIS Palo Alto Benchmark v1.1.0, CIS AWS Benchmark v1.4.0, NIST SP 800-53, NIST SP 800-171, PCI-DSS, SOX 404).
- **No Live Threat Intelligence**: SimuGuard AI does not query real-time threat intelligence feeds (e.g. Palo Alto WildFire live cloud lookups, AlienVault OTX, or VirusTotal). IP addresses and domains are evaluated structurally against enterprise RFC 1918 allocations, corporate partner registries, and CIDR segmentations.

### D. Automated Remediation Synthesis Scope
- **Candidate Configurations**: The automated remediation engine synthesizes *candidate* Terraform HCL configurations intended for human review.
- **Synthesized Changes**:
  - Scoping wildcard `0.0.0.0/0` destinations to verified partner CIDRs (`198.51.100.0/24` or `52.84.120.0/22`).
  - Enforcing explicit Layer 7 App-IDs (`applications = ["ssl", "web-browsing"]`).
  - Attaching enterprise threat prevention profile groups (`corporate-threat-prevention-standard`).
  - Replacing wildcard IAM attachments (`AmazonS3FullAccess`) with scoped least-privilege customer policies.
- **Manual Review Required**: If a proposed destination CIDR or IAM action cannot be verified against the Digital Twin or original configuration, SimuGuard generates a recommendation marked with `NEEDS_MANUAL_REVIEW` and a `# PLACEHOLDER:` tag. It never invents partner IP ranges or credentials.

---

## 2. Platform Capabilities Matrix

| Functional Area | Current Local Capability | Production Cloud Equivalent (Future Extension) |
| :--- | :--- | :--- |
| **IaC Ingestion** | Python-based HCL parsing (`python-hcl2`) for PAN-OS and AWS Terraform | Terraform Cloud / GitHub Enterprise Actions CI/CD webhook runner |
| **Topology Modeling** | Local NetworkX Directed Graph (`nx.DiGraph`) | Neo4j / AWS Neptune Enterprise Graph Database |
| **Identity Governance** | Synthetic SailPoint ISC identity and entitlement schema | SailPoint ISC Event Webhook & IdentityNow REST Integration |
| **Firewall Analysis** | PAN-OS 11.1 Layer 7 App-ID, security profile groups, zone matrix | Live Palo Alto Panorama XML API policy push & commit validation |
| **ITSM Integration** | ServiceNow-inspired UI backed by local SQLite persistence | Bi-directional ServiceNow Change Management Table API connector |
| **Executive Reports** | Local PDF generation via ReportLab & JSON export | Automated attachment to ServiceNow tickets & JIRA Service Desk |

---

## 3. Safe Demonstration Guidelines

- **Database Separation**: Demonstrations should be conducted in **Demo Sandbox Mode** using the dedicated `data/simuguard_demo.db` database.
- **Repeatability**: The demo database can be restored to its certified state at any time via the sidebar button **"🔄 Reset Demo Scenarios"** or by running `python -m ui.services.demo_service`.
- **Zero Production Mutation**: The production database `data/simuguard_history.db` remains 100% clean and unpopulated by sample demonstration workflows.
