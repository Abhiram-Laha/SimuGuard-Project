# SimuGuard AI — Project Limitations & Boundary Specifications
**Apex Global Technologies Pre-Deployment Simulation Platform**

---

## 1. Architectural Scope & Operational Boundaries

SimuGuard AI is designed and implemented strictly as a **local pre-deployment change simulation and risk modeling platform**. To guarantee absolute safety, eliminate production risk, and provide 100% reproducible demonstrations, the following deliberate architectural boundaries are maintained:

### A. Synthetic Enterprise Digital Twin
- **Static In-Memory Dataset**: The modeled network topology, firewalls, subnets, AWS cloud multi-account resources, data vaults, and SailPoint identity governance entities represent the **Apex Global Technologies Synthetic Enterprise Dataset** (220 active nodes, 77 directional relationships).
- **Offline Topology**: The topology is compiled from static local JSON files (`demo_environment/`). It does not dynamically poll live infrastructure or cloud accounts.
- **No Real-Time Infrastructure Discovery**: SimuGuard AI does not perform live network scanning (e.g. Nmap, SNMP, NetFlow) or dynamic cloud inventory discovery (e.g. AWS Config, CloudTrail, Azure Resource Graph). Workloads and relationships not declared in the Digital Twin are treated as unmapped.

### B. Air-Gapped Simulation & Zero Live Production Integrations
The application operates entirely within an isolated local environment. It intentionally contains **zero outbound API connectors, credentials, or live production integrations**:
- **No Live Palo Alto Panorama / PAN-OS Pushes**: SimuGuard AI does not connect to Palo Alto Panorama or PAN-OS XML/REST APIs. It does not commit, push, or execute firewall configuration changes on live appliances.
- **No Live SailPoint ISC Provisioning**: SimuGuard AI does not connect to SailPoint Identity Security Cloud (ISC) or IdentityNow REST APIs. It does not provision, modify, or de-provision real identity accounts or entitlements.
- **No Live ServiceNow Production Connector**: While the user interface is styled and modeled around ServiceNow change request workflows, the platform does not connect to live ServiceNow Table APIs, OAuth endpoints, or mid-servers. Intake operates via text paste and local SQLite storage.
- **No Live AWS / Cloud API Modifications**: SimuGuard AI does not execute AWS STS, IAM, EC2, or S3 API calls. It cannot create or detach real cloud IAM policies or modify security groups in live AWS accounts.

### C. Unknown & Unmapped Data Handling
- **Missing Data Is Never Assumed Safe**: In accordance with enterprise zero-trust principles, missing topology data is never treated as proof of isolation:
  - If a proposed security group (e.g. `sg-guest-network-01`) is absent from Digital Twin mappings, it is assigned `ImpactStatus.UNKNOWN`.
  - If a network zone (e.g. `DC-APP`, `VPN-VENDOR`) is not declared in the Digital Twin, it is flagged as an unmapped resource (`TOPOLOGY-01`), preventing an automatic `ALLOW` verdict and requiring manual review (`WARN_MANUAL_REVIEW`).
  - If an identity employee/worker ID is absent from the authoritative directory, it is marked `UNMAPPED` (`SP-CORR-01`), blocking automated deployment.
- **Strict Identity Ambiguity Policy**: The platform strictly prohibits guessing or substituting identities. If an explicit employee or worker ID (e.g. `EMP-4102`, `CTR-0924`) cannot be resolved in the directory, the resolver immediately returns `UNMAPPED` and will never substitute a similar-named employee.

### D. AI & Text Extraction Boundaries
- **Regex & Deterministic Pattern Parsing**: The `ServiceNowExtractor` utilizes deterministic regular expressions and AST parsers to extract parameters from text tickets. It is not a probabilistic LLM parser and does not execute remote AI API calls.
- **Formatting Dependencies**: Text tickets must contain standard recognizable change-management patterns (e.g. `Rule Name:`, `Source Zone:`, `Destination Address:`, `Application:`, `Action:`, `Identity:`). Non-standard freeform prose that omits key technical attributes may require manual field completion in the Review Extracted Configuration form.
- **Truthful Justification Extraction**: The plain-English summary generator strictly extracts the business justification provided in the original text. It does not fabricate, extrapolate, or hallucinate business purposes not present in the input.

### E. Approval & Authorization Boundaries
- **In-Flight Access Policy (`SP-01`)**: SimuGuard AI enforces `PENDING_IS_NOT_ACCESS`. If a ServiceNow ticket lists required approvals (e.g. Change Manager, Security Architect, Line Manager, Internal Audit) that are in `Pending` or `Not Started` state, the engine treats the change as unapproved, preventing automated deployment.
- **Simulation Only**: SimuGuard AI provides pre-flight risk recommendations and validation evidence for human Change Advisory Board (CAB) review. It does not grant legal CAB sign-off or replace mandatory governance gates.

### F. Candidate Remediation Synthesis Boundaries
- **Candidate Configurations Are Advisory**: Candidate Terraform HCL configurations generated by the `ConfigGenerator` are synthesized proposals for human review. They are not pushed to Git repositories or CI/CD pipelines automatically.
- **Placeholder IP Constraints**: When scoping overly broad rules, the engine utilizes verified partner CIDR ranges defined in the enterprise dataset. If a target IP cannot be determined, it emits `# PLACEHOLDER: NEEDS_MANUAL_REVIEW` and flags `INCOMPLETE-01`. It never invents IP addresses or credentials.

---

## 2. Platform Capabilities vs Production Cloud Comparison

| Functional Area | Current Local Capability (SimuGuard AI) | Production Enterprise Equivalent (Out of Scope) |
| :--- | :--- | :--- |
| **Change Request Intake** | Local text paste, structured regex extraction, local scenario buttons | Bi-directional ServiceNow REST Table API integration via MID Server |
| **IaC Ingestion** | Local Python-based AST parser (`python-hcl2`) for PAN-OS & AWS Terraform | GitHub Enterprise Actions / GitLab CI / Terraform Cloud webhook runners |
| **Infrastructure Topology** | In-memory NetworkX directed graph (220 nodes, 77 edges) | Enterprise graph databases (Neo4j, AWS Neptune) with real-time discovery agents |
| **Firewall Policy Analysis** | Offline PAN-OS 11.1 App-ID, security profiles, and zone matrix evaluation | Live Panorama XML API pre-commit dry-run verification and candidate pushes |
| **Identity Governance** | Offline SailPoint ISC governance model and SoD conflict matrix | Live SailPoint IdentityNow / ISC event webhooks and active provisioning |
| **Remediation Application** | In-memory candidate overlay simulation and validation | Automated Pull Request creation via GitHub API or Terraform Cloud run execution |
| **Audit Persistence** | Local SQLite databases (`simuguard_demo.db`, `simuguard_history.db`) | Enterprise PostgreSQL / Oracle database with centralized SIEM streaming |
| **Compliance Export** | Local PDF generation via ReportLab & JSON file downloads | Automated attachment to ServiceNow records, JIRA issues, and S3 compliance buckets |

---

## 3. Demo Sandbox & Database Segregation Guarantees

1. **Demo Sandbox Isolation**:
   - All interactive demonstrations run in **Demo Sandbox Mode** backed by `data/simuguard_demo.db`.
   - The demo database can be restored to its certified state at any time via the UI (**⚙️ Settings & Diagnostics** $\rightarrow$ **🔄 Reset Demo Scenarios**).
2. **Production Database Immutability**:
   - The production database `data/simuguard_history.db` remains completely isolated and maintains **0 records** during demo operations and automated test suite execution.
   - All test fixtures execute against ephemeral temporary SQLite instances (`temp_repo`), guaranteeing zero test bleed into production history.
