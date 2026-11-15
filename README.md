# 🛡️ SimuGuard AI

**Pre-Deployment Infrastructure Blast Radius & Security Simulation Platform**

SimuGuard AI is a pre-flight cybersecurity simulation platform designed to analyze Infrastructure as Code (IaC) changes before they reach production. It models changes against a **Digital Twin** network topology, identifies firewall and IAM misconfigurations, determines blast radius, calculates quantitative risk scores, and generates least-privilege remediation plans.

---

## 📁 Package Architecture

SimuGuard AI is organized into a modular Python package structure:

```
simuguard-demo/
├── simuguard/                         # Core Python package
│   ├── __init__.py                    # Package metadata & top-level exports
│   ├── models/                        # [Phase 1] Strict Pydantic v2 domain schemas
│   │   ├── __init__.py                # Model exports
│   │   ├── enums.py                   # Severity, DeploymentVerdict, AssetCriticality, BlastTier, ImpactStatus
│   │   ├── security_gap.py            # SecurityGap model
│   │   ├── affected_asset.py          # AffectedAsset model & blast-tier parser
│   │   ├── validation_check.py        # ValidationCheck playbook model
│   │   └── report.py                  # PreFlightSimulationReport root model
│   ├── parsers/                       # [Phase 2] Terraform / HCL Ingestion & Parsing Engine
│   │   ├── __init__.py                # Parser exports
│   │   ├── hcl_parser.py              # TerraformHclParser (python-hcl2 wrapper & normalizer)
│   │   └── resource_models.py         # Normalized resource models & schema error models
│   ├── graph/                         # [Phase 3] Digital Twin Graph & Blast Radius Engine
│   │   ├── __init__.py                # Graph exports
│   │   ├── digital_twin.py            # DigitalTwinGraph (NetworkX representation & explicit SG mapping)
│   │   └── blast_radius.py            # BlastRadiusAnalyzer (conditional traversal & ImpactStatus classifier)
│   ├── rules/                         # [Phase 4] Deterministic Security Rule Engine
│   │   └── __init__.py
│   ├── engine/                        # [Phase 4/5] Risk Scorer & Remediation Engine
│   │   └── __init__.py
│   └── reporters/                     # [Phase 5/6] Terminal UI & JSON Artifact Renderers
│       └── __init__.py
├── tests/                             # Pytest unit & integration test suite
│   ├── __init__.py
│   ├── conftest.py                    # Reusable test fixtures
│   ├── test_models.py                 # Pydantic schema validation tests (43 tests)
│   ├── test_parsers.py                # HCL parsing & schema validation tests (13 tests)
│   └── test_graph.py                  # Graph traversal, explicit mapping & regression tests (19 tests)
├── changes/                           # Sample Terraform PR change tickets
│   ├── allow_netflix.tf               # PR #4101 (AWS SG rule sample)
│   ├── pr_4082_firewall_iam.tf        # PR #4082 (AWS SG rule + IAM attachment)
│   └── pr_4083_firewall_iam.tf        # PR #4082 (PAN-OS policy + IAM attachment)
├── .agents/skills/                    # Agent Skill definitions
│   └── blast-radius-analyzer/
│       ├── SKILL.md
│       └── references/
│           └── topology_graph.json    # Enterprise Digital Twin topology
├── agent_runner.py                    # Original mock runner (preserved for baseline reference)
├── simulation_output_artifact.json    # Original JSON artifact (preserved for baseline reference)
├── requirements.txt                   # Dependencies (pydantic, pytest, python-hcl2, networkx)
└── pytest.ini                         # Pytest test discovery & pythonpath configuration
```

---

## 🕸️ Digital Twin & Blast Radius Engine (Phase 3)

The `DigitalTwinGraph` loads and validates the infrastructure topology (`topology_graph.json`) using Pydantic and converts it into a `networkx.DiGraph`.

### Explicit Security Group Mapping
Associations between AWS Security Groups and workloads must be explicitly verified. Silently guessing mappings through substring matching is strictly prohibited:
- `DEFAULT_SG_WORKLOAD_MAPPINGS`: Explicitly binds `sg-analytics-web-01` $\rightarrow$ `eks-analytics-worker-pool`.
- Custom mappings can be registered via `register_security_group_mapping()`.
- Unmapped security groups (e.g., `sg-guest-network-01`) produce an **`UNKNOWN`** impact status.

### Explicit Impact Statuses (`ImpactStatus`)
- **`AFFECTED`**: Assets directly targeted or downstream within a satisfied blast propagation path.
- **`NOT_AFFECTED`**: Assets confirmed isolated only when the entire change set has verified topology mappings.
- **`UNKNOWN`**: Assigned when resources or security groups cannot be mapped to the Digital Twin. **Crucially: Missing topology data is never treated as proof of isolation.**

### Condition-Aware Graph Traversal
The engine evaluates the `blast_condition` on each edge before propagating blast radius:
- `ENFORCES_ZONE_POLICY`: Traverses to compute workloads only if Layer 7 App-ID is bypassed (`any`) or destination addresses are wildcarded (`any`).
- `ZONE_INTERCONNECT_ROUTING`: Traverses to `zone-restricted-financial` only if Security Profile Groups are removed (`none`). Active threat prevention blocks traversal.
- `CROSS_ZONE_IAM_PATH`: Traverses to `s3-enterprise-cui-vault` only if overprivileged policies (`AmazonS3FullAccess` or `AdministratorAccess`) are attached. Scoped policies block traversal.

---

## 🧪 Running the Tests

To execute the complete test suite (75 unit tests across Phases 1, 2, and 3):

```bash
# From workspace root or simuguard-demo directory:
python -m pytest -v
```
