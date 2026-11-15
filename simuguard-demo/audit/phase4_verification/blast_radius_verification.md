# SimuGuard AI — Digital Twin & Blast Radius Verification (Phase 4)

This document presents the independent audit of the Digital Twin graph engine and blast radius traversal implementation.

---

## 1. Digital Twin Graph Metrics & Referential Integrity

- **Compiled Active Graph Nodes:** 220 vertices in NetworkX directed graph (`nx_graph`).
- **Compiled Active Graph Edges:** 77 directed edges.
  - 37 explicit infrastructure edges (`demo_environment/topology_edges.json`).
  - 38 explicit SailPoint governance edges (`demo_environment/sailpoint/relationships.json`).
  - 2 dynamically enriched runtime edges (`is_enriched = True`):
    1. `eks-dev-cluster` $\xrightarrow{\text{ASSUMES_ROLE}}$ `role-dev-developer-sandbox`
    2. `ec2-sec-siem-forwarder` $\xrightarrow{\text{ASSUMES_ROLE}}$ `role-secops-incident-responder`
- **Referential Integrity:** 100% verified. Zero dangling references or orphan edges exist.

---

## 2. Blast Radius Traversal Engine Mechanics

### Direct vs. Cascading Impact Identification
1. **Direct Impacts ($N_{\text{direct}}$):** Infrastructure assets directly configured or targeted by the evaluated Terraform resource.
   - *Example:* For `aws_security_group_rule` on `sg-analytics-web-01`, directly impacts compute workload `eks-analytics-worker-pool`.
   - *Example:* For `aws_iam_role_policy_attachment` on `role-analytics-ingestion-svc`, directly impacts IAM role `role-analytics-ingestion-svc`.
2. **Cascading Impacts ($N_{\text{cascading}}$):** Downstream assets reached transitively across valid graph relationships.
   - *Example:* `eks-analytics-worker-pool` $\rightarrow$ `APP-003-CUSTOMER-ANALYTICS` (Application hosted on workload).
   - *Example:* `role-analytics-ingestion-svc` $\rightarrow$ `s3-enterprise-cui-vault` $\rightarrow$ `DATA-01-CUI-FINANCIAL-VAULT` (Sensitive data asset).

---

## 3. Conditional Edge Traversal Audit

The traversal engine evaluates edge-level `blast_condition` rules before propagating risk:

### Test Case: `role-analytics-ingestion-svc` $\xrightarrow{\text{CROSS_ZONE_IAM_PATH}}$ `s3-enterprise-cui-vault`
- **Blast Condition:** *"Granting AmazonS3FullAccess gives pods in Trust-DMZ unrestricted read and write privileges over the Restricted CUI Vault."*
- **Test A (Broad Policy: `AmazonS3FullAccess`):**
  - **Result:** Condition satisfied. Traversal propagates to `s3-enterprise-cui-vault`, `DATA-01-CUI-FINANCIAL-VAULT`, and `kms-cui-vault`.
  - **Cascading Asset Count:** 7 cascading nodes identified.
- **Test B (Scoped Policy: `S3TelemetryWriteOnly`):**
  - **Result:** Condition blocked. Traversal halts at `role-analytics-ingestion-svc`.
  - **Cascading Asset Count:** 0 cascading nodes identified.

---

## 4. Unmapped Resource Guardrail Audit

### Test Case: Unmapped Security Group (`sg-nonexistent-unknown-9999`)
- **Evaluation:** Evaluated resource referencing unmapped security group.
- **Results:**
  - `has_unknowns`: **True**.
  - `unknown_impacts`: All 220 topology nodes assigned status `ImpactStatus.UNKNOWN`.
  - `not_affected_nodes`: **0** (strictly 0 confirmed safe nodes).
  - Verdict: Escalated to `WARN_MANUAL_REVIEW`.

**Audit Conclusion:**
Missing topology relationships are never treated as proof of isolation. The system enforces strict fail-closed safety semantics.
