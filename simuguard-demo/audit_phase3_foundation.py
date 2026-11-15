"""Comprehensive Foundation Audit for Phase 3 Final Closure and Phase 4 Readiness."""

import json
from pathlib import Path
import networkx as nx

REPO_ROOT = Path(__file__).resolve().parent
DEMO_DIR = REPO_ROOT / "demo_environment"
DELIVERABLES_DIR = REPO_ROOT / "deliverables"

def audit():
    from simuguard.graph.dataset_loader import EnterpriseDatasetLoader
    from simuguard.graph.digital_twin import DigitalTwinGraph
    from simuguard.graph.blast_radius import BlastRadiusAnalyzer
    from simuguard.models.enums import AssetCriticality, ImpactStatus
    from simuguard.parsers.resource_models import AwsSecurityGroupRuleResource

    loader = EnterpriseDatasetLoader(DEMO_DIR)
    report = loader.validate_dataset()
    dt = loader.load_as_digital_twin_graph()
    sp = loader.load_sailpoint_governance()

    print("=== Part A.1 & A.2: Digital Twin Metric Reconciliation ===")
    print(f"Validation Registered Node IDs: {report.total_nodes}")
    print(f"Digital Twin Compiled Active Nodes: {dt.node_count}")
    print(f"Validation Explicit Validated Edges: {report.total_edges}")
    print(f"Digital Twin Graph Active Edges: {dt.edge_count}")

    # Section A.3: SailPoint Relationships
    print("\n=== Part A.3: SailPoint Hierarchy Verification ===")
    identities = sp["identities"]["identities"]
    accounts = sp["accounts"]["accounts"]
    roles = sp["roles"]["roles"]
    aps = sp["access_profiles"]["access_profiles"]
    ents = sp["entitlements"]["entitlements"]

    print(f"Total Identities: {len(identities)}")
    print(f"Total Correlated Accounts: {len(accounts)}")
    print(f"Total Roles: {len(roles)}")
    print(f"Total Access Profiles: {len(aps)}")
    print(f"Total Entitlements: {len(ents)}")

    # Verify Identity -> Account (OWNS_ACCOUNT)
    sarah_accts = [a["id"] for a in accounts if a["identity_id"] == "sp-ident-sarah-chen"]
    print(f"Sarah Chen accounts ({len(sarah_accts)}): {sarah_accts}")
    assert len(sarah_accts) >= 3

    # Verify Role -> Access Profile -> Entitlement
    fin_role = next(r for r in roles if r["id"] == "sp-role-finance-analyst")
    print(f"Finance Analyst APs: {fin_role['access_profiles']}")
    assert "sp-ap-aws-prod-s3-read" in fin_role["access_profiles"]

    s3_read_ap = next(a for a in aps if a["id"] == "sp-ap-aws-prod-s3-read")
    print(f"S3 Read AP Entitlements: {s3_read_ap['entitlements']}")
    assert "sp-ent-aws-s3-cui-read" in s3_read_ap["entitlements"]

    s3_cui_ent = next(e for e in ents if e["id"] == "sp-ent-aws-s3-cui-read")
    print(f"S3 CUI Entitlement Target: {s3_cui_ent['target_resource_id']} (action: {s3_cui_ent['attribute_value']})")
    assert s3_cui_ent["target_resource_id"] == "s3-enterprise-cui-vault"

    # Section A.4: Lifecycle Semantics
    print("\n=== Part A.4: Approval & Provisioning Lifecycle Semantics ===")
    reqs = sp["access_requests"]["access_requests"]
    provs = sp["provisioning_events"]["provisioning_events"]
    certs = sp["certifications"]["certifications"]

    pending_req = next(r for r in reqs if r["id"] == "sp-req-1003-pending-admin-access")
    print(f"Pending Request effective_access_granted: {pending_req['effective_access_granted']}")
    assert pending_req["effective_access_granted"] is False

    pending_prov = next(p for p in provs if p["id"] == "sp-prov-2004-pending-admin-grant")
    print(f"Pending Provisioning Event state: {pending_prov['state']} (reconciliation: {pending_prov['reconciliation_status']})")
    assert pending_prov["state"] == "REQUESTED_NOT_PROVISIONED"

    prov_grant = next(p for p in provs if p["id"] == "sp-prov-2001-grant-s3-read")
    print(f"Provisioned Event state: {prov_grant['state']} (reconciliation: {prov_grant['reconciliation_status']})")
    assert prov_grant["state"] == "PROVISIONED"

    # Section A.5: AWS Resource Permissions Separation
    print("\n=== Part A.5: AWS Resource Permissions vs. SailPoint Governance ===")
    policies = loader._read_json("iam/policies.json")["policies"]
    policy_arns = [p["arn"] for p in policies]
    print(f"Customer-Managed AWS Policies in repo: {len(policies)}")
    assert "arn:aws:iam::111122223333:policy/S3TelemetryWriteOnly" in policy_arns
    assert "arn:aws:iam::111122223333:policy/PCITokenVaultAccess" in policy_arns
    assert "arn:aws:iam::111122223333:policy/ApexWorkloadBoundary" in policy_arns

    # Verify that in graph, SailPoint connects to AWS accounts via GOVERNED_BY_SAILPOINT
    edge_sp_aws = dt.nx_graph.get_edge_data("sp-src-aws-prod", "111122223333")
    print(f"SailPoint to AWS Production Edge: {edge_sp_aws}")
    assert edge_sp_aws["relationship"] == "GOVERNED_BY_SAILPOINT"

    # Section A.6: Firewall and Network Topology
    print("\n=== Part A.6: Firewall & Network Topology Relationships ===")
    fw_edge = dt.get_perimeter_firewall()
    print(f"Perimeter Firewall: {fw_edge.id} ({fw_edge.name})")
    assert fw_edge.id == "fw-edge-01-primary"

    edge_to_dmz = dt.nx_graph.get_edge_data("fw-edge-01-primary", "zone-trust-dmz")
    print(f"Edge to Trust-DMZ: {edge_to_dmz}")
    assert edge_to_dmz["relationship"] == "ENFORCES_ZONE_POLICY"

    edge_transit = dt.nx_graph.get_edge_data("fw-edge-01-primary", "fw-internal-01-primary")
    print(f"Edge Firewall to Internal Firewall: {edge_transit}")
    assert edge_transit["relationship"] == "CONNECTS_TO"

    edge_internal_vault = dt.nx_graph.get_edge_data("fw-internal-01-primary", "zone-restricted-data-vault")
    print(f"Internal Firewall to Restricted Vault Zone: {edge_internal_vault}")
    assert edge_internal_vault["relationship"] == "ZONE_INTERCONNECT_ROUTING"

    # Section A.7: Unmapped Assets Remain UNKNOWN
    print("\n=== Part A.7: Unmapped Asset UNKNOWN Status Guardrail ===")
    analyzer = BlastRadiusAnalyzer(dt)
    unmapped_rule = AwsSecurityGroupRuleResource(
        resource_type="aws_security_group_rule",
        resource_name="test_unmapped_rule",
        source_file="test.tf",
        rule_type="ingress",
        from_port=80,
        to_port=80,
        protocol="tcp",
        cidr_blocks=["0.0.0.0/0"],
        security_group_id="sg-nonexistent-unknown-9999",
    )
    res = analyzer.analyze_resources([unmapped_rule])
    print(f"Unmapped resources flagged: {res.unmapped_resources}")
    print(f"Unknown impacts count: {len(res.unknown_impacts)}")
    print(f"Not affected nodes count: {len(res.not_affected_nodes)} (MUST be 0)")
    assert len(res.not_affected_nodes) == 0
    assert len(res.unknown_nodes) > 0
    assert res.unknown_impacts[0].status == ImpactStatus.UNKNOWN

    # Section A.8: Deliverable Verification
    print("\n=== Part A.8: PowerPoint and Mermaid Deliverables Verification ===")
    pptx_path = DELIVERABLES_DIR / "Apex_Global_Technologies_Complete_Enterprise_Architecture.pptx"
    assert pptx_path.is_file(), f"PPTX missing: {pptx_path}"
    print(f"PPTX exists: {pptx_path.name} ({pptx_path.stat().st_size:,} bytes)")

    mmd_files = [
        "complete_enterprise_architecture.mmd",
        "network_architecture.mmd",
        "panorama_architecture.mmd",
        "aws_architecture.mmd",
        "sailpoint_architecture.mmd",
        "application_architecture.mmd",
        "data_architecture.mmd",
        "end_to_end_dependency.mmd",
    ]
    for m in mmd_files:
        f = DELIVERABLES_DIR / "diagrams" / m
        assert f.is_file(), f"Mermaid file missing: {f}"
        print(f"Mermaid file exists: {m} ({f.stat().st_size:,} bytes)")

    print("\n=== Part A Foundation Audit: ALL CHECKS PASSED SUCCESSFULLY ===")

if __name__ == "__main__":
    audit()
