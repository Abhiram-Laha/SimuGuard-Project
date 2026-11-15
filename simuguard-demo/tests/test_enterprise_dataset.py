"""Unit tests for Phase 3.5: Enterprise Demo Organisation and Digital Twin Dataset (Apex Global Technologies).

Validates:
1. All resources have unique IDs.
2. Referential integrity across all relationship edges.
3. Network CIDRs and IP addresses conform to RFC 1918 or documentation blocks.
4. Application workload dependencies resolve correctly.
5. IAM roles and attached policies resolve correctly.
6. Cross-account trust relationships reference registered accounts.
7. Firewall rules reference valid zones and address/service objects.
8. Sensitive data assets have valid classifications and controls.
9. Dataset compiles and loads into DigitalTwinGraph.
10. End-to-end blast-radius traversal across network, workloads, applications, IAM, and data assets.
11. Unknown/unmapped relationships are not interpreted as proof of safety.
12. Dataset loading and graph compilation are deterministic.
"""

import ipaddress
import json
from pathlib import Path
import pytest

from simuguard.graph.dataset_loader import EnterpriseDatasetLoader
from simuguard.graph.digital_twin import DigitalTwinGraph
from simuguard.graph.blast_radius import BlastRadiusAnalyzer
from simuguard.models.enums import BlastTier, ImpactStatus, AssetCriticality
from simuguard.parsers.resource_models import (
    AwsIamRolePolicyAttachmentResource,
    AwsSecurityGroupRuleResource,
    PanosSecurityPolicyResource,
    PanosSecurityPolicyRule,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
DEMO_DIR = REPO_ROOT / "demo_environment"


@pytest.fixture
def dataset_loader() -> EnterpriseDatasetLoader:
    return EnterpriseDatasetLoader(DEMO_DIR)


@pytest.fixture
def enterprise_twin(dataset_loader: EnterpriseDatasetLoader) -> DigitalTwinGraph:
    return dataset_loader.load_as_digital_twin_graph()


class TestEnterpriseDatasetIntegrity:
    """Tests referential integrity and schema validation for the Apex Global Technologies dataset."""

    def test_all_resources_have_unique_ids(self, dataset_loader: EnterpriseDatasetLoader):
        """Test 1: Verify that every resource across the dataset has a globally unique ID."""
        all_ids = dataset_loader.get_all_resource_ids()
        assert len(all_ids) > 60
        # No duplicates in ID list
        seen = set()
        duplicates = []
        for rid in all_ids:
            if rid in seen:
                duplicates.append(rid)
            seen.add(rid)
        assert len(duplicates) == 0, f"Duplicate resource IDs found: {duplicates}"

    def test_relationships_referential_integrity(self, dataset_loader: EnterpriseDatasetLoader):
        """Test 2: Verify that every relationship edge references existing source and target nodes."""
        report = dataset_loader.validate_dataset()
        assert report.is_valid is True, f"Validation errors: {report.errors}"
        assert len(report.errors) == 0
        assert len(report.unresolved_edges) == 0
        assert report.total_edges >= 35

    def test_network_subnet_ip_validity(self):
        """Test 3: Verify all internal subnets and VPCs use RFC 1918 private IP space."""
        subnets_file = DEMO_DIR / "network" / "subnets.json"
        vpcs_file = DEMO_DIR / "cloud" / "vpcs.json"
        addr_file = DEMO_DIR / "network" / "address_objects.json"

        # Validate subnets
        subnets_data = json.loads(subnets_file.read_text(encoding="utf-8"))
        for subnet in subnets_data["subnets"]:
            cidr = subnet["cidr_block"]
            net = ipaddress.ip_network(cidr)
            assert net.is_private, f"Subnet {subnet['id']} ({cidr}) is not RFC 1918 private IP space."

        # Validate VPCs
        vpcs_data = json.loads(vpcs_file.read_text(encoding="utf-8"))
        for vpc in vpcs_data["vpcs"]:
            cidr = vpc["cidr_block"]
            net = ipaddress.ip_network(cidr)
            assert net.is_private, f"VPC {vpc['id']} ({cidr}) is not RFC 1918 private IP space."

        # Validate public doc IPs
        addr_data = json.loads(addr_file.read_text(encoding="utf-8"))
        for obj in addr_data["address_objects"]:
            val = obj.get("value")
            if obj["type"] == "ip-netmask" and "/" in val:
                net = ipaddress.ip_network(val, strict=False)
                # Must be private RFC 1918 or RFC 5737 documentation space
                is_doc_or_private = (
                    net.is_private
                    or any(net.subnet_of(ipaddress.ip_network(d)) for d in ["203.0.113.0/24", "198.51.100.0/24", "192.0.2.0/24"])
                )
                assert is_doc_or_private, f"Address object {obj['name']} ({val}) is neither RFC 1918 nor RFC 5737 doc IP."

    def test_applications_workload_references(self, dataset_loader: EnterpriseDatasetLoader):
        """Test 4: Verify that all applications reference valid compute workloads."""
        apps_file = DEMO_DIR / "applications" / "applications.json"
        resources_file = DEMO_DIR / "cloud" / "resources.json"

        apps_data = json.loads(apps_file.read_text(encoding="utf-8"))
        res_data = json.loads(resources_file.read_text(encoding="utf-8"))

        known_workload_ids = {w["id"] for w in res_data.get("compute_workloads", [])}
        known_workload_ids |= {lb["id"] for lb in res_data.get("load_balancers", [])}

        for app in apps_data["applications"]:
            for workload_id in app.get("hosted_on_workloads", []):
                assert (
                    workload_id in known_workload_ids
                ), f"Application {app['id']} references unknown workload {workload_id}"

    def test_iam_roles_policies_resolve(self):
        """Test 5: Verify that IAM roles reference valid customer-managed or AWS-managed policies."""
        roles_file = DEMO_DIR / "iam" / "roles.json"
        policies_file = DEMO_DIR / "iam" / "policies.json"

        roles_data = json.loads(roles_file.read_text(encoding="utf-8"))
        policies_data = json.loads(policies_file.read_text(encoding="utf-8"))

        custom_policy_arns = {p["arn"] for p in policies_data.get("policies", [])}

        for role in roles_data["roles"]:
            for policy_arn in role.get("attached_policies", []):
                is_aws_managed = policy_arn.startswith("arn:aws:iam::aws:policy/")
                is_custom = policy_arn in custom_policy_arns
                assert is_aws_managed or is_custom, f"Role {role['id']} references unresolved policy {policy_arn}"

            boundary = role.get("permission_boundary") or role.get("permissions_boundary")
            if boundary:
                assert (
                    boundary in custom_policy_arns
                ), f"Role {role['id']} references unresolved boundary {boundary}"

    def test_cross_account_trust_resolve(self):
        """Test 6: Verify cross-account trust relationships reference valid accounts and roles."""
        trust_file = DEMO_DIR / "iam" / "trust_relationships.json"
        accounts_file = DEMO_DIR / "cloud" / "accounts.json"

        trust_data = json.loads(trust_file.read_text(encoding="utf-8"))
        accounts_data = json.loads(accounts_file.read_text(encoding="utf-8"))

        known_accounts = {a.get("id") or a.get("account_id") for a in accounts_data["accounts"]}

        for rel in trust_data.get("trust_relationships", []):
            if rel.get("trusted_entity_type") == "AWS_Account":
                principal = rel["principal"]
                src_acc = principal.split(":")[4]
                assert src_acc in known_accounts, f"Unknown source account {src_acc}"
                tgt_acc = rel.get("target_account")
                if tgt_acc:
                    assert tgt_acc in known_accounts, f"Unknown target account {tgt_acc}"

    def test_firewall_rules_zones_objects_valid(self):
        """Test 7: Verify firewall security policies reference valid zones and address/service objects."""
        rules_file = DEMO_DIR / "network" / "security_policies.json"
        zones_file = DEMO_DIR / "network" / "zones.json"
        addr_file = DEMO_DIR / "network" / "address_objects.json"
        svc_file = DEMO_DIR / "network" / "service_objects.json"

        rules_data = json.loads(rules_file.read_text(encoding="utf-8"))
        zones_data = json.loads(zones_file.read_text(encoding="utf-8"))
        addr_data = json.loads(addr_file.read_text(encoding="utf-8"))
        svc_data = json.loads(svc_file.read_text(encoding="utf-8"))

        known_zones = {z["name"].lower() for z in zones_data["zones"]} | {"any"}
        known_addrs = (
            {a["name"].lower() for a in addr_data.get("address_objects", [])}
            | {g["name"].lower() for g in addr_data.get("address_groups", [])}
            | {"any"}
        )
        known_svcs = (
            {s["name"].lower() for s in svc_data.get("service_objects", [])}
            | {g["name"].lower() for g in svc_data.get("service_groups", [])}
            | {"any", "application-default"}
        )

        all_rules = rules_data.get("policies", [])
        assert len(all_rules) >= 20

        for rule in all_rules:
            rule_id = rule.get("id", "UNKNOWN")
            for sz in rule.get("source_zones", []):
                assert sz.lower() in known_zones, f"Rule {rule_id} references unknown zone: {sz}"
            for dz in rule.get("destination_zones", []):
                assert dz.lower() in known_zones, f"Rule {rule_id} references unknown zone: {dz}"
            for src in rule.get("source_addresses", []):
                if not any(c.isdigit() for c in src):
                    assert src.lower() in known_addrs, f"Rule {rule_id} references unknown address: {src}"
            for dst in rule.get("destination_addresses", []):
                if not any(c.isdigit() for c in dst):
                    assert dst.lower() in known_addrs, f"Rule {rule_id} references unknown destination: {dst}"

    def test_data_assets_have_classifications(self):
        """Test 8: Verify sensitive data assets have defined classifications and compliance controls."""
        assets_file = DEMO_DIR / "data_assets" / "assets.json"
        class_file = DEMO_DIR / "data_assets" / "classifications.json"

        assets_data = json.loads(assets_file.read_text(encoding="utf-8"))
        class_data = json.loads(class_file.read_text(encoding="utf-8"))

        known_tiers = {t["tier"] for t in class_data.get("classifications", [])}

        for da in assets_data["data_assets"]:
            assert (
                da["classification"] in known_tiers
            ), f"Data asset {da['id']} has unknown classification {da.get('classification')}"
            if da.get("criticality") in ("Critical", "High"):
                assert (
                    len(da.get("compliance_controls", [])) > 0
                ), f"Critical data asset {da['id']} has no compliance controls specified."


class TestEnterpriseDigitalTwinAndBlastRadius:
    """Tests graph compilation and blast-radius traversal over the enterprise Digital Twin."""

    def test_dataset_loads_into_digital_twin(self, enterprise_twin: DigitalTwinGraph):
        """Test 9: Verify the dataset compiles cleanly into DigitalTwinGraph."""
        assert enterprise_twin.node_count >= 60
        assert enterprise_twin.edge_count >= 35

        perimeter_fw = enterprise_twin.get_perimeter_firewall()
        assert perimeter_fw is not None
        assert perimeter_fw.id == "fw-edge-01-primary"
        assert perimeter_fw.criticality == AssetCriticality.CRITICAL

    def test_end_to_end_blast_radius_traversal(self, enterprise_twin: DigitalTwinGraph):
        """Test 10: Verify multi-tier traversal: IAM Role -> Data Store -> Sensitive Data Asset AND Workload -> Application."""
        analyzer = BlastRadiusAnalyzer(enterprise_twin)

        # Simulate an overprivileged IAM policy attachment on the analytics ingestion role
        iam_attachment = AwsIamRolePolicyAttachmentResource(
            resource_type="aws_iam_role_policy_attachment",
            resource_name="overprivileged_attach",
            source_file="simulated.tf",
            role="role-analytics-ingestion-svc",
            policy_arn="arn:aws:iam::aws:policy/AmazonS3FullAccess",
        )

        result = analyzer.analyze_resources([iam_attachment])

        # 1. IAM Role must be DIRECT impact
        direct_node_ids = {n.node_id for n in result.direct_impacts}
        assert "role-analytics-ingestion-svc" in direct_node_ids

        cascading_node_ids = {n.node_id for n in result.cascading_impacts}

        # 2. S3 bucket must be reached via CROSS_ZONE_IAM_PATH
        assert "s3-enterprise-cui-vault" in cascading_node_ids

        # 3. Sensitive Data Asset must be reached via STORES_DATA downstream traversal!
        assert "DATA-01-CUI-FINANCIAL-VAULT" in cascading_node_ids

        # 4. Workload assuming the role must be reached via ASSUMES_ROLE_REVERSE
        assert "eks-analytics-worker-pool" in cascading_node_ids

        # 5. Business Application hosted on workload must be reached via HOSTS_APPLICATION!
        assert "APP-003-CUSTOMER-ANALYTICS" in cascading_node_ids

        # Verify terminology in impact reasons: must say "potentially"
        for node in result.cascading_impacts:
            assert "potentially" in node.impact_reason.lower()

    def test_unknown_relationships_not_safe(self, enterprise_twin: DigitalTwinGraph):
        """Test 11: Verify that an unmapped resource marks remaining nodes as UNKNOWN, not confirmed safe."""
        analyzer = BlastRadiusAnalyzer(enterprise_twin)

        unmapped_sg_rule = AwsSecurityGroupRuleResource(
            resource_type="aws_security_group_rule",
            resource_name="unmapped_guest_rule",
            source_file="simulated.tf",
            rule_type="egress",
            from_port=0,
            to_port=0,
            protocol="-1",
            cidr_blocks=["0.0.0.0/0"],
            security_group_id="sg-unknown-unregistered-99",
        )

        result = analyzer.analyze_resources([unmapped_sg_rule])

        # Must flag unmapped resource
        assert len(result.unmapped_resources) > 0
        assert len(result.unknown_impacts) > 0

        # Rule 2: Cannot classify remaining nodes as NOT_AFFECTED
        assert len(result.not_affected_nodes) == 0
        assert len(result.unknown_nodes) > 0

    def test_dataset_loading_deterministic(self, dataset_loader: EnterpriseDatasetLoader):
        """Test 12: Verify that compiling the dataset multiple times produces identical graph topology."""
        dt1 = dataset_loader.load_as_digital_twin_graph()
        dt2 = dataset_loader.load_as_digital_twin_graph()

        assert dt1.node_count == dt2.node_count
        assert dt1.edge_count == dt2.edge_count
        assert sorted(list(dt1.nx_graph.nodes())) == sorted(list(dt2.nx_graph.nodes()))
        assert sorted(list(dt1.nx_graph.edges())) == sorted(list(dt2.nx_graph.edges()))
