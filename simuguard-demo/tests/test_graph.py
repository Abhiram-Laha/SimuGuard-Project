"""Unit tests for Digital Twin Graph Engine and Blast Radius Traversal."""

from pathlib import Path
import networkx as nx
import pytest
from pydantic import ValidationError
from simuguard.graph.blast_radius import (
    BlastRadiusAnalyzer,
    BlastRadiusResult,
    ImpactedNode,
    UnknownImpactAsset,
)
from simuguard.graph.digital_twin import (
    DigitalTwinGraph,
    DigitalTwinTopology,
    TopologyEdge,
    TopologyMetadata,
    TopologyNode,
)
from simuguard.models.affected_asset import AffectedAsset
from simuguard.models.enums import AssetCriticality, BlastTier, ImpactStatus
from simuguard.parsers.hcl_parser import TerraformHclParser
from simuguard.parsers.resource_models import (
    AwsIamRolePolicyAttachmentResource,
    AwsSecurityGroupRuleResource,
    PanosSecurityPolicyResource,
    PanosSecurityPolicyRule,
)

BASE_DIR = Path(__file__).parent.parent.resolve()
TOPOLOGY_PATH = BASE_DIR / ".agents" / "skills" / "blast-radius-analyzer" / "references" / "topology_graph.json"
CHANGES_DIR = BASE_DIR / "changes"


@pytest.fixture
def digital_twin() -> DigitalTwinGraph:
    """Load the real digital twin topology graph."""
    return DigitalTwinGraph.from_file(TOPOLOGY_PATH)


@pytest.fixture
def hcl_parser() -> TerraformHclParser:
    return TerraformHclParser()


class TestDigitalTwinLoadingAndValidation:
    """Tests for topology JSON ingestion and schema validation."""

    def test_load_real_topology_file(self, digital_twin: DigitalTwinGraph):
        assert digital_twin.node_count == 6
        assert digital_twin.edge_count == 5  # 3 original + 2 enriched
        assert digital_twin.topology is not None
        assert digital_twin.topology.metadata.perimeter_firewall == "pan-vm-core-firewall-01"
        assert "PAN-OS" in digital_twin.topology.metadata.firewall_vendor

    def test_perimeter_firewall_lookup(self, digital_twin: DigitalTwinGraph):
        fw = digital_twin.get_perimeter_firewall()
        assert fw is not None
        assert fw.id == "pan-vm-core-firewall-01"
        assert fw.type == "NGFW_Palo_Alto"
        assert fw.criticality == AssetCriticality.CRITICAL

    def test_nonexistent_file_raises_not_found(self):
        with pytest.raises(FileNotFoundError):
            DigitalTwinGraph.from_file("nonexistent_topology.json")

    def test_node_validation_missing_required_fields(self):
        with pytest.raises(ValidationError):
            TopologyNode(id="bad-node", name="Bad Node")  # type: ignore

    def test_fuzzy_finder(self, digital_twin: DigitalTwinGraph):
        node = digital_twin.find_node_by_identifier("s3-enterprise-cui-vault")
        assert node is not None
        assert node.type == "Storage_S3_Bucket"

        workload = digital_twin.find_node_by_identifier("role-analytics-ingestion-svc")
        assert workload is not None

        cui = digital_twin.find_node_by_identifier("s3://corp-restricted-cui-financial-vault")
        assert cui is not None
        assert cui.id == "s3-enterprise-cui-vault"


class TestSecurityGroupExplicitMapping:
    """Tests that security group mapping is explicit and rejects silent assumptions."""

    def test_explicit_default_mapping(self, digital_twin: DigitalTwinGraph):
        node = digital_twin.get_node_for_security_group("sg-analytics-web-01")
        assert node is not None
        assert node.id == "eks-analytics-worker-pool"

    def test_unmapped_security_group_returns_none(self, digital_twin: DigitalTwinGraph):
        # Must return None without guessing based on substring
        node = digital_twin.get_node_for_security_group("sg-guest-network-01")
        assert node is None

        node_fake = digital_twin.get_node_for_security_group("sg-analytics-unrelated-random")
        assert node_fake is None

    def test_custom_registration_works(self, digital_twin: DigitalTwinGraph):
        digital_twin.register_security_group_mapping("sg-custom-db", "zone-restricted-financial")
        node = digital_twin.get_node_for_security_group("sg-custom-db")
        assert node is not None
        assert node.id == "zone-restricted-financial"


class TestRelationshipEnrichment:
    """Tests for enriching implicit node attributes into explicit graph edges."""

    def test_enriched_contains_workload_edge(self, digital_twin: DigitalTwinGraph):
        assert digital_twin.nx_graph.has_edge("subnet-trust-dmz", "eks-analytics-worker-pool")
        edge_data = digital_twin.nx_graph.get_edge_data("subnet-trust-dmz", "eks-analytics-worker-pool")
        assert edge_data["relationship"] == "CONTAINS_WORKLOAD"
        assert edge_data["is_enriched"] is True

    def test_enriched_assumes_role_edge(self, digital_twin: DigitalTwinGraph):
        assert digital_twin.nx_graph.has_edge("eks-analytics-worker-pool", "role-analytics-ingestion-svc")
        edge_data = digital_twin.nx_graph.get_edge_data("eks-analytics-worker-pool", "role-analytics-ingestion-svc")
        assert edge_data["relationship"] == "ASSUMES_ROLE"
        assert edge_data["is_enriched"] is True

    def test_preserved_original_edges(self, digital_twin: DigitalTwinGraph):
        assert digital_twin.nx_graph.has_edge("role-analytics-ingestion-svc", "s3-enterprise-cui-vault")
        edge_data = digital_twin.nx_graph.get_edge_data("role-analytics-ingestion-svc", "s3-enterprise-cui-vault")
        assert edge_data["relationship"] == "CROSS_ZONE_IAM_PATH"
        assert edge_data["is_enriched"] is False


class TestConditionalEdgeTraversal:
    """Tests condition-aware graph propagation (respecting blast_condition)."""

    def test_threat_prevention_enforced_blocks_financial_zone_propagation(
        self, digital_twin: DigitalTwinGraph
    ):
        """When security_profile_group is active, ZONE_INTERCONNECT_ROUTING is NOT breached."""
        analyzer = BlastRadiusAnalyzer(digital_twin)
        safe_rule = PanosSecurityPolicyResource(
            resource_type="panos_security_policy",
            resource_name="safe_rule",
            source_file="safe.tf",
            rules=[
                PanosSecurityPolicyRule(
                    name="Safe-Egress",
                    source_zones=["Trust-DMZ"],
                    source_addresses=["10.100.4.0/24"],
                    destination_zones=["Untrust-Internet"],
                    destination_addresses=["52.84.120.0/22"],
                    applications=["ssl"],
                    services=["service-https"],
                    action="allow",
                    security_profile_group="Strict-Enterprise-Security",  # Active threat profile!
                )
            ],
        )
        res = analyzer.analyze_resources([safe_rule])
        affected_ids = {n.node_id for n in res.all_affected_nodes}

        # Perimeter firewall & Trust-DMZ are direct
        assert "pan-vm-core-firewall-01" in affected_ids
        assert "subnet-trust-dmz" in affected_ids

        # zone-restricted-financial MUST NOT be affected because threat profile is active!
        assert "zone-restricted-financial" not in affected_ids
        assert "zone-restricted-financial" in res.not_affected_nodes

    def test_threat_prevention_disabled_triggers_financial_zone_propagation(
        self, digital_twin: DigitalTwinGraph
    ):
        """When security_profile_group is 'none', ZONE_INTERCONNECT_ROUTING is breached."""
        analyzer = BlastRadiusAnalyzer(digital_twin)
        insecure_rule = PanosSecurityPolicyResource(
            resource_type="panos_security_policy",
            resource_name="insecure_rule",
            source_file="insecure.tf",
            rules=[
                PanosSecurityPolicyRule(
                    name="Insecure-Rule",
                    source_zones=["Trust-DMZ"],
                    source_addresses=["10.100.4.0/24"],
                    destination_zones=["Untrust-Internet"],
                    destination_addresses=["any"],
                    applications=["any"],
                    services=["service-https"],
                    action="allow",
                    security_profile_group="none",  # Disabled!
                )
            ],
        )
        res = analyzer.analyze_resources([insecure_rule])
        affected_ids = {n.node_id for n in res.all_affected_nodes}
        assert "zone-restricted-financial" in affected_ids

    def test_scoped_iam_policy_blocks_cui_vault_propagation(self, digital_twin: DigitalTwinGraph):
        """When IAM policy is strictly scoped, CROSS_ZONE_IAM_PATH is NOT breached."""
        analyzer = BlastRadiusAnalyzer(digital_twin)
        scoped_attachment = AwsIamRolePolicyAttachmentResource(
            resource_type="aws_iam_role_policy_attachment",
            resource_name="telemetry_scoped",
            source_file="scoped_iam.tf",
            role="role-analytics-ingestion-svc",
            policy_arn="arn:aws:iam::111122223333:policy/S3TelemetryWriteOnly",  # Scoped!
        )
        res = analyzer.analyze_resources([scoped_attachment])
        affected_ids = {n.node_id for n in res.all_affected_nodes}

        assert "role-analytics-ingestion-svc" in affected_ids
        # CUI vault MUST NOT be affected because policy is scoped to telemetry!
        assert "s3-enterprise-cui-vault" not in affected_ids
        assert "s3-enterprise-cui-vault" in res.not_affected_nodes

    def test_broad_iam_policy_triggers_cui_vault_propagation(self, digital_twin: DigitalTwinGraph):
        """When IAM policy is AmazonS3FullAccess, CROSS_ZONE_IAM_PATH is breached."""
        analyzer = BlastRadiusAnalyzer(digital_twin)
        full_access_attachment = AwsIamRolePolicyAttachmentResource(
            resource_type="aws_iam_role_policy_attachment",
            resource_name="full_s3",
            source_file="full_iam.tf",
            role="role-analytics-ingestion-svc",
            policy_arn="arn:aws:iam::aws:policy/AmazonS3FullAccess",
        )
        res = analyzer.analyze_resources([full_access_attachment])
        affected_ids = {n.node_id for n in res.all_affected_nodes}
        assert "s3-enterprise-cui-vault" in affected_ids


class TestUnmappedResourceUnknownStatus:
    """Tests that unmapped resources produce UNKNOWN status and never classify assets as confirmed safe."""

    def test_unmapped_sg_produces_unknown_status(
        self, digital_twin: DigitalTwinGraph, hcl_parser: TerraformHclParser
    ):
        parsed = hcl_parser.parse_file(CHANGES_DIR / "allow_netflix.tf")
        analyzer = BlastRadiusAnalyzer(digital_twin)
        result = analyzer.analyze_resources(parsed.resources)

        # 0 directly or cascading affected assets
        assert result.total_affected_count == 0
        assert len(result.direct_impacts) == 0
        assert len(result.cascading_impacts) == 0

        # Unmapped resource warning preserved
        assert len(result.unmapped_resources) == 1
        assert "sg-guest-network-01" in result.unmapped_resources[0]

        # UNKNOWN status produced
        assert len(result.unknown_impacts) > 0
        unknown_reasons = [u.reason for u in result.unknown_impacts]
        assert any("sg-guest-network-01" in r for r in unknown_reasons)

        # Do NOT classify all Digital Twin assets as confirmed safe (NOT_AFFECTED)
        assert len(result.not_affected_nodes) == 0
        # All 6 Digital Twin nodes are classified as UNKNOWN
        assert len(result.unknown_nodes) == 6


class TestBlastRadiusPRScenarios:
    """Regression tests for PR #4082 and PR #4083 scenarios."""

    def test_pr_4083_all_nodes_affected(
        self, digital_twin: DigitalTwinGraph, hcl_parser: TerraformHclParser
    ):
        parsed = hcl_parser.parse_file(CHANGES_DIR / "pr_4083_firewall_iam.tf")
        analyzer = BlastRadiusAnalyzer(digital_twin)
        result = analyzer.analyze_resources(parsed.resources)

        assert result.total_affected_count == 6
        assert len(result.not_affected_nodes) == 0
        assert len(result.unknown_nodes) == 0

        direct_ids = {n.node_id for n in result.direct_impacts}
        assert direct_ids == {
            "pan-vm-core-firewall-01",
            "subnet-trust-dmz",
            "role-analytics-ingestion-svc",
        }

        cascading_ids = {n.node_id for n in result.cascading_impacts}
        assert cascading_ids == {
            "eks-analytics-worker-pool",
            "s3-enterprise-cui-vault",
            "zone-restricted-financial",
        }

        # Check terminology: must say "potentially"
        cui_node = [n for n in result.cascading_impacts if n.node_id == "s3-enterprise-cui-vault"][0]
        assert "potentially" in cui_node.impact_reason.lower()
        assert cui_node.status == ImpactStatus.AFFECTED

    def test_pr_4082_partial_nodes_affected(
        self, digital_twin: DigitalTwinGraph, hcl_parser: TerraformHclParser
    ):
        parsed = hcl_parser.parse_file(CHANGES_DIR / "pr_4082_firewall_iam.tf")
        analyzer = BlastRadiusAnalyzer(digital_twin)
        result = analyzer.analyze_resources(parsed.resources)

        assert result.total_affected_count == 4
        assert len(result.unknown_nodes) == 0
        # Remaining 2 nodes are confirmed NOT_AFFECTED because all resources were fully mapped
        assert set(result.not_affected_nodes) == {
            "pan-vm-core-firewall-01",
            "zone-restricted-financial",
        }


class TestCircularGraphResilience:
    """Tests that cyclic topology relationships do not cause infinite loops."""

    def test_circular_topology_termination(self):
        data = {
            "metadata": {
                "organization": "Test Corp",
                "firewall_vendor": "Palo Alto",
                "perimeter_firewall": "node-a",
                "compliance_frameworks": [],
            },
            "nodes": [
                {"id": "node-a", "name": "Node A", "type": "NGFW_Palo_Alto", "criticality": "Critical", "zones": ["ZoneA"]},
                {"id": "node-b", "name": "Node B", "type": "Network_Zone", "criticality": "High", "zones": ["ZoneA"]},
                {"id": "node-c", "name": "Node C", "type": "Compute_Cluster", "criticality": "Medium"},
            ],
            "edges": [
                {"source": "node-a", "target": "node-b", "relationship": "ENFORCES_ZONE_POLICY"},
                {"source": "node-b", "target": "node-c", "relationship": "CONTAINS_WORKLOAD"},
                {"source": "node-c", "target": "node-a", "relationship": "FEEDBACK_LOOP"},
            ],
        }
        dt = DigitalTwinGraph.from_dict(data)
        assert nx.is_directed_acyclic_graph(dt.nx_graph) is False

        analyzer = BlastRadiusAnalyzer(dt)
        mock_policy = PanosSecurityPolicyResource(
            resource_type="panos_security_policy",
            resource_name="test_cycle",
            source_file="test.tf",
            rules=[
                PanosSecurityPolicyRule(
                    name="rule1",
                    source_zones=["ZoneA"],
                    source_addresses=["10.0.0.0/8"],
                    destination_zones=["any"],
                    destination_addresses=["any"],
                    applications=["any"],
                    services=["any"],
                )
            ],
        )
        res = analyzer.analyze_resources([mock_policy])
        assert res.total_affected_count >= 1
